//! Waiting for a condition.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use regex::Regex;
use serde_json::Value;
use tokio::sync::Semaphore;

use super::args::{Args, Param};
use super::fs::{denied_by, dir_resource};
use super::paths::{check_absolute, open_path, within};
use super::service::{lookup, normalize_unit};
use super::{Authorized, Ctx, Tool, ToolError, ToolResult, blocking, command_text, required};
use crate::policy::Access;
use crate::sanitize::redact_text;
use crate::timefmt::{now_secs, rfc3339_utc};

/// Where wait_for looks. A parameter, so that tests can point it elsewhere.
#[derive(Clone, Debug)]
pub struct Places {
    /// The directory holding the kernel's `tcp` and `tcp6` socket tables.
    pub proc_net: PathBuf,
}

impl Places {
    pub fn system() -> Places {
        Places {
            proc_net: PathBuf::from("/proc/net"),
        }
    }
}

const CONDITIONS: [&str; 7] = [
    "unit_active",
    "unit_inactive",
    "port_listening",
    "port_closed",
    "file_exists",
    "file_absent",
    "log_line",
];

pub fn tools() -> Vec<Tool> {
    tools_with(Places::system())
}

/// Bounds how many waits are under way at once. Sized by the first call.
///
/// AIDEV-NOTE: a wait holds one of the server's call slots (limits.max_concurrent_calls)
/// for its whole length, so without a limit of its own a caller who starts as many waits
/// as there are slots would shut everyone else out for minutes. Waits may therefore hold
/// at most half of the slots (`waits_at_once`); one more is refused at once. The limit
/// belongs to the tool, and a server builds its tools once, so it is one limit for the
/// whole server; it is not a `static`, so that each test has its own.
#[derive(Default)]
struct Waits(OnceLock<Semaphore>);

pub fn tools_with(places: Places) -> Vec<Tool> {
    let places = Arc::new(places);
    let waits = Arc::new(Waits::default());
    vec![Tool::new(
        "wait_for",
        "Wait, for a bounded time, until ONE condition holds: a systemd unit is active or \
         inactive, a local TCP port is listening or closed, a file exists or is gone, or a \
         unit logs a line matching a pattern. Use it after starting, stopping or restarting \
         something, instead of calling a status tool again and again. The result is an \
         error when the condition was not met in time. Waiting on something needs the \
         permission to look at it as well (service.view, net.view, fs.view or journal.view).",
        Access::Read,
        "wait.use",
        vec![
            Param::choice("condition", "What to wait for", &CONDITIONS).required(),
            Param::str(
                "unit",
                "For unit_active, unit_inactive and log_line: the unit, e.g. nginx or \
                 nginx.service",
            )
            .max_len(255),
            Param::int(
                "port",
                "For port_listening and port_closed: the local TCP port",
                1,
                65_535,
            ),
            Param::str(
                "path",
                "For file_exists and file_absent: the absolute path, written without . or .. \
                 in it",
            )
            .max_len(4096),
            Param::str(
                "pattern",
                "For log_line: a regular expression that a log message of the unit must \
                 match (start it with (?i) to ignore case)",
            )
            .max_len(512),
            Param::int(
                "seconds",
                "Longest time to wait (default 30). The server's time limit for one call may \
                 shorten it; the result says so when it does",
                1,
                600,
            ),
            Param::int(
                "lookback_seconds",
                "For log_line: also accept a line logged up to this long before the call \
                 began (default 0). Use it when the line may already have been logged",
                0,
                600,
            ),
        ],
        move |ctx, args| wait_for(places.clone(), waits.clone(), ctx, args),
    )]
}

// ---- ports ----------------------------------------------------------------------------

/// The port of a listening socket, from a line of `/proc/net/tcp` or `tcp6`:
/// `N: ADDRESS:PORT ADDRESS:PORT STATE ...`, everything in hexadecimal; state `0A` is
/// LISTEN.
pub fn parse_listener(line: &str) -> Option<u16> {
    let mut fields = line.split_whitespace();
    let (_slot, local, _remote, state) = (
        fields.next()?,
        fields.next()?,
        fields.next()?,
        fields.next()?,
    );
    if state != "0A" {
        return None;
    }
    let (_address, port) = local.rsplit_once(':')?;
    if port.len() != 4 {
        return None;
    }
    u16::from_str_radix(port, 16).ok()
}

/// Whether anything listens on a TCP port, on any address, IPv4 or IPv6.
///
/// AIDEV-NOTE: read from the kernel's own tables rather than by connecting: a connection
/// would be seen (and logged) by the service, and would miss one bound to an address
/// that is not ours to guess. An error (neither table readable) is never "closed".
pub fn port_is_listening(dir: &Path, port: u16) -> std::io::Result<bool> {
    let mut read_any = false;
    for name in ["tcp", "tcp6"] {
        // A host without IPv6 has only one of the two.
        let Ok(file) = std::fs::File::open(dir.join(name)) else {
            continue;
        };
        read_any = true;
        for line in BufReader::new(file).lines() {
            let Ok(line) = line else { break };
            if parse_listener(&line) == Some(port) {
                return Ok(true);
            }
        }
    }
    if read_any {
        Ok(false)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("neither tcp nor tcp6 can be read in {}", dir.display()),
        ))
    }
}

// ---- time -----------------------------------------------------------------------------

/// What the call keeps back for putting the answer together (as `CallClock` does).
fn reserve(call_timeout: u64) -> u64 {
    (call_timeout / 4).clamp(1, 10)
}

/// How long to wait: what was asked for, or what the call's time limit leaves after the
/// `spent` seconds already used, the reserve, and a second for the last look. Also
/// whether that is less than was asked for.
pub fn wait_limit(asked: u64, call_timeout: u64, spent: u64) -> (u64, bool) {
    let room = call_timeout
        .saturating_sub(reserve(call_timeout))
        .saturating_sub(spent)
        .saturating_sub(1);
    let seconds = asked.min(room);
    (seconds, seconds < asked)
}

/// How many wait_for calls may be under way at once: half of the server's call slots,
/// and at least one.
pub fn waits_at_once(max_concurrent_calls: usize) -> usize {
    (max_concurrent_calls / 2).max(1)
}

// ---- what is watched --------------------------------------------------------------------

/// What one look found.
enum Look {
    Met(String),
    NotYet(String),
    /// Not met, and waiting longer cannot change that.
    Never(String),
}

enum Watch {
    Unit {
        id: String,
        active: bool,
    },
    Port {
        dir: PathBuf,
        port: u16,
        listening: bool,
    },
    File {
        path: String,
        /// What the call was authorized for: `file/` and the real path.
        resource: String,
        present: bool,
    },
    Log {
        unit: String,
        pattern: Regex,
        /// Unix seconds from which entries count.
        since: i64,
        /// Where the last look stopped reading.
        cursor: Option<String>,
        examined: u64,
    },
}

/// `text` on one line: every run of whitespace and control characters is one space.
fn one_line(text: &str) -> String {
    text.split(|c: char| c.is_whitespace() || c.is_control())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// `text` cut to `max` characters, with a mark if anything was cut.
fn cut(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut kept: String = text.chars().take(max).collect();
    kept.push_str("...");
    kept
}

/// A journal field as text (journalctl prints bytes that are not UTF-8 as an array).
fn field(entry: &Value, name: &str) -> Option<String> {
    match entry.get(name)? {
        Value::String(text) => Some(text.clone()),
        Value::Array(items) => {
            let bytes: Option<Vec<u8>> = items
                .iter()
                .map(|item| item.as_u64().and_then(|byte| u8::try_from(byte).ok()))
                .collect();
            bytes.map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        }
        _ => None,
    }
}

/// A journal cursor as journalctl prints one. It is passed back to journalctl, so
/// anything else is not used.
fn is_cursor(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 512
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "=;_-".contains(c))
}

/// The real path a file that does not exist would have: the real path of the deepest
/// directory on the way that does exist, then the rest as written.
///
/// AIDEV-NOTE: every check is made on this, as fs_stat makes its checks on a file's
/// real path. Without it, a link in a directory the caller may list could be used to
/// ask about files in one the caller may not: the answer for a file that is there
/// (judged by its real path) would differ from the answer for one that is not (judged
/// as written). `path` has no `.`, `..` or empty parts: `prepare` refuses those.
fn settled(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    for keep in (0..parts.len()).rev() {
        let (Some(above), Some(below)) = (parts.get(..keep), parts.get(keep..)) else {
            continue;
        };
        let ancestor = format!("/{}", above.join("/"));
        if let Ok(opened) = open_path(&ancestor, true) {
            let base = opened.real.trim_end_matches('/');
            return format!("{base}/{}", below.join("/"));
        }
    }
    path.to_string()
}

/// What one look at a path found.
struct Seen {
    present: bool,
    /// The file's real path (see `settled` for a file that is not there), without a
    /// trailing slash. The call is authorized under wait.use for `file/` and this.
    real: String,
    /// Why the server could not look, when it could not.
    trouble: Option<std::io::Error>,
}

/// Looks at the path once, after checking that this caller may be told what is there.
///
/// AIDEV-NOTE: the limits are those of fs_stat, on the same name fs_stat would use: the
/// path must lie in `fs.list_roots`, must not be a never-readable path, and the caller
/// must hold fs.view on it. They are checked at every look, not just the first: what
/// appears at the path later is judged by what it then is. A refusal's text names only
/// the path as the caller wrote it; the audit record names the real one.
fn file_seen(ctx: &Ctx, path: &str) -> Result<Seen, ToolError> {
    use std::io::ErrorKind;
    // `view` is the name fs_stat would authorize: a directory's has a trailing slash.
    let (present, real, view, trouble) = match std::fs::symlink_metadata(path) {
        // Not following: a link is itself the thing that exists, as for fs_stat.
        Ok(_) => match open_path(path, false) {
            Ok(opened) if opened.meta.is_dir() => {
                (true, opened.real.clone(), dir_resource(&opened.real), None)
            }
            Ok(opened) => (true, opened.real.clone(), opened.real.clone(), None),
            // Gone again between the two looks.
            Err(_) => {
                let real = settled(path);
                (false, real.clone(), real, None)
            }
        },
        Err(e) => {
            let real = settled(path);
            let absent = matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory);
            (false, real.clone(), real, (!absent).then_some(e))
        }
    };
    let resource = format!("file/{real}");
    let cfg = &ctx.cfg().fs;
    let real_roots: Vec<PathBuf> = cfg
        .list_roots
        .iter()
        .filter_map(|root| std::fs::canonicalize(root).ok())
        .collect();
    if !within(&view, &cfg.list_roots) && !within(&view, &real_roots) {
        let reason =
            format!("{path} is outside the directories that fs.list_roots allows on this host");
        return Err(ctx.deny(Some(&resource), &reason));
    }
    if let Some(pattern) = denied_by(cfg, &view) {
        let reason = format!("{path} matches the never-readable pattern {pattern}");
        return Err(ctx.deny(Some(&resource), &reason));
    }
    if !ctx.holds_read_on("fs.view", &view) {
        return Err(ctx.deny(
            Some(&resource),
            "waiting on a file shows whether it exists, which needs fs.view on it; this \
             caller does not hold that",
        ));
    }
    Ok(Seen {
        present,
        real,
        trouble,
    })
}

impl Watch {
    /// How long to pause between looks.
    fn interval(&self) -> Duration {
        match self {
            Watch::Log { .. } => Duration::from_secs(2),
            _ => Duration::from_secs(1),
        }
    }

    /// Looks once. `limit` bounds any command this runs.
    async fn look(&mut self, ctx: &Ctx, limit: Duration) -> Result<Look, ToolError> {
        match self {
            Watch::Unit { id, active } => {
                let is_active = ctx
                    .command("systemctl")?
                    .args(["is-active", "--", id.as_str()])
                    .timeout(limit);
                let out = ctx.run(is_active).await?;
                let said = String::from_utf8_lossy(&out.stdout);
                let said = said.trim();
                let plain = !said.is_empty()
                    && said.len() <= 32
                    && said.chars().all(|c| c.is_ascii_lowercase() || c == '-');
                let state = if plain { said } else { "unknown" };
                Ok(match (*active, state) {
                    (true, "active") => Look::Met(format!("{id} is active.")),
                    (true, "failed") => Look::Never(format!(
                        "{id} is failed, and a failed unit does not start again by itself"
                    )),
                    (false, "inactive") => Look::Met(format!("{id} is inactive.")),
                    (false, "failed") => Look::Met(format!("{id} is failed (it is not running).")),
                    _ => Look::NotYet(format!("{id} is {state}.")),
                })
            }
            Watch::Port {
                dir,
                port,
                listening,
            } => {
                let (dir, port) = (dir.clone(), *port);
                let open = blocking(ctx.clone(), move || {
                    port_is_listening(&dir, port).map_err(|e| {
                        ToolError::Failed(format!(
                            "cannot read the kernel's table of TCP sockets: {e}"
                        ))
                    })
                })
                .await?;
                let found = if open {
                    format!("something is listening on TCP port {port}.")
                } else {
                    format!("nothing is listening on TCP port {port}.")
                };
                Ok(if open == *listening {
                    Look::Met(found)
                } else {
                    Look::NotYet(found)
                })
            }
            Watch::File {
                path,
                resource,
                present,
            } => {
                let (walker, at) = (ctx.clone(), path.clone());
                let seen = blocking(ctx.clone(), move || file_seen(&walker, &at)).await?;
                // AIDEV-NOTE: the call was authorized for the real path the file had
                // when the wait began. If the path has since come to lead elsewhere (a
                // directory on the way replaced by a link), what is there now must be
                // something this caller may wait on too, or the wait ends here.
                let now = format!("file/{}", seen.real);
                if now != *resource && !ctx.permits(&now) {
                    let reason =
                        format!("{path} has come to lead to a place this caller may not wait on");
                    return Err(ctx.deny(Some(&now), &reason));
                }
                if let Some(problem) = seen.trouble {
                    return Err(ToolError::Failed(format!("{path}: {problem}")));
                }
                let found = if seen.present {
                    format!("{path} exists.")
                } else {
                    format!("{path} does not exist.")
                };
                Ok(if seen.present == *present {
                    Look::Met(found)
                } else {
                    Look::NotYet(found)
                })
            }
            Watch::Log {
                unit,
                pattern,
                since,
                cursor,
                examined,
            } => {
                // AIDEV-NOTE: every value is `--option=value` in one argument. The
                // cursor is journalctl's own, checked by `is_cursor`; carrying on from
                // it means a look never re-reads or skips an entry, even when one look
                // had more output than is kept.
                let mut argv = vec![
                    "--no-pager".to_string(),
                    "--quiet".to_string(),
                    "--output=json".to_string(),
                    "--output-fields=MESSAGE".to_string(),
                    format!("--unit={unit}"),
                ];
                argv.push(match cursor {
                    Some(cursor) => format!("--after-cursor={cursor}"),
                    None => format!("--since=@{since}"),
                });
                let mut journalctl = ctx.command("journalctl")?.args(argv).timeout(limit);
                journalctl.max_output = 4 << 20;
                let mut out = ctx.run(journalctl).await?;
                let entries = std::mem::take(&mut out.stdout);
                // journalctl --quiet exits 1 with no output when nothing matched.
                if entries.is_empty() && !out.timed_out && !matches!(out.code, Some(0) | Some(1)) {
                    return Err(ToolError::Failed(format!(
                        "cannot read the journal: {}",
                        cut(&one_line(&command_text(&out)), 300)
                    )));
                }
                let mut read = 0u64;
                for line in entries.split(|byte| *byte == b'\n') {
                    // A last line cut off by the output limit is not an entry; the next
                    // look starts again after the last whole one.
                    let Ok(entry) = serde_json::from_slice::<Value>(line) else {
                        continue;
                    };
                    read += 1;
                    *examined += 1;
                    if let Some(next) = field(&entry, "__CURSOR").filter(|next| is_cursor(next)) {
                        *cursor = Some(next);
                    }
                    let Some(message) = field(&entry, "MESSAGE") else {
                        continue;
                    };
                    if pattern.is_match(&message) {
                        let when = field(&entry, "__REALTIME_TIMESTAMP")
                            .and_then(|usec| usec.trim().parse::<u64>().ok())
                            .and_then(|usec| i64::try_from(usec / 1_000_000).ok())
                            .map(rfc3339_utc)
                            .unwrap_or_default();
                        // Log lines carry command lines and connection strings: mask
                        // what looks like a secret, as journal_query's readers expect.
                        let line = cut(&one_line(&redact_text(&message)), 300);
                        return Ok(Look::Met(format!(
                            "{unit} logged a matching line:\n{when} {line}"
                        )));
                    }
                }
                // AIDEV-NOTE: stopped at its time limit without one whole entry, this
                // look saw nothing: that is "could not look", not "nothing matched". A
                // look that timed out after reading some entries has made progress (the
                // cursor moved on) and the wait carries on from there.
                if out.timed_out && read == 0 {
                    return Err(ToolError::Failed(format!(
                        "the journal of {unit} could not be read in time: journalctl gave \
                         nothing within {} s and was stopped. Whether a matching line was \
                         logged is not known; the journal may be very large or its disk \
                         slow (journal_query with a short time range may still answer).",
                        limit.as_secs().max(1)
                    )));
                }
                Ok(Look::NotYet(format!(
                    "no line of {unit} has matched ({examined} examined)."
                )))
            }
        }
    }
}

/// Checks that the arguments given are the ones the condition uses.
fn check_arguments(condition: &str, args: &Args) -> Result<(), ToolError> {
    let (needs, also): (&[&str], &[&str]) = match condition {
        "unit_active" | "unit_inactive" => (&["unit"], &[]),
        "port_listening" | "port_closed" => (&["port"], &[]),
        "file_exists" | "file_absent" => (&["path"], &[]),
        "log_line" => (&["unit", "pattern"], &["lookback_seconds"]),
        other => {
            return Err(ToolError::Invalid(format!("{other:?} is not a condition")));
        }
    };
    for name in ["unit", "port", "path", "pattern", "lookback_seconds"] {
        let given = args.str(name).is_some() || args.int(name).is_some();
        if needs.contains(&name) && !given {
            return Err(ToolError::Invalid(format!("{condition} needs {name}")));
        }
        if given && !needs.contains(&name) && !also.contains(&name) {
            return Err(ToolError::Invalid(format!(
                "{name} does not apply to {condition}"
            )));
        }
    }
    Ok(())
}

/// Works out what to watch, and settles whether this caller may watch it.
///
/// AIDEV-NOTE, security: a wait is an oracle for whatever it watches (with a pattern on
/// a log, bit by bit for the log's content). So besides authorizing the call under
/// wait.use, the caller must hold the permission of the tool that owns that
/// information, on that same thing, named exactly as that tool names it: service.view
/// on the unit's real name (service_status), net.view (net_sockets), fs.view on the
/// file's real path (fs_stat), journal.view on the unit (journal_query). Otherwise the
/// wait is refused, and nothing is looked at.
async fn prepare(
    places: &Places,
    ctx: &Ctx,
    condition: &str,
    args: &Args,
    began: i64,
) -> Result<(Watch, Authorized), ToolError> {
    match condition {
        "unit_active" | "unit_inactive" => {
            let unit = normalize_unit(required(args, "unit")?)?;
            // Judged by the unit's real name, as service_status judges it: asking by an
            // alias must not get around a grant or a deny written for the unit itself.
            let (id, load_state) = lookup(ctx, &unit).await?;
            let resource = format!("unit/{id}");
            if !ctx.holds_read_on("service.view", &id) {
                // AIDEV-NOTE: the caller reads this text, and it names the unit as it
                // was asked for. The real name behind an alias is something only a
                // caller who may see that unit is told; the audit record (the
                // operator's) has it as the resource.
                let reason = format!(
                    "waiting on a unit shows its state, which needs service.view on {unit} \
                     (on the unit it stands for, if that name is an alias); this caller \
                     does not hold that"
                );
                return Err(ctx.deny(Some(&resource), &reason));
            }
            let auth = ctx.authorize(Some(&resource))?;
            if load_state == "not-found" {
                return Err(ToolError::Failed(format!(
                    "{id}: there is no such unit on this host"
                )));
            }
            let watch = Watch::Unit {
                id,
                active: condition == "unit_active",
            };
            Ok((watch, auth))
        }
        "port_listening" | "port_closed" => {
            let port = args
                .int("port")
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port != 0)
                .ok_or_else(|| {
                    ToolError::Invalid("port must be between 1 and 65535".to_string())
                })?;
            let resource = format!("port/{port}");
            if !ctx.holds_read("net.view") {
                return Err(ctx.deny(
                    Some(&resource),
                    "waiting on a port shows what is listening, which needs net.view; this \
                     caller does not hold that",
                ));
            }
            let auth = ctx.authorize(Some(&resource))?;
            let watch = Watch::Port {
                dir: places.proc_net.clone(),
                port,
                listening: condition == "port_listening",
            };
            Ok((watch, auth))
        }
        "file_exists" | "file_absent" => {
            let path = required(args, "path")?.to_string();
            check_absolute(&path)?;
            if path
                .split('/')
                .skip(1)
                .any(|part| part.is_empty() || part == "." || part == "..")
            {
                return Err(ToolError::Invalid(
                    "path must be written out in full: no \".\" or \"..\" in it, no doubled \
                     or trailing slash"
                        .to_string(),
                ));
            }
            // The first look, before the call is authorized: a path this caller may not
            // ask about is refused whether or not anything is there. That the server
            // cannot look at all (`trouble`) is reported by the first look of the wait,
            // after authorization.
            let (walker, at) = (ctx.clone(), path.clone());
            let seen = blocking(ctx.clone(), move || file_seen(&walker, &at)).await?;
            // AIDEV-NOTE: authorized by the REAL path, the same one the fs.view check
            // is made on (for a file that is not there: the real path of the deepest
            // directory that exists, then the rest). Authorizing the path as written
            // would let a link in an allowed place step around a deny for wait.use that
            // names the real location.
            let resource = format!("file/{}", seen.real);
            let auth = ctx.authorize(Some(&resource))?;
            let watch = Watch::File {
                path,
                resource,
                present: condition == "file_exists",
            };
            Ok((watch, auth))
        }
        _ => {
            // As journal_query names it: the unit's name, completed but not looked up.
            let unit = normalize_unit(required(args, "unit")?)?;
            let pattern = regex::RegexBuilder::new(required(args, "pattern")?)
                .size_limit(1 << 20)
                .build()
                .map_err(|e| {
                    ToolError::Invalid(format!("pattern is not a valid regular expression: {e}"))
                })?;
            let resource = format!("log/{unit}");
            if !ctx.holds_read_on("journal.view", &unit) {
                let reason = format!(
                    "waiting on a unit's log shows what it logs, which needs journal.view on \
                     {unit}; this caller does not hold that"
                );
                return Err(ctx.deny(Some(&resource), &reason));
            }
            let auth = ctx.authorize(Some(&resource))?;
            let watch = Watch::Log {
                unit,
                pattern,
                since: began.saturating_sub(args.int("lookback_seconds").unwrap_or(0)),
                cursor: None,
                examined: 0,
            };
            Ok((watch, auth))
        }
    }
}

async fn wait_for(places: Arc<Places>, waits: Arc<Waits>, ctx: Ctx, args: Args) -> ToolResult {
    let began = Instant::now();
    let began_unix = now_secs();
    let condition = required(&args, "condition")?.to_string();
    check_arguments(&condition, &args)?;
    let asked = u64::try_from(args.int("seconds").unwrap_or(30)).unwrap_or(30);
    let (mut watch, auth) = prepare(&places, &ctx, &condition, &args, began_unix).await?;
    // After authorization, so that a call turned away here is in the audit trail and a
    // caller who may not wait at all learns nothing about how busy the server is.
    let slots = waits
        .0
        .get_or_init(|| Semaphore::new(waits_at_once(ctx.cfg().limits.max_concurrent_calls)));
    let Ok(_slot) = slots.try_acquire() else {
        return Err(ToolError::Failed(
            "too many waits are in progress on this server; try again shortly".to_string(),
        ));
    };

    // AIDEV-NOTE: a call that outlasts limits.call_timeout_secs is cut off and returns
    // nothing, so the wait ends in time for one more look and the answer. While it
    // waits, the call holds one of the server's call slots; that is what `seconds` and
    // the call limit bound.
    let limits = &ctx.cfg().limits;
    let call = limits.call_timeout_secs;
    let (seconds, shortened) = wait_limit(asked, call, began.elapsed().as_secs());
    let hard_stop = began + Duration::from_secs(call.saturating_sub(reserve(call)));
    let command = Duration::from_secs(limits.command_timeout_secs);
    let note = if shortened {
        format!(
            "[the wait was shortened from {asked} s to {seconds} s: this server ends a call \
             after {call} s (limits.call_timeout_secs)]\n"
        )
    } else {
        String::new()
    };

    let waiting = Instant::now();
    let wait_end = waiting + Duration::from_secs(seconds);
    let last = loop {
        let left = hard_stop.saturating_duration_since(Instant::now());
        let limit = command.min(left).max(Duration::from_secs(1));
        let found = match watch.look(&ctx, limit).await? {
            Look::Met(found) => {
                let after = waiting.elapsed().as_secs();
                return auth.ok(format!("Met after {after} s: {found}\n{note}"));
            }
            Look::Never(found) => {
                let after = waiting.elapsed().as_secs();
                return auth.failed(format!(
                    "Not met: {found} (stopped waiting after {after} s).\n{note}"
                ));
            }
            Look::NotYet(found) => found,
        };
        let now = Instant::now();
        if now >= wait_end {
            break found;
        }
        tokio::time::sleep((wait_end - now).min(watch.interval())).await;
    };
    auth.failed(format!("Not met within {seconds} s: {last}\n{note}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::timefmt::now_secs;
    use crate::tools::testing::{FakeBins, call, find, host, ok_text};
    use crate::tools::{Host, ToolError, ToolResult};
    use serde_json::{Value, json};
    use std::sync::Arc;

    // ---- pure parts -------------------------------------------------------------------

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   \
        0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 23456 1 0000000000000000 100 0 0 10 0\n   \
        1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 23457 1 0000000000000000 100 0 0 10 0\n   \
        2: 0A000005:D431 0A000009:01BB 01 00000000:00000000 02:000A0B0C 00000000  1000        0 23458 2 0000000000000000 20 4 30 10 -1\n";
    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   \
        0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 9001 1 0000000000000000 100 0 0 10 0\n";

    #[test]
    fn a_listening_socket_gives_its_port() {
        let ports: Vec<u16> = TCP.lines().filter_map(parse_listener).collect();
        // 53 and 8080 listen; the established connection from port 54321 does not count
        assert_eq!(ports, [53, 8080]);
        let ports: Vec<u16> = TCP6.lines().filter_map(parse_listener).collect();
        assert_eq!(ports, [22]);
        for line in [
            "",
            "garbage",
            "0: 0100007F:0035 00000000:0000",
            "0: 0100007F:ZZZZ 00000000:0000 0A",
            "0: 0100007F0035 00000000:0000 0A",
            "0: 0100007F:10035 00000000:0000 0A",
        ] {
            assert_eq!(parse_listener(line), None, "{line:?}");
        }
    }

    #[test]
    fn a_port_is_listening_if_either_table_says_so() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("tcp"), TCP).unwrap();
        // no IPv6 on this machine: only one table
        assert!(port_is_listening(dir.path(), 8080).unwrap());
        assert!(!port_is_listening(dir.path(), 22).unwrap());
        // the port of an established connection is not a listener
        assert!(!port_is_listening(dir.path(), 54321).unwrap());
        std::fs::write(dir.path().join("tcp6"), TCP6).unwrap();
        assert!(port_is_listening(dir.path(), 22).unwrap());
        // neither table can be read: that is not "closed"
        let empty = tempfile::tempdir().unwrap();
        assert!(port_is_listening(empty.path(), 22).is_err());
    }

    #[test]
    fn a_wait_never_outlasts_the_call() {
        // plenty of room: as asked
        assert_eq!(wait_limit(30, 120, 0), (30, false));
        // the call keeps ten seconds back (a quarter, at most ten) and one more for the
        // last look
        assert_eq!(wait_limit(600, 120, 0), (109, true));
        assert_eq!(wait_limit(109, 120, 0), (109, false));
        // time already spent looking things up counts
        assert_eq!(wait_limit(600, 120, 9), (100, true));
        // a short call limit
        assert_eq!(wait_limit(600, 4, 0), (2, true));
        // nothing left at all: one look, no waiting
        assert_eq!(wait_limit(30, 4, 10), (0, true));
        assert_eq!(wait_limit(1, 1, 0), (0, true));
    }

    // ---- the tool ---------------------------------------------------------------------

    /// A systemctl stand-in: `show` answers for the unit asked about; `is-active`
    /// prints `first` the first time and `then` from the second time on.
    fn systemctl(fake: FakeBins, dir: &Path, first: &str, then: &str) -> FakeBins {
        let seen = dir.join("seen").display().to_string();
        fake.add_script(
            "systemctl",
            &format!(
                "for last; do :; done\n\
                 case \"$1\" in\n\
                 show) printf '%s\\n' \"Id=$last\" 'LoadState=loaded' ;;\n\
                 is-active) if [ -f '{seen}' ]; then printf '%s\\n' '{then}'; else : > '{seen}'; printf '%s\\n' '{first}'; fi ;;\n\
                 esac"
            ),
        )
    }

    fn fixture(fake: &FakeBins, extra: &str) -> (Arc<Host>, MemorySink) {
        host(&format!(
            r#"
[roles.reader]
allow = ["@read"]
[roles.web]
allow = ["wait.use", "service.view:nginx.service", "journal.view:nginx.service"]
[roles.waiter]
allow = ["wait.use"]
[roles.viewer]
allow = ["service.view", "net.view", "fs.view", "journal.view"]
[unix_users.rita]
roles = ["reader"]
[unix_users.wendy]
roles = ["web"]
[unix_users.walt]
roles = ["waiter"]
[unix_users.vera]
roles = ["viewer"]
{extra}
{}"#,
            fake.config_only()
        ))
    }

    async fn wait_in(
        host: &Arc<Host>,
        proc_net: &Path,
        user: &str,
        arguments: Value,
    ) -> ToolResult {
        let places = Places {
            proc_net: proc_net.to_path_buf(),
        };
        call(host, user, &find(tools_with(places), "wait_for"), arguments).await
    }

    async fn wait(host: &Arc<Host>, user: &str, arguments: Value) -> ToolResult {
        wait_in(host, Path::new("/nonexistent/proc/net"), user, arguments).await
    }

    fn failed_text(result: ToolResult) -> String {
        match result {
            Ok(output) if output.is_error() => output.text().to_string(),
            other => panic!("expected a failed result, got {other:?}"),
        }
    }

    fn refusal(result: ToolResult) -> String {
        match result {
            Err(ToolError::Denied(message)) => message,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    fn invalid(result: ToolResult) -> String {
        match result {
            Err(ToolError::Invalid(message)) => message,
            other => panic!("expected invalid arguments, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_unit_that_is_already_active_is_met_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let fake = systemctl(FakeBins::new(), dir.path(), "active", "active");
        let (host, sink) = fixture(&fake, "");
        let text = ok_text(
            wait(
                &host,
                "rita",
                json!({"condition": "unit_active", "unit": "nginx"}),
            )
            .await,
        );
        assert_eq!(text, "Met after 0 s: nginx.service is active.\n");
        let calls = fake.calls("systemctl");
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert_eq!(calls[1], ["is-active", "--", "nginx.service"]);
        let records = sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["decision"], "allow");
        assert_eq!(records[0]["resource"], "unit/nginx.service");
        assert_eq!(records[0]["permission"], "wait.use");
    }

    #[tokio::test]
    async fn a_unit_that_becomes_active_is_met_when_it_does() {
        let dir = tempfile::tempdir().unwrap();
        let fake = systemctl(FakeBins::new(), dir.path(), "activating", "active");
        let (host, _sink) = fixture(&fake, "");
        let text = ok_text(
            wait(
                &host,
                "rita",
                json!({"condition": "unit_active", "unit": "nginx.service", "seconds": 5}),
            )
            .await,
        );
        assert!(
            text == "Met after 1 s: nginx.service is active.\n"
                || text == "Met after 2 s: nginx.service is active.\n",
            "{text}"
        );
    }

    #[tokio::test]
    async fn a_unit_that_fails_ends_the_wait_as_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        let fake = systemctl(FakeBins::new(), dir.path(), "failed", "failed");
        let (host, _sink) = fixture(&fake, "");
        let started = std::time::Instant::now();
        let text = failed_text(
            wait(
                &host,
                "rita",
                json!({"condition": "unit_active", "unit": "nginx", "seconds": 30}),
            )
            .await,
        );
        assert!(
            text.starts_with("Not met: nginx.service is failed"),
            "{text}"
        );
        assert!(started.elapsed().as_secs() < 5, "it should not have waited");
    }

    #[tokio::test]
    async fn a_condition_that_is_not_met_in_time_is_a_failed_result() {
        let dir = tempfile::tempdir().unwrap();
        let fake = systemctl(FakeBins::new(), dir.path(), "activating", "activating");
        let (host, _sink) = fixture(&fake, "");
        let text = failed_text(
            wait(
                &host,
                "rita",
                json!({"condition": "unit_active", "unit": "nginx", "seconds": 1}),
            )
            .await,
        );
        assert_eq!(text, "Not met within 1 s: nginx.service is activating.\n");
        // looked at the start and again at the end
        let looks = fake
            .calls("systemctl")
            .iter()
            .filter(|call| call[0] == "is-active")
            .count();
        assert_eq!(looks, 2);
    }

    #[tokio::test]
    async fn a_unit_counts_as_inactive_when_it_has_stopped_or_failed() {
        for (state, said) in [
            ("inactive", "nginx.service is inactive"),
            ("failed", "nginx.service is failed"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let fake = systemctl(FakeBins::new(), dir.path(), "deactivating", state);
            let (host, _sink) = fixture(&fake, "");
            let text = ok_text(
                wait(
                    &host,
                    "rita",
                    json!({"condition": "unit_inactive", "unit": "nginx", "seconds": 5}),
                )
                .await,
            );
            assert!(
                text.starts_with("Met after ") && text.contains(said),
                "{text}"
            );
            assert!(!text.starts_with("Met after 0 s"), "{text}");
        }
    }

    #[tokio::test]
    async fn waiting_on_a_unit_needs_the_right_to_see_that_unit() {
        let dir = tempfile::tempdir().unwrap();
        let fake = systemctl(FakeBins::new(), dir.path(), "active", "active");
        let (host, sink) = fixture(&fake, "");
        // wendy may see nginx
        ok_text(
            wait(
                &host,
                "wendy",
                json!({"condition": "unit_active", "unit": "nginx"}),
            )
            .await,
        );
        // but not postgresql: a wait would tell her its state
        let message = refusal(
            wait(
                &host,
                "wendy",
                json!({"condition": "unit_active", "unit": "postgresql"}),
            )
            .await,
        );
        assert!(message.starts_with("Refused:"), "{message}");
        assert!(message.contains("service.view"), "{message}");
        // walt may wait, but sees nothing
        let message = refusal(
            wait(
                &host,
                "walt",
                json!({"condition": "unit_inactive", "unit": "nginx"}),
            )
            .await,
        );
        assert!(message.contains("service.view"), "{message}");
        // vera sees everything, but may not use this tool
        let message = refusal(
            wait(
                &host,
                "vera",
                json!({"condition": "unit_active", "unit": "nginx"}),
            )
            .await,
        );
        assert!(message.starts_with("Permission denied"), "{message}");

        // the unit's state was asked for once only: for the wait that was allowed
        let looks = fake
            .calls("systemctl")
            .iter()
            .filter(|call| call[0] == "is-active")
            .count();
        assert_eq!(looks, 1);
        let decisions: Vec<&str> = sink
            .records()
            .iter()
            .map(|record| record["decision"].as_str().unwrap().to_string())
            .map(|decision| if decision == "allow" { "allow" } else { "deny" })
            .collect();
        assert_eq!(decisions, ["allow", "deny", "deny", "deny"]);
        let reason = sink.records()[1]["reason"].as_str().unwrap().to_string();
        assert!(reason.contains("service.view"), "{reason}");
    }

    /// AIDEV-NOTE: the unit is judged by its real name, which is looked up before the
    /// caller's right to see it is known. Naming that real name in the refusal would
    /// tell a caller without service.view what an alias points to.
    #[tokio::test]
    async fn a_refusal_names_the_unit_as_it_was_asked_for_not_what_it_resolves_to() {
        // sshd.service is an alias of ssh.service here
        let fake = FakeBins::new().add_script(
            "systemctl",
            "case \"$1\" in\n\
             show) printf '%s\\n' 'Id=ssh.service' 'LoadState=loaded' ;;\n\
             is-active) printf '%s\\n' 'active' ;;\n\
             esac",
        );
        let (host, sink) = fixture(&fake, "");
        // wendy may wait, and may see nginx only
        let message = refusal(
            wait(
                &host,
                "wendy",
                json!({"condition": "unit_active", "unit": "sshd"}),
            )
            .await,
        );
        assert!(message.contains("service.view"), "{message}");
        assert!(message.contains("sshd.service"), "{message}");
        assert!(!message.contains("ssh.service"), "{message}");
        // the audit trail, which is the operator's, names the real unit
        let record = sink.records().pop().unwrap();
        assert_eq!(record["decision"], "deny");
        assert_eq!(record["resource"], "unit/ssh.service");
        // and the unit's state was never asked for
        assert!(
            fake.calls("systemctl")
                .iter()
                .all(|call| call[0] != "is-active")
        );
    }

    #[tokio::test]
    async fn a_unit_that_does_not_exist_is_a_failure_after_the_permission_check() {
        let fake = FakeBins::new().add_script(
            "systemctl",
            "for last; do :; done\nprintf '%s\\n' \"Id=$last\" 'LoadState=not-found'",
        );
        let (host, _sink) = fixture(&fake, "");
        let result = wait(
            &host,
            "rita",
            json!({"condition": "unit_active", "unit": "nope"}),
        )
        .await;
        assert!(
            matches!(&result, Err(ToolError::Failed(message)) if message.contains("no such unit")),
            "{result:?}"
        );
        // someone who may not see it learns nothing about whether it exists
        let message = refusal(
            wait(
                &host,
                "wendy",
                json!({"condition": "unit_active", "unit": "nope"}),
            )
            .await,
        );
        assert!(!message.contains("no such unit"), "{message}");
    }

    #[tokio::test]
    async fn arguments_must_fit_the_condition() {
        let fake = FakeBins::new();
        let (host, sink) = fixture(&fake, "");
        for (arguments, needle) in [
            (json!({"condition": "unit_active"}), "unit"),
            (
                json!({"condition": "unit_active", "unit": "ssh*"}),
                "unit name",
            ),
            (
                json!({"condition": "unit_active", "unit": "nginx", "port": 80}),
                "port",
            ),
            (json!({"condition": "port_listening"}), "port"),
            (
                json!({"condition": "port_listening", "port": 80, "unit": "nginx"}),
                "unit",
            ),
            (json!({"condition": "file_exists"}), "path"),
            (
                json!({"condition": "file_exists", "path": "relative/path"}),
                "absolute",
            ),
            (
                json!({"condition": "file_exists", "path": "/run/../etc/passwd"}),
                "..",
            ),
            (json!({"condition": "file_exists", "path": "/run/./x"}), "."),
            (
                json!({"condition": "file_absent", "path": "/run/x", "pattern": "x"}),
                "pattern",
            ),
            (json!({"condition": "log_line", "unit": "nginx"}), "pattern"),
            (json!({"condition": "log_line", "pattern": "ready"}), "unit"),
            (
                json!({"condition": "log_line", "unit": "nginx", "pattern": "(unclosed"}),
                "regular expression",
            ),
            (
                json!({"condition": "unit_active", "unit": "nginx", "lookback_seconds": 5}),
                "lookback_seconds",
            ),
        ] {
            let message = invalid(wait(&host, "rita", arguments.clone()).await);
            assert!(message.contains(needle), "{arguments}: {message}");
        }
        // nothing was decided or run for any of them
        assert_eq!(sink.records().len(), 0);
    }

    #[tokio::test]
    async fn a_port_is_watched_in_the_kernel_table_and_needs_net_view() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("tcp"), TCP).unwrap();
        let fake = FakeBins::new();
        let (host, sink) = fixture(&fake, "");
        let text = ok_text(
            wait_in(
                &host,
                dir.path(),
                "rita",
                json!({"condition": "port_listening", "port": 8080}),
            )
            .await,
        );
        assert_eq!(
            text,
            "Met after 0 s: something is listening on TCP port 8080.\n"
        );
        let text = ok_text(
            wait_in(
                &host,
                dir.path(),
                "rita",
                json!({"condition": "port_closed", "port": 9999}),
            )
            .await,
        );
        assert_eq!(
            text,
            "Met after 0 s: nothing is listening on TCP port 9999.\n"
        );
        let text = failed_text(
            wait_in(
                &host,
                dir.path(),
                "rita",
                json!({"condition": "port_listening", "port": 9999, "seconds": 1}),
            )
            .await,
        );
        assert_eq!(
            text,
            "Not met within 1 s: nothing is listening on TCP port 9999.\n"
        );
        assert_eq!(sink.records()[0]["resource"], "port/8080");

        // wendy holds wait.use but not net.view
        let message = refusal(
            wait_in(
                &host,
                dir.path(),
                "wendy",
                json!({"condition": "port_listening", "port": 8080}),
            )
            .await,
        );
        assert!(message.contains("net.view"), "{message}");
    }

    #[tokio::test]
    async fn a_socket_table_that_cannot_be_read_is_an_error_not_a_closed_port() {
        let fake = FakeBins::new();
        let (host, _sink) = fixture(&fake, "");
        let result = wait(
            &host,
            "rita",
            json!({"condition": "port_closed", "port": 80}),
        )
        .await;
        assert!(matches!(result, Err(ToolError::Failed(_))), "{result:?}");
    }

    #[tokio::test]
    async fn a_file_is_waited_for_until_it_appears_or_goes() {
        let dir = tempfile::tempdir().unwrap();
        let ready = dir.path().join("ready");
        let fake = FakeBins::new();
        let (host, sink) = fixture(&fake, "");
        let path = ready.to_str().unwrap().to_string();

        let text = ok_text(
            wait(
                &host,
                "rita",
                json!({"condition": "file_absent", "path": path}),
            )
            .await,
        );
        assert_eq!(text, format!("Met after 0 s: {path} does not exist.\n"));
        let real = std::fs::canonicalize(dir.path()).unwrap().join("ready");
        assert_eq!(
            sink.records()[0]["resource"],
            format!("file/{}", real.display())
        );

        // it appears while the wait is under way
        let later = ready.clone();
        let writer = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            std::fs::write(later, "x").unwrap();
        });
        let text = ok_text(
            wait(
                &host,
                "rita",
                json!({"condition": "file_exists", "path": path, "seconds": 5}),
            )
            .await,
        );
        writer.await.unwrap();
        assert!(
            text.starts_with("Met after ") && text.ends_with(&format!(": {path} exists.\n")),
            "{text}"
        );
        assert!(!text.starts_with("Met after 0 s"), "{text}");

        let text = failed_text(
            wait(
                &host,
                "rita",
                json!({"condition": "file_absent", "path": path, "seconds": 1}),
            )
            .await,
        );
        assert_eq!(text, format!("Not met within 1 s: {path} exists.\n"));
    }

    #[tokio::test]
    async fn a_file_is_only_watched_where_fs_stat_would_show_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let open = root.join("open");
        let closed = root.join("closed");
        std::fs::create_dir(&open).unwrap();
        std::fs::create_dir(&closed).unwrap();
        std::fs::write(open.join("here"), "x").unwrap();
        std::fs::write(closed.join("secret"), "x").unwrap();
        std::fs::write(open.join("server.key"), "x").unwrap();
        // a way from the open directory into the closed one
        std::os::unix::fs::symlink(&closed, open.join("door")).unwrap();
        let outside = tempfile::tempdir().unwrap();

        let fake = FakeBins::new();
        let extra = format!(
            "[roles.files]\nallow = [\"wait.use\", \"fs.view:{open}/**\"]\n\
             [unix_users.fred]\nroles = [\"files\"]\n\
             [fs]\nlist_roots = [\"{root}\"]\ndeny = [\"**/*.key\"]\n",
            open = open.display(),
            root = root.display()
        );
        let (host, sink) = fixture(&fake, &extra);
        let at = |path: &Path| path.to_str().unwrap().to_string();

        // where he may look, he may wait
        ok_text(
            wait(
                &host,
                "fred",
                json!({"condition": "file_exists", "path": at(&open.join("here"))}),
            )
            .await,
        );
        ok_text(
            wait(
                &host,
                "fred",
                json!({"condition": "file_absent", "path": at(&open.join("later"))}),
            )
            .await,
        );

        // not in a directory he has no grant for, whether the file is there or not
        for name in ["secret", "nothing"] {
            let message = refusal(
                wait(
                    &host,
                    "fred",
                    json!({"condition": "file_exists", "path": at(&closed.join(name))}),
                )
                .await,
            );
            assert!(message.contains("fs.view"), "{message}");
        }
        // nor through a link that leads there: the answers must not differ
        let mut through_the_door = Vec::new();
        for name in ["secret", "nothing"] {
            through_the_door.push(refusal(
                wait(
                    &host,
                    "fred",
                    json!({"condition": "file_exists", "path": at(&open.join("door").join(name))}),
                )
                .await,
            ));
        }
        assert!(
            through_the_door[0].contains("fs.view"),
            "{through_the_door:?}"
        );
        assert_eq!(
            through_the_door[0].replace("secret", "X"),
            through_the_door[1].replace("nothing", "X")
        );
        // never what the filesystem tools never show
        let message = refusal(
            wait(
                &host,
                "rita",
                json!({"condition": "file_exists", "path": at(&open.join("server.key"))}),
            )
            .await,
        );
        assert!(message.contains("never-readable"), "{message}");
        // nor outside the directories this host allows at all, there or not
        for name in ["x", "y/z"] {
            let message = refusal(
                wait(
                    &host,
                    "rita",
                    json!({"condition": "file_absent", "path": at(&outside.path().join(name))}),
                )
                .await,
            );
            assert!(message.contains("fs.list_roots"), "{message}");
        }
        // every refusal is in the audit trail
        let denials = sink
            .records()
            .iter()
            .filter(|record| record["decision"] == "deny")
            .count();
        assert_eq!(denials, 7);
    }

    /// AIDEV-NOTE: the name a grant or a deny for wait.use is matched against is the
    /// file's REAL path. Were it the path as written, a deny for a directory could be
    /// stepped around through a link that leads into it.
    #[tokio::test]
    async fn a_file_wait_is_authorized_by_the_real_path_of_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let real = root.join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(real.join("flag"), "x").unwrap();
        std::os::unix::fs::symlink(&real, root.join("link")).unwrap();
        let fake = FakeBins::new();
        // pia may look everywhere, and wait anywhere except under the real directory
        let extra = format!(
            "[roles.picky]\nallow = [\"wait.use\", \"fs.view\"]\n\
             deny = [\"wait.use:file/{real}/**\"]\n\
             [unix_users.pia]\nroles = [\"picky\"]\n",
            real = real.display()
        );
        let (host, sink) = fixture(&fake, &extra);
        let at = |path: &Path| path.to_str().unwrap().to_string();

        // through the link, a file that is there and one that is not: both refused
        for name in ["flag", "nothing"] {
            let through = root.join("link").join(name);
            let result = wait(
                &host,
                "pia",
                json!({"condition": "file_exists", "path": at(&through), "seconds": 1}),
            )
            .await;
            assert!(
                matches!(result, Err(ToolError::Denied(_))),
                "{name}: {result:?}"
            );
            let record = sink.records().pop().unwrap();
            assert_eq!(record["decision"], "deny");
            assert_eq!(record["resource"], format!("file/{}", at(&real.join(name))));
        }
        // elsewhere she may wait, and the record names the real path there too
        ok_text(
            wait(
                &host,
                "pia",
                json!({"condition": "file_absent", "path": at(&root.join("other"))}),
            )
            .await,
        );
        let record = sink.records().pop().unwrap();
        assert_eq!(record["decision"], "allow");
        assert_eq!(
            record["resource"],
            format!("file/{}", at(&root.join("other")))
        );
    }

    /// What is at the path can change while the wait is under way. If it then lies
    /// somewhere this caller may not wait on, the wait ends with a refusal.
    #[tokio::test]
    async fn a_path_that_comes_to_lead_somewhere_else_is_judged_again() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let closed = root.join("closed");
        std::fs::create_dir(&closed).unwrap();
        std::fs::write(closed.join("flag"), "x").unwrap();
        let fake = FakeBins::new();
        let extra = format!(
            "[roles.picky]\nallow = [\"wait.use\", \"fs.view\"]\n\
             deny = [\"wait.use:file/{closed}/**\"]\n\
             [unix_users.pia]\nroles = [\"picky\"]\n",
            closed = closed.display()
        );
        let (host, _sink) = fixture(&fake, &extra);
        // `spot` does not exist yet: waiting for spot/flag is allowed as written
        let spot = root.join("spot");
        let path = spot.join("flag").to_str().unwrap().to_string();
        let (link, target) = (spot.clone(), closed.clone());
        let switcher = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            // now `spot` becomes a way into the closed directory
            std::os::unix::fs::symlink(target, link).unwrap();
        });
        let result = wait(
            &host,
            "pia",
            json!({"condition": "file_exists", "path": path, "seconds": 5}),
        )
        .await;
        switcher.await.unwrap();
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
    }

    /// One journal entry as `journalctl --output=json` prints it.
    fn entry(cursor: &str, at: i64, message: &str) -> String {
        format!(
            "{}\n",
            json!({"__CURSOR": cursor, "__REALTIME_TIMESTAMP": format!("{}", at * 1_000_000), "MESSAGE": message})
        )
    }

    /// A journalctl stand-in that prints `first` the first time and `then` afterwards.
    fn journalctl(dir: &Path, first: &str, then: &str) -> FakeBins {
        std::fs::write(dir.join("first"), first).unwrap();
        std::fs::write(dir.join("then"), then).unwrap();
        let at = dir.display().to_string();
        FakeBins::new().add_script(
            "journalctl",
            &format!(
                "if [ -f '{at}/seen' ]; then file='{at}/then'; else : > '{at}/seen'; file='{at}/first'; fi\n\
                 while IFS= read -r line; do printf '%s\\n' \"$line\"; done < \"$file\""
            ),
        )
    }

    #[tokio::test]
    async fn a_log_line_is_found_as_soon_as_it_is_logged() {
        let dir = tempfile::tempdir().unwrap();
        let now = now_secs();
        let first =
            entry("s=1;i=a", now, "starting up") + &entry("s=1;i=b", now, "loading modules");
        let then = entry("s=1;i=c", now, "still loading")
            + &entry(
                "s=1;i=d",
                now,
                "ready to accept connections on port 5432 password=hunter2",
            )
            + &entry("s=1;i=e", now, "ready again");
        let fake = journalctl(dir.path(), &first, &then);
        let (host, sink) = fixture(&fake, "");
        let before = now_secs();
        let text = ok_text(
            wait(
                &host,
                "wendy",
                json!({"condition": "log_line", "unit": "nginx", "pattern": "^ready to accept", "seconds": 10}),
            )
            .await,
        );
        assert!(text.starts_with("Met after "), "{text}");
        assert!(!text.starts_with("Met after 0 s"), "{text}");
        assert!(
            text.contains(" s: nginx.service logged a matching line:\n"),
            "{text}"
        );
        assert!(
            text.contains("ready to accept connections on port 5432"),
            "{text}"
        );
        // secrets in a log line are masked
        assert!(!text.contains("hunter2"), "{text}");
        // only the first match is returned
        assert!(!text.contains("ready again"), "{text}");
        assert_eq!(sink.records()[0]["resource"], "log/nginx.service");

        let calls = fake.calls("journalctl");
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert_eq!(
            calls[0][..5],
            [
                "--no-pager",
                "--quiet",
                "--output=json",
                "--output-fields=MESSAGE",
                "--unit=nginx.service"
            ]
        );
        // the first look starts at the moment the call began
        let since: i64 = calls[0][5]
            .strip_prefix("--since=@")
            .unwrap()
            .parse()
            .unwrap();
        assert!(
            (before - 1..=before + 1).contains(&since),
            "{since} vs {before}"
        );
        // later looks carry on after the last entry seen
        assert_eq!(calls[1][5], "--after-cursor=s=1;i=b");
    }

    #[tokio::test]
    async fn a_log_wait_can_reach_back_and_gives_up_in_time() {
        let dir = tempfile::tempdir().unwrap();
        let now = now_secs();
        let fake = journalctl(dir.path(), &entry("s=1;i=a", now, "nothing of note"), "");
        let (host, _sink) = fixture(&fake, "");
        let before = now_secs();
        let text = failed_text(
            wait(
                &host,
                "rita",
                json!({"condition": "log_line", "unit": "nginx", "pattern": "ready", "seconds": 1, "lookback_seconds": 120}),
            )
            .await,
        );
        assert!(
            text.starts_with(
                "Not met within 1 s: no line of nginx.service has matched (1 examined)."
            ),
            "{text}"
        );
        let calls = fake.calls("journalctl");
        let since: i64 = calls[0][5]
            .strip_prefix("--since=@")
            .unwrap()
            .parse()
            .unwrap();
        assert!(
            (before - 121..=before - 119).contains(&since),
            "{since} vs {before}"
        );
    }

    #[tokio::test]
    async fn a_long_matching_line_is_cut_and_stays_on_one_line() {
        let dir = tempfile::tempdir().unwrap();
        let now = now_secs();
        let message = format!("ready\nsecond line {}", "x".repeat(600));
        let fake = journalctl(dir.path(), &entry("s=1;i=a", now, &message), "");
        let (host, _sink) = fixture(&fake, "");
        let text = ok_text(
            wait(
                &host,
                "rita",
                json!({"condition": "log_line", "unit": "nginx", "pattern": "ready"}),
            )
            .await,
        );
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert!(
            lines[1].chars().count() <= 340,
            "{}",
            lines[1].chars().count()
        );
        assert!(lines[1].ends_with("..."), "{text}");
    }

    #[tokio::test]
    async fn watching_a_units_log_needs_the_right_to_read_that_log() {
        let dir = tempfile::tempdir().unwrap();
        let fake = journalctl(
            dir.path(),
            &entry("s=1;i=a", now_secs(), "secret thing"),
            "",
        );
        let (host, _sink) = fixture(&fake, "");
        // wendy may read nginx's log only
        let message = refusal(
            wait(
                &host,
                "wendy",
                json!({"condition": "log_line", "unit": "postgresql", "pattern": "secret"}),
            )
            .await,
        );
        assert!(message.contains("journal.view"), "{message}");
        let message = refusal(
            wait(
                &host,
                "walt",
                json!({"condition": "log_line", "unit": "nginx", "pattern": "secret"}),
            )
            .await,
        );
        assert!(message.contains("journal.view"), "{message}");
        assert_eq!(fake.calls("journalctl").len(), 0);
    }

    #[tokio::test]
    async fn a_journal_that_cannot_be_read_ends_the_wait_with_its_error() {
        let fake = FakeBins::new().add_script(
            "journalctl",
            "printf '%s\\n' 'Failed to open journal: Permission denied' >&2; exit 2",
        );
        let (host, _sink) = fixture(&fake, "");
        let result = wait(
            &host,
            "rita",
            json!({"condition": "log_line", "unit": "nginx", "pattern": "x", "seconds": 30}),
        )
        .await;
        assert!(
            matches!(&result, Err(ToolError::Failed(message)) if message.contains("Failed to open journal")),
            "{result:?}"
        );
    }

    /// AIDEV-NOTE: a journalctl that is stopped at its time limit before it has printed
    /// one whole entry has not looked at anything. That is "could not look", and must
    /// not end as "no line has matched (0 examined)".
    #[tokio::test]
    async fn a_journal_that_cannot_be_read_in_time_is_not_reported_as_no_match() {
        // never prints, never ends (stand-ins have only shell built-ins)
        let fake = FakeBins::new().add_script("journalctl", "while :; do :; done");
        let (host, _sink) = fixture(
            &fake,
            "[limits]\ncommand_timeout_secs = 1\ncall_timeout_secs = 30\n",
        );
        let began = std::time::Instant::now();
        let result = wait(
            &host,
            "rita",
            json!({"condition": "log_line", "unit": "nginx", "pattern": "ready", "seconds": 10}),
        )
        .await;
        let message = match result {
            Err(ToolError::Failed(message)) => message,
            other => panic!("expected a failure, got {other:?}"),
        };
        assert!(message.contains("could not be read in time"), "{message}");
        assert!(message.contains("nginx.service"), "{message}");
        assert!(!message.contains("examined"), "{message}");
        // it gave up after the first look instead of trying for the whole wait
        assert!(began.elapsed() < std::time::Duration::from_secs(6));
        assert_eq!(fake.calls("journalctl").len(), 1);
    }

    /// AIDEV-NOTE: a wait holds one of the server's call slots for its whole length.
    /// Without a limit of its own, a caller starting as many waits as there are slots
    /// would leave none for anyone else.
    #[tokio::test]
    async fn only_half_of_the_call_slots_may_be_held_by_waits() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("tcp"), TCP).unwrap();
        let fake = FakeBins::new();
        // two call slots: one wait at a time
        let (host, sink) = fixture(&fake, "[limits]\nmax_concurrent_calls = 2\n");
        let places = Places {
            proc_net: dir.path().to_path_buf(),
        };
        // one tool, as one server has
        let tool = find(tools_with(places), "wait_for");
        let arguments = json!({"condition": "port_listening", "port": 9, "seconds": 2});
        let (first, second) = tokio::join!(
            call(&host, "rita", &tool, arguments.clone()),
            call(&host, "rita", &tool, arguments.clone()),
        );
        let mut refused = 0;
        let mut waited = 0;
        for result in [first, second] {
            match result {
                Err(ToolError::Failed(message)) => {
                    assert!(
                        message.contains("too many waits are in progress"),
                        "{message}"
                    );
                    refused += 1;
                }
                Ok(output) => {
                    assert!(
                        output.text().starts_with("Not met within 2 s"),
                        "{output:?}"
                    );
                    waited += 1;
                }
                other => panic!("unexpected: {other:?}"),
            }
        }
        assert_eq!((waited, refused), (1, 1));
        // both calls were authorized (and so recorded) before one was turned away
        let allowed = sink
            .records()
            .iter()
            .filter(|record| record["decision"] == "allow")
            .count();
        assert_eq!(allowed, 2);
        // with the first one over there is room again
        let again = call(
            &host,
            "rita",
            &tool,
            json!({"condition": "port_listening", "port": 8080}),
        )
        .await;
        assert_eq!(
            ok_text(again),
            "Met after 0 s: something is listening on TCP port 8080.\n"
        );
    }

    #[test]
    fn the_number_of_waits_at_once_is_half_the_call_slots_and_at_least_one() {
        assert_eq!(waits_at_once(8), 4);
        assert_eq!(waits_at_once(3), 1);
        assert_eq!(waits_at_once(2), 1);
        assert_eq!(waits_at_once(1), 1);
        assert_eq!(waits_at_once(256), 128);
    }

    #[tokio::test]
    async fn a_wait_longer_than_the_call_allows_is_shortened_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let fake = systemctl(FakeBins::new(), dir.path(), "activating", "activating");
        let (host, _sink) = fixture(
            &fake,
            "[limits]\ncall_timeout_secs = 4\ncommand_timeout_secs = 2\n",
        );
        let started = std::time::Instant::now();
        let text = failed_text(
            wait(
                &host,
                "rita",
                json!({"condition": "unit_active", "unit": "nginx", "seconds": 600}),
            )
            .await,
        );
        assert!(started.elapsed().as_secs() < 4, "{:?}", started.elapsed());
        assert!(
            text.starts_with("Not met within 2 s: nginx.service is activating."),
            "{text}"
        );
        assert!(text.contains("shortened"), "{text}");
        assert!(text.contains("limits.call_timeout_secs"), "{text}");
    }

    #[tokio::test]
    async fn only_a_real_journal_cursor_is_passed_back_to_journalctl() {
        let dir = tempfile::tempdir().unwrap();
        let now = now_secs();
        // an entry whose cursor is not a cursor: an option in disguise
        let first = entry("--file=/etc/shadow", now, "starting up");
        let fake = journalctl(dir.path(), &first, "");
        let (host, _sink) = fixture(&fake, "");
        failed_text(
            wait(
                &host,
                "rita",
                json!({"condition": "log_line", "unit": "nginx", "pattern": "ready", "seconds": 2}),
            )
            .await,
        );
        let calls = fake.calls("journalctl");
        assert_eq!(calls.len(), 2, "{calls:?}");
        for call in &calls {
            assert_eq!(call.len(), 6, "{call:?}");
            assert!(call[5].starts_with("--since=@"), "{call:?}");
        }
        assert!(is_cursor(
            "s=e4efb177;i=67d5c3;b=a67734fb;m=24ffa6c85cd;t=660c216d50633;x=90356e"
        ));
        for bad in [
            "",
            "--file=/etc/shadow",
            "s=1 --file=x",
            "s=1\n",
            &"a".repeat(513),
        ] {
            assert!(!is_cursor(bad), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn a_message_that_is_not_utf8_is_still_matched() {
        let dir = tempfile::tempdir().unwrap();
        // journalctl prints such a message as an array of bytes
        let bytes: Vec<u8> = b"ready \xff now".to_vec();
        let first = format!(
            "{}\n",
            json!({"__CURSOR": "s=1;i=a", "__REALTIME_TIMESTAMP": "1795194000000000", "MESSAGE": bytes})
        );
        let fake = journalctl(dir.path(), &first, "");
        let (host, _sink) = fixture(&fake, "");
        let text = ok_text(
            wait(
                &host,
                "rita",
                json!({"condition": "log_line", "unit": "nginx", "pattern": "^ready"}),
            )
            .await,
        );
        assert!(text.contains("2026-11-20T17:00:00Z ready"), "{text}");
    }

    #[tokio::test]
    async fn an_answer_from_systemctl_that_is_not_a_state_is_shown_as_unknown() {
        let fake = FakeBins::new().add_script(
            "systemctl",
            "for last; do :; done\n\
             case \"$1\" in\n\
             show) printf '%s\\n' \"Id=$last\" 'LoadState=loaded' ;;\n\
             is-active) printf '%s\\n' 'active now' 'Met after 0 s: all is well' ;;\n\
             esac",
        );
        let (host, _sink) = fixture(&fake, "");
        let text = failed_text(
            wait(
                &host,
                "rita",
                json!({"condition": "unit_active", "unit": "nginx", "seconds": 1}),
            )
            .await,
        );
        assert_eq!(text, "Not met within 1 s: nginx.service is unknown.\n");
    }
}
