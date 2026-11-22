//! Recent AppArmor, SELinux and seccomp denials.
//!
//! AIDEV-NOTE: the same denial can reach us twice. The kernel's audit records go to the
//! journal (as kernel messages, or through journald's audit socket) and, where auditd
//! runs, to /var/log/audit/audit.log. Both are read, and a record is counted once: its
//! audit time stamp and serial number, which every copy carries, tell the copies apart
//! from new records.

use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};
use serde_json::Value;

use super::args::{Args, Param};
use super::triage::{field_text, no_entries};
use super::{Ctx, Tool, ToolResult, blocking, command_text, format_table};
use crate::policy::Access;
use crate::sanitize::{keep_head, redact_text};
use crate::timefmt::{now_secs, rfc3339_utc};

/// What journalctl is asked to find. Upper case on purpose: journalctl matches without
/// regard to case only when a pattern is all lower case.
const JOURNAL_PATTERN: &str =
    r#"apparmor="(DENIED|ALLOWED|KILLED)"|avc: +denied|type=1326 |^SECCOMP "#;
/// Most journalctl output that is kept.
const MAX_JOURNAL_BYTES: usize = 8 << 20;
/// Most that is read from the end of the audit logs, in all.
const MAX_AUDIT_BYTES: u64 = 16 << 20;
/// A journal entry longer than this is skipped (see `triage::summarize`).
const MAX_ENTRY_BYTES: usize = 256 * 1024;
const EXAMPLE_CHARS: usize = 200;
const CELL_CHARS: usize = 60;
const PROGRAM_CHARS: usize = 32;

/// Where the kernel and auditd keep what this tool reads. Tests point these at a
/// temporary directory.
#[derive(Clone, Debug)]
pub struct Paths {
    /// `/sys/kernel/security/apparmor`
    pub apparmor: PathBuf,
    /// `/sys/fs/selinux`
    pub selinux: PathBuf,
    /// auditd's log files, newest first.
    pub audit_logs: Vec<PathBuf>,
}

impl Paths {
    pub fn system() -> Paths {
        Paths {
            apparmor: PathBuf::from("/sys/kernel/security/apparmor"),
            selinux: PathBuf::from("/sys/fs/selinux"),
            audit_logs: vec![
                PathBuf::from("/var/log/audit/audit.log"),
                PathBuf::from("/var/log/audit/audit.log.1"),
            ],
        }
    }
}

pub fn tools() -> Vec<Tool> {
    tools_with(Paths::system())
}

pub fn tools_with(paths: Paths) -> Vec<Tool> {
    vec![Tool::new(
        "security_denials",
        "List what AppArmor, SELinux and seccomp refused recently, grouped by program: how \
         often, what was refused (the operation or permission), on what, and when last. \
         Use it when a program fails with 'permission denied' or is killed although its \
         file permissions and user look right: a security profile is the usual hidden \
         cause. The first line is the verdict; denials that were only logged (complain or \
         permissive mode) are marked.",
        Access::Read,
        "security.view",
        vec![
            Param::int("hours", "How far back to look (default 24)", 1, 168),
            Param::int("limit", "Most groups to show (default 20)", 1, 100),
        ],
        move |ctx, args| security_denials(ctx, args, paths.clone()),
    )]
}

// ---- one audit record -------------------------------------------------------------------

/// What kind of record its type says it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hint {
    /// An access-vector record: AppArmor and SELinux both use these.
    Avc,
    Seccomp,
    /// The type is missing or is neither: the text decides.
    Unknown,
}

/// The type of an audit record, by name (audit.log) or by number (the kernel log).
pub fn hint(record_type: &str) -> Hint {
    match record_type {
        "AVC" | "USER_AVC" | "1400" | "1107" => Hint::Avc,
        "SECCOMP" | "1326" => Hint::Seccomp,
        _ => Hint::Unknown,
    }
}

/// One record as it was found, before it is understood.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Raw {
    pub hint: Hint,
    /// When the kernel made the record, in milliseconds since 1970.
    pub when_ms: u64,
    /// The audit serial number, when the source gave one.
    pub serial: Option<u64>,
    /// The record itself: the `key=value` text.
    pub body: String,
}

/// Takes apart a line that carries the audit header: `type=AVC msg=audit(1700000000.123:45):
/// BODY` (audit.log) or `audit: type=1400 audit(1700000000.123:45): BODY` (kernel log).
pub fn split_audit_line(line: &str) -> Option<Raw> {
    let at = line.find("audit(")?;
    let before = line.get(..at)?;
    let after = line.get(at + "audit(".len()..)?;
    let (stamp, rest) = after.split_once(')')?;
    let (time, serial) = stamp.split_once(':')?;
    let (secs, millis) = time.split_once('.').unwrap_or((time, "0"));
    let secs: u64 = secs.parse().ok()?;
    let millis: u64 = millis.get(..millis.len().min(3))?.parse().ok()?;
    let serial: u64 = serial.parse().ok()?;
    let record_type = before
        .rsplit_once("type=")
        .map(|(_, rest)| rest.split_whitespace().next().unwrap_or(""))
        .unwrap_or("");
    Some(Raw {
        hint: hint(record_type),
        when_ms: secs.saturating_mul(1000).saturating_add(millis),
        serial: Some(serial),
        body: rest.strip_prefix(':').unwrap_or(rest).trim().to_string(),
    })
}

/// Whether a journal entry was written by the kernel or came through journald's audit
/// socket, as opposed to by a program.
///
/// AIDEV-NOTE: this is what keeps forged denials out. Any local user can put a line into
/// the journal that reads exactly like one (`logger 'apparmor="DENIED" ... comm="sshd"
/// name="/etc/shadow"'`), and an agent would act on it. Real ones are written only by the
/// kernel (`_TRANSPORT=kernel`) or arrive on the audit socket (`_TRANSPORT=audit`, with
/// `_AUDIT_TYPE`). Fields whose names begin with an underscore are set by journald
/// itself; a client cannot supply them. journalctl is asked for these transports only
/// (`journal_argv`), and every entry is checked again here.
pub fn from_the_kernel(entry: &serde_json::Map<String, Value>) -> bool {
    let transport = field_text(entry.get("_TRANSPORT"));
    matches!(transport.as_deref(), Some("kernel" | "audit")) || entry.contains_key("_AUDIT_TYPE")
}

/// One journal entry (`journalctl --output=json`) as a record, if it is one. An entry
/// that did not come from the kernel or the audit socket is never one.
pub fn journal_raw(entry: &serde_json::Map<String, Value>) -> Option<Raw> {
    if !from_the_kernel(entry) {
        return None;
    }
    let message = field_text(entry.get("MESSAGE"))?;
    let number =
        |name: &str| field_text(entry.get(name)).and_then(|text| text.trim().parse::<u64>().ok());
    let logged_ms = number("__REALTIME_TIMESTAMP").map(|usec| usec / 1000);
    if let Some(audit_type) = number("_AUDIT_TYPE") {
        // journald's audit socket: the header is gone from the message (which now starts
        // with the type's name), and the fields carry what it held.
        let body = match message.split_once(' ') {
            Some((name, rest)) if name.bytes().all(|b| b.is_ascii_uppercase() || b == b'_') => rest,
            _ => message.as_str(),
        };
        return Some(Raw {
            hint: hint(&audit_type.to_string()),
            when_ms: number("_SOURCE_REALTIME_TIMESTAMP")
                .map(|usec| usec / 1000)
                .or(logged_ms)?,
            serial: number("_AUDIT_ID"),
            body: body.trim().to_string(),
        });
    }
    if let Some(raw) = split_audit_line(&message) {
        return Some(raw);
    }
    // No audit header at all (a kernel message that is not an audit record): the text
    // decides.
    Some(Raw {
        hint: Hint::Unknown,
        when_ms: logged_ms?,
        serial: None,
        body: message.trim().to_string(),
    })
}

/// The `key=value` pairs of a record, in order, with whether the value was in quotes.
///
/// AIDEV-NOTE: the kernel writes a value it does not trust either in double quotes
/// (then it holds no quote, space or control character) or, if it holds any of those,
/// as hexadecimal without quotes. Values the kernel composes itself, and records made
/// in user space, can be quoted and hold spaces. So: a quoted value runs to the next
/// quote, an unquoted one to the next white space.
pub fn pairs(body: &str) -> Vec<(&str, &str, bool)> {
    let bytes = body.as_bytes();
    let is_key = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'-';
    let at = |i: usize| bytes.get(i).copied();
    let mut found = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !at(i).is_some_and(is_key) {
            i += 1;
            continue;
        }
        let start = i;
        while at(i).is_some_and(is_key) {
            i += 1;
        }
        if at(i) != Some(b'=') {
            // a word that is not a key: on to the next white space
            while at(i).is_some_and(|b| !b.is_ascii_whitespace()) {
                i += 1;
            }
            continue;
        }
        let key = body.get(start..i).unwrap_or("");
        i += 1;
        if at(i) == Some(b'"') {
            i += 1;
            let value_start = i;
            while at(i).is_some_and(|b| b != b'"') {
                i += 1;
            }
            found.push((key, body.get(value_start..i).unwrap_or(""), true));
            i += 1;
        } else {
            let value_start = i;
            while at(i).is_some_and(|b| !b.is_ascii_whitespace()) {
                i += 1;
            }
            // a record wrapped in msg='...' ends in the closing quote
            let value = body.get(value_start..i).unwrap_or("");
            found.push((key, value.trim_end_matches('\''), false));
        }
    }
    found
}

/// A value the kernel did not trust: as it stands if it was quoted, decoded if it was
/// written as hexadecimal.
fn untrusted(value: &str, quoted: bool) -> String {
    let is_hex = !quoted
        && value.len() >= 2
        && value.len().is_multiple_of(2)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b));
    if !is_hex {
        return value.to_string();
    }
    let decoded: Option<Vec<u8>> = value
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|digits| u8::from_str_radix(digits, 16).ok())
        })
        .collect();
    match decoded {
        Some(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        None => value.to_string(),
    }
}

/// The fields of a record that the tool uses, looked up by name. The first of a name
/// wins, except that an empty or `(null)` value is passed over.
struct Fields<'a>(Vec<(&'a str, &'a str, bool)>);

impl Fields<'_> {
    fn find(&self, key: &str) -> Option<(&str, bool)> {
        self.0
            .iter()
            .find(|(name, value, _)| *name == key && !value.is_empty() && *value != "(null)")
            .map(|(_, value, quoted)| (*value, *quoted))
    }

    /// A value the kernel composes itself (a number, a keyword, a security context):
    /// taken as it stands.
    fn get(&self, key: &str) -> Option<String> {
        self.find(key).map(|(value, _)| value.to_string())
    }

    /// A name that comes from outside the kernel (a command, a path, a profile): these
    /// are the fields that are written as hexadecimal when they hold odd characters.
    ///
    /// AIDEV-NOTE: only for such fields. Decoding everything that looks like
    /// hexadecimal would turn `syscall=41` into `A`.
    fn name(&self, key: &str) -> Option<String> {
        self.find(key)
            .map(|(value, quoted)| untrusted(value, quoted))
    }
}

fn base_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Which mechanism refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    AppArmor,
    SELinux,
    Seccomp,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::AppArmor => "AppArmor",
            Kind::SELinux => "SELinux",
            Kind::Seccomp => "seccomp",
        }
    }
}

/// One denial, reduced to what makes two denials "the same thing again".
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Denial {
    pub kind: Kind,
    pub program: String,
    /// The operation or permission that was refused.
    pub refused: String,
    /// What it was refused on, or `-`.
    pub target: String,
    /// False when the denial was only logged (complain or permissive mode): the
    /// program was let through.
    pub enforced: bool,
}

fn apparmor(body: &str) -> Option<Denial> {
    let fields = Fields(pairs(body));
    let enforced = match fields.get("apparmor")?.as_str() {
        "DENIED" | "KILLED" => true,
        "ALLOWED" => false,
        // STATUS, AUDIT and the like are not denials
        _ => return None,
    };
    let mut refused = fields.get("operation").unwrap_or_else(|| "?".to_string());
    let detail = fields
        .get("denied_mask")
        .or_else(|| fields.get("capname"))
        .or_else(|| match (fields.get("family"), fields.get("sock_type")) {
            (Some(family), Some(kind)) => Some(format!("{family} {kind}")),
            (Some(family), None) => Some(family),
            _ => None,
        })
        .or_else(|| fields.get("signal"));
    if let Some(detail) = detail {
        refused.push(' ');
        refused.push_str(&detail);
    }
    Some(Denial {
        kind: Kind::AppArmor,
        program: fields
            .name("comm")
            .or_else(|| fields.name("profile"))
            .unwrap_or_else(|| "?".to_string()),
        refused,
        target: fields
            .name("name")
            .or_else(|| fields.name("peer"))
            .unwrap_or_else(|| "-".to_string()),
        enforced,
    })
}

fn selinux(body: &str) -> Option<Denial> {
    let rest = body.get(body.find("avc:")? + "avc:".len()..)?;
    let (verdict, rest) = rest.split_once('{')?;
    if verdict.trim() != "denied" {
        // "granted" is an audited permission, not a denial
        return None;
    }
    let (permissions, rest) = rest.split_once('}')?;
    let permissions = permissions.split_whitespace().collect::<Vec<_>>().join(" ");
    let fields = Fields(pairs(rest));
    let class = fields.get("tclass").unwrap_or_else(|| "?".to_string());
    let program = fields
        .name("comm")
        .or_else(|| fields.name("exe").map(|exe| base_name(&exe).to_string()))
        .or_else(|| {
            // the type of the source context: user:role:TYPE:level
            let context = fields.get("scontext")?;
            context.split(':').nth(2).map(str::to_string)
        })
        .unwrap_or_else(|| "?".to_string());
    Some(Denial {
        kind: Kind::SELinux,
        program,
        refused: format!("{permissions} on {class}"),
        target: fields
            .name("path")
            .or_else(|| fields.name("name"))
            .or_else(|| fields.get("tcontext"))
            .unwrap_or_else(|| "-".to_string()),
        enforced: fields.get("permissive").as_deref() != Some("1"),
    })
}

fn seccomp(body: &str) -> Option<Denial> {
    let fields = Fields(pairs(body));
    let syscall = fields.get("syscall")?;
    // What the filter did, from the action bits of its return value.
    let code = fields
        .get("code")
        .and_then(|code| u64::from_str_radix(code.trim_start_matches("0x"), 16).ok());
    let (action, enforced) = match code.map(|code| code & 0xffff_0000) {
        Some(0x8000_0000) | Some(0x0000_0000) => ("killed", true),
        Some(0x0003_0000) => ("trapped", true),
        Some(0x0005_0000) => ("error returned", true),
        Some(0x7ffc_0000) => ("logged only", false),
        Some(0x7fff_0000) => return None,
        _ => ("refused", true),
    };
    Some(Denial {
        kind: Kind::Seccomp,
        program: fields
            .name("comm")
            .or_else(|| fields.name("exe").map(|exe| base_name(&exe).to_string()))
            .unwrap_or_else(|| "?".to_string()),
        refused: format!("syscall {syscall}, {action}"),
        target: "-".to_string(),
        enforced,
    })
}

/// Understands one record. `None` for a record that is not a denial.
pub fn parse_denial(raw: &Raw) -> Option<Denial> {
    let body = raw.body.as_str();
    if body.contains("apparmor=") {
        return apparmor(body);
    }
    if body.contains("avc:") {
        return selinux(body);
    }
    match raw.hint {
        Hint::Seccomp => seccomp(body),
        // without a type, only a line that says it is one
        Hint::Unknown if body.contains("SECCOMP") || body.contains("type=1326") => seccomp(body),
        _ => None,
    }
}

// ---- collecting -------------------------------------------------------------------------

/// The denials that are the same thing, counted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    pub denial: Denial,
    pub count: u64,
    /// When it last happened, in milliseconds since 1970.
    pub last_ms: u64,
    /// The newest record, with likely secrets masked, on one line and cut short.
    pub example: String,
}

fn one_line_cut(text: &str, max: usize) -> String {
    let joined = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if joined.chars().count() <= max {
        return joined;
    }
    let mut kept: String = joined.chars().take(max).collect();
    kept.push_str("...");
    kept
}

/// Takes records from every source and groups the denials among them.
pub struct Collector {
    since_ms: u64,
    seen: HashSet<(u64, u64, u64)>,
    groups: HashMap<Denial, Group>,
}

impl Collector {
    /// Collects denials made at or after `since_ms`.
    pub fn new(since_ms: u64) -> Collector {
        Collector {
            since_ms,
            seen: HashSet::new(),
            groups: HashMap::new(),
        }
    }

    pub fn add(&mut self, raw: &Raw) {
        if raw.when_ms < self.since_ms {
            return;
        }
        let Some(denial) = parse_denial(raw) else {
            return;
        };
        // AIDEV-NOTE: one event can produce several records with the same time and
        // serial (SELinux refusing two permissions in one system call), so the text is
        // part of what makes a record "the same one". A record without a serial cannot
        // be recognised again and is always counted.
        if let Some(serial) = raw.serial {
            let mut hasher = DefaultHasher::new();
            raw.body.hash(&mut hasher);
            if !self.seen.insert((raw.when_ms, serial, hasher.finish())) {
                return;
            }
        }
        let group = self.groups.entry(denial.clone()).or_insert(Group {
            denial,
            count: 0,
            last_ms: 0,
            example: String::new(),
        });
        group.count += 1;
        if raw.when_ms >= group.last_ms {
            group.last_ms = raw.when_ms;
            // command lines appear in user-space records: mask what looks like a secret
            group.example = one_line_cut(&redact_text(&raw.body), EXAMPLE_CHARS);
        }
    }

    /// The groups, most frequent first.
    pub fn finish(self) -> Vec<Group> {
        let mut groups: Vec<Group> = self.groups.into_values().collect();
        groups.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then(b.last_ms.cmp(&a.last_ms))
                .then(a.denial.program.cmp(&b.denial.program))
                .then(a.denial.refused.cmp(&b.denial.refused))
                .then(a.denial.target.cmp(&b.denial.target))
        });
        groups
    }
}

/// The journalctl arguments. `--reverse`: newest first, so that if the output limit or
/// the time limit cuts the search short it is the oldest records that are missing.
pub fn journal_argv(hours: i64) -> Vec<String> {
    vec![
        "--no-pager".to_string(),
        "--quiet".to_string(),
        "--reverse".to_string(),
        "--output=json".to_string(),
        "--output-fields=MESSAGE,_TRANSPORT,_AUDIT_TYPE,_AUDIT_ID,_SOURCE_REALTIME_TIMESTAMP"
            .to_string(),
        format!("--since=-{hours}h"),
        format!("--grep={JOURNAL_PATTERN}"),
        // Only what the kernel wrote and what came through the audit socket (see
        // `from_the_kernel`). Two matches on one field mean either; matches are
        // positional, so they come last.
        "_TRANSPORT=kernel".to_string(),
        "_TRANSPORT=audit".to_string(),
    ]
}

/// What to say about how much of the journal was searched, for a server with this
/// effective uid.
///
/// AIDEV-NOTE: with `--quiet` journalctl prints no warning about the entries a user may
/// not read. A server that does not run as root (and is not in the journal's group)
/// sees only its own user's entries, where the kernel's audit records never are: "no
/// denials found" must not pass for an all-clear there.
pub fn journal_scope_note(euid: u32) -> Option<String> {
    (euid != 0).then(|| {
        "[the server does not run as root: it sees only the journal entries its user may \
         read, which may not include the kernel's]"
            .to_string()
    })
}

/// Adds the records in `journalctl --output=json` output. Returns how many lines could
/// not be used.
pub fn add_journal(collector: &mut Collector, stdout: &[u8]) -> usize {
    let mut unusable = 0;
    for line in stdout.split(|byte| *byte == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if line.len() > MAX_ENTRY_BYTES {
            unusable += 1;
            continue;
        }
        let Ok(Value::Object(entry)) = serde_json::from_slice::<Value>(line) else {
            unusable += 1;
            continue;
        };
        if !from_the_kernel(&entry) {
            // not asked for and not a record: passed over, not "unreadable"
            continue;
        }
        match journal_raw(&entry) {
            Some(raw) => collector.add(&raw),
            None => unusable += 1,
        }
    }
    unusable
}

/// What became of one audit log file.
#[derive(Debug, PartialEq, Eq)]
pub enum LogRead {
    /// There is no such file.
    Absent,
    /// It is there but may not be read (the server is not root).
    Unreadable(String),
    /// Read: this many bytes, and whether its start was skipped to stay within budget.
    Read { bytes: u64, from_start: bool },
}

/// Adds the records at the end of one audit log, reading at most `budget` bytes.
pub fn add_audit_log(collector: &mut Collector, path: &Path, budget: u64) -> LogRead {
    // Not followed if it is a link, and never blocking: the path is fixed, but nothing
    // is lost by being careful with a file in a log directory.
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let mut file = match rustix::fs::open(path, flags, Mode::empty()) {
        Ok(fd) => std::fs::File::from(fd),
        Err(rustix::io::Errno::NOENT) => return LogRead::Absent,
        Err(e) => return LogRead::Unreadable(std::io::Error::from(e).to_string()),
    };
    let size = match file.metadata() {
        Ok(meta) if meta.is_file() => meta.len(),
        Ok(_) => return LogRead::Unreadable("it is not a regular file".to_string()),
        Err(e) => return LogRead::Unreadable(e.to_string()),
    };
    let skip = size.saturating_sub(budget);
    if skip > 0 && file.seek(SeekFrom::Start(skip)).is_err() {
        return LogRead::Unreadable("it cannot be read from the middle".to_string());
    }
    let mut data = Vec::new();
    if let Err(e) = file.take(budget).read_to_end(&mut data) {
        return LogRead::Unreadable(e.to_string());
    }
    let text = String::from_utf8_lossy(&data);
    let mut lines = text.lines();
    if skip > 0 {
        // the first line is the tail end of one that began before where we started
        lines.next();
    }
    for line in lines {
        // cheap test first: most lines of an audit log are of other types
        if !(line.contains("type=AVC")
            || line.contains("type=USER_AVC")
            || line.contains("type=SECCOMP")
            || line.contains("apparmor="))
        {
            continue;
        }
        if let Some(raw) = split_audit_line(line) {
            collector.add(&raw);
        }
    }
    LogRead::Read {
        bytes: data.len() as u64,
        from_start: skip == 0,
    }
}

/// One line for each mandatory-access-control system that is switched on.
pub fn mac_mode(paths: &Paths) -> Vec<String> {
    let mut lines = Vec::new();
    if paths.apparmor.is_dir() {
        match std::fs::read_to_string(paths.apparmor.join("profiles")) {
            Ok(profiles) => {
                let count = |mode: &str| {
                    profiles
                        .lines()
                        .filter(|line| line.trim_end().ends_with(mode))
                        .count()
                };
                let (enforce, complain) = (count("(enforce)"), count("(complain)"));
                let other = profiles
                    .lines()
                    .filter(|line| !line.trim().is_empty())
                    .count()
                    .saturating_sub(enforce + complain);
                let mut line = format!(
                    "AppArmor: on; {enforce} profiles enforced, {complain} in complain mode \
                     (their denials are logged, not enforced)"
                );
                if other > 0 {
                    line.push_str(&format!(", {other} in other modes"));
                }
                lines.push(line);
            }
            Err(_) => lines.push(
                "AppArmor: on (the list of profiles cannot be read without being root)".to_string(),
            ),
        }
    }
    if let Ok(enforce) = std::fs::read_to_string(paths.selinux.join("enforce")) {
        lines.push(match enforce.trim() {
            "1" => "SELinux: enforcing".to_string(),
            "0" => "SELinux: permissive (denials are logged, not enforced)".to_string(),
            other => format!("SELinux: on (enforce = {})", one_line_cut(other, 20)),
        });
    }
    if lines.is_empty() {
        lines.push(
            "Neither AppArmor nor SELinux is switched on here; seccomp filters can still refuse."
                .to_string(),
        );
    }
    lines
}

// ---- showing ----------------------------------------------------------------------------

fn cell(text: &str, max: usize) -> String {
    one_line_cut(text, max)
}

/// The report. `groups` are most frequent first. `incomplete` says that not everything
/// could be searched (the notes say what and why).
///
/// AIDEV-NOTE: the first line is all that some readers act on. "No denials were found"
/// after a search that was cut short, or by a server that may not read the kernel's
/// records, would pass for an all-clear when it means "could not look".
pub fn render(
    groups: &[Group],
    hours: i64,
    limit: usize,
    mode: &[String],
    notes: &[String],
    incomplete: bool,
    budget: usize,
) -> String {
    let total: u64 = groups.iter().map(|group| group.count).sum();
    let logged_only: u64 = groups
        .iter()
        .filter(|group| !group.denial.enforced)
        .map(|group| group.count)
        .sum();
    let programs: HashSet<&str> = groups
        .iter()
        .map(|group| group.denial.program.as_str())
        .collect();
    let mut text = if total == 0 && incomplete {
        format!(
            "No AppArmor, SELinux or seccomp denials in the last {hours} h: none found in what \
             could be searched (see the notes).\n"
        )
    } else if total == 0 {
        format!("No AppArmor, SELinux or seccomp denials were found in the last {hours} h.\n")
    } else {
        let mut line = format!(
            "{total} {} in the last {hours} h, from {} {}",
            if total == 1 { "denial" } else { "denials" },
            programs.len(),
            if programs.len() == 1 {
                "program"
            } else {
                "programs"
            }
        );
        if logged_only == total {
            line.push_str("; all only logged, not enforced");
        } else if logged_only > 0 {
            line.push_str(&format!(
                "; {logged_only} of them only logged, not enforced"
            ));
        }
        line.push('.');
        if incomplete {
            line.push_str(" There may be more: not everything could be searched (see the notes).");
        }
        line.push('\n');
        line
    };
    for line in mode {
        text.push_str(line);
        text.push('\n');
    }
    let mut tail = String::new();
    if groups.len() > limit {
        tail.push_str(&format!(
            "[{} more groups left out, all less frequent; raise limit to see them]\n",
            groups.len().saturating_sub(limit)
        ));
    }
    for note in notes {
        tail.push_str(note);
        tail.push('\n');
    }
    if total == 0 {
        text.push_str(&tail);
        return text;
    }

    let shown = groups.get(..limit.min(groups.len())).unwrap_or(groups);
    let rows: Vec<Vec<String>> = shown
        .iter()
        .enumerate()
        .map(|(index, group)| {
            let denial = &group.denial;
            let kind = if denial.enforced {
                denial.kind.name().to_string()
            } else {
                format!("{} (logged only)", denial.kind.name())
            };
            vec![
                (index + 1).to_string(),
                group.count.to_string(),
                kind,
                cell(&denial.program, PROGRAM_CHARS),
                cell(&denial.refused, CELL_CHARS),
                cell(&denial.target, CELL_CHARS),
                rfc3339_utc(i64::try_from(group.last_ms / 1000).unwrap_or(0)),
            ]
        })
        .collect();
    let table = format_table(
        &["#", "COUNT", "KIND", "PROGRAM", "REFUSED", "TARGET", "LAST"],
        &rows,
        &[true, true, false, false, false, false, false],
    );
    let mut examples = String::from("\nThe newest record of each row:\n");
    for (index, group) in shown.iter().enumerate() {
        examples.push_str(&format!("{:>3}: {}\n", index + 1, group.example));
    }

    // The table matters most; the examples give way first.
    let room = budget.saturating_sub(text.len() + tail.len() + 200);
    let (table, dropped) = keep_head(&table, room);
    text.push('\n');
    text.push_str(&table);
    if dropped > 0 {
        text.push_str(&format!(
            "[{dropped} more rows left out to fit the output limit; ask for a lower limit]\n"
        ));
    }
    let room = room.saturating_sub(table.len());
    let (examples, dropped) = keep_head(&examples, room);
    if examples.lines().count() > 2 || dropped == 0 {
        text.push_str(&examples);
    }
    if dropped > 0 {
        text.push_str(&format!(
            "[the records of {dropped} rows left out to fit the output limit]\n"
        ));
    }
    text.push_str(&tail);
    text
}

async fn security_denials(ctx: Ctx, args: Args, paths: Paths) -> ToolResult {
    let hours = args.int("hours").unwrap_or(24).clamp(1, 168);
    let limit = usize::try_from(args.int("limit").unwrap_or(20).clamp(1, 100)).unwrap_or(20);
    let auth = ctx.authorize(None)?;

    let since_ms = u64::try_from(now_secs().saturating_sub(hours.saturating_mul(3600)))
        .unwrap_or(0)
        .saturating_mul(1000);
    let mut collector = Collector::new(since_ms);
    let mut notes: Vec<String> = Vec::new();
    // Whether any source could be searched: without one there is no answer to give.
    let mut searched = false;

    match ctx.optional_command("journalctl")? {
        None => notes.push("[the journal was not searched: journalctl is not installed]".into()),
        Some(cmd) => {
            let mut cmd = cmd.args(journal_argv(hours));
            cmd.max_output = MAX_JOURNAL_BYTES;
            match ctx.run(cmd).await {
                Err(_) => notes
                    .push("[the journal was not searched: journalctl could not be started]".into()),
                Ok(out) => {
                    let unusable = add_journal(&mut collector, &out.stdout);
                    let has_output = !out.stdout.iter().all(u8::is_ascii_whitespace);
                    if no_entries(&out) || has_output {
                        searched = true;
                    }
                    if !no_entries(&out) {
                        // What journalctl itself said went wrong, without the entries.
                        let mut silent = out.clone();
                        silent.stdout.clear();
                        let trouble = one_line_cut(&command_text(&silent), 300);
                        // exit status 1 with entries printed is not a complaint
                        let complaint = out.timed_out
                            || out.truncated
                            || !out.stderr.iter().all(u8::is_ascii_whitespace)
                            || !has_output;
                        if complaint && !trouble.is_empty() {
                            notes.push(format!(
                                "[journalctl: {trouble}{}]",
                                if has_output {
                                    "; the oldest records may be missing"
                                } else {
                                    ""
                                }
                            ));
                        }
                    }
                    if unusable > 0 {
                        notes.push(format!(
                            "[{unusable} journal entries could not be read and were skipped]"
                        ));
                    }
                    notes.extend(journal_scope_note(rustix::process::geteuid().as_raw()));
                }
            }
        }
    }

    let budget = ctx.output_budget();
    blocking(ctx.clone(), move || {
        let mut left = MAX_AUDIT_BYTES;
        for path in &paths.audit_logs {
            match add_audit_log(&mut collector, path, left) {
                LogRead::Absent => {}
                LogRead::Unreadable(why) => notes.push(format!(
                    "[{} was not searched: {}]",
                    path.display(),
                    one_line_cut(&why, 200)
                )),
                LogRead::Read { bytes, from_start } => {
                    searched = true;
                    left = left.saturating_sub(bytes);
                    if !from_start {
                        notes.push(format!(
                            "[only the last {} MiB of {} were searched]",
                            bytes >> 20,
                            path.display()
                        ));
                    }
                }
            }
            if left == 0 {
                break;
            }
        }
        let mode = mac_mode(&paths);
        let groups = collector.finish();
        if !searched {
            let mut text = "Denials could not be looked for: neither the journal nor an audit \
                            log could be searched.\n"
                .to_string();
            for line in mode.iter().chain(notes.iter()) {
                text.push_str(line);
                text.push('\n');
            }
            return auth.failed(text);
        }
        // Every note above is about something that could not be searched, or not all
        // of it: a search cut short or truncated, a journal this user may not read in
        // full, an audit log that is unreadable or was read only at its end.
        let incomplete = !notes.is_empty();
        auth.ok(render(
            &groups, hours, limit, &mode, &notes, incomplete, budget,
        ))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::testing::{FakeBins, call, find, host, ok_text};
    use crate::tools::{Host, ToolError};
    use serde_json::json;
    use std::sync::Arc;

    const T0: u64 = 1_700_000_000;

    const APPARMOR: &str = r#"apparmor="DENIED" operation="open" class="file" profile="/usr/sbin/nginx" name="/etc/ssl/private/site.key" pid=812 comm="nginx" requested_mask="r" denied_mask="r" fsuid=33 ouid=0"#;
    const SELINUX: &str = r#"avc:  denied  { read write } for  pid=2001 comm="httpd" name="app.sock" dev="dm-0" ino=4711 scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:var_run_t:s0 tclass=sock_file permissive=0"#;
    const SECCOMP: &str = r#"auid=1000 uid=1000 gid=100 ses=3 subj=unconfined pid=3003 comm="worker" exe="/usr/bin/worker" sig=31 arch=c000003e syscall=41 compat=0 ip=0x7f1a2b3c4d5e code=0x80000000"#;

    fn raw(hint: Hint, when_ms: u64, serial: u64, body: &str) -> Raw {
        Raw {
            hint,
            when_ms,
            serial: Some(serial),
            body: body.to_string(),
        }
    }

    // ---- taking records apart -------------------------------------------------------

    #[test]
    fn an_audit_log_line_gives_type_time_serial_and_body() {
        let line = format!("type=AVC msg=audit({T0}.123:456): {APPARMOR}");
        assert_eq!(
            split_audit_line(&line),
            Some(raw(Hint::Avc, T0 * 1000 + 123, 456, APPARMOR))
        );
        // the same record as the kernel log has it
        let line = format!("audit: type=1400 audit({T0}.123:456): {APPARMOR}");
        assert_eq!(
            split_audit_line(&line),
            Some(raw(Hint::Avc, T0 * 1000 + 123, 456, APPARMOR))
        );
        let line = format!("type=SECCOMP msg=audit({T0}.001:9): {SECCOMP}");
        assert_eq!(split_audit_line(&line).unwrap().hint, Hint::Seccomp);
        let line = format!("audit: type=1326 audit({T0}.001:9): {SECCOMP}");
        assert_eq!(split_audit_line(&line).unwrap().hint, Hint::Seccomp);
        let line = format!("type=SYSCALL msg=audit({T0}.001:9): arch=c000003e syscall=257");
        assert_eq!(split_audit_line(&line).unwrap().hint, Hint::Unknown);
        for bad in [
            "",
            "no header here",
            "type=AVC msg=audit(",
            "type=AVC msg=audit(abc.123:456): x",
            "type=AVC msg=audit(1700000000.123:x): x",
            "type=AVC msg=audit(1700000000.123): x",
        ] {
            assert_eq!(split_audit_line(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn pairs_reads_quoted_and_bare_values() {
        assert_eq!(
            pairs(
                r#"apparmor="DENIED" info="Failed name lookup - disconnected path" pid=812 name=2F746D702F6120 msg='avc: x' key="" last=1"#
            ),
            [
                ("apparmor", "DENIED", true),
                ("info", "Failed name lookup - disconnected path", true),
                ("pid", "812", false),
                ("name", "2F746D702F6120", false),
                ("msg", "'avc:", false),
                ("key", "", true),
                ("last", "1", false),
            ]
        );
        // words that are not pairs are passed over, and a record cut off in the middle
        // of a quoted value does not hang or panic
        assert_eq!(
            pairs("avc:  denied  { read } for  pid=7"),
            [("pid", "7", false)]
        );
        assert_eq!(pairs(r#"comm="ngi"#), [("comm", "ngi", true)]);
        assert_eq!(pairs("key="), [("key", "", false)]);
        assert_eq!(pairs("= =x"), []);
        assert_eq!(pairs(""), []);
        // the closing quote of msg='...' is not part of the last value
        assert_eq!(
            pairs("msg='terminal=? res=1'").last(),
            Some(&("res", "1", false))
        );
        // values that are not ASCII do not break the slicing
        assert_eq!(
            pairs("name=\"/srv/dät\" x=é"),
            [("name", "/srv/dät", true), ("x", "é", false)]
        );
    }

    #[test]
    fn an_apparmor_denial_names_the_program_the_operation_and_the_file() {
        let denial = parse_denial(&raw(Hint::Avc, 1, 1, APPARMOR)).unwrap();
        assert_eq!(
            denial,
            Denial {
                kind: Kind::AppArmor,
                program: "nginx".to_string(),
                refused: "open r".to_string(),
                target: "/etc/ssl/private/site.key".to_string(),
                enforced: true,
            }
        );
        // complain mode: logged, let through
        let allowed = APPARMOR.replace("DENIED", "ALLOWED");
        assert!(
            !parse_denial(&raw(Hint::Avc, 1, 1, &allowed))
                .unwrap()
                .enforced
        );
        // a capability, a network operation and a signal have no file
        let capable = r#"apparmor="DENIED" operation="capable" profile="/usr/bin/man" pid=5 comm="man" capability=12 capname="net_admin""#;
        let denial = parse_denial(&raw(Hint::Avc, 1, 1, capable)).unwrap();
        assert_eq!(
            (denial.refused.as_str(), denial.target.as_str()),
            ("capable net_admin", "-")
        );
        let network = r#"apparmor="DENIED" operation="create" profile="snap.app" pid=5 comm="app" family="inet" sock_type="stream" protocol=6 requested_mask="create" denied_mask="create""#;
        assert_eq!(
            parse_denial(&raw(Hint::Avc, 1, 1, network))
                .unwrap()
                .refused,
            "create create"
        );
        let ptrace = r#"apparmor="DENIED" operation="ptrace" profile="docker-default" pid=5 comm="ps" requested_mask="read" denied_mask="read" peer="unconfined""#;
        assert_eq!(
            parse_denial(&raw(Hint::Avc, 1, 1, ptrace)).unwrap().target,
            "unconfined"
        );
        // without a command name the profile stands in
        let no_comm = r#"apparmor="DENIED" operation="mount" profile="lxc-default" name="/proc/" pid=5 flags="rw""#;
        assert_eq!(
            parse_denial(&raw(Hint::Avc, 1, 1, no_comm))
                .unwrap()
                .program,
            "lxc-default"
        );
        // profile loading and the like are not denials
        let status = r#"apparmor="STATUS" operation="profile_load" profile="unconfined" name="docker-default" pid=5 comm="apparmor_parser""#;
        assert_eq!(parse_denial(&raw(Hint::Avc, 1, 1, status)), None);
    }

    #[test]
    fn a_value_written_as_hexadecimal_is_decoded() {
        // the kernel writes a name with a space in it as hex, without quotes
        let body = r#"apparmor="DENIED" operation="open" profile="/usr/bin/app" name=2F7372762F6D7920646972 pid=5 comm=6D7920617070 denied_mask="r""#;
        let denial = parse_denial(&raw(Hint::Avc, 1, 1, body)).unwrap();
        assert_eq!(denial.target, "/srv/my dir");
        assert_eq!(denial.program, "my app");
        // quoted values are never decoded, and neither is something that is not hex
        let body = r#"apparmor="DENIED" operation="open" name="CAFE" comm="BEEF" denied_mask="r""#;
        let denial = parse_denial(&raw(Hint::Avc, 1, 1, body)).unwrap();
        assert_eq!(
            (denial.target.as_str(), denial.program.as_str()),
            ("CAFE", "BEEF")
        );
        let body = r#"apparmor="DENIED" operation="open" name=(null) comm=cafe denied_mask="r""#;
        let denial = parse_denial(&raw(Hint::Avc, 1, 1, body)).unwrap();
        assert_eq!(
            (denial.target.as_str(), denial.program.as_str()),
            ("-", "cafe")
        );
    }

    #[test]
    fn an_selinux_denial_names_the_permissions_the_class_and_the_target() {
        let denial = parse_denial(&raw(Hint::Avc, 1, 1, SELINUX)).unwrap();
        assert_eq!(
            denial,
            Denial {
                kind: Kind::SELinux,
                program: "httpd".to_string(),
                refused: "read write on sock_file".to_string(),
                target: "app.sock".to_string(),
                enforced: true,
            }
        );
        let with_path = SELINUX.replace("name=\"app.sock\"", "path=\"/run/app/app.sock\"");
        assert_eq!(
            parse_denial(&raw(Hint::Avc, 1, 1, &with_path))
                .unwrap()
                .target,
            "/run/app/app.sock"
        );
        let permissive = SELINUX.replace("permissive=0", "permissive=1");
        assert!(
            !parse_denial(&raw(Hint::Avc, 1, 1, &permissive))
                .unwrap()
                .enforced
        );
        // a denial reported by a user-space manager (systemd, dbus), wrapped in msg='...'
        let user = r#"pid=1 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:init_t:s0 msg='avc:  denied  { status } for auid=1000 uid=1000 gid=1000 path="/usr/lib/systemd/system/app.service" cmdline="systemctl status app" function="mac_selinux_filter" scontext=user_u:user_r:user_t:s0 tcontext=system_u:object_r:app_unit_file_t:s0 tclass=service permissive=0  exe="/usr/lib/systemd/systemd" sauid=0 hostname=? addr=? terminal=?'"#;
        let denial = parse_denial(&raw(Hint::Avc, 1, 1, user)).unwrap();
        assert_eq!(denial.program, "systemd");
        assert_eq!(denial.refused, "status on service");
        assert_eq!(denial.target, "/usr/lib/systemd/system/app.service");
        // an audited grant is not a denial
        let granted = SELINUX.replace("denied", "granted");
        assert_eq!(parse_denial(&raw(Hint::Avc, 1, 1, &granted)), None);
        assert_eq!(
            parse_denial(&raw(Hint::Avc, 1, 1, "avc:  denied  { read")),
            None
        );
    }

    #[test]
    fn a_seccomp_record_says_which_call_and_what_was_done_about_it() {
        let denial = parse_denial(&raw(Hint::Seccomp, 1, 1, SECCOMP)).unwrap();
        assert_eq!(
            denial,
            Denial {
                kind: Kind::Seccomp,
                program: "worker".to_string(),
                refused: "syscall 41, killed".to_string(),
                target: "-".to_string(),
                enforced: true,
            }
        );
        let with = |code: &str| {
            parse_denial(&raw(
                Hint::Seccomp,
                1,
                1,
                &SECCOMP.replace("0x80000000", code),
            ))
        };
        assert_eq!(with("0x0").unwrap().refused, "syscall 41, killed");
        assert_eq!(
            with("0x50001").unwrap().refused,
            "syscall 41, error returned"
        );
        assert_eq!(with("0x30000").unwrap().refused, "syscall 41, trapped");
        let logged = with("0x7ffc0000").unwrap();
        assert_eq!(
            (logged.refused.as_str(), logged.enforced),
            ("syscall 41, logged only", false)
        );
        // "allowed" is not a denial; neither is the same text without the seccomp type
        assert_eq!(with("0x7fff0000"), None);
        assert_eq!(parse_denial(&raw(Hint::Unknown, 1, 1, SECCOMP)), None);
        assert_eq!(
            parse_denial(&raw(Hint::Avc, 1, 1, "pid=1 uid=0 res=success")),
            None
        );
    }

    // ---- the journal ----------------------------------------------------------------

    fn entry(value: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn a_kernel_message_in_the_journal_carries_its_own_audit_header() {
        let found = journal_raw(&entry(json!({
            "__REALTIME_TIMESTAMP": "1700000099000000",
            "_TRANSPORT": "kernel",
            "MESSAGE": format!("audit: type=1400 audit({T0}.123:456): {APPARMOR}"),
        })))
        .unwrap();
        // the kernel's time, not the time journald filed it
        assert_eq!(found, raw(Hint::Avc, T0 * 1000 + 123, 456, APPARMOR));
    }

    #[test]
    fn a_record_from_journald_s_audit_socket_has_its_header_in_fields() {
        let found = journal_raw(&entry(json!({
            "__REALTIME_TIMESTAMP": "1700000099000000",
            "_SOURCE_REALTIME_TIMESTAMP": format!("{}", T0 * 1_000_000 + 123_000),
            "_AUDIT_TYPE": "1400",
            "_AUDIT_ID": "456",
            "MESSAGE": format!("AVC {APPARMOR}"),
        })))
        .unwrap();
        // identical to what audit.log holds: that is what lets a copy be recognised
        assert_eq!(found, raw(Hint::Avc, T0 * 1000 + 123, 456, APPARMOR));
        let seccomp = journal_raw(&entry(json!({
            "__REALTIME_TIMESTAMP": "1700000099000000",
            "_AUDIT_TYPE": "1326",
            "_AUDIT_ID": "9",
            "MESSAGE": format!("SECCOMP {SECCOMP}"),
        })))
        .unwrap();
        assert_eq!(seccomp, raw(Hint::Seccomp, 1_700_000_099_000, 9, SECCOMP));
    }

    #[test]
    fn a_line_without_any_header_is_dated_by_the_journal() {
        let found = journal_raw(&entry(json!({
            "__REALTIME_TIMESTAMP": "1700000099000000",
            "_TRANSPORT": "kernel",
            "MESSAGE": format!("kernel: {APPARMOR}"),
        })))
        .unwrap();
        assert_eq!(found.hint, Hint::Unknown);
        assert_eq!(found.when_ms, 1_700_000_099_000);
        assert_eq!(found.serial, None);
        assert!(parse_denial(&found).is_some());
        assert_eq!(
            journal_raw(&entry(json!({"_TRANSPORT": "kernel", "MESSAGE": "x"}))),
            None
        );
        assert_eq!(
            journal_raw(&entry(
                json!({"_TRANSPORT": "kernel", "__REALTIME_TIMESTAMP": "1"})
            )),
            None
        );
    }

    /// AIDEV-NOTE: any local user can write a journal entry that reads like a denial
    /// (`logger 'apparmor="DENIED" ... comm="sshd" name="/etc/shadow"'`). Only the kernel
    /// and journald's audit socket write real ones, and journald itself records which
    /// way an entry came (`_TRANSPORT`, `_AUDIT_TYPE`): a client cannot set those.
    #[test]
    fn an_entry_a_user_wrote_is_not_taken_for_a_denial() {
        let forged = |transport: Option<&str>| {
            let mut fields = json!({
                "__REALTIME_TIMESTAMP": "1700000099000000",
                "MESSAGE": format!("audit: type=1400 audit({T0}.123:456): {APPARMOR}"),
            });
            if let Some(transport) = transport {
                fields["_TRANSPORT"] = json!(transport);
            }
            entry(fields)
        };
        for transport in [
            Some("syslog"),
            Some("journal"),
            Some("stdout"),
            Some("driver"),
            None,
        ] {
            assert!(!from_the_kernel(&forged(transport)), "{transport:?}");
            assert_eq!(journal_raw(&forged(transport)), None, "{transport:?}");
        }
        assert!(from_the_kernel(&forged(Some("kernel"))));
        assert!(from_the_kernel(&forged(Some("audit"))));
        // journald's audit socket marks its entries with the audit type
        assert!(from_the_kernel(&entry(
            json!({"_AUDIT_TYPE": "1400", "MESSAGE": "AVC x"})
        )));

        // such entries are passed over without a word: they are not "unreadable"
        let line = |transport: &str, serial: u64| {
            json!({
                "__REALTIME_TIMESTAMP": "1700000099000000",
                "_TRANSPORT": transport,
                "MESSAGE": format!("audit: type=1400 audit({T0}.123:{serial}): {APPARMOR}"),
            })
            .to_string()
        };
        let stdout = format!("{}\n{}\n", line("syslog", 1), line("kernel", 2));
        let mut collector = Collector::new(0);
        assert_eq!(add_journal(&mut collector, stdout.as_bytes()), 0);
        let groups = collector.finish();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].count, 1);
    }

    #[test]
    fn journalctl_is_asked_for_denials_newest_first() {
        let argv = journal_argv(24);
        assert_eq!(
            argv[..4],
            ["--no-pager", "--quiet", "--reverse", "--output=json"]
        );
        assert!(argv.contains(&"--since=-24h".to_string()), "{argv:?}");
        // only what the kernel and the audit socket wrote: two matches on one field,
        // which journalctl takes as either-or; matches come after every option
        assert_eq!(
            argv[argv.len() - 2..],
            ["_TRANSPORT=kernel", "_TRANSPORT=audit"]
        );
        let fields = argv
            .iter()
            .find(|a| a.starts_with("--output-fields="))
            .unwrap();
        assert!(
            fields.split(['=', ',']).any(|f| f == "_TRANSPORT"),
            "{fields}"
        );
        let grep = argv.iter().find(|a| a.starts_with("--grep=")).unwrap();
        // upper case somewhere, or journalctl would match without regard to case
        assert!(grep.chars().any(|c| c.is_ascii_uppercase()), "{grep}");
        let pattern = regex::Regex::new(grep.trim_start_matches("--grep=")).unwrap();
        for line in [
            format!("audit: type=1400 audit({T0}.123:456): {APPARMOR}"),
            format!("AVC {SELINUX}"),
            format!("audit: type=1326 audit({T0}.001:9): {SECCOMP}"),
            format!("SECCOMP {SECCOMP}"),
            APPARMOR.replace("DENIED", "ALLOWED"),
        ] {
            assert!(pattern.is_match(&line), "{line}");
        }
        for line in [
            r#"audit: type=1400 audit(1.1:1): apparmor="STATUS" operation="profile_load""#,
            "Started nginx.service",
            "avc:  granted  { read }",
        ] {
            assert!(!pattern.is_match(line), "{line}");
        }
    }

    #[test]
    fn a_server_that_is_not_root_says_that_it_may_not_see_everything() {
        // journalctl --quiet says nothing about the entries it may not show
        assert_eq!(journal_scope_note(0), None);
        let note = journal_scope_note(1000).unwrap();
        assert!(note.contains("not run as root"), "{note}");
        assert!(note.starts_with('[') && note.ends_with(']'), "{note}");
    }

    // ---- collecting -----------------------------------------------------------------

    #[test]
    fn the_same_record_from_two_sources_counts_once() {
        let mut collector = Collector::new(0);
        let journal = journal_raw(&entry(json!({
            "__REALTIME_TIMESTAMP": "1700000099000000",
            "_TRANSPORT": "kernel",
            "MESSAGE": format!("audit: type=1400 audit({T0}.123:456): {APPARMOR}"),
        })))
        .unwrap();
        let log =
            split_audit_line(&format!("type=AVC msg=audit({T0}.123:456): {APPARMOR}")).unwrap();
        collector.add(&journal);
        collector.add(&log);
        // the same denial again, later: a new record
        collector.add(&raw(Hint::Avc, T0 * 1000 + 900, 457, APPARMOR));
        // one event that refused two things: same time and serial, different text
        collector.add(&raw(Hint::Avc, T0 * 1000 + 950, 458, SELINUX));
        collector.add(&raw(
            Hint::Avc,
            T0 * 1000 + 950,
            458,
            &SELINUX.replace("app.sock", "other.sock"),
        ));
        let groups = collector.finish();
        let counts: Vec<(String, u64)> = groups
            .iter()
            .map(|g| (g.denial.target.clone(), g.count))
            .collect();
        assert_eq!(
            counts,
            [
                ("/etc/ssl/private/site.key".to_string(), 2),
                ("app.sock".to_string(), 1),
                ("other.sock".to_string(), 1),
            ]
        );
        assert_eq!(groups[0].last_ms, T0 * 1000 + 900);
    }

    #[test]
    fn records_from_before_the_period_and_records_that_are_no_denials_are_left_out() {
        let mut collector = Collector::new(T0 * 1000);
        collector.add(&raw(Hint::Avc, T0 * 1000 - 1, 1, APPARMOR));
        collector.add(&raw(
            Hint::Unknown,
            T0 * 1000 + 5,
            2,
            "arch=c000003e syscall=257 success=no",
        ));
        assert!(collector.finish().is_empty());
        // without a serial a record cannot be recognised again: each one counts
        let mut collector = Collector::new(0);
        let mut bare = raw(Hint::Unknown, 5, 0, APPARMOR);
        bare.serial = None;
        collector.add(&bare);
        collector.add(&bare);
        assert_eq!(collector.finish()[0].count, 2);
    }

    #[test]
    fn the_example_is_the_newest_record_masked_and_cut() {
        let mut collector = Collector::new(0);
        let long = format!(
            "pid=1 uid=0 msg='avc:  denied  {{ status }} for path=\"/x\" cmdline=\"mysql --password=hunter2 {}\" scontext=a:b:c_t:s0 tcontext=d:e:f_t:s0 tclass=service permissive=0'",
            "x".repeat(400)
        );
        collector.add(&raw(Hint::Avc, 10, 1, &long));
        let groups = collector.finish();
        assert!(
            !groups[0].example.contains("hunter2"),
            "{}",
            groups[0].example
        );
        assert!(
            groups[0].example.chars().count() <= 203,
            "{}",
            groups[0].example.len()
        );
        assert!(groups[0].example.ends_with("..."));
    }

    #[test]
    fn journal_output_is_read_line_by_line_and_bad_lines_are_counted() {
        let good = json!({
            "__REALTIME_TIMESTAMP": "1700000099000000",
            "_TRANSPORT": "kernel",
            "MESSAGE": format!("audit: type=1400 audit({T0}.123:456): {APPARMOR}"),
        })
        .to_string();
        // a message that is not UTF-8 comes as an array of bytes
        let bytes: Vec<u8> =
            format!("audit: type=1400 audit({T0}.500:460): {APPARMOR}").into_bytes();
        let as_bytes = json!({
            "__REALTIME_TIMESTAMP": "1700000099000000",
            "_TRANSPORT": "kernel",
            "MESSAGE": bytes
        })
        .to_string();
        let stdout = format!(
            "{good}\nnot json\n\n{as_bytes}\n{{\"_TRANSPORT\":\"kernel\",\"MESSAGE\":null}}\n"
        );
        let mut collector = Collector::new(0);
        assert_eq!(add_journal(&mut collector, stdout.as_bytes()), 2);
        assert_eq!(collector.finish()[0].count, 2);
    }

    // ---- the audit log --------------------------------------------------------------

    fn audit_line(serial: u64, body: &str) -> String {
        format!("type=AVC msg=audit({}.000:{serial}): {body}\n", T0 + serial)
    }

    #[test]
    fn an_audit_log_is_read_from_its_end_within_a_budget() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let mut text = String::new();
        for serial in 1..=100 {
            text.push_str(&format!(
                "type=SYSCALL msg=audit({}.000:{serial}): arch=c000003e syscall=257 success=no\n",
                T0 + serial
            ));
            text.push_str(&audit_line(serial, APPARMOR));
        }
        std::fs::write(&path, &text).unwrap();
        let mut collector = Collector::new(0);
        let read = add_audit_log(&mut collector, &path, 1 << 20);
        assert_eq!(
            read,
            LogRead::Read {
                bytes: text.len() as u64,
                from_start: true
            }
        );
        assert_eq!(collector.finish()[0].count, 100);

        // a budget smaller than the file: the newest records, and no half line
        let mut collector = Collector::new(0);
        let read = add_audit_log(&mut collector, &path, 2000);
        assert_eq!(
            read,
            LogRead::Read {
                bytes: 2000,
                from_start: false
            }
        );
        let groups = collector.finish();
        assert!(
            groups[0].count > 0 && groups[0].count < 10,
            "{}",
            groups[0].count
        );
        assert_eq!(groups[0].last_ms, (T0 + 100) * 1000);
    }

    #[test]
    fn a_missing_or_odd_audit_log_is_told_apart() {
        let dir = tempfile::tempdir().unwrap();
        let mut collector = Collector::new(0);
        assert_eq!(
            add_audit_log(&mut collector, &dir.path().join("audit.log"), 1000),
            LogRead::Absent
        );
        assert!(matches!(
            add_audit_log(&mut collector, dir.path(), 1000),
            LogRead::Unreadable(_)
        ));
        // a link is not followed
        std::fs::write(dir.path().join("real"), audit_line(1, APPARMOR)).unwrap();
        std::os::unix::fs::symlink(dir.path().join("real"), dir.path().join("link")).unwrap();
        assert!(matches!(
            add_audit_log(&mut collector, &dir.path().join("link"), 1000),
            LogRead::Unreadable(_)
        ));
        assert!(collector.finish().is_empty());
    }

    // ---- what is switched on ----------------------------------------------------------

    fn paths(dir: &Path) -> Paths {
        Paths {
            apparmor: dir.join("apparmor"),
            selinux: dir.join("selinux"),
            audit_logs: vec![dir.join("audit.log"), dir.join("audit.log.1")],
        }
    }

    #[test]
    fn the_mode_line_says_what_is_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        assert_eq!(
            mac_mode(&paths),
            ["Neither AppArmor nor SELinux is switched on here; seccomp filters can still refuse."]
        );
        std::fs::create_dir(&paths.apparmor).unwrap();
        assert_eq!(
            mac_mode(&paths),
            ["AppArmor: on (the list of profiles cannot be read without being root)"]
        );
        std::fs::write(
            paths.apparmor.join("profiles"),
            "/usr/sbin/nginx (enforce)\n/usr/bin/man (enforce)\nsnap.app (complain)\ndocker-default (kill)\n",
        )
        .unwrap();
        assert_eq!(
            mac_mode(&paths),
            [
                "AppArmor: on; 2 profiles enforced, 1 in complain mode (their denials are logged, not enforced), 1 in other modes"
            ]
        );
        std::fs::create_dir(&paths.selinux).unwrap();
        std::fs::write(paths.selinux.join("enforce"), "1").unwrap();
        assert_eq!(mac_mode(&paths)[1], "SELinux: enforcing");
        std::fs::write(paths.selinux.join("enforce"), "0\n").unwrap();
        assert_eq!(
            mac_mode(&paths)[1],
            "SELinux: permissive (denials are logged, not enforced)"
        );
    }

    // ---- how it is shown ------------------------------------------------------------

    fn group(
        kind: Kind,
        program: &str,
        refused: &str,
        target: &str,
        enforced: bool,
        count: u64,
    ) -> Group {
        Group {
            denial: Denial {
                kind,
                program: program.to_string(),
                refused: refused.to_string(),
                target: target.to_string(),
                enforced,
            },
            count,
            last_ms: T0 * 1000,
            example: format!("record of {program}"),
        }
    }

    fn sample() -> Vec<Group> {
        vec![
            group(
                Kind::AppArmor,
                "nginx",
                "open r",
                "/etc/ssl/private/site.key",
                true,
                30,
            ),
            group(
                Kind::SELinux,
                "httpd",
                "read write on sock_file",
                "/run/app/app.sock",
                true,
                5,
            ),
            group(Kind::AppArmor, "nginx", "open w", "/var/cache/x", false, 2),
        ]
    }

    #[test]
    fn the_verdict_counts_denials_programs_and_what_was_only_logged() {
        let mode = vec!["SELinux: enforcing".to_string()];
        let text = render(&sample(), 24, 20, &mode, &[], false, 60_000);
        let mut lines = text.lines();
        assert_eq!(
            lines.next(),
            Some(
                "37 denials in the last 24 h, from 2 programs; 2 of them only logged, not enforced."
            )
        );
        assert_eq!(lines.next(), Some("SELinux: enforcing"));
        let none = render(&[], 6, 20, &mode, &["[a note]".to_string()], false, 60_000);
        assert_eq!(
            none,
            "No AppArmor, SELinux or seccomp denials were found in the last 6 h.\nSELinux: enforcing\n[a note]\n"
        );
        let one = render(&sample()[1..2], 24, 20, &[], &[], false, 60_000);
        assert!(
            one.starts_with("5 denials in the last 24 h, from 1 program.\n"),
            "{one}"
        );
        let single = vec![group(
            Kind::Seccomp,
            "worker",
            "syscall 41, logged only",
            "-",
            false,
            1,
        )];
        let text = render(&single, 24, 20, &[], &[], false, 60_000);
        assert!(
            text.starts_with(
                "1 denial in the last 24 h, from 1 program; all only logged, not enforced.\n"
            ),
            "{text}"
        );
    }

    /// AIDEV-NOTE: "no denials were found" from a search that was cut short, or by a
    /// server that may not read the kernel's records, is "could not look", not an
    /// all-clear. The first line is all some readers act on.
    #[test]
    fn a_search_that_was_not_complete_does_not_read_as_an_all_clear() {
        let notes = [
            "[journalctl: the command was stopped; the oldest records may be missing]".to_string(),
        ];
        let none = render(&[], 6, 20, &[], &notes, true, 60_000);
        assert_eq!(
            none.lines().next(),
            Some(
                "No AppArmor, SELinux or seccomp denials in the last 6 h: none found in what \
                 could be searched (see the notes)."
            )
        );
        assert!(
            none.ends_with("the oldest records may be missing]\n"),
            "{none}"
        );
        // with denials found, the count stands and the line says there may be more
        let some = render(&sample(), 24, 20, &[], &notes, true, 60_000);
        assert_eq!(
            some.lines().next(),
            Some(
                "37 denials in the last 24 h, from 2 programs; 2 of them only logged, not \
                 enforced. There may be more: not everything could be searched (see the notes)."
            )
        );
        // a complete search says neither
        let whole = render(&[], 6, 20, &[], &[], false, 60_000);
        assert!(
            whole.starts_with(
                "No AppArmor, SELinux or seccomp denials were found in the last 6 h.\n"
            ),
            "{whole}"
        );
    }

    #[test]
    fn the_table_has_a_row_and_a_record_for_each_group() {
        let text = render(
            &sample(),
            24,
            20,
            &[],
            &["[a note]".to_string()],
            false,
            60_000,
        );
        let header = text.lines().find(|line| line.contains("COUNT")).unwrap();
        assert_eq!(
            header.split_whitespace().collect::<Vec<_>>(),
            ["#", "COUNT", "KIND", "PROGRAM", "REFUSED", "TARGET", "LAST"]
        );
        let first = text.lines().find(|line| line.contains("site.key")).unwrap();
        assert_eq!(
            first.split_whitespace().collect::<Vec<_>>(),
            [
                "1",
                "30",
                "AppArmor",
                "nginx",
                "open",
                "r",
                "/etc/ssl/private/site.key",
                "2023-11-14T22:13:20Z"
            ]
        );
        assert!(text.contains("AppArmor (logged only)"), "{text}");
        assert!(text.contains("\nThe newest record of each row:\n  1: record of nginx\n  2: record of httpd\n  3: record of nginx\n"), "{text}");
        assert!(text.ends_with("[a note]\n"), "{text}");
    }

    #[test]
    fn groups_beyond_the_limit_are_counted_not_shown() {
        let text = render(&sample(), 24, 2, &[], &[], false, 60_000);
        assert!(text.contains("httpd"), "{text}");
        assert!(!text.contains("/var/cache/x"), "{text}");
        assert!(
            text.contains("[1 more groups left out, all less frequent; raise limit to see them]"),
            "{text}"
        );
        // the first line still counts everything
        assert!(text.starts_with("37 denials"), "{text}");
    }

    #[test]
    fn long_names_are_cut_and_a_small_budget_drops_the_records_first() {
        let long = "/srv/".to_string() + &"deep/".repeat(40);
        let many: Vec<Group> = (0..80u64)
            .map(|n| {
                group(
                    Kind::AppArmor,
                    &format!("prog{n}"),
                    "open r",
                    &long,
                    true,
                    100 - n,
                )
            })
            .collect();
        let text = render(&many, 24, 100, &[], &["[a note]".to_string()], false, 4000);
        assert!(text.len() <= 4000, "{}", text.len());
        assert!(text.contains("prog0 "), "{text}");
        assert!(text.contains("left out to fit the output limit"), "{text}");
        assert!(text.ends_with("[a note]\n"), "{text}");
        assert!(
            text.lines().all(|line| line.chars().count() < 200),
            "{text}"
        );
    }

    // ---- the tool -------------------------------------------------------------------

    fn fixture(fake: &FakeBins) -> Arc<Host> {
        host(&format!(
            r#"
[roles.reader]
allow = ["@read"]
[roles.other]
allow = ["system.view"]
[unix_users.rita]
roles = ["reader"]
[unix_users.olga]
roles = ["other"]
{}"#,
            fake.config_only()
        ))
        .0
    }

    fn now_ms() -> u64 {
        u64::try_from(now_secs()).unwrap() * 1000
    }

    fn journal_line(when_ms: u64, serial: u64, body: &str) -> String {
        json!({
            "__REALTIME_TIMESTAMP": format!("{}", when_ms * 1000),
            "_TRANSPORT": "kernel",
            "MESSAGE": format!("audit: type=1400 audit({}.{:03}:{serial}): {body}", when_ms / 1000, when_ms % 1000),
        })
        .to_string()
    }

    /// What the first line says when nothing was found, for the user running the tests:
    /// a server that is not root may not see the kernel's records, and says so.
    fn none_found(hours: i64) -> String {
        if rustix::process::geteuid().is_root() {
            format!("No AppArmor, SELinux or seccomp denials were found in the last {hours} h.\n")
        } else {
            format!(
                "No AppArmor, SELinux or seccomp denials in the last {hours} h: none found in \
                 what could be searched (see the notes).\n"
            )
        }
    }

    async fn run(
        host: &Arc<Host>,
        user: &str,
        paths: Paths,
        arguments: serde_json::Value,
    ) -> ToolResult {
        call(
            host,
            user,
            &find(tools_with(paths), "security_denials"),
            arguments,
        )
        .await
    }

    #[tokio::test]
    async fn security_denials_merges_the_journal_and_the_audit_log() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        let now = now_ms();
        // the journal has two denials; the audit log has one of them again and one more
        let journal = format!(
            "{}\n{}\n",
            journal_line(now - 60_000, 11, APPARMOR),
            journal_line(now - 50_000, 12, APPARMOR)
        );
        let log = format!(
            "type=AVC msg=audit({}.{:03}:12): {APPARMOR}\ntype=AVC msg=audit({}.{:03}:13): {SELINUX}\ntype=AVC msg=audit({}.000:1): {SELINUX}\n",
            (now - 50_000) / 1000,
            (now - 50_000) % 1000,
            (now - 40_000) / 1000,
            (now - 40_000) % 1000,
            // long before the period
            now / 1000 - 30 * 86_400,
        );
        std::fs::write(&paths.audit_logs[0], log).unwrap();
        let fake = FakeBins::new().add("journalctl", &journal, 0);
        let host = fixture(&fake);
        let text = ok_text(run(&host, "rita", paths, json!({"hours": 6})).await);
        assert!(
            text.starts_with("3 denials in the last 6 h, from 2 programs."),
            "{text}"
        );
        assert!(text.contains("nginx") && text.contains("httpd"), "{text}");
        let argv = &fake.calls("journalctl")[0];
        assert!(argv.contains(&"--since=-6h".to_string()), "{argv:?}");
        assert!(argv.iter().any(|a| a.starts_with("--grep=")), "{argv:?}");
    }

    #[tokio::test]
    async fn security_denials_says_so_when_there_are_none() {
        let dir = tempfile::tempdir().unwrap();
        // journalctl --quiet prints nothing and exits 1 when nothing matched
        let fake = FakeBins::new().add("journalctl", "", 1);
        let host = fixture(&fake);
        let text = ok_text(run(&host, "rita", paths(dir.path()), json!({})).await);
        assert!(text.starts_with(&none_found(24)), "{text}");
        assert!(text.contains("Neither AppArmor nor SELinux"), "{text}");
        assert!(!text.contains("exit status"), "{text}");
    }

    #[tokio::test]
    async fn security_denials_passes_over_entries_that_a_user_wrote() {
        let dir = tempfile::tempdir().unwrap();
        let now = now_ms();
        // what `logger 'apparmor="DENIED" ...'` leaves in the journal, and a real record
        let forged = json!({
            "__REALTIME_TIMESTAMP": format!("{}", (now - 30_000) * 1000),
            "_TRANSPORT": "syslog",
            "MESSAGE": r#"apparmor="DENIED" operation="open" profile="sshd" name="/etc/shadow" comm="sshd" requested_mask="r" denied_mask="r""#,
        })
        .to_string();
        let journal = format!("{forged}\n{}\n", journal_line(now - 60_000, 11, APPARMOR));
        let fake = FakeBins::new().add("journalctl", &journal, 0);
        let host = fixture(&fake);
        let text = ok_text(run(&host, "rita", paths(dir.path()), json!({})).await);
        assert!(
            text.starts_with("1 denial in the last 24 h, from 1 program."),
            "{text}"
        );
        assert!(
            !text.contains("/etc/shadow") && !text.contains("sshd"),
            "{text}"
        );
        assert!(!text.contains("could not be read"), "{text}");
        let argv = &fake.calls("journalctl")[0];
        assert_eq!(
            argv[argv.len() - 2..],
            ["_TRANSPORT=kernel", "_TRANSPORT=audit"]
        );
    }

    #[tokio::test]
    async fn security_denials_says_when_the_journal_search_was_cut_short() {
        let dir = tempfile::tempdir().unwrap();
        // journalctl never finishes: it is stopped at the time limit with nothing found
        let fake = FakeBins::new().add_script("journalctl", "while :; do :; done");
        let host = host(&format!(
            "[roles.reader]\nallow = [\"@read\"]\n[unix_users.rita]\nroles = [\"reader\"]\n\
             [limits]\ncommand_timeout_secs = 1\ncall_timeout_secs = 20\n{}",
            fake.config_only()
        ))
        .0;
        // an audit log exists, so there IS something that was searched
        let paths = paths(dir.path());
        std::fs::write(&paths.audit_logs[0], "").unwrap();
        let text = ok_text(run(&host, "rita", paths, json!({"hours": 6})).await);
        assert_eq!(
            text.lines().next(),
            Some(
                "No AppArmor, SELinux or seccomp denials in the last 6 h: none found in what \
                 could be searched (see the notes)."
            ),
            "{text}"
        );
        assert!(text.contains("[journalctl: "), "{text}");
    }

    #[tokio::test]
    async fn security_denials_fails_when_nothing_could_be_searched() {
        let dir = tempfile::tempdir().unwrap();
        // no journalctl and no audit log
        let fake = FakeBins::new();
        let host = fixture(&fake);
        let output = run(&host, "rita", paths(dir.path()), json!({}))
            .await
            .unwrap();
        assert!(output.is_error());
        assert!(
            output.text().starts_with("Denials could not be looked for"),
            "{}",
            output.text()
        );
        assert!(
            output.text().contains("journalctl is not installed"),
            "{}",
            output.text()
        );

        // journalctl fails outright: the same, with its words
        let fake = FakeBins::new().add_script(
            "journalctl",
            "printf '%s\\n' 'No journal files were opened due to insufficient permissions.' >&2; exit 1",
        );
        let host = fixture(&fake);
        let output = run(&host, "rita", paths(dir.path()), json!({}))
            .await
            .unwrap();
        assert!(output.is_error());
        assert!(
            output.text().contains("insufficient permissions"),
            "{}",
            output.text()
        );

        // ... but with an audit log to read there is an answer
        let paths = paths(dir.path());
        let now = now_ms();
        std::fs::write(
            &paths.audit_logs[0],
            format!(
                "type=AVC msg=audit({}.000:5): {APPARMOR}\n",
                now / 1000 - 10
            ),
        )
        .unwrap();
        let text = ok_text(run(&host, "rita", paths, json!({})).await);
        assert!(
            text.starts_with(
                "1 denial in the last 24 h, from 1 program. There may be more: not \
                 everything could be searched (see the notes).\n"
            ),
            "{text}"
        );
        assert!(text.contains("insufficient permissions"), "{text}");
    }

    #[tokio::test]
    async fn security_denials_needs_security_view() {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeBins::new().add("journalctl", "", 1);
        let host = fixture(&fake);
        let result = run(&host, "olga", paths(dir.path()), json!({})).await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        assert!(fake.calls("journalctl").is_empty());
        let tool = find(tools(), "security_denials");
        assert_eq!(
            (tool.access, tool.permission.as_str()),
            (Access::Read, "security.view")
        );
    }
}
