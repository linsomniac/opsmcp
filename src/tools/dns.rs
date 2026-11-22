//! How this host resolves names.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::args::Args;
use super::net::resolver_lines;
use super::{CallClock, Ctx, Tool, ToolError, ToolResult, blocking, command_ok, command_text};
use crate::exec::Cmd;
use crate::policy::Access;
use crate::sanitize::keep_head;

/// The files that decide how names are resolved. A parameter so that tests can use a
/// temporary directory; the server always uses `Paths::default()`.
#[derive(Clone, Debug)]
pub struct Paths {
    pub resolv_conf: PathBuf,
    pub nsswitch: PathBuf,
    pub hosts: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Paths {
            resolv_conf: PathBuf::from("/etc/resolv.conf"),
            nsswitch: PathBuf::from("/etc/nsswitch.conf"),
            hosts: PathBuf::from("/etc/hosts"),
        }
    }
}

pub fn tools() -> Vec<Tool> {
    tools_with(Paths::default())
}

/// The tool, reading the files named by `paths`.
pub fn tools_with(paths: Paths) -> Vec<Tool> {
    let paths = Arc::new(paths);
    vec![Tool::new(
        "dns_config",
        "Show how this host resolves names: the nameservers, search domains and options in \
         resolv.conf (with settings that often surprise pointed out), what systemd-resolved \
         uses per network link and how its cache is doing, the order of sources in \
         nsswitch.conf, and the entries of the hosts file. The first line sums it up. Use \
         it when a name does not resolve, resolves to the wrong address or resolves \
         slowly; net_probe with mode=dns then looks up one name.",
        Access::Read,
        "net.view",
        vec![],
        move |ctx, args| dns_config(ctx, args, paths.clone()),
    )]
}

/// Most characters of one line of a file that are repeated.
const MAX_LINE: usize = 200;
/// Most entries of the hosts file that are shown.
const MAX_HOSTS: usize = 50;
/// glibc asks at most this many nameservers.
const USED_NAMESERVERS: usize = 3;

fn cut(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        let mut kept: String = text.chars().take(max).collect();
        kept.push_str("...");
        kept
    }
}

/// The address in a nameserver entry, which may carry a zone (`fe80::1%eth0`).
fn server_address(word: &str) -> Option<IpAddr> {
    let (address, zone) = match word.split_once('%') {
        Some((address, zone)) => (address, Some(zone)),
        None => (word, None),
    };
    let zone_ok = zone.is_none_or(|zone| {
        !zone.is_empty()
            && zone.len() <= 16
            && zone
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
    });
    address.parse().ok().filter(|_| zone_ok)
}

fn is_domain(word: &str) -> bool {
    !word.is_empty()
        && word.len() <= 253
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

/// What a resolv.conf says, as the C library reads it.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ResolvConf {
    pub nameservers: Vec<String>,
    pub search: Vec<String>,
    pub options: Vec<String>,
}

/// Reads a resolv.conf.
///
/// AIDEV-NOTE: only what looks like what it should be is kept (a nameserver must be an
/// address, a domain a domain). These values are repeated in the tool's own first
/// line, and a file on the host must not be able to put words of its choosing there.
/// The same goes for what `parse_resolved_status` takes from resolvectl's output.
pub fn parse_resolv_conf(text: &str) -> ResolvConf {
    let mut conf = ResolvConf::default();
    for line in text.lines().take(1000) {
        let line = line.trim();
        if line.starts_with(['#', ';']) {
            continue;
        }
        // A trailing comment ends the line.
        let mut words = line
            .split_whitespace()
            .take_while(|word| !word.starts_with(['#', ';']));
        match words.next() {
            Some("nameserver") => {
                if let Some(server) = words.next()
                    && server_address(server).is_some()
                    && conf.nameservers.len() < 16
                {
                    conf.nameservers.push(server.to_string());
                }
            }
            // The last `search` or `domain` line is the one that counts.
            Some("search" | "domain") => {
                conf.search = words
                    .filter(|word| is_domain(word))
                    .take(12)
                    .map(str::to_string)
                    .collect();
            }
            Some("options") => {
                let plain = |word: &&str| {
                    word.len() <= 32
                        && word
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || ":_-".contains(c))
                };
                let room = 16usize.saturating_sub(conf.options.len());
                conf.options
                    .extend(words.filter(plain).take(room).map(str::to_string));
            }
            _ => {}
        }
    }
    conf
}

/// The number given to an option such as `ndots:5`.
fn option_value(conf: &ResolvConf, name: &str) -> Option<u32> {
    conf.options.iter().rev().find_map(|option| {
        let (key, value) = option.split_once(':')?;
        (key == name).then(|| value.parse().ok())?
    })
}

/// What deserves a remark in a resolv.conf, as bracketed notes.
pub fn resolv_notes(conf: &ResolvConf) -> Vec<String> {
    let mut notes = Vec::new();
    if let Some(unused) = conf.nameservers.get(USED_NAMESERVERS..)
        && !unused.is_empty()
    {
        notes.push(format!(
            "[only the first three nameservers are used: {} {} never asked]",
            unused.join(", "),
            if unused.len() == 1 { "is" } else { "are" }
        ));
    }
    if let Some(ndots) = option_value(conf, "ndots")
        && ndots > 1
    {
        notes.push(format!(
            "[ndots is {ndots}: a name with fewer than {ndots} dots is tried with every search \
             domain before it is tried as written, which multiplies the queries]"
        ));
    }
    if conf.options.iter().any(|option| option == "rotate") {
        notes.push(
            "[rotate is set: queries are spread over the nameservers rather than always \
             starting with the first]"
                .to_string(),
        );
    }
    if let Some(timeout) = option_value(conf, "timeout")
        && timeout < 2
    {
        notes.push(format!(
            "[timeout is {timeout} s: a nameserver that takes longer than that to answer counts \
             as having failed]"
        ));
    }
    notes
}

/// Who answers this host's queries, going by resolv.conf.
#[derive(Debug, PartialEq, Eq)]
pub enum Mode {
    /// systemd-resolved's local stub.
    Stub,
    /// Another resolver on this host (dnsmasq, unbound, named...), at this address.
    Local(String),
    /// The listed servers, asked directly.
    Direct,
    /// No nameserver is configured.
    Nothing,
}

/// The file systemd-resolved offers for programs to be pointed at its stub.
fn is_stub_file(real: &str) -> bool {
    real.ends_with("/systemd/resolve/stub-resolv.conf") || real.ends_with("/systemd/resolv.conf")
}

/// `real` is where resolv.conf really is, when it is a link.
pub fn mode(conf: &ResolvConf, real: Option<&str>) -> Mode {
    let addresses: Vec<IpAddr> = conf
        .nameservers
        .iter()
        .filter_map(|server| server_address(server))
        .collect();
    let Some(first) = conf.nameservers.first() else {
        return Mode::Nothing;
    };
    // The addresses systemd-resolved's stub listens on.
    let stub_addresses = ["127.0.0.53", "127.0.0.54"];
    let all_stub = conf
        .nameservers
        .iter()
        .all(|server| stub_addresses.contains(&server.as_str()));
    let all_local = !addresses.is_empty() && addresses.iter().all(IpAddr::is_loopback);
    if all_stub || (all_local && real.is_some_and(is_stub_file)) {
        Mode::Stub
    } else if all_local {
        Mode::Local(first.clone())
    } else {
        Mode::Direct
    }
}

/// The servers and domains systemd-resolved reports, across the global settings and
/// every link.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Resolved {
    pub servers: Vec<String>,
    pub domains: Vec<String>,
}

/// A DNS server as resolvectl prints it: an address, possibly with a zone, a port and
/// the name its certificate is checked against (`[2001:db8::53]:853#dns.example.com`).
fn listed_server(word: &str) -> Option<IpAddr> {
    let word = word.split('#').next().unwrap_or(word);
    if let Ok(socket) = word.parse::<SocketAddr>() {
        return Some(socket.ip());
    }
    let word = word.split('%').next().unwrap_or(word);
    word.parse().ok()
}

/// Reads `resolvectl status` (or the older `systemd-resolve --status`) output.
///
/// Newer versions print every server on one line; older ones print one per line, the
/// further lines indented and without a key. A line with `KEY: value` starts a new key.
pub fn parse_resolved_status(text: &str) -> Resolved {
    #[derive(Clone, Copy)]
    enum Collecting {
        Servers,
        Domains,
    }
    let mut found = Resolved::default();
    let mut collecting = None;
    let mut add = |into: Collecting, words: &str| {
        for word in words.split_whitespace() {
            match into {
                Collecting::Servers => {
                    if let Some(address) = listed_server(word) {
                        let address = address.to_string();
                        if !found.servers.contains(&address) && found.servers.len() < 64 {
                            found.servers.push(address);
                        }
                    }
                }
                Collecting::Domains => {
                    let name = word.strip_prefix('~').unwrap_or(word);
                    if is_domain(name)
                        && !found.domains.iter().any(|domain| domain == word)
                        && found.domains.len() < 64
                    {
                        found.domains.push(word.to_string());
                    }
                }
            }
        }
    };
    for line in text.lines().take(20_000) {
        match line.split_once(": ") {
            Some((key, value)) => {
                collecting = match key.trim() {
                    "DNS Servers" => Some(Collecting::Servers),
                    "DNS Domain" => Some(Collecting::Domains),
                    _ => None,
                };
                if let Some(into) = collecting {
                    add(into, value);
                }
            }
            None => match collecting {
                Some(into) if line.starts_with(char::is_whitespace) => add(into, line),
                _ => collecting = None,
            },
        }
    }
    found
}

/// `resolvectl status` without the links that have no DNS settings (a container host
/// has one per container). Returns the text and how many links were left out.
pub fn condense_status(text: &str) -> (String, usize) {
    let dns_keys = ["DNS Servers", "Current DNS Server", "DNS Domain"];
    let mut kept: Vec<String> = Vec::new();
    let mut left_out = 0usize;
    let mut block: Vec<&str> = Vec::new();
    let mut close = |block: &mut Vec<&str>| {
        if block.is_empty() {
            return;
        }
        let is_link = block.first().is_some_and(|line| line.starts_with("Link "));
        let has_dns = block.iter().any(|line| {
            line.split_once(':')
                .is_some_and(|(key, _)| dns_keys.contains(&key.trim()))
        });
        if is_link && !has_dns {
            left_out = left_out.saturating_add(1);
        } else {
            kept.push(block.join("\n"));
        }
        block.clear();
    };
    for line in text.lines() {
        if line.trim().is_empty() {
            close(&mut block);
        } else {
            block.push(line);
        }
    }
    close(&mut block);
    let mut out = kept.join("\n\n");
    if !out.is_empty() {
        out.push('\n');
    }
    (out, left_out)
}

/// The `hosts:` line of an nsswitch.conf.
pub fn nsswitch_hosts(text: &str) -> Option<String> {
    text.lines().take(1000).find_map(|line| {
        let sources = line.trim().strip_prefix("hosts:")?;
        let sources: Vec<&str> = sources
            .split_whitespace()
            .take_while(|word| !word.starts_with('#'))
            .collect();
        Some(cut(&format!("hosts: {}", sources.join(" ")), MAX_LINE))
    })
}

/// The entries of a hosts file: comments and blank lines dropped, spacing evened out.
pub fn hosts_entries(text: &str) -> Vec<String> {
    text.lines()
        .take(100_000)
        .filter_map(|line| {
            let line = line.split('#').next().unwrap_or(line);
            let words: Vec<&str> = line.split_whitespace().collect();
            // an address and at least one name
            let (address, names) = words.split_first()?;
            if names.is_empty() || server_address(address).is_none() {
                return None;
            }
            Some(cut(&words.join(" "), MAX_LINE))
        })
        .collect()
}

/// A list for the first line: the first four, then how many more there are.
fn short_list(items: &[String]) -> String {
    let shown: Vec<&str> = items.iter().take(4).map(String::as_str).collect();
    match items.len().saturating_sub(shown.len()) {
        0 => shown.join(", "),
        more => format!("{} and {more} more", shown.join(", ")),
    }
}

/// The one-sentence answer the result starts with.
///
/// `resolved` is what systemd-resolved reported, when it was asked and answered;
/// `not_answering` says that it was asked and did not answer.
///
/// AIDEV-NOTE: when resolv.conf points at systemd-resolved's stub and the service does
/// not answer, no name resolves on this host. That is the one state this line must not
/// describe as "resolves through ...": it is said first, as a PROBLEM.
pub fn summary(
    conf: Option<&ResolvConf>,
    mode: &Mode,
    resolved: Option<&Resolved>,
    not_answering: bool,
) -> String {
    let Some(conf) = conf else {
        return "The resolver configuration cannot be read: without it the C library asks a \
                resolver on this host (127.0.0.1)."
            .to_string();
    };
    let search = if conf.search.is_empty() {
        "no search domain".to_string()
    } else {
        format!("search {}", short_list(&conf.search))
    };
    let who = match mode {
        Mode::Stub => match resolved.filter(|resolved| !resolved.servers.is_empty()) {
            Some(resolved) => format!(
                "Resolves through systemd-resolved; upstream {}",
                short_list(&resolved.servers)
            ),
            None if not_answering => {
                "PROBLEM: names go through systemd-resolved, which is not answering".to_string()
            }
            None => "Resolves through systemd-resolved (its upstream servers could not be read)"
                .to_string(),
        },
        Mode::Local(address) => format!("Resolves through a resolver on this host at {address}"),
        Mode::Direct => format!(
            "Resolves by asking {} directly",
            short_list(&conf.nameservers)
        ),
        Mode::Nothing => "No nameserver is configured: the C library then asks a resolver on \
                          this host (127.0.0.1)"
            .to_string(),
    };
    format!("{who}; {search}.")
}

/// The start of a regular file as text. A file that is something else (a FIFO would
/// block) is not read.
fn read_text(path: &Path, max: u64) -> Result<String, String> {
    use rustix::fs::{Mode as FileMode, OFlags};
    use std::io::Read;
    let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    let file = rustix::fs::open(path, flags, FileMode::empty())
        .map(std::fs::File::from)
        .map_err(|e| std::io::Error::from(e).to_string())?;
    let is_file = file.metadata().map_err(|e| e.to_string())?.is_file();
    if !is_file {
        return Err("it is not a regular file".to_string());
    }
    let mut data = Vec::new();
    file.take(max)
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&data).into_owned())
}

/// What the three files say.
struct Files {
    resolv: Result<String, String>,
    /// Where resolv.conf really is, when it is a symbolic link.
    resolv_real: Option<String>,
    nsswitch: Result<String, String>,
    hosts: Result<String, String>,
}

fn read_files(paths: &Paths) -> Files {
    let is_link = std::fs::symlink_metadata(&paths.resolv_conf)
        .is_ok_and(|meta| meta.file_type().is_symlink());
    let resolv_real = if is_link {
        std::fs::canonicalize(&paths.resolv_conf)
            .ok()
            .map(|real| real.to_string_lossy().into_owned())
    } else {
        None
    };
    Files {
        resolv: read_text(&paths.resolv_conf, 64 * 1024),
        resolv_real,
        nsswitch: read_text(&paths.nsswitch, 64 * 1024),
        hosts: read_text(&paths.hosts, 1024 * 1024),
    }
}

/// What systemd-resolved had to say.
struct ResolvedPart {
    /// Its status, already without the links that have no DNS settings.
    status: String,
    /// Notes and statistics that follow the status (never cut).
    after: String,
    seen: Option<Resolved>,
    /// It was asked for its status and failed, or did not answer in time.
    not_answering: bool,
}

fn first_line(text: &str) -> String {
    cut(text.lines().next().unwrap_or("").trim(), MAX_LINE)
}

async fn run_within(
    ctx: &Ctx,
    clock: &CallClock,
    cmd: Cmd,
) -> Result<crate::exec::CmdOutput, String> {
    let Some(limit) = clock.next() else {
        return Err("the call ran out of time".to_string());
    };
    // Boxed: a running command's future is large, and this is awaited more than once.
    match Box::pin(ctx.run(cmd.timeout(limit))).await {
        Ok(out) => Ok(out),
        Err(ToolError::Failed(why)) => Err(why),
        Err(_) => Err("the command could not be run".to_string()),
    }
}

async fn resolved_part(ctx: &Ctx, clock: &CallClock) -> ResolvedPart {
    let note = |text: String| ResolvedPart {
        status: String::new(),
        after: text,
        seen: None,
        not_answering: false,
    };
    // `resolvectl` since systemd 239; before that the same thing was `systemd-resolve`.
    let (program, cmd, status_args): (&str, Cmd, [&str; 2]) =
        match ctx.optional_command("resolvectl") {
            Ok(Some(cmd)) => ("resolvectl", cmd, ["status", "--no-pager"]),
            Ok(None) => match ctx.optional_command("systemd-resolve") {
                Ok(Some(cmd)) => ("systemd-resolve", cmd, ["--status", "--no-pager"]),
                Ok(None) => return note("[not in use: resolvectl is not installed]\n".to_string()),
                Err(error) => return note(format!("[not available: {}]\n", reason(error))),
            },
            Err(error) => return note(format!("[not available: {}]\n", reason(error))),
        };
    let out = match run_within(ctx, clock, cmd.args(status_args)).await {
        Ok(out) => out,
        Err(why) => return note(format!("[not available: {}]\n", cut(&why, MAX_LINE))),
    };
    if !command_ok(&out) {
        // Asked, and it failed or took too long: when names go through it, that is why
        // nothing resolves, and the first line says so (see `summary`).
        let said = first_line(&command_text(&out));
        return ResolvedPart {
            status: String::new(),
            after: format!("[not answering: {said}]\n"),
            seen: None,
            not_answering: true,
        };
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let seen = parse_resolved_status(&text);
    let (status, left_out) = condense_status(&text);
    let mut after = String::new();
    if out.truncated {
        after.push_str("[the status was longer than is read: some links are missing]\n");
    }
    match left_out {
        0 => {}
        1 => after.push_str("[1 link without DNS settings left out]\n"),
        n => after.push_str(&format!("[{n} links without DNS settings left out]\n")),
    }
    // The cache figures, from the newer command only.
    if program == "resolvectl"
        && let Ok(Some(cmd)) = ctx.optional_command("resolvectl")
        && let Ok(stats) = run_within(ctx, clock, cmd.args(["statistics", "--no-pager"])).await
        && command_ok(&stats)
    {
        let lines: Vec<String> = String::from_utf8_lossy(&stats.stdout)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .take(24)
            .map(|line| cut(line, MAX_LINE))
            .collect();
        if !lines.is_empty() {
            after.push_str("-- statistics --\n");
            after.push_str(&lines.join("\n"));
            after.push('\n');
        }
    }
    ResolvedPart {
        status,
        after,
        seen: Some(seen),
        not_answering: false,
    }
}

fn reason(error: ToolError) -> String {
    match error {
        ToolError::Failed(why) | ToolError::Denied(why) | ToolError::Invalid(why) => {
            cut(&why, MAX_LINE)
        }
        ToolError::Internal(_) => "an internal error".to_string(),
    }
}

async fn dns_config(ctx: Ctx, _args: Args, paths: Arc<Paths>) -> ToolResult {
    let auth = ctx.authorize(None)?;
    let clock = CallClock::start(&ctx);
    let files = blocking(ctx.clone(), move || Ok(read_files(&paths))).await?;
    let resolved = resolved_part(&ctx, &clock).await;

    let conf = files
        .resolv
        .as_ref()
        .ok()
        .map(|text| parse_resolv_conf(text));
    let mode = match &conf {
        Some(conf) => mode(conf, files.resolv_real.as_deref()),
        None => Mode::Nothing,
    };

    let mut head = summary(
        conf.as_ref(),
        &mode,
        resolved.seen.as_ref(),
        resolved.not_answering,
    );
    head.push_str("\n== resolv.conf ==\n");
    if let Some(real) = &files.resolv_real {
        let meaning = if is_stub_file(real) {
            ": names go through systemd-resolved's stub at 127.0.0.53"
        } else if real.ends_with("/systemd/resolve/resolv.conf") {
            ": written by systemd-resolved, whose upstream servers are asked directly"
        } else {
            ""
        };
        head.push_str(&format!(
            "[a link to {}{meaning}]\n",
            super::one_line_cell(&cut(real, MAX_LINE))
        ));
    }
    match (&files.resolv, &conf) {
        (Ok(text), Some(conf)) => {
            let lines = resolver_lines(text);
            if lines.is_empty() {
                head.push_str("[it has no nameserver, search or options line]\n");
            }
            for line in lines {
                head.push_str(&cut(&line, MAX_LINE));
                head.push('\n');
            }
            for note in resolv_notes(conf) {
                head.push_str(&note);
                head.push('\n');
            }
        }
        (Err(why), _) => head.push_str(&format!("[cannot be read: {}]\n", cut(why, MAX_LINE))),
        (Ok(_), None) => {}
    }
    head.push_str("== systemd-resolved ==\n");

    let mut tail = resolved.after;
    tail.push_str("== nsswitch.conf ==\n");
    match &files.nsswitch {
        Ok(text) => match nsswitch_hosts(text) {
            Some(line) => {
                tail.push_str(&line);
                tail.push('\n');
            }
            None => tail.push_str(
                "[it has no hosts: line: the C library's default applies (the hosts file, then DNS)]\n",
            ),
        },
        Err(why) => tail.push_str(&format!("[cannot be read: {}]\n", cut(why, MAX_LINE))),
    }
    tail.push_str("== hosts file ==\n");
    match &files.hosts {
        Ok(text) => {
            let entries = hosts_entries(text);
            if entries.is_empty() {
                tail.push_str("[no entries]\n");
            }
            for entry in entries.iter().take(MAX_HOSTS) {
                tail.push_str(entry);
                tail.push('\n');
            }
            if let Some(more) = entries
                .len()
                .checked_sub(MAX_HOSTS)
                .filter(|more| *more > 0)
            {
                tail.push_str(&format!("[{more} more entries]\n"));
            }
        }
        Err(why) => tail.push_str(&format!("[cannot be read: {}]\n", cut(why, MAX_LINE))),
    }

    // AIDEV-NOTE: the status of systemd-resolved is the one part that can be long (a
    // container host has a link per container). It gets what the rest leaves, so the
    // short sections after it are never the ones that are lost to the output limit.
    let budget = ctx.output_budget();
    let room = budget.saturating_sub(head.len() + tail.len() + 120);
    let (status, dropped) = keep_head(&resolved.status, room);
    let mut text = head;
    text.push_str(&status);
    if dropped > 0 {
        text.push_str(&format!(
            "[{dropped} more lines of this status left out to fit the output limit]\n"
        ));
    }
    text.push_str(&tail);
    // Only with a very small limit can the rest be too much by itself.
    let (text, dropped) = keep_head(&text, budget);
    if dropped > 0 {
        return auth.ok(format!(
            "{text}[{dropped} more lines left out to fit the output limit]\n"
        ));
    }
    auth.ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::Host;
    use crate::tools::testing::{FakeBins, call, find, host, ok_text};
    use serde_json::json;

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn resolv_conf_is_read_the_way_the_c_library_reads_it() {
        let conf = parse_resolv_conf(
            "# managed elsewhere\n\
             ; another comment\n\
             domain old.example.com\n\
             nameserver 10.0.0.2\n\
             nameserver   10.0.0.3   # the second\n\
             nameserver fe80::1%eth0\n\
             search example.com  corp.example.com\n\
             options ndots:2 rotate\n\
             options timeout:1\n\
             sortlist 10.0.0.0/8\n\
             nameserver\n\
             nonsense\n",
        );
        assert_eq!(
            conf.nameservers,
            strings(&["10.0.0.2", "10.0.0.3", "fe80::1%eth0"])
        );
        // the last of search and domain wins
        assert_eq!(conf.search, strings(&["example.com", "corp.example.com"]));
        assert_eq!(conf.options, strings(&["ndots:2", "rotate", "timeout:1"]));
        assert_eq!(parse_resolv_conf(""), ResolvConf::default());
    }

    #[test]
    fn a_nameserver_that_is_not_an_address_is_not_repeated() {
        let conf = parse_resolv_conf(
            "nameserver dns.example.com\nnameserver 10.0.0.2;rm\nnameserver 10.0.0.2\n",
        );
        assert_eq!(conf.nameservers, strings(&["10.0.0.2"]));
    }

    #[test]
    fn resolv_conf_settings_that_surprise_people_are_pointed_out() {
        let conf = |text: &str| parse_resolv_conf(text);
        assert_eq!(
            resolv_notes(&conf("nameserver 10.0.0.2\nsearch example.com\n")),
            Vec::<String>::new()
        );
        let four = conf(
            "nameserver 10.0.0.1\nnameserver 10.0.0.2\nnameserver 10.0.0.3\nnameserver 10.0.0.4\n",
        );
        let notes = resolv_notes(&four);
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(
            notes[0].contains("first three") && notes[0].contains("10.0.0.4"),
            "{notes:?}"
        );

        let notes = resolv_notes(&conf(
            "nameserver 10.0.0.2\noptions ndots:5 rotate timeout:1 edns0\n",
        ));
        assert_eq!(notes.len(), 3, "{notes:?}");
        assert!(notes[0].contains("ndots is 5"), "{notes:?}");
        assert!(notes[1].contains("rotate"), "{notes:?}");
        assert!(notes[2].contains("timeout is 1 s"), "{notes:?}");
        // the defaults and harmless options are not worth a line
        assert!(
            resolv_notes(&conf(
                "nameserver 10.0.0.2\noptions ndots:1 timeout:5 edns0 trust-ad\n"
            ))
            .is_empty()
        );
        for note in notes {
            assert!(note.starts_with('[') && note.ends_with(']'), "{note}");
        }
    }

    #[test]
    fn who_answers_is_told_from_the_servers_and_from_where_the_file_lives() {
        let conf = |text: &str| parse_resolv_conf(text);
        let stub = conf("nameserver 127.0.0.53\noptions edns0 trust-ad\n");
        assert_eq!(mode(&stub, None), Mode::Stub);
        assert_eq!(
            mode(&stub, Some("/run/systemd/resolve/stub-resolv.conf")),
            Mode::Stub
        );
        // systemd-resolved's own list of upstream servers: asked directly, no stub
        let upstream = conf("nameserver 10.0.0.2\nnameserver 10.0.0.3\n");
        assert_eq!(
            mode(&upstream, Some("/run/systemd/resolve/resolv.conf")),
            Mode::Direct
        );
        assert_eq!(mode(&upstream, None), Mode::Direct);
        assert_eq!(
            mode(&conf("nameserver 127.0.0.1\n"), None),
            Mode::Local("127.0.0.1".to_string())
        );
        assert_eq!(
            mode(&conf("nameserver ::1\n"), None),
            Mode::Local("::1".to_string())
        );
        // one outside server is enough for queries to leave the host
        assert_eq!(
            mode(&conf("nameserver 127.0.0.1\nnameserver 10.0.0.2\n"), None),
            Mode::Direct
        );
        assert_eq!(mode(&conf("search example.com\n"), None), Mode::Nothing);
    }

    const STATUS_NEW: &str = "Global
         Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
  resolv.conf mode: stub

Link 2 (eth0)
    Current Scopes: DNS
         Protocols: +DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
Current DNS Server: 10.0.0.2
       DNS Servers: 10.0.0.2 10.0.0.3 2001:db8::53
        DNS Domain: example.com ~corp.example.com

Link 3 (docker0)
    Current Scopes: none
         Protocols: -DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported

Link 5 (veth1a2b3c)
    Current Scopes: none
         Protocols: -DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
";

    const STATUS_OLD: &str = "Global
          DNSSEC NTA: 10.in-addr.arpa
                      16.172.in-addr.arpa

Link 2 (ens3)
      Current Scopes: DNS
       LLMNR setting: yes
MulticastDNS setting: no
      DNSSEC setting: no
    DNSSEC supported: no
         DNS Servers: 10.0.0.2
                      10.0.0.3
                      2001:db8::53
          DNS Domain: example.com
                      corp.example.com
";

    #[test]
    fn the_servers_and_domains_of_systemd_resolved_are_found_in_both_layouts() {
        let new = parse_resolved_status(STATUS_NEW);
        assert_eq!(
            new.servers,
            strings(&["10.0.0.2", "10.0.0.3", "2001:db8::53"])
        );
        assert_eq!(new.domains, strings(&["example.com", "~corp.example.com"]));
        let old = parse_resolved_status(STATUS_OLD);
        assert_eq!(
            old.servers,
            strings(&["10.0.0.2", "10.0.0.3", "2001:db8::53"])
        );
        assert_eq!(old.domains, strings(&["example.com", "corp.example.com"]));
        assert_eq!(
            parse_resolved_status("Failed to get global data: not found\n"),
            Resolved::default()
        );
    }

    #[test]
    fn a_server_listed_on_two_links_counts_once_and_decorations_are_dropped() {
        let text = "Global\n       DNS Servers: 10.0.0.2#dns.example.com 10.0.0.2\n\n\
                    Link 2 (eth0)\n       DNS Servers: 10.0.0.2 fe80::1%2 [2001:db8::53]:853#x\n";
        assert_eq!(
            parse_resolved_status(text).servers,
            strings(&["10.0.0.2", "fe80::1", "2001:db8::53"])
        );
    }

    #[test]
    fn links_without_dns_settings_are_left_out_of_the_status() {
        let (text, left_out) = condense_status(STATUS_NEW);
        assert_eq!(left_out, 2);
        assert!(text.starts_with("Global\n"), "{text}");
        assert!(text.contains("Link 2 (eth0)"), "{text}");
        assert!(text.contains("DNS Servers: 10.0.0.2 10.0.0.3"), "{text}");
        assert!(
            !text.contains("docker0") && !text.contains("veth1a2b3c"),
            "{text}"
        );
        // the old layout has one block, and it is kept
        let (text, left_out) = condense_status(STATUS_OLD);
        assert_eq!(left_out, 0);
        assert!(
            text.contains("Link 2 (ens3)") && text.contains("16.172.in-addr.arpa"),
            "{text}"
        );
        // anything unexpected passes through
        assert_eq!(
            condense_status("something else\n"),
            ("something else\n".to_string(), 0)
        );
    }

    #[test]
    fn the_hosts_line_of_nsswitch_is_found() {
        let text = "passwd: files systemd\n# hosts: commented out\nhosts:   files mymachines resolve [!UNAVAIL=return] dns\nnetworks: files\n";
        assert_eq!(
            nsswitch_hosts(text).as_deref(),
            Some("hosts: files mymachines resolve [!UNAVAIL=return] dns")
        );
        assert_eq!(nsswitch_hosts("passwd: files\n"), None);
    }

    #[test]
    fn hosts_entries_are_the_lines_that_name_something() {
        let text = "# a comment\n\n127.0.0.1\tlocalhost\n10.0.0.7   db1.example.com   db1   # the database\n   \n::1 ip6-localhost ip6-loopback\n#10.0.0.8 old\n10.0.0.9\n";
        assert_eq!(
            hosts_entries(text),
            strings(&[
                "127.0.0.1 localhost",
                "10.0.0.7 db1.example.com db1",
                "::1 ip6-localhost ip6-loopback",
            ])
        );
    }

    #[test]
    fn the_summary_says_who_answers_and_which_domains_are_searched() {
        let conf = parse_resolv_conf("nameserver 127.0.0.53\nsearch example.com\n");
        let resolved = parse_resolved_status(STATUS_NEW);
        assert_eq!(
            summary(Some(&conf), &Mode::Stub, Some(&resolved), false),
            "Resolves through systemd-resolved; upstream 10.0.0.2, 10.0.0.3, 2001:db8::53; search example.com."
        );
        assert_eq!(
            summary(Some(&conf), &Mode::Stub, None, false),
            "Resolves through systemd-resolved (its upstream servers could not be read); search example.com."
        );
        let direct = parse_resolv_conf("nameserver 10.0.0.2\nnameserver 10.0.0.3\n");
        assert_eq!(
            summary(Some(&direct), &Mode::Direct, None, false),
            "Resolves by asking 10.0.0.2, 10.0.0.3 directly; no search domain."
        );
        let local = parse_resolv_conf("nameserver 127.0.0.1\nsearch a.example.com b.example.com\n");
        assert_eq!(
            summary(
                Some(&local),
                &Mode::Local("127.0.0.1".to_string()),
                None,
                false
            ),
            "Resolves through a resolver on this host at 127.0.0.1; search a.example.com, b.example.com."
        );
        let none = parse_resolv_conf("");
        assert!(
            summary(Some(&none), &Mode::Nothing, None, false)
                .starts_with("No nameserver is configured"),
        );
        assert!(summary(None, &Mode::Nothing, None, false).contains("cannot be read"));
    }

    /// AIDEV-NOTE: resolv.conf pointing at 127.0.0.53 with systemd-resolved stopped is
    /// the state in which NO name resolves on the host. The first line used to read as
    /// if all were well ("Resolves through systemd-resolved (...)").
    #[test]
    fn a_stub_whose_service_does_not_answer_is_a_problem_in_the_first_line() {
        let conf = parse_resolv_conf("nameserver 127.0.0.53\nsearch example.com\n");
        assert_eq!(
            summary(Some(&conf), &Mode::Stub, None, true),
            "PROBLEM: names go through systemd-resolved, which is not answering; search example.com."
        );
        // names that do not go through it are not affected by its being down
        let direct = parse_resolv_conf("nameserver 10.0.0.2\n");
        assert_eq!(
            summary(Some(&direct), &Mode::Direct, None, true),
            "Resolves by asking 10.0.0.2 directly; no search domain."
        );
        let local = parse_resolv_conf("nameserver 127.0.0.1\n");
        assert!(
            summary(
                Some(&local),
                &Mode::Local("127.0.0.1".to_string()),
                None,
                true
            )
            .starts_with("Resolves through a resolver on this host"),
        );
    }

    #[test]
    fn a_long_list_of_upstream_servers_is_shortened_in_the_summary() {
        let conf = parse_resolv_conf("nameserver 127.0.0.53\n");
        let resolved = Resolved {
            servers: strings(&[
                "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6",
            ]),
            domains: Vec::new(),
        };
        let text = summary(Some(&conf), &Mode::Stub, Some(&resolved), false);
        assert!(text.contains("10.0.0.4 and 2 more"), "{text}");
        assert!(!text.contains("10.0.0.5"), "{text}");
    }

    // ---- the tool ----------------------------------------------------------------------

    struct Fixture {
        dir: tempfile::TempDir,
        host: Arc<Host>,
        sink: MemorySink,
    }

    impl Fixture {
        fn paths(dir: &tempfile::TempDir) -> Paths {
            Paths {
                resolv_conf: dir.path().join("resolv.conf"),
                nsswitch: dir.path().join("nsswitch.conf"),
                hosts: dir.path().join("hosts"),
            }
        }

        fn new(fake: &FakeBins, extra: &str) -> Fixture {
            let dir = tempfile::tempdir().unwrap();
            let (host, sink) = host(&format!(
                "[roles.reader]\nallow = [\"@read\"]\n[roles.none]\nallow = [\"system.view\"]\n\
                 [unix_users.rita]\nroles = [\"reader\"]\n[unix_users.nora]\nroles = [\"none\"]\n{extra}{}",
                fake.config_only()
            ));
            Fixture { dir, host, sink }
        }

        fn write(&self, name: &str, text: &str) {
            std::fs::write(self.dir.path().join(name), text).unwrap();
        }

        async fn run(&self, user: &str) -> ToolResult {
            let tool = find(tools_with(Fixture::paths(&self.dir)), "dns_config");
            call(&self.host, user, &tool, json!({})).await
        }
    }

    /// A stand-in resolvectl that prints `status` (which must hold no single quote).
    fn resolvectl(status: &str) -> FakeBins {
        assert!(!status.contains('\''));
        FakeBins::new().add_script(
            "resolvectl",
            &format!(
                "case \"$1\" in\n\
                 status) printf '%s' '{status}';;\n\
                 statistics) printf 'Transactions\\nCurrent Transactions: 0\\nCache\\n  Current Cache Size: 12\\n          Cache Hits: 340\\n        Cache Misses: 56\\n';;\n\
                 esac"
            ),
        )
    }

    #[test]
    fn it_is_a_read_tool_under_net_view_and_takes_no_arguments() {
        let tool = find(tools(), "dns_config");
        assert_eq!(tool.access, Access::Read);
        assert_eq!(tool.permission, "net.view");
        assert!(tool.params.is_empty());
    }

    #[tokio::test]
    async fn a_host_on_systemd_resolved_gets_the_whole_picture() {
        let fake = resolvectl(STATUS_NEW);
        let fixture = Fixture::new(&fake, "");
        // as on a real host: resolv.conf is a link to the stub file
        fixture.write(
            "stub-resolv.conf",
            "# This is /run/systemd/resolve/stub-resolv.conf\nnameserver 127.0.0.53\noptions edns0 trust-ad\nsearch example.com\n",
        );
        std::os::unix::fs::symlink(
            fixture.dir.path().join("stub-resolv.conf"),
            fixture.dir.path().join("resolv.conf"),
        )
        .unwrap();
        fixture.write(
            "nsswitch.conf",
            "hosts: files resolve [!UNAVAIL=return] dns\n",
        );
        fixture.write(
            "hosts",
            "127.0.0.1 localhost\n10.0.0.7 db1.example.com db1\n",
        );

        let text = ok_text(fixture.run("rita").await);
        let first = text.lines().next().unwrap();
        assert_eq!(
            first,
            "Resolves through systemd-resolved; upstream 10.0.0.2, 10.0.0.3, 2001:db8::53; search example.com."
        );
        for wanted in [
            "== resolv.conf ==",
            "stub-resolv.conf",
            "nameserver 127.0.0.53",
            "search example.com",
            "== systemd-resolved ==",
            "Link 2 (eth0)",
            "[2 links without DNS settings left out]",
            "Cache Hits: 340",
            "== nsswitch.conf ==",
            "hosts: files resolve [!UNAVAIL=return] dns",
            "== hosts file ==",
            "10.0.0.7 db1.example.com db1",
        ] {
            assert!(text.contains(wanted), "missing {wanted:?} in:\n{text}");
        }
        assert!(!text.contains("docker0"), "{text}");
        assert_eq!(
            fake.calls("resolvectl"),
            vec![
                strings(&["status", "--no-pager"]),
                strings(&["statistics", "--no-pager"])
            ]
        );
        // one audited decision, for the tool as a whole
        let records = fixture.sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["decision"], "allow");
        assert!(records[0].get("resource").is_none());
    }

    #[tokio::test]
    async fn a_host_without_systemd_resolved_is_described_from_its_files() {
        let fake = FakeBins::new();
        let fixture = Fixture::new(&fake, "");
        fixture.write(
            "resolv.conf",
            "nameserver 10.0.0.1\nnameserver 10.0.0.2\nnameserver 10.0.0.3\nnameserver 10.0.0.4\noptions ndots:5\n",
        );
        fixture.write("hosts", "127.0.0.1 localhost\n");
        let text = ok_text(fixture.run("rita").await);
        assert!(
            text.starts_with("Resolves by asking 10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.4 directly; no search domain.\n"),
            "{text}"
        );
        assert!(
            text.contains("[only the first three nameservers are used"),
            "{text}"
        );
        assert!(text.contains("[ndots is 5"), "{text}");
        assert!(
            text.contains("== systemd-resolved ==\n[not in use: resolvectl is not installed]"),
            "{text}"
        );
        // a file that is not there is said so, and is not an error
        assert!(
            text.contains("== nsswitch.conf ==\n[cannot be read:"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn the_older_command_name_is_used_where_there_is_no_resolvectl() {
        let fake = FakeBins::new().add_script(
            "systemd-resolve",
            "printf 'Global\\n         DNS Servers: 10.0.0.2\\n'",
        );
        let fixture = Fixture::new(&fake, "");
        fixture.write("resolv.conf", "nameserver 127.0.0.53\n");
        let text = ok_text(fixture.run("rita").await);
        assert!(
            text.starts_with(
                "Resolves through systemd-resolved; upstream 10.0.0.2; no search domain.\n"
            ),
            "{text}"
        );
        assert_eq!(
            fake.calls("systemd-resolve"),
            vec![strings(&["--status", "--no-pager"])]
        );
    }

    #[tokio::test]
    async fn systemd_resolved_not_running_is_a_note_not_a_failure() {
        let fake = FakeBins::new().add_script(
            "resolvectl",
            "echo 'Failed to get global data: Unit dbus-org.freedesktop.resolve1.service not found.' >&2\nexit 1",
        );
        let fixture = Fixture::new(&fake, "");
        fixture.write("resolv.conf", "nameserver 10.0.0.2\nsearch example.com\n");
        let text = ok_text(fixture.run("rita").await);
        assert!(
            text.starts_with("Resolves by asking 10.0.0.2 directly; search example.com.\n"),
            "{text}"
        );
        assert!(
            text.contains("== systemd-resolved ==\n[not answering: Failed to get global data"),
            "{text}"
        );
        // statistics are not asked of a service that did not answer
        assert_eq!(fake.calls("resolvectl").len(), 1);
    }

    #[tokio::test]
    async fn names_that_go_through_a_stopped_systemd_resolved_are_a_problem() {
        let fake = FakeBins::new().add_script(
            "resolvectl",
            "echo 'Failed to get global data: Unit dbus-org.freedesktop.resolve1.service not found.' >&2\nexit 1",
        );
        let fixture = Fixture::new(&fake, "");
        fixture.write(
            "resolv.conf",
            "nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch example.com\n",
        );
        let text = ok_text(fixture.run("rita").await);
        assert!(
            text.starts_with(
                "PROBLEM: names go through systemd-resolved, which is not answering; search example.com.\n"
            ),
            "{text}"
        );
        assert!(
            text.contains("== systemd-resolved ==\n[not answering: Failed to get global data"),
            "{text}"
        );

        // one that never finishes is not answering either
        let fake = FakeBins::new().add_script("resolvectl", "while :; do :; done");
        let fixture = Fixture::new(
            &fake,
            "[limits]\ncommand_timeout_secs = 1\ncall_timeout_secs = 20\n",
        );
        fixture.write("resolv.conf", "nameserver 127.0.0.53\n");
        let text = ok_text(fixture.run("rita").await);
        assert!(
            text.starts_with("PROBLEM: names go through systemd-resolved, which is not answering;"),
            "{text}"
        );

        // without resolvectl it cannot be asked: no claim either way
        let fake = FakeBins::new();
        let fixture = Fixture::new(&fake, "");
        fixture.write("resolv.conf", "nameserver 127.0.0.53\n");
        let text = ok_text(fixture.run("rita").await);
        assert!(
            text.starts_with(
                "Resolves through systemd-resolved (its upstream servers could not be read);"
            ),
            "{text}"
        );
    }

    #[tokio::test]
    async fn a_long_hosts_file_is_cut_with_a_count() {
        let fake = FakeBins::new();
        let fixture = Fixture::new(&fake, "");
        fixture.write("resolv.conf", "nameserver 10.0.0.2\n");
        let hosts: String = (0..73).map(|n| format!("10.1.0.{n} host{n}\n")).collect();
        fixture.write("hosts", &hosts);
        let text = ok_text(fixture.run("rita").await);
        assert!(text.contains("10.1.0.49 host49\n"), "{text}");
        assert!(!text.contains("host50"), "{text}");
        assert!(text.contains("[23 more entries]"), "{text}");
    }

    #[tokio::test]
    async fn a_missing_resolv_conf_is_reported_in_the_first_line() {
        let fake = FakeBins::new();
        let fixture = Fixture::new(&fake, "");
        let text = ok_text(fixture.run("rita").await);
        assert!(
            text.lines().next().unwrap().contains("cannot be read"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn the_output_stays_within_the_limit() {
        let mut status = String::from("Global\n       DNS Servers: 10.0.0.2\n");
        for n in 0..400 {
            status.push_str(&format!(
                "\nLink {n} (eth{n})\n       DNS Servers: 10.0.{}.{}\n        DNS Domain: zone{n}.example.com\n",
                n / 250,
                n % 250
            ));
        }
        let fake = resolvectl(&status);
        let fixture = Fixture::new(&fake, "[limits]\nmax_output_bytes = 4096\n");
        fixture.write("resolv.conf", "nameserver 127.0.0.53\n");
        fixture.write("hosts", "127.0.0.1 localhost\n");
        let text = ok_text(fixture.run("rita").await);
        assert!(text.len() <= 4096, "{}", text.len());
        assert!(text.contains("left out to fit the output limit"), "{text}");
        // the short sections after the long one are still there
        assert!(
            text.contains("== hosts file ==\n127.0.0.1 localhost"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn it_needs_net_view() {
        let fake = FakeBins::new().add("resolvectl", "Global\n", 0);
        let fixture = Fixture::new(&fake, "");
        fixture.write("resolv.conf", "nameserver 10.0.0.2\n");
        match fixture.run("nora").await {
            Err(ToolError::Denied(message)) => {
                assert!(message.contains("net.view"), "{message}")
            }
            other => panic!("expected a denial, got {other:?}"),
        }
        assert!(fake.calls("resolvectl").is_empty());
    }
}
