//! Network: interfaces, routes, sockets, probes and packet capture.

use std::collections::BTreeMap;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::args::{Args, Kind, Param};
use super::{
    Authorized, Ctx, Tool, ToolError, ToolResult, blocking, command_ok, command_text, format_rows,
    format_table, required,
};
use crate::glob::glob_match;
use crate::policy::Access;
use crate::sanitize::keep_head;

const SYS_NET: &str = "/sys/class/net";
const PROC_BONDING: &str = "/proc/net/bonding";
const RESOLV_CONF: &str = "/etc/resolv.conf";

/// Most interfaces given a link-state line (a container host can have hundreds of veths).
const MAX_INTERFACES: usize = 256;
/// Most addresses of one name that a TCP probe tries.
const MAX_PROBE_ADDRESSES: usize = 4;
const TCP_CONNECT_LIMIT: Duration = Duration::from_secs(5);
const RESOLVE_LIMIT: Duration = Duration::from_secs(10);
/// Bytes of `ss` output kept for a summary: enough for well over 100,000 sockets.
const SUMMARY_MAX_OUTPUT: usize = 16 * 1024 * 1024;
const MAX_FILTER_TOKENS: usize = 64;
const MAX_FILTER_TOKEN_LEN: usize = 64;
/// Bytes of each packet printed when contents are asked for.
const PAYLOAD_SNAPLEN: &str = "512";
/// Bytes captured of each packet otherwise: enough for the link, IP and TCP headers.
const HEADER_SNAPLEN: &str = "96";

pub fn tools() -> Vec<Tool> {
    vec![
        interfaces_tool(PathBuf::from(SYS_NET), PathBuf::from(PROC_BONDING)),
        Tool::new(
            "net_routes",
            "Show the routing tables (ip route) and, on request, the policy routing rules \
             (ip rule) and the neighbour (ARP/NDP) table (ip neigh), for IPv4 and IPv6. Use \
             it to see where traffic for an address would be sent, or whether a neighbour \
             is reachable.",
            Access::Read,
            "net.view",
            vec![
                Param::choice(
                    "show",
                    "What to show (default routes)",
                    &["routes", "rules", "neighbours", "all"],
                ),
                Param::choice(
                    "family",
                    "IPv4, IPv6 or both (default both)",
                    &["4", "6", "both"],
                ),
                Param::str(
                    "table",
                    "Routing table to show routes from: a name or number such as main, local \
                     or 100, or 'all' (default: the main table)",
                )
                .max_len(32),
            ],
            net_routes,
        ),
        Tool::new(
            "net_sockets",
            "Show TCP and UDP sockets and the process that owns each (ss): what is listening \
             by default, or the established connections, optionally only those using one \
             port. With summary, counts TCP sockets by state and shows the busiest local \
             ports and peers instead of listing them, which is the better choice on a busy \
             host.",
            Access::Read,
            "net.view",
            vec![
                Param::choice(
                    "state",
                    "Which sockets to list (default listening)",
                    &["listening", "connected", "all"],
                ),
                Param::choice(
                    "protocol",
                    "tcp, udp or all (default all)",
                    &["tcp", "udp", "all"],
                ),
                Param::int(
                    "port",
                    "Only sockets whose local or remote port is this one",
                    1,
                    65535,
                ),
                Param::int("limit", "Most sockets to list (default 200)", 1, 2000),
                Param::bool(
                    "summary",
                    "Count TCP sockets (by state, local port and peer) instead of listing; \
                     state, protocol and limit are then ignored",
                ),
            ],
            net_sockets,
        ),
        Tool::new(
            "net_probe",
            "Test from this host whether another host can be reached: ping it, open a TCP \
             connection to one of its ports (nothing is sent), trace the route to it, or \
             resolve its name with this host's own resolver. Answers questions like 'can \
             this host reach the database?'. Only targets that this host's configuration \
             (net.probe_targets) allows can be probed.",
            Access::Read,
            "net.probe",
            vec![
                Param::str(
                    "target",
                    "Host to probe: a host name, or an IPv4 or IPv6 address (no port, no URL)",
                )
                .max_len(254)
                .required(),
                Param::choice(
                    "mode",
                    "ping (default), tcp (connect to port), trace (route) or dns (resolve the name)",
                    &["ping", "tcp", "trace", "dns"],
                ),
                Param::int(
                    "port",
                    "TCP port to connect to (needed for mode tcp)",
                    1,
                    65535,
                ),
                Param::int("count", "Pings to send (default 3)", 1, 10),
                Param::choice(
                    "family",
                    "Use only IPv4 or only IPv6 (default auto: whatever the name resolves to)",
                    &["4", "6", "auto"],
                ),
            ],
            net_probe,
        ),
        // AIDEV-NOTE: packet_capture changes nothing on the host, yet it is tagged WRITE
        // on purpose. The `@read` group grants every read permission, and a role that is
        // "read-only" must never thereby get the ability to read other people's traffic.
        // Do not "correct" this to Access::Read.
        Tool::new(
            "packet_capture",
            "Capture packets on one network interface with tcpdump and return one line per \
             packet: time, addresses, ports, protocol and length. TCP flags, decoded \
             protocol detail and packet contents are shown only with payload, where this \
             host allows it; without it, use the filter to pick out what matters (for \
             example [\"tcp[tcpflags]\", \"&\", \"tcp-rst\", \"!=\", \"0\"] for resets). Stops \
             after a number of packets or seconds, whichever comes first. Works only on \
             the interfaces this host's configuration (net.capture_interfaces) allows, \
             and does not put the interface into promiscuous mode.",
            Access::Write,
            "net.capture",
            vec![
                Param::str("interface", "Interface to capture on, e.g. eth0")
                    .max_len(15)
                    .required(),
                Param {
                    kind: Kind::StrList {
                        max_items: MAX_FILTER_TOKENS,
                        max_len: MAX_FILTER_TOKEN_LEN,
                    },
                    ..Param::list(
                        "filter",
                        "A tcpdump filter expression, one word per item, e.g. \
                         [\"host\", \"10.0.0.5\", \"and\", \"tcp\", \"port\", \"443\"] (default: every packet)",
                    )
                },
                Param::int(
                    "count",
                    "Stop after this many packets (default 100)",
                    1,
                    1000,
                ),
                Param::int(
                    "seconds",
                    "Stop after this many seconds (default 10)",
                    1,
                    30,
                ),
                Param::bool(
                    "payload",
                    "Also show TCP flags, decoded protocol detail and the start of each \
                     packet's contents (only where the host's configuration allows it)",
                ),
            ],
            packet_capture,
        ),
    ]
}

/// net_interfaces, reading link state from `sys_root` (normally /sys/class/net) and bond
/// details from `bonding_root` (normally /proc/net/bonding). Tests point both elsewhere.
fn interfaces_tool(sys_root: PathBuf, bonding_root: PathBuf) -> Tool {
    Tool::new(
        "net_interfaces",
        "Show this host's network interfaces: addresses, state, MTU, and packet, error and \
         drop counters (ip -s -d address), plus link speed and duplex where the driver \
         reports them. Name an interface to see just that one (a bond also gets the status \
         of its members); use brief for one line per interface.",
        Access::Read,
        "net.view",
        vec![
            Param::str("interface", "Only this interface, e.g. eth0 or bond0").max_len(15),
            Param::bool(
                "brief",
                "One line per interface: name, state and addresses only",
            ),
        ],
        move |ctx, args| net_interfaces(ctx, args, sys_root.clone(), bonding_root.clone()),
    )
}

// ---- shared helpers -------------------------------------------------------------------

fn end_line(text: &mut String) {
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
}

/// `text` cut to at most `budget` bytes, keeping its start and ending on a whole line,
/// with a note saying how much was left out and (`hint`) what to do about it.
fn fit_head(text: &str, budget: usize, hint: &str) -> String {
    let (whole, dropped) = keep_head(text, budget);
    if dropped == 0 {
        return whole;
    }
    let (mut kept, dropped) = keep_head(text, budget.saturating_sub(200));
    end_line(&mut kept);
    kept.push_str(&format!(
        "[{dropped} more lines left out to fit the output limit; {hint}]\n"
    ));
    kept
}

/// The start of a small file, or `None` if it cannot be read (or is not a plain file).
fn read_small(path: &Path, max: u64) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut data = Vec::new();
    file.take(max).read_to_end(&mut data).ok()?;
    Some(String::from_utf8_lossy(&data).into_owned())
}

/// Checks an interface name.
///
/// AIDEV-NOTE: the name becomes an argument of `ip` and `tcpdump` and a component of
/// paths under /sys and /proc. So: no leading `-` (an option), no `/`, and not `.` or
/// `..` (another directory). The kernel's own rules (at most 15 bytes, no `/`, no
/// whitespace) are narrower than this in places and that is fine.
pub fn check_interface(name: &str) -> Result<(), ToolError> {
    let allowed = |c: char| c.is_ascii_alphanumeric() || "_.-@:".contains(c);
    let ok = !name.is_empty()
        && name.len() <= 15
        && !name.starts_with('-')
        && name != "."
        && name != ".."
        && name.chars().all(allowed);
    if ok {
        Ok(())
    } else {
        Err(ToolError::Invalid(format!(
            "{name:?} is not an interface name (at most 15 letters, digits and _ . - @ :, not starting with -)"
        )))
    }
}

// ---- net_interfaces -------------------------------------------------------------------

/// One line about an interface's link from sysfs: state, speed, duplex, MTU and how often
/// the carrier changed. `None` when sysfs has nothing readable for that name.
fn link_line(sys_root: &Path, name: &str) -> Option<String> {
    let dir = sys_root.join(name);
    let value = |file: &str| {
        read_small(&dir.join(file), 256)
            .map(|text| text.trim().to_string())
            .filter(|text| !text.is_empty())
    };
    let mut parts = Vec::new();
    if let Some(state) = value("operstate") {
        parts.push(format!("state {state}"));
    }
    // The driver reports -1 (or fails the read) when it does not know the speed.
    if let Some(speed) = value("speed").and_then(|s| s.parse::<i64>().ok())
        && speed > 0
    {
        parts.push(format!("speed {speed} Mb/s"));
    }
    if let Some(duplex) = value("duplex").filter(|d| d != "unknown") {
        parts.push(format!("duplex {duplex}"));
    }
    if let Some(mtu) = value("mtu") {
        parts.push(format!("mtu {mtu}"));
    }
    if let Some(changes) = value("carrier_changes") {
        parts.push(format!("carrier changes {changes}"));
    }
    if parts.is_empty() {
        None
    } else {
        Some(format!("{name}: {}", parts.join(", ")))
    }
}

/// The interfaces sysfs lists, in name order.
fn interface_names(sys_root: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(sys_root) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| check_interface(name).is_ok())
        .collect();
    names.sort();
    names.truncate(MAX_INTERFACES);
    names
}

/// What sysfs and the bonding driver add to `ip`'s output: a link-state line for each
/// interface (or for `only`), and for a bond asked for by name, its members' status.
fn link_details(sys_root: &Path, bonding_root: &Path, only: Option<&str>) -> String {
    let names = match only {
        Some(name) => vec![name.to_string()],
        None => interface_names(sys_root),
    };
    let lines: Vec<String> = names
        .iter()
        .filter_map(|name| link_line(sys_root, name))
        .collect();
    let mut text = String::new();
    if !lines.is_empty() {
        text.push_str("== link state (/sys/class/net) ==\n");
        for line in lines {
            text.push_str(&line);
            text.push('\n');
        }
    }
    if let Some(name) = only
        && let Some(bond) = read_small(&bonding_root.join(name), 64 * 1024)
    {
        text.push_str(&format!("== bonding (/proc/net/bonding/{name}) ==\n{bond}"));
        end_line(&mut text);
    }
    text
}

async fn net_interfaces(
    ctx: Ctx,
    args: Args,
    sys_root: PathBuf,
    bonding_root: PathBuf,
) -> ToolResult {
    let interface = args.str("interface").map(str::to_string);
    if let Some(name) = &interface {
        check_interface(name)?;
    }
    let mut argv: Vec<String> = if args.bool("brief") == Some(true) {
        vec!["-br".to_string()]
    } else {
        vec!["-s".to_string(), "-d".to_string()]
    };
    argv.extend(["address".to_string(), "show".to_string()]);
    if let Some(name) = &interface {
        argv.extend(["dev".to_string(), name.clone()]);
    }
    let auth = ctx.authorize(None)?;
    let out = ctx.run(ctx.command("ip")?.args(argv)).await?;
    let mut text = command_text(&out);
    if !command_ok(&out) {
        return auth.failed(text);
    }
    let details = blocking(ctx.clone(), move || {
        Ok(link_details(&sys_root, &bonding_root, interface.as_deref()))
    })
    .await?;
    end_line(&mut text);
    text.push_str(&details);
    auth.ok(fit_head(
        &text,
        ctx.output_budget(),
        "ask for one interface, or use brief",
    ))
}

// ---- net_routes -----------------------------------------------------------------------

/// Checks a routing table name or number (`ip route show table NAME`).
pub fn check_table(name: &str) -> Result<(), ToolError> {
    let allowed = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
    if name.is_empty() || name.len() > 32 || name.starts_with('-') || !name.chars().all(allowed) {
        return Err(ToolError::Invalid(format!(
            "{name:?} is not a routing table (a name or number such as main, local or 100, or 'all')"
        )));
    }
    Ok(())
}

async fn net_routes(ctx: Ctx, args: Args) -> ToolResult {
    let table = args.str("table").map(str::to_string);
    if let Some(table) = &table {
        check_table(table)?;
    }
    let kinds: &[&str] = match args.str("show").unwrap_or("routes") {
        "rules" => &["rules"],
        "neighbours" => &["neighbours"],
        "all" => &["routes", "rules", "neighbours"],
        _ => &["routes"],
    };
    let families: &[(&str, &str)] = match args.str("family").unwrap_or("both") {
        "4" => &[("-4", "IPv4")],
        "6" => &[("-6", "IPv6")],
        _ => &[("-4", "IPv4"), ("-6", "IPv6")],
    };
    let auth = ctx.authorize(None)?;

    // Each section gets an equal share of the output limit, so that one huge table (a
    // full BGP feed) cannot push the sections after it out of the answer.
    let sections = kinds.len().saturating_mul(families.len()).max(1);
    let share = ctx.output_budget() / sections;
    let mut text = String::new();
    let mut any_ok = false;
    for kind in kinds {
        for (flag, label) in families {
            let mut argv = vec![flag.to_string()];
            let title = match *kind {
                "rules" => {
                    argv.extend(["rule".to_string(), "show".to_string()]);
                    format!("{label} policy rules")
                }
                "neighbours" => {
                    argv.extend(["neigh".to_string(), "show".to_string()]);
                    format!("{label} neighbours")
                }
                _ => {
                    argv.extend(["route".to_string(), "show".to_string()]);
                    match &table {
                        Some(table) => {
                            argv.extend(["table".to_string(), table.clone()]);
                            format!("{label} routes (table {table})")
                        }
                        None => format!("{label} routes"),
                    }
                }
            };
            let out = ctx.run(ctx.command("ip")?.args(argv)).await?;
            any_ok |= command_ok(&out);
            let header = format!("== {title} ==\n");
            let body = command_text(&out);
            text.push_str(&header);
            if body.trim().is_empty() {
                text.push_str("(none)\n");
            } else {
                text.push_str(&fit_head(
                    &body,
                    share.saturating_sub(header.len()),
                    "narrow it with show, family or table",
                ));
                end_line(&mut text);
            }
        }
    }
    auth.done(text, any_ok)
}

// ---- net_sockets ----------------------------------------------------------------------

/// One socket, as `ss -H -n` prints it.
#[derive(Debug, PartialEq, Eq)]
pub struct Socket {
    pub netid: String,
    pub state: String,
    pub recv_q: String,
    pub send_q: String,
    pub local: String,
    pub peer: String,
    /// The owning processes (`users:(("nginx",pid=1,fd=6))`); empty when ss did not say.
    pub process: String,
}

impl Socket {
    fn uses_port(&self, port: u16) -> bool {
        port_of(&self.local) == Some(port) || port_of(&self.peer) == Some(port)
    }
}

/// Parses one line of `ss -H -n [-p]` output.
///
/// ss prints a leading protocol column (`tcp`, `udp`) only when it lists more than one
/// kind of socket; without it, `default_netid` says what was asked for. The two layouts
/// are told apart by where the two queue lengths (plain numbers) sit.
pub fn parse_socket(line: &str, default_netid: &str) -> Option<Socket> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let numeric = |index: usize| {
        tokens
            .get(index)
            .is_some_and(|t| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()))
    };
    let (netid, at) = if numeric(1) && numeric(2) {
        (default_netid, 0)
    } else if numeric(2) && numeric(3) {
        (*tokens.first()?, 1)
    } else {
        return None;
    };
    Some(Socket {
        netid: netid.to_string(),
        state: tokens.get(at)?.to_string(),
        recv_q: tokens.get(at + 1)?.to_string(),
        send_q: tokens.get(at + 2)?.to_string(),
        local: tokens.get(at + 3)?.to_string(),
        peer: tokens.get(at + 4)?.to_string(),
        process: tokens
            .get(at + 5..)
            .map(|rest| rest.join(" "))
            .unwrap_or_default(),
    })
}

/// The port of an `ADDRESS:PORT` endpoint; `None` for `*` or anything unparsable.
pub fn port_of(endpoint: &str) -> Option<u16> {
    endpoint.rsplit_once(':')?.1.parse().ok()
}

/// The address of an `ADDRESS:PORT` endpoint.
pub fn address_of(endpoint: &str) -> &str {
    endpoint
        .rsplit_once(':')
        .map_or(endpoint, |(address, _)| address)
}

/// The `most` largest counts, largest first (ties in key order).
fn busiest(counts: &BTreeMap<String, usize>, most: usize) -> Vec<Vec<String>> {
    let mut all: Vec<(&String, &usize)> = counts.iter().collect();
    all.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    all.into_iter()
        .take(most)
        .map(|(key, count)| vec![format!("  {key}"), count.to_string()])
        .collect()
}

/// Counts of TCP sockets: by state, and for connections (everything but listeners) by
/// local port and by peer address.
pub fn summarize(sockets: &[Socket]) -> String {
    let mut states: BTreeMap<String, usize> = BTreeMap::new();
    let mut ports: BTreeMap<String, usize> = BTreeMap::new();
    let mut peers: BTreeMap<String, usize> = BTreeMap::new();
    for socket in sockets {
        *states.entry(socket.state.clone()).or_default() += 1;
        if socket.state == "LISTEN" {
            continue;
        }
        if let Some(port) = port_of(&socket.local) {
            *ports.entry(port.to_string()).or_default() += 1;
        }
        *peers
            .entry(address_of(&socket.peer).to_string())
            .or_default() += 1;
    }
    let right = [false, true];
    let mut text = format!("TCP sockets: {}\n", sockets.len());
    if sockets.is_empty() {
        return text;
    }
    text.push_str("By state:\n");
    text.push_str(&format_rows(&busiest(&states, usize::MAX), &right));
    if !ports.is_empty() {
        text.push_str("Busiest local ports (connections; listening sockets not counted):\n");
        text.push_str(&format_rows(&busiest(&ports, 10), &right));
        text.push_str("Busiest peers (connections):\n");
        text.push_str(&format_rows(&busiest(&peers, 10), &right));
    }
    text
}

const SS_CUT: &str = "[ss produced more output than is kept: sockets are missing here]\n";

async fn socket_summary(ctx: &Ctx, auth: Authorized, port: Option<u16>) -> ToolResult {
    let mut cmd = ctx.command("ss")?.args(["-H", "-n", "-t", "-a"]);
    cmd.max_output = SUMMARY_MAX_OUTPUT;
    let out = ctx.run(cmd).await?;
    if !command_ok(&out) {
        return auth.failed(command_text(&out));
    }
    let listing = String::from_utf8_lossy(&out.stdout);
    let sockets: Vec<Socket> = listing
        .lines()
        .filter_map(|line| parse_socket(line, "tcp"))
        .filter(|socket| port.is_none_or(|port| socket.uses_port(port)))
        .collect();
    let mut text = summarize(&sockets);
    if let Some(port) = port {
        text = text.replacen(
            "TCP sockets:",
            &format!("TCP sockets using port {port}:"),
            1,
        );
    }
    if out.truncated {
        text.push_str("[ss produced more output than is kept: these counts are too low]\n");
    }
    auth.ok(text)
}

async fn net_sockets(ctx: Ctx, args: Args) -> ToolResult {
    let port = args.int("port").and_then(|port| u16::try_from(port).ok());
    let limit = usize::try_from(args.int("limit").unwrap_or(200)).unwrap_or(200);
    let protocol = args.str("protocol").unwrap_or("all");
    let auth = ctx.authorize(None)?;
    if args.bool("summary") == Some(true) {
        return socket_summary(&ctx, auth, port).await;
    }

    // AIDEV-NOTE: the options are fixed strings chosen here. Nothing the caller sends is
    // ever passed to ss: the port filter is applied below to the parsed columns, so there
    // is no ss filter expression to inject into.
    let mut argv = vec!["-H", "-n", "-p"];
    match args.str("state").unwrap_or("listening") {
        "listening" => argv.push("-l"),
        "all" => argv.push("-a"),
        _ => {}
    }
    match protocol {
        "tcp" => argv.push("-t"),
        "udp" => argv.push("-u"),
        _ => argv.extend(["-t", "-u"]),
    }
    let out = ctx.run(ctx.command("ss")?.args(argv)).await?;
    if !command_ok(&out) {
        return auth.failed(command_text(&out));
    }
    let default_netid = if protocol == "udp" { "udp" } else { "tcp" };
    let listing = String::from_utf8_lossy(&out.stdout);
    let mut unread = 0usize;
    let mut sockets = Vec::new();
    for line in listing.lines().filter(|line| !line.trim().is_empty()) {
        match parse_socket(line, default_netid) {
            Some(socket) if port.is_none_or(|port| socket.uses_port(port)) => sockets.push(socket),
            Some(_) => {}
            None => unread += 1,
        }
    }

    let mut text = String::new();
    if sockets.is_empty() {
        text.push_str("(no matching sockets)\n");
    } else {
        let rows: Vec<Vec<String>> = sockets
            .iter()
            .take(limit)
            .map(|socket| {
                // A server with many workers lists them all: keep the row readable.
                let mut process: String = socket.process.chars().take(160).collect();
                if process.len() < socket.process.len() {
                    process.push_str("...");
                }
                vec![
                    socket.netid.clone(),
                    socket.state.clone(),
                    socket.recv_q.clone(),
                    socket.send_q.clone(),
                    socket.local.clone(),
                    socket.peer.clone(),
                    process,
                ]
            })
            .collect();
        let headers = [
            "NETID", "STATE", "RECV-Q", "SEND-Q", "LOCAL", "PEER", "PROCESS",
        ];
        let right = [false, false, true, true, false, false, false];
        let shown = rows.len();
        text.push_str(&fit_head(
            &format_table(&headers, &rows, &right),
            ctx.output_budget().saturating_sub(400),
            "lower limit, give a port, or use summary",
        ));
        let total = sockets.len();
        if shown < total {
            text.push_str(&format!(
                "[{shown} of {total} sockets shown; raise limit, give a port, or use summary]\n"
            ));
        } else {
            text.push_str(&format!("[{shown} of {total} sockets shown]\n"));
        }
    }
    if unread > 0 {
        text.push_str(&format!(
            "[{unread} lines of ss output were not understood and are left out]\n"
        ));
    }
    if out.truncated {
        text.push_str(SS_CUT);
    }
    auth.ok(text)
}

// ---- net_probe ------------------------------------------------------------------------

/// Checks a probe target and returns the one name it goes by in the host's
/// `net.probe_targets` and in grants: a lower-case host name without a trailing dot, or
/// an address in its standard form.
///
/// AIDEV-NOTE: this is what the allow-list and the grants are matched against, so every
/// way of writing one destination must come out as one string, and nothing may come out
/// that a resolver would read differently from how a pattern reads it:
/// - an address is re-printed in standard form, and an IPv4-mapped IPv6 address
///   (`::ffff:10.0.0.5`, which reaches 10.0.0.5) becomes that IPv4 address;
/// - a name's last label must start with a letter. ping and getaddrinfo read `127.1`,
///   `2130706433` and `0x7f000001` as 127.0.0.1, which a deny for `127.*` would miss;
/// - a name's first label must not be all digits. Otherwise the NAME `10.evil.example`
///   would match a pattern such as `10.*` that was written to mean a network.
///
/// What a name resolves to is NOT checked against the patterns: a grant for a name is a
/// grant for whatever this host's resolver says that name is.
pub fn canonical_target(target: &str) -> Result<String, ToolError> {
    let refuse = |why: &str| {
        Err(ToolError::Invalid(format!(
            "{target:?} is not a usable target: {why}"
        )))
    };
    if let Ok(address) = target.parse::<IpAddr>() {
        return Ok(unmapped(address).to_string());
    }
    let name = target
        .strip_suffix('.')
        .unwrap_or(target)
        .to_ascii_lowercase();
    if name.is_empty() || name.len() > 253 {
        return refuse("give a host name of at most 253 characters, or an IPv4 or IPv6 address");
    }
    let label_ok = |label: &str| {
        (1..=63).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    if !name.split('.').all(label_ok) {
        return refuse(
            "a host name is labels of letters, digits and '-' separated by dots (no port, URL or brackets)",
        );
    }
    let first_is_number = name
        .split('.')
        .next()
        .is_some_and(|label| label.bytes().all(|b| b.is_ascii_digit()));
    let last_starts_with_letter = name
        .rsplit('.')
        .next()
        .is_some_and(|label| label.starts_with(|c: char| c.is_ascii_lowercase()));
    if first_is_number || !last_starts_with_letter {
        return refuse(
            "it looks like an address but is not a plain IPv4 or IPv6 address \
             (a host name cannot begin with an all-digit label or end with a label that starts with a digit)",
        );
    }
    Ok(name)
}

/// An IPv4-mapped IPv6 address as the IPv4 address it reaches; any other address as it is.
fn unmapped(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
        v4 => v4,
    }
}

/// Whether the host's `net.probe_targets` allows probing this (canonical) target.
pub fn probe_allowed(patterns: &[String], target: &str) -> bool {
    patterns
        .iter()
        .any(|pattern| glob_match(&pattern.to_ascii_lowercase(), target))
}

/// The `nameserver`, `search`, `domain` and `options` lines of a resolv.conf.
pub fn resolver_lines(resolv_conf: &str) -> Vec<String> {
    resolv_conf
        .lines()
        .map(str::trim)
        .filter(|line| {
            ["nameserver", "search", "domain", "options"]
                .iter()
                .any(|key| line.split_whitespace().next() == Some(key))
        })
        .take(20)
        .map(str::to_string)
        .collect()
}

/// `-4` or `-6` for the address family asked for, if one was.
fn family_flag(family: Option<&str>) -> Option<&'static str> {
    match family {
        Some("4") => Some("-4"),
        Some("6") => Some("-6"),
        _ => None,
    }
}

fn family_allows(family: Option<&str>, address: &IpAddr) -> bool {
    match family {
        Some("4") => address.is_ipv4(),
        Some("6") => address.is_ipv6(),
        _ => true,
    }
}

/// The addresses to probe for a canonical target: itself if it is an address, otherwise
/// whatever this host's resolver says, limited to the family asked for.
///
/// AIDEV-NOTE: the lookup runs on one of the runtime's blocking threads. If the resolver
/// is slow we stop waiting after `RESOLVE_LIMIT`, and the lookup ends by itself when the
/// resolver's own timeouts (resolv.conf) run out; it cannot hang for ever the way a read
/// from a dead NFS mount can, which is why it does not take a `tools::blocking` slot.
async fn resolve(target: &str, port: u16, family: Option<&str>) -> Result<Vec<SocketAddr>, String> {
    let found: Vec<SocketAddr> = match target.parse::<IpAddr>() {
        Ok(address) => vec![SocketAddr::new(address, port)],
        Err(_) => {
            match tokio::time::timeout(RESOLVE_LIMIT, tokio::net::lookup_host((target, port))).await
            {
                Ok(Ok(found)) => found.collect(),
                Ok(Err(e)) => return Err(format!("{target} does not resolve: {e}")),
                Err(_) => {
                    return Err(format!(
                        "{target}: no answer from the resolver within {} seconds",
                        RESOLVE_LIMIT.as_secs()
                    ));
                }
            }
        }
    };
    let mut addresses: Vec<SocketAddr> = Vec::new();
    for address in found {
        if family_allows(family, &address.ip()) && !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    if addresses.is_empty() {
        let which = match family {
            Some("4") => "IPv4 ",
            Some("6") => "IPv6 ",
            _ => "",
        };
        return Err(format!("{target} has no {which}address"));
    }
    Ok(addresses)
}

async fn probe_ping(ctx: &Ctx, auth: Authorized, args: &Args, target: &str) -> ToolResult {
    let count = args.int("count").unwrap_or(3).clamp(1, 10);
    let mut argv = vec![
        "-n".to_string(),
        "-c".to_string(),
        count.to_string(),
        "-W".to_string(),
        "2".to_string(),
    ];
    if let Some(flag) = family_flag(args.str("family")) {
        argv.push(flag.to_string());
    }
    argv.extend(["--".to_string(), target.to_string()]);
    let wanted = u64::try_from(count).unwrap_or(3).saturating_mul(3) + 5;
    let limit = wanted
        .min(ctx.cfg().limits.call_timeout_secs.saturating_sub(5))
        .max(1);
    let out = ctx
        .run(
            ctx.command("ping")?
                .args(argv)
                .timeout(Duration::from_secs(limit)),
        )
        .await?;
    let mut text = command_text(&out);
    end_line(&mut text);
    // ping exits 0 when replies came back, 1 when none did, 2 when it could not try.
    match (out.timed_out, out.code) {
        (false, Some(0)) => {
            text.push_str(&format!("Result: {target} answers ping\n"));
            auth.ok(text)
        }
        (false, Some(1)) => {
            text.push_str(&format!(
                "Result: {target} does NOT answer ping (it may be down, unreachable, or dropping ICMP)\n"
            ));
            auth.ok(text)
        }
        _ => {
            text.push_str(&format!("Result: could not ping {target}\n"));
            auth.failed(text)
        }
    }
}

async fn probe_tcp(auth: Authorized, target: &str, port: u16, family: Option<&str>) -> ToolResult {
    let addresses = match resolve(target, port, family).await {
        Ok(addresses) => addresses,
        Err(problem) => return auth.failed(format!("{problem}\n")),
    };
    let mut text = String::new();
    let mut reachable = false;
    // AIDEV-NOTE: connect, note the result, close. Nothing is ever written to or read
    // from the connection: the tool reports reachability, it is not a way to talk to a
    // service on another host.
    for address in addresses.iter().take(MAX_PROBE_ADDRESSES) {
        let started = Instant::now();
        let attempt =
            tokio::time::timeout(TCP_CONNECT_LIMIT, tokio::net::TcpStream::connect(address)).await;
        let outcome = match attempt {
            Ok(Ok(stream)) => {
                drop(stream);
                reachable = true;
                format!("connected in {} ms", started.elapsed().as_millis())
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                "connection refused (nothing is listening there, or a firewall rejects it)"
                    .to_string()
            }
            Ok(Err(e)) => format!("failed: {e}"),
            Err(_) => format!(
                "no answer within {} seconds (host down, or a firewall drops it)",
                TCP_CONNECT_LIMIT.as_secs()
            ),
        };
        text.push_str(&format!("{address}: {outcome}\n"));
    }
    if addresses.len() > MAX_PROBE_ADDRESSES {
        text.push_str(&format!(
            "[{} more addresses not tried]\n",
            addresses.len() - MAX_PROBE_ADDRESSES
        ));
    }
    let verdict = if reachable {
        "is reachable"
    } else {
        "is NOT reachable"
    };
    text.push_str(&format!(
        "Result: {target} port {port} {verdict} from this host\n"
    ));
    auth.ok(text)
}

async fn probe_trace(ctx: &Ctx, auth: Authorized, args: &Args, target: &str) -> ToolResult {
    // AIDEV-NOTE: no `--` before the target here: not every traceroute implementation
    // accepts it. It is not needed either, because `canonical_target` never returns
    // anything that starts with `-`.
    let family = family_flag(args.str("family"));
    let (cmd, fixed): (_, &[&str]) = match ctx.command("traceroute") {
        Ok(cmd) => (cmd, &["-n", "-w", "2", "-q", "1", "-m", "20"]),
        Err(ToolError::Failed(first)) => match ctx.command("tracepath") {
            Ok(cmd) => (cmd, &["-n", "-m", "20"]),
            Err(ToolError::Failed(second)) => {
                return Err(ToolError::Failed(format!(
                    "neither traceroute nor tracepath can be run on this host \
                     (packages traceroute, iputils-tracepath): {first}; {second}"
                )));
            }
            Err(other) => return Err(other),
        },
        Err(other) => return Err(other),
    };
    let mut argv: Vec<String> = fixed.iter().map(|s| s.to_string()).collect();
    if let Some(flag) = family {
        argv.push(flag.to_string());
    }
    argv.push(target.to_string());
    let out = ctx.run(cmd.args(argv)).await?;
    // A trace that ran out of time has still shown how far it got.
    let answered = command_ok(&out) || (out.timed_out && !out.stdout.is_empty());
    auth.done(command_text(&out), answered)
}

async fn probe_dns(ctx: &Ctx, auth: Authorized, args: &Args, target: &str) -> ToolResult {
    let addresses = match resolve(target, 0, args.str("family")).await {
        Ok(addresses) => addresses,
        Err(problem) => return auth.failed(format!("{problem}\n")),
    };
    let mut text = format!("{target} resolves to:\n");
    for address in &addresses {
        text.push_str(&format!("  {}\n", address.ip()));
    }
    let resolver = blocking(ctx.clone(), || {
        Ok(read_small(Path::new(RESOLV_CONF), 64 * 1024)
            .map(|conf| resolver_lines(&conf))
            .unwrap_or_default())
    })
    .await?;
    if !resolver.is_empty() {
        text.push_str(&format!("Resolver configuration ({RESOLV_CONF}):\n"));
        for line in resolver {
            text.push_str(&format!("  {line}\n"));
        }
    }
    auth.ok(text)
}

async fn net_probe(ctx: Ctx, args: Args) -> ToolResult {
    let target = canonical_target(required(&args, "target")?)?;
    let mode = args.str("mode").unwrap_or("ping").to_string();
    let port = args.int("port").and_then(|port| u16::try_from(port).ok());
    if mode == "tcp" && port.is_none() {
        return Err(ToolError::Invalid(
            "mode tcp needs a port to connect to".to_string(),
        ));
    }
    // The host-wide limit comes first: it holds whatever the caller has been granted.
    if !probe_allowed(&ctx.cfg().net.probe_targets, &target) {
        let reason = format!(
            "{target} is not among the hosts this host may probe (net.probe_targets in the configuration)"
        );
        return Err(ctx.deny(Some(&target), &reason));
    }
    let auth = ctx.authorize(Some(&target))?;
    match (mode.as_str(), port) {
        ("tcp", Some(port)) => probe_tcp(auth, &target, port, args.str("family")).await,
        ("trace", _) => probe_trace(&ctx, auth, &args, &target).await,
        ("dns", _) => probe_dns(&ctx, auth, &args, &target).await,
        _ => probe_ping(&ctx, auth, &args, &target).await,
    }
}

// ---- packet_capture -------------------------------------------------------------------

/// Checks the words of a tcpdump filter expression and joins them into the single
/// argument tcpdump is given.
///
/// AIDEV-NOTE: this is what keeps tcpdump's dangerous options out. tcpdump runs as root,
/// and `-w FILE` writes a file, `-z COMMAND` runs a command, `-r FILE`, `-F FILE` and
/// `-V FILE` read files. Three things together make them unreachable; keep all three:
/// 1. no word may start with `-`;
/// 2. only the characters a filter expression needs are allowed (no quotes, no
///    backslash, no whitespace inside a word);
/// 3. the words are joined into ONE argument that `capture_argv` places after `--`,
///    where tcpdump reads it as an expression and never as options.
pub fn check_filter(tokens: &[&str]) -> Result<String, ToolError> {
    let refuse = |why: String| Err(ToolError::Invalid(format!("filter: {why}")));
    if tokens.len() > MAX_FILTER_TOKENS {
        return refuse(format!("at most {MAX_FILTER_TOKENS} words"));
    }
    let allowed = |c: char| c.is_ascii_alphanumeric() || "_.:/[]()&|!=<>*+-".contains(c);
    for token in tokens {
        if token.is_empty() || token.len() > MAX_FILTER_TOKEN_LEN {
            return refuse(format!(
                "each word must be 1 to {MAX_FILTER_TOKEN_LEN} characters"
            ));
        }
        if token.starts_with('-') {
            return refuse(format!(
                "{token:?} starts with '-': only a filter expression is accepted, not tcpdump options"
            ));
        }
        if !token.chars().all(allowed) {
            return refuse(format!(
                "{token:?} has a character that a filter expression does not need \
                 (letters, digits and _ . : / [ ] ( ) & | ! = < > * + - only)"
            ));
        }
    }
    Ok(tokens.join(" "))
}

/// The tcpdump arguments for a capture. `filter` is what `check_filter` returned.
fn capture_argv(interface: &str, count: i64, payload: bool, filter: &str) -> Vec<String> {
    // -n: no name lookups. -p: do not put the interface into promiscuous mode.
    // -l and --immediate-mode: print each packet as it arrives, so that what was seen
    // is not lost in a buffer when the time limit ends the capture.
    let mut argv: Vec<String> = ["-i", interface, "-n", "-p", "-l", "--immediate-mode", "-c"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    argv.push(count.to_string());
    if payload {
        argv.extend([
            "-A".to_string(),
            "-s".to_string(),
            PAYLOAD_SNAPLEN.to_string(),
        ]);
    } else {
        // AIDEV-NOTE: this is what makes "headers only" true. Left to itself tcpdump
        // decodes what it can of a packet's contents (an HTTP request line with its
        // query string, an SNMP community string, DNS names), which would hand out
        // contents without `net.capture_payload`. -q prints addresses, ports, protocol
        // and length and runs no such decoder; the short snap length means the contents
        // are not even captured.
        argv.extend([
            "-q".to_string(),
            "-s".to_string(),
            HEADER_SNAPLEN.to_string(),
        ]);
    }
    if !filter.is_empty() {
        argv.extend(["--".to_string(), filter.to_string()]);
    }
    argv
}

/// How long a capture may run: what was asked for (1 to 30 seconds), but always ending
/// at least 5 seconds before the call itself would be stopped.
fn capture_seconds(asked: i64, call_timeout_secs: u64) -> u64 {
    u64::try_from(asked.clamp(1, 30))
        .unwrap_or(1)
        .min(call_timeout_secs.saturating_sub(5))
        .max(1)
}

async fn packet_capture(ctx: Ctx, args: Args) -> ToolResult {
    let interface = required(&args, "interface")?.to_string();
    check_interface(&interface)?;
    let filter = check_filter(&args.list("filter").unwrap_or_default())?;
    let count = args.int("count").unwrap_or(100).clamp(1, 1000);
    let payload = args.bool("payload") == Some(true);

    // Host-wide limits first: they hold whatever the caller has been granted.
    let net = &ctx.cfg().net;
    if !net
        .capture_interfaces
        .iter()
        .any(|pattern| glob_match(pattern, &interface))
    {
        let reason = format!(
            "packet capture on {interface} is not allowed on this host (net.capture_interfaces in the configuration)"
        );
        return Err(ctx.deny(Some(&interface), &reason));
    }
    if payload && !net.capture_payload {
        let reason = "capturing packet contents is not allowed on this host \
                      (net.capture_payload in the configuration); ask without payload for headers only";
        return Err(ctx.deny(Some(&interface), reason));
    }
    let auth = ctx.authorize(Some(&interface))?;

    let seconds = capture_seconds(
        args.int("seconds").unwrap_or(10),
        ctx.cfg().limits.call_timeout_secs,
    );
    let out = ctx
        .run(
            ctx.command("tcpdump")?
                .args(capture_argv(&interface, count, payload, &filter))
                .timeout(Duration::from_secs(seconds)),
        )
        .await?;

    // tcpdump's own remarks (what it listens on, how many packets it saw) go below the
    // packets, and are kept whole: the packets are what gets cut if there are too many.
    let (remarks, _) = keep_head(&String::from_utf8_lossy(&out.stderr), 2048);
    let room = ctx.output_budget().saturating_sub(remarks.len() + 400);
    let packets = String::from_utf8_lossy(&out.stdout);
    let mut text = if packets.trim().is_empty() {
        "(no packets captured)\n".to_string()
    } else {
        fit_head(&packets, room, "capture fewer packets or narrow the filter")
    };
    end_line(&mut text);
    text.push_str(&remarks);
    end_line(&mut text);
    if out.truncated {
        text.push_str("[tcpdump produced more output than is kept]\n");
    }
    // Reaching the time limit is one of the two normal ways for a capture to end.
    if out.timed_out {
        let unit = if seconds == 1 { "second" } else { "seconds" };
        text.push_str(&format!("[capture stopped after {seconds} {unit}]\n"));
        return auth.ok(text);
    }
    match (out.code, out.signal) {
        (Some(0), _) => auth.ok(text),
        (Some(code), _) => {
            text.push_str(&format!("[exit status {code}]\n"));
            auth.failed(text)
        }
        (None, signal) => {
            let signal = signal.map_or_else(|| "?".to_string(), |s| s.to_string());
            text.push_str(&format!("[tcpdump was killed by signal {signal}]\n"));
            auth.failed(text)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::Host;
    use crate::tools::testing::{FakeBins, call, find, host, ok_text};
    use serde_json::{Value, json};
    use std::sync::Arc;

    /// A host where adam may do everything, rita holds `@read`, nina holds narrow grants
    /// and zoe holds nothing to do with the network. `net` is the body of `[net]`.
    fn fixture(fake: &FakeBins, net: &str) -> (Arc<Host>, MemorySink) {
        host(&format!(
            r#"
[roles.admin]
allow = ["@all"]
[roles.reader]
allow = ["@read"]
[roles.narrow]
allow = ["net.probe:*.example.com", "net.capture:eth0"]
[roles.other]
allow = ["system.view"]
[unix_users.adam]
roles = ["admin"]
[unix_users.rita]
roles = ["reader"]
[unix_users.nina]
roles = ["narrow"]
[unix_users.zoe]
roles = ["other"]
[net]
{net}
{}"#,
            fake.config_only()
        ))
    }

    async fn run(host: &Arc<Host>, user: &str, tool: &str, arguments: Value) -> ToolResult {
        call(host, user, &find(tools(), tool), arguments).await
    }

    fn argv(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn is_invalid(result: ToolResult) -> String {
        match result {
            Err(ToolError::Invalid(message)) => message,
            other => panic!("expected the arguments to be refused, got {other:?}"),
        }
    }

    fn is_denied(result: ToolResult) -> String {
        match result {
            Err(ToolError::Denied(message)) => message,
            other => panic!("expected a denial, got {other:?}"),
        }
    }

    // ---- the tool list ------------------------------------------------------------

    #[test]
    fn the_tools_carry_the_intended_permissions() {
        let got: Vec<(String, Access, String)> = tools()
            .into_iter()
            .map(|t| (t.name, t.access, t.permission))
            .collect();
        let want = [
            ("net_interfaces", Access::Read, "net.view"),
            ("net_routes", Access::Read, "net.view"),
            ("net_sockets", Access::Read, "net.view"),
            ("net_probe", Access::Read, "net.probe"),
            // write on purpose: see the note on packet_capture
            ("packet_capture", Access::Write, "net.capture"),
        ];
        let want: Vec<(String, Access, String)> = want
            .iter()
            .map(|(n, a, p)| (n.to_string(), *a, p.to_string()))
            .collect();
        assert_eq!(got, want);
    }

    #[tokio::test]
    async fn the_view_tools_need_net_view_and_run_nothing_without_it() {
        let fake = FakeBins::new().add("ip", "x\n", 0).add("ss", "x\n", 0);
        let (host, audit) = fixture(&fake, "");
        for tool in ["net_interfaces", "net_routes", "net_sockets"] {
            let message = is_denied(run(&host, "zoe", tool, json!({})).await);
            assert!(message.contains("net.view"), "{tool}: {message}");
        }
        assert!(fake.calls("ip").is_empty() && fake.calls("ss").is_empty());
        assert_eq!(audit.records().len(), 3);
        assert!(audit.records().iter().all(|r| r["decision"] == "deny"));
    }

    // ---- net_interfaces -----------------------------------------------------------

    #[test]
    fn check_interface_accepts_interface_names_only() {
        for good in [
            "eth0",
            "lo",
            "br-3a40785c69ba",
            "bond0.100",
            "eth0:1",
            "veth1@if2",
            "wg_office",
            "a23456789012345",
        ] {
            assert!(check_interface(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "-eth0",
            "--all",
            ".",
            "..",
            "eth0/..",
            "../lo",
            "a b",
            "eth0;id",
            "eth0\u{e9}",
            "a234567890123456",
        ] {
            assert!(check_interface(bad).is_err(), "{bad:?}");
        }
    }

    /// A stand-in /sys/class/net and /proc/net/bonding.
    fn fake_sysfs() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let sys = dir.path().join("sys");
        let bonding = dir.path().join("bonding");
        let files = [
            ("eth0/operstate", "up\n"),
            ("eth0/speed", "10000\n"),
            ("eth0/duplex", "full\n"),
            ("eth0/mtu", "1500\n"),
            ("eth0/carrier_changes", "2\n"),
            ("lo/operstate", "unknown\n"),
            ("lo/speed", "-1\n"),
            ("lo/mtu", "65536\n"),
            ("bond0/operstate", "up\n"),
            ("bond0/mtu", "9000\n"),
        ];
        for (name, content) in files {
            let path = sys.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, content).unwrap();
        }
        // not an interface: the bonding driver keeps a plain file here
        std::fs::write(sys.join("bonding_masters"), "bond0\n").unwrap();
        std::fs::create_dir_all(&bonding).unwrap();
        std::fs::write(
            bonding.join("bond0"),
            "Bonding Mode: IEEE 802.3ad\nSlave Interface: eth0\nMII Status: up\n",
        )
        .unwrap();
        (dir, sys, bonding)
    }

    async fn interfaces(
        host: &Arc<Host>,
        user: &str,
        sysfs: &(tempfile::TempDir, PathBuf, PathBuf),
        arguments: Value,
    ) -> ToolResult {
        let tool = interfaces_tool(sysfs.1.clone(), sysfs.2.clone());
        call(host, user, &tool, arguments).await
    }

    #[test]
    fn link_line_reports_what_sysfs_knows_and_skips_what_it_does_not() {
        let sysfs = fake_sysfs();
        assert_eq!(
            link_line(&sysfs.1, "eth0").unwrap(),
            "eth0: state up, speed 10000 Mb/s, duplex full, mtu 1500, carrier changes 2"
        );
        // a speed of -1 means the driver does not know
        assert_eq!(
            link_line(&sysfs.1, "lo").unwrap(),
            "lo: state unknown, mtu 65536"
        );
        assert_eq!(link_line(&sysfs.1, "bonding_masters"), None);
        assert_eq!(link_line(&sysfs.1, "nope0"), None);
    }

    #[tokio::test]
    async fn net_interfaces_runs_ip_and_adds_link_state_from_sysfs() {
        let fake = FakeBins::new().add("ip", "1: lo: <LOOPBACK,UP>\n2: eth0: <UP>\n", 0);
        let (host, _audit) = fixture(&fake, "");
        let sysfs = fake_sysfs();
        let text = ok_text(interfaces(&host, "rita", &sysfs, json!({})).await);
        assert_eq!(
            fake.calls("ip"),
            vec![argv(&["-s", "-d", "address", "show"])]
        );
        assert!(
            text.starts_with("1: lo: <LOOPBACK,UP>\n2: eth0: <UP>\n"),
            "{text}"
        );
        assert!(
            text.contains("eth0: state up, speed 10000 Mb/s, duplex full, mtu 1500"),
            "{text}"
        );
        assert!(text.contains("lo: state unknown, mtu 65536"), "{text}");
        assert!(text.contains("bond0: state up"), "{text}");
        // bonding details only when the bond is asked for by name
        assert!(!text.contains("802.3ad"), "{text}");
        assert!(!text.contains("bonding_masters"), "{text}");
    }

    #[tokio::test]
    async fn net_interfaces_for_one_interface_asks_ip_for_it_and_shows_a_bonds_members() {
        let fake = FakeBins::new().add("ip", "5: bond0: <UP>\n", 0);
        let (host, _audit) = fixture(&fake, "");
        let sysfs = fake_sysfs();
        let text = ok_text(interfaces(&host, "rita", &sysfs, json!({"interface": "bond0"})).await);
        assert_eq!(
            fake.calls("ip"),
            vec![argv(&["-s", "-d", "address", "show", "dev", "bond0"])]
        );
        assert!(text.contains("bond0: state up, mtu 9000"), "{text}");
        assert!(text.contains("Bonding Mode: IEEE 802.3ad"), "{text}");
        assert!(text.contains("Slave Interface: eth0"), "{text}");
        // only the interface asked about
        assert!(!text.contains("eth0: state"), "{text}");
    }

    #[tokio::test]
    async fn net_interfaces_brief_asks_ip_for_the_short_form() {
        let fake = FakeBins::new().add("ip", "lo UNKNOWN 127.0.0.1/8\n", 0);
        let (host, _audit) = fixture(&fake, "");
        let sysfs = fake_sysfs();
        ok_text(interfaces(&host, "rita", &sysfs, json!({"brief": true})).await);
        assert_eq!(fake.calls("ip"), vec![argv(&["-br", "address", "show"])]);
    }

    #[tokio::test]
    async fn net_interfaces_refuses_a_bad_name_before_running_anything() {
        let fake = FakeBins::new().add("ip", "x\n", 0);
        let (host, audit) = fixture(&fake, "");
        let sysfs = fake_sysfs();
        for bad in ["-all", "..", "eth0/x"] {
            is_invalid(interfaces(&host, "adam", &sysfs, json!({"interface": bad})).await);
        }
        assert!(fake.calls("ip").is_empty());
        assert!(audit.records().is_empty());
    }

    #[tokio::test]
    async fn net_interfaces_reports_ips_failure_as_a_failure() {
        let fake =
            FakeBins::new().add_script("ip", "echo 'Device \"eth9\" does not exist.' >&2; exit 1");
        let (host, _audit) = fixture(&fake, "");
        let sysfs = fake_sysfs();
        let output = interfaces(&host, "rita", &sysfs, json!({"interface": "eth9"}))
            .await
            .unwrap();
        assert!(output.is_error());
        assert!(
            output.text().contains("does not exist"),
            "{}",
            output.text()
        );
    }

    #[tokio::test]
    async fn net_interfaces_says_so_when_ip_is_not_installed() {
        let fake = FakeBins::new();
        let (host, _audit) = fixture(&fake, "");
        let sysfs = fake_sysfs();
        match interfaces(&host, "rita", &sysfs, json!({})).await {
            Err(ToolError::Failed(message)) => assert!(message.contains("`ip`"), "{message}"),
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[test]
    fn long_output_is_cut_at_a_line_with_a_note() {
        let lines: String = (1..=200)
            .map(|i| format!("interface line {i:03}\n"))
            .collect();
        assert_eq!(fit_head(&lines, 100_000, "narrow it"), lines);
        let cut = fit_head(&lines, 1000, "narrow it");
        assert!(cut.len() <= 1000, "{} bytes", cut.len());
        assert!(cut.starts_with("interface line 001\n"), "{cut}");
        assert!(!cut.contains("interface line 200"), "{cut}");
        let note = cut.lines().last().unwrap();
        assert!(
            note.starts_with('[') && note.contains("left out") && note.contains("narrow it"),
            "{note}"
        );
    }

    // ---- net_routes ---------------------------------------------------------------

    #[test]
    fn check_table_accepts_table_names_and_numbers_only() {
        for good in ["main", "local", "default", "all", "100", "my_table-1"] {
            assert!(check_table(good).is_ok(), "{good}");
        }
        for bad in ["", "-x", "a b", "main;id", "t/1", &"x".repeat(33)] {
            assert!(check_table(bad).is_err(), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn net_routes_shows_the_routes_of_both_families_by_default() {
        let fake = FakeBins::new().add_script(
            "ip",
            r#"case "$1" in -4) echo "default via 10.0.0.1 dev eth0" ;; esac"#,
        );
        let (host, _audit) = fixture(&fake, "");
        let text = ok_text(run(&host, "rita", "net_routes", json!({})).await);
        assert_eq!(
            fake.calls("ip"),
            vec![
                argv(&["-4", "route", "show"]),
                argv(&["-6", "route", "show"])
            ]
        );
        assert_eq!(
            text,
            "== IPv4 routes ==\ndefault via 10.0.0.1 dev eth0\n== IPv6 routes ==\n(none)\n"
        );
    }

    #[tokio::test]
    async fn net_routes_all_adds_rules_and_neighbours_and_passes_the_table() {
        let fake = FakeBins::new().add("ip", "entry\n", 0);
        let (host, _audit) = fixture(&fake, "");
        let text = ok_text(
            run(
                &host,
                "rita",
                "net_routes",
                json!({"show": "all", "family": "4", "table": "100"}),
            )
            .await,
        );
        assert_eq!(
            fake.calls("ip"),
            vec![
                argv(&["-4", "route", "show", "table", "100"]),
                argv(&["-4", "rule", "show"]),
                argv(&["-4", "neigh", "show"]),
            ]
        );
        for header in [
            "== IPv4 routes (table 100) ==",
            "== IPv4 policy rules ==",
            "== IPv4 neighbours ==",
        ] {
            assert!(text.contains(header), "{header}: {text}");
        }
    }

    #[tokio::test]
    async fn net_routes_refuses_a_bad_table_before_running_anything() {
        let fake = FakeBins::new().add("ip", "entry\n", 0);
        let (host, _audit) = fixture(&fake, "");
        is_invalid(run(&host, "rita", "net_routes", json!({"table": "-6"})).await);
        assert!(fake.calls("ip").is_empty());
    }

    #[tokio::test]
    async fn net_routes_fails_only_when_every_section_failed() {
        // IPv4 answers, IPv6 fails: still an answer
        let fake = FakeBins::new().add_script(
            "ip",
            r#"case "$1" in -4) echo "default via 10.0.0.1" ;; *) echo "Error: no table" >&2; exit 2 ;; esac"#,
        );
        let (host, _audit) = fixture(&fake, "");
        let text = ok_text(run(&host, "rita", "net_routes", json!({})).await);
        assert!(
            text.contains("Error: no table") && text.contains("exit status 2"),
            "{text}"
        );

        let fake = FakeBins::new().add_script("ip", "echo 'Error: no table' >&2; exit 2");
        let (host, _audit) = fixture(&fake, "");
        let output = run(&host, "rita", "net_routes", json!({})).await.unwrap();
        assert!(output.is_error());
    }

    #[tokio::test]
    async fn net_routes_gives_each_section_a_share_of_the_output_limit() {
        // a full routing table must not crowd out the section after it
        let fake = FakeBins::new().add_script(
            "ip",
            r#"case "$1" in
  -4) i=0; while [ $i -lt 3000 ]; do echo "10.$i.0.0/16 via 10.0.0.1 dev eth0 proto bgp"; i=$((i+1)); done ;;
  -6) echo "fe80::/64 dev eth0" ;;
esac"#,
        );
        let (host, _audit) = fixture(&fake, "");
        let text = ok_text(run(&host, "rita", "net_routes", json!({})).await);
        assert!(text.len() <= 64 * 1024, "{} bytes", text.len());
        assert!(text.contains("left out"), "the cut should be announced");
        assert!(
            text.contains("== IPv6 routes ==\nfe80::/64 dev eth0\n"),
            "the later section must survive"
        );
    }

    // ---- net_sockets --------------------------------------------------------------

    fn socket(netid: &str, state: &str, local: &str, peer: &str, process: &str) -> Socket {
        Socket {
            netid: netid.to_string(),
            state: state.to_string(),
            recv_q: "0".to_string(),
            send_q: "128".to_string(),
            local: local.to_string(),
            peer: peer.to_string(),
            process: process.to_string(),
        }
    }

    #[test]
    fn parse_socket_reads_lines_with_and_without_a_netid_column() {
        // as `ss -H -n -p -l -t -u` prints them
        let with_netid = r#"udp UNCONN 0      128          0.0.0.0:5353  0.0.0.0:* users:(("avahi daemon",pid=812,fd=12))"#;
        assert_eq!(
            parse_socket(with_netid, "tcp"),
            Some(socket(
                "udp",
                "UNCONN",
                "0.0.0.0:5353",
                "0.0.0.0:*",
                r#"users:(("avahi daemon",pid=812,fd=12))"#
            ))
        );
        // as `ss -H -n -p -l -t` prints them: no first column
        let without = r#"LISTEN 0      128                  127.0.0.1:38419 0.0.0.0:* users:(("codex",pid=2715455,fd=37))"#;
        assert_eq!(
            parse_socket(without, "tcp"),
            Some(socket(
                "tcp",
                "LISTEN",
                "127.0.0.1:38419",
                "0.0.0.0:*",
                r#"users:(("codex",pid=2715455,fd=37))"#
            ))
        );
        // no process column (not ours to see)
        assert_eq!(
            parse_socket("tcp ESTAB 0 128 [::1]:22 [::1]:51000", "tcp"),
            Some(socket("tcp", "ESTAB", "[::1]:22", "[::1]:51000", ""))
        );
        for junk in [
            "",
            "garbage",
            "Netid State Recv-Q Send-Q Local Peer",
            "a b c",
        ] {
            assert_eq!(parse_socket(junk, "tcp"), None, "{junk:?}");
        }
    }

    #[test]
    fn endpoints_split_into_address_and_port() {
        let cases = [
            ("127.0.0.1:80", "127.0.0.1", Some(80)),
            ("[::]:22", "[::]", Some(22)),
            ("*:53785", "*", Some(53785)),
            ("0.0.0.0:*", "0.0.0.0", None),
            ("127.0.0.53%lo:53", "127.0.0.53%lo", Some(53)),
            ("[fe80::1]%eth0:546", "[fe80::1]%eth0", Some(546)),
            ("nonsense", "nonsense", None),
        ];
        for (endpoint, address, port) in cases {
            assert_eq!(address_of(endpoint), address, "{endpoint}");
            assert_eq!(port_of(endpoint), port, "{endpoint}");
        }
    }

    const LISTENING: &str = r#"udp   UNCONN 0      0            0.0.0.0:5353      0.0.0.0:*    users:(("avahi-daemon",pid=812,fd=12))
tcp   LISTEN 0      511          0.0.0.0:443       0.0.0.0:*    users:(("nginx",pid=901,fd=6),("nginx",pid=900,fd=6))
tcp   LISTEN 0      128             [::]:22           [::]:*    users:(("sshd",pid=700,fd=4))
tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=700,fd=3))
tcp   LISTEN 0      4096       127.0.0.1:5432      0.0.0.0:*    users:(("postgres",pid=650,fd=5))
"#;

    #[tokio::test]
    async fn net_sockets_lists_listening_sockets_by_default_as_an_aligned_table() {
        let fake = FakeBins::new().add("ss", LISTENING, 0);
        let (host, _audit) = fixture(&fake, "");
        let text = ok_text(run(&host, "rita", "net_sockets", json!({})).await);
        assert_eq!(
            fake.calls("ss"),
            vec![argv(&["-H", "-n", "-p", "-l", "-t", "-u"])]
        );
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[0].split_whitespace().collect::<Vec<_>>(),
            [
                "NETID", "STATE", "RECV-Q", "SEND-Q", "LOCAL", "PEER", "PROCESS"
            ]
        );
        assert_eq!(
            lines[1].split_whitespace().collect::<Vec<_>>(),
            [
                "udp",
                "UNCONN",
                "0",
                "0",
                "0.0.0.0:5353",
                "0.0.0.0:*",
                r#"users:(("avahi-daemon",pid=812,fd=12))"#
            ]
        );
        assert!(text.contains("[5 of 5 sockets shown]"), "{text}");
        // columns line up: LOCAL starts at the same offset in the header and a row
        let column = lines[0].find("LOCAL").unwrap();
        assert_eq!(&lines[2][column..column + 11], "0.0.0.0:443");
    }

    #[tokio::test]
    async fn net_sockets_state_and_protocol_choose_the_ss_options() {
        let fake = FakeBins::new().add("ss", "ESTAB 0 0 10.0.0.5:443 10.0.0.9:51000\n", 0);
        let (host, _audit) = fixture(&fake, "");
        let text = ok_text(
            run(
                &host,
                "rita",
                "net_sockets",
                json!({"state": "connected", "protocol": "tcp"}),
            )
            .await,
        );
        // a listing of one protocol has no netid column: it is filled in
        assert!(text.lines().nth(1).unwrap().starts_with("tcp"), "{text}");
        ok_text(
            run(
                &host,
                "rita",
                "net_sockets",
                json!({"state": "all", "protocol": "udp"}),
            )
            .await,
        );
        assert_eq!(
            fake.calls("ss"),
            vec![
                argv(&["-H", "-n", "-p", "-t"]),
                argv(&["-H", "-n", "-p", "-a", "-u"])
            ]
        );
    }

    #[tokio::test]
    async fn net_sockets_filters_by_port_itself_and_never_passes_a_filter_to_ss() {
        let fake = FakeBins::new().add("ss", LISTENING, 0);
        let (host, _audit) = fixture(&fake, "");
        let text = ok_text(run(&host, "rita", "net_sockets", json!({"port": 22})).await);
        assert_eq!(
            fake.calls("ss"),
            vec![argv(&["-H", "-n", "-p", "-l", "-t", "-u"])]
        );
        assert!(
            text.contains("[::]:22") && text.contains("0.0.0.0:22"),
            "{text}"
        );
        assert!(
            !text.contains("nginx") && !text.contains("postgres"),
            "{text}"
        );
        assert!(text.contains("[2 of 2 sockets shown]"), "{text}");
        // 5432 must not match a search for 543 or 432
        let text = ok_text(run(&host, "rita", "net_sockets", json!({"port": 543})).await);
        assert!(text.contains("no matching sockets"), "{text}");
    }

    #[tokio::test]
    async fn net_sockets_limit_says_how_many_were_left_out() {
        let fake = FakeBins::new().add("ss", LISTENING, 0);
        let (host, _audit) = fixture(&fake, "");
        let text = ok_text(run(&host, "rita", "net_sockets", json!({"limit": 2})).await);
        assert_eq!(text.lines().count(), 4, "{text}");
        assert!(text.contains("[2 of 5 sockets shown"), "{text}");
    }

    #[tokio::test]
    async fn net_sockets_reports_a_failing_ss_as_a_failure() {
        let fake =
            FakeBins::new().add_script("ss", "echo 'Cannot open netlink socket' >&2; exit 255");
        let (host, _audit) = fixture(&fake, "");
        let output = run(&host, "rita", "net_sockets", json!({})).await.unwrap();
        assert!(output.is_error());
        assert!(output.text().contains("netlink"), "{}", output.text());
    }

    const CONNECTIONS: &str = "LISTEN    0  511   0.0.0.0:443     0.0.0.0:*
ESTAB     0  0     10.0.0.5:443    10.0.0.7:51000
ESTAB     0  0     10.0.0.5:443    10.0.0.7:51001
ESTAB     0  0     10.0.0.5:443    10.0.0.8:40000
ESTAB     0  0     10.0.0.5:22     10.0.0.9:50022
TIME-WAIT 0  0     10.0.0.5:443    10.0.0.7:51002
";

    #[test]
    fn summarize_counts_states_ports_and_peers() {
        let sockets: Vec<Socket> = CONNECTIONS
            .lines()
            .filter_map(|line| parse_socket(line, "tcp"))
            .collect();
        let text = summarize(&sockets);
        let has = |needle: &[&str]| {
            text.lines()
                .any(|line| line.split_whitespace().collect::<Vec<_>>() == needle)
        };
        assert!(text.starts_with("TCP sockets: 6\n"), "{text}");
        assert!(has(&["ESTAB", "4"]), "{text}");
        assert!(has(&["LISTEN", "1"]), "{text}");
        assert!(has(&["TIME-WAIT", "1"]), "{text}");
        // listeners are not connections: port 443 has 4, port 22 has 1
        assert!(has(&["443", "4"]), "{text}");
        assert!(has(&["22", "1"]), "{text}");
        assert!(has(&["10.0.0.7", "3"]), "{text}");
        assert!(has(&["10.0.0.8", "1"]), "{text}");
        // the busiest comes first
        assert!(
            text.find("10.0.0.7").unwrap() < text.find("10.0.0.8").unwrap(),
            "{text}"
        );
    }

    #[tokio::test]
    async fn net_sockets_summary_counts_instead_of_listing() {
        let fake = FakeBins::new().add("ss", CONNECTIONS, 0);
        let (host, _audit) = fixture(&fake, "");
        let text = ok_text(run(&host, "rita", "net_sockets", json!({"summary": true})).await);
        assert_eq!(fake.calls("ss"), vec![argv(&["-H", "-n", "-t", "-a"])]);
        assert!(text.starts_with("TCP sockets: 6\n"), "{text}");
        assert!(
            !text.contains("51000"),
            "a summary lists no single connection: {text}"
        );
        // with a port: only the sockets using it
        let text = ok_text(
            run(
                &host,
                "rita",
                "net_sockets",
                json!({"summary": true, "port": 22}),
            )
            .await,
        );
        assert!(text.starts_with("TCP sockets using port 22: 1\n"), "{text}");
    }

    // ---- net_probe ----------------------------------------------------------------

    #[test]
    fn canonical_target_normalises_names_and_addresses() {
        let cases = [
            ("db1.example.com", "db1.example.com"),
            ("DB1.Example.COM.", "db1.example.com"),
            ("localhost", "localhost"),
            ("web-3.stg", "web-3.stg"),
            ("10.0.0.5", "10.0.0.5"),
            ("::1", "::1"),
            ("2001:DB8::5", "2001:db8::5"),
            // one address, one name: however it is written
            ("0:0:0:0:0:0:0:1", "::1"),
            ("::ffff:127.0.0.1", "127.0.0.1"),
            ("::FFFF:10.0.0.5", "10.0.0.5"),
        ];
        for (given, want) in cases {
            assert_eq!(canonical_target(given).unwrap(), want, "{given}");
        }
    }

    #[test]
    fn canonical_target_refuses_everything_that_is_not_a_plain_name_or_address() {
        let long_label = format!("{}.example.com", "a".repeat(64));
        let long_name = format!("{}com", "abcdefgh.".repeat(28));
        for bad in [
            "",
            ".",
            "-h",
            "-x.example.com",
            "x-.example.com",
            "a..b",
            "host:80",
            "http://example.com",
            "example.com/path",
            "[::1]",
            "fe80::1%eth0",
            "a b",
            "x_y.example.com",
            "caf\u{e9}.example.com",
            "user@example.com",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            assert!(canonical_target(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn canonical_target_refuses_names_that_resolvers_read_as_addresses() {
        // AIDEV-NOTE: ping and getaddrinfo take these as 127.0.0.1; a deny written for
        // 127.* would not match them, so they are not accepted as names at all.
        for sneaky in [
            "127.1",
            "2130706433",
            "0x7f000001",
            "0177.0.0.1",
            "010.0.0.1",
            "1.2.3.4.",
        ] {
            assert!(canonical_target(sneaky).is_err(), "{sneaky:?}");
        }
        // and a NAME must not be mistaken for an address by a pattern such as 10.*
        for confusing in ["10.attacker.example", "192.168.evil.example", "10.com"] {
            assert!(canonical_target(confusing).is_err(), "{confusing:?}");
        }
        // digits elsewhere in a name are fine
        for fine in ["web3.example.com", "3com.example.com", "a.10.example.com"] {
            assert!(canonical_target(fine).is_ok(), "{fine:?}");
        }
    }

    #[test]
    fn probe_allowed_matches_the_canonical_target_against_the_configured_globs() {
        let patterns =
            |list: &[&str]| -> Vec<String> { list.iter().map(|s| s.to_string()).collect() };
        assert!(!probe_allowed(&[], "db.example.com"));
        let some = patterns(&["10.*", "*.Example.com", "::1"]);
        assert!(probe_allowed(&some, "10.1.2.3"));
        assert!(probe_allowed(&some, "db.example.com"));
        assert!(probe_allowed(&some, "::1"));
        assert!(!probe_allowed(&some, "example.com"));
        assert!(!probe_allowed(&some, "192.168.1.1"));
        assert!(!probe_allowed(&some, "db.example.com.evil.net"));
        assert!(probe_allowed(&patterns(&["**"]), "anything.example.org"));
    }

    const PROBE: &str =
        "probe_targets = [\"*.example.com\", \"10.*\", \"127.0.0.1\", \"localhost\"]";

    #[tokio::test]
    async fn net_probe_is_refused_everywhere_until_probe_targets_is_configured() {
        let fake = FakeBins::new().add("ping", "pong\n", 0);
        let (host, audit) = fixture(&fake, "");
        let message = is_denied(
            run(
                &host,
                "adam",
                "net_probe",
                json!({"target": "db.example.com"}),
            )
            .await,
        );
        assert!(message.contains("net.probe_targets"), "{message}");
        assert!(fake.calls("ping").is_empty());
        let records = audit.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["decision"], "deny");
        assert_eq!(records[0]["resource"], "db.example.com");
        assert!(
            records[0]["reason"]
                .as_str()
                .unwrap()
                .contains("net.probe_targets"),
            "{}",
            records[0]
        );
    }

    #[tokio::test]
    async fn net_probe_refuses_targets_the_host_does_not_allow() {
        let fake = FakeBins::new().add("ping", "pong\n", 0);
        let (host, _audit) = fixture(&fake, PROBE);
        for target in ["db.other.net", "192.168.1.1", "::1", "example.com.evil.net"] {
            let message =
                is_denied(run(&host, "adam", "net_probe", json!({"target": target})).await);
            assert!(message.contains("net.probe_targets"), "{target}: {message}");
        }
        // the mapped form of an allowed address is that address; of a refused one, refused
        is_denied(
            run(
                &host,
                "adam",
                "net_probe",
                json!({"target": "::ffff:192.168.1.1"}),
            )
            .await,
        );
        assert!(fake.calls("ping").is_empty());
        ok_text(
            run(
                &host,
                "adam",
                "net_probe",
                json!({"target": "::ffff:10.0.0.5"}),
            )
            .await,
        );
        assert_eq!(fake.calls("ping").len(), 1);
        assert_eq!(fake.calls("ping")[0].last().unwrap(), "10.0.0.5");
    }

    #[tokio::test]
    async fn net_probe_needs_a_grant_that_covers_the_target() {
        let fake = FakeBins::new().add("ping", "pong\n", 0);
        let (host, audit) = fixture(&fake, PROBE);
        // nina holds net.probe:*.example.com
        ok_text(
            run(
                &host,
                "nina",
                "net_probe",
                json!({"target": "DB.Example.com."}),
            )
            .await,
        );
        let message =
            is_denied(run(&host, "nina", "net_probe", json!({"target": "10.0.0.5"})).await);
        assert!(
            message.contains("net.probe") && message.contains("10.0.0.5"),
            "{message}"
        );
        assert_eq!(fake.calls("ping").len(), 1);
        let records = audit.records();
        assert_eq!(records[0]["resource"], "db.example.com");
        assert_eq!(records[0]["decision"], "allow");
        assert_eq!(records[1]["resource"], "10.0.0.5");
        assert_eq!(records[1]["decision"], "deny");
        // and someone with no network grant at all
        is_denied(
            run(
                &host,
                "zoe",
                "net_probe",
                json!({"target": "db.example.com"}),
            )
            .await,
        );
    }

    #[tokio::test]
    async fn net_probe_ping_runs_ping_with_fixed_options() {
        let fake = FakeBins::new().add("ping", "3 packets transmitted, 3 received\n", 0);
        let (host, _audit) = fixture(&fake, PROBE);
        let text = ok_text(
            run(
                &host,
                "adam",
                "net_probe",
                json!({"target": "db.example.com"}),
            )
            .await,
        );
        assert!(text.contains("3 received"), "{text}");
        assert!(
            text.contains("Result: db.example.com answers ping"),
            "{text}"
        );
        ok_text(
            run(
                &host,
                "adam",
                "net_probe",
                json!({"target": "db.example.com", "mode": "ping", "count": 5, "family": "6"}),
            )
            .await,
        );
        assert_eq!(
            fake.calls("ping"),
            vec![
                argv(&["-n", "-c", "3", "-W", "2", "--", "db.example.com"]),
                argv(&["-n", "-c", "5", "-W", "2", "-6", "--", "db.example.com"]),
            ]
        );
    }

    #[tokio::test]
    async fn net_probe_ping_without_a_reply_is_an_answer_but_a_broken_ping_is_a_failure() {
        // ping exits 1 when nothing came back: that is the answer to the question
        let fake = FakeBins::new().add("ping", "3 packets transmitted, 0 received\n", 1);
        let (host, _audit) = fixture(&fake, PROBE);
        let text = ok_text(run(&host, "adam", "net_probe", json!({"target": "10.0.0.5"})).await);
        assert!(
            text.contains("Result: 10.0.0.5 does NOT answer ping"),
            "{text}"
        );
        // exit 2: ping could not do its job (unknown host, no permission)
        let fake = FakeBins::new().add_script("ping", "echo 'ping: unknown host' >&2; exit 2");
        let (host, _audit) = fixture(&fake, PROBE);
        let output = run(
            &host,
            "adam",
            "net_probe",
            json!({"target": "x.example.com"}),
        )
        .await
        .unwrap();
        assert!(output.is_error());
        assert!(output.text().contains("unknown host"), "{}", output.text());
    }

    #[tokio::test]
    async fn net_probe_refuses_bad_arguments_before_anything_else() {
        let fake = FakeBins::new().add("ping", "pong\n", 0);
        let (host, audit) = fixture(&fake, PROBE);
        is_invalid(run(&host, "adam", "net_probe", json!({"target": "-c5"})).await);
        is_invalid(
            run(
                &host,
                "adam",
                "net_probe",
                json!({"target": "db.example.com:22"}),
            )
            .await,
        );
        let message = is_invalid(
            run(
                &host,
                "adam",
                "net_probe",
                json!({"target": "db.example.com", "mode": "tcp"}),
            )
            .await,
        );
        assert!(message.contains("port"), "{message}");
        assert!(fake.calls("ping").is_empty());
        assert!(audit.records().is_empty());
    }

    #[tokio::test]
    async fn net_probe_tcp_connects_and_reports_what_happened() {
        let fake = FakeBins::new();
        let (host, _audit) = fixture(&fake, PROBE);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open = listener.local_addr().unwrap().port();
        let text = ok_text(
            run(
                &host,
                "adam",
                "net_probe",
                json!({"target": "127.0.0.1", "mode": "tcp", "port": open}),
            )
            .await,
        );
        assert!(
            text.contains(&format!("127.0.0.1:{open}: connected in")),
            "{text}"
        );
        assert!(
            text.contains(&format!("Result: 127.0.0.1 port {open} is reachable")),
            "{text}"
        );
        // A port nothing listens on. The socket is bound but never listens, and is kept
        // until the end of the test: connecting to it is refused, and no other test (or
        // program) can be given the same port in the meantime.
        let not_listening = tokio::net::TcpSocket::new_v4().unwrap();
        not_listening.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let closed = not_listening.local_addr().unwrap().port();
        let text = ok_text(
            run(
                &host,
                "adam",
                "net_probe",
                json!({"target": "127.0.0.1", "mode": "tcp", "port": closed}),
            )
            .await,
        );
        assert!(text.contains("refused"), "{text}");
        assert!(
            text.contains(&format!("Result: 127.0.0.1 port {closed} is NOT reachable")),
            "{text}"
        );
        // asked for IPv6 only, the target has no such address
        let output = run(
            &host,
            "adam",
            "net_probe",
            json!({"target": "127.0.0.1", "mode": "tcp", "port": open, "family": "6"}),
        )
        .await
        .unwrap();
        assert!(output.is_error());
        assert!(output.text().contains("IPv6"), "{}", output.text());
        drop(not_listening);
    }

    #[tokio::test]
    async fn net_probe_trace_uses_traceroute_and_falls_back_to_tracepath() {
        let fake = FakeBins::new()
            .add("traceroute", " 1  10.0.0.1  0.5 ms\n", 0)
            .add("tracepath", " 1:  10.0.0.1  0.5ms\n", 0);
        let (host, _audit) = fixture(&fake, PROBE);
        let text = ok_text(
            run(
                &host,
                "adam",
                "net_probe",
                json!({"target": "db.example.com", "mode": "trace", "family": "4"}),
            )
            .await,
        );
        assert!(text.contains("10.0.0.1  0.5 ms"), "{text}");
        assert_eq!(
            fake.calls("traceroute"),
            vec![argv(&[
                "-n",
                "-w",
                "2",
                "-q",
                "1",
                "-m",
                "20",
                "-4",
                "db.example.com"
            ])]
        );
        assert!(fake.calls("tracepath").is_empty());

        let fake = FakeBins::new().add("tracepath", " 1:  10.0.0.1  0.5ms\n", 0);
        let (host, _audit) = fixture(&fake, PROBE);
        let text = ok_text(
            run(
                &host,
                "adam",
                "net_probe",
                json!({"target": "db.example.com", "mode": "trace"}),
            )
            .await,
        );
        assert!(text.contains("10.0.0.1  0.5ms"), "{text}");
        assert_eq!(
            fake.calls("tracepath"),
            vec![argv(&["-n", "-m", "20", "db.example.com"])]
        );

        // neither installed
        let fake = FakeBins::new();
        let (host, _audit) = fixture(&fake, PROBE);
        match run(
            &host,
            "adam",
            "net_probe",
            json!({"target": "db.example.com", "mode": "trace"}),
        )
        .await
        {
            Err(ToolError::Failed(message)) => {
                assert!(
                    message.contains("traceroute") && message.contains("tracepath"),
                    "{message}"
                )
            }
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn net_probe_dns_lists_what_the_name_resolves_to() {
        let fake = FakeBins::new();
        let (host, _audit) = fixture(&fake, PROBE);
        let text = ok_text(
            run(
                &host,
                "adam",
                "net_probe",
                json!({"target": "localhost", "mode": "dns"}),
            )
            .await,
        );
        assert!(text.starts_with("localhost resolves to:\n"), "{text}");
        assert!(text.contains("127.0.0.1") || text.contains("::1"), "{text}");
    }

    #[test]
    fn resolver_lines_keeps_the_settings_and_drops_comments() {
        let text = "# managed by resolvconf\nnameserver 127.0.0.53\n\n; old\nnameserver 10.0.0.2\nsearch example.com stg.example.com\noptions edns0 trust-ad\nsortlist 10.0.0.0\n";
        assert_eq!(
            resolver_lines(text),
            [
                "nameserver 127.0.0.53",
                "nameserver 10.0.0.2",
                "search example.com stg.example.com",
                "options edns0 trust-ad",
            ]
        );
    }

    // ---- packet_capture -----------------------------------------------------------

    #[test]
    fn check_filter_joins_a_bpf_expression_into_one_argument() {
        assert_eq!(check_filter(&[]).unwrap(), "");
        assert_eq!(
            check_filter(&["tcp", "port", "443", "and", "host", "10.0.0.5"]).unwrap(),
            "tcp port 443 and host 10.0.0.5"
        );
        assert_eq!(
            check_filter(&["tcp[13]", "&", "2", "!=", "0"]).unwrap(),
            "tcp[13] & 2 != 0"
        );
        assert_eq!(
            check_filter(&[
                "(",
                "udp",
                "or",
                "icmp6",
                ")",
                "and",
                "net",
                "2001:db8::/32"
            ])
            .unwrap(),
            "( udp or icmp6 ) and net 2001:db8::/32"
        );
        assert_eq!(
            check_filter(&[
                "ether",
                "host",
                "aa:bb:cc:dd:ee:ff",
                "and",
                "len",
                "<=",
                "128"
            ])
            .unwrap(),
            "ether host aa:bb:cc:dd:ee:ff and len <= 128"
        );
    }

    #[test]
    fn check_filter_refuses_anything_tcpdump_could_read_as_an_option() {
        // AIDEV-NOTE: -w writes a file, -z runs a command, -r and -F read files. As root.
        for sneaky in [
            vec!["-w", "/tmp/x"],
            vec!["-z", "id"],
            vec!["-r", "/etc/shadow"],
            vec!["-F", "/etc/passwd"],
            vec!["-V", "/etc/passwd"],
            vec!["port", "80", "-w", "/tmp/x"],
            vec!["--version"],
            vec!["-"],
        ] {
            assert!(check_filter(&sneaky).is_err(), "{sneaky:?}");
        }
    }

    #[test]
    fn check_filter_refuses_odd_characters_and_oversized_expressions() {
        let long_token = "a".repeat(65);
        let many = vec!["or"; 65];
        for bad in [
            vec![""],
            vec!["a b"],
            vec!["port;id"],
            vec!["$(id)"],
            vec!["`id`"],
            vec!["'x'"],
            vec!["\"x\""],
            vec!["port", "80\\"],
            vec![long_token.as_str()],
            many,
        ] {
            assert!(check_filter(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn capture_seconds_stays_inside_the_time_a_call_may_take() {
        assert_eq!(capture_seconds(10, 120), 10);
        assert_eq!(capture_seconds(30, 120), 30);
        assert_eq!(capture_seconds(30, 20), 15);
        assert_eq!(capture_seconds(30, 6), 1);
        assert_eq!(capture_seconds(30, 1), 1);
    }

    const CAPTURE: &str = "capture_interfaces = [\"eth*\", \"lo\"]";

    #[tokio::test]
    async fn packet_capture_is_refused_until_capture_interfaces_is_configured() {
        let fake = FakeBins::new().add("tcpdump", "packet\n", 0);
        let (host, audit) = fixture(&fake, "");
        let message = is_denied(
            run(
                &host,
                "adam",
                "packet_capture",
                json!({"interface": "eth0"}),
            )
            .await,
        );
        assert!(message.contains("net.capture_interfaces"), "{message}");
        assert!(fake.calls("tcpdump").is_empty());
        let records = audit.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["decision"], "deny");
        assert_eq!(records[0]["resource"], "eth0");
    }

    #[tokio::test]
    async fn packet_capture_refuses_interfaces_the_host_does_not_allow() {
        let fake = FakeBins::new().add("tcpdump", "packet\n", 0);
        let (host, _audit) = fixture(&fake, CAPTURE);
        for interface in ["any", "wg0", "docker0"] {
            let message = is_denied(
                run(
                    &host,
                    "adam",
                    "packet_capture",
                    json!({"interface": interface}),
                )
                .await,
            );
            assert!(message.contains("net.capture_interfaces"), "{message}");
        }
        assert!(fake.calls("tcpdump").is_empty());
    }

    #[tokio::test]
    async fn packet_capture_runs_tcpdump_with_the_filter_as_one_argument_after_the_separator() {
        let fake = FakeBins::new().add(
            "tcpdump",
            "12:00:00.000001 IP 10.0.0.5.443 > 10.0.0.7.51000: Flags [S.]\n",
            0,
        );
        let (host, _audit) = fixture(&fake, CAPTURE);
        let text = ok_text(
            run(
                &host,
                "adam",
                "packet_capture",
                json!({"interface": "eth0", "filter": ["tcp", "port", "443"]}),
            )
            .await,
        );
        assert!(text.contains("10.0.0.5.443 > 10.0.0.7.51000"), "{text}");
        ok_text(
            run(
                &host,
                "adam",
                "packet_capture",
                json!({"interface": "lo", "count": 5}),
            )
            .await,
        );
        assert_eq!(
            fake.calls("tcpdump"),
            vec![
                argv(&[
                    "-i",
                    "eth0",
                    "-n",
                    "-p",
                    "-l",
                    "--immediate-mode",
                    "-c",
                    "100",
                    "-q",
                    "-s",
                    "96",
                    "--",
                    "tcp port 443"
                ]),
                // AIDEV-NOTE: -q and a short snap length are what make "headers only"
                // true. Without them tcpdump decodes what it can of the contents: an
                // HTTP request line with its query string, an SNMP community string.
                argv(&[
                    "-i",
                    "lo",
                    "-n",
                    "-p",
                    "-l",
                    "--immediate-mode",
                    "-c",
                    "5",
                    "-q",
                    "-s",
                    "96"
                ]),
            ]
        );
    }

    #[test]
    fn the_filter_suggested_in_the_description_is_accepted() {
        assert_eq!(
            check_filter(&["tcp[tcpflags]", "&", "tcp-rst", "!=", "0"]).unwrap(),
            "tcp[tcpflags] & tcp-rst != 0"
        );
    }

    #[tokio::test]
    async fn packet_capture_never_runs_tcpdump_with_an_option_smuggled_in_the_filter() {
        let fake = FakeBins::new().add("tcpdump", "packet\n", 0);
        let (host, audit) = fixture(&fake, CAPTURE);
        for filter in [
            json!(["-w", "/tmp/out.pcap"]),
            json!(["-z", "/bin/sh"]),
            json!(["-r", "/etc/shadow"]),
            json!(["-F", "/etc/shadow"]),
            json!(["port", "80", "-w", "/tmp/out.pcap"]),
        ] {
            is_invalid(
                run(
                    &host,
                    "adam",
                    "packet_capture",
                    json!({"interface": "eth0", "filter": filter}),
                )
                .await,
            );
        }
        // nor with one in the interface name
        is_invalid(run(&host, "adam", "packet_capture", json!({"interface": "-w"})).await);
        assert!(fake.calls("tcpdump").is_empty());
        assert!(audit.records().is_empty());
    }

    #[tokio::test]
    async fn packet_capture_returns_contents_only_where_the_host_allows_it() {
        let fake = FakeBins::new().add("tcpdump", "packet\n", 0);
        let (host, audit) = fixture(&fake, CAPTURE);
        let message = is_denied(
            run(
                &host,
                "adam",
                "packet_capture",
                json!({"interface": "eth0", "payload": true}),
            )
            .await,
        );
        assert!(message.contains("net.capture_payload"), "{message}");
        assert!(fake.calls("tcpdump").is_empty());
        assert_eq!(audit.records()[0]["decision"], "deny");

        let (host, _audit) = fixture(&fake, &format!("{CAPTURE}\ncapture_payload = true"));
        ok_text(
            run(
                &host,
                "adam",
                "packet_capture",
                json!({"interface": "eth0", "payload": true, "filter": ["port", "80"]}),
            )
            .await,
        );
        assert_eq!(
            fake.calls("tcpdump"),
            vec![argv(&[
                "-i",
                "eth0",
                "-n",
                "-p",
                "-l",
                "--immediate-mode",
                "-c",
                "100",
                "-A",
                "-s",
                "512",
                "--",
                "port 80"
            ])]
        );
    }

    #[tokio::test]
    async fn packet_capture_needs_a_grant_for_the_interface_and_is_not_part_of_read() {
        let fake = FakeBins::new().add("tcpdump", "packet\n", 0);
        let (host, _audit) = fixture(&fake, CAPTURE);
        // nina holds net.capture:eth0
        ok_text(
            run(
                &host,
                "nina",
                "packet_capture",
                json!({"interface": "eth0"}),
            )
            .await,
        );
        is_denied(
            run(
                &host,
                "nina",
                "packet_capture",
                json!({"interface": "eth1"}),
            )
            .await,
        );
        // rita holds @read: every read tool, but not other people's traffic
        is_denied(
            run(
                &host,
                "rita",
                "packet_capture",
                json!({"interface": "eth0"}),
            )
            .await,
        );
        assert_eq!(fake.calls("tcpdump").len(), 1);
    }

    #[tokio::test]
    async fn packet_capture_treats_its_time_limit_as_the_normal_end() {
        let fake = FakeBins::new().add_script(
            "tcpdump",
            // the stand-in runs with an empty PATH: say where sleep lives
            "echo 'listening on eth0' >&2; echo '12:00:00.1 IP a > b: one'; \
             PATH=/usr/bin:/bin:/run/current-system/sw/bin; sleep 30",
        );
        let (host, _audit) = fixture(&fake, CAPTURE);
        let started = std::time::Instant::now();
        let text = ok_text(
            run(
                &host,
                "adam",
                "packet_capture",
                json!({"interface": "eth0", "seconds": 1}),
            )
            .await,
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        assert!(text.starts_with("12:00:00.1 IP a > b: one\n"), "{text}");
        assert!(text.contains("[capture stopped after 1 second]"), "{text}");
        // tcpdump's own remarks come after the packets
        assert!(
            text.find("listening on eth0").unwrap() > text.find("IP a > b").unwrap(),
            "{text}"
        );
        assert!(
            !text.contains("time limit"),
            "not reported as a problem: {text}"
        );
    }

    #[tokio::test]
    async fn packet_capture_reports_a_tcpdump_error_as_a_failure() {
        let fake = FakeBins::new().add_script(
            "tcpdump",
            "echo 'tcpdump: cannot parse filter expression: syntax error' >&2; exit 1",
        );
        let (host, _audit) = fixture(&fake, CAPTURE);
        let output = run(
            &host,
            "adam",
            "packet_capture",
            json!({"interface": "eth0", "filter": ["port", "port"]}),
        )
        .await
        .unwrap();
        assert!(output.is_error());
        assert!(output.text().contains("syntax error"), "{}", output.text());
        assert!(output.text().contains("exit status 1"), "{}", output.text());
    }

    #[tokio::test]
    async fn packet_capture_says_so_when_nothing_was_seen() {
        let fake = FakeBins::new().add_script("tcpdump", "echo '0 packets captured' >&2");
        let (host, _audit) = fixture(&fake, CAPTURE);
        let text = ok_text(
            run(
                &host,
                "adam",
                "packet_capture",
                json!({"interface": "eth0"}),
            )
            .await,
        );
        assert!(text.starts_with("(no packets captured)\n"), "{text}");
        assert!(text.contains("0 packets captured"), "{text}");
    }

    #[tokio::test]
    async fn packet_capture_keeps_the_first_packets_when_there_are_too_many() {
        let fake = FakeBins::new().add_script(
            "tcpdump",
            r#"i=0; while [ $i -lt 2000 ]; do echo "12:00:00.$i IP 10.0.0.5.443 > 10.0.0.7.51000: Flags [P.], length 1400 number $i"; i=$((i+1)); done; echo '2000 packets captured' >&2"#,
        );
        let (host, _audit) = fixture(&fake, CAPTURE);
        let text = ok_text(
            run(
                &host,
                "adam",
                "packet_capture",
                json!({"interface": "eth0"}),
            )
            .await,
        );
        assert!(text.len() <= 64 * 1024, "{} bytes", text.len());
        assert!(text.contains("number 0\n"), "{text}");
        assert!(!text.contains("number 1999\n"));
        assert!(text.contains("left out"), "the cut should be announced");
        assert!(
            text.contains("2000 packets captured"),
            "tcpdump's summary survives"
        );
    }
}
