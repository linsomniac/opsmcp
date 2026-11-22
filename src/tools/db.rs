//! Database status: MariaDB and Galera, PostgreSQL, Patroni.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use nix::unistd::User;
use serde_json::Value;

use super::args::{Args, Param};
use super::{
    CallClock, Ctx, Tool, ToolError, ToolResult, blocking, command_ok, command_text, format_rows,
    format_table, one_line_cell, required,
};
use crate::exec::{Cmd, CmdOutput, RunAs};
use crate::policy::Access;
use crate::sanitize::{keep_head, redact_text};
use crate::timefmt::{human_bytes, human_duration};

/// What db_status needs to know about the machine. Tests point these at a temporary
/// directory.
#[derive(Clone, Debug)]
pub struct Env {
    /// Where Patroni's configuration is looked for when `db.patroni_config` is not set.
    pub patroni_configs: Vec<PathBuf>,
    /// The file holding this machine's host name.
    pub hostname: PathBuf,
}

impl Env {
    pub fn system() -> Env {
        Env {
            patroni_configs: [
                "/etc/patroni/patroni.yml",
                "/etc/patroni/config.yml",
                "/etc/patroni/patroni.yaml",
                "/etc/patroni.yml",
            ]
            .iter()
            .map(PathBuf::from)
            .collect(),
            hostname: PathBuf::from("/proc/sys/kernel/hostname"),
        }
    }
}

const ENGINES: [&str; 3] = ["mariadb", "postgres", "patroni"];

pub fn tools() -> Vec<Tool> {
    tools_with(Env::system())
}

pub fn tools_with(env: Env) -> Vec<Tool> {
    let env = Arc::new(env);
    vec![Tool::new(
        "db_status",
        "Show the health of a database server on this host, from a fixed set of status \
         queries (no SQL is taken from the caller). mariadb: MariaDB, MySQL or Percona \
         Server, with Galera cluster state and replication; postgres: connections, \
         replication and lag, replication slots, long transactions, locks, transaction ID \
         age and WAL archiving; patroni: the members of a Patroni-managed PostgreSQL \
         cluster with their roles, state, timeline and lag, maintenance mode and recent \
         leader changes. The first line is the verdict, beginning with PROBLEM: when \
         something is wrong. The text of running queries is shown only if this host's \
         configuration allows it.",
        Access::Read,
        "db.view",
        vec![
            Param::choice("engine", "Which database to look at", &ENGINES).required(),
            Param::int(
                "long_seconds",
                "List statements or transactions that have been running at least this \
                 long (default 60). mariadb and postgres only",
                1,
                86_400,
            ),
            Param::int(
                "limit",
                "Most rows in each list (default 20). mariadb and postgres only",
                1,
                100,
            ),
        ],
        move |ctx, args| {
            let env = env.clone();
            async move { db_status(ctx, args, env).await }
        },
    )]
}

/// The rows of one section of a client's output.
pub type Rows = Vec<Vec<String>>;

/// The most a status report needs of any one value from a server.
const VALUE_MAX: usize = 120;
/// Lag above this is reported as a problem (PostgreSQL and Patroni).
const LAG_PROBLEM_MB: u64 = 64;
/// An inactive replication slot holding back more WAL than this is a problem.
const SLOT_PROBLEM_BYTES: u64 = 1 << 30;
/// A transaction ID age above this is a problem (wraparound is at about 2.1 billion).
const XID_PROBLEM_AGE: u64 = 1_500_000_000;
/// Connections above this share of the maximum are a problem.
const CONNECTIONS_PROBLEM_PERCENT: u64 = 85;
/// A MariaDB or MySQL replica this many seconds behind its source is a problem.
const REPLICATION_BEHIND_PROBLEM_SECS: u64 = 300;
/// The longest any one patronictl command is waited for, in seconds. It answers within
/// a second or two when the DCS is reachable, and not for minutes when it is not.
const PATRONICTL_WAIT_SECS: u64 = 15;

/// Server text on one line of ours, cut to `max` characters.
///
/// AIDEV-NOTE: names of databases, users, members and clusters, states and error texts
/// all come from the server or from other machines. Everything shown passes through
/// here, so none of it can start a line that looks like the tool's own (a made-up
/// verdict, say).
fn shown(text: &str, max: usize) -> String {
    let line = one_line_cell(text.trim());
    if line.chars().count() <= max {
        return line;
    }
    let mut kept: String = line.chars().take(max).collect();
    kept.push_str("...");
    kept
}

fn field(row: &[String], index: usize) -> &str {
    row.get(index).map(String::as_str).unwrap_or("")
}

fn number(text: &str) -> Option<u64> {
    text.trim().parse().ok()
}

/// `1 thing` or `3 things`.
fn count(n: u64, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

/// `part` as a whole percentage of `whole`, rounded down.
fn percent(part: u64, whole: u64) -> u64 {
    part.saturating_mul(100).checked_div(whole).unwrap_or(0)
}

/// What a client said on stderr (and how it ended), on one line, secrets masked.
fn complaint(out: &CmdOutput) -> String {
    let mut quiet = out.clone();
    quiet.stdout.clear();
    let text = redact_text(&command_text(&quiet));
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    shown(&lines.join(" "), 400)
}

/// The last few lines a command wrote to stderr, secrets masked.
fn stderr_tail(out: &CmdOutput, lines: usize) -> String {
    let text = redact_text(&String::from_utf8_lossy(&out.stderr));
    let all: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let mut tail = String::new();
    for line in all.iter().skip(all.len().saturating_sub(lines)) {
        tail.push_str(&shown(line, 300));
        tail.push('\n');
    }
    tail
}

/// What a report says first.
#[derive(Default)]
struct Verdict {
    problems: Vec<String>,
    summary: String,
}

impl Verdict {
    fn line(&self) -> String {
        if self.problems.is_empty() {
            self.summary.clone()
        } else {
            format!("PROBLEM: {}. {}", self.problems.join("; "), self.summary)
        }
    }
}

/// What one engine found.
struct Report {
    text: String,
    /// Whether the server (or patronictl) answered at all. A report full of problems is
    /// still an answer; a server that cannot be asked is a failed call.
    answered: bool,
}

impl Report {
    /// The server could not be asked: `problem` is the verdict, `detail` what was said.
    fn unanswered(problem: &str, detail: &str) -> Report {
        let mut text = format!("PROBLEM: {problem}\n");
        if !detail.is_empty() {
            text.push_str(detail);
            if !detail.ends_with('\n') {
                text.push('\n');
            }
        }
        Report {
            text,
            answered: false,
        }
    }
}

/// Runs `cmd` with what the call has left of its time (at most `cap` seconds). `Err` is
/// a sentence saying why it was not run.
async fn run_limited(
    ctx: &Ctx,
    clock: &CallClock,
    cmd: Cmd,
    cap: Option<u64>,
) -> Result<(CmdOutput, u64), String> {
    let Some(mut limit) = clock.next() else {
        return Err("the call's time ran out".to_string());
    };
    if let Some(cap) = cap {
        limit = limit.min(Duration::from_secs(cap));
    }
    let seconds = limit.as_secs().max(1);
    match ctx.run(cmd.timeout(limit)).await {
        Ok(out) => Ok((out, seconds)),
        Err(ToolError::Failed(problem)) => Err(shown(&problem, 300)),
        Err(_) => Err("it could not be started".to_string()),
    }
}

/// The text of a query for the table: shown, masked and cut, only where the host's
/// configuration allows it.
///
/// AIDEV-NOTE: the text of a running query carries whatever the application put in it:
/// names, e-mail addresses, password hashes being compared. It is off by default
/// (`db.show_queries`), and when it is off the queries below do not even fetch it.
fn query_cell(show: bool, text: &str) -> String {
    if !show {
        return "(hidden)".to_string();
    }
    shown(&redact_text(text), 200)
}

const HIDDEN_NOTE: &str = "[query text is hidden: db.show_queries is off on this host]\n";

// ---- MariaDB, MySQL, Galera -----------------------------------------------------------

/// The row that starts a section in the MariaDB client's output.
pub const MYSQL_MARKER: &str = "#opsmcp-section";

/// Splits `mariadb --batch --skip-column-names` output into the sections that the
/// marker rows start. Fields are separated by tabs.
///
/// AIDEV-NOTE: in batch mode the client escapes tabs and line breaks inside values, so
/// a value cannot begin a row of its own, and the rows of our sections begin with a
/// variable name or a numeric id, never with the marker.
pub fn mysql_sections(output: &str) -> BTreeMap<String, Rows> {
    let mut sections: BTreeMap<String, Rows> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in output.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.first() == Some(&MYSQL_MARKER) {
            let name = fields.get(1).copied().unwrap_or("").to_string();
            sections.entry(name.clone()).or_default();
            current = Some(name);
        } else if let Some(name) = &current
            && let Some(rows) = sections.get_mut(name)
        {
            rows.push(fields.iter().map(|f| f.to_string()).collect());
        }
    }
    sections
}

/// The statements that show replication status, the newest spelling first.
///
/// AIDEV-NOTE: the ALL forms come first on purpose. On MariaDB a server can replicate
/// from several sources ("connections"), and `SHOW REPLICA STATUS` shows the default
/// connection ONLY (checked on 10.11): a second connection that had stopped would never
/// be seen. MySQL does not know the ALL forms and answers with a syntax error; its
/// `SHOW REPLICA STATUS` lists every channel by itself.
const REPLICATION_STATEMENTS: [&str; 4] = [
    "SHOW ALL REPLICAS STATUS\\G",
    "SHOW ALL SLAVES STATUS\\G",
    "SHOW REPLICA STATUS\\G",
    "SHOW SLAVE STATUS\\G",
];

/// One replication connection or channel, from the vertical output of one of
/// `REPLICATION_STATEMENTS`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Replication {
    /// The name of the connection (MariaDB) or channel (MySQL); empty for the default.
    pub channel: String,
    /// The name came as a MariaDB `Connection_name`.
    pub connection: bool,
    pub source: String,
    pub io_running: String,
    pub sql_running: String,
    /// Seconds behind the source; `None` when the server says NULL.
    pub behind: Option<u64>,
    pub io_error: String,
    pub sql_error: String,
    /// The numbers of those errors, as the server gives them (`0` or empty for none).
    pub io_errno: String,
    pub sql_errno: String,
}

/// Reads the client's vertical output (`name: value` lines under a `*** N. row ***`
/// line per channel), under the names older and newer servers use.
pub fn parse_replication(text: &str) -> Vec<Replication> {
    let mut channels: Vec<Replication> = Vec::new();
    for line in text.lines() {
        if line.trim_start().starts_with("***") {
            channels.push(Replication::default());
            continue;
        }
        let Some(channel) = channels.last_mut() else {
            continue;
        };
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "source_host" | "master_host" => channel.source = value.to_string(),
            "replica_io_running" | "slave_io_running" => channel.io_running = value.to_string(),
            "replica_sql_running" | "slave_sql_running" => {
                channel.sql_running = value.to_string();
            }
            "seconds_behind_source" | "seconds_behind_master" => channel.behind = number(value),
            "last_io_error" => channel.io_error = value.to_string(),
            "last_sql_error" => channel.sql_error = value.to_string(),
            "last_io_errno" => channel.io_errno = value.to_string(),
            "last_sql_errno" => channel.sql_errno = value.to_string(),
            "channel_name" => channel.channel = value.to_string(),
            "connection_name" => {
                channel.channel = value.to_string();
                channel.connection = true;
            }
            _ => {}
        }
    }
    channels
}

/// Where a replication error starts to name the statement it failed on, if it does.
/// Statement-based replication reports `Error '<message>' on query. Default database:
/// '<name>'. Query: '<statement>'`.
fn statement_starts(error: &str) -> Option<usize> {
    // ASCII lower-casing keeps every byte where it was, so an offset found in the
    // lower-cased text is the same place in the original.
    let lower = error.to_ascii_lowercase();
    [" on query", "query:", "default database:"]
        .iter()
        .filter_map(|marker| lower.find(marker))
        .min()
}

/// What KIND of error a replication SQL error is: its leading words, without the
/// statement it names and without the values in it.
///
/// AIDEV-NOTE: the SQL thread's error is made of the application's data. It quotes the
/// statement that failed, and the message in front of it quotes row values ("Duplicate
/// entry 'bob@example.com' for key ..."). With `db.show_queries` off neither may be
/// shown, exactly as the text of running queries is not. So the text is cut where the
/// statement begins, and again at the first quoted value. That loses the names of
/// tables and keys along with the values; the error number is shown beside it, and the
/// whole text is there for an operator who turns the setting on.
fn error_class(error: &str) -> String {
    let error = error.trim();
    let mut hidden = false;
    let mut text = error;
    if let Some(at) = statement_starts(text) {
        text = text.get(..at).unwrap_or(text);
        hidden = true;
    }
    let text = text.strip_prefix("Error '").unwrap_or(text);
    // The first quote that opens a value. An apostrophe between two letters ("Can't",
    // "doesn't") is part of a word.
    let bytes = text.as_bytes();
    let opens_value = |at: usize| {
        let letter = |index: Option<usize>| {
            index
                .and_then(|index| bytes.get(index))
                .is_some_and(u8::is_ascii_alphabetic)
        };
        match bytes.get(at) {
            Some(b'"') | Some(b'`') => true,
            Some(b'\'') => !(letter(at.checked_sub(1)) && letter(at.checked_add(1))),
            _ => false,
        }
    };
    let text = match (0..bytes.len()).find(|at| opens_value(*at)) {
        Some(at) => {
            hidden = true;
            text.get(..at).unwrap_or(text)
        }
        None => text,
    };
    let kept = text.trim_end_matches(|c: char| c.is_whitespace() || "'\".,;:".contains(c));
    if hidden {
        format!("{kept} ...")
    } else {
        kept.to_string()
    }
}

/// Why a server that runs as root may not use `file`, the client options file named by
/// `db.mysql_defaults_file`; `None` when it may.
///
/// AIDEV-NOTE: the client is started as root and does what that file says: it can name
/// a plugin directory and a plugin to load, which is code run as root. So for a root
/// server the file is held to the rule the configuration file and every program are
/// held to: it, and every directory on the way to it, belong to root and can be
/// replaced by nobody else. A server that is not root starts the client as itself, and
/// has nothing more to lose than its own user already has.
fn untrusted_defaults_file(file: &Path, as_root: bool) -> Option<String> {
    if !as_root {
        return None;
    }
    crate::exec::check_trusted_path(file, &[]).err()
}

/// The statements sent for the main part of the report.
///
/// AIDEV-NOTE: every statement is fixed text. The only values put into it are the two
/// integers, which come from validated integer parameters; nothing a caller writes can
/// become SQL.
fn mysql_sql(long_seconds: i64, limit: i64, show_queries: bool) -> String {
    let query = if show_queries {
        "IFNULL(LEFT(INFO, 200), '')"
    } else {
        "''"
    };
    format!(
        "SELECT '{MYSQL_MARKER}', 'variables'; \
         SHOW GLOBAL VARIABLES WHERE Variable_name IN ('version', 'version_comment', \
         'max_connections', 'read_only', 'server_id', 'wsrep_on', 'wsrep_cluster_name', \
         'wsrep_node_name'); \
         SELECT '{MYSQL_MARKER}', 'status'; \
         SHOW GLOBAL STATUS WHERE Variable_name IN ('Uptime', 'Threads_connected', \
         'Threads_running', 'Max_used_connections', 'Aborted_connects', 'Slow_queries', \
         'Innodb_row_lock_current_waits', 'wsrep_cluster_size', 'wsrep_cluster_status', \
         'wsrep_local_state_comment', 'wsrep_ready', 'wsrep_connected', \
         'wsrep_local_recv_queue_avg', 'wsrep_local_send_queue_avg', \
         'wsrep_flow_control_paused', 'wsrep_cert_deps_distance', \
         'wsrep_incoming_addresses', 'wsrep_last_committed'); \
         SELECT '{MYSQL_MARKER}', 'statements'; \
         SELECT ID, USER, HOST, IFNULL(DB, ''), COMMAND, TIME, IFNULL(STATE, ''), {query} \
         FROM information_schema.PROCESSLIST \
         WHERE COMMAND NOT IN ('Sleep', 'Daemon', 'Binlog Dump', 'Binlog Dump GTID') \
         AND USER NOT IN ('system user', 'event_scheduler') \
         AND ID <> CONNECTION_ID() AND TIME >= {long_seconds} \
         ORDER BY TIME DESC LIMIT {limit}"
    )
}

/// `name → value` for a section of two-column rows, names in lower case.
fn pairs(rows: Option<&Rows>) -> BTreeMap<String, String> {
    rows.map(|rows| {
        rows.iter()
            .filter(|row| row.len() >= 2)
            .map(|row| {
                (
                    field(row, 0).to_ascii_lowercase(),
                    field(row, 1).to_string(),
                )
            })
            .collect()
    })
    .unwrap_or_default()
}

/// The server and Galera parts, from the variables and status sections.
fn mysql_server_text(
    vars: &BTreeMap<String, String>,
    status: &BTreeMap<String, String>,
    verdict: &mut Verdict,
) -> String {
    let var = |name: &str| vars.get(name).map(String::as_str).unwrap_or("");
    let stat = |name: &str| status.get(name).map(String::as_str).unwrap_or("");
    let or_unknown = |value: &str| {
        if value.is_empty() {
            "unknown".to_string()
        } else {
            shown(value, VALUE_MAX)
        }
    };

    let version = var("version");
    let comment = var("version_comment");
    let product = if version.contains("MariaDB") {
        "MariaDB"
    } else if comment.contains("Percona") {
        "Percona Server"
    } else {
        "MySQL"
    };
    let uptime = number(stat("uptime")).map(human_duration);
    let connected = number(stat("threads_connected"));
    let maximum = number(var("max_connections"));

    let mut text = String::from("== server ==\n");
    text.push_str(&format!("Version: {}", or_unknown(version)));
    if !comment.is_empty() {
        text.push_str(&format!(" ({})", shown(comment, VALUE_MAX)));
    }
    text.push('\n');
    text.push_str(&format!(
        "Uptime: {}\n",
        uptime.clone().unwrap_or_else(|| "unknown".to_string())
    ));
    text.push_str(&format!("Read only: {}\n", or_unknown(var("read_only"))));
    let connections = match (connected, maximum) {
        (Some(connected), Some(maximum)) => {
            let share = percent(connected, maximum);
            if connected.saturating_mul(100) > maximum.saturating_mul(CONNECTIONS_PROBLEM_PERCENT) {
                verdict
                    .problems
                    .push(format!("connections are at {share}% of the maximum"));
            }
            format!("{connected} of {maximum} ({share}%)")
        }
        (Some(connected), None) => connected.to_string(),
        _ => "unknown".to_string(),
    };
    text.push_str(&format!(
        "Connections: {connections}; most used at once: {}; running now: {}; aborted connects: {}\n",
        or_unknown(stat("max_used_connections")),
        or_unknown(stat("threads_running")),
        or_unknown(stat("aborted_connects")),
    ));
    text.push_str(&format!(
        "Slow queries: {}; row lock waits now: {}\n",
        or_unknown(stat("slow_queries")),
        or_unknown(stat("innodb_row_lock_current_waits")),
    ));

    verdict.summary = format!(
        "{product} {}, up {}; connections {connections}",
        or_unknown(version),
        uptime.unwrap_or_else(|| "unknown".to_string()),
    );

    // Galera: when the server says it is on, or (older servers have no wsrep_on status)
    // when it reports a cluster status at all.
    let galera = match var("wsrep_on") {
        "" => !stat("wsrep_cluster_status").is_empty(),
        on => on.eq_ignore_ascii_case("ON"),
    };
    if galera {
        let cluster_status = stat("wsrep_cluster_status");
        let node_state = stat("wsrep_local_state_comment");
        let ready = stat("wsrep_ready");
        let connected = stat("wsrep_connected");
        let paused = stat("wsrep_flow_control_paused").parse::<f64>().ok();
        if cluster_status != "Primary" {
            verdict.problems.push(format!(
                "the Galera cluster status is {}, not Primary",
                or_unknown(cluster_status)
            ));
        }
        if node_state == "Donor/Desynced" {
            // Expected while another node takes a state transfer from this one: still
            // not a node to send traffic to, but it passes by itself.
            verdict.problems.push(
                "this node is a donor for another node's state transfer, which is temporary"
                    .to_string(),
            );
        } else if node_state != "Synced" {
            verdict.problems.push(format!(
                "this node is {}, not Synced",
                or_unknown(node_state)
            ));
        }
        if !ready.eq_ignore_ascii_case("ON") {
            verdict
                .problems
                .push(format!("wsrep_ready is {}", or_unknown(ready)));
        }
        if !connected.is_empty() && !connected.eq_ignore_ascii_case("ON") {
            verdict
                .problems
                .push(format!("wsrep_connected is {}", shown(connected, 20)));
        }
        // AIDEV-NOTE: wsrep_flow_control_paused is the share of time replication was
        // paused since the last FLUSH STATUS (or since the server started). One bad hour
        // weeks ago keeps it high for good, so it is shown, with what it covers, and is
        // not called a problem by itself: the queue figures beside it are the present.
        text.push_str("== galera ==\n");
        text.push_str(&format!(
            "Cluster: {}; status {}; {} nodes\n",
            or_unknown(var("wsrep_cluster_name")),
            or_unknown(cluster_status),
            or_unknown(stat("wsrep_cluster_size")),
        ));
        text.push_str(&format!(
            "Node: {}; state {}; ready {}; connected {}\n",
            or_unknown(var("wsrep_node_name")),
            or_unknown(node_state),
            or_unknown(ready),
            or_unknown(connected),
        ));
        text.push_str(&format!(
            "Queues: receive {}, send {} (averages); flow control paused {} of the time \
             since the last FLUSH STATUS (or the start); certification distance {}\n",
            or_unknown(stat("wsrep_local_recv_queue_avg")),
            or_unknown(stat("wsrep_local_send_queue_avg")),
            paused
                .map(|share| format!("{:.1}%", share * 100.0))
                .unwrap_or_else(|| "unknown".to_string()),
            or_unknown(stat("wsrep_cert_deps_distance")),
        ));
        text.push_str(&format!(
            "Members: {}\n",
            shown(stat("wsrep_incoming_addresses"), 600)
        ));
        text.push_str(&format!(
            "Last committed: {}\n",
            or_unknown(stat("wsrep_last_committed"))
        ));
        verdict.summary.push_str(&format!(
            "; Galera {}, {} nodes, this node {}",
            or_unknown(cluster_status),
            or_unknown(stat("wsrep_cluster_size")),
            or_unknown(node_state),
        ));
    }
    text
}

/// The replication part, from the connections or channels the server reported.
fn mysql_replication_text(
    channels: &[Replication],
    show_queries: bool,
    verdict: &mut Verdict,
) -> String {
    let mut text = String::from("== replication ==\n");
    if channels.is_empty() {
        text.push_str("This server is not a replica.\n");
        return text;
    }
    let mut hid_something = false;
    for channel in channels {
        let mut from = format!("replication from {}", shown(&channel.source, VALUE_MAX));
        if !channel.channel.is_empty() {
            from.push_str(&format!(
                " ({} {})",
                if channel.connection {
                    "connection"
                } else {
                    "channel"
                },
                shown(&channel.channel, 60)
            ));
        }
        for (thread, state) in [("IO", &channel.io_running), ("SQL", &channel.sql_running)] {
            if state != "Yes" {
                let detail = if state == "No" || state.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", shown(state, 40))
                };
                verdict.problems.push(format!(
                    "{from}: the {thread} thread is not running{detail}"
                ));
            }
        }
        if let Some(seconds) = channel.behind
            && seconds >= REPLICATION_BEHIND_PROBLEM_SECS
        {
            verdict
                .problems
                .push(format!("{from} is {seconds} s behind"));
        }
        let behind = match channel.behind {
            Some(seconds) => format!("{seconds} s"),
            None => "unknown".to_string(),
        };
        text.push_str(&format!(
            "{from}: IO thread {}, SQL thread {}, behind: {behind}\n",
            shown(&channel.io_running, 40),
            shown(&channel.sql_running, 40),
        ));
        for (label, error, errno, is_sql) in [
            ("last IO error", &channel.io_error, &channel.io_errno, false),
            (
                "last SQL error",
                &channel.sql_error,
                &channel.sql_errno,
                true,
            ),
        ] {
            if error.is_empty() {
                continue;
            }
            let number = match errno.trim() {
                "" | "0" => String::new(),
                number => format!(" ({})", shown(number, 12)),
            };
            // See `error_class`: what the error says of the application's data is shown
            // only where the text of queries may be shown.
            let said = if show_queries {
                shown(&redact_text(error), 300)
            } else if is_sql {
                let class = error_class(error);
                hid_something |= class.ends_with(" ...");
                shown(&redact_text(&class), 300)
            } else {
                // The IO thread's errors are about the connection, not about data; only
                // a statement, should one ever be named, is cut off.
                match statement_starts(error) {
                    Some(at) => {
                        hid_something = true;
                        format!(
                            "{} ...",
                            shown(&redact_text(error.get(..at).unwrap_or("")), 300)
                        )
                    }
                    None => shown(&redact_text(error), 300),
                }
            };
            text.push_str(&format!("  {label}{number}: {said}\n"));
        }
    }
    if hid_something {
        text.push_str(
            "[the statement and the values named in a replication error are hidden: \
             db.show_queries is off on this host]\n",
        );
    }
    if let [only] = channels
        && only.io_running == "Yes"
        && only.sql_running == "Yes"
    {
        verdict.summary.push_str(&format!(
            "; replica of {}, {} behind",
            shown(&only.source, VALUE_MAX),
            match only.behind {
                Some(seconds) => format!("{seconds} s"),
                None => "an unknown time".to_string(),
            }
        ));
    }
    text
}

/// Whether the client's refusal says the server does not know the statement at all.
fn is_syntax_error(out: &CmdOutput) -> bool {
    let said = String::from_utf8_lossy(&out.stderr);
    said.contains("ERROR 1064") || said.contains("error in your SQL syntax")
}

/// The long-running statements.
fn mysql_statements_text(rows: Option<&Rows>, long_seconds: i64, show_queries: bool) -> String {
    let mut text = format!("== statements running for {long_seconds} s or more ==\n");
    let Some(rows) = rows else {
        text.push_str("[no answer]\n");
        return text;
    };
    if rows.is_empty() {
        text.push_str("none\n");
        return text;
    }
    let table: Rows = rows
        .iter()
        .map(|row| {
            vec![
                shown(field(row, 0), 20),
                shown(field(row, 1), 40),
                shown(field(row, 2), 60),
                shown(field(row, 3), 40),
                shown(field(row, 4), 20),
                shown(field(row, 5), 12),
                shown(field(row, 6), 60),
                query_cell(show_queries, field(row, 7)),
            ]
        })
        .collect();
    text.push_str(&format_table(
        &[
            "ID", "USER", "CLIENT", "DATABASE", "COMMAND", "SECONDS", "STATE", "QUERY",
        ],
        &table,
        &[true, false, false, false, false, true, false, false],
    ));
    if !show_queries {
        text.push_str(HIDDEN_NOTE);
    }
    text
}

async fn mariadb(
    ctx: &Ctx,
    clock: &CallClock,
    long_seconds: i64,
    limit: i64,
) -> Result<Report, ToolError> {
    let (client, name) = match ctx.optional_command("mariadb")? {
        Some(cmd) => (cmd, "mariadb"),
        None => match ctx.optional_command("mysql")? {
            Some(cmd) => (cmd, "mysql"),
            None => {
                return Err(ToolError::Failed(
                    "neither mariadb nor mysql (the command-line client) is installed on \
                     this host (package mariadb-client or mysql-client)"
                        .to_string(),
                ));
            }
        },
    };
    let show_queries = ctx.cfg().db.show_queries;

    // AIDEV-NOTE: the client is only ever pointed at the local server, with the
    // credentials the operator configured (or socket authentication as the server's own
    // user). No host, user or password argument is built here, and
    // --defaults-extra-file has to be the first argument for the client to honour it.
    let mut base: Vec<String> = Vec::new();
    if let Some(file) = &ctx.cfg().db.mysql_defaults_file {
        let as_root = rustix::process::geteuid().is_root();
        let checked = file.clone();
        let problem = blocking(ctx.clone(), move || {
            Ok(untrusted_defaults_file(&checked, as_root))
        })
        .await?;
        if let Some(problem) = problem {
            return Err(ToolError::Failed(format!(
                "refusing to use the client options file (db.mysql_defaults_file): {problem}. \
                 This server runs as root and the client does what that file says, which \
                 can include loading a plugin: the file and every directory on the way to \
                 it must belong to root and be writable by nobody else"
            )));
        }
        base.push(format!("--defaults-extra-file={}", file.display()));
    }
    let with = |extra: &[&str]| {
        let mut args = base.clone();
        args.extend(extra.iter().map(|arg| arg.to_string()));
        args
    };

    let sql = mysql_sql(long_seconds, limit, show_queries);
    let main = client.clone().args(with(&[
        "--batch",
        "--skip-column-names",
        "--connect-timeout=5",
        "-e",
        sql.as_str(),
    ]));
    let (out, seconds) = match run_limited(ctx, clock, main, None).await {
        Ok(done) => done,
        Err(why) => {
            return Ok(Report::unanswered(
                &format!("the server could not be queried: {why}."),
                "",
            ));
        }
    };
    let sections = mysql_sections(&String::from_utf8_lossy(&out.stdout));
    if !sections.contains_key("status") {
        let problem = if out.timed_out {
            format!("the server could not be queried: {name} did not answer within {seconds} s.")
        } else {
            format!("the server could not be queried with {name}.")
        };
        return Ok(Report::unanswered(&problem, &complaint(&out)));
    }

    let mut verdict = Verdict::default();
    let vars = pairs(sections.get("variables"));
    let status = pairs(sections.get("status"));
    let mut body = mysql_server_text(&vars, &status, &mut verdict);
    if !command_ok(&out) {
        body.push_str(&format!("[{name} reported: {}]\n", complaint(&out)));
    }

    // Replication, under the newest spelling first. A server that does not know a
    // statement answers with a syntax error, which is not worth showing: the next
    // spelling is tried. Any other refusal (a missing privilege, a timeout) would be the
    // same under every spelling, and is the answer.
    let mut channels = None;
    let mut refusal = String::new();
    for statement in REPLICATION_STATEMENTS {
        // No --skip-column-names here: in vertical output the names are the keys.
        let cmd = client
            .clone()
            .args(with(&["--batch", "--connect-timeout=5", "-e", statement]));
        match run_limited(ctx, clock, cmd, None).await {
            Ok((out, _)) if command_ok(&out) => {
                channels = Some(parse_replication(&String::from_utf8_lossy(&out.stdout)));
                break;
            }
            Ok((out, _)) => {
                refusal = complaint(&out);
                if !is_syntax_error(&out) {
                    break;
                }
            }
            Err(why) => {
                refusal = why;
                break;
            }
        }
    }
    match &channels {
        Some(channels) => {
            body.push_str(&mysql_replication_text(
                channels,
                show_queries,
                &mut verdict,
            ));
        }
        None => body.push_str(&format!(
            "== replication ==\n[replication status not read: {refusal}]\n"
        )),
    }

    // The marker row of a part is printed before its query runs, so when the client
    // reported a failure an empty part means "no answer", not "nothing found".
    let statements = sections
        .get("statements")
        .filter(|rows| command_ok(&out) || !rows.is_empty());
    body.push_str(&mysql_statements_text(
        statements,
        long_seconds,
        show_queries,
    ));
    verdict.summary.push('.');
    Ok(Report {
        text: format!("{}\n{body}", verdict.line()),
        answered: true,
    })
}

// ---- PostgreSQL -----------------------------------------------------------------------

/// Between the fields of a row, and between the rows of one result, in psql's output.
const FIELD_SEPARATOR: char = '\u{1f}';
const RECORD_SEPARATOR: char = '\u{1e}';

/// What psql prints after the marker of the line that ends a section (see `postgres`).
const END_TAG: &str = "-end ";

/// Splits `psql -A -t` output (fields separated by U+001F, records by U+001E) into the
/// sections of the queries that ANSWERED. `marker` is the first field of a marker row.
///
/// A section starts with a marker row, `MARKER<US>NAME`, and ends with the end line
/// `MARKER-end NAME false`, which psql prints after the section's query (`\echo` with
/// its `ERROR` variable). A section whose end line says `true` belongs to a query that
/// failed (an error, the statement timeout, a refusal); one without an end line was cut
/// off. Neither is in the result.
///
/// AIDEV-NOTE: this is what keeps "the query failed" apart from "the query found
/// nothing". psql carries on after a failed statement and prints nothing for it, so
/// without the end line a failed query for replicas would read as "no replicas", and a
/// failed query for blocked sessions as "nothing is blocked".
///
/// AIDEV-NOTE: values can hold anything, line breaks included (a query's text, a
/// database's name), so the output is not split into lines. A section starts, and ends,
/// only where a record begins with this call's own marker, which carries random digits
/// made for this one call; no value can forge that. psql ends the last record of each
/// result with a line break whatever the record separator is; a record separator there
/// is accepted as well.
pub fn psql_sections(output: &str, marker: &str) -> BTreeMap<String, Rows> {
    let start = format!("{marker}{FIELD_SEPARATOR}");
    let end_line = format!("{marker}{END_TAG}");
    let is_end = |c: char| c == '\n' || c == RECORD_SEPARATOR;
    // Where `needle` begins a record of `text`: at its very start, or right after the
    // end of another record.
    let record_starts = |text: &str, needle: &str| -> Vec<usize> {
        text.match_indices(needle)
            .map(|(at, _)| at)
            .filter(|at| {
                *at == 0
                    || text
                        .get(..*at)
                        .is_some_and(|before| before.ends_with(is_end))
            })
            .collect()
    };
    let begins = record_starts(output, &start);
    let mut sections = BTreeMap::new();
    for (index, at) in begins.iter().enumerate() {
        let until = begins.get(index + 1).copied().unwrap_or(output.len());
        let Some(section) = output.get(at + start.len()..until) else {
            continue;
        };
        let (name, body) = match section.find(is_end) {
            Some(end) => (
                section.get(..end).unwrap_or(""),
                section.get(end + 1..).unwrap_or(""),
            ),
            None => (section, ""),
        };
        // The end line: without it the section was cut off, which is no answer.
        let Some(ends_at) = record_starts(body, &end_line).first().copied() else {
            continue;
        };
        let said = body
            .get(ends_at + end_line.len()..)
            .unwrap_or("")
            .lines()
            .next()
            .unwrap_or("");
        // `NAME false` after a query that worked, `NAME true` after one that failed. A
        // psql older than 10 has no such variable and prints its name: it cannot say, and
        // its sections are taken as answered, as they were before there was an end line.
        if said.split_whitespace().next_back() == Some("true") {
            continue;
        }
        let body = body.get(..ends_at).unwrap_or("");
        let body = body.strip_suffix(is_end).unwrap_or(body);
        let rows: Rows = if body.is_empty() {
            Vec::new()
        } else {
            body.split(RECORD_SEPARATOR)
                .map(|record| record.split(FIELD_SEPARATOR).map(str::to_string).collect())
                .collect()
        };
        sections.insert(name.to_string(), rows);
    }
    sections
}

/// Where the WAL has got to, on a primary or a replica.
const WAL_POSITION: &str = "case when pg_is_in_recovery() then pg_last_wal_replay_lsn() \
                            else pg_current_wal_lsn() end";

/// One part of the PostgreSQL report: the name of its section, how many fields each of
/// its rows has, and the query.
pub struct Part {
    pub name: &'static str,
    pub fields: usize,
    pub sql: String,
}

/// `expr` (text from the server) without the two characters that separate fields and
/// records in psql's output.
///
/// AIDEV-NOTE: a database, a role or an application can be NAMED anything, the two
/// separator characters included, by whoever may create one. Left in, such a name would
/// split into extra fields or extra rows of our report: a made-up database with a
/// frightening transaction ID age, or a real row pushed out of sight. They are removed
/// in the server, before the value is ever printed; rows that still do not have the
/// number of fields their query selects are dropped in `postgres_text`.
fn separator_free(expr: &str) -> String {
    format!("translate({expr}, chr(30) || chr(31), '')")
}

/// The fixed queries of the report, each with the name of its section.
///
/// AIDEV-NOTE: every statement is fixed text. The only values put into it are the two
/// integers, which come from validated integer parameters; nothing a caller writes can
/// become SQL. Each starts with `select` and none changes anything; the session is also
/// opened read-only (see `postgres`).
fn postgres_queries(long_seconds: i64, limit: i64, show_queries: bool) -> Vec<Part> {
    let query = if show_queries {
        separator_free("regexp_replace(left(query, 200), '[[:space:]]+', ' ', 'g')")
    } else {
        "''".to_string()
    };
    let user = separator_free("coalesce(usename, '')");
    let database = separator_free("coalesce(datname, '')");
    let part = |name: &'static str, fields: usize, sql: String| Part { name, fields, sql };
    vec![
        // The last two fields: whether the user this runs as may see everything the
        // other parts ask about (see `postgres_text`), and that user's name.
        part(
            "server",
            8,
            format!(
                "select current_setting('server_version'), \
                 extract(epoch from now() - pg_postmaster_start_time())::bigint, \
                 pg_is_in_recovery(), current_setting('max_connections'), \
                 (select count(*) from pg_stat_activity where backend_type = 'client backend'), \
                 {}, pg_has_role('pg_read_all_stats', 'member'), {}",
                separator_free("coalesce(current_setting('cluster_name', true), '')"),
                separator_free("current_user::text")
            ),
        ),
        part(
            "states",
            2,
            "select coalesce(state, 'unknown'), count(*) from pg_stat_activity \
             where backend_type = 'client backend' group by 1 order by 2 desc"
                .to_string(),
        ),
        part(
            "replicas",
            6,
            format!(
                "select {}, coalesce(host(client_addr), 'local'), state, \
                 sync_state, coalesce(pg_wal_lsn_diff({WAL_POSITION}, replay_lsn), -1)::bigint, \
                 coalesce(extract(epoch from replay_lag), -1)::bigint \
                 from pg_stat_replication order by 1",
                separator_free("application_name")
            ),
        ),
        part(
            "receiver",
            4,
            format!(
                "select coalesce((select status from pg_stat_wal_receiver), 'none'), \
                 coalesce((select {} from pg_stat_wal_receiver), ''), \
                 coalesce(pg_wal_lsn_diff(pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn()), -1)::bigint, \
                 coalesce(extract(epoch from now() - pg_last_xact_replay_timestamp()), -1)::bigint \
                 where pg_is_in_recovery()",
                separator_free("sender_host")
            ),
        ),
        part(
            "slots",
            4,
            format!(
                "select {}, slot_type, active, \
                 coalesce(pg_wal_lsn_diff({WAL_POSITION}, restart_lsn), -1)::bigint \
                 from pg_replication_slots order by 4 desc",
                separator_free("slot_name")
            ),
        ),
        part(
            "long",
            7,
            format!(
                "select pid, {user}, {database}, coalesce(state, ''), \
                 extract(epoch from now() - coalesce(xact_start, query_start))::bigint, \
                 coalesce(wait_event_type || ':' || wait_event, ''), {query} \
                 from pg_stat_activity where backend_type = 'client backend' \
                 and state <> 'idle' and pid <> pg_backend_pid() \
                 and now() - coalesce(xact_start, query_start) >= interval '{long_seconds} seconds' \
                 order by 5 desc limit {limit}"
            ),
        ),
        part(
            "locks",
            1,
            "select count(*) from pg_locks where not granted".to_string(),
        ),
        part(
            "blocked",
            4,
            format!(
                "select pid, array_to_string(pg_blocking_pids(pid), ','), \
                 {user}, {database} from pg_stat_activity \
                 where cardinality(pg_blocking_pids(pid)) > 0 order by 1 limit {limit}"
            ),
        ),
        part(
            "databases",
            2,
            format!(
                "select {}, pg_database_size(datname) from pg_database \
                 where not datistemplate order by 2 desc limit 10",
                separator_free("datname")
            ),
        ),
        part(
            "xid",
            2,
            format!(
                "select {}, age(datfrozenxid) from pg_database order by 2 desc limit 3",
                separator_free("datname")
            ),
        ),
        part(
            "archiver",
            4,
            "select archived_count, failed_count, \
             coalesce(extract(epoch from now() - last_failed_time), -1)::bigint, \
             coalesce(extract(epoch from now() - last_archived_time), -1)::bigint \
             from pg_stat_archiver"
                .to_string(),
        ),
    ]
}

/// What each part of the report is called in a sentence.
fn part_title(name: &str) -> &'static str {
    match name {
        "states" => "connection states",
        "replicas" => "replicas",
        "receiver" => "WAL receiver",
        "slots" => "replication slots",
        "long" => "long transactions",
        "locks" => "lock requests",
        "blocked" => "blocked sessions",
        "databases" => "database sizes",
        "xid" => "transaction ID age",
        "archiver" => "WAL archiving",
        _ => "server",
    }
}

/// A byte count from the server; `None` for the -1 that stands for "not known".
fn bytes_of(text: &str) -> Option<u64> {
    text.trim()
        .parse::<i64>()
        .ok()
        .and_then(|n| u64::try_from(n).ok())
}

/// The whole PostgreSQL report from the sections psql returned. `None` when the server
/// section is missing: the server did not answer.
///
/// AIDEV-NOTE: a section that is not in `sections` is a query that gave NO ANSWER (it
/// failed, or psql was cut off): its part says so and nothing is concluded from it, and
/// the verdict counts such parts. An empty section is a query that found nothing. Keep
/// the two apart in every part below: "no replicas attached" from a failed query would
/// be a false all-clear.
fn postgres_text(
    sections: &BTreeMap<String, Rows>,
    long_seconds: i64,
    show_queries: bool,
) -> Option<String> {
    // Only rows with the number of fields their query selects are used (see
    // `separator_free`): a row that a name full of separators made up, or broke, is
    // dropped and counted.
    let parts = postgres_queries(long_seconds, 1, show_queries);
    let mut malformed = 0usize;
    let mut checked: BTreeMap<&str, Rows> = BTreeMap::new();
    for part in &parts {
        let Some(rows) = sections.get(part.name) else {
            continue;
        };
        let kept: Rows = rows
            .iter()
            .filter(|row| row.len() == part.fields)
            .cloned()
            .collect();
        malformed = malformed.saturating_add(rows.len().saturating_sub(kept.len()));
        checked.insert(part.name, kept);
    }
    let sections = checked;
    let unread: Vec<&str> = parts
        .iter()
        .filter(|part| part.name != "server" && !sections.contains_key(part.name))
        .map(|part| part_title(part.name))
        .collect();

    let server = sections.get("server")?.first()?;
    let mut verdict = Verdict::default();
    if !unread.is_empty() {
        verdict.problems.push(format!(
            "{} of this report could not be read ({})",
            count(unread.len() as u64, "part", "parts"),
            unread.join(", ")
        ));
    }
    // AIDEV-NOTE: found against a real server. To a database user who is neither a
    // superuser nor in pg_read_all_stats (pg_monitor includes it), PostgreSQL shows
    // other users' sessions with every telling column NULL, and replication rows
    // without their state. No query fails: the report would simply say "1 connection",
    // "no long transactions" and "replica pg2 is , not streaming". The server is asked
    // whether this user may see those things, and when it may not the verdict says the
    // report is incomplete instead of drawing conclusions from the gaps.
    let sees_everything = field(server, 6) == "t";
    if !sees_everything {
        verdict.problems.push(format!(
            "the database user {} may not see other sessions or the state of replication, \
             so this report is incomplete (it needs the pg_monitor role)",
            shown(field(server, 7), 60)
        ));
    }
    let version = shown(field(server, 0), 60);
    let uptime = number(field(server, 1)).map(human_duration);
    let replica = field(server, 2) == "t";
    let maximum = number(field(server, 3));
    let connected = number(field(server, 4));
    let cluster_name = field(server, 5);

    let mut text = String::from("== server ==\n");
    text.push_str(&format!("Version: {version}"));
    if !cluster_name.is_empty() {
        text.push_str(&format!("; cluster name: {}", shown(cluster_name, 60)));
    }
    text.push('\n');
    text.push_str(if replica {
        "Role: replica (in recovery)\n"
    } else {
        "Role: primary (not in recovery)\n"
    });
    text.push_str(&format!(
        "Uptime: {}\n",
        uptime.clone().unwrap_or_else(|| "unknown".to_string())
    ));
    let connections = match (connected, maximum) {
        (Some(connected), Some(maximum)) => {
            let share = percent(connected, maximum);
            if connected.saturating_mul(100) > maximum.saturating_mul(CONNECTIONS_PROBLEM_PERCENT) {
                verdict
                    .problems
                    .push(format!("connections are at {share}% of the maximum"));
            }
            format!("{connected} of {maximum} ({share}%)")
        }
        _ => "unknown".to_string(),
    };
    text.push_str(&format!("Connections: {connections}"));
    match sections.get("states") {
        Some(states) if !states.is_empty() => {
            let listed: Vec<String> = states
                .iter()
                .map(|row| format!("{} {}", shown(field(row, 0), 40), shown(field(row, 1), 12)))
                .collect();
            text.push_str(&format!(": {}\n", listed.join(", ")));
        }
        Some(_) => text.push('\n'),
        None => text.push_str("\n[connections by state: no answer]\n"),
    }

    // replication, as a sender
    //
    // AIDEV-NOTE: pg_stat_replication lists every WAL sender, and not every sender
    // feeds a replica. A base backup (pg_basebackup, and Patroni building a new
    // replica) shows up in state `backup` for as long as it runs: it is listed as a
    // backup and is not a replica. A replica that has just connected is in `startup`
    // and then `catchup` until it has caught up; that is what joining looks like, so it
    // is counted and named as catching up, and is not a fault. (How far behind it is
    // still is judged, below.)
    let mut following = String::new();
    match sections.get("replicas") {
        Some(rows) => {
            let (backups, senders): (Vec<&Vec<String>>, Vec<&Vec<String>>) =
                rows.iter().partition(|row| field(row, 2) == "backup");
            let catching_up = |state: &str| matches!(state, "startup" | "catchup");
            if !senders.is_empty() {
                text.push_str("== replicas of this server ==\n");
                let mut table = Rows::new();
                for row in &senders {
                    let name = shown(field(row, 0), 60);
                    let state = field(row, 2);
                    let lag = bytes_of(field(row, 4));
                    // An empty state is one this database user may not see (above).
                    if state != "streaming" && !catching_up(state) && !state.is_empty() {
                        verdict.problems.push(format!(
                            "replica {name} is {}, not streaming",
                            shown(state, 40)
                        ));
                    }
                    if let Some(lag) = lag
                        && lag > LAG_PROBLEM_MB * 1024 * 1024
                    {
                        verdict
                            .problems
                            .push(format!("replica {name} is {} behind", human_bytes(lag)));
                    }
                    table.push(vec![
                        name,
                        shown(field(row, 1), 60),
                        if catching_up(state) {
                            format!("{} (catching up)", shown(state, 40))
                        } else if state.is_empty() {
                            "(hidden)".to_string()
                        } else {
                            shown(state, 40)
                        },
                        shown(field(row, 3), 20),
                        lag.map(human_bytes)
                            .unwrap_or_else(|| "unknown".to_string()),
                        bytes_of(field(row, 5))
                            .map(human_duration)
                            .unwrap_or_else(|| "-".to_string()),
                    ]);
                }
                text.push_str(&format_table(
                    &["NAME", "CLIENT", "STATE", "SYNC", "BEHIND", "REPLAY DELAY"],
                    &table,
                    &[false, false, false, false, true, true],
                ));
                let streaming = senders
                    .iter()
                    .filter(|row| field(row, 2) == "streaming")
                    .count();
                let joining = senders
                    .iter()
                    .filter(|row| catching_up(field(row, 2)))
                    .count();
                let hidden = senders
                    .iter()
                    .filter(|row| field(row, 2).is_empty())
                    .count();
                following = if hidden == senders.len() {
                    format!(
                        "{} attached, state hidden",
                        count(senders.len() as u64, "WAL sender", "WAL senders")
                    )
                } else if streaming == senders.len() {
                    format!(
                        "{} streaming",
                        count(senders.len() as u64, "replica", "replicas")
                    )
                } else {
                    format!("{streaming} of {} replicas streaming", senders.len())
                };
                if joining > 0 {
                    following.push_str(&format!(", {joining} catching up"));
                }
            } else if !replica {
                text.push_str("Replicas: none attached\n");
                following = "no replicas attached".to_string();
            }
            if !backups.is_empty() {
                let listed: Vec<String> = backups
                    .iter()
                    .map(|row| {
                        format!(
                            "{} from {}",
                            shown(field(row, 0), 60),
                            shown(field(row, 1), 60)
                        )
                    })
                    .collect();
                text.push_str(&format!(
                    "Base backups in progress: {}\n",
                    listed.join(", ")
                ));
            }
        }
        None => text.push_str("[replicas of this server: no answer]\n"),
    }

    // replication, as a receiver
    if replica {
        match sections.get("receiver").and_then(|rows| rows.first()) {
            Some(row) => {
                let status = field(row, 0);
                let sender = field(row, 1);
                let from = if sender.is_empty() {
                    String::new()
                } else {
                    format!(" from {}", shown(sender, VALUE_MAX))
                };
                text.push_str("== this replica ==\n");
                text.push_str(&format!("WAL receiver: {}{from}\n", shown(status, 40)));
                if status != "streaming" {
                    verdict.problems.push(format!(
                        "this replica is not streaming from its primary (WAL receiver: {})",
                        shown(status, 40)
                    ));
                }
                if let Some(gap) = bytes_of(field(row, 2)) {
                    text.push_str(&format!(
                        "Received but not yet replayed: {}\n",
                        human_bytes(gap)
                    ));
                    if gap > LAG_PROBLEM_MB * 1024 * 1024 {
                        verdict.problems.push(format!(
                            "replay is {} behind what has been received",
                            human_bytes(gap)
                        ));
                    }
                }
                if let Some(age) = bytes_of(field(row, 3)) {
                    text.push_str(&format!(
                        "Last replayed transaction: {} ago (this grows while the primary is idle)\n",
                        human_duration(age)
                    ));
                }
                let mine = format!("{}{from}", shown(status, 40));
                following = if following.is_empty() {
                    mine
                } else {
                    format!("{mine}; {following}")
                };
            }
            None => text.push_str("[this replica's WAL receiver: no answer]\n"),
        }
    }

    // replication slots
    match sections.get("slots") {
        Some(rows) if !rows.is_empty() => {
            text.push_str("== replication slots ==\n");
            let mut table = Rows::new();
            for row in rows {
                let name = shown(field(row, 0), 60);
                let active = field(row, 2) == "t";
                let retained = bytes_of(field(row, 3));
                if !active
                    && let Some(retained) = retained
                    && retained > SLOT_PROBLEM_BYTES
                {
                    verdict.problems.push(format!(
                        "the inactive replication slot {name} holds back {} of WAL",
                        human_bytes(retained)
                    ));
                }
                table.push(vec![
                    name,
                    shown(field(row, 1), 20),
                    if active { "yes" } else { "NO" }.to_string(),
                    retained
                        .map(human_bytes)
                        .unwrap_or_else(|| "unknown".to_string()),
                ]);
            }
            text.push_str(&format_table(
                &["SLOT", "TYPE", "ACTIVE", "WAL HELD BACK"],
                &table,
                &[false, false, false, true],
            ));
        }
        Some(_) => text.push_str("Replication slots: none\n"),
        None => text.push_str("[replication slots: no answer]\n"),
    }

    // long transactions
    match sections.get("long") {
        Some(rows) if !rows.is_empty() => {
            text.push_str(&format!(
                "== transactions running for {long_seconds} s or more ==\n"
            ));
            let table: Rows = rows
                .iter()
                .map(|row| {
                    vec![
                        shown(field(row, 0), 12),
                        shown(field(row, 1), 40),
                        shown(field(row, 2), 40),
                        shown(field(row, 3), 40),
                        shown(field(row, 4), 12),
                        shown(field(row, 5), 60),
                        query_cell(show_queries, field(row, 6)),
                    ]
                })
                .collect();
            text.push_str(&format_table(
                &[
                    "PID",
                    "USER",
                    "DATABASE",
                    "STATE",
                    "SECONDS",
                    "WAITING ON",
                    "QUERY",
                ],
                &table,
                &[true, false, false, false, true, false, false],
            ));
            if !show_queries {
                text.push_str(HIDDEN_NOTE);
            }
        }
        Some(_) => text.push_str(&format!(
            "No transaction has been running for {long_seconds} s or more.\n"
        )),
        None => text.push_str("[long transactions: no answer]\n"),
    }

    // locks
    match sections.get("locks").and_then(|rows| rows.first()) {
        Some(waiting) => text.push_str(&format!(
            "Lock requests waiting: {}\n",
            shown(field(waiting, 0), 12)
        )),
        None => text.push_str("[lock requests: no answer]\n"),
    }
    match sections.get("blocked") {
        Some(rows) if !rows.is_empty() => {
            verdict.problems.push(format!(
                "{} blocked by locks",
                count(rows.len() as u64, "session is", "sessions are")
            ));
            for row in rows {
                text.push_str(&format!(
                    "  pid {} ({} on {}) is blocked by {}\n",
                    shown(field(row, 0), 12),
                    shown(field(row, 2), 40),
                    shown(field(row, 3), 40),
                    shown(field(row, 1), 120),
                ));
            }
        }
        Some(_) => {}
        None => text.push_str("[blocked sessions: no answer]\n"),
    }

    // sizes and transaction ID age
    match sections.get("databases") {
        Some(rows) if !rows.is_empty() => {
            text.push_str("== largest databases ==\n");
            let table: Rows = rows
                .iter()
                .map(|row| {
                    vec![
                        shown(field(row, 0), 60),
                        bytes_of(field(row, 1))
                            .map(human_bytes)
                            .unwrap_or_else(|| "unknown".to_string()),
                    ]
                })
                .collect();
            text.push_str(&format_rows(&table, &[false, true]));
        }
        _ => text.push_str("[database sizes: no answer]\n"),
    }
    match sections.get("xid") {
        Some(rows) if !rows.is_empty() => {
            text.push_str(
                "== oldest transaction IDs (the server stops taking writes near 2 billion) ==\n",
            );
            let mut table = Rows::new();
            for row in rows {
                let name = shown(field(row, 0), 60);
                if let Some(age) = number(field(row, 1))
                    && age > XID_PROBLEM_AGE
                {
                    verdict
                        .problems
                        .push(format!("the transaction ID age of {name} is {age}"));
                }
                table.push(vec![name, shown(field(row, 1), 20)]);
            }
            text.push_str(&format_rows(&table, &[false, true]));
        }
        _ => text.push_str("[transaction ID age: no answer]\n"),
    }

    // archiving
    match sections.get("archiver").and_then(|rows| rows.first()) {
        Some(row) => {
            let failed = number(field(row, 1)).unwrap_or(0);
            let last_failed = bytes_of(field(row, 2));
            let last_archived = bytes_of(field(row, 3));
            text.push_str(&format!(
                "WAL archiving: {} segments archived, {}",
                shown(field(row, 0), 20),
                count(failed, "failure", "failures"),
            ));
            if let Some(age) = last_failed {
                text.push_str(&format!("; last failure {} ago", human_duration(age)));
            }
            if let Some(age) = last_archived {
                text.push_str(&format!("; last success {} ago", human_duration(age)));
            }
            text.push('\n');
            // Failing now: the newest attempt failed (no success since).
            let failing = match (last_failed, last_archived) {
                (Some(failed_ago), Some(archived_ago)) => failed_ago < archived_ago,
                (Some(_), None) => true,
                _ => false,
            };
            if failing {
                verdict
                    .problems
                    .push("WAL archiving is failing".to_string());
            }
        }
        None => text.push_str("WAL archiving: no answer\n"),
    }

    verdict.summary = format!(
        "PostgreSQL {version} {}, up {}; connections {connections}",
        if replica { "replica" } else { "primary" },
        uptime.unwrap_or_else(|| "unknown".to_string()),
    );
    if !following.is_empty() {
        verdict.summary.push_str(&format!("; {following}"));
    }
    verdict.summary.push('.');
    if malformed > 0 {
        text.push_str(&format!(
            "[{} with an unexpected number of fields {} left out: a name on the server \
             holds a character that separates fields]\n",
            count(malformed as u64, "record", "records"),
            if malformed == 1 { "was" } else { "were" }
        ));
    }
    Some(format!("{}\n{text}", verdict.line()))
}

/// The user psql runs as, and the environment that goes with it.
struct Identity {
    run_as: RunAs,
    environment: Vec<(String, String)>,
}

/// Who psql runs as when the server is root: the database's own Unix user, so that peer
/// authentication lets it in. `None` when it runs as the server's own user.
fn postgres_identity(ctx: &Ctx) -> Result<Option<Identity>, ToolError> {
    let euid = rustix::process::geteuid();
    if !euid.is_root() {
        return Ok(None);
    }
    let name = &ctx.cfg().db.postgres_user;
    let account = User::from_name(name).ok().flatten().ok_or_else(|| {
        ToolError::Failed(format!(
            "the user {name}, which psql is set to run as (db.postgres_user), does not exist"
        ))
    })?;
    if account.uid.as_raw() == euid.as_raw() {
        return Ok(None);
    }
    let environment = vec![
        (
            "HOME".to_string(),
            account.dir.to_string_lossy().into_owned(),
        ),
        ("USER".to_string(), account.name.clone()),
        ("LOGNAME".to_string(), account.name.clone()),
    ];
    Ok(Some(Identity {
        run_as: RunAs {
            uid: account.uid.as_raw(),
            gid: account.gid.as_raw(),
        },
        environment,
    }))
}

async fn postgres(
    ctx: &Ctx,
    clock: &CallClock,
    long_seconds: i64,
    limit: i64,
) -> Result<Report, ToolError> {
    let mut cmd = ctx.command("psql")?;
    let show_queries = ctx.cfg().db.show_queries;

    // The marker of this call's section rows: random, so that no value can forge one.
    let mut random = [0u8; 16];
    getrandom::fill(&mut random)
        .map_err(|e| ToolError::Failed(format!("cannot get random bytes: {e}")))?;
    let digits: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let marker = format!("#opsmcp-{digits}");

    // AIDEV-NOTE: -X: no startup file; --no-password: fail rather than wait for a
    // password; one connection for the whole report, so a server near its connection
    // limit is asked once. ON_ERROR_STOP is deliberately not set: a query that an older
    // server does not know, or that runs into the statement timeout, must not take the
    // parts after it away. psql then exits 0 all the same, so each query is followed by
    // a line in which psql says whether it failed; a failed query's part is reported as
    // "no answer", counted in the verdict, and what psql said about it is shown.
    let mut args: Vec<String> = vec![
        "-X".to_string(),
        "-A".to_string(),
        "-t".to_string(),
        "-F".to_string(),
        FIELD_SEPARATOR.to_string(),
        "-R".to_string(),
        RECORD_SEPARATOR.to_string(),
        "--no-password".to_string(),
        "-d".to_string(),
        "postgres".to_string(),
    ];
    if let Some(dir) = &ctx.cfg().db.postgres_socket_dir {
        args.push("-h".to_string());
        args.push(dir.display().to_string());
    }
    for part in postgres_queries(long_seconds, limit, show_queries) {
        args.push("-c".to_string());
        args.push(format!("select '{marker}', '{}'", part.name));
        args.push("-c".to_string());
        args.push(part.sql);
        // psql's own word on whether that query failed (see `psql_sections`). ERROR is
        // a variable psql sets after every query; a backslash command may be given to
        // -c by itself, and this one prints `MARKER-end NAME false` (or `true`).
        args.push("-c".to_string());
        args.push(format!("\\echo {marker}{END_TAG}{} :ERROR", part.name));
    }
    cmd = cmd.args(args);
    // AIDEV-NOTE: belt and braces. The queries only read, and the session is told to
    // refuse anything else and to give up on any statement after five seconds.
    cmd.env.extend([
        (
            "PGOPTIONS".to_string(),
            "-c statement_timeout=5000 -c default_transaction_read_only=on".to_string(),
        ),
        ("PGCONNECT_TIMEOUT".to_string(), "5".to_string()),
        ("PGAPPNAME".to_string(), "opsmcp".to_string()),
    ]);
    if let Some(identity) = postgres_identity(ctx)? {
        cmd.run_as = Some(identity.run_as);
        cmd.env.extend(identity.environment);
    }

    let (out, seconds) = match run_limited(ctx, clock, cmd, None).await {
        Ok(done) => done,
        Err(why) => {
            return Ok(Report::unanswered(
                &format!("the server could not be queried: {why}."),
                "",
            ));
        }
    };
    let sections = psql_sections(&String::from_utf8_lossy(&out.stdout), &marker);
    let Some(mut text) = postgres_text(&sections, long_seconds, show_queries) else {
        let problem = if out.timed_out {
            format!("the server could not be queried: psql did not answer within {seconds} s.")
        } else {
            "the server could not be queried with psql.".to_string()
        };
        return Ok(Report::unanswered(&problem, &complaint(&out)));
    };
    if out.timed_out || !out.stderr.iter().all(u8::is_ascii_whitespace) {
        text.push_str(&format!("[psql reported: {}]\n", complaint(&out)));
    }
    Ok(Report {
        text,
        answered: true,
    })
}

// ---- Patroni --------------------------------------------------------------------------

/// How far a Patroni member is behind the leader.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lag {
    /// The leader: there is nothing to be behind.
    NotApplicable,
    /// Patroni does not say, or says "unknown".
    Unknown,
    Megabytes(u64),
}

/// One member of a Patroni cluster, from `patronictl list --format json`.
#[derive(Debug, PartialEq, Eq)]
pub struct Member {
    pub cluster: String,
    pub name: String,
    pub host: String,
    pub role: String,
    pub state: String,
    pub timeline: Option<u64>,
    pub lag: Lag,
    pub pending_restart: bool,
    /// Tags and the reason for a pending restart, for the notes column.
    pub notes: String,
}

/// How a member's state is to be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Health {
    /// Serving, as a leader or a replica.
    Up,
    /// On its way up: being built, started or restarted. Not a fault, and not yet a
    /// member that can be counted on.
    InProgress,
    /// Anything else, an empty or unheard-of state included.
    Down,
}

impl Member {
    pub fn is_leader(&self) -> bool {
        let role = self.role.to_ascii_lowercase();
        role == "leader" || role == "standby leader"
    }

    /// Reads the state Patroni reports for the member.
    ///
    /// AIDEV-NOTE: the list of healthy and in-progress states is closed on purpose: a
    /// state this code has never heard of counts as down. `in archive recovery` is how a
    /// replica that restores from the WAL archive (no streaming connection) looks when
    /// all is well. The in-progress states are what a member passes through while
    /// Patroni builds or (re)starts it; calling those a PROBLEM made every replica
    /// rebuild and every rolling restart look like a failure.
    pub fn health(&self) -> Health {
        match self.state.as_str() {
            "running" | "streaming" | "in archive recovery" => Health::Up,
            "starting"
            | "restarting"
            | "creating replica"
            | "running custom bootstrap script"
            | "initializing new cluster" => Health::InProgress,
            _ => Health::Down,
        }
    }

    fn is_up(&self) -> bool {
        self.health() == Health::Up
    }
}

/// A whole number from a JSON number or a string of digits. Anything else is `None`.
fn whole(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64().or_else(|| {
            number
                .as_f64()
                .filter(|float| float.is_finite() && *float >= 0.0 && *float < 1e15)
                .map(|float| float.round() as u64)
        }),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

fn text_of(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

/// The names Patroni has given a member's lag: one figure up to 4.0, receive and replay
/// figures from 4.1 on. All are in MB.
const LAG_KEYS: [&str; 4] = ["Lag in MB", "Replay Lag", "Receive Lag", "Lag"];

/// Reads `patronictl list --format json`: an array with one object per member. Patroni
/// leaves out the keys whose value is empty.
///
/// AIDEV-NOTE: a lag or a timeline that is missing, empty or not a number is UNKNOWN. It
/// must never be read as zero: "0 MB behind" for a stopped member would hide the very
/// thing this report is for. Patroni 4.1 gives two lags (received, replayed): when
/// either of them is not a number the member's lag is unknown, whatever the other says.
pub fn parse_members(json: &str) -> Result<Vec<Member>, String> {
    let parsed: Value = serde_json::from_str(json.trim()).map_err(|e| format!("not JSON ({e})"))?;
    let Value::Array(items) = parsed else {
        return Err("not a list of members".to_string());
    };
    let mut members = Vec::with_capacity(items.len());
    for item in &items {
        let Value::Object(fields) = item else {
            return Err("not a list of members".to_string());
        };
        let name = text_of(fields.get("Member"));
        if name.is_empty() {
            return Err("a member without a name".to_string());
        }
        let role = text_of(fields.get("Role"));
        let leader = {
            let role = role.to_ascii_lowercase();
            role == "leader" || role == "standby leader"
        };
        let given: Vec<Option<u64>> = LAG_KEYS
            .iter()
            .filter_map(|key| fields.get(*key))
            .map(whole)
            .collect();
        let lag = if given.is_empty() {
            match leader {
                true => Lag::NotApplicable,
                false => Lag::Unknown,
            }
        } else if given.iter().any(Option::is_none) {
            Lag::Unknown
        } else {
            match given.iter().flatten().max() {
                Some(megabytes) => Lag::Megabytes(*megabytes),
                None => Lag::Unknown,
            }
        };
        let pending_restart = match fields.get("Pending restart") {
            Some(Value::Bool(pending)) => *pending,
            Some(Value::String(mark)) => !mark.trim().is_empty(),
            _ => false,
        };
        let mut notes = Vec::new();
        let reason = text_of(fields.get("Pending restart reason"));
        if !reason.trim().is_empty() {
            notes.push(format!("restart pending for {}", reason.trim()));
        }
        let scheduled = text_of(fields.get("Scheduled restart"));
        if !scheduled.trim().is_empty() {
            notes.push(format!("restart scheduled {}", scheduled.trim()));
        }
        match fields.get("Tags") {
            None | Some(Value::Null) => {}
            Some(Value::String(tags)) if tags.trim().is_empty() => {}
            Some(tags) => notes.push(format!("tags {}", text_of(Some(tags)))),
        }
        members.push(Member {
            cluster: text_of(fields.get("Cluster")),
            name,
            host: text_of(fields.get("Host")),
            role,
            state: text_of(fields.get("State")),
            timeline: fields.get("TL").and_then(whole),
            lag,
            pending_restart,
            notes: notes.join("; "),
        });
    }
    Ok(members)
}

/// Whether the Patroni member `member` is this machine, whose host name is `hostname`:
/// the same name, or one of them is the other's first label (a member named in full on
/// a machine that knows only its short name, or the reverse).
pub fn is_this_node(member: &str, hostname: &str) -> bool {
    let member = member.trim().to_ascii_lowercase();
    let hostname = hostname.trim().to_ascii_lowercase();
    if member.is_empty() || hostname.is_empty() {
        return false;
    }
    let first = |name: &str| name.split('.').next().unwrap_or("").to_string();
    member == hostname || first(&member) == hostname || member == first(&hostname)
}

/// What matters to a status report in Patroni's dynamic configuration.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Dynamic {
    pub paused: bool,
    pub synchronous_mode: Option<String>,
}

/// Picks the top-level `pause:` and `synchronous_mode:` lines out of `patronictl
/// show-config` output. Nothing else is looked at.
///
/// AIDEV-NOTE: the dynamic configuration can hold passwords (in `postgresql.parameters`
/// or a standby cluster's connection settings). It is scanned for these two keys at the
/// start of a line and nothing of it is ever shown.
pub fn scan_dynamic_config(text: &str) -> Dynamic {
    let mut found = Dynamic::default();
    for line in text.lines() {
        // Top level only: YAML nests by indentation.
        if line.starts_with([' ', '\t', '-', '#']) {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim().trim_matches(['"', '\'']);
        match key.trim() {
            "pause" => {
                found.paused = matches!(value.to_ascii_lowercase().as_str(), "true" | "yes" | "on");
            }
            "synchronous_mode" => {
                let plain = value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
                let off = matches!(
                    value.to_ascii_lowercase().as_str(),
                    "" | "false" | "no" | "off" | "null" | "~"
                );
                if plain && !off {
                    found.synchronous_mode = Some(match value.to_ascii_lowercase().as_str() {
                        "true" | "yes" | "on" => "on".to_string(),
                        _ => value.to_string(),
                    });
                }
            }
            _ => {}
        }
    }
    found
}

/// One change of leader, from `patronictl history --format json`.
#[derive(Debug, PartialEq, Eq)]
pub struct LeaderChange {
    pub timeline: String,
    pub time: String,
    pub reason: String,
    pub new_leader: String,
}

pub fn parse_history(json: &str) -> Result<Vec<LeaderChange>, String> {
    let parsed: Value = serde_json::from_str(json.trim()).map_err(|e| format!("not JSON ({e})"))?;
    let Value::Array(items) = parsed else {
        return Err("not a list".to_string());
    };
    Ok(items
        .iter()
        .filter_map(|item| {
            let fields = item.as_object()?;
            Some(LeaderChange {
                timeline: text_of(fields.get("TL")),
                time: text_of(fields.get("Timestamp")),
                reason: text_of(fields.get("Reason")),
                new_leader: text_of(fields.get("New Leader")),
            })
        })
        .collect())
}

/// The verdict and the member table.
fn members_text(members: &[Member], hostname: &str, verdict: &mut Verdict) -> String {
    let cluster = members
        .first()
        .map(|member| shown(&member.cluster, 60))
        .unwrap_or_default();
    let leader = members.iter().find(|member| member.is_leader());
    let followers: Vec<&Member> = members
        .iter()
        .filter(|member| !member.is_leader())
        .collect();

    if members.is_empty() {
        verdict
            .problems
            .push("patronictl lists no members".to_string());
    } else if leader.is_none() {
        verdict
            .problems
            .push("the cluster has no leader".to_string());
    } else if followers.is_empty() {
        // AIDEV-NOTE: a member whose Patroni has stopped leaves this list once its key
        // expires, so a cluster that lost its replicas looks like a healthy cluster of
        // one. Patroni exists to fail over; with nothing to fail over to, say so.
        verdict
            .problems
            .push("the cluster has no replica: there is nothing to fail over to".to_string());
    }
    // Members on their way up: named in the summary, not problems.
    let mut in_progress = Vec::new();
    for member in members {
        let name = shown(&member.name, 60);
        match member.health() {
            Health::Up => {}
            Health::InProgress => {
                in_progress.push(format!("{name} is {}", shown(&member.state, 40)));
            }
            Health::Down => verdict.problems.push(format!(
                "{name} is {}",
                if member.state.is_empty() {
                    "in an unknown state".to_string()
                } else {
                    shown(&member.state, 40)
                }
            )),
        }
        if let Lag::Megabytes(megabytes) = member.lag
            && megabytes > LAG_PROBLEM_MB
        {
            verdict
                .problems
                .push(format!("{name} is {megabytes} MB behind"));
        }
        if member.pending_restart {
            verdict
                .problems
                .push(format!("{name} has a pending restart"));
        }
    }
    let timelines: Vec<(&Member, u64)> = members
        .iter()
        .filter_map(|member| Some((member, member.timeline?)))
        .collect();
    if timelines
        .iter()
        .any(|(_, timeline)| Some(*timeline) != timelines.first().map(|(_, first)| *first))
    {
        let listed: Vec<String> = timelines
            .iter()
            .take(8)
            .map(|(member, timeline)| format!("{} on {timeline}", shown(&member.name, 60)))
            .collect();
        verdict.problems.push(format!(
            "members are on different timelines ({})",
            listed.join(", ")
        ));
    }

    // the summary
    let leading = match leader {
        Some(leader) => format!(
            "leader {}{}",
            shown(&leader.name, 60),
            match leader.timeline {
                Some(timeline) => format!(" (timeline {timeline})"),
                None => String::new(),
            }
        ),
        None => "NO LEADER".to_string(),
    };
    let following = if followers.is_empty() {
        "no replicas".to_string()
    } else {
        let up = followers.iter().filter(|member| member.is_up()).count();
        // Older Patroni shows a healthy replica as "running", newer as "streaming".
        let word = if followers
            .iter()
            .filter(|member| member.is_up())
            .all(|member| member.state == "streaming")
        {
            "streaming"
        } else {
            "running"
        };
        let known: Vec<u64> = followers
            .iter()
            .filter_map(|member| match member.lag {
                Lag::Megabytes(megabytes) => Some(megabytes),
                _ => None,
            })
            .collect();
        let lag = match known.iter().max() {
            Some(largest) if followers.len() == 1 => format!("lag {largest} MB"),
            Some(largest) if known.len() == followers.len() => {
                format!("largest lag {largest} MB")
            }
            Some(largest) => format!("largest known lag {largest} MB"),
            None => "lag unknown".to_string(),
        };
        let counted = if up == followers.len() {
            format!("{} {word}", count(up as u64, "replica", "replicas"))
        } else {
            format!("{up} of {} replicas {word}", followers.len())
        };
        format!("{counted}, {lag}")
    };
    verdict.summary = format!("Cluster {cluster}: {leading}; {following}");
    for note in in_progress.iter().take(8) {
        verdict.summary.push_str(&format!("; {note}"));
    }
    verdict.summary.push('.');

    // the table
    let mut text = String::from("== members ==\n");
    let rows: Rows = members
        .iter()
        .map(|member| {
            let mut name = shown(&member.name, 60);
            if is_this_node(&member.name, hostname) {
                name.push_str(" (this node)");
            }
            let mut notes = Vec::new();
            if member.pending_restart {
                notes.push("PENDING RESTART".to_string());
            }
            if !member.notes.is_empty() {
                notes.push(shown(&redact_text(&member.notes), 200));
            }
            vec![
                name,
                shown(&member.host, 60),
                shown(&member.role, 30),
                shown(&member.state, 40),
                member
                    .timeline
                    .map(|timeline| timeline.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                match member.lag {
                    Lag::NotApplicable => "-".to_string(),
                    Lag::Unknown => "unknown".to_string(),
                    Lag::Megabytes(megabytes) => format!("{megabytes} MB"),
                },
                notes.join("; "),
            ]
        })
        .collect();
    text.push_str(&format_table(
        &[
            "MEMBER", "HOST", "ROLE", "STATE", "TIMELINE", "LAG", "NOTES",
        ],
        &rows,
        &[false, false, false, false, true, true, false],
    ));
    text
}

/// Patroni's own state on this node, from systemd.
async fn patroni_unit_text(ctx: &Ctx, clock: &CallClock, verdict: &mut Verdict) -> String {
    // AIDEV-NOTE: a member whose Patroni has died stays listed (as streaming, even)
    // until its key in the DCS expires. For THIS node systemd knows at once, so it is
    // asked as well; nothing more is claimed about the other members than patronictl says.
    let Ok(Some(systemctl)) = ctx.optional_command("systemctl") else {
        return String::new();
    };
    let cmd = systemctl.args([
        "show",
        "--property=LoadState",
        "--property=ActiveState",
        "--property=SubState",
        "--",
        "patroni.service",
    ]);
    let out = match run_limited(ctx, clock, cmd, Some(10)).await {
        Ok((out, _)) if command_ok(&out) => out,
        Ok((out, _)) => {
            return format!(
                "== this node ==\n[patroni.service not checked: {}]\n",
                complaint(&out)
            );
        }
        Err(why) => return format!("== this node ==\n[patroni.service not checked: {why}]\n"),
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let property = |name: &str| {
        stdout
            .lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix('='))
            .unwrap_or("")
            .trim()
            .to_string()
    };
    let (load, active, sub) = (
        property("LoadState"),
        property("ActiveState"),
        property("SubState"),
    );
    if load == "not-found" {
        return "== this node ==\n[there is no patroni.service unit on this node: whether \
                Patroni runs here was not checked]\n"
            .to_string();
    }
    if active != "active" {
        verdict.problems.push(format!(
            "Patroni is {} on this node",
            if active.is_empty() {
                "in an unknown state".to_string()
            } else {
                shown(&active, 20)
            }
        ));
    }
    format!(
        "== this node ==\npatroni.service: {} ({})\n",
        shown(&active, 20),
        shown(&sub, 20)
    )
}

/// The health of the etcd cluster behind Patroni, when etcdctl is there to ask.
async fn etcd_text(ctx: &Ctx, clock: &CallClock) -> String {
    let Ok(Some(etcdctl)) = ctx.optional_command("etcdctl") else {
        return String::new();
    };
    let mut cmd = etcdctl.args(["endpoint", "health", "--cluster"]);
    cmd.env.push(("ETCDCTL_API".to_string(), "3".to_string()));
    match run_limited(ctx, clock, cmd, Some(10)).await {
        // etcd 3.4 prints the result on stderr, 3.5 on stdout: both are shown.
        Ok((out, _)) => {
            let (said, _) = keep_head(&redact_text(&command_text(&out)), 4096);
            format!("== etcd ==\n{said}")
        }
        Err(why) => format!("== etcd ==\n[etcd not asked: {why}]\n"),
    }
}

async fn patroni(ctx: &Ctx, clock: &CallClock, env: &Arc<Env>) -> Result<Report, ToolError> {
    // AIDEV-NOTE: the configuration file belongs to patronictl. opsmcp passes its path
    // and never opens it: it can hold the superuser's and the replication passwords.
    //
    // AIDEV-NOTE: unlike the MariaDB client options file, this file is NOT required to
    // be root's alone, although patronictl is run as root: it normally belongs to the
    // postgres user, and requiring otherwise would rule out every usual installation.
    // What its owner can do with that: point patronictl at a DCS of their own choosing
    // (and at certificates of their choosing), and so make this report say whatever
    // they like about the cluster. What they cannot do through it: have code run.
    // patronictl takes connection settings from the file; `list`, `show-config` and
    // `history` only read the DCS, and nothing in the file names a program or a module
    // for them to load. Whoever owns that file already controls the database it
    // describes, so a report they can falsify tells them nothing new and gives them no
    // new power; an agent reading it should still know whose word it is.
    let config = match &ctx.cfg().db.patroni_config {
        Some(file) => file.clone(),
        None => {
            let candidates = env.patroni_configs.clone();
            let found = blocking(ctx.clone(), move || {
                Ok(candidates.into_iter().find(|file| file.is_file()))
            })
            .await?;
            let Some(file) = found else {
                let tried: Vec<String> = env
                    .patroni_configs
                    .iter()
                    .map(|file| file.display().to_string())
                    .collect();
                return Err(ToolError::Failed(format!(
                    "no Patroni configuration file was found (looked for {}); set \
                     db.patroni_config",
                    tried.join(", ")
                )));
            };
            file
        }
    };
    let config = config.display().to_string();
    let hostname_file = env.hostname.clone();
    let hostname = blocking(ctx.clone(), move || {
        Ok(std::fs::read_to_string(hostname_file).unwrap_or_default())
    })
    .await?;

    let patronictl = {
        let mut cmd = ctx.command("patronictl")?;
        // patronictl is a Python program: have it write UTF-8 whatever the names hold.
        cmd.env.extend([
            ("LC_ALL".to_string(), "C.UTF-8".to_string()),
            ("LANG".to_string(), "C.UTF-8".to_string()),
        ]);
        cmd
    };
    let ctl = |extra: &[&str]| {
        let mut args = vec!["-c".to_string(), config.clone()];
        args.extend(extra.iter().map(|arg| arg.to_string()));
        patronictl.clone().args(args)
    };

    let mut verdict = Verdict::default();

    // The members. AIDEV-NOTE: when the DCS (etcd) is unreachable patronictl does not
    // fail: it retries for many minutes. So every patronictl call has its own time
    // limit, and one that runs into it is reported as exactly that, at once, instead of
    // the call ending with nothing. The other patronictl commands would hang the same
    // way and are not started.
    let wait = Some(PATRONICTL_WAIT_SECS);
    let listed = run_limited(ctx, clock, ctl(&["list", "--format=json"]), wait).await;
    let failure = match &listed {
        Err(why) => Some((format!("patronictl was not run: {why}."), String::new())),
        Ok((out, seconds)) if out.timed_out => Some((
            format!(
                "patronictl did not answer within {seconds} s; the DCS (etcd) is probably unreachable."
            ),
            stderr_tail(out, 5),
        )),
        Ok((out, _)) if !command_ok(out) => Some((
            format!(
                "patronictl list failed ({}).",
                match out.code {
                    Some(code) => format!("exit {code}"),
                    None => "killed".to_string(),
                }
            ),
            format!("{}\n", complaint(out)),
        )),
        Ok(_) => None,
    };
    let members = match (&listed, &failure) {
        (Ok((out, _)), None) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            match parse_members(&stdout) {
                Ok(members) => Some(members),
                Err(why) => {
                    let (head, _) = keep_head(&redact_text(&stdout), 600);
                    let mut report = Report::unanswered(
                        &format!("patronictl's answer was not understood: {why}."),
                        &head,
                    );
                    report
                        .text
                        .push_str(&patroni_unit_text(ctx, clock, &mut Verdict::default()).await);
                    return Ok(report);
                }
            }
        }
        _ => None,
    };
    let Some(members) = members else {
        let (problem, detail) = failure.unwrap_or_default();
        let mut report = Report::unanswered(&problem, &detail);
        // What can still be learned: this node's own service, and the DCS itself.
        report
            .text
            .push_str(&patroni_unit_text(ctx, clock, &mut Verdict::default()).await);
        report.text.push_str(&etcd_text(ctx, clock).await);
        return Ok(report);
    };

    let mut body = members_text(&members, &hostname, &mut verdict);

    // Maintenance mode. patronictl's JSON does not carry it; the dynamic configuration
    // does.
    body.push_str("== cluster settings ==\n");
    // Set when a later patronictl command hangs (the DCS went away after the list was
    // read): the next one would only hang as well.
    let mut hung = false;
    match run_limited(ctx, clock, ctl(&["show-config"]), wait).await {
        Ok((out, _)) if command_ok(&out) => {
            let dynamic = scan_dynamic_config(&String::from_utf8_lossy(&out.stdout));
            if dynamic.paused {
                verdict.problems.push(
                    "the cluster is in maintenance mode (paused), so Patroni will not fail over"
                        .to_string(),
                );
            }
            body.push_str(&format!(
                "Maintenance mode (pause): {}\nSynchronous mode: {}\n",
                if dynamic.paused { "ON" } else { "off" },
                dynamic.synchronous_mode.as_deref().unwrap_or("off"),
            ));
        }
        Ok((out, _)) => {
            hung = out.timed_out;
            body.push_str(&format!(
                "[maintenance mode not checked: {}]\n",
                complaint(&out)
            ));
        }
        Err(why) => body.push_str(&format!("[maintenance mode not checked: {why}]\n")),
    }

    // Leader changes.
    let history = if hung {
        Err("patronictl has stopped answering".to_string())
    } else {
        run_limited(ctx, clock, ctl(&["history", "--format=json"]), wait).await
    };
    match history {
        Ok((out, _)) if command_ok(&out) => {
            match parse_history(&String::from_utf8_lossy(&out.stdout)) {
                Ok(changes) if changes.is_empty() => {
                    body.push_str("No leader change is recorded.\n");
                }
                Ok(changes) => {
                    body.push_str("== leader changes (the newest last) ==\n");
                    let rows: Rows = changes
                        .iter()
                        .skip(changes.len().saturating_sub(5))
                        .map(|change| {
                            vec![
                                shown(&change.timeline, 12),
                                shown(&change.time, 40),
                                shown(&change.reason, 80),
                                shown(&change.new_leader, 60),
                            ]
                        })
                        .collect();
                    body.push_str(&format_table(
                        &["TIMELINE", "TIME", "REASON", "NEW LEADER"],
                        &rows,
                        &[true, false, false, false],
                    ));
                }
                Err(why) => body.push_str(&format!("[leader changes not read: {why}]\n")),
            }
        }
        Ok((out, _)) => body.push_str(&format!("[leader changes not read: {}]\n", complaint(&out))),
        Err(why) => body.push_str(&format!("[leader changes not read: {why}]\n")),
    }

    body.push_str(&patroni_unit_text(ctx, clock, &mut verdict).await);
    body.push_str(&etcd_text(ctx, clock).await);
    Ok(Report {
        text: format!("{}\n{body}", verdict.line()),
        answered: true,
    })
}

async fn db_status(ctx: Ctx, args: Args, env: Arc<Env>) -> ToolResult {
    let engine = required(&args, "engine")?.to_string();
    let long_seconds = args.int("long_seconds").unwrap_or(60);
    let limit = args.int("limit").unwrap_or(20);
    // The engine is the resource, so a grant can cover one kind of database and not
    // another (`db.view:patroni`).
    let auth = ctx.authorize(Some(&engine))?;
    let clock = CallClock::start(&ctx);
    let report = match engine.as_str() {
        "mariadb" => mariadb(&ctx, &clock, long_seconds, limit).await?,
        "postgres" => postgres(&ctx, &clock, long_seconds, limit).await?,
        "patroni" => patroni(&ctx, &clock, &env).await?,
        other => {
            return Err(ToolError::Invalid(format!(
                "{other:?} is not a database this tool knows"
            )));
        }
    };

    // The verdict and the summary parts come first, so the start is what is kept.
    const NOTE_ROOM: usize = 80;
    let (kept, dropped) = keep_head(&report.text, ctx.output_budget().saturating_sub(NOTE_ROOM));
    let text = if dropped == 0 {
        kept
    } else {
        format!("{kept}[{dropped} more lines left out to fit the output limit]\n")
    };
    // AIDEV-NOTE: a report that names problems is an answer, so it is a success. Only a
    // server (or a patronictl) that could not be asked at all makes the call fail.
    auth.done(text, report.answered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::testing::{FakeBins, call, find, host, ok_text};
    use crate::tools::{Host, ToolError, ToolResult};
    use serde_json::{Value, json};
    use std::fs;
    use std::path::Path;

    fn row(fields: &[&str]) -> Vec<String> {
        fields.iter().map(|f| f.to_string()).collect()
    }

    // ---- parsing ----------------------------------------------------------------------

    #[test]
    fn the_mariadb_output_is_split_at_the_marker_rows() {
        let output = "#opsmcp-section\tvariables\nversion\t10.11.6-MariaDB\nmax_connections\t500\n\
                      #opsmcp-section\tstatus\nUptime\t60\n#opsmcp-section\tstatements\n";
        let sections = mysql_sections(output);
        assert_eq!(
            sections.get("variables"),
            Some(&vec![
                row(&["version", "10.11.6-MariaDB"]),
                row(&["max_connections", "500"])
            ])
        );
        assert_eq!(sections.get("status"), Some(&vec![row(&["Uptime", "60"])]));
        // a section that returned no rows is still known to have been reached
        assert_eq!(sections.get("statements"), Some(&Vec::new()));
        assert_eq!(sections.get("replication"), None);
    }

    #[test]
    fn rows_before_the_first_marker_belong_to_no_section() {
        let sections = mysql_sections("stray\trow\n#opsmcp-section\tstatus\nUptime\t60\n");
        assert_eq!(sections.len(), 1);
        assert_eq!(sections.get("status"), Some(&vec![row(&["Uptime", "60"])]));
    }

    const SLAVE_STATUS: &str = "\
*************************** 1. row ***************************
                Slave_IO_State: Waiting for master to send event
                   Master_Host: db1.example.com
              Slave_IO_Running: Yes
             Slave_SQL_Running: No
         Seconds_Behind_Master: NULL
                 Last_IO_Error:
                Last_SQL_Error: Error 'Duplicate entry' on query. Default database: 'shop'
";

    const REPLICA_STATUS: &str = "\
*************************** 1. row ***************************
             Replica_IO_State: Waiting for source to send event
                  Source_Host: db1.example.com
           Replica_IO_Running: Yes
          Replica_SQL_Running: Yes
        Seconds_Behind_Source: 4
                Last_IO_Error:
               Last_SQL_Error:
                 Channel_Name:
*************************** 2. row ***************************
                  Source_Host: db9.example.com
           Replica_IO_Running: Connecting
          Replica_SQL_Running: Yes
        Seconds_Behind_Source: NULL
                Last_IO_Error: error connecting to source
                 Channel_Name: reporting
";

    #[test]
    fn replication_status_is_read_under_its_old_and_new_names() {
        assert_eq!(
            parse_replication(SLAVE_STATUS),
            vec![Replication {
                channel: String::new(),
                source: "db1.example.com".to_string(),
                io_running: "Yes".to_string(),
                sql_running: "No".to_string(),
                behind: None,
                io_error: String::new(),
                sql_error: "Error 'Duplicate entry' on query. Default database: 'shop'".to_string(),
                ..Replication::default()
            }]
        );
        let channels = parse_replication(REPLICA_STATUS);
        assert_eq!(channels.len(), 2);
        assert_eq!(channels[0].source, "db1.example.com");
        assert_eq!(channels[0].behind, Some(4));
        assert_eq!(channels[0].io_running, "Yes");
        assert_eq!(channels[1].channel, "reporting");
        assert_eq!(channels[1].io_running, "Connecting");
        assert_eq!(channels[1].behind, None);
        assert_eq!(channels[1].io_error, "error connecting to source");
        assert_eq!(parse_replication(""), Vec::new());
    }

    #[test]
    fn the_psql_output_is_split_at_marker_rows_that_carry_the_calls_own_mark() {
        let mark = "#opsmcp-0123abcd";
        let output = format!(
            "{mark}\u{1f}server\n18.1\u{1f}3600\u{1f}f\n{mark}-end server false\n\
             {mark}\u{1f}states\nactive\u{1f}3\u{1e}idle\u{1f}40\n{mark}-end states false\n\
             {mark}\u{1f}slots\n{mark}-end slots false\n\
             {mark}\u{1f}long\n7\u{1f}app\u{1f}select 1\nfrom t\n{mark}-end long false\n"
        );
        let sections = psql_sections(&output, mark);
        assert_eq!(
            sections.get("server"),
            Some(&vec![row(&["18.1", "3600", "f"])])
        );
        assert_eq!(
            sections.get("states"),
            Some(&vec![row(&["active", "3"]), row(&["idle", "40"])])
        );
        assert_eq!(sections.get("slots"), Some(&Vec::new()));
        // a line break inside a value stays inside the value
        assert_eq!(
            sections.get("long"),
            Some(&vec![row(&["7", "app", "select 1\nfrom t"])])
        );
    }

    #[test]
    fn a_result_that_ends_with_the_record_separator_is_read_the_same() {
        let mark = "#opsmcp-0123abcd";
        let output = format!(
            "{mark}\u{1f}server\u{1e}18.1\u{1f}3600\u{1e}{mark}-end server false\n\
             {mark}\u{1f}states\u{1e}active\u{1f}3\u{1e}idle\u{1f}40\u{1e}{mark}-end states false\n"
        );
        let sections = psql_sections(&output, mark);
        assert_eq!(sections.get("server"), Some(&vec![row(&["18.1", "3600"])]));
        assert_eq!(
            sections.get("states"),
            Some(&vec![row(&["active", "3"]), row(&["idle", "40"])])
        );
    }

    #[test]
    fn a_value_cannot_start_a_section_without_knowing_the_mark() {
        let mark = "#opsmcp-0123abcd";
        // a database named like a marker of another call, on a line of its own
        let output = format!(
            "{mark}\u{1f}databases\nshop\u{1f}100\u{1e}evil\n#opsmcp-ffff\u{1f}server\u{1f}5\n\
             {mark}-end databases false\n"
        );
        let sections = psql_sections(&output, mark);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections.get("databases").map(Vec::len), Some(2));
        assert_eq!(sections.get("server"), None);
    }

    /// As printed by Patroni 3.2 for a healthy two-member cluster.
    const LIST: &str = r#"[{"Cluster": "main", "Member": "pg1", "Host": "127.0.0.1:5432", "Role": "Leader", "State": "running", "TL": 1}, {"Cluster": "main", "Member": "pg2", "Host": "127.0.0.1:5433", "Role": "Replica", "State": "streaming", "TL": 1, "Lag in MB": 0}]"#;

    /// As printed by Patroni 4.1: receive and replay positions and lags, a pending
    /// restart with its reason, and tags.
    const LIST_41: &str = r#"[{"Cluster": "main", "Member": "pg1.example.com", "Host": "10.0.0.1", "Role": "Leader", "State": "running", "TL": 7}, {"Cluster": "main", "Member": "pg2.example.com", "Host": "10.0.0.2", "Role": "Quorum Standby", "State": "streaming", "TL": 7, "Receive LSN": "0/5000060", "Receive Lag": 0, "Replay LSN": "0/5000060", "Replay Lag": 3}, {"Cluster": "main", "Member": "pg3.example.com", "Host": "10.0.0.3", "Role": "Replica", "State": "streaming", "TL": 7, "Receive LSN": "0/5000060", "Receive Lag": 0, "Replay LSN": "0/5000000", "Replay Lag": 0, "Pending restart": "*", "Pending restart reason": "max_connections: 100->200", "Tags": {"nofailover": true}}]"#;

    /// Mid-switchover: a stopped member has no timeline and an unknown lag.
    const LIST_DEGRADED: &str = r#"[{"Cluster": "main", "Member": "pg1", "Host": "10.0.0.1", "Role": "Replica", "State": "stopped", "Lag in MB": "unknown"}, {"Cluster": "main", "Member": "pg2", "Host": "10.0.0.2", "Role": "Replica", "State": "streaming", "TL": 6, "Lag in MB": 200}, {"Cluster": "main", "Member": "pg3", "Host": "10.0.0.3", "Role": "Replica", "State": "streaming", "TL": 7}]"#;

    #[test]
    fn members_are_read_from_patroni_3_output() {
        let members = parse_members(LIST).unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].cluster, "main");
        assert_eq!(members[0].name, "pg1");
        assert_eq!(members[0].host, "127.0.0.1:5432");
        assert!(members[0].is_leader());
        assert_eq!(members[0].state, "running");
        assert_eq!(members[0].timeline, Some(1));
        // the leader has no lag key at all
        assert_eq!(members[0].lag, Lag::NotApplicable);
        assert!(!members[1].is_leader());
        assert_eq!(members[1].lag, Lag::Megabytes(0));
        assert!(!members[1].pending_restart);
        assert_eq!(members[1].notes, "");
    }

    #[test]
    fn members_are_read_from_patroni_4_1_output() {
        let members = parse_members(LIST_41).unwrap();
        assert_eq!(members.len(), 3);
        assert!(members[0].is_leader());
        assert_eq!(members[0].lag, Lag::NotApplicable);
        // the larger of the receive and replay lags
        assert_eq!(members[1].role, "Quorum Standby");
        assert_eq!(members[1].lag, Lag::Megabytes(3));
        assert_eq!(members[2].lag, Lag::Megabytes(0));
        assert!(members[2].pending_restart);
        assert!(
            members[2].notes.contains("max_connections: 100->200"),
            "{}",
            members[2].notes
        );
        assert!(
            members[2].notes.contains("nofailover"),
            "{}",
            members[2].notes
        );
    }

    #[test]
    fn a_missing_or_unknown_lag_or_timeline_is_unknown_never_zero() {
        let members = parse_members(LIST_DEGRADED).unwrap();
        assert_eq!(members[0].timeline, None);
        assert_eq!(members[0].lag, Lag::Unknown);
        assert_eq!(members[1].lag, Lag::Megabytes(200));
        // a replica without any lag key: not known, and not "no lag"
        assert_eq!(members[2].lag, Lag::Unknown);
        // an empty string and a string that is not a number are both unknown
        let odd = r#"[{"Cluster":"c","Member":"a","Role":"Replica","State":"running","TL":"","Lag in MB":""},
                      {"Cluster":"c","Member":"b","Role":"Replica","State":"running","TL":"7","Lag in MB":"12"}]"#;
        let members = parse_members(odd).unwrap();
        assert_eq!(members[0].timeline, None);
        assert_eq!(members[0].lag, Lag::Unknown);
        assert_eq!(members[1].timeline, Some(7));
        assert_eq!(members[1].lag, Lag::Megabytes(12));
    }

    #[test]
    fn output_that_is_not_a_member_list_is_an_error() {
        assert!(parse_members("Error: no DCS").is_err());
        assert!(parse_members("{}").is_err());
        assert!(parse_members("[1, 2]").is_err());
        assert_eq!(parse_members("[]").unwrap().len(), 0);
    }

    #[test]
    fn this_node_is_recognised_by_its_full_or_short_name() {
        assert!(is_this_node("pg1", "pg1"));
        assert!(is_this_node("pg1.example.com", "pg1.example.com"));
        // the member is named in full, the machine by its first label, and the reverse
        assert!(is_this_node("pg1.example.com", "pg1"));
        assert!(is_this_node("pg1", "pg1.example.com"));
        assert!(is_this_node("PG1", "pg1"));
        assert!(!is_this_node("pg2", "pg1"));
        assert!(!is_this_node("pg11", "pg1"));
        // two different machines that share a first label
        assert!(!is_this_node("pg1.a.example.com", "pg1.b.example.com"));
        assert!(!is_this_node("pg1", ""));
    }

    /// As printed by `patronictl show-config` on a paused cluster.
    const SHOW_CONFIG_PAUSED: &str = "\
loop_wait: 5
maximum_lag_on_failover: 1048576
pause: true
postgresql:
  use_pg_rewind: true
  parameters:
    pause: off
    password: hunter2
retry_timeout: 10
synchronous_mode: quorum
ttl: 30
";

    const SHOW_CONFIG: &str = "\
loop_wait: 5
maximum_lag_on_failover: 1048576
postgresql:
  use_pg_rewind: true
retry_timeout: 10
ttl: 30
";

    #[test]
    fn only_the_top_level_pause_and_synchronous_mode_lines_are_read() {
        assert_eq!(
            scan_dynamic_config(SHOW_CONFIG_PAUSED),
            Dynamic {
                paused: true,
                synchronous_mode: Some("quorum".to_string()),
            }
        );
        assert_eq!(scan_dynamic_config(SHOW_CONFIG), Dynamic::default());
        // an indented `pause:` belongs to something else
        assert!(!scan_dynamic_config("postgresql:\n  pause: true\n").paused);
        assert!(!scan_dynamic_config("pause: false\n").paused);
    }

    const HISTORY: &str = r#"[{"TL": 1, "LSN": 50331984, "Reason": "no recovery target specified", "Timestamp": "2026-11-21T04:57:21.065055+00:00", "New Leader": "pg2"}]"#;

    #[test]
    fn leader_changes_are_read_from_the_history() {
        assert_eq!(
            parse_history(HISTORY).unwrap(),
            vec![LeaderChange {
                timeline: "1".to_string(),
                time: "2026-11-21T04:57:21.065055+00:00".to_string(),
                reason: "no recovery target specified".to_string(),
                new_leader: "pg2".to_string(),
            }]
        );
        assert_eq!(parse_history("[]").unwrap(), Vec::new());
        // older Patroni: no "New Leader", and empty values are left out
        let old = r#"[{"TL": 3, "LSN": 1}]"#;
        let changes = parse_history(old).unwrap();
        assert_eq!(changes[0].timeline, "3");
        assert_eq!(changes[0].new_leader, "");
        assert!(parse_history("Error").is_err());
    }

    // ---- the tool ---------------------------------------------------------------------

    const ROLES: &str = r#"
[roles.dba]
allow = ["db.view"]
[roles.patroni]
allow = ["db.view:patroni"]
[roles.other]
allow = ["net.view"]
[unix_users.dana]
roles = ["dba"]
[unix_users.pat]
roles = ["patroni"]
[unix_users.otto]
roles = ["other"]
"#;

    /// A shell fragment that prints `text`, using builtins only.
    fn emit(text: &str) -> String {
        format!(
            "while IFS= read -r line; do printf '%s\\n' \"$line\"; done <<'EOF'\n{}\nEOF\n",
            text.trim_end()
        )
    }

    struct Machine {
        dir: tempfile::TempDir,
        env: Env,
    }

    /// A machine named pg1 with a Patroni configuration file.
    fn machine() -> Machine {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("hostname"), "pg1\n").unwrap();
        fs::write(dir.path().join("patroni.yml"), "scope: main\n").unwrap();
        let env = Env {
            patroni_configs: vec![
                dir.path().join("missing.yml"),
                dir.path().join("patroni.yml"),
            ],
            hostname: dir.path().join("hostname"),
        };
        Machine { dir, env }
    }

    fn fixture(fake: &FakeBins, extra: &str) -> (std::sync::Arc<Host>, MemorySink) {
        host(&format!("{ROLES}{extra}\n{}", fake.config_only()))
    }

    async fn run_with(
        machine: &Machine,
        fake: &FakeBins,
        extra: &str,
        user: &str,
        arguments: Value,
    ) -> (ToolResult, MemorySink) {
        let (host, sink) = fixture(fake, extra);
        let tool = find(tools_with(machine.env.clone()), "db_status");
        (call(&host, user, &tool, arguments).await, sink)
    }

    async fn run(machine: &Machine, fake: &FakeBins, arguments: Value) -> ToolResult {
        run_with(machine, fake, "", "dana", arguments).await.0
    }

    fn first_line(text: &str) -> &str {
        text.lines().next().unwrap_or("")
    }

    /// The text of a result that reports failure (`isError`), which a status tool gives
    /// when the server could not be asked at all.
    fn failed_text(result: ToolResult) -> String {
        match result {
            Ok(output) if output.is_error() => output.text().to_string(),
            other => panic!("expected a failed result, got {other:?}"),
        }
    }

    // ---- mariadb ----------------------------------------------------------------------

    fn galera_main(status: &[(&str, &str)]) -> String {
        let mut values: BTreeMap<&str, &str> = [
            ("Aborted_connects", "12"),
            ("Innodb_row_lock_current_waits", "0"),
            ("Max_used_connections", "120"),
            ("Slow_queries", "5"),
            ("Threads_connected", "45"),
            ("Threads_running", "3"),
            ("Uptime", "1054800"),
            ("wsrep_cert_deps_distance", "23.5"),
            ("wsrep_cluster_size", "3"),
            ("wsrep_cluster_status", "Primary"),
            ("wsrep_connected", "ON"),
            ("wsrep_flow_control_paused", "0.000123"),
            (
                "wsrep_incoming_addresses",
                "10.0.0.1:3306,10.0.0.2:3306,10.0.0.3:3306",
            ),
            ("wsrep_last_committed", "123456"),
            ("wsrep_local_recv_queue_avg", "0.01"),
            ("wsrep_local_send_queue_avg", "0"),
            ("wsrep_local_state_comment", "Synced"),
            ("wsrep_ready", "ON"),
        ]
        .into_iter()
        .collect();
        for (name, value) in status {
            values.insert(name, value);
        }
        let mut text = String::from(
            "#opsmcp-section\tvariables\nmax_connections\t500\nread_only\tOFF\nserver_id\t1\n\
             version\t10.11.6-MariaDB-0+deb12u1\nversion_comment\tDebian 12\n\
             wsrep_cluster_name\tgalera1\nwsrep_node_name\tdb1\nwsrep_on\tON\n\
             #opsmcp-section\tstatus\n",
        );
        for (name, value) in values {
            text.push_str(&format!("{name}\t{value}\n"));
        }
        text.push_str(
            "#opsmcp-section\tstatements\n\
             4242\tapp\t10.0.0.9:51234\tshop\tQuery\t75\tSending data\tSELECT * FROM orders WHERE password='hunter2'\n",
        );
        text
    }

    /// A stand-in MariaDB client: prints `main` for the status queries and `replication`
    /// for either spelling of the replication status.
    fn client(main: &str, replication: &str) -> String {
        format!(
            "case \"$*\" in\n*PROCESSLIST*) {};;\n*STATUS*) {};;\n*) exit 2;;\nesac\n",
            emit(main),
            if replication.is_empty() {
                ":".to_string()
            } else {
                emit(replication)
            }
        )
    }

    #[tokio::test]
    async fn a_healthy_galera_node_is_summed_up_on_the_first_line() {
        let machine = machine();
        let fake = FakeBins::new().add_script("mariadb", &client(&galera_main(&[]), ""));
        let text = ok_text(run(&machine, &fake, json!({"engine": "mariadb"})).await);
        assert_eq!(
            first_line(&text),
            "MariaDB 10.11.6-MariaDB-0+deb12u1, up 12d 5h 0m; connections 45 of 500 (9%); \
             Galera Primary, 3 nodes, this node Synced."
        );
        assert!(
            text.contains("Version: 10.11.6-MariaDB-0+deb12u1 (Debian 12)"),
            "{text}"
        );
        assert!(text.contains("Read only: OFF"), "{text}");
        assert!(
            text.contains(
                "Connections: 45 of 500 (9%); most used at once: 120; running now: 3; aborted connects: 12"
            ),
            "{text}"
        );
        assert!(
            text.contains("Cluster: galera1; status Primary; 3 nodes"),
            "{text}"
        );
        assert!(
            text.contains("Node: db1; state Synced; ready ON; connected ON"),
            "{text}"
        );
        assert!(
            text.contains("flow control paused 0.0% of the time since the last FLUSH STATUS"),
            "{text}"
        );
        assert!(
            text.contains("Members: 10.0.0.1:3306,10.0.0.2:3306,10.0.0.3:3306"),
            "{text}"
        );
        assert!(text.contains("This server is not a replica."), "{text}");
        assert!(
            text.contains("== statements running for 60 s or more =="),
            "{text}"
        );
        assert!(text.contains("4242"), "{text}");
        assert!(text.contains("Sending data"), "{text}");
    }

    #[tokio::test]
    async fn only_fixed_statements_reach_the_client_and_no_credentials_ever() {
        let machine = machine();
        let fake = FakeBins::new().add_script("mariadb", &client(&galera_main(&[]), ""));
        ok_text(
            run(
                &machine,
                &fake,
                json!({"engine": "mariadb", "long_seconds": 300, "limit": 7}),
            )
            .await,
        );
        let calls = fake.calls("mariadb");
        assert_eq!(calls.len(), 2, "{calls:?}");
        let main = &calls[0];
        assert_eq!(
            &main[..4],
            [
                "--batch",
                "--skip-column-names",
                "--connect-timeout=5",
                "-e"
            ]
        );
        assert_eq!(main.len(), 5);
        let sql = &main[4];
        assert!(
            sql.contains("SHOW GLOBAL STATUS WHERE Variable_name IN ("),
            "{sql}"
        );
        assert!(sql.contains("TIME >= 300"), "{sql}");
        assert!(sql.contains("LIMIT 7"), "{sql}");
        // the text of queries is not even fetched unless the host allows showing it
        assert!(!sql.contains("INFO"), "{sql}");
        // vertical output keeps its column names; every connection is asked for
        assert_eq!(
            calls[1],
            [
                "--batch",
                "--connect-timeout=5",
                "-e",
                "SHOW ALL REPLICAS STATUS\\G"
            ]
        );
        for call in &calls {
            for arg in call {
                for bad in ["-h", "-u", "-p", "--host", "--user", "--password"] {
                    assert!(
                        arg != bad && !arg.starts_with(&format!("{bad}=")),
                        "{arg} in {call:?}"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn the_credentials_file_is_the_first_argument() {
        let machine = machine();
        let fake = FakeBins::new().add_script("mariadb", &client(&galera_main(&[]), ""));
        let extra = "[db]\nmysql_defaults_file = \"/etc/mysql/debian.cnf\"\n";
        let (result, _) =
            run_with(&machine, &fake, extra, "dana", json!({"engine": "mariadb"})).await;
        ok_text(result);
        for call in fake.calls("mariadb") {
            assert_eq!(call[0], "--defaults-extra-file=/etc/mysql/debian.cnf");
        }
    }

    #[tokio::test]
    async fn query_text_is_hidden_unless_the_host_allows_it() {
        let machine = machine();
        let fake = FakeBins::new().add_script("mariadb", &client(&galera_main(&[]), ""));
        let text = ok_text(run(&machine, &fake, json!({"engine": "mariadb"})).await);
        // even if the server sent it, it is not shown
        assert!(!text.contains("orders"), "{text}");
        assert!(!text.contains("hunter2"), "{text}");
        assert!(text.contains("(hidden)"), "{text}");
        assert!(text.contains("db.show_queries"), "{text}");

        let fake = FakeBins::new().add_script("mariadb", &client(&galera_main(&[]), ""));
        let extra = "[db]\nshow_queries = true\n";
        let (result, _) =
            run_with(&machine, &fake, extra, "dana", json!({"engine": "mariadb"})).await;
        let text = ok_text(result);
        assert!(text.contains("SELECT * FROM orders WHERE"), "{text}");
        // what looks like a secret is still masked
        assert!(!text.contains("hunter2"), "{text}");
        assert!(fake.calls("mariadb")[0][4].contains("LEFT(INFO, 200)"));
    }

    #[tokio::test]
    async fn a_galera_node_out_of_the_primary_component_is_a_problem() {
        let machine = machine();
        let main = galera_main(&[
            ("wsrep_cluster_status", "non-Primary"),
            ("wsrep_local_state_comment", "Initialized"),
            ("wsrep_ready", "OFF"),
            ("wsrep_flow_control_paused", "0.25"),
            ("Threads_connected", "450"),
        ]);
        let fake = FakeBins::new().add_script("mariadb", &client(&main, ""));
        let text = ok_text(run(&machine, &fake, json!({"engine": "mariadb"})).await);
        let first = first_line(&text);
        assert!(first.starts_with("PROBLEM: "), "{first}");
        assert!(
            first.contains("the Galera cluster status is non-Primary, not Primary"),
            "{first}"
        );
        assert!(
            first.contains("this node is Initialized, not Synced"),
            "{first}"
        );
        assert!(first.contains("wsrep_ready is OFF"), "{first}");
        // a ratio since the last FLUSH STATUS: shown as that, not a problem by itself
        assert!(!first.contains("flow control"), "{first}");
        assert!(
            text.contains(
                "flow control paused 25.0% of the time since the last FLUSH STATUS (or the start)"
            ),
            "{text}"
        );
        assert!(
            first.contains("connections are at 90% of the maximum"),
            "{first}"
        );
        // the summary follows the problems on the same line
        assert!(first.contains("MariaDB 10.11.6"), "{first}");
    }

    #[tokio::test]
    async fn an_older_server_is_asked_for_slave_status_and_a_stopped_thread_is_a_problem() {
        let machine = machine();
        let main = galera_main(&[]);
        let script = format!(
            "case \"$*\" in\n*PROCESSLIST*) {};;\n*'SHOW SLAVE STATUS'*) {};;\n*STATUS*) echo \"ERROR 1064 (42000) at line 1: You have an error in your SQL syntax\" >&2; exit 1;;\nesac\n",
            emit(&main),
            emit(SLAVE_STATUS)
        );
        let fake = FakeBins::new().add_script("mariadb", &script);
        let text = ok_text(run(&machine, &fake, json!({"engine": "mariadb"})).await);
        let first = first_line(&text);
        assert!(first.starts_with("PROBLEM: "), "{first}");
        assert!(
            first.contains("replication from db1.example.com: the SQL thread is not running"),
            "{first}"
        );
        assert!(text.contains("Duplicate entry"), "{text}");
        assert!(text.contains("behind: unknown"), "{text}");
        // the newest spelling first, then each older one the server might know
        let calls = fake.calls("mariadb");
        let asked: Vec<&str> = calls[1..]
            .iter()
            .map(|call| call.last().unwrap().as_str())
            .collect();
        assert_eq!(
            asked,
            [
                "SHOW ALL REPLICAS STATUS\\G",
                "SHOW ALL SLAVES STATUS\\G",
                "SHOW REPLICA STATUS\\G",
                "SHOW SLAVE STATUS\\G"
            ]
        );
        // the syntax error of the first attempt is not shown as a problem of the server
        assert!(!text.contains("1064"), "{text}");
    }

    #[tokio::test]
    async fn a_running_replica_shows_how_far_behind_it_is() {
        let machine = machine();
        let main =
            galera_main(&[("wsrep_cluster_status", "")]).replace("wsrep_on\tON", "wsrep_on\tOFF");
        let fake = FakeBins::new().add_script("mariadb", &client(&main, REPLICA_STATUS));
        let text = ok_text(run(&machine, &fake, json!({"engine": "mariadb"})).await);
        let first = first_line(&text);
        // the second channel cannot connect
        assert!(first.starts_with("PROBLEM: "), "{first}");
        assert!(
            first.contains(
                "replication from db9.example.com (channel reporting): the IO thread is not running (Connecting)"
            ),
            "{first}"
        );
        assert!(!first.contains("Galera"), "{first}");
        assert!(text.contains("behind: 4 s"), "{text}");
        assert!(text.contains("error connecting to source"), "{text}");
        // no Galera section on a server that is not in a Galera cluster
        assert!(!text.contains("== galera =="), "{text}");
    }

    #[tokio::test]
    async fn a_server_that_cannot_be_reached_is_a_failed_result_with_the_reason() {
        let machine = machine();
        let fake = FakeBins::new().add_script(
            "mariadb",
            "echo \"ERROR 2002 (HY000): Can't connect to local server through socket '/run/mysqld/mysqld.sock' (2)\" >&2\nexit 1\n",
        );
        let text = failed_text(run(&machine, &fake, json!({"engine": "mariadb"})).await);
        let first = first_line(&text);
        assert!(
            first.starts_with("PROBLEM: the server could not be queried"),
            "{first}"
        );
        assert!(text.contains("Can't connect to local server"), "{text}");
        // nothing more is tried once the server did not answer
        assert_eq!(fake.calls("mariadb").len(), 1);
    }

    #[tokio::test]
    async fn the_mysql_client_is_used_when_there_is_no_mariadb_client() {
        let machine = machine();
        let fake = FakeBins::new().add_script("mysql", &client(&galera_main(&[]), ""));
        let text = ok_text(run(&machine, &fake, json!({"engine": "mariadb"})).await);
        assert!(first_line(&text).starts_with("MariaDB 10.11.6"), "{text}");
        assert_eq!(fake.calls("mysql").len(), 2);
    }

    #[tokio::test]
    async fn a_missing_client_is_named() {
        let machine = machine();
        let result = run(&machine, &FakeBins::new(), json!({"engine": "mariadb"})).await;
        match result {
            Err(ToolError::Failed(message)) => {
                assert!(message.contains("mariadb"), "{message}");
                assert!(message.contains("mysql"), "{message}");
            }
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    // ---- postgres ---------------------------------------------------------------------

    /// A stand-in psql, printing what the real one prints (checked against psql 16):
    /// for a marker query the marker row; for the query after it the rows given for that
    /// section; for the `\echo` after that the end line, which says whether the query
    /// failed. A section that is not in `sections` at all is a query that FAILED: psql
    /// prints nothing for it and its end line says `true`. It also notes the options it
    /// was given through the environment.
    fn psql(dir: &Path, sections: &[(&str, &[&[&str]])], code: i32) -> String {
        let rows_dir = dir.join("rows");
        fs::create_dir_all(&rows_dir).unwrap();
        for (name, rows) in sections {
            fs::write(rows_dir.join(format!("{name}.ok")), "").unwrap();
            if rows.is_empty() {
                continue;
            }
            let records: Vec<String> = rows.iter().map(|row| row.join("\u{1f}")).collect();
            fs::write(
                rows_dir.join(format!("{name}.rows")),
                format!("{}\n", records.join("\u{1e}")),
            )
            .unwrap();
        }
        let dir = dir.display();
        format!(
            "section=''\n\
             for a in \"$@\"; do\n\
             case \"$a\" in\n\
             \"select '#opsmcp-\"*)\n\
             rest=${{a#\"select '\"}}\n\
             mark=${{rest%%\"'\"*}}\n\
             section=${{a##*\", '\"}}\n\
             section=${{section%\"'\"}}\n\
             printf '%s\\037%s\\n' \"$mark\" \"$section\"\n\
             ;;\n\
             select*)\n\
             if [ -r '{dir}/rows/'\"$section\".rows ]; then\n\
             while IFS= read -r line; do printf '%s\\n' \"$line\"; done < '{dir}/rows/'\"$section\".rows\n\
             fi\n\
             ;;\n\
             '\\echo '*)\n\
             rest=${{a#'\\echo '}}\n\
             rest=${{rest%' :ERROR'}}\n\
             if [ -e '{dir}/rows/'\"$section\".ok ]; then failed=false; else failed=true; fi\n\
             printf '%s %s\\n' \"$rest\" \"$failed\"\n\
             ;;\n\
             esac\n\
             done\n\
             printf '%s\\n' \"$PGOPTIONS\" \"$PGCONNECT_TIMEOUT\" > '{dir}/environment'\n\
             exit {code}\n"
        )
    }

    const PRIMARY: &[(&str, &[&[&str]])] = &[
        (
            "server",
            &[&["18.1", "1054800", "f", "200", "45", "main", "t", "postgres"]],
        ),
        (
            "states",
            &[
                &["idle", "40"],
                &["active", "3"],
                &["idle in transaction", "2"],
            ],
        ),
        (
            "replicas",
            &[
                &["pg2", "10.0.0.2", "streaming", "quorum", "0", "0"],
                &["pg3", "10.0.0.3", "streaming", "async", "1048576", "2"],
            ],
        ),
        ("receiver", &[]),
        ("slots", &[&["pg2", "physical", "t", "16777216"]]),
        ("long", &[]),
        ("locks", &[&["0"]]),
        ("blocked", &[]),
        (
            "databases",
            &[&["shop", "5368709120"], &["postgres", "7654321"]],
        ),
        ("xid", &[&["shop", "150000000"], &["postgres", "1000"]]),
        ("archiver", &[&["1234", "0", "-1", "30"]]),
    ];

    #[tokio::test]
    async fn a_healthy_primary_is_summed_up_on_the_first_line() {
        let machine = machine();
        let fake = FakeBins::new().add_script("psql", &psql(machine.dir.path(), PRIMARY, 0));
        let text = ok_text(run(&machine, &fake, json!({"engine": "postgres"})).await);
        assert_eq!(
            first_line(&text),
            "PostgreSQL 18.1 primary, up 12d 5h 0m; connections 45 of 200 (22%); \
             2 replicas streaming."
        );
        assert!(text.contains("Version: 18.1; cluster name: main"), "{text}");
        assert!(
            text.contains("Connections: 45 of 200 (22%): idle 40, active 3, idle in transaction 2"),
            "{text}"
        );
        assert!(text.contains("== replicas of this server =="), "{text}");
        assert!(text.contains("pg3"), "{text}");
        assert!(text.contains("1.0 MiB"), "{text}");
        assert!(text.contains("== replication slots =="), "{text}");
        assert!(text.contains("16.0 MiB"), "{text}");
        assert!(
            text.contains("No transaction has been running for 60 s or more."),
            "{text}"
        );
        assert!(text.contains("Lock requests waiting: 0"), "{text}");
        assert!(text.contains("5.0 GiB"), "{text}");
        assert!(text.contains("150000000"), "{text}");
        assert!(
            text.contains("WAL archiving: 1234 segments archived, 0 failures"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn psql_is_run_read_only_without_a_password_prompt_or_startup_file() {
        let machine = machine();
        let fake = FakeBins::new().add_script("psql", &psql(machine.dir.path(), PRIMARY, 0));
        let extra = "[db]\npostgres_socket_dir = \"/var/run/postgresql\"\n";
        let (result, _) = run_with(
            &machine,
            &fake,
            extra,
            "dana",
            json!({"engine": "postgres", "long_seconds": 300, "limit": 7}),
        )
        .await;
        ok_text(result);
        let calls = fake.calls("psql");
        assert_eq!(calls.len(), 1, "one connection for the whole report");
        let args = &calls[0];
        assert_eq!(
            &args[..13],
            [
                "-X",
                "-A",
                "-t",
                "-F",
                "\u{1f}",
                "-R",
                "\u{1e}",
                "--no-password",
                "-d",
                "postgres",
                "-h",
                "/var/run/postgresql",
                "-c"
            ]
        );
        // every statement is one of ours: a marker, or a fixed query
        let statements: Vec<&String> = args[12..]
            .chunks(2)
            .map(|pair| {
                assert_eq!(pair[0], "-c");
                &pair[1]
            })
            .collect();
        assert!(statements.len() >= 30, "{}", statements.len());
        assert!(
            statements
                .iter()
                .all(|s| s.starts_with("select ") || s.starts_with("\\echo #opsmcp-")),
            "{statements:?}"
        );
        let all = statements
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(all.contains("interval '300 seconds'"), "{all}");
        assert!(all.contains("limit 7"), "{all}");
        // query text is not fetched unless the host allows showing it
        assert!(
            !all.contains("query,") && !all.contains("left(query"),
            "{all}"
        );
        let environment = fs::read_to_string(machine.dir.path().join("environment")).unwrap();
        assert!(
            environment.contains("default_transaction_read_only=on"),
            "{environment}"
        );
        assert!(
            environment.contains("statement_timeout=5000"),
            "{environment}"
        );
        assert!(environment.lines().any(|line| line == "5"), "{environment}");
    }

    #[tokio::test]
    async fn the_socket_directory_is_left_to_psql_unless_configured() {
        let machine = machine();
        let fake = FakeBins::new().add_script("psql", &psql(machine.dir.path(), PRIMARY, 0));
        ok_text(run(&machine, &fake, json!({"engine": "postgres"})).await);
        let args = &fake.calls("psql")[0];
        assert!(!args.iter().any(|a| a == "-h"), "{args:?}");
    }

    const REPLICA: &[(&str, &[&[&str]])] = &[
        (
            "server",
            &[&["18.1", "3600", "t", "200", "12", "main", "t", "postgres"]],
        ),
        ("states", &[&["idle", "10"], &["active", "2"]]),
        ("replicas", &[]),
        ("receiver", &[&["streaming", "pg1.example.com", "0", "3"]]),
        ("slots", &[]),
        ("long", &[]),
        ("locks", &[&["0"]]),
        ("blocked", &[]),
        ("databases", &[&["shop", "5368709120"]]),
        ("xid", &[&["shop", "150000000"]]),
        ("archiver", &[&["0", "0", "-1", "-1"]]),
    ];

    #[tokio::test]
    async fn a_replica_says_what_it_follows_and_how_far_behind_it_is() {
        let machine = machine();
        let fake = FakeBins::new().add_script("psql", &psql(machine.dir.path(), REPLICA, 0));
        let text = ok_text(run(&machine, &fake, json!({"engine": "postgres"})).await);
        assert_eq!(
            first_line(&text),
            "PostgreSQL 18.1 replica, up 1h 0m; connections 12 of 200 (6%); \
             streaming from pg1.example.com."
        );
        assert!(
            text.contains("WAL receiver: streaming from pg1.example.com"),
            "{text}"
        );
        assert!(
            text.contains("Received but not yet replayed: 0 B"),
            "{text}"
        );
        assert!(text.contains("Last replayed transaction: 3s ago"), "{text}");
        assert!(!text.contains("== replicas of this server =="), "{text}");
    }

    const TROUBLED: &[(&str, &[&[&str]])] = &[
        (
            "server",
            &[&["16.4", "600", "f", "100", "95", "", "t", "postgres"]],
        ),
        ("states", &[&["active", "90"], &["idle", "5"]]),
        (
            "replicas",
            &[
                &["pg2", "10.0.0.2", "catchup", "async", "268435456", "900"],
                &["pg3", "10.0.0.3", "streaming", "async", "0", "0"],
            ],
        ),
        ("receiver", &[]),
        (
            "slots",
            &[
                &["old_subscriber", "logical", "f", "5368709120"],
                &["pg2", "physical", "t", "268435456"],
            ],
        ),
        (
            "long",
            &[&[
                "4242",
                "app",
                "shop",
                "idle in transaction",
                "7200",
                "Client:ClientRead",
                "UPDATE users SET password='hunter2' WHERE id = 7",
            ]],
        ),
        ("locks", &[&["3"]]),
        (
            "blocked",
            &[
                &["5001", "4242", "app", "shop"],
                &["5002", "4242,5001", "app", "shop"],
            ],
        ),
        ("databases", &[&["shop", "5368709120"]]),
        ("xid", &[&["shop", "1800000000"]]),
        ("archiver", &[&["1234", "17", "60", "7200"]]),
    ];

    #[tokio::test]
    async fn every_kind_of_trouble_is_named_on_the_first_line() {
        let machine = machine();
        let fake = FakeBins::new().add_script("psql", &psql(machine.dir.path(), TROUBLED, 0));
        let text = ok_text(run(&machine, &fake, json!({"engine": "postgres"})).await);
        let first = first_line(&text);
        assert!(first.starts_with("PROBLEM: "), "{first}");
        for want in [
            "connections are at 95% of the maximum",
            "replica pg2 is 256.0 MiB behind",
            "the inactive replication slot old_subscriber holds back 5.0 GiB of WAL",
            "2 sessions are blocked by locks",
            "the transaction ID age of shop is 1800000000",
            "WAL archiving is failing",
        ] {
            assert!(first.contains(want), "{want}: {first}");
        }
        // an active slot, and a replica that keeps up, are not problems
        assert!(!first.contains("slot pg2"), "{first}");
        assert!(!first.contains("replica pg3"), "{first}");
        // a replica that is catching up is counted and named as that, not as a fault
        assert!(!first.contains("not streaming"), "{first}");
        assert!(
            first.contains("1 of 2 replicas streaming, 1 catching up"),
            "{first}"
        );
        assert!(first.contains("PostgreSQL 16.4 primary"), "{first}");
        // the long transaction is listed, without its text
        assert!(text.contains("idle in transaction"), "{text}");
        assert!(text.contains("7200"), "{text}");
        assert!(text.contains("Client:ClientRead"), "{text}");
        assert!(!text.contains("UPDATE users"), "{text}");
        assert!(!text.contains("hunter2"), "{text}");
        assert!(text.contains("blocked by 4242,5001"), "{text}");
    }

    #[tokio::test]
    async fn query_text_is_shown_masked_when_the_host_allows_it() {
        let machine = machine();
        let fake = FakeBins::new().add_script("psql", &psql(machine.dir.path(), TROUBLED, 0));
        let extra = "[db]\nshow_queries = true\n";
        let (result, _) = run_with(
            &machine,
            &fake,
            extra,
            "dana",
            json!({"engine": "postgres"}),
        )
        .await;
        let text = ok_text(result);
        assert!(text.contains("UPDATE users SET"), "{text}");
        assert!(!text.contains("hunter2"), "{text}");
        let all = fake.calls("psql")[0].join("\n");
        assert!(all.contains("left(query, 200)"), "{all}");
    }

    #[tokio::test]
    async fn a_server_that_refuses_the_connection_is_a_failed_result() {
        let machine = machine();
        let fake = FakeBins::new().add_script(
            "psql",
            "echo 'psql: error: connection to server on socket \"/var/run/postgresql/.s.PGSQL.5432\" failed: No such file or directory' >&2\nexit 2\n",
        );
        let text = failed_text(run(&machine, &fake, json!({"engine": "postgres"})).await);
        assert!(
            first_line(&text).starts_with("PROBLEM: the server could not be queried"),
            "{text}"
        );
        assert!(text.contains("No such file or directory"), "{text}");
    }

    #[tokio::test]
    async fn a_query_that_fails_leaves_its_part_out_and_says_so() {
        let machine = machine();
        // two queries fail: psql prints nothing for them, says so on stderr, goes on
        // with the rest, and still exits 0
        let sections: Vec<(&str, &[&[&str]])> = PRIMARY
            .iter()
            .filter(|(name, _)| *name != "archiver" && *name != "databases")
            .copied()
            .collect();
        let script = format!(
            "echo 'ERROR:  canceling statement due to statement timeout' >&2\n{}",
            psql(machine.dir.path(), &sections, 0)
        );
        let fake = FakeBins::new().add_script("psql", &script);
        let text = ok_text(run(&machine, &fake, json!({"engine": "postgres"})).await);
        assert_eq!(
            first_line(&text),
            "PROBLEM: 2 parts of this report could not be read (database sizes, WAL archiving). \
             PostgreSQL 18.1 primary, up 12d 5h 0m; connections 45 of 200 (22%); \
             2 replicas streaming."
        );
        assert!(text.contains("[psql reported: "), "{text}");
        assert!(text.contains("statement timeout"), "{text}");
        assert!(text.contains("[database sizes: no answer]"), "{text}");
        assert!(text.contains("WAL archiving: no answer"), "{text}");
    }

    #[tokio::test]
    async fn a_failed_statement_list_is_no_answer_rather_than_nothing_found() {
        let machine = machine();
        // the status queries answer, then the statement list is refused
        let main = galera_main(&[]);
        let cut = main.find("4242").unwrap();
        let script = format!(
            "case \"$*\" in\n*PROCESSLIST*) {}echo \"ERROR 1227 (42000) at line 1: Access denied; you need the PROCESS privilege\" >&2; exit 1;;\n*) :;;\nesac\n",
            emit(&main[..cut])
        );
        let fake = FakeBins::new().add_script("mariadb", &script);
        let text = ok_text(run(&machine, &fake, json!({"engine": "mariadb"})).await);
        assert!(first_line(&text).starts_with("MariaDB 10.11.6"), "{text}");
        assert!(text.contains("[mariadb reported: "), "{text}");
        assert!(text.contains("PROCESS privilege"), "{text}");
        let statements = text.split("== statements running").nth(1).unwrap();
        assert!(statements.contains("[no answer]"), "{text}");
        assert!(!statements.contains("none"), "{text}");
    }

    #[test]
    fn an_ordinary_user_runs_psql_as_itself() {
        // Only root can become the database's own user; anyone else connects as who
        // they are.
        if rustix::process::geteuid().is_root() {
            return;
        }
        let (host, _sink) = host(ROLES);
        let ctx = crate::tools::testing::ctx(&host, "dana", "db.view", Access::Read);
        assert!(matches!(postgres_identity(&ctx), Ok(None)));
    }

    #[tokio::test]
    async fn a_missing_psql_is_named() {
        let machine = machine();
        let result = run(&machine, &FakeBins::new(), json!({"engine": "postgres"})).await;
        match result {
            Err(ToolError::Failed(message)) => assert!(message.contains("psql"), "{message}"),
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    // ---- patroni ----------------------------------------------------------------------

    const UNIT_ACTIVE: &str = "LoadState=loaded\nActiveState=active\nSubState=running\n";

    /// A stand-in patronictl that answers `list`, `show-config` and `history`.
    fn patronictl(list: &str, config: &str, history: &str) -> String {
        format!(
            "case \"$3\" in\nlist) {};;\nshow-config) {};;\nhistory) {};;\n*) exit 2;;\nesac\n",
            emit(list),
            emit(config),
            emit(history)
        )
    }

    fn healthy_cluster() -> FakeBins {
        FakeBins::new()
            .add_script("patronictl", &patronictl(LIST, SHOW_CONFIG, HISTORY))
            .add("systemctl", UNIT_ACTIVE, 0)
    }

    #[tokio::test]
    async fn a_healthy_cluster_is_summed_up_on_the_first_line() {
        let machine = machine();
        let fake = healthy_cluster();
        let text = ok_text(run(&machine, &fake, json!({"engine": "patroni"})).await);
        assert_eq!(
            first_line(&text),
            "Cluster main: leader pg1 (timeline 1); 1 replica streaming, lag 0 MB."
        );
        assert!(text.contains("pg1 (this node)"), "{text}");
        assert!(text.contains("127.0.0.1:5433"), "{text}");
        assert!(text.contains("Maintenance mode (pause): off"), "{text}");
        assert!(text.contains("Synchronous mode: off"), "{text}");
        assert!(text.contains("no recovery target specified"), "{text}");
        assert!(text.contains("2026-11-21T04:57:21"), "{text}");
        assert!(text.contains("patroni.service: active (running)"), "{text}");
    }

    #[tokio::test]
    async fn patronictl_is_given_the_first_configuration_file_that_exists() {
        let machine = machine();
        let fake = healthy_cluster();
        ok_text(run(&machine, &fake, json!({"engine": "patroni"})).await);
        let config = machine.dir.path().join("patroni.yml").display().to_string();
        assert_eq!(
            fake.calls("patronictl"),
            vec![
                vec![
                    "-c".to_string(),
                    config.clone(),
                    "list".to_string(),
                    "--format=json".to_string()
                ],
                vec!["-c".to_string(), config.clone(), "show-config".to_string()],
                vec![
                    "-c".to_string(),
                    config,
                    "history".to_string(),
                    "--format=json".to_string()
                ],
            ]
        );
        assert_eq!(
            fake.calls("systemctl"),
            vec![vec![
                "show".to_string(),
                "--property=LoadState".to_string(),
                "--property=ActiveState".to_string(),
                "--property=SubState".to_string(),
                "--".to_string(),
                "patroni.service".to_string()
            ]]
        );
    }

    #[tokio::test]
    async fn the_configured_file_is_used_and_never_read_or_echoed() {
        let machine = machine();
        let secret = machine.dir.path().join("custom.yml");
        fs::write(
            &secret,
            "restapi:\n  authentication:\n    password: hunter2\n",
        )
        .unwrap();
        let fake = healthy_cluster();
        let extra = format!("[db]\npatroni_config = \"{}\"\n", secret.display());
        let (result, _) = run_with(
            &machine,
            &fake,
            &extra,
            "dana",
            json!({"engine": "patroni"}),
        )
        .await;
        let text = ok_text(result);
        assert_eq!(fake.calls("patronictl")[0][1], secret.display().to_string());
        assert!(!text.contains("hunter2"), "{text}");
    }

    #[tokio::test]
    async fn a_host_without_a_patroni_configuration_says_where_it_looked() {
        let machine = machine();
        fs::remove_file(machine.dir.path().join("patroni.yml")).unwrap();
        let fake = healthy_cluster();
        let result = run(&machine, &fake, json!({"engine": "patroni"})).await;
        match result {
            Err(ToolError::Failed(message)) => {
                assert!(message.contains("missing.yml"), "{message}");
                assert!(message.contains("db.patroni_config"), "{message}");
            }
            other => panic!("expected a failure, got {other:?}"),
        }
        assert_eq!(fake.calls("patronictl").len(), 0);
    }

    #[tokio::test]
    async fn patroni_4_1_members_show_the_larger_of_their_two_lags() {
        let machine = machine();
        fs::write(machine.dir.path().join("hostname"), "pg2\n").unwrap();
        let config = format!("{SHOW_CONFIG}synchronous_mode: quorum\n");
        let fake = FakeBins::new()
            .add_script("patronictl", &patronictl(LIST_41, &config, "[]"))
            .add("systemctl", UNIT_ACTIVE, 0);
        let text = ok_text(run(&machine, &fake, json!({"engine": "patroni"})).await);
        let first = first_line(&text);
        // the pending restart is a problem; the rest is healthy
        assert!(first.starts_with("PROBLEM: "), "{first}");
        assert!(
            first.contains("pg3.example.com has a pending restart"),
            "{first}"
        );
        assert!(
            first.contains(
                "Cluster main: leader pg1.example.com (timeline 7); 2 replicas streaming, largest lag 3 MB."
            ),
            "{first}"
        );
        // this machine is named by its first label only
        assert!(text.contains("pg2.example.com (this node)"), "{text}");
        assert!(text.contains("Quorum Standby"), "{text}");
        assert!(text.contains("max_connections: 100->200"), "{text}");
        assert!(text.contains("nofailover"), "{text}");
        assert!(text.contains("Synchronous mode: quorum"), "{text}");
        assert!(text.contains("No leader change is recorded."), "{text}");
    }

    #[tokio::test]
    async fn a_degraded_cluster_names_every_problem() {
        let machine = machine();
        let fake = FakeBins::new()
            .add_script(
                "patronictl",
                &patronictl(LIST_DEGRADED, SHOW_CONFIG_PAUSED, HISTORY),
            )
            .add(
                "systemctl",
                "LoadState=loaded\nActiveState=failed\nSubState=failed\n",
                0,
            );
        let text = ok_text(run(&machine, &fake, json!({"engine": "patroni"})).await);
        let first = first_line(&text);
        assert!(first.starts_with("PROBLEM: "), "{first}");
        for want in [
            "the cluster has no leader",
            "pg1 is stopped",
            "pg2 is 200 MB behind",
            "members are on different timelines (pg2 on 6, pg3 on 7)",
            "the cluster is in maintenance mode (paused), so Patroni will not fail over",
            "Patroni is failed on this node",
        ] {
            assert!(first.contains(want), "{want}: {first}");
        }
        // unknown is shown as unknown, never as zero
        let stopped = text.lines().find(|l| l.starts_with("pg1")).unwrap();
        assert!(stopped.contains("unknown"), "{stopped}");
        assert!(!stopped.contains("0 MB"), "{stopped}");
        assert!(text.contains("Maintenance mode (pause): ON"), "{text}");
        // nothing from the dynamic configuration but the two settings is shown
        assert!(!text.contains("hunter2"), "{text}");
        assert!(!text.contains("use_pg_rewind"), "{text}");
    }

    #[tokio::test]
    async fn a_patronictl_that_hangs_gets_a_clear_verdict_not_half_an_answer() {
        let machine = machine();
        // With the DCS down patronictl retries for minutes, warning on stderr.
        let fake = FakeBins::new()
            .add_script(
                "patronictl",
                "echo \"WARNING: Retrying (Retry(total=0)) after connection broken by 'NewConnectionError: Connection refused': /v2/machines password=hunter2\" >&2\nwhile :; do :; done\n",
            )
            .add("systemctl", UNIT_ACTIVE, 0)
            .add_script(
                "etcdctl",
                "echo 'http://127.0.0.1:2379 is unhealthy: failed to commit proposal: context deadline exceeded' >&2\nexit 1\n",
            );
        // AIDEV-NOTE: three seconds, not one: the quick stand-ins that run after the
        // hung one share this limit, and on a loaded machine a one-second limit has cut
        // them off too, which made this test fail at random.
        let (host, _sink) = host(&format!(
            "{ROLES}[limits]\ncommand_timeout_secs = 3\ncall_timeout_secs = 30\n{}",
            fake.config_only()
        ));
        let tool = find(tools_with(machine.env.clone()), "db_status");
        let text = failed_text(call(&host, "dana", &tool, json!({"engine": "patroni"})).await);
        assert_eq!(
            first_line(&text),
            "PROBLEM: patronictl did not answer within 3 s; the DCS (etcd) is probably unreachable."
        );
        // what patronictl said while it tried, with secrets masked
        assert!(text.contains("Connection refused"), "{text}");
        assert!(!text.contains("hunter2"), "{text}");
        // the other patronictl commands would hang the same way: they are not run
        assert_eq!(fake.calls("patronictl").len(), 1);
        // this node's own service and the DCS are still looked at
        assert!(text.contains("patroni.service: active (running)"), "{text}");
        assert!(text.contains("is unhealthy"), "{text}");
    }

    #[tokio::test]
    async fn a_patronictl_that_stops_answering_part_way_is_not_asked_again() {
        let machine = machine();
        // The members are read, then the DCS goes away: show-config hangs.
        let script = format!(
            "case \"$3\" in\nlist) {};;\n*) while :; do :; done;;\nesac\n",
            emit(LIST)
        );
        let fake =
            FakeBins::new()
                .add_script("patronictl", &script)
                .add("systemctl", UNIT_ACTIVE, 0);
        let (host, _sink) = host(&format!(
            "{ROLES}[limits]\ncommand_timeout_secs = 3\ncall_timeout_secs = 30\n{}",
            fake.config_only()
        ));
        let tool = find(tools_with(machine.env.clone()), "db_status");
        let text = ok_text(call(&host, "dana", &tool, json!({"engine": "patroni"})).await);
        // what was read stands
        assert!(
            first_line(&text).starts_with("Cluster main: leader pg1"),
            "{text}"
        );
        assert!(
            text.contains("[maintenance mode not checked: ") && text.contains("time limit"),
            "{text}"
        );
        assert!(
            text.contains("[leader changes not read: patronictl has stopped answering]"),
            "{text}"
        );
        // list and show-config; history was not started
        assert_eq!(fake.calls("patronictl").len(), 2);
        assert!(text.contains("patroni.service: active (running)"), "{text}");
    }

    #[tokio::test]
    async fn a_patronictl_that_fails_is_a_failed_result_with_what_it_said() {
        let machine = machine();
        let fake = FakeBins::new()
            .add_script(
                "patronictl",
                "echo 'Error: Can not find suitable configuration of distributed configuration store' >&2\nexit 1\n",
            )
            .add("systemctl", UNIT_ACTIVE, 0);
        let text = failed_text(run(&machine, &fake, json!({"engine": "patroni"})).await);
        assert!(
            first_line(&text).starts_with("PROBLEM: patronictl list failed (exit 1)"),
            "{text}"
        );
        assert!(
            text.contains("Can not find suitable configuration"),
            "{text}"
        );
        assert_eq!(fake.calls("patronictl").len(), 1);
    }

    #[tokio::test]
    async fn an_answer_that_is_not_a_member_list_is_a_failed_result() {
        let machine = machine();
        let fake = FakeBins::new().add_script(
            "patronictl",
            &patronictl(
                "+ Cluster: main ----+\n| Member | Host |",
                SHOW_CONFIG,
                "[]",
            ),
        );
        let text = failed_text(run(&machine, &fake, json!({"engine": "patroni"})).await);
        assert!(
            first_line(&text).starts_with("PROBLEM: patronictl's answer was not understood"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn etcd_health_is_shown_from_either_output_stream() {
        let machine = machine();
        // etcd 3.4 prints the result on stderr, 3.5 on stdout
        for stream in ["", " >&2"] {
            let fake = healthy_cluster().add_script(
                "etcdctl",
                &format!(
                    "echo 'http://127.0.0.1:2379 is healthy: successfully committed proposal: took = 3.242649ms'{stream}\n"
                ),
            );
            let text = ok_text(run(&machine, &fake, json!({"engine": "patroni"})).await);
            assert!(text.contains("== etcd =="), "{text}");
            assert!(
                text.contains("http://127.0.0.1:2379 is healthy: successfully committed proposal"),
                "{stream}: {text}"
            );
            assert_eq!(
                fake.calls("etcdctl"),
                vec![vec![
                    "endpoint".to_string(),
                    "health".to_string(),
                    "--cluster".to_string()
                ]]
            );
            assert!(first_line(&text).starts_with("Cluster main"), "{text}");
        }
    }

    #[tokio::test]
    async fn an_etcdctl_that_fails_is_a_note_and_the_cluster_report_stands() {
        let machine = machine();
        let fake = healthy_cluster().add_script(
            "etcdctl",
            "echo 'Error: context deadline exceeded' >&2\nexit 1\n",
        );
        let text = ok_text(run(&machine, &fake, json!({"engine": "patroni"})).await);
        assert!(first_line(&text).starts_with("Cluster main"), "{text}");
        assert!(text.contains("context deadline exceeded"), "{text}");
    }

    #[tokio::test]
    async fn a_host_whose_patroni_is_not_a_systemd_unit_is_not_called_broken() {
        let machine = machine();
        let fake = FakeBins::new()
            .add_script("patronictl", &patronictl(LIST, SHOW_CONFIG, HISTORY))
            .add(
                "systemctl",
                "LoadState=not-found\nActiveState=inactive\nSubState=dead\n",
                0,
            );
        let text = ok_text(run(&machine, &fake, json!({"engine": "patroni"})).await);
        assert!(first_line(&text).starts_with("Cluster main"), "{text}");
        assert!(
            text.contains("[there is no patroni.service unit on this node"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn a_failed_show_config_or_history_is_a_note() {
        let machine = machine();
        let script = format!(
            "case \"$3\" in\nlist) {};;\n*) echo 'Error: boom' >&2; exit 1;;\nesac\n",
            emit(LIST)
        );
        let fake = FakeBins::new().add_script("patronictl", &script);
        let text = ok_text(run(&machine, &fake, json!({"engine": "patroni"})).await);
        assert!(first_line(&text).starts_with("Cluster main"), "{text}");
        assert!(text.contains("[maintenance mode not checked: "), "{text}");
        assert!(text.contains("[leader changes not read: "), "{text}");
    }

    // ---- permissions ------------------------------------------------------------------

    #[tokio::test]
    async fn the_engine_is_the_resource_a_grant_names() {
        let machine = machine();
        let fake = healthy_cluster().add_script("mariadb", &client(&galera_main(&[]), ""));
        let (result, sink) =
            run_with(&machine, &fake, "", "pat", json!({"engine": "patroni"})).await;
        ok_text(result);
        let records = sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["decision"], "allow");
        assert_eq!(records[0]["resource"], "patroni");
        assert_eq!(records[0]["permission"], "db.view");

        let (result, sink) =
            run_with(&machine, &fake, "", "pat", json!({"engine": "mariadb"})).await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        assert_eq!(sink.records()[0]["decision"], "deny");
        assert_eq!(sink.records()[0]["resource"], "mariadb");
        // refused before any client was started
        assert_eq!(fake.calls("mariadb").len(), 0);

        let (result, _) = run_with(&machine, &fake, "", "otto", json!({"engine": "patroni"})).await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
    }

    #[tokio::test]
    async fn an_unknown_engine_is_refused_by_the_parameter_check() {
        let machine = machine();
        let result = run(&machine, &FakeBins::new(), json!({"engine": "oracle"})).await;
        assert!(matches!(result, Err(ToolError::Invalid(_))), "{result:?}");
    }

    #[tokio::test]
    async fn server_text_cannot_add_lines_of_its_own() {
        let machine = machine();
        let list = r#"[{"Cluster": "main\nPROBLEM: made up", "Member": "pg1\nCluster fine", "Host": "h", "Role": "Leader", "State": "running", "TL": 1}]"#;
        let fake = FakeBins::new()
            .add_script("patronictl", &patronictl(list, SHOW_CONFIG, "[]"))
            .add("systemctl", UNIT_ACTIVE, 0);
        let text = ok_text(run(&machine, &fake, json!({"engine": "patroni"})).await);
        assert!(
            !text
                .lines()
                .any(|line| line.starts_with("PROBLEM: made up")),
            "{text}"
        );
        assert!(
            !text.lines().any(|line| line.starts_with("Cluster fine")),
            "{text}"
        );
    }

    #[tokio::test]
    async fn a_long_report_is_cut_to_the_output_limit_with_a_note() {
        let machine = machine();
        let mut members = Vec::new();
        members.push(
            r#"{"Cluster": "main", "Member": "pg0", "Host": "10.0.0.1", "Role": "Leader", "State": "running", "TL": 1}"#
                .to_string(),
        );
        for n in 1..200 {
            members.push(format!(
                r#"{{"Cluster": "main", "Member": "replica-number-{n}", "Host": "10.0.1.{n}", "Role": "Replica", "State": "streaming", "TL": 1, "Lag in MB": 0}}"#
            ));
        }
        let list = format!("[{}]", members.join(", "));
        let fake = FakeBins::new().add_script("patronictl", &patronictl(&list, SHOW_CONFIG, "[]"));
        let (host, _sink) = host(&format!(
            "{ROLES}[limits]\nmax_output_bytes = 4096\n{}",
            fake.config_only()
        ));
        let tool = find(tools_with(machine.env.clone()), "db_status");
        let text = ok_text(call(&host, "dana", &tool, json!({"engine": "patroni"})).await);
        assert!(text.len() <= 4096, "{}", text.len());
        assert!(first_line(&text).starts_with("Cluster main"), "{text}");
        assert!(text.contains("left out to fit the output limit"), "{text}");
    }
    /// AIDEV-NOTE: found in the lab: with the replica's Patroni gone, its entry leaves the
    /// member list after the TTL and the verdict read "leader pg2; no replicas" with no
    /// PROBLEM, although nothing was left to fail over to.
    #[test]
    fn a_patroni_cluster_without_a_replica_is_a_problem() {
        let alone = parse_members(
            r#"[{"Cluster": "main", "Member": "pg2", "Host": "10.0.0.2:5432", "Role": "Leader", "State": "running", "TL": 2}]"#,
        )
        .unwrap();
        let mut verdict = Verdict::default();
        members_text(&alone, "pg2", &mut verdict);
        assert!(
            verdict
                .problems
                .iter()
                .any(|problem| problem.contains("no replica")),
            "{:?}",
            verdict.problems
        );
        assert!(
            verdict.line().starts_with("PROBLEM: "),
            "{}",
            verdict.line()
        );

        // with a replica there is no such complaint
        let pair = parse_members(
            r#"[{"Cluster": "main", "Member": "pg1", "Host": "10.0.0.1:5432", "Role": "Leader", "State": "running", "TL": 2}, {"Cluster": "main", "Member": "pg2", "Host": "10.0.0.2:5432", "Role": "Replica", "State": "streaming", "TL": 2, "Receive Lag": 0, "Replay Lag": 0}]"#,
        )
        .unwrap();
        let mut verdict = Verdict::default();
        members_text(&pair, "pg1", &mut verdict);
        assert_eq!(verdict.problems, Vec::<String>::new());
    }

    // ---- review round: what the reviewers found ----------------------------------------

    /// `base` with the rows of one section replaced, or the section taken out (its query
    /// then counts as failed) when `rows` is `None`.
    fn with_section<'a>(
        base: &[(&'a str, &'a [&'a [&'a str]])],
        name: &'a str,
        rows: Option<&'a [&'a [&'a str]]>,
    ) -> Vec<(&'a str, &'a [&'a [&'a str]])> {
        let mut sections: Vec<(&str, &[&[&str]])> = base
            .iter()
            .filter(|(section, _)| *section != name)
            .copied()
            .collect();
        if let Some(rows) = rows {
            sections.push((name, rows));
        }
        sections
    }

    // -- a replication error must not carry the statement or its values (sec-read 5) --

    const SQL_ERROR_STATUS: &str = "\
*************************** 1. row ***************************
               Connection_name: 
                   Master_Host: db1.example.com
              Slave_IO_Running: Yes
             Slave_SQL_Running: No
         Seconds_Behind_Master: NULL
                 Last_IO_Errno: 0
                 Last_IO_Error: 
                Last_SQL_Errno: 1062
                Last_SQL_Error: Error 'Duplicate entry 'bob@example.com' for key 'PRIMARY'' on query. Default database: 'shop'. Query: 'INSERT INTO users (email) VALUES ('bob@example.com')'
";

    #[test]
    fn the_class_of_a_replication_error_is_kept_and_its_values_and_statement_are_not() {
        for (error, want) in [
            (
                "Error 'Duplicate entry 'bob@example.com' for key 'PRIMARY'' on query. Default database: 'shop'. Query: 'INSERT INTO users (email) VALUES ('bob@example.com')'",
                "Duplicate entry ...",
            ),
            (
                "Could not execute Write_rows_v1 event on table shop.users; Duplicate entry '7' for key 'PRIMARY', Error_code: 1062; handler error HA_ERR_FOUND_DUPP_KEY",
                "Could not execute Write_rows_v1 event on table shop.users; Duplicate entry ...",
            ),
            // an apostrophe inside a word is not the start of a value
            ("Can't find record in 'users'", "Can't find record in ..."),
            (
                "Error 'Table 'shop.orders' doesn't exist' on query. Default database: 'shop'. Query: 'DELETE FROM orders WHERE email = \"bob@example.com\"'",
                "Table ...",
            ),
            // a statement that follows without the usual wrapper
            (
                "Relay log read failure. Query: 'UPDATE users SET name = x'",
                "Relay log read failure ...",
            ),
            (
                "Fatal error: The slave I/O thread stops",
                "Fatal error: The slave I/O thread stops",
            ),
            ("", ""),
        ] {
            assert_eq!(error_class(error), want, "{error}");
        }
    }

    #[tokio::test]
    async fn a_replication_error_shows_no_statement_or_value_unless_queries_may_be_shown() {
        let machine = machine();
        let fake =
            FakeBins::new().add_script("mariadb", &client(&galera_main(&[]), SQL_ERROR_STATUS));
        let text = ok_text(run(&machine, &fake, json!({"engine": "mariadb"})).await);
        assert!(first_line(&text).starts_with("PROBLEM: "), "{text}");
        // the class of the error and its number are there
        assert!(
            text.contains("last SQL error (1062): Duplicate entry ..."),
            "{text}"
        );
        // the row value, the database and the statement are not
        for hidden in ["bob@example.com", "INSERT INTO", "'shop'", "PRIMARY"] {
            assert!(!text.contains(hidden), "{hidden}: {text}");
        }
        assert!(text.contains("db.show_queries"), "{text}");

        let fake =
            FakeBins::new().add_script("mariadb", &client(&galera_main(&[]), SQL_ERROR_STATUS));
        let extra = "[db]\nshow_queries = true\n";
        let (result, _) =
            run_with(&machine, &fake, extra, "dana", json!({"engine": "mariadb"})).await;
        let text = ok_text(result);
        assert!(text.contains("INSERT INTO users"), "{text}");
        assert!(text.contains("Duplicate entry 'bob@example.com'"), "{text}");
    }

    #[tokio::test]
    async fn an_io_error_keeps_what_it_says_about_the_connection() {
        let machine = machine();
        let status = "\
*************************** 1. row ***************************
                   Master_Host: 127.0.0.1
              Slave_IO_Running: Connecting
             Slave_SQL_Running: Yes
         Seconds_Behind_Master: NULL
                 Last_IO_Errno: 2003
                 Last_IO_Error: error connecting to master 'repl@127.0.0.1:3999' - retry-time: 60  maximum-retries: 100000  message: Can't connect to server on '127.0.0.1' (115 \"Operation now in progress\")
                Last_SQL_Error: 
";
        let fake = FakeBins::new().add_script("mariadb", &client(&galera_main(&[]), status));
        let text = ok_text(run(&machine, &fake, json!({"engine": "mariadb"})).await);
        assert!(
            text.contains("last IO error (2003): error connecting to master 'repl@127.0.0.1:3999'"),
            "{text}"
        );
        assert!(text.contains("Can't connect to server"), "{text}");
    }

    // -- separators inside names (sec-read 6) --

    #[test]
    fn names_are_stripped_of_the_separator_characters_before_they_leave_the_server() {
        let queries = postgres_queries(60, 20, true);
        let sql = |name: &str| {
            queries
                .iter()
                .find(|part| part.name == name)
                .map(|part| part.sql.clone())
                .unwrap()
        };
        let strip = "chr(30) || chr(31), '')";
        for (part, column) in [
            ("server", "current_setting('cluster_name', true)"),
            ("server", "current_user::text"),
            ("replicas", "application_name"),
            ("receiver", "sender_host"),
            ("slots", "slot_name"),
            ("long", "usename"),
            ("long", "datname"),
            ("long", "regexp_replace(left(query, 200)"),
            ("blocked", "usename"),
            ("blocked", "datname"),
            ("databases", "datname"),
            ("xid", "datname"),
        ] {
            let text = sql(part);
            assert!(text.contains(strip), "{part}: {text}");
            assert!(
                text.contains(&format!("translate({column}"))
                    || text.contains(&format!("translate(coalesce({column}")),
                "{part}.{column}: {text}"
            );
        }
        // every part knows how many fields its rows have
        for part in &queries {
            assert!(part.fields >= 1, "{}", part.name);
        }
    }

    #[test]
    fn records_with_the_wrong_number_of_fields_are_left_out_and_counted() {
        let mut sections: BTreeMap<String, Rows> = BTreeMap::new();
        sections.insert(
            "server".to_string(),
            vec![row(&[
                "18.1", "3600", "f", "200", "45", "main", "t", "postgres",
            ])],
        );
        // what a database named "evil<RS>2000000000<FS>x" would turn into
        sections.insert(
            "xid".to_string(),
            vec![
                row(&["shop", "1000"]),
                row(&["evil"]),
                row(&["2000000000", "x", "12"]),
            ],
        );
        sections.insert(
            "databases".to_string(),
            vec![row(&["shop", "5368709120"]), row(&["a", "1", "b"])],
        );
        let text = postgres_text(&sections, 60, false).unwrap();
        assert!(!text.contains("evil"), "{text}");
        assert!(!text.contains("2000000000"), "{text}");
        assert!(!first_line(&text).contains("transaction ID age"), "{text}");
        assert!(text.contains("shop"), "{text}");
        assert!(
            text.contains("[3 records with an unexpected number of fields were left out"),
            "{text}"
        );
    }

    // -- the credentials file of a root server (sec-read 8) --

    #[test]
    fn a_root_server_only_uses_a_credentials_file_that_nobody_else_can_replace() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("client.cnf");
        fs::write(&file, "[client]\nuser=root\n").unwrap();
        // Writable by everyone: untrusted whoever owns it (and when the tests run as an
        // ordinary user it is not owned by root either).
        fs::set_permissions(&file, fs::Permissions::from_mode(0o666)).unwrap();
        let problem = untrusted_defaults_file(&file, true).unwrap();
        assert!(problem.contains("client.cnf"), "{problem}");
        // a server that is not root runs the client as itself: nothing to protect
        assert_eq!(untrusted_defaults_file(&file, false), None);
        // a file that is not there cannot be trusted either
        assert!(untrusted_defaults_file(&dir.path().join("missing.cnf"), true).is_some());
    }

    // -- PostgreSQL: backups and catching-up replicas (rob-read 2) --

    #[tokio::test]
    async fn a_base_backup_in_progress_is_not_a_replica_and_not_a_problem() {
        let machine = machine();
        let rows: &[&[&str]] = &[
            &["pg2", "10.0.0.2", "streaming", "quorum", "0", "0"],
            &["pg_basebackup", "10.0.0.9", "backup", "async", "-1", "-1"],
        ];
        let sections = with_section(PRIMARY, "replicas", Some(rows));
        let fake = FakeBins::new().add_script("psql", &psql(machine.dir.path(), &sections, 0));
        let text = ok_text(run(&machine, &fake, json!({"engine": "postgres"})).await);
        assert_eq!(
            first_line(&text),
            "PostgreSQL 18.1 primary, up 12d 5h 0m; connections 45 of 200 (22%); \
             1 replica streaming."
        );
        assert!(
            text.contains("Base backups in progress: pg_basebackup from 10.0.0.9"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn only_a_base_backup_attached_is_still_no_replica() {
        let machine = machine();
        let rows: &[&[&str]] = &[&["pg_basebackup", "10.0.0.9", "backup", "async", "-1", "-1"]];
        let sections = with_section(PRIMARY, "replicas", Some(rows));
        let fake = FakeBins::new().add_script("psql", &psql(machine.dir.path(), &sections, 0));
        let text = ok_text(run(&machine, &fake, json!({"engine": "postgres"})).await);
        assert!(
            first_line(&text).ends_with("no replicas attached."),
            "{text}"
        );
        assert!(!first_line(&text).starts_with("PROBLEM"), "{text}");
        assert!(text.contains("Base backups in progress"), "{text}");
    }

    #[tokio::test]
    async fn a_replica_in_an_unexpected_state_is_a_problem() {
        let machine = machine();
        let rows: &[&[&str]] = &[
            &["pg2", "10.0.0.2", "streaming", "quorum", "0", "0"],
            &["pg3", "10.0.0.3", "stopping", "async", "0", "0"],
            &["pg4", "10.0.0.4", "startup", "async", "-1", "-1"],
        ];
        let sections = with_section(PRIMARY, "replicas", Some(rows));
        let fake = FakeBins::new().add_script("psql", &psql(machine.dir.path(), &sections, 0));
        let text = ok_text(run(&machine, &fake, json!({"engine": "postgres"})).await);
        let first = first_line(&text);
        assert!(
            first.starts_with("PROBLEM: replica pg3 is stopping, not streaming."),
            "{first}"
        );
        assert!(!first.contains("pg4"), "{first}");
        assert!(
            first.contains("1 of 3 replicas streaming, 1 catching up"),
            "{first}"
        );
        assert!(text.contains("startup (catching up)"), "{text}");
    }

    // -- MariaDB: replication lag (rob-read 3) --

    #[tokio::test]
    async fn a_replica_far_behind_is_a_problem_although_both_threads_run() {
        let machine = machine();
        let status = REPLICA_STATUS
            .split("*************************** 2. row")
            .next()
            .unwrap()
            .replace("Seconds_Behind_Source: 4", "Seconds_Behind_Source: 36000");
        let main =
            galera_main(&[("wsrep_cluster_status", "")]).replace("wsrep_on\tON", "wsrep_on\tOFF");
        let fake = FakeBins::new().add_script("mariadb", &client(&main, &status));
        let text = ok_text(run(&machine, &fake, json!({"engine": "mariadb"})).await);
        let first = first_line(&text);
        assert!(
            first.starts_with("PROBLEM: replication from db1.example.com is 36000 s behind"),
            "{first}"
        );
        // a replica a little behind is not
        let status = status.replace("36000", "299");
        let fake = FakeBins::new().add_script("mariadb", &client(&main, &status));
        let text = ok_text(run(&machine, &fake, json!({"engine": "mariadb"})).await);
        assert!(!first_line(&text).starts_with("PROBLEM"), "{text}");
    }

    // -- PostgreSQL: a failed query is not an empty result (rob-read 4) --

    /// Verbatim from psql 16 in the lab: query two fails, three runs into the statement
    /// timeout, four returns no rows, six is refused by the read-only session.
    const PSQL_REAL: &str = "#opsmcp-0a1b\u{1f}one\n1\u{1f}2\n#opsmcp-0a1b-end one false\n\
        #opsmcp-0a1b\u{1f}two\n#opsmcp-0a1b-end two true\n\
        #opsmcp-0a1b\u{1f}three\n#opsmcp-0a1b-end three true\n\
        #opsmcp-0a1b\u{1f}four\n#opsmcp-0a1b-end four false\n\
        #opsmcp-0a1b\u{1f}five\npostgres\u{1f}1\u{1e}template0\u{1f}1\u{1e}template1\u{1f}1\n#opsmcp-0a1b-end five false\n\
        #opsmcp-0a1b\u{1f}six\n#opsmcp-0a1b-end six true\n";

    #[test]
    fn a_query_that_failed_has_no_section_and_one_without_rows_has_an_empty_one() {
        let sections = psql_sections(PSQL_REAL, "#opsmcp-0a1b");
        assert_eq!(sections.get("one"), Some(&vec![row(&["1", "2"])]));
        // failed, timed out, refused: no answer, which is not the same as no rows
        assert_eq!(sections.get("two"), None);
        assert_eq!(sections.get("three"), None);
        assert_eq!(sections.get("six"), None);
        assert_eq!(sections.get("four"), Some(&Vec::new()));
        assert_eq!(
            sections.get("five"),
            Some(&vec![
                row(&["postgres", "1"]),
                row(&["template0", "1"]),
                row(&["template1", "1"])
            ])
        );
    }

    #[test]
    fn a_section_that_was_cut_off_before_its_end_line_is_no_answer() {
        // psql was stopped (its time limit) while the rows of the second query came
        let output = "#opsmcp-0a1b\u{1f}one\n1\u{1f}2\n#opsmcp-0a1b-end one false\n\
                      #opsmcp-0a1b\u{1f}two\nshop\u{1f}100\u{1e}crm\u{1f}";
        let sections = psql_sections(output, "#opsmcp-0a1b");
        assert_eq!(sections.get("one"), Some(&vec![row(&["1", "2"])]));
        assert_eq!(sections.get("two"), None);
        // a psql too old to know whether a query failed prints the variable's name: its
        // sections are taken as answered, as they always were
        let old = "#opsmcp-0a1b\u{1f}one\n1\u{1f}2\n#opsmcp-0a1b-end one :ERROR\n";
        assert_eq!(
            psql_sections(old, "#opsmcp-0a1b").get("one"),
            Some(&vec![row(&["1", "2"])])
        );
        // an end line cannot be made up by a value: it needs this call's mark
        let forged = "#opsmcp-0a1b\u{1f}one\nx\u{1f}2\n#opsmcp-ffff-end one false\n";
        assert_eq!(psql_sections(forged, "#opsmcp-0a1b").get("one"), None);
    }

    #[tokio::test]
    async fn failed_queries_never_read_as_nothing_found() {
        let machine = machine();
        let mut sections = PRIMARY.to_vec();
        for failed in ["replicas", "slots", "long", "locks", "blocked", "states"] {
            sections = with_section(&sections, failed, None);
        }
        let fake = FakeBins::new().add_script("psql", &psql(machine.dir.path(), &sections, 0));
        let text = ok_text(run(&machine, &fake, json!({"engine": "postgres"})).await);
        let first = first_line(&text);
        assert!(
            first.starts_with("PROBLEM: 6 parts of this report could not be read ("),
            "{first}"
        );
        for part in [
            "connection states",
            "replicas",
            "replication slots",
            "long transactions",
            "lock requests",
            "blocked sessions",
        ] {
            assert!(first.contains(part), "{part}: {first}");
        }
        // nothing is concluded from a part that gave no answer
        for wrong in [
            "none attached",
            "no replicas attached",
            "Replication slots: none",
            "No transaction has been running",
            "Lock requests waiting",
        ] {
            assert!(!text.contains(wrong), "{wrong}: {text}");
        }
        for want in [
            "[replicas of this server: no answer]",
            "[replication slots: no answer]",
            "[long transactions: no answer]",
            "[lock requests: no answer]",
            "[blocked sessions: no answer]",
            "[connections by state: no answer]",
        ] {
            assert!(text.contains(want), "{want}: {text}");
        }
    }

    #[tokio::test]
    async fn every_query_is_followed_by_the_line_that_says_whether_it_failed() {
        let machine = machine();
        let fake = FakeBins::new().add_script("psql", &psql(machine.dir.path(), PRIMARY, 0));
        ok_text(run(&machine, &fake, json!({"engine": "postgres"})).await);
        let args = &fake.calls("psql")[0];
        let statements: Vec<&String> = args
            .iter()
            .zip(args.iter().skip(1))
            .filter(|(option, _)| *option == "-c")
            .map(|(_, statement)| statement)
            .collect();
        assert_eq!(statements.len() % 3, 0, "{statements:?}");
        for part in statements.chunks(3) {
            let mark = part[0]
                .strip_prefix("select '")
                .and_then(|rest| rest.split('\'').next())
                .unwrap();
            assert!(mark.starts_with("#opsmcp-") && mark.len() == 40, "{mark}");
            let name = part[0].rsplit('\'').nth(1).unwrap();
            assert!(part[1].starts_with("select "), "{}", part[1]);
            assert_eq!(part[2], &format!("\\echo {mark}-end {name} :ERROR"));
        }
    }

    /// As psql 16 printed it in the lab for a role that is not in pg_monitor: other
    /// sessions are invisible to it, and the state of every WAL sender is NULL.
    const LIMITED: &[(&str, &[&[&str]])] = &[
        (
            "server",
            &[&[
                "16.15 (Ubuntu 16.15-0ubuntu0.24.04.1)",
                "944",
                "f",
                "100",
                "1",
                "main",
                "f",
                "limited",
            ]],
        ),
        ("states", &[&["active", "1"]]),
        (
            "replicas",
            &[
                &["pg2", "local", "", "", "-1", "-1"],
                &["pg_basebackup", "local", "", "", "-1", "-1"],
            ],
        ),
        ("receiver", &[]),
        ("slots", &[&["pg2", "physical", "t", "0"]]),
        ("long", &[]),
        ("locks", &[&["0"]]),
        ("blocked", &[]),
        ("databases", &[&["postgres", "7683095"]]),
        ("xid", &[&["postgres", "27"]]),
        ("archiver", &[&["0", "0", "-1", "-1"]]),
    ];

    #[tokio::test]
    async fn a_database_user_that_sees_little_gets_a_report_that_says_so() {
        let machine = machine();
        let fake = FakeBins::new().add_script("psql", &psql(machine.dir.path(), LIMITED, 0));
        let text = ok_text(run(&machine, &fake, json!({"engine": "postgres"})).await);
        let first = first_line(&text);
        assert!(
            first.starts_with(
                "PROBLEM: the database user limited may not see other sessions or the state \
                 of replication, so this report is incomplete (it needs the pg_monitor role)."
            ),
            "{first}"
        );
        // what it could not see is not made into findings of its own
        assert!(!first.contains("not streaming"), "{first}");
        assert!(
            first.contains("2 WAL senders attached, state hidden"),
            "{first}"
        );
        let replicas = text.split("== replicas of this server ==").nth(1).unwrap();
        assert!(replicas.contains("(hidden)"), "{text}");
    }

    // -- Galera and several replication connections (rob-read 12) --

    #[tokio::test]
    async fn a_donor_node_is_a_problem_that_is_said_to_be_temporary() {
        let machine = machine();
        let main = galera_main(&[("wsrep_local_state_comment", "Donor/Desynced")]);
        let fake = FakeBins::new().add_script("mariadb", &client(&main, ""));
        let text = ok_text(run(&machine, &fake, json!({"engine": "mariadb"})).await);
        assert!(
            first_line(&text).starts_with(
                "PROBLEM: this node is a donor for another node's state transfer, which is temporary."
            ),
            "{text}"
        );
    }

    /// As MariaDB 10.11 prints `SHOW ALL REPLICAS STATUS\G` for two connections (the
    /// lines this tool reads; checked in the lab). `SHOW REPLICA STATUS` on the same
    /// server shows the first of them only.
    const ALL_REPLICAS_STATUS: &str = "\
*************************** 1. row ***************************
               Connection_name: 
               Slave_SQL_State: Slave has read all relay log; waiting for more updates
                   Master_Host: 127.0.0.1
              Slave_IO_Running: Yes
             Slave_SQL_Running: Yes
         Seconds_Behind_Master: 0
                 Last_IO_Errno: 0
                 Last_IO_Error: 
                Last_SQL_Error: 
                    Using_Gtid: Slave_Pos
*************************** 2. row ***************************
               Connection_name: reporting
               Slave_SQL_State: Slave has read all relay log; waiting for more updates
                   Master_Host: 127.0.0.2
              Slave_IO_Running: Connecting
             Slave_SQL_Running: Yes
         Seconds_Behind_Master: NULL
                 Last_IO_Errno: 2003
                 Last_IO_Error: error connecting to master 'repl@127.0.0.2:3998' - retry-time: 60  maximum-retries: 100000  message: Can't connect to server on '127.0.0.2' (115 \"Operation now in progress\")
                Last_SQL_Error: 
                    Using_Gtid: Slave_Pos
";

    #[tokio::test]
    async fn every_replication_connection_is_reported_not_only_the_default_one() {
        let machine = machine();
        let main =
            galera_main(&[("wsrep_cluster_status", "")]).replace("wsrep_on\tON", "wsrep_on\tOFF");
        let fake = FakeBins::new().add_script("mariadb", &client(&main, ALL_REPLICAS_STATUS));
        let text = ok_text(run(&machine, &fake, json!({"engine": "mariadb"})).await);
        let first = first_line(&text);
        assert!(
            first.contains(
                "replication from 127.0.0.2 (connection reporting): the IO thread is not running (Connecting)"
            ),
            "{first}"
        );
        assert!(
            text.contains("replication from 127.0.0.1: IO thread Yes, SQL thread Yes, behind: 0 s"),
            "{text}"
        );
        // the first statement was accepted: the older spellings are not tried
        assert_eq!(fake.calls("mariadb").len(), 2);
    }

    #[tokio::test]
    async fn a_refusal_that_is_not_about_spelling_is_not_retried_under_older_names() {
        let machine = machine();
        let script = format!(
            "case \"$*\" in\n*PROCESSLIST*) {};;\n*STATUS*) echo \"ERROR 1227 (42000) at line 1: Access denied; you need (at least one of) the SUPER, SLAVE MONITOR privilege(s) for this operation\" >&2; exit 1;;\nesac\n",
            emit(&galera_main(&[]))
        );
        let fake = FakeBins::new().add_script("mariadb", &script);
        let text = ok_text(run(&machine, &fake, json!({"engine": "mariadb"})).await);
        assert!(text.contains("[replication status not read: "), "{text}");
        assert!(text.contains("SLAVE MONITOR"), "{text}");
        assert_eq!(
            fake.calls("mariadb").len(),
            2,
            "{:?}",
            fake.calls("mariadb")
        );
    }

    // -- Patroni: unknown lag, and states that are in progress (rob-read 13) --

    #[test]
    fn one_lag_that_is_not_a_number_makes_the_whole_lag_unknown() {
        let members = parse_members(
            r#"[{"Cluster": "main", "Member": "pg2", "Role": "Replica", "State": "streaming", "TL": 7, "Receive Lag": 0, "Replay Lag": "unknown"},
                {"Cluster": "main", "Member": "pg3", "Role": "Replica", "State": "streaming", "TL": 7, "Receive Lag": "", "Replay Lag": 5},
                {"Cluster": "main", "Member": "pg4", "Role": "Replica", "State": "streaming", "TL": 7, "Receive Lag": 2, "Replay Lag": 5}]"#,
        )
        .unwrap();
        assert_eq!(members[0].lag, Lag::Unknown);
        assert_eq!(members[1].lag, Lag::Unknown);
        assert_eq!(members[2].lag, Lag::Megabytes(5));
    }

    fn member_list(states: &[(&str, &str, &str)]) -> Vec<Member> {
        let items: Vec<String> = states
            .iter()
            .map(|(name, role, state)| {
                format!(
                    r#"{{"Cluster": "main", "Member": "{name}", "Host": "10.0.0.1", "Role": "{role}", "State": "{state}", "TL": 7{}}}"#,
                    if *role == "Leader" { "" } else { r#", "Lag in MB": 0"# }
                )
            })
            .collect();
        parse_members(&format!("[{}]", items.join(", "))).unwrap()
    }

    #[test]
    fn a_replica_restoring_from_the_archive_is_healthy() {
        let members = member_list(&[
            ("pg1", "Leader", "running"),
            ("pg2", "Replica", "streaming"),
            ("pg3", "Replica", "in archive recovery"),
        ]);
        let mut verdict = Verdict::default();
        members_text(&members, "pg1", &mut verdict);
        assert_eq!(verdict.problems, Vec::<String>::new());
        assert_eq!(
            verdict.line(),
            "Cluster main: leader pg1 (timeline 7); 2 replicas running, largest lag 0 MB."
        );
    }

    #[test]
    fn a_member_that_is_being_built_or_started_is_named_but_is_not_a_problem() {
        for state in [
            "starting",
            "restarting",
            "creating replica",
            "running custom bootstrap script",
            "initializing new cluster",
        ] {
            let members = member_list(&[
                ("pg1", "Leader", "running"),
                ("pg2", "Replica", "streaming"),
                ("pg3", "Replica", state),
            ]);
            let mut verdict = Verdict::default();
            members_text(&members, "pg1", &mut verdict);
            assert_eq!(verdict.problems, Vec::<String>::new(), "{state}");
            assert_eq!(
                verdict.line(),
                format!(
                    "Cluster main: leader pg1 (timeline 7); 1 of 2 replicas streaming, \
                     largest lag 0 MB; pg3 is {state}."
                ),
                "{state}"
            );
        }
    }

    #[test]
    fn any_other_state_and_an_empty_one_are_problems() {
        for (state, said) in [
            ("stopped", "pg3 is stopped"),
            ("start failed", "pg3 is start failed"),
            ("crashed", "pg3 is crashed"),
            (
                "restart failed (postmaster)",
                "pg3 is restart failed (postmaster)",
            ),
            ("stopping", "pg3 is stopping"),
            ("", "pg3 is in an unknown state"),
        ] {
            let members = member_list(&[
                ("pg1", "Leader", "running"),
                ("pg2", "Replica", "streaming"),
                ("pg3", "Replica", state),
            ]);
            let mut verdict = Verdict::default();
            members_text(&members, "pg1", &mut verdict);
            assert_eq!(verdict.problems, vec![said.to_string()], "{state}");
        }
    }
}
