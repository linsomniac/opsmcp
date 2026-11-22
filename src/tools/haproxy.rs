//! HAProxy backend servers: looking at them, and draining and enabling them.
//!
//! AIDEV-NOTE: two tools on purpose. A tool is tagged read or write as a whole, and
//! `@read` grants every read tool: looking at servers (`haproxy_servers`, read) must be
//! possible for a read-only caller, and taking one out of rotation
//! (`haproxy_server_state`, write) must never be. Do not give the write tool a listing
//! action again, nor the read tool anything that changes HAProxy.
//!
//! AIDEV-NOTE: how the admin socket behaves, as seen on HAProxy 2.8 (the stand-in in the
//! tests answers the same way):
//!   - without `prompt`, one connection takes commands until the client is done; two
//!     commands separated by a line break in ONE write both run. Nothing but the
//!     character set of `check_name` keeps a caller's text from adding a command.
//!   - a `set server B/S state X` that worked is answered with one empty line; anything
//!     else is the refusal ("No such server.", "No such backend.", ...).
//!   - `show stat` is CSV with a header line that starts `# pxname,svname,`. Servers are
//!     the rows whose `type` is 2 (0 frontend, 1 the backend's total, 3 a listener).
//!   - a server that has no health check reports the status `no check`, and it IS
//!     serving. After drain it reports `DRAIN`, after maint `MAINT`.

use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use super::args::{Args, Param};
use super::{Ctx, Tool, ToolError, ToolResult, format_table, one_line_cell, required};
use crate::policy::Access;
use crate::sanitize::keep_head;

const ACTIONS: [&str; 3] = ["ready", "drain", "maint"];
/// Time allowed for one exchange with HAProxy (connecting, asking, reading the answer).
const IO_LIMIT: Duration = Duration::from_secs(5);
/// Most bytes kept of one answer from HAProxy.
///
/// AIDEV-NOTE: `show stat` describes every proxy and server of the HAProxy, about a
/// hundred bytes each, and is read whole before every action. 32 MiB is room for some
/// hundred thousand servers; beyond it the tool says so rather than reading on.
const MAX_REPLY: usize = 32 * 1024 * 1024;

pub fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "haproxy_servers",
            "Show the servers behind HAProxy with their status (UP, DOWN, DRAIN, MAINT, or \
             `no check` for a server without a health check) and the sessions each has in \
             progress, read from HAProxy's admin socket. Name a backend to see its servers, \
             or a backend and a server for one; with neither, every backend is listed. \
             Use it to see what is in rotation, and to watch a drain finish (SESSIONS \
             falling to 0). It changes nothing; haproxy_server_state does the changing.",
            Access::Read,
            "haproxy.view",
            vec![
                Param::str(
                    "backend",
                    "The backend's name in HAProxy's configuration (default: every backend)",
                )
                .max_len(64),
                Param::str(
                    "server",
                    "One server within that backend (default: all of its servers)",
                )
                .max_len(64),
            ],
            |ctx, args| haproxy_servers(ctx, args, IO_LIMIT),
        ),
        Tool::new(
            "haproxy_server_state",
            "Take a backend server out of HAProxy's rotation and put it back, through \
             HAProxy's admin socket, for rolling maintenance: drain (no new sessions; the \
             ones in progress finish), maint (out of service at once) or ready (back in \
             service). The result shows the backend's servers before and after; \
             haproxy_servers shows them at any time, which is how to watch a drain \
             finish. The change is to the running HAProxy only: a restart, or a reload \
             without a server-state file, puts the configured state back. Draining or \
             disabling the last server that is up in a backend is refused unless force \
             is set.",
            Access::Write,
            "haproxy.server",
            vec![
                Param::choice("action", "What to do", &ACTIONS).required(),
                Param::str("backend", "The backend's name in HAProxy's configuration")
                    .max_len(64)
                    .required(),
                Param::str("server", "The server's name within the backend")
                    .max_len(64)
                    .required(),
                Param::bool(
                    "force",
                    "Drain or disable the server even if it is the last one up in its backend",
                ),
            ],
            |ctx, args| haproxy_server_state(ctx, args, IO_LIMIT),
        ),
    ]
}

/// Checks the name of a backend or a server: 1 to 64 letters, digits and `_ . : -`, not
/// starting with `-`.
///
/// AIDEV-NOTE: this is the whole defence against sending HAProxy a second command. On the
/// admin socket a `;` or a line break starts another command (confirmed against a real
/// HAProxy: both commands run), and a space starts another argument; none of them can
/// be part of a name here. HAProxy itself allows exactly these characters in proxy and
/// server names, so nothing real is shut out. Do not widen this set.
pub fn check_name(kind: &str, name: &str) -> Result<(), ToolError> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.:-".contains(c));
    if valid {
        Ok(())
    } else {
        let shown: String = name.chars().take(80).collect();
        Err(ToolError::Invalid(format!(
            "{shown:?} is not a valid {kind} name (1 to 64 letters, digits and _ . : - only)"
        )))
    }
}

/// One line of `show stat` that describes a server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerRow {
    pub backend: String,
    pub server: String,
    pub status: String,
    /// Sessions in progress, when HAProxy reports a number.
    pub sessions: Option<u64>,
    pub weight: String,
}

impl ServerRow {
    /// Whether the server is taking traffic: `UP` (also in the forms HAProxy shows while
    /// checks are failing or recovering, `UP 1/3`), or `no check` for a server that has
    /// no health check. Not: `DOWN...`, `DRAIN`, `MAINT...`, `NOLB`.
    fn is_up(&self) -> bool {
        self.status.starts_with("UP") || self.status == "no check"
    }
}

/// Splits CSV text into records of fields. A field in double quotes may hold commas and
/// line breaks; `""` inside it is one quote. Empty lines are skipped.
///
/// AIDEV-NOTE: `show stat` ends each line with free text that comes from the backend
/// servers themselves (the last health check's answer). HAProxy quotes such a field
/// when it holds a comma or a line break, so the records must be split with the quotes
/// in mind: splitting at every line break would let a server's health-check answer add
/// lines that look like other servers.
pub fn csv_records(text: &str) -> Vec<Vec<String>> {
    let mut records = Vec::new();
    let mut record: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    // Whether anything has been read for the current record.
    let mut started = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if quoted {
            if c != '"' {
                field.push(c);
            } else if chars.peek() == Some(&'"') {
                chars.next();
                field.push('"');
            } else {
                quoted = false;
            }
            continue;
        }
        match c {
            '"' if field.is_empty() => {
                quoted = true;
                started = true;
            }
            ',' => {
                record.push(std::mem::take(&mut field));
                started = true;
            }
            '\r' if chars.peek() == Some(&'\n') => {}
            '\n' => {
                if started {
                    record.push(std::mem::take(&mut field));
                    records.push(std::mem::take(&mut record));
                }
                started = false;
            }
            other => {
                field.push(other);
                started = true;
            }
        }
    }
    if started {
        record.push(field);
        records.push(record);
    }
    records
}

/// The servers in the CSV that `show stat` prints. The columns are found by the names in
/// the header line, so a HAProxy version that adds or reorders columns is still read
/// correctly. Frontends, backend totals and listening sockets are left out.
pub fn parse_stat(csv: &str) -> Result<Vec<ServerRow>, String> {
    let not_the_table = || {
        let first: String = csv.lines().next().unwrap_or("").chars().take(200).collect();
        if first.trim().is_empty() {
            "HAProxy gave no answer to `show stat`".to_string()
        } else {
            format!(
                "HAProxy did not answer `show stat` with its statistics table, but with: {}",
                one_line_cell(first.trim())
            )
        }
    };
    // The header is the line that starts with `#` and names the columns.
    let title = |field: &str| field.trim_start_matches("# ").to_string();
    let mut records = csv_records(csv).into_iter();
    let header = records
        .by_ref()
        .find(|record| {
            record.first().is_some_and(|first| first.starts_with('#'))
                && record.iter().any(|field| title(field) == "pxname")
        })
        .ok_or_else(not_the_table)?;
    let column = |name: &str| header.iter().position(|field| title(field) == name);
    let (Some(proxy_at), Some(name_at), Some(sessions_at), Some(status_at), Some(weight_at)) = (
        column("pxname"),
        column("svname"),
        column("scur"),
        column("status"),
        column("weight"),
    ) else {
        return Err(format!(
            "the statistics table from `show stat` lacks a column that is needed \
             (pxname, svname, scur, status, weight); its header was: {}",
            one_line_cell(&header.join(",").chars().take(200).collect::<String>())
        ));
    };
    let type_at = column("type");

    let mut rows = Vec::new();
    for record in records {
        let (Some(backend), Some(server), Some(sessions), Some(status), Some(weight)) = (
            record.get(proxy_at),
            record.get(name_at),
            record.get(sessions_at),
            record.get(status_at),
            record.get(weight_at),
        ) else {
            continue;
        };
        // type: 0 frontend, 1 backend, 2 server, 3 listening socket
        let is_server = match type_at {
            Some(at) => record.get(at).is_some_and(|kind| kind == "2"),
            None => server != "FRONTEND" && server != "BACKEND",
        };
        if !is_server {
            continue;
        }
        rows.push(ServerRow {
            backend: backend.clone(),
            server: server.clone(),
            status: status.clone(),
            sessions: sessions.parse().ok(),
            weight: weight.clone(),
        });
    }
    Ok(rows)
}

/// Sends one command to HAProxy's admin socket and returns its answer. One command per
/// connection: without `prompt`, HAProxy answers one line and hangs up.
async fn ask(
    socket: &Path,
    command: &str,
    limit: Duration,
    max_reply: usize,
) -> Result<String, String> {
    // Every command sent is built from a fixed word list and checked names. This is the
    // last line of defence should that ever change: `;` and line breaks start a new
    // command on this socket.
    if command.contains(['\n', '\r', ';']) {
        return Err("refusing to send HAProxy anything but one command on one line".to_string());
    }
    let verb: String = command.split(' ').take(2).collect::<Vec<_>>().join(" ");
    let at = socket.display();
    let exchange = async {
        let mut stream = UnixStream::connect(socket)
            .await
            .map_err(|e| format!("cannot connect to HAProxy's admin socket {at}: {e}"))?;
        stream
            .write_all(format!("{command}\n").as_bytes())
            .await
            .map_err(|e| format!("cannot send `{verb}` to HAProxy: {e}"))?;
        let mut reply = Vec::new();
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            let count = stream
                .read(&mut buffer)
                .await
                .map_err(|e| format!("reading HAProxy's answer to `{verb}`: {e}"))?;
            if count == 0 {
                break;
            }
            if reply.len() + count > max_reply {
                return Err(format!(
                    "HAProxy's answer to `{verb}` is more than {max_reply} bytes; not reading on"
                ));
            }
            reply.extend_from_slice(buffer.get(..count).unwrap_or_default());
        }
        Ok(reply)
    };
    match tokio::time::timeout(limit, exchange).await {
        Ok(result) => result.map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
        Err(_) => Err(format!(
            "HAProxy did not answer `{verb}` on {at} within {:.1} s",
            limit.as_secs_f64()
        )),
    }
}

/// Checks that the configured admin socket is there and is a socket.
async fn check_socket(socket: &Path) -> Result<(), ToolError> {
    let at = socket.display();
    match tokio::fs::metadata(socket).await {
        Ok(meta) if meta.file_type().is_socket() => Ok(()),
        Ok(_) => Err(ToolError::Failed(format!(
            "{at} is not a socket: haproxy.socket in opsmcp's configuration must name \
             HAProxy's admin socket (`stats socket ... level admin`)"
        ))),
        Err(e) => Err(ToolError::Failed(format!(
            "HAProxy's admin socket {at} cannot be used ({e}): is HAProxy running, and is \
             haproxy.socket in opsmcp's configuration right?"
        ))),
    }
}

/// Every server of every backend, as HAProxy reports them now.
async fn all_servers(socket: &Path, limit: Duration) -> Result<Vec<ServerRow>, String> {
    let reply = ask(socket, "show stat", limit, MAX_REPLY).await?;
    parse_stat(&reply)
}

/// The servers of `backend` as HAProxy reports them now.
async fn servers_of(
    socket: &Path,
    backend: &str,
    limit: Duration,
) -> Result<Vec<ServerRow>, String> {
    let mut rows = all_servers(socket, limit).await?;
    rows.retain(|row| row.backend == backend);
    Ok(rows)
}

/// Whether this caller may be shown a server: the rule the tables and the counts share.
fn may_see(ctx: &Ctx, row: &ServerRow) -> bool {
    ctx.permits(&format!("{}/{}", row.backend, row.server))
}

/// "1 server" or "3 servers".
fn counted(count: usize, one: &str, many: &str) -> String {
    if count == 1 {
        format!("1 {one}")
    } else {
        format!("{count} {many}")
    }
}

/// The table of servers, limited to those this caller may be shown.
///
/// AIDEV-NOTE: a caller may be granted one server of a backend only. The call was
/// authorized for what it names; the other servers of the backend are shown only where
/// the caller could have asked about them too.
fn table(ctx: &Ctx, rows: &[ServerRow], only: Option<&str>) -> String {
    table_of(ctx, rows, only, false)
}

/// `table`, with the backend's name in front of each server when the rows are of
/// several backends.
fn table_of(ctx: &Ctx, rows: &[ServerRow], only: Option<&str>, with_backend: bool) -> String {
    let mut hidden = false;
    let mut cells = Vec::new();
    for row in rows {
        if only.is_some_and(|server| server != row.server) {
            continue;
        }
        if !may_see(ctx, row) {
            hidden = true;
            continue;
        }
        let mut cell = Vec::with_capacity(5);
        if with_backend {
            cell.push(row.backend.clone());
        }
        cell.extend([
            row.server.clone(),
            row.status.clone(),
            row.sessions
                .map_or_else(|| "-".to_string(), |count| count.to_string()),
            row.weight.clone(),
        ]);
        cells.push(cell);
    }
    let mut text = if with_backend {
        format_table(
            &["BACKEND", "SERVER", "STATUS", "SESSIONS", "WEIGHT"],
            &cells,
            &[false, false, false, true, true],
        )
    } else {
        format_table(
            &["SERVER", "STATUS", "SESSIONS", "WEIGHT"],
            &cells,
            &[false, false, true, true],
        )
    };
    if hidden {
        text.push_str("[some servers are not shown: this caller may not see them]\n");
    }
    text
}

/// Cuts a result to what the server may return: lines are dropped from the end, with a
/// note. Results are written with what matters most first, so only table rows go.
fn fit(ctx: &Ctx, text: &str) -> String {
    let (mut kept, dropped) = keep_head(text, ctx.output_budget().saturating_sub(160));
    if dropped > 0 {
        kept.push_str(&format!(
            "[{dropped} more lines left out to fit the output limit; name a server to see \
             just that one]\n"
        ));
    }
    kept
}

/// The rows with the server called `first` moved to the top.
fn leading(rows: &[ServerRow], first: &str) -> Vec<ServerRow> {
    let (mut ordered, others): (Vec<ServerRow>, Vec<ServerRow>) =
        rows.iter().cloned().partition(|row| row.server == first);
    ordered.extend(others);
    ordered
}

/// What each state means, for the result of a change.
fn meaning(state: &str) -> &'static str {
    match state {
        "drain" => "no new sessions go to it; the sessions in progress finish",
        "maint" => "it is out of service at once, and its health checks stop",
        _ => "it is back in service, as far as its health checks allow",
    }
}

/// Shows servers: one backend's, one server, or every backend's.
async fn haproxy_servers(ctx: Ctx, args: Args, limit: Duration) -> ToolResult {
    let backend = args.str("backend");
    let server = args.str("server");
    if let Some(backend) = backend {
        check_name("backend", backend)?;
    }
    if let Some(server) = server {
        check_name("server", server)?;
        if backend.is_none() {
            return Err(ToolError::Invalid(
                "a server is named within a backend: give backend as well".to_string(),
            ));
        }
    }

    // A grant names `BACKEND/SERVER`; a listing of a whole backend is `BACKEND/`, which a
    // grant for `BACKEND/*` covers. Listing every backend names no resource, so it needs
    // a grant that is not limited to some of them.
    let resource = backend.map(|backend| format!("{backend}/{}", server.unwrap_or("")));
    let auth = ctx.authorize(resource.as_deref())?;

    let socket = ctx.cfg().haproxy.socket.clone();
    check_socket(&socket).await?;
    let mut rows = all_servers(&socket, limit)
        .await
        .map_err(ToolError::Failed)?;

    let Some(backend) = backend else {
        // AIDEV-NOTE: counted over the servers this caller is shown, like the table.
        let shown: Vec<&ServerRow> = rows.iter().filter(|row| may_see(&ctx, row)).collect();
        if shown.is_empty() && rows.is_empty() {
            return auth.ok("HAProxy has no backend with servers in it.\n");
        }
        let mut backends: Vec<&str> = shown.iter().map(|row| row.backend.as_str()).collect();
        backends.sort_unstable();
        backends.dedup();
        let up = shown.iter().filter(|row| row.is_up()).count();
        let mut text = format!(
            "HAProxy: {}, {}, {up} up.\n",
            counted(backends.len(), "backend", "backends"),
            counted(shown.len(), "server", "servers"),
        );
        text.push_str(&table_of(&ctx, &rows, None, true));
        return auth.ok(fit(&ctx, &text));
    };

    rows.retain(|row| row.backend == backend);
    if rows.is_empty() {
        return Err(ToolError::Failed(format!(
            "HAProxy has no backend named {backend} with servers in it"
        )));
    }
    let mut text = match server {
        Some(server) => {
            if !rows.iter().any(|row| row.server == server) {
                return Err(ToolError::Failed(format!(
                    "backend {backend} has no server named {server}"
                )));
            }
            format!("Server {backend}/{server} in HAProxy:\n")
        }
        None => {
            // AIDEV-NOTE: counted over the servers this caller is shown, like the
            // table below. Counting them all would tell a caller who may see one
            // server of the backend how many others there are and how many are up.
            let shown: Vec<&ServerRow> = rows.iter().filter(|row| may_see(&ctx, row)).collect();
            let up = shown.iter().filter(|row| row.is_up()).count();
            format!(
                "Backend {backend} in HAProxy: {}, {up} up.\n",
                counted(shown.len(), "server", "servers")
            )
        }
    };
    text.push_str(&table(&ctx, &rows, server));
    auth.ok(fit(&ctx, &text))
}

/// Changes one server's state.
async fn haproxy_server_state(ctx: Ctx, args: Args, limit: Duration) -> ToolResult {
    let state = required(&args, "action")?;
    let backend = required(&args, "backend")?;
    check_name("backend", backend)?;
    let server = required(&args, "server")?;
    check_name("server", server)?;
    let force = args.bool("force").unwrap_or(false);
    if !ACTIONS.contains(&state) {
        return Err(ToolError::Invalid(format!(
            "{state:?} is not a known action"
        )));
    }

    let resource = format!("{backend}/{server}");
    let auth = ctx.authorize(Some(&resource))?;

    let socket = ctx.cfg().haproxy.socket.clone();
    check_socket(&socket).await?;
    let before = servers_of(&socket, backend, limit)
        .await
        .map_err(ToolError::Failed)?;
    if before.is_empty() {
        return Err(ToolError::Failed(format!(
            "HAProxy has no backend named {backend} with servers in it"
        )));
    }
    let target = before
        .iter()
        .find(|row| row.server == server)
        .ok_or_else(|| {
            ToolError::Failed(format!("backend {backend} has no server named {server}"))
        })?;

    let name = format!("{backend}/{}", target.server);
    if !force && state != "ready" && target.is_up() {
        let up = before.iter().filter(|row| row.is_up()).count();
        if up <= 1 {
            return auth.failed(format!(
                "Nothing was changed: {} is the last server that is up in backend \
                 {backend}, and {state} would leave the backend with none. Bring another \
                 server back first, or pass force to do it anyway.\n{}",
                target.server,
                table(&ctx, &before, Some(server))
            ));
        }
    }

    let command = format!("set server {name} state {state}");
    let reply = match ask(&socket, &command, limit, MAX_REPLY).await {
        Ok(reply) => reply,
        // The command may have been sent, and acted on, before things went wrong.
        Err(problem) => {
            return auth.failed(format!(
                "{problem}. Whether {name} was set to {state} is not known: check with \
                 haproxy_servers.\n"
            ));
        }
    };
    let said = reply.trim();
    if !said.is_empty() {
        // HAProxy answers one empty line when it has done it; anything else is its
        // refusal.
        let shown: String = said.chars().take(300).collect();
        let mut text = format!(
            "HAProxy refused to set {name} to {state}: {}\n",
            one_line_cell(&shown)
        );
        if said.contains("Permission denied") {
            text.push_str(
                "[the socket named by haproxy.socket must be declared with `level admin` in \
                 HAProxy's configuration]\n",
            );
        }
        return auth.failed(text);
    }

    // What was done, how long it lasts and the server's state now come first, so that
    // they survive whatever has to be cut from the tables of a very large backend. The
    // server that was changed leads each table for the same reason.
    let mut text = format!("Set {name} to {state}: {}.\n", meaning(state));
    text.push_str(
        "This changed the running HAProxy only: a restart, or a reload without a \
         server-state file, puts the configured state back.\n",
    );
    if state == "drain" {
        text.push_str(
            "Use haproxy_servers to watch SESSIONS fall to 0 before stopping the server.\n",
        );
    }
    let after = servers_of(&socket, backend, limit).await;
    match &after {
        Ok(after) => {
            if let Some(row) = after.iter().find(|row| row.server == target.server) {
                let sessions = row
                    .sessions
                    .map_or_else(|| "an unknown number of".to_string(), |n| n.to_string());
                text.push_str(&format!(
                    "Now: {} is {} with {sessions} sessions in progress.\n",
                    row.server,
                    one_line_cell(&row.status)
                ));
            }
        }
        Err(problem) => text.push_str(&format!(
            "[the change was made, but the state afterwards could not be read: {problem}]\n"
        )),
    }
    text.push_str("Before:\n");
    text.push_str(&table(&ctx, &leading(&before, &target.server), None));
    if let Ok(after) = &after {
        text.push_str("After:\n");
        text.push_str(&table(&ctx, &leading(after, &target.server), None));
    }
    auth.ok(fit(&ctx, &text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::testing::{call, ctx, find, host, ok_text};
    use crate::tools::{Host, ToolError, ToolResult};
    use serde_json::{Value, json};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    // ---- a stand-in for HAProxy's admin socket ----

    const HEADER: &str = "# pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,\
                          ereq,econ,eresp,wretr,wredis,status,weight,act,bck,chkfail,chkdown,\
                          lastchg,downtime,qlimit,pid,iid,sid,throttle,lbtot,tracked,type,\
                          rate,rate_lim,rate_max,check_status,check_code,check_duration,";

    /// One `show stat` line: a frontend (type 0), a backend total (1) or a server (2).
    fn stat_line(proxy: &str, name: &str, sessions: u64, status: &str, weight: &str) -> String {
        let kind = match name {
            "FRONTEND" => 0,
            "BACKEND" => 1,
            _ => 2,
        };
        format!(
            "{proxy},{name},0,0,{sessions},9,,120,1000,2000,0,0,,0,0,0,0,{status},{weight},1,0,\
             0,0,300,0,,1,3,1,,120,,{kind},0,,5,L7OK,200,1,"
        )
    }

    /// One server as the stand-in knows it.
    struct FakeServer {
        backend: String,
        server: String,
        status: String,
        sessions: u64,
        /// What the server reports when it is in service: `UP`, or `no check` for one
        /// that has no health check configured.
        in_service: String,
    }

    /// What the stand-in knows: its servers, and every command line it was sent. It
    /// answers as HAProxy 2.8 was seen to.
    #[derive(Default)]
    struct Fake {
        servers: Vec<FakeServer>,
        commands: Vec<String>,
        /// What `set server` answers instead of applying the change.
        refuse_with: Option<String>,
        /// What `set server` answers when it has applied the change (HAProxy: one empty
        /// line).
        done_with: Option<String>,
        /// Take a `set server` command, apply it, and then never answer.
        silent_on_set: bool,
    }

    fn serving(status: &str) -> bool {
        status.starts_with("UP") || status == "no check"
    }

    impl Fake {
        fn stat(&self) -> String {
            let mut text = format!("{HEADER}\n");
            text.push_str(&stat_line("fe", "FRONTEND", 12, "OPEN", ""));
            text.push('\n');
            let mut backends: Vec<&str> = self.servers.iter().map(|s| s.backend.as_str()).collect();
            backends.dedup();
            for backend in backends {
                let mut total = 0;
                let mut up = 0;
                for entry in self.servers.iter().filter(|s| s.backend == backend) {
                    total += entry.sessions;
                    if serving(&entry.status) {
                        up += 1;
                    }
                    text.push_str(&stat_line(
                        backend,
                        &entry.server,
                        entry.sessions,
                        &entry.status,
                        "1",
                    ));
                    text.push('\n');
                }
                // with every server drained or in maintenance the backend is DOWN, weight 0
                let status = if up > 0 { "UP" } else { "DOWN" };
                text.push_str(&stat_line(
                    backend,
                    "BACKEND",
                    total,
                    status,
                    &up.to_string(),
                ));
                text.push('\n');
            }
            text.push('\n');
            text
        }

        /// The answer to a command; `None` means stay silent.
        fn answer(&mut self, command: &str) -> Option<String> {
            let reply = self.reply_to(command);
            if self.silent_on_set && command.starts_with("set ") {
                return None;
            }
            Some(reply)
        }

        fn reply_to(&mut self, command: &str) -> String {
            self.commands.push(command.to_string());
            let words: Vec<&str> = command.split(' ').collect();
            match words.as_slice() {
                ["show", "stat"] => self.stat(),
                ["set", "server", target, "state", state] => {
                    if let Some(refusal) = &self.refuse_with {
                        return refusal.clone();
                    }
                    let Some((backend, server)) = target.split_once('/') else {
                        return "Require 'backend/server'.\n\n".to_string();
                    };
                    if !self.servers.iter().any(|s| s.backend == backend) {
                        return "No such backend.\n\n".to_string();
                    }
                    let found = self
                        .servers
                        .iter_mut()
                        .find(|s| s.backend == backend && s.server == server);
                    let Some(entry) = found else {
                        return "No such server.\n\n".to_string();
                    };
                    entry.status = match *state {
                        "ready" => entry.in_service.clone(),
                        "drain" => "DRAIN".to_string(),
                        "maint" => "MAINT".to_string(),
                        _ => {
                            return "'set server <srv> state' expects 'ready', 'drain' and 'maint'.\n\n"
                                .to_string();
                        }
                    };
                    self.done_with.clone().unwrap_or_else(|| "\n".to_string())
                }
                _ => "Unknown command. Please enter one of the following commands only:\n\n"
                    .to_string(),
            }
        }
    }

    struct Site {
        dir: tempfile::TempDir,
        fake: Arc<Mutex<Fake>>,
    }

    impl Site {
        fn socket(&self) -> PathBuf {
            self.dir.path().join("admin.sock")
        }

        fn commands(&self) -> Vec<String> {
            self.fake.lock().unwrap().commands.clone()
        }

        fn status_of(&self, backend: &str, server: &str) -> String {
            let fake = self.fake.lock().unwrap();
            let entry = fake
                .servers
                .iter()
                .find(|s| s.backend == backend && s.server == server)
                .unwrap();
            entry.status.clone()
        }
    }

    /// Starts the stand-in with these servers: (backend, server, status, sessions).
    fn site(servers: &[(&str, &str, &str, u64)]) -> Site {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Mutex::new(Fake {
            servers: servers
                .iter()
                .map(|(backend, server, status, sessions)| FakeServer {
                    backend: backend.to_string(),
                    server: server.to_string(),
                    status: status.to_string(),
                    sessions: *sessions,
                    in_service: if *status == "no check" {
                        "no check"
                    } else {
                        "UP"
                    }
                    .to_string(),
                })
                .collect(),
            ..Fake::default()
        }));
        let listener = UnixListener::bind(dir.path().join("admin.sock")).unwrap();
        let shared = fake.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let shared = shared.clone();
                tokio::spawn(async move {
                    // one command line per connection, as HAProxy does without `prompt`
                    let mut line = Vec::new();
                    let mut byte = [0u8; 1];
                    while let Ok(1) = stream.read(&mut byte).await {
                        if byte[0] == b'\n' {
                            break;
                        }
                        line.push(byte[0]);
                    }
                    let command = String::from_utf8_lossy(&line).into_owned();
                    let reply = shared.lock().unwrap().answer(&command);
                    match reply {
                        Some(reply) => {
                            let _ = stream.write_all(reply.as_bytes()).await;
                            let _ = stream.shutdown().await;
                        }
                        None => {
                            // hold the connection until the client gives up
                            let _ = stream.read(&mut byte).await;
                        }
                    }
                });
            }
        });
        Site { dir, fake }
    }

    fn two_web_servers() -> Site {
        site(&[
            ("web", "web1", "UP", 7),
            ("web", "web2", "UP", 5),
            ("api", "api1", "UP", 3),
        ])
    }

    fn fixture(socket: &Path) -> (Arc<Host>, MemorySink) {
        fixture_with(socket, "")
    }

    fn fixture_with(socket: &Path, extra: &str) -> (Arc<Host>, MemorySink) {
        host(&format!(
            r#"
[roles.reader]
allow = ["@read"]
[roles.balancer]
allow = ["haproxy.server", "haproxy.view"]
[roles.web]
allow = ["haproxy.server:web/*", "haproxy.view:web/*"]
[roles.one]
allow = ["haproxy.server:web/web1", "haproxy.view:web/web1"]
[unix_users.rita]
roles = ["reader"]
[unix_users.bob]
roles = ["balancer"]
[unix_users.wendy]
roles = ["web"]
[unix_users.oscar]
roles = ["one"]
[haproxy]
socket = "{}"
{extra}
"#,
            socket.display()
        ))
    }

    async fn run(host: &Arc<Host>, user: &str, arguments: Value) -> ToolResult {
        call(
            host,
            user,
            &find(tools(), "haproxy_server_state"),
            arguments,
        )
        .await
    }

    /// Calls the read tool, `haproxy_servers`.
    async fn view(host: &Arc<Host>, user: &str, arguments: Value) -> ToolResult {
        call(host, user, &find(tools(), "haproxy_servers"), arguments).await
    }

    fn failed_text(result: ToolResult) -> String {
        match result {
            Ok(output) if output.is_error() => output.into_parts().0,
            other => panic!("expected a failed result, got {other:?}"),
        }
    }

    // ---- names ----

    #[test]
    fn a_name_is_what_haproxy_allows_and_can_never_carry_a_second_command() {
        for good in ["web", "web1", "be_app-1", "app.example.com:443", "A"] {
            assert!(check_name("backend", good).is_ok(), "{good}");
        }
        let long = "a".repeat(65);
        for bad in [
            "",
            "-web",
            "web 1",
            "web;shutdown sessions server web/web1",
            "web\nshow stat",
            "web\rx",
            "web/web1",
            "web\tx",
            "wéb",
            "web\0",
            long.as_str(),
        ] {
            match check_name("backend", bad) {
                Err(ToolError::Invalid(message)) => {
                    assert!(message.contains("backend"), "{message}")
                }
                other => panic!("{bad:?} should be refused, got {other:?}"),
            }
        }
        assert!(check_name("server", &"a".repeat(64)).is_ok());
    }

    // ---- reading `show stat` ----

    #[test]
    fn csv_records_keep_quoted_commas_and_line_breaks_inside_one_field() {
        let text = "a,b,c\n1,\"x, y\",3\n4,\"line one\nweb,evil,0\",\"say \"\"hi\"\"\"\n\n5,,\n";
        assert_eq!(
            csv_records(text),
            vec![
                vec!["a", "b", "c"],
                vec!["1", "x, y", "3"],
                vec!["4", "line one\nweb,evil,0", "say \"hi\""],
                vec!["5", "", ""],
            ]
        );
        // a final record without a line break, and CRLF line ends
        assert_eq!(
            csv_records("a,b\r\nc,d"),
            vec![vec!["a", "b"], vec!["c", "d"]]
        );
    }

    #[test]
    fn show_stat_is_read_by_its_column_names() {
        let text = format!(
            "{HEADER}\n{}\n{}\n{}\n{}\n\n",
            stat_line("www", "FRONTEND", 12, "OPEN", ""),
            stat_line("web", "web1", 7, "UP", "1"),
            stat_line("web", "web2", 0, "MAINT", "1"),
            stat_line("web", "BACKEND", 7, "UP", "1"),
        );
        let rows = parse_stat(&text).unwrap();
        assert_eq!(
            rows,
            vec![
                ServerRow {
                    backend: "web".into(),
                    server: "web1".into(),
                    status: "UP".into(),
                    sessions: Some(7),
                    weight: "1".into(),
                },
                ServerRow {
                    backend: "web".into(),
                    server: "web2".into(),
                    status: "MAINT".into(),
                    sessions: Some(0),
                    weight: "1".into(),
                },
            ]
        );

        // columns in another order, and without a `type` column (old HAProxy)
        let other = "# svname,status,pxname,scur,weight,\nweb1,UP 1/3,web,4,10,\nBACKEND,UP,web,4,10,\nFRONTEND,OPEN,web,4,,\n";
        let rows = parse_stat(other).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].server, "web1");
        assert_eq!(rows[0].status, "UP 1/3");
        assert_eq!(rows[0].sessions, Some(4));
        assert_eq!(rows[0].weight, "10");
    }

    #[test]
    fn a_listener_of_a_listen_section_is_not_taken_for_a_server() {
        // type 3 is a listening socket; it shares the proxy name with the servers
        let mut socket_line = stat_line("mixed", "sock-1", 0, "OPEN", "");
        socket_line = socket_line.replace(",2,0,,5,L7OK", ",3,0,,5,L7OK");
        let text = format!(
            "{HEADER}\n{socket_line}\n{}\n",
            stat_line("mixed", "app1", 1, "UP", "1")
        );
        let rows = parse_stat(&text).unwrap();
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].server, "app1");
    }

    #[test]
    fn a_health_check_text_cannot_add_a_server_of_its_own() {
        // the last field is free text from a health check; quoted, with a line break
        let line = format!(
            "{}\"503 oops\nweb,ghost,0,0,0,0,,0,0,0,0,0,,0,0,0,0,UP,1,1,0,0,0,0,0,,1,3,9,,0,,2,0,,0,,,,\"",
            stat_line("web", "web1", 7, "UP", "1")
        );
        let rows = parse_stat(&format!("{HEADER}last_chk,\n{line}\n")).unwrap();
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].server, "web1");
    }

    #[test]
    fn an_answer_that_is_not_the_statistics_table_is_an_error() {
        for text in ["", "Permission denied\n", "Unknown command.\n", "\n"] {
            let problem = parse_stat(text).unwrap_err();
            assert!(problem.contains("show stat"), "{problem}");
        }
        // the table without the columns that are needed
        assert!(parse_stat("# pxname,svname,\nweb,web1,\n").is_err());
    }

    // ---- show ----

    #[tokio::test]
    async fn show_lists_the_servers_of_one_backend() {
        let site = two_web_servers();
        let (host, audit) = fixture(&site.socket());
        let text = ok_text(view(&host, "bob", json!({"backend": "web"})).await);
        assert!(text.contains("SERVER"), "{text}");
        assert!(text.contains("web1"), "{text}");
        assert!(text.contains("web2"), "{text}");
        // the other backend's servers are not shown
        assert!(!text.contains("api1"), "{text}");
        // sessions in progress are what tells the agent a drain has finished
        let web1 = text.lines().find(|l| l.starts_with("web1")).unwrap();
        assert_eq!(
            web1.split_whitespace().collect::<Vec<_>>(),
            ["web1", "UP", "7", "1"]
        );
        assert_eq!(site.commands(), ["show stat"]);
        let records = audit.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["resource"], "web/");
        assert_eq!(records[0]["decision"], "allow");
    }

    #[tokio::test]
    async fn show_can_be_limited_to_one_server() {
        let site = two_web_servers();
        let (host, audit) = fixture(&site.socket());
        let arguments = json!({"backend": "web", "server": "web2"});
        let text = ok_text(view(&host, "bob", arguments).await);
        assert!(text.contains("web2"), "{text}");
        assert!(!text.lines().any(|l| l.starts_with("web1")), "{text}");
        assert_eq!(audit.records()[0]["resource"], "web/web2");
    }

    // ---- changes ----

    #[tokio::test]
    async fn drain_sends_one_set_server_command_and_shows_before_and_after() {
        let site = two_web_servers();
        let (host, audit) = fixture(&site.socket());
        let arguments = json!({"action": "drain", "backend": "web", "server": "web1"});
        let text = ok_text(run(&host, "bob", arguments).await);
        assert_eq!(
            site.commands(),
            ["show stat", "set server web/web1 state drain", "show stat"]
        );
        assert_eq!(site.status_of("web", "web1"), "DRAIN");
        // what was done, the table before and after, and how long it lasts
        assert!(text.contains("web/web1"), "{text}");
        let before = text.find("Before").unwrap();
        let after = text.find("After").unwrap();
        assert!(before < after, "{text}");
        assert!(text[before..after].contains("UP"), "{text}");
        assert!(text[after..].contains("DRAIN"), "{text}");
        assert!(text.contains("running HAProxy only"), "{text}");
        assert!(text.contains("reload"), "{text}");
        let records = audit.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["resource"], "web/web1");
    }

    #[tokio::test]
    async fn maint_and_ready_use_haproxys_own_words_for_the_state() {
        let site = two_web_servers();
        let (host, _audit) = fixture(&site.socket());
        let maint = json!({"action": "maint", "backend": "web", "server": "web2"});
        ok_text(run(&host, "bob", maint).await);
        assert_eq!(site.status_of("web", "web2"), "MAINT");
        let ready = json!({"action": "ready", "backend": "web", "server": "web2"});
        let text = ok_text(run(&host, "bob", ready).await);
        assert_eq!(site.status_of("web", "web2"), "UP");
        assert!(text.contains("ready"), "{text}");
        let sent: Vec<String> = site
            .commands()
            .into_iter()
            .filter(|c| c.starts_with("set "))
            .collect();
        assert_eq!(
            sent,
            [
                "set server web/web2 state maint",
                "set server web/web2 state ready"
            ]
        );
    }

    #[tokio::test]
    async fn a_change_needs_the_name_of_a_server() {
        let site = two_web_servers();
        let (host, audit) = fixture(&site.socket());
        for action in ["ready", "drain", "maint"] {
            let result = run(&host, "bob", json!({"action": action, "backend": "web"})).await;
            match result {
                Err(ToolError::Invalid(message)) => {
                    assert!(message.contains("server"), "{message}")
                }
                other => panic!("expected invalid arguments, got {other:?}"),
            }
        }
        assert!(site.commands().is_empty());
        assert!(audit.records().is_empty());
    }

    #[tokio::test]
    async fn the_last_server_that_is_up_is_not_drained_or_disabled_without_force() {
        let site = site(&[
            ("web", "web1", "UP", 7),
            ("web", "web2", "MAINT", 0),
            ("web", "web3", "DOWN", 0),
        ]);
        let (host, _audit) = fixture(&site.socket());
        for action in ["drain", "maint"] {
            let arguments = json!({"action": action, "backend": "web", "server": "web1"});
            let text = failed_text(run(&host, "bob", arguments).await);
            assert!(text.contains("last server"), "{text}");
            assert!(text.contains("force"), "{text}");
        }
        // HAProxy was asked for its state, and told nothing
        assert!(
            site.commands().iter().all(|c| c == "show stat"),
            "{:?}",
            site.commands()
        );
        assert_eq!(site.status_of("web", "web1"), "UP");

        let forced = json!({"action": "drain", "backend": "web", "server": "web1", "force": true});
        ok_text(run(&host, "bob", forced).await);
        assert_eq!(site.status_of("web", "web1"), "DRAIN");
    }

    #[tokio::test]
    async fn a_server_that_is_not_up_can_be_disabled_whatever_else_is_up() {
        let site = site(&[("web", "web1", "UP", 7), ("web", "web2", "DOWN", 0)]);
        let (host, _audit) = fixture(&site.socket());
        let arguments = json!({"action": "maint", "backend": "web", "server": "web2"});
        ok_text(run(&host, "bob", arguments).await);
        assert_eq!(site.status_of("web", "web2"), "MAINT");
    }

    #[tokio::test]
    async fn a_server_with_no_health_check_counts_as_up_for_the_guard() {
        let site = site(&[("web", "web1", "no check", 7), ("web", "web2", "MAINT", 0)]);
        let (host, _audit) = fixture(&site.socket());
        let arguments = json!({"action": "maint", "backend": "web", "server": "web1"});
        let text = failed_text(run(&host, "bob", arguments).await);
        assert!(text.contains("last server"), "{text}");
    }

    #[test]
    fn a_server_is_in_service_when_it_is_up_or_has_no_health_check() {
        let row = |status: &str| ServerRow {
            backend: "web".into(),
            server: "web1".into(),
            status: status.into(),
            sessions: Some(0),
            weight: "1".into(),
        };
        for status in ["UP", "UP 1/3", "UP 2/3", "no check"] {
            assert!(row(status).is_up(), "{status}");
        }
        for status in [
            "DOWN",
            "DOWN 1/2",
            "DOWN (agent)",
            "DRAIN",
            "MAINT",
            "MAINT (via web/web2)",
            "MAINT (resolution)",
            "NOLB",
            "",
        ] {
            assert!(!row(status).is_up(), "{status}");
        }
    }

    #[tokio::test]
    async fn servers_without_health_checks_are_guarded_like_any_other() {
        // what HAProxy shows for servers that have no `check`: status "no check"
        let site = site(&[
            ("web", "web1", "no check", 0),
            ("web", "web2", "no check", 0),
        ]);
        let (host, _audit) = fixture(&site.socket());
        let text = ok_text(view(&host, "bob", json!({"backend": "web"})).await);
        assert!(text.contains("2 servers, 2 up"), "{text}");
        assert!(text.contains("no check"), "{text}");

        // the first can go: the second still serves
        let first = json!({"action": "drain", "backend": "web", "server": "web1"});
        ok_text(run(&host, "bob", first).await);
        assert_eq!(site.status_of("web", "web1"), "DRAIN");

        // the second is now the last one in service
        let second = json!({"action": "drain", "backend": "web", "server": "web2"});
        let text = failed_text(run(&host, "bob", second.clone()).await);
        assert!(text.contains("last server"), "{text}");
        assert_eq!(site.status_of("web", "web2"), "no check");
        let sent: Vec<String> = site
            .commands()
            .into_iter()
            .filter(|c| c.starts_with("set "))
            .collect();
        assert_eq!(sent, ["set server web/web1 state drain"]);

        // forced, it goes too; and ready brings a server back to "no check"
        let mut forced = second;
        forced["force"] = json!(true);
        ok_text(run(&host, "bob", forced).await);
        assert_eq!(site.status_of("web", "web2"), "DRAIN");
        let back = json!({"action": "ready", "backend": "web", "server": "web1"});
        let text = ok_text(run(&host, "bob", back).await);
        assert_eq!(site.status_of("web", "web1"), "no check");
        let after = text.find("After").unwrap();
        assert!(text[after..].contains("no check"), "{text}");
    }

    #[tokio::test]
    async fn an_answer_of_nothing_but_white_space_means_the_change_was_made() {
        // HAProxy answers a successful `set server` with one empty line
        for done in ["\n", "", "\n\n", " \n"] {
            let site = two_web_servers();
            site.fake.lock().unwrap().done_with = Some(done.to_string());
            let (host, _audit) = fixture(&site.socket());
            let arguments = json!({"action": "maint", "backend": "web", "server": "web1"});
            let text = ok_text(run(&host, "bob", arguments).await);
            assert!(text.contains("Set web/web1 to maint"), "{done:?}: {text}");
            assert_eq!(site.status_of("web", "web1"), "MAINT");
        }
    }

    #[tokio::test]
    async fn haproxys_own_refusals_are_passed_on_in_one_line() {
        for refusal in [
            "No such server.\n\n",
            "No such backend.\n\n",
            "'set server <srv> state' expects 'ready', 'drain' and 'maint'.\n\n",
        ] {
            let site = two_web_servers();
            site.fake.lock().unwrap().refuse_with = Some(refusal.to_string());
            let (host, _audit) = fixture(&site.socket());
            let arguments = json!({"action": "drain", "backend": "web", "server": "web1"});
            let text = failed_text(run(&host, "bob", arguments).await);
            assert!(text.contains(refusal.trim()), "{text}");
            assert!(text.starts_with("HAProxy refused"), "{text}");
            assert_eq!(text.lines().count(), 1, "{text}");
            assert_eq!(site.status_of("web", "web1"), "UP");
        }
    }

    #[tokio::test]
    async fn a_backend_with_nothing_left_in_service_is_shown_as_such() {
        let site = site(&[("web", "web1", "DRAIN", 2), ("web", "web2", "MAINT", 0)]);
        let (host, _audit) = fixture(&site.socket());
        let text = ok_text(view(&host, "bob", json!({"backend": "web"})).await);
        assert!(text.contains("2 servers, 0 up"), "{text}");
        // the backend's own total line is not listed as if it were a server
        assert!(!text.contains("BACKEND"), "{text}");
        assert!(!text.contains("FRONTEND"), "{text}");
    }

    #[tokio::test]
    async fn haproxys_refusal_is_reported_as_a_failure() {
        let site = two_web_servers();
        site.fake.lock().unwrap().refuse_with = Some("Permission denied\n".to_string());
        let (host, _audit) = fixture(&site.socket());
        let arguments = json!({"action": "drain", "backend": "web", "server": "web1"});
        let text = failed_text(run(&host, "bob", arguments).await);
        assert!(text.contains("Permission denied"), "{text}");
        assert!(text.contains("level admin"), "{text}");
        assert_eq!(site.status_of("web", "web1"), "UP");
    }

    #[tokio::test]
    async fn an_unknown_backend_or_server_is_reported_only_to_a_caller_who_may_ask() {
        let site = two_web_servers();
        let (host, _audit) = fixture(&site.socket());
        let result = view(&host, "bob", json!({"backend": "nope"})).await;
        match result {
            Err(ToolError::Failed(message)) => assert!(message.contains("nope"), "{message}"),
            other => panic!("expected a failure, got {other:?}"),
        }
        let arguments = json!({"action": "drain", "backend": "web", "server": "web9"});
        match run(&host, "bob", arguments).await {
            Err(ToolError::Failed(message)) => assert!(message.contains("web9"), "{message}"),
            other => panic!("expected a failure, got {other:?}"),
        }
        assert!(site.commands().iter().all(|c| c == "show stat"));

        // wendy may only touch backend web: she learns nothing about other names
        let before = site.commands().len();
        for backend in ["api", "nope"] {
            let arguments = json!({"backend": backend});
            match view(&host, "wendy", arguments).await {
                Err(ToolError::Denied(message)) => {
                    assert!(message.contains("haproxy.view"), "{message}")
                }
                other => panic!("expected a denial, got {other:?}"),
            }
        }
        assert_eq!(
            site.commands().len(),
            before,
            "nothing was asked of HAProxy"
        );
    }

    #[tokio::test]
    async fn a_grant_can_be_limited_to_one_backend() {
        let site = two_web_servers();
        let (host, audit) = fixture(&site.socket());
        let web = json!({"action": "drain", "backend": "web", "server": "web1"});
        ok_text(run(&host, "wendy", web).await);
        ok_text(view(&host, "wendy", json!({"backend": "web"})).await);
        let api = json!({"action": "drain", "backend": "api", "server": "api1", "force": true});
        assert!(matches!(
            run(&host, "wendy", api).await,
            Err(ToolError::Denied(_))
        ));
        assert_eq!(site.status_of("api", "api1"), "UP");
        let last = audit.records().pop().unwrap();
        assert_eq!(last["decision"], "deny");
        assert_eq!(last["resource"], "api/api1");
    }

    #[tokio::test]
    async fn a_caller_granted_one_server_is_shown_only_that_server() {
        let site = two_web_servers();
        let (host, _audit) = fixture(&site.socket());
        // the whole backend is more than oscar was granted
        assert!(matches!(
            view(&host, "oscar", json!({"backend": "web"})).await,
            Err(ToolError::Denied(_))
        ));
        assert!(site.commands().is_empty());

        let arguments = json!({"action": "drain", "backend": "web", "server": "web1"});
        let text = ok_text(run(&host, "oscar", arguments).await);
        assert_eq!(site.status_of("web", "web1"), "DRAIN");
        assert!(text.contains("web1"), "{text}");
        assert!(!text.contains("web2"), "{text}");
        assert!(text.contains("some servers are not shown"), "{text}");
    }

    /// AIDEV-NOTE: the header of a listing counted every server of the backend, also
    /// the ones the table leaves out: a caller told "3 servers, 2 up" and shown one row
    /// has learnt how many others there are and how they fare.
    #[tokio::test]
    async fn the_counts_in_a_listing_cover_only_the_servers_the_caller_is_shown() {
        let site = site(&[
            ("web", "web1", "UP", 7),
            ("web", "web2", "DOWN", 0),
            ("web", "web3", "UP", 2),
        ]);
        // may list the backend, but not see web2 or web3
        let extra = "[roles.partial]\nallow = [\"haproxy.view:web/*\"]\n\
                     deny = [\"haproxy.view:web/web2\", \"haproxy.view:web/web3\"]\n\
                     [unix_users.pat]\nroles = [\"partial\"]\n";
        let (host, _audit) = fixture_with(&site.socket(), extra);
        let text = ok_text(view(&host, "pat", json!({"backend": "web"})).await);
        assert!(
            text.starts_with("Backend web in HAProxy: 1 server, 1 up.\n"),
            "{text}"
        );
        assert!(text.contains("web1"), "{text}");
        assert!(!text.contains("web2") && !text.contains("web3"), "{text}");
        assert!(text.contains("some servers are not shown"), "{text}");
        // neither the real total nor the real number that are up appears anywhere
        assert!(
            !text.contains("3 servers") && !text.contains("2 up"),
            "{text}"
        );

        // a caller who may see them all gets the real figures
        let text = ok_text(view(&host, "bob", json!({"backend": "web"})).await);
        assert!(
            text.starts_with("Backend web in HAProxy: 3 servers, 2 up.\n"),
            "{text}"
        );
    }

    /// AIDEV-NOTE: `show stat` covers every proxy of the HAProxy, not just the backend
    /// asked about, and is read whole before a change as well. A few thousand servers
    /// are more than 4 MiB of it.
    #[tokio::test]
    async fn a_statistics_table_of_several_megabytes_is_still_read() {
        let names: Vec<String> = (0..50_000).map(|n| format!("app{n:05}")).collect();
        let servers: Vec<(&str, &str, &str, u64)> = names
            .iter()
            .map(|name| ("big", name.as_str(), "UP", 1))
            .collect();
        let site = site(&servers);
        let size = site.fake.lock().unwrap().stat().len();
        assert!(size > 4 * 1024 * 1024 && size < MAX_REPLY, "{size} bytes");
        let (host, _audit) = fixture(&site.socket());
        let arguments = json!({"backend": "big", "server": "app00042"});
        let text = ok_text(view(&host, "bob", arguments).await);
        assert!(text.contains("app00042"), "{text}");
    }

    #[tokio::test]
    async fn a_very_large_backend_is_cut_to_the_output_limit_with_a_note() {
        let names: Vec<String> = (0..3000).map(|n| format!("app{n:04}")).collect();
        let servers: Vec<(&str, &str, &str, u64)> = names
            .iter()
            .map(|name| ("big", name.as_str(), "UP", 1))
            .collect();
        let site = site(&servers);
        let (host, _audit) = fixture_with(&site.socket(), "[limits]\nmax_output_bytes = 4096\n");
        let text = ok_text(view(&host, "bob", json!({"backend": "big"})).await);
        assert!(text.len() <= 4096, "{} bytes", text.len());
        assert!(text.contains("3000 servers"), "{text}");
        assert!(text.contains("app0000"), "{text}");
        assert!(text.contains("left out"), "{text}");

        // after a change, what matters most is said before the tables
        let arguments = json!({"action": "drain", "backend": "big", "server": "app0001"});
        let text = ok_text(run(&host, "bob", arguments).await);
        assert!(text.len() <= 4096, "{} bytes", text.len());
        assert!(text.starts_with("Set big/app0001 to drain"), "{text}");
        assert!(text.contains("running HAProxy only"), "{text}");
        assert!(text.contains("left out"), "{text}");
        assert_eq!(site.status_of("big", "app0001"), "DRAIN");
    }

    /// AIDEV-NOTE: looking and changing are two tools because a tool is either read or
    /// write. `@read` must cover watching a drain; it must never cover starting one.
    #[tokio::test]
    async fn read_access_covers_looking_at_servers_and_never_changing_them() {
        let site = two_web_servers();
        let (host, audit) = fixture(&site.socket());
        // rita holds @read and nothing else
        let text = ok_text(view(&host, "rita", json!({"backend": "web"})).await);
        assert!(
            text.starts_with("Backend web in HAProxy: 2 servers, 2 up.\n"),
            "{text}"
        );
        assert!(text.contains("web1") && text.contains("web2"), "{text}");
        assert_eq!(audit.records()[0]["permission"], "haproxy.view");

        for state in ["drain", "maint", "ready"] {
            let arguments = json!({"action": state, "backend": "web", "server": "web1"});
            assert!(matches!(
                run(&host, "rita", arguments).await,
                Err(ToolError::Denied(_))
            ));
        }
        // nothing but the listing ever reached HAProxy
        assert_eq!(site.commands(), ["show stat"]);
        assert_eq!(site.status_of("web", "web1"), "UP");

        let look = find(tools(), "haproxy_servers");
        assert_eq!(look.access, Access::Read);
        assert_eq!(look.permission, "haproxy.view");
        let change = find(tools(), "haproxy_server_state");
        assert_eq!(change.access, Access::Write);
        assert_eq!(change.permission, "haproxy.server");
    }

    #[tokio::test]
    async fn the_tool_that_changes_servers_no_longer_lists_them() {
        let site = two_web_servers();
        let (host, _audit) = fixture(&site.socket());
        let result = run(&host, "bob", json!({"action": "show", "backend": "web"})).await;
        assert!(matches!(result, Err(ToolError::Invalid(_))), "{result:?}");
        // and it always needs a server to act on
        let result = run(&host, "bob", json!({"action": "drain", "backend": "web"})).await;
        assert!(matches!(result, Err(ToolError::Invalid(_))), "{result:?}");
        assert!(site.commands().is_empty());
    }

    #[tokio::test]
    async fn without_a_backend_every_backend_is_listed() {
        let site = site(&[
            ("web", "web1", "UP", 7),
            ("web", "web2", "DRAIN", 5),
            ("api", "api1", "no check", 3),
        ]);
        let (host, audit) = fixture(&site.socket());
        let text = ok_text(view(&host, "rita", json!({})).await);
        assert!(
            text.starts_with("HAProxy: 2 backends, 3 servers, 2 up.\n"),
            "{text}"
        );
        let row = |server: &str| -> Vec<String> {
            text.lines()
                .find(|line| line.split_whitespace().nth(1) == Some(server))
                .unwrap_or_else(|| panic!("no row for {server}: {text}"))
                .split_whitespace()
                .map(str::to_string)
                .collect()
        };
        assert_eq!(row("web2"), ["web", "web2", "DRAIN", "5", "1"]);
        assert_eq!(row("api1"), ["api", "api1", "no", "check", "3", "1"]);
        assert!(text.contains("BACKEND"), "{text}");
        // the whole of HAProxy is an operation that names no resource
        let records = audit.records();
        assert_eq!(records.len(), 1);
        assert!(records[0].get("resource").is_none(), "{:?}", records[0]);
    }

    #[tokio::test]
    async fn a_caller_limited_to_one_backend_cannot_list_them_all() {
        let site = two_web_servers();
        let (host, _audit) = fixture(&site.socket());
        // wendy holds haproxy.view for web/* only
        assert!(matches!(
            view(&host, "wendy", json!({})).await,
            Err(ToolError::Denied(_))
        ));
        assert!(site.commands().is_empty());
        ok_text(view(&host, "wendy", json!({"backend": "web"})).await);
    }

    #[tokio::test]
    async fn a_server_can_only_be_named_within_a_backend() {
        let site = two_web_servers();
        let (host, _audit) = fixture(&site.socket());
        let result = view(&host, "bob", json!({"server": "web1"})).await;
        assert!(matches!(result, Err(ToolError::Invalid(_))), "{result:?}");
        assert!(site.commands().is_empty());
    }

    #[tokio::test]
    async fn a_name_that_could_carry_a_command_never_reaches_the_socket() {
        let site = two_web_servers();
        let (host, audit) = fixture(&site.socket());
        for (backend, server) in [
            ("web;shutdown sessions server web/web2", "web1"),
            ("web", "web1 ; disable server web/web2"),
            ("web", "web1\nset server web/web2 state maint"),
            ("-web", "web1"),
        ] {
            let arguments = json!({"action": "drain", "backend": backend, "server": server});
            assert!(
                matches!(
                    run(&host, "bob", arguments).await,
                    Err(ToolError::Invalid(_))
                ),
                "{backend:?} {server:?}"
            );
        }
        assert!(site.commands().is_empty());
        assert!(audit.records().is_empty());
    }

    // ---- the socket ----

    #[tokio::test]
    async fn a_missing_socket_is_explained() {
        let dir = tempfile::tempdir().unwrap();
        let (host, _audit) = fixture(&dir.path().join("admin.sock"));
        match view(&host, "bob", json!({"backend": "web"})).await {
            Err(ToolError::Failed(message)) => {
                assert!(message.contains("admin.sock"), "{message}");
                assert!(message.contains("haproxy.socket"), "{message}");
            }
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn something_that_is_not_a_socket_is_not_talked_to() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("admin.sock");
        std::fs::write(&path, "not a socket").unwrap();
        let (host, _audit) = fixture(&path);
        match view(&host, "bob", json!({"backend": "web"})).await {
            Err(ToolError::Failed(message)) => {
                assert!(message.contains("not a socket"), "{message}")
            }
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_socket_that_never_answers_is_given_up_on() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("admin.sock");
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream); // accepted, then silence
            }
        });
        let (host, _audit) = fixture(&path);
        let tool = find(tools(), "haproxy_servers");
        let arguments = json!({"backend": "web"});
        let args = Args::parse(&tool.params, Some(&arguments)).unwrap();
        let started = std::time::Instant::now();
        let result = haproxy_servers(
            ctx(&host, "bob", "haproxy.view", Access::Read),
            args,
            Duration::from_millis(200),
        )
        .await;
        assert!(started.elapsed() < Duration::from_secs(3));
        match result {
            Err(ToolError::Failed(message)) => {
                assert!(message.contains("did not answer"), "{message}")
            }
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_change_that_gets_no_answer_is_said_to_be_of_unknown_outcome() {
        let site = two_web_servers();
        site.fake.lock().unwrap().silent_on_set = true;
        let (host, _audit) = fixture(&site.socket());
        let tool = find(tools(), "haproxy_server_state");
        let arguments = json!({"action": "drain", "backend": "web", "server": "web1"});
        let args = Args::parse(&tool.params, Some(&arguments)).unwrap();
        let result = haproxy_server_state(
            ctx(&host, "bob", "haproxy.server", Access::Write),
            args,
            Duration::from_millis(300),
        )
        .await;
        let text = failed_text(result);
        assert!(text.contains("did not answer"), "{text}");
        // the command was sent, so the server may well be draining now
        assert!(text.contains("not known"), "{text}");
        assert!(text.contains("haproxy_servers"), "{text}");
    }

    #[tokio::test]
    async fn an_answer_is_read_up_to_a_limit_and_no_further() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("admin.sock");
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let chunk = [b'x'; 4096];
                    // far more than anyone should keep; stops when the reader hangs up
                    for _ in 0..100_000 {
                        if stream.write_all(&chunk).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        let problem = ask(&path, "show stat", Duration::from_secs(5), 64 * 1024)
            .await
            .unwrap_err();
        assert!(problem.contains("more than"), "{problem}");
    }

    #[tokio::test]
    async fn one_command_is_one_line_on_the_socket() {
        let site = two_web_servers();
        let reply = ask(
            &site.socket(),
            "show stat",
            Duration::from_secs(5),
            MAX_REPLY,
        )
        .await
        .unwrap();
        assert!(reply.starts_with("# pxname,svname,"), "{reply}");
        assert_eq!(site.commands(), ["show stat"]);
        // a command with a line break in it is never sent, whoever asks
        let problem = ask(
            &site.socket(),
            "show stat\nshow info",
            Duration::from_secs(5),
            MAX_REPLY,
        )
        .await
        .unwrap_err();
        assert!(problem.contains("one line"), "{problem}");
        assert_eq!(site.commands(), ["show stat"]);
    }
}
