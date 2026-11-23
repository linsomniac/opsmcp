//! The tools the server offers, and the context a tool runs in.

pub mod args;
pub mod checks;
pub mod cluster;
pub mod container;
mod ctx;
pub mod custom;
pub mod cve;
pub mod db;
pub mod denials;
pub mod dns;
pub mod edit;
pub mod firewall;
pub mod fs;
pub mod fwset;
pub mod haproxy;
pub mod hardware;
pub mod headroom;
pub mod history;
pub mod kernel;
pub mod kernelinfo;
pub mod logs;
pub mod lvm;
pub mod monitoring;
pub mod mounts;
pub mod net;
pub mod nrpe;
pub mod package;
pub mod paths;
pub mod posture;
pub mod process;
pub mod reboot;
pub mod reclaim;
pub mod schedule;
pub mod search;
pub mod service;
pub mod sessions;
pub mod storage;
pub mod system;
pub mod timesync;
pub mod tls;
pub mod trace;
pub mod triage;
pub mod unitres;
pub mod users;
pub mod wait;

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::exec::CmdOutput;
use crate::policy::Access;
use crate::sanitize::keep_tail;
use args::{Args, Param};
pub use ctx::{Authorized, Call, Ctx, Host, Output, ToolError};

pub type ToolResult = Result<Output, ToolError>;
type HandlerFuture = Pin<Box<dyn Future<Output = ToolResult> + Send>>;
type Handler = Arc<dyn Fn(Ctx, Args) -> HandlerFuture + Send + Sync>;

/// One tool: what the agent sees, what permission it needs, and the code behind it.
pub struct Tool {
    pub name: String,
    pub description: String,
    pub access: Access,
    pub permission: String,
    pub params: Vec<Param>,
    handler: Handler,
}

impl Tool {
    pub fn new<F, Fut>(
        name: &str,
        description: &str,
        access: Access,
        permission: &str,
        params: Vec<Param>,
        handler: F,
    ) -> Tool
    where
        F: Fn(Ctx, Args) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ToolResult> + Send + 'static,
    {
        Tool {
            name: name.to_string(),
            description: description.to_string(),
            access,
            permission: permission.to_string(),
            params,
            handler: Arc::new(move |ctx, args| Box::pin(handler(ctx, args))),
        }
    }

    /// Runs the tool. The caller has already checked `Rules::may_use` and the arguments.
    pub fn run(&self, ctx: Ctx, args: Args) -> impl Future<Output = ToolResult> + Send + 'static {
        (self.handler)(ctx, args)
    }
}

/// Runs blocking work (file reads, directory walks) off the async threads.
///
/// AIDEV-NOTE: a blocking job cannot be cancelled. If the kernel never completes a read
/// (a dead NFS server, a process stuck in the kernel), the call that started the job
/// times out but the job's thread stays stuck. Each job therefore holds one of a fixed
/// number of slots until it really finishes; when stuck jobs hold them all, new jobs are
/// refused at once instead of piling up threads until the runtime has none left.
pub async fn blocking<T, F>(ctx: Ctx, work: F) -> Result<T, ToolError>
where
    F: FnOnce() -> Result<T, ToolError> + Send + 'static,
    T: Send + 'static,
{
    let Ok(slot) = ctx.blocking_slots().try_acquire_owned() else {
        return Err(ToolError::Failed(
            "The server is busy: earlier reads of files or /proc have not finished \
             (a hung network filesystem can cause this). Try again later."
                .to_string(),
        ));
    };
    tokio::task::spawn_blocking(move || {
        let _held_until_done = slot;
        work()
    })
    .await
    .map_err(|e| ToolError::Internal(format!("blocking task failed: {e}")))?
}

/// The time that the commands of one call share.
///
/// AIDEV-NOTE: a call that outlasts `limits.call_timeout_secs` is cut off and returns
/// nothing at all. A tool that runs several commands one after another therefore gives
/// each of them at most what is left of the call, keeps some back for sending the
/// answer, and starts no command once nothing is left. One section saying that it ran
/// out of time is better than no answer.
pub struct CallClock {
    deadline: Instant,
    command: Duration,
}

impl CallClock {
    /// Starts the clock: call it when the tool begins.
    pub fn start(ctx: &Ctx) -> CallClock {
        let limits = &ctx.cfg().limits;
        // Kept back for putting the answer together: a quarter of the call, at least a
        // second and at most ten.
        let reserve = (limits.call_timeout_secs / 4).clamp(1, 10);
        let usable = limits.call_timeout_secs.saturating_sub(reserve);
        CallClock {
            deadline: Instant::now() + Duration::from_secs(usable),
            command: Duration::from_secs(limits.command_timeout_secs),
        }
    }

    /// The time limit for the next command: the usual limit for a command, or what is
    /// left of the call if that is less. `None` when there is too little left to be
    /// worth starting one.
    pub fn next(&self) -> Option<Duration> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        (left >= Duration::from_secs(1)).then(|| self.command.min(left))
    }
}

/// A required string argument. (The dispatcher has already checked it is present; this
/// keeps tools free of unwraps.)
pub fn required<'a>(args: &'a Args, name: &str) -> Result<&'a str, ToolError> {
    args.str(name)
        .ok_or_else(|| ToolError::Invalid(format!("missing required argument {name:?}")))
}

/// The text shown to the agent for a finished command: its output, then bracketed notes
/// for anything that went wrong.
pub fn command_text(out: &CmdOutput) -> String {
    fn end_line(text: &mut String) {
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
    }
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !stderr.trim().is_empty() {
        end_line(&mut text);
        text.push_str(&stderr);
    }
    let mut notes = Vec::new();
    if out.truncated {
        notes.push("[output truncated: the command produced more than is kept]".to_string());
    }
    if out.timed_out {
        notes.push("[the command was stopped when it reached its time limit]".to_string());
    } else if let Some(signal) = out.signal {
        notes.push(format!("[the command was killed by signal {signal}]"));
    } else if let Some(code) = out.code
        && code != 0
    {
        notes.push(format!("[exit status {code}]"));
    }
    for note in notes {
        end_line(&mut text);
        text.push_str(&note);
        text.push('\n');
    }
    text
}

/// A plain-text table: columns two spaces apart, sized to their widest cell. Columns
/// flagged in `right` are right-aligned. The last column is never padded, so lines have
/// no trailing spaces.
pub fn format_table(headers: &[&str], rows: &[Vec<String>], right: &[bool]) -> String {
    let mut all = Vec::with_capacity(rows.len() + 1);
    all.push(headers.iter().map(|h| h.to_string()).collect());
    all.extend(rows.iter().cloned());
    format_rows(&all, right)
}

/// `format_table` without a header line.
///
/// AIDEV-NOTE: cells hold host data (a process's arguments, a file name, a drive's model
/// string). A line break inside a cell would let that data add rows of its own that look
/// like the tool's, so line breaks and tabs in cells are shown as `\\n`, `\\r`, `\\t`.
pub fn format_rows(rows: &[Vec<String>], right: &[bool]) -> String {
    let rows: Vec<Vec<String>> = rows
        .iter()
        .map(|row| row.iter().map(|cell| one_line_cell(cell)).collect())
        .collect();
    let columns = rows.iter().map(Vec::len).max().unwrap_or(0);
    let widths: Vec<usize> = (0..columns)
        .map(|column| {
            rows.iter()
                .filter_map(|row| row.get(column))
                .map(|cell| cell.chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    let mut out = String::new();
    for row in &rows {
        for (column, cell) in row.iter().enumerate() {
            if column > 0 {
                out.push_str("  ");
            }
            let width = widths.get(column).copied().unwrap_or(0);
            let pad = " ".repeat(width.saturating_sub(cell.chars().count()));
            if right.get(column) == Some(&true) {
                out.push_str(&pad);
                out.push_str(cell);
            } else {
                out.push_str(cell);
                if column + 1 != columns {
                    out.push_str(&pad);
                }
            }
        }
        out.push('\n');
    }
    out
}

/// A value on one line: line breaks and tabs become visible escapes. For host data that
/// is placed in a table cell or on a line of the tool's own.
pub fn one_line_cell(text: &str) -> String {
    if !text.contains(['\n', '\r', '\t']) {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

/// `command_text` for output whose END matters most (logs): if it would be longer than
/// `budget`, the oldest lines of stdout are left out, with a note saying how many.
pub fn command_text_tail(out: &CmdOutput, budget: usize) -> String {
    // What the command said went wrong (stderr, exit status) is always kept.
    let mut without_stdout = out.clone();
    without_stdout.stdout.clear();
    let trailer = command_text(&without_stdout);
    let room = budget.saturating_sub(trailer.len() + 120);
    let (body, dropped) = keep_tail(&String::from_utf8_lossy(&out.stdout), room);
    let mut text = String::new();
    if dropped > 0 {
        text.push_str(&format!(
            "[{dropped} earlier lines left out to fit the output limit; ask for fewer or narrow the query]\n"
        ));
    }
    text.push_str(&body);
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&trailer);
    text
}

/// True when the command ran to completion and exited 0.
pub fn command_ok(out: &CmdOutput) -> bool {
    out.code == Some(0) && !out.timed_out
}

/// Every built-in tool.
fn built_in_tools() -> Vec<Tool> {
    let mut tools = Vec::new();
    tools.extend(system::tools());
    tools.extend(process::tools());
    tools.extend(service::tools());
    tools.extend(logs::tools());
    tools.extend(fs::tools());
    tools.extend(kernel::tools());
    tools.extend(firewall::tools());
    tools.extend(container::tools());
    tools.extend(cluster::tools());
    tools.extend(nrpe::tools());
    tools.extend(net::tools());
    tools.extend(tls::tools());
    tools.extend(package::tools());
    tools.extend(reboot::tools());
    tools.extend(storage::tools());
    tools.extend(triage::tools());
    tools.extend(users::tools());
    tools.extend(timesync::tools());
    tools.extend(schedule::tools());
    tools.extend(checks::tools());
    tools.extend(history::tools());
    tools.extend(wait::tools());
    tools.extend(search::tools());
    tools.extend(edit::tools());
    tools.extend(monitoring::tools());
    tools.extend(haproxy::tools());
    tools.extend(reclaim::tools());
    tools.extend(lvm::tools());
    tools.extend(mounts::tools());
    tools.extend(unitres::tools());
    tools.extend(sessions::tools());
    tools.extend(trace::tools());
    tools.extend(headroom::tools());
    tools.extend(denials::tools());
    tools.extend(fwset::tools());
    tools.extend(dns::tools());
    tools.extend(posture::tools());
    tools.extend(cve::tools());
    tools.extend(db::tools());
    tools.extend(kernelinfo::tools());
    tools.extend(hardware::tools());
    tools
}

/// The set of tools on offer.
#[derive(Default)]
pub struct Registry {
    tools: BTreeMap<String, Arc<Tool>>,
}

impl Registry {
    /// Adds a tool, refusing duplicates and malformed names.
    pub fn add(&mut self, tool: Tool) -> Result<(), String> {
        let name = &tool.name;
        let mut chars = name.chars();
        let name_ok = name.len() <= 64
            && chars.next().is_some_and(|c| c.is_ascii_lowercase())
            && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        if !name_ok {
            return Err(format!("{name:?} is not a valid tool name"));
        }
        // A permission is a plain name: no globs and no groups, those belong in grants.
        let permission_ok = !tool.permission.is_empty()
            && tool
                .permission
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "_.-".contains(c));
        if !permission_ok {
            return Err(format!(
                "tool {name}: {:?} is not a valid permission name",
                tool.permission
            ));
        }
        if self.tools.contains_key(name) {
            return Err(format!("there is already a tool named {name}"));
        }
        self.tools.insert(name.clone(), Arc::new(tool));
        Ok(())
    }

    /// The tools for a host: every built-in tool the configuration has not disabled,
    /// plus the operator's custom tools. Returns the registry and any warnings, or every
    /// problem found.
    pub fn build(cfg: &Config) -> Result<(Registry, Vec<String>), Vec<String>> {
        let mut registry = Registry::default();
        let mut errors = Vec::new();
        // Grants are checked against every permission that could exist here, including
        // those of disabled tools: disabling a tool on one host should not make a shared
        // roles file invalid there.
        let mut known: Vec<(String, Access)> = Vec::new();
        let mut built_in_names = Vec::new();

        for tool in built_in_tools() {
            known.push((tool.permission.clone(), tool.access));
            built_in_names.push(tool.name.clone());
            if cfg.tools.disabled.contains(&tool.name) {
                continue;
            }
            if let Err(e) = registry.add(tool) {
                errors.push(e);
            }
        }
        for name in &cfg.tools.disabled {
            if !built_in_names.contains(name) {
                errors.push(format!(
                    "tools.disabled: there is no built-in tool named {name:?}"
                ));
            }
        }
        for (name, custom) in &cfg.custom {
            if built_in_names.contains(name) {
                errors.push(format!(
                    "custom.{name}: {name} is the name of a built-in tool"
                ));
                continue;
            }
            match custom::tool(name, custom) {
                Ok(tool) => {
                    known.push((tool.permission.clone(), tool.access));
                    if let Err(e) = registry.add(tool) {
                        errors.push(format!("custom.{name}: {e}"));
                    }
                }
                Err(e) => errors.push(e),
            }
        }

        let grants = cfg.validate_grants(&known);
        errors.extend(grants.errors);
        if errors.is_empty() {
            Ok((registry, grants.warnings))
        } else {
            Err(errors)
        }
    }

    pub fn get(&self, name: &str) -> Option<Arc<Tool>> {
        self.tools.get(name).cloned()
    }

    pub fn tools(&self) -> impl Iterator<Item = &Arc<Tool>> {
        self.tools.values()
    }
}

#[cfg(test)]
pub mod testing {
    //! Helpers for tests that need a `Host` or a `Ctx`.
    use super::*;
    use crate::audit::Audit;
    use crate::audit::testing::MemorySink;
    use crate::exec::Bins;
    use serde_json::{Value, json};

    /// A host with the given configuration text and an in-memory audit sink.
    pub fn host(config: &str) -> (Arc<Host>, MemorySink) {
        host_with_trust(config, None)
    }

    /// Like `host`, but choosing whether programs must be owned by root (or one of the
    /// given uids), as they must when the server runs as root.
    pub fn host_with_trust(config: &str, trust: Option<Vec<u32>>) -> (Arc<Host>, MemorySink) {
        let cfg = Config::parse(config).unwrap();
        let sink = MemorySink::default();
        let audit = Audit::with_sinks(vec![Box::new(sink.clone())], cfg.audit.fail_closed);
        let bins = Bins::new(&cfg.paths, trust);
        (Arc::new(Host::new(cfg, bins, audit)), sink)
    }

    /// Runs one tool as Unix user `user`, the way the dispatcher would after its own
    /// checks: arguments validated, then the handler.
    pub async fn call(host: &Arc<Host>, user: &str, tool: &Tool, arguments: Value) -> ToolResult {
        let args = Args::parse(&tool.params, Some(&arguments)).map_err(ToolError::Invalid)?;
        let principal = host.cfg.principal_for_unix(user, &[]).unwrap();
        let call = Call {
            id: "test-1".to_string(),
            transport: "test",
            peer: None,
            principal: Arc::new(principal),
            tool: tool.name.clone(),
            permission: tool.permission.clone(),
            access: tool.access,
            args: arguments,
            args_sha256: None,
            read_only: false,
            via: None,
        };
        tool.run(Ctx::new(host.clone(), Arc::new(call)), args).await
    }

    /// The tool with this name from a module's tool list.
    pub fn find(tools: Vec<Tool>, name: &str) -> Tool {
        tools.into_iter().find(|t| t.name == name).unwrap()
    }

    /// The text of a successful result; fails the test otherwise.
    pub fn ok_text(result: ToolResult) -> String {
        match result {
            Ok(output) if !output.is_error() => output.into_parts().0,
            other => panic!("expected success, got {other:?}"),
        }
    }

    /// Creates an executable script for a test to run.
    ///
    /// AIDEV-NOTE: the file is written by a child process, never by this one. If this
    /// process held it open for writing, a test thread that forked at that moment would
    /// inherit the descriptor, and running the script would fail with "Text file busy"
    /// until that other child had exec'ed. That made tests fail at random under load.
    pub fn write_executable(path: &std::path::Path, content: &str) {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut writer = Command::new("/bin/sh")
            .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
            .arg(path)
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        writer
            .stdin
            .take()
            .unwrap()
            .write_all(content.as_bytes())
            .unwrap();
        assert!(writer.wait().unwrap().success(), "writing {path:?}");
    }

    /// Stand-ins for system commands (systemctl, journalctl...): small scripts that record
    /// the arguments they were run with and print canned output. Tests use them to check
    /// exactly what a tool would run, and that it runs nothing when it should not.
    pub struct FakeBins {
        dir: tempfile::TempDir,
        names: Vec<String>,
    }

    impl FakeBins {
        pub fn new() -> FakeBins {
            FakeBins {
                dir: tempfile::tempdir().unwrap(),
                names: Vec::new(),
            }
        }

        /// Adds a command that prints `stdout` and exits with `code`.
        pub fn add(self, name: &str, stdout: &str, code: i32) -> FakeBins {
            let out = format!("{}/{name}.out", self.dir.path().display());
            std::fs::write(&out, stdout).unwrap();
            let body = format!(
                "while IFS= read -r line; do printf '%s\\n' \"$line\"; done < '{out}'\nexit {code}\n"
            );
            self.add_script(name, &body)
        }

        /// Adds a command whose behaviour is the shell fragment `body` (it sees the
        /// arguments as "$@"). Its arguments are recorded before `body` runs.
        ///
        /// AIDEV-NOTE: the record of one run is ONE line, appended with one write: the
        /// arguments with a file-separator character after each, and line breaks inside
        /// an argument written as a group-separator character. Tools run the same command
        /// several times at once (mount_health probes mounts in parallel). A record of
        /// several lines is not safe: bash writes it a line at a time, so the records of
        /// two runs interleaved and tests failed at random under load. Only shell
        /// builtins are used: a stand-in has no other commands on its PATH.
        pub fn add_script(mut self, name: &str, body: &str) -> FakeBins {
            let dir = self.dir.path().display().to_string();
            let script = format!(
                "#!/bin/sh\n\
                 opsmcp_sep=$(printf '\\034')\n\
                 opsmcp_nl=$(printf '\\035')\n\
                 opsmcp_lf='\n\
                 '\n\
                 opsmcp_record=''\n\
                 for opsmcp_arg in \"$@\"; do\n\
                 while :; do\n\
                 case $opsmcp_arg in\n\
                 *\"$opsmcp_lf\"*) opsmcp_record=\"$opsmcp_record${{opsmcp_arg%%\"$opsmcp_lf\"*}}$opsmcp_nl\"; opsmcp_arg=${{opsmcp_arg#*\"$opsmcp_lf\"}} ;;\n\
                 *) opsmcp_record=\"$opsmcp_record$opsmcp_arg$opsmcp_sep\"; break ;;\n\
                 esac\n\
                 done\n\
                 done\n\
                 printf '%s\\n' \"$opsmcp_record\" >> '{dir}/{name}.calls'\n\
                 {body}\n"
            );
            write_executable(std::path::Path::new(&format!("{dir}/{name}")), &script);
            self.names.push(name.to_string());
            self
        }

        /// The configuration that makes the server use these commands and find no others,
        /// whatever happens to be installed on the machine running the tests.
        pub fn config_only(&self) -> String {
            format!("[paths]\nsearch = [\"/nonexistent\"]\n{}", self.config())
        }

        /// The `[paths.bin]` configuration that makes the server use these commands.
        pub fn config(&self) -> String {
            let mut text = "[paths.bin]\n".to_string();
            for name in &self.names {
                text.push_str(&format!(
                    "\"{name}\" = \"{}/{name}\"\n",
                    self.dir.path().display()
                ));
            }
            text
        }

        /// The argument list of every run of `name` so far.
        pub fn calls(&self, name: &str) -> Vec<Vec<String>> {
            let path = format!("{}/{name}.calls", self.dir.path().display());
            let Ok(text) = std::fs::read_to_string(path) else {
                return Vec::new();
            };
            // One run per line; see `add_script` for the format.
            text.lines()
                .map(|line| {
                    let mut arguments: Vec<String> = line
                        .split('\u{1c}')
                        .map(|argument| argument.replace('\u{1d}', "\n"))
                        .collect();
                    // every argument is FOLLOWED by a separator: the last piece is empty
                    arguments.pop();
                    arguments
                })
                .collect()
        }
    }

    /// A context for a call by Unix user `user` to a tool with this permission.
    pub fn ctx(host: &Arc<Host>, user: &str, permission: &str, access: Access) -> Ctx {
        let principal = host.cfg.principal_for_unix(user, &[]).unwrap();
        let call = Call {
            id: "test-1".to_string(),
            transport: "test",
            peer: None,
            principal: Arc::new(principal),
            tool: "test_tool".to_string(),
            permission: permission.to_string(),
            access,
            args: json!({"name": "value"}),
            args_sha256: None,
            read_only: false,
            via: None,
        };
        Ctx::new(host.clone(), Arc::new(call))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::{Duration, Instant};

    const CONFIG: &str = r#"
[roles.operator]
allow = ["service.control:nginx.service", "service.view"]
[unix_users.olivia]
roles = ["operator"]
"#;

    #[test]
    fn authorize_allows_what_the_policy_allows_and_audits_it() {
        let (host, sink) = testing::host(CONFIG);
        let ctx = testing::ctx(&host, "olivia", "service.control", Access::Write);
        assert!(ctx.authorize(Some("nginx.service")).is_ok());
        let records = sink.records();
        assert_eq!(records.len(), 1);
        let want = json!({
            "event": "tool_call", "call": "test-1", "principal": "olivia", "transport": "test",
            "tool": "test_tool", "permission": "service.control", "access": "write",
            "resource": "nginx.service", "decision": "allow", "args": {"name": "value"}
        });
        for (key, value) in want.as_object().unwrap() {
            assert_eq!(&records[0][key], value, "field {key}");
        }
    }

    #[test]
    fn authorize_refuses_what_the_policy_refuses_and_audits_that_too() {
        let (host, sink) = testing::host(CONFIG);
        let ctx = testing::ctx(&host, "olivia", "service.control", Access::Write);
        match ctx.authorize(Some("postgresql.service")) {
            Err(ToolError::Denied(message)) => {
                assert!(message.contains("service.control"), "{message}");
                assert!(message.contains("postgresql.service"), "{message}");
            }
            other => panic!("expected a denial, got {other:?}"),
        }
        let records = sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["decision"], "deny");
        assert_eq!(records[0]["resource"], "postgresql.service");
    }

    #[test]
    fn deny_refuses_with_the_reason_and_audits_it() {
        let (host, sink) = testing::host(CONFIG);
        let ctx = testing::ctx(&host, "olivia", "service.control", Access::Write);
        match ctx.deny(Some("sshd.service"), "sshd.service is a protected unit") {
            ToolError::Denied(message) => assert!(message.contains("protected unit"), "{message}"),
            other => panic!("expected a denial, got {other:?}"),
        }
        let records = sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["decision"], "deny");
        assert_eq!(records[0]["resource"], "sshd.service");
        assert_eq!(records[0]["reason"], "sshd.service is a protected unit");
    }

    #[test]
    fn authorize_without_a_resource_needs_an_unscoped_grant() {
        let (host, _sink) = testing::host(CONFIG);
        let scoped = testing::ctx(&host, "olivia", "service.control", Access::Write);
        assert!(matches!(scoped.authorize(None), Err(ToolError::Denied(_))));
        let unscoped = testing::ctx(&host, "olivia", "service.view", Access::Read);
        assert!(unscoped.authorize(None).is_ok());
    }

    #[test]
    fn permits_answers_for_one_resource_without_writing_an_audit_record() {
        let (host, sink) = testing::host(CONFIG);
        let ctx = testing::ctx(&host, "olivia", "service.control", Access::Write);
        assert!(ctx.permits("nginx.service"));
        assert!(!ctx.permits("postgresql.service"));
        assert_eq!(sink.records().len(), 0);
    }

    #[test]
    fn permits_respects_a_deny() {
        let config = "[roles.r]\nallow = [\"fs.view\"]\ndeny = [\"fs.view:/srv/secret/**\"]\n\
                      [unix_users.rita]\nroles = [\"r\"]\n";
        let (host, _sink) = testing::host(config);
        let ctx = testing::ctx(&host, "rita", "fs.view", Access::Read);
        assert!(ctx.permits("/srv/www/"));
        assert!(!ctx.permits("/srv/secret/keys/"));
    }

    /// The stand-in commands that tests use must record their runs faithfully, or every
    /// test built on them is in doubt.
    #[tokio::test]
    async fn a_stand_in_records_each_run_whole_even_when_many_run_at_once() {
        let fake = testing::FakeBins::new().add_script("probe", "exit 0");
        let config = format!(
            "[roles.r]\nallow = [\"@read\"]\n[unix_users.rita]\nroles = [\"r\"]\n{}",
            fake.config_only()
        );
        let (host, _sink) = testing::host(&config);
        let ctx = testing::ctx(&host, "rita", "system.view", Access::Read);

        // awkward arguments: none, an empty one, spaces, and line breaks
        for args in [
            vec![],
            vec!["", "a b", "--flag=x"],
            vec!["first line\nsecond line\n", "-e", "last"],
        ] {
            let cmd = ctx.command("probe").unwrap().args(args);
            assert_eq!(ctx.run(cmd).await.unwrap().code, Some(0));
        }
        assert_eq!(
            fake.calls("probe"),
            [
                vec![],
                vec!["".to_string(), "a b".to_string(), "--flag=x".to_string()],
                vec![
                    "first line\nsecond line\n".to_string(),
                    "-e".to_string(),
                    "last".to_string()
                ],
            ]
        );

        // many at once: every record must come out whole
        let mut runs = Vec::new();
        for n in 0..60 {
            let ctx = ctx.clone();
            runs.push(tokio::spawn(async move {
                let cmd = ctx.command("probe").unwrap().args([
                    "-f".to_string(),
                    "--".to_string(),
                    format!("/mnt/number-{n}"),
                ]);
                ctx.run(cmd).await.unwrap().code
            }));
        }
        for run in runs {
            assert_eq!(run.await.unwrap(), Some(0));
        }
        let mut seen: Vec<Vec<String>> = fake.calls("probe").split_off(3);
        seen.sort();
        let mut want: Vec<Vec<String>> = (0..60)
            .map(|n| {
                vec![
                    "-f".to_string(),
                    "--".to_string(),
                    format!("/mnt/number-{n}"),
                ]
            })
            .collect();
        want.sort();
        assert_eq!(seen, want);
    }

    #[test]
    fn holds_read_on_answers_for_one_resource_of_another_read_permission() {
        let config = "[roles.r]\nallow = [\"wait.use\", \"service.view:nginx.service\", \"journal.view\"]\n\
                      deny = [\"journal.view:secret.service\"]\n\
                      [unix_users.rita]\nroles = [\"r\"]\n";
        let (host, sink) = testing::host(config);
        let ctx = testing::ctx(&host, "rita", "wait.use", Access::Read);
        assert!(ctx.holds_read_on("service.view", "nginx.service"));
        // a scoped grant covers what it names and nothing else
        assert!(!ctx.holds_read_on("service.view", "postgresql.service"));
        // an unscoped grant covers every resource, except where a deny says otherwise
        assert!(ctx.holds_read_on("journal.view", "nginx.service"));
        assert!(!ctx.holds_read_on("journal.view", "secret.service"));
        // not granted at all
        assert!(!ctx.holds_read_on("fs.view", "/etc/"));
        assert_eq!(sink.records().len(), 0);
    }

    #[test]
    fn a_local_call_has_no_network_peer() {
        let (host, _sink) = testing::host(CONFIG);
        let ctx = testing::ctx(&host, "olivia", "service.view", Access::Read);
        assert_eq!(ctx.peer(), None);
    }

    #[test]
    fn holds_read_is_true_only_for_another_read_permission_granted_in_full() {
        let config = "[roles.r]\nallow = [\"system.view\", \"process.view\", \"journal.view:nginx.service\", \"service.control\"]\n\
                      deny = [\"service.view:secret.service\"]\n\
                      [roles.all]\nallow = [\"@read\"]\n\
                      [unix_users.rita]\nroles = [\"r\"]\n\
                      [unix_users.ann]\nroles = [\"all\", \"r\"]\n";
        let (host, sink) = testing::host(config);
        let ctx = testing::ctx(&host, "rita", "system.view", Access::Read);
        assert!(ctx.holds_read("process.view"));
        // granted for one unit only: not held in full
        assert!(!ctx.holds_read("journal.view"));
        // not granted at all
        assert!(!ctx.holds_read("net.view"));
        // @read grants it, but a scoped deny means it is not held in full
        let ann = testing::ctx(&host, "ann", "system.view", Access::Read);
        assert!(ann.holds_read("net.view"));
        assert!(!ann.holds_read("service.view"));
        assert_eq!(sink.records().len(), 0);
    }

    #[test]
    fn authorize_fails_closed_when_the_audit_record_cannot_be_written() {
        let (host, sink) = testing::host(CONFIG);
        sink.set_failing(true);
        let ctx = testing::ctx(&host, "olivia", "service.control", Access::Write);
        match ctx.authorize(Some("nginx.service")) {
            Err(ToolError::Failed(message)) => assert!(message.contains("audit"), "{message}"),
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[test]
    fn authorize_proceeds_without_audit_only_if_configured_to() {
        let (host, sink) = testing::host(&format!("{CONFIG}\n[audit]\nfail_closed = false\n"));
        sink.set_failing(true);
        let ctx = testing::ctx(&host, "olivia", "service.control", Access::Write);
        assert!(ctx.authorize(Some("nginx.service")).is_ok());
    }

    fn output(code: Option<i32>, stdout: &str, stderr: &str) -> CmdOutput {
        CmdOutput {
            code,
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
            ..CmdOutput::default()
        }
    }

    #[test]
    fn command_text_is_just_the_output_when_all_went_well() {
        assert_eq!(command_text(&output(Some(0), "active\n", "")), "active\n");
    }

    #[test]
    fn command_text_notes_everything_that_went_wrong() {
        let text = command_text(&output(Some(3), "inactive\n", "warning: x\n"));
        assert!(text.starts_with("inactive\n"), "{text}");
        assert!(text.contains("warning: x"), "{text}");
        assert!(text.contains("exit status 3"), "{text}");

        let mut timed_out = output(None, "partial", "");
        timed_out.timed_out = true;
        let text = command_text(&timed_out);
        assert!(
            text.contains("partial") && text.contains("time limit"),
            "{text}"
        );

        let mut killed = output(None, "", "");
        killed.signal = Some(9);
        assert!(command_text(&killed).contains("signal 9"));

        let mut truncated = output(Some(0), "lots", "");
        truncated.truncated = true;
        assert!(command_text(&truncated).contains("truncated"));
    }

    #[test]
    fn format_table_aligns_columns_to_their_widest_cell() {
        let rows = vec![
            vec!["a".to_string(), "10".to_string()],
            vec!["long-name".to_string(), "5".to_string()],
        ];
        assert_eq!(
            format_table(&["NAME", "SIZE"], &rows, &[false, true]),
            "NAME       SIZE\na            10\nlong-name     5\n"
        );
    }

    #[test]
    fn a_call_clock_gives_each_command_what_is_left_of_the_call() {
        let config =
            format!("{CONFIG}\n[limits]\ncall_timeout_secs = 40\ncommand_timeout_secs = 5\n");
        let (host, _sink) = testing::host(&config);
        let ctx = testing::ctx(&host, "olivia", "service.view", Access::Read);
        // plenty of the call left: the usual limit for one command
        let clock = CallClock::start(&ctx);
        assert_eq!(clock.next(), Some(Duration::from_secs(5)));
        // less than a command's limit left: only what is left
        let short = CallClock {
            deadline: Instant::now() + Duration::from_millis(2500),
            command: Duration::from_secs(5),
        };
        let limit = short.next().unwrap();
        assert!(
            limit <= Duration::from_millis(2500) && limit >= Duration::from_secs(2),
            "{limit:?}"
        );
        // nothing worth starting a command for
        let spent = CallClock {
            deadline: Instant::now() + Duration::from_millis(300),
            command: Duration::from_secs(5),
        };
        assert_eq!(spent.next(), None);
    }

    #[test]
    fn a_call_clock_always_keeps_time_back_for_sending_the_answer() {
        for (call, command) in [(120, 30), (30, 30), (4, 4), (1, 1)] {
            let config = format!(
                "{CONFIG}\n[limits]\ncall_timeout_secs = {call}\ncommand_timeout_secs = {command}\n"
            );
            let (host, _sink) = testing::host(&config);
            let ctx = testing::ctx(&host, "olivia", "service.view", Access::Read);
            let clock = CallClock::start(&ctx);
            let left = clock.deadline.saturating_duration_since(Instant::now());
            assert!(
                left < Duration::from_secs(call),
                "call {call}: {left:?} is the whole call"
            );
        }
    }

    #[test]
    fn a_table_cell_cannot_start_a_line_of_its_own() {
        // AIDEV-NOTE: cells hold host data (a process's arguments, a file's name). A line
        // break inside one would let that data add rows that look like the tool's own.
        let rows = vec![
            vec!["1".to_string(), "sleep\n9999 root 99.9 forged".to_string()],
            vec!["2".to_string(), "a\tb\rc".to_string()],
        ];
        assert_eq!(
            format_table(&["PID", "COMMAND"], &rows, &[true, false]),
            "PID  COMMAND\n  1  sleep\\n9999 root 99.9 forged\n  2  a\\tb\\rc\n"
        );
    }

    #[test]
    fn format_table_does_not_pad_the_last_column() {
        let rows = vec![
            vec!["1".to_string(), "/".to_string()],
            vec!["22".to_string(), "/var/log".to_string()],
        ];
        assert_eq!(
            format_table(&["N", "MOUNT"], &rows, &[true, false]),
            " N  MOUNT\n 1  /\n22  /var/log\n"
        );
    }

    #[tokio::test]
    async fn blocking_work_is_refused_once_stuck_jobs_hold_every_slot() {
        // max_concurrent_calls = 1 gives 8 slots for blocking work
        let (host, _sink) =
            testing::host(&format!("{CONFIG}\n[limits]\nmax_concurrent_calls = 1\n"));
        let ctx = testing::ctx(&host, "olivia", "service.view", Access::Read);
        let (release, stuck) = std::sync::mpsc::channel::<()>();
        let stuck = Arc::new(std::sync::Mutex::new(stuck));
        let mut calls = Vec::new();
        for _ in 0..8 {
            let stuck = stuck.clone();
            calls.push(tokio::spawn(blocking(ctx.clone(), move || {
                // stands in for a read that the kernel never completes
                let _ = stuck.lock().map(|rx| rx.recv());
                Ok(())
            })));
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        // the calls that started them give up (time out); the jobs are still stuck
        for call in &calls {
            call.abort();
        }
        match blocking(ctx.clone(), || Ok(())).await {
            Err(ToolError::Failed(message)) => assert!(message.contains("busy"), "{message}"),
            other => panic!("expected to be refused, got {other:?}"),
        }
        // once the stuck jobs finish, work is accepted again
        drop(release);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while blocking(ctx.clone(), || Ok(())).await.is_err() {
            assert!(
                std::time::Instant::now() < deadline,
                "slots were never given back"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    #[test]
    fn command_text_tail_keeps_the_newest_output_and_says_what_it_left_out() {
        let lines: String = (1..=100).map(|i| format!("entry {i:03}\n")).collect();
        let whole = command_text_tail(&output(Some(0), &lines, ""), 10_000);
        assert_eq!(whole, lines);

        let mut failed = output(Some(1), &lines, "journal is corrupt\n");
        failed.timed_out = false;
        let text = command_text_tail(&failed, 300);
        assert!(text.len() <= 300, "{} bytes", text.len());
        assert!(
            text.contains("entry 100"),
            "the newest line must survive: {text}"
        );
        assert!(!text.contains("entry 001"), "{text}");
        assert!(
            text.starts_with('['),
            "should open with a note about what was left out: {text}"
        );
        // what the command said went wrong is never the part that is dropped
        assert!(
            text.contains("journal is corrupt") && text.contains("exit status 1"),
            "{text}"
        );
    }

    #[test]
    fn command_ok_requires_a_clean_exit() {
        assert!(command_ok(&output(Some(0), "", "")));
        assert!(!command_ok(&output(Some(1), "", "")));
        assert!(!command_ok(&output(None, "", "")));
    }

    fn built(config: &str) -> Result<(Registry, Vec<String>), Vec<String>> {
        Registry::build(&Config::parse(config).unwrap())
    }

    /// Every distinct permission among the tools, with its access class.
    fn permissions(registry: &Registry) -> Vec<(String, Access)> {
        let mut all: Vec<(String, Access)> = registry
            .tools()
            .map(|t| (t.permission.clone(), t.access))
            .collect();
        all.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.as_str().cmp(b.1.as_str())));
        all.dedup();
        all
    }

    fn names(registry: &Registry) -> Vec<&str> {
        registry.tools().map(|t| t.name.as_str()).collect()
    }

    #[test]
    fn build_offers_every_built_in_tool() {
        let (registry, warnings) = built("").unwrap();
        assert_eq!(warnings, Vec::<String>::new());
        assert_eq!(
            names(&registry),
            [
                "block_devices",
                "cgroup_limits",
                "change_history",
                "cluster_maintenance_mode",
                "cluster_node",
                "cluster_resource",
                "cluster_status",
                "config_edit",
                "config_validate",
                "container_control",
                "container_inspect",
                "container_list",
                "container_logs",
                "container_stats",
                "corosync_status",
                "cpu_profile",
                "crash_events",
                "cve_status",
                "db_status",
                "disk_health",
                "disk_hogs",
                "disk_io",
                "disk_usage",
                "dns_config",
                "firewall_reset_counters",
                "firewall_set_member",
                "fs_grep",
                "fs_list",
                "fs_read",
                "fs_search",
                "fs_stat",
                "haproxy_server_state",
                "haproxy_servers",
                "hardware_health",
                "host_reboot",
                "incident_snapshot",
                "iptables_list",
                "iptables_rule",
                "journal_query",
                "kernel_log",
                "kernel_status",
                "limits_headroom",
                "log_list",
                "log_read",
                "log_summary",
                "lvm_extend",
                "memory_info",
                "monitoring_downtime",
                "mount_health",
                "net_interfaces",
                "net_probe",
                "net_routes",
                "net_sockets",
                "nft_list",
                "nft_rule",
                "nrpe_check",
                "nrpe_list",
                "package_query",
                "package_updates",
                "package_upgrade",
                "packet_capture",
                "perf_history",
                "process_info",
                "process_list",
                "process_signal",
                "process_trace",
                "resource_top",
                "scheduled_jobs",
                "security_denials",
                "security_posture",
                "service_control",
                "service_dependencies",
                "service_enable",
                "service_limits",
                "service_list",
                "service_status",
                "session_terminate",
                "space_reclaim",
                "sysctl_get",
                "sysctl_set",
                "sysfs_set",
                "system_info",
                "time_sync_status",
                "tls_cert_check",
                "user_list",
                "user_modify",
                "wait_for",
            ]
        );
    }

    /// AIDEV-NOTE: this list is the contract behind the `@read` group. A tool that changes
    /// anything must never carry one of the read permissions; if this test fails because
    /// a tool was added, decide deliberately which side it belongs on.
    #[test]
    fn every_permission_is_tagged_read_or_write_as_intended() {
        let (registry, _) = built("").unwrap();
        let read = [
            "cluster.view",
            "config.validate",
            "container.logs",
            "container.view",
            "crash.view",
            "db.view",
            "firewall.view",
            "fs.read",
            "fs.view",
            "haproxy.view",
            "hardware.view",
            "history.view",
            "journal.view",
            "kernel_log.view",
            "logs.view",
            "net.probe",
            "net.view",
            "nrpe.run",
            "nrpe.view",
            "package.view",
            "process.profile",
            "process.view",
            "schedule.view",
            "security.view",
            "service.view",
            "storage.view",
            "sysctl.view",
            "system.view",
            "time.view",
            "tls.view",
            "user.view",
            "wait.use",
        ];
        let write = [
            "cluster.modify",
            "container.control",
            "firewall.modify",
            "firewall.set",
            "fs.write",
            "haproxy.server",
            "host.reboot",
            "monitoring.downtime",
            "net.capture",
            "package.modify",
            "process.signal",
            "process.trace",
            "service.control",
            "service.enable",
            "service.limits",
            "storage.extend",
            "storage.reclaim",
            "sysctl.modify",
            "sysfs.modify",
            "user.modify",
            "user.session",
        ];
        let mut want: Vec<(String, Access)> = read
            .iter()
            .map(|p| (p.to_string(), Access::Read))
            .chain(write.iter().map(|p| (p.to_string(), Access::Write)))
            .collect();
        want.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(permissions(&registry), want);
    }

    #[test]
    fn every_tool_describes_itself_and_its_parameters() {
        let (registry, _) = built("").unwrap();
        for tool in registry.tools() {
            assert!(
                tool.description.len() >= 20,
                "{} needs a real description",
                tool.name
            );
            for param in &tool.params {
                assert!(
                    !param.description.is_empty(),
                    "{}.{} has no description",
                    tool.name,
                    param.name
                );
            }
        }
    }

    /// AIDEV-NOTE: an async function's local state lives in its future, and a future
    /// that awaits others holds theirs too. One tool reached 219 KiB that way and
    /// overflowed a 2 MiB thread stack in a debug build (the future is built on the stack
    /// before it is boxed, and each level of nesting copies it again). Parts that run
    /// side by side or are large should be boxed (`Box::pin`); this keeps every tool's
    /// future small enough that it cannot happen again unnoticed.
    #[test]
    fn no_tool_has_a_future_large_enough_to_threaten_the_stack() {
        const LIMIT: usize = 32 * 1024;
        let (host, _sink) =
            testing::host("[roles.r]\nallow = [\"@all\"]\n[unix_users.u]\nroles = [\"r\"]\n");
        let mut sizes = Vec::new();
        for tool in built_in_tools() {
            let ctx = testing::ctx(&host, "u", &tool.permission, tool.access);
            // Creating the future runs nothing: an async function starts when first polled.
            let future = (tool.handler)(ctx, Args::default());
            sizes.push((std::mem::size_of_val(&*future), tool.name.clone()));
        }
        sizes.sort();
        let too_large: Vec<_> = sizes.iter().filter(|(size, _)| *size > LIMIT).collect();
        assert!(
            too_large.is_empty(),
            "futures over {LIMIT} bytes: {too_large:?}"
        );
    }

    #[test]
    fn the_packaged_example_configuration_is_valid() {
        let example = include_str!("../../packaging/config.example.toml");
        let cfg = Config::parse(example).unwrap();
        let (registry, warnings) = Registry::build(&cfg).unwrap();
        assert_eq!(warnings, Vec::<String>::new());
        // it shows each kind of custom tool, and they come out as tools
        for name in [
            "haproxy_status",
            "haproxy_set",
            "cert_request",
            "galera_status",
        ] {
            assert!(registry.get(name).is_some(), "{name}");
        }
        // and each kind of caller
        assert!(cfg.principal_for_unix("sean", &[]).is_some());
        assert!(
            cfg.principal_for_unix("someone", &["ops".to_string()])
                .is_some()
        );
        assert_eq!(cfg.tokens.len(), 1);
        assert_eq!(cfg.client_certs.len(), 1);
        assert!(cfg.http.is_some());
    }

    // AIDEV-NOTE: the .deb installs this file as /etc/opsmcp/config.toml on every machine
    // the package goes onto, so what it lists is listed everywhere at once. It has to
    // stay a file that lets nobody in and opens nothing: a caller, a listener or an
    // allowance added to it is a change to every installation, not an example. Examples
    // belong in packaging/config.example.toml.
    #[test]
    fn the_configuration_the_package_installs_is_valid_and_lets_nobody_in() {
        let installed = include_str!("../../packaging/deb/etc/opsmcp/config.toml");
        let mut cfg = Config::parse(installed).unwrap();
        let (_, warnings) = Registry::build(&cfg).unwrap();
        assert_eq!(warnings, Vec::<String>::new());

        assert!(cfg.unix_users.is_empty());
        assert!(cfg.unix_groups.is_empty());
        assert!(cfg.tokens.is_empty());
        assert!(cfg.client_certs.is_empty());
        assert!(cfg.http.is_none());
        // every call is recorded, and none runs when it cannot be
        assert!(cfg.audit.syslog && cfg.audit.fail_closed);

        // It names roles for the operator to hand out. Apart from those it sets nothing
        // that an empty file does not: no custom tool, nothing writable, no fleet.
        assert!(!cfg.roles.is_empty());
        cfg.roles.clear();
        let empty = Config::parse("").unwrap();
        assert_eq!(format!("{cfg:#?}"), format!("{empty:#?}"));
    }

    #[test]
    fn build_leaves_out_disabled_tools_and_rejects_unknown_names() {
        let (registry, _) =
            built("[tools]\ndisabled = [\"fs_read\", \"process_signal\"]\n").unwrap();
        assert!(!names(&registry).contains(&"fs_read"));
        assert!(!names(&registry).contains(&"process_signal"));
        assert!(names(&registry).contains(&"fs_list"));

        let errors = built("[tools]\ndisabled = [\"fs_reed\"]\n").err().unwrap();
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("fs_reed"), "{errors:?}");
    }

    const CUSTOM: &str = "description = \"Galera status\"\naccess = \"read\"\ncommand = [\"/usr/local/bin/galera-status\"]\n";

    #[test]
    fn build_adds_custom_tools_under_their_own_permission() {
        let (registry, _) = built(&format!("[custom.galera_status]\n{CUSTOM}")).unwrap();
        let tool = registry.get("galera_status").unwrap();
        assert_eq!(
            (tool.permission.as_str(), tool.access),
            ("custom.galera_status", Access::Read)
        );
    }

    #[test]
    fn a_custom_tool_cannot_take_the_name_of_a_built_in_one() {
        let errors = built(&format!("[custom.fs_read]\n{CUSTOM}")).err().unwrap();
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("fs_read"), "{errors:?}");
        // not even a disabled one: the name keeps its meaning
        let errors = built(&format!(
            "[tools]\ndisabled = [\"fs_read\"]\n[custom.fs_read]\n{CUSTOM}"
        ))
        .err()
        .unwrap();
        assert!(errors[0].contains("fs_read"), "{errors:?}");
    }

    #[test]
    fn build_checks_grants_against_the_permissions_that_exist() {
        // a deny that matches nothing is an error
        let errors = built("[roles.ops]\nallow = [\"@read\"]\ndeny = [\"proces.signal\"]\n")
            .err()
            .unwrap();
        assert!(errors[0].contains("proces.signal"), "{errors:?}");
        // an allow that matches nothing is a warning; so is one for a custom tool that
        // this host does not define
        let (_, warnings) =
            built("[roles.ops]\nallow = [\"servce.control\", \"custom.elsewhere\"]\n").unwrap();
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        // grants for custom tools and for disabled built-in tools are fine
        let config = format!(
            "[roles.ops]\nallow = [\"custom.galera_status\", \"fs.read\"]\ndeny = [\"process.signal\"]\n\
             [tools]\ndisabled = [\"fs_read\", \"process_signal\"]\n[custom.galera_status]\n{CUSTOM}"
        );
        let (_, warnings) = built(&config).unwrap();
        assert_eq!(warnings, Vec::<String>::new());
    }

    fn tool(name: &str, permission: &str, access: Access) -> Tool {
        Tool::new(
            name,
            "A test tool",
            access,
            permission,
            vec![],
            |ctx: Ctx, _args| async move { ctx.authorize(None)?.ok("done") },
        )
    }

    #[test]
    fn the_registry_refuses_duplicates_and_malformed_names() {
        let mut registry = Registry::default();
        registry
            .add(tool("service_list", "service.view", Access::Read))
            .unwrap();
        assert!(
            registry
                .add(tool("service_list", "service.view", Access::Read))
                .is_err()
        );
        assert!(
            registry
                .add(tool("Service-List", "service.view", Access::Read))
                .is_err()
        );
        assert!(
            registry
                .add(tool("", "service.view", Access::Read))
                .is_err()
        );
        assert!(
            registry
                .add(tool("ok_name", "Bad Permission", Access::Read))
                .is_err()
        );
        assert!(
            registry
                .add(tool("ok_name", "@read", Access::Read))
                .is_err()
        );
        assert!(
            registry
                .add(tool("ok_name", "service.*", Access::Read))
                .is_err()
        );
        assert!(registry.get("service_list").is_some());
        assert!(registry.get("ok_name").is_none());
    }

    #[test]
    fn the_registry_lists_each_permission_once() {
        let mut registry = Registry::default();
        registry
            .add(tool("service_list", "service.view", Access::Read))
            .unwrap();
        registry
            .add(tool("service_status", "service.view", Access::Read))
            .unwrap();
        registry
            .add(tool("service_control", "service.control", Access::Write))
            .unwrap();
        assert_eq!(
            permissions(&registry),
            vec![
                ("service.control".to_string(), Access::Write),
                ("service.view".to_string(), Access::Read),
            ]
        );
    }
}
