//! The tools the server offers, and the context a tool runs in.

pub mod args;
pub mod cluster;
pub mod container;
mod ctx;
pub mod custom;
pub mod firewall;
pub mod fs;
pub mod kernel;
pub mod logs;
pub mod nrpe;
pub mod paths;
pub mod process;
pub mod service;
pub mod system;

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

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
pub fn format_rows(rows: &[Vec<String>], right: &[bool]) -> String {
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
    for row in rows {
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
        pub fn add_script(mut self, name: &str, body: &str) -> FakeBins {
            use std::os::unix::fs::PermissionsExt;
            let dir = self.dir.path().display().to_string();
            let script = format!(
                "#!/bin/sh\n\
                 {{ for a in \"$@\"; do printf '%s\\n' \"$a\"; done; printf -- '--END--\\n'; }} >> '{dir}/{name}.calls'\n\
                 {body}\n"
            );
            let path = format!("{dir}/{name}");
            std::fs::write(&path, script).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
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
            let mut calls = Vec::new();
            let mut current = Vec::new();
            for line in text.lines() {
                if line == "--END--" {
                    calls.push(std::mem::take(&mut current));
                } else {
                    current.push(line.to_string());
                }
            }
            calls
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
        };
        Ctx::new(host.clone(), Arc::new(call))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
                "cluster_maintenance_mode",
                "cluster_node",
                "cluster_resource",
                "cluster_status",
                "container_control",
                "container_inspect",
                "container_list",
                "container_logs",
                "container_stats",
                "corosync_status",
                "disk_io",
                "disk_usage",
                "firewall_reset_counters",
                "fs_list",
                "fs_read",
                "fs_stat",
                "iptables_list",
                "iptables_rule",
                "journal_query",
                "kernel_log",
                "log_list",
                "log_read",
                "memory_info",
                "nft_list",
                "nft_rule",
                "nrpe_check",
                "nrpe_list",
                "process_info",
                "process_list",
                "process_signal",
                "service_control",
                "service_enable",
                "service_list",
                "service_status",
                "sysctl_get",
                "sysctl_set",
                "sysfs_set",
                "system_info",
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
            "container.logs",
            "container.view",
            "firewall.view",
            "fs.read",
            "fs.view",
            "journal.view",
            "kernel_log.view",
            "logs.view",
            "nrpe.run",
            "nrpe.view",
            "process.view",
            "service.view",
            "sysctl.view",
            "system.view",
        ];
        let write = [
            "cluster.modify",
            "container.control",
            "firewall.modify",
            "process.signal",
            "service.control",
            "service.enable",
            "sysctl.modify",
            "sysfs.modify",
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
