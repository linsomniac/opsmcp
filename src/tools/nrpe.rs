//! NRPE checks: list the checks defined in nrpe.cfg and run one on demand.
//!
//! A check is run the way the NRPE daemon runs it: its command line from nrpe.cfg goes
//! to `/bin/sh -c`, as the NRPE user.
//!
//! AIDEV-NOTE: this is the one place opsmcp uses a shell. It is sound because the command
//! line comes only from nrpe.cfg, never from the caller: the caller picks a check by
//! name and can pass no arguments (checks that take `$ARGn$` are refused). When opsmcp
//! runs as root, nrpe.cfg and everything it includes must be root-owned and not writable
//! by others, and the check runs as the NRPE user, never as root.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use nix::unistd::{Group, User};

use super::args::{Args, Param};
use super::{Ctx, Tool, ToolError, ToolResult, blocking, required};
use crate::exec::{RunAs, check_trusted_path};
use crate::policy::Access;

/// Where nrpe.cfg usually is, tried in order when `nrpe.config` is not set.
const DEFAULT_CONFIGS: [&str; 4] = [
    "/etc/nagios/nrpe.cfg",
    "/etc/nrpe/nrpe.cfg",
    "/etc/nrpe.cfg",
    "/usr/local/nagios/etc/nrpe.cfg",
];
const MAX_FILES: usize = 256;
const MAX_DEPTH: usize = 8;
const MAX_FILE_BYTES: u64 = 1024 * 1024;
const SHELL: &str = "/bin/sh";

pub fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "nrpe_list",
            "List the monitoring checks defined for NRPE on this host (the checks Nagios or \
             Icinga runs here), with the plugin each one uses.",
            Access::Read,
            "nrpe.view",
            vec![],
            nrpe_list,
        ),
        Tool::new(
            "nrpe_check",
            "Run one NRPE check now, as the monitoring system would, and report its status \
             (OK, WARNING, CRITICAL or UNKNOWN) and output.",
            Access::Read,
            "nrpe.run",
            vec![
                Param::str("name", "Name of the check, as listed by nrpe_list")
                    .max_len(128)
                    .required(),
            ],
            nrpe_check,
        ),
    ]
}

/// What was read from nrpe.cfg and the files it includes.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct NrpeConfig {
    /// Check name to command line.
    pub commands: BTreeMap<String, String>,
    pub user: Option<String>,
    pub group: Option<String>,
    pub command_timeout: Option<u64>,
    pub command_prefix: Option<String>,
}

/// Reads nrpe.cfg, following `include` and `include_dir`. With `trusted_owners` set,
/// every file read must pass `check_trusted_path` for those owners (plus root).
pub fn load_config(path: &Path, trusted_owners: Option<&[u32]>) -> Result<NrpeConfig, String> {
    let mut reader = Reader {
        trusted_owners,
        seen: BTreeSet::new(),
        cfg: NrpeConfig::default(),
    };
    reader.file(path, 0, true)?;
    Ok(reader.cfg)
}

struct Reader<'a> {
    trusted_owners: Option<&'a [u32]>,
    /// Real paths already read: each file counts once, so include loops end.
    seen: BTreeSet<PathBuf>,
    cfg: NrpeConfig,
}

impl Reader<'_> {
    fn file(&mut self, path: &Path, depth: usize, required: bool) -> Result<(), String> {
        let shown = path.display();
        let real = match std::fs::canonicalize(path) {
            Ok(real) => real,
            // NRPE itself only warns about an include that is not there.
            Err(_) if !required => return Ok(()),
            Err(e) => return Err(format!("{shown}: {e}")),
        };
        if !self.seen.insert(real.clone()) {
            return Ok(());
        }
        if depth > MAX_DEPTH || self.seen.len() > MAX_FILES {
            return Err(format!("{shown}: too many included files"));
        }
        if let Some(owners) = self.trusted_owners {
            check_trusted_path(&real, owners)
                .map_err(|e| format!("refusing to use {shown}: {e}"))?;
        }
        let size = std::fs::metadata(&real)
            .map_err(|e| format!("{shown}: {e}"))?
            .len();
        if size > MAX_FILE_BYTES {
            return Err(format!("{shown}: larger than {MAX_FILE_BYTES} bytes"));
        }
        let text = std::fs::read_to_string(&real).map_err(|e| format!("{shown}: {e}"))?;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let (key, value) = (key.trim(), value.trim());
            match key {
                "include" if Path::new(value).is_absolute() => {
                    self.file(Path::new(value), depth + 1, false)?
                }
                "include_dir" if Path::new(value).is_absolute() => {
                    self.dir(Path::new(value), depth + 1)?
                }
                "nrpe_user" => self.cfg.user = Some(value.to_string()),
                "nrpe_group" => self.cfg.group = Some(value.to_string()),
                "command_timeout" => self.cfg.command_timeout = value.parse().ok(),
                "command_prefix" => self.cfg.command_prefix = Some(value.to_string()),
                _ => {
                    let name = key
                        .strip_prefix("command[")
                        .and_then(|k| k.strip_suffix(']'));
                    if let Some(name) = name.filter(|n| is_check_name(n))
                        && !value.is_empty()
                    {
                        self.cfg
                            .commands
                            .insert(name.to_string(), value.to_string());
                    }
                }
            }
        }
        Ok(())
    }

    /// Every `*.cfg` in a directory and, as NRPE does, in its subdirectories.
    fn dir(&mut self, dir: &Path, depth: usize) -> Result<(), String> {
        if depth > MAX_DEPTH {
            return Err(format!("{}: directories nested too deeply", dir.display()));
        }
        let Ok(reader) = std::fs::read_dir(dir) else {
            return Ok(());
        };
        let mut paths: Vec<PathBuf> = reader.flatten().map(|e| e.path()).collect();
        paths.sort();
        for path in paths {
            if path.is_dir() {
                self.dir(&path, depth + 1)?;
            } else if path.extension().is_some_and(|ext| ext == "cfg") {
                self.file(&path, depth, false)?;
            }
        }
        Ok(())
    }
}

fn is_check_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
}

/// Finds and reads this host's NRPE configuration.
fn load(ctx: &Ctx) -> Result<NrpeConfig, ToolError> {
    let path = match &ctx.cfg().nrpe.config {
        Some(path) => path.clone(),
        None => DEFAULT_CONFIGS
            .iter()
            .map(PathBuf::from)
            .find(|p| p.is_file())
            .ok_or_else(|| {
                ToolError::Failed(format!(
                    "NRPE does not seem to be installed here: none of {} exists (set nrpe.config if it is elsewhere)",
                    DEFAULT_CONFIGS.join(", ")
                ))
            })?,
    };
    // As root, what nrpe.cfg says gets executed: it must be root's file. See module notes.
    let as_root = rustix::process::geteuid().is_root();
    let owners: Option<&[u32]> = if as_root { Some(&[]) } else { None };
    load_config(&path, owners)
        .map_err(|e| ToolError::Failed(format!("cannot read the NRPE configuration: {e}")))
}

/// The user and group NRPE runs checks as.
fn nrpe_identity(cfg: &NrpeConfig) -> Result<RunAs, ToolError> {
    let failed = |problem: &str| ToolError::Failed(problem.to_string());
    let candidates: Vec<&str> = match &cfg.user {
        Some(user) => vec![user.as_str()],
        None => vec!["nagios", "nrpe"],
    };
    let user = candidates
        .iter()
        .find_map(|name| User::from_name(name).ok().flatten())
        .ok_or_else(|| {
            failed("cannot find the NRPE user (nrpe_user in nrpe.cfg, else nagios or nrpe)")
        })?;
    if user.uid.is_root() {
        return Err(failed(
            "the NRPE user is root; opsmcp does not run checks as root",
        ));
    }
    let gid = match &cfg.group {
        Some(group) => Group::from_name(group)
            .ok()
            .flatten()
            .map(|g| g.gid.as_raw())
            .ok_or_else(|| failed("cannot find the NRPE group named by nrpe_group in nrpe.cfg"))?,
        None => user.gid.as_raw(),
    };
    Ok(RunAs {
        uid: user.uid.as_raw(),
        gid,
    })
}

/// The basename of the program a check's command line starts with.
pub fn plugin_name(command_line: &str) -> String {
    let program = command_line.split_whitespace().next().unwrap_or_default();
    program.rsplit('/').next().unwrap_or_default().to_string()
}

/// The Nagios meaning of a plugin's exit status.
pub fn status_name(code: Option<i32>) -> Option<&'static str> {
    match code {
        Some(0) => Some("OK"),
        Some(1) => Some("WARNING"),
        Some(2) => Some("CRITICAL"),
        Some(3) => Some("UNKNOWN"),
        _ => None,
    }
}

/// True for a check whose command line expects arguments from the monitoring server.
fn takes_arguments(command_line: &str) -> bool {
    command_line.contains("$ARG")
}

async fn nrpe_list(ctx: Ctx, _args: Args) -> ToolResult {
    let auth = ctx.authorize(None)?;
    blocking(ctx.clone(), move || {
        let cfg = load(&ctx)?;
        // Only the plugin's name is shown: command lines often carry credentials.
        let rows: Vec<Vec<String>> = cfg
            .commands
            .iter()
            .map(|(name, line)| {
                let note = if takes_arguments(line) {
                    "takes arguments from the monitoring server; cannot be run here"
                } else {
                    ""
                };
                vec![name.clone(), plugin_name(line), note.to_string()]
            })
            .collect();
        let mut text =
            super::format_table(&["CHECK", "PLUGIN", "NOTE"], &rows, &[false, false, false]);
        text.push_str(&format!("[{} checks defined]\n", rows.len()));
        auth.ok(text)
    })
    .await
}

async fn nrpe_check(ctx: Ctx, args: Args) -> ToolResult {
    let name = required(&args, "name")?.to_string();
    if !is_check_name(&name) {
        return Err(ToolError::Invalid(format!("{name:?} is not a check name")));
    }
    let cfg = {
        let ctx = ctx.clone();
        blocking(ctx.clone(), move || load(&ctx)).await?
    };
    let auth = ctx.authorize(Some(&name))?;
    let Some(line) = cfg.commands.get(&name) else {
        return Err(ToolError::Failed(format!(
            "there is no NRPE check named {name} (nrpe_list shows the checks)"
        )));
    };
    if takes_arguments(line) {
        return Err(ToolError::Failed(format!(
            "{name} takes arguments from the monitoring server, which opsmcp does not pass; it cannot be run here"
        )));
    }
    let command_line = match &cfg.command_prefix {
        Some(prefix) => format!("{prefix} {line}"),
        None => line.clone(),
    };

    ctx.bins()
        .check_program(Path::new(SHELL))
        .map_err(ToolError::Failed)?;
    let limits = &ctx.cfg().limits;
    let wait = cfg
        .command_timeout
        .unwrap_or(60)
        .clamp(1, limits.call_timeout_secs.saturating_sub(5).max(1));
    let mut cmd = ctx
        .command_at(PathBuf::from(SHELL))
        .timeout(Duration::from_secs(wait))
        .args(["-c", command_line.as_str()]);
    cmd.env
        .push(("NRPE_MULTILINESUPPORT".to_string(), "1".to_string()));
    if rustix::process::geteuid().is_root() {
        cmd.run_as = Some(nrpe_identity(&cfg)?);
    }
    let out = ctx.run(cmd).await?;

    let output = String::from_utf8_lossy(&out.stdout);
    match status_name(out.code).filter(|_| !out.timed_out) {
        Some(status) => {
            let mut text = format!(
                "{status} (exit status {})\n{output}",
                out.code.unwrap_or_default()
            );
            let stderr = String::from_utf8_lossy(&out.stderr);
            if !stderr.trim().is_empty() {
                text.push_str(&format!("\n[stderr]\n{stderr}"));
            }
            auth.ok(text)
        }
        None => auth.failed(format!(
            "{name} did not end with a Nagios status (0 to 3):\n{}",
            super::command_text(&out)
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::Host;
    use crate::tools::testing::{call, find, host, ok_text};
    use serde_json::{Value, json};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn load_config_reads_settings_commands_and_includes() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().display();
        write(
            &dir.path().join("nrpe.cfg"),
            &format!(
                "# a comment\n\n  nrpe_user=nagios\nnrpe_group = nagios\ncommand_timeout=45\n\
                 command[check_load]=/usr/lib/nagios/plugins/check_load -w 5,4,3 -c 10,8,6\n\
                 command[check_mysql]=/usr/lib/nagios/plugins/check_mysql -u monitor -p hunter2\n\
                 command[check_by_arg]=/usr/lib/nagios/plugins/check_http -H $ARG1$\n\
                 not a setting\n\
                 include={d}/extra.cfg\ninclude_dir={d}/conf.d\ninclude={d}/missing.cfg\n"
            ),
        );
        // a later definition replaces an earlier one
        write(
            &dir.path().join("extra.cfg"),
            "command[check_load]=/usr/lib/nagios/plugins/check_load -w 1,1,1 -c 2,2,2\n",
        );
        write(
            &dir.path().join("conf.d/a.cfg"),
            "command[check_disk]=/usr/lib/nagios/plugins/check_disk -w 10% -c 5% -p /\n",
        );
        write(
            &dir.path().join("conf.d/ignored.txt"),
            "command[check_ignored]=/bin/true\n",
        );
        write(
            &dir.path().join("conf.d/sub/b.cfg"),
            "command[check_swap]=/usr/lib/nagios/plugins/check_swap -w 20% -c 10%\n",
        );

        let cfg = load_config(&dir.path().join("nrpe.cfg"), None).unwrap();
        assert_eq!(cfg.user.as_deref(), Some("nagios"));
        assert_eq!(cfg.group.as_deref(), Some("nagios"));
        assert_eq!(cfg.command_timeout, Some(45));
        let names: Vec<&str> = cfg.commands.keys().map(String::as_str).collect();
        assert_eq!(
            names,
            [
                "check_by_arg",
                "check_disk",
                "check_load",
                "check_mysql",
                "check_swap"
            ]
        );
        assert_eq!(
            cfg.commands["check_load"],
            "/usr/lib/nagios/plugins/check_load -w 1,1,1 -c 2,2,2"
        );
    }

    #[test]
    fn load_config_survives_a_file_that_includes_itself() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("nrpe.cfg");
        write(
            &main,
            &format!(
                "command[check_a]=/bin/true\ninclude={}\ninclude_dir={}\n",
                main.display(),
                dir.path().display()
            ),
        );
        let cfg = load_config(&main, None).unwrap();
        assert_eq!(cfg.commands.len(), 1);
    }

    #[test]
    fn load_config_fails_without_the_main_file() {
        assert!(load_config(Path::new("/nonexistent/nrpe.cfg"), None).is_err());
    }

    #[test]
    fn load_config_refuses_files_others_could_have_written_when_trust_is_required() {
        let dir = tempfile::tempdir().unwrap();
        let me = rustix::process::getuid().as_raw();
        let main = dir.path().join("nrpe.cfg");
        let included = dir.path().join("extra.cfg");
        write(
            &main,
            &format!(
                "command[check_a]=/bin/true\ninclude={}\n",
                included.display()
            ),
        );
        write(&included, "command[check_b]=/bin/true\n");
        assert_eq!(load_config(&main, Some(&[me])).unwrap().commands.len(), 2);

        // an included file that anyone may write to taints the whole configuration
        std::fs::set_permissions(&included, std::fs::Permissions::from_mode(0o666)).unwrap();
        let error = load_config(&main, Some(&[me])).unwrap_err();
        assert!(error.contains("extra.cfg"), "{error}");
        // without the requirement (not running as root) it is read
        assert_eq!(load_config(&main, None).unwrap().commands.len(), 2);
    }

    #[test]
    fn plugin_name_is_the_program_without_its_directory_or_arguments() {
        assert_eq!(
            plugin_name("/usr/lib/nagios/plugins/check_mysql -u monitor -p hunter2"),
            "check_mysql"
        );
        assert_eq!(plugin_name("check_local"), "check_local");
        assert_eq!(plugin_name("  /usr/bin/sudo /usr/lib/check_raid"), "sudo");
        assert_eq!(plugin_name(""), "");
    }

    #[test]
    fn status_name_follows_the_nagios_convention() {
        assert_eq!(status_name(Some(0)), Some("OK"));
        assert_eq!(status_name(Some(1)), Some("WARNING"));
        assert_eq!(status_name(Some(2)), Some("CRITICAL"));
        assert_eq!(status_name(Some(3)), Some("UNKNOWN"));
        assert_eq!(status_name(Some(4)), None);
        assert_eq!(status_name(None), None);
    }

    struct Fixture {
        dir: tempfile::TempDir,
        host: Arc<Host>,
        audit: MemorySink,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().display().to_string();
        write(
            &dir.path().join("nrpe.cfg"),
            &format!(
                "command[check_ok]=echo \"DISK OK - 10% used\"\n\
                 command[check_crit]=echo \"CRITICAL - service down\"; exit 2\n\
                 command[check_weird]=exit 7\n\
                 command[check_pipe]=echo one two | {{ read a b; echo \"second=$b\"; }}\n\
                 command[check_arg]=echo $ARG1$\n\
                 command[check_secret]=echo fine # -p hunter2\n\
                 command[check_mark]=: > {d}/marker; echo marked\n"
            ),
        );
        let (host, audit) = host(&format!(
            r#"
[roles.reader]
allow = ["@read"]
[roles.narrow]
allow = ["nrpe.run:check_ok"]
[unix_users.rita]
roles = ["reader"]
[unix_users.nora]
roles = ["narrow"]
[nrpe]
config = "{d}/nrpe.cfg"
"#
        ));
        Fixture { dir, host, audit }
    }

    impl Fixture {
        async fn run(&self, user: &str, tool: &str, arguments: Value) -> ToolResult {
            call(&self.host, user, &find(tools(), tool), arguments).await
        }
    }

    #[tokio::test]
    async fn nrpe_list_names_checks_and_plugins_but_not_their_arguments() {
        let f = fixture();
        let text = ok_text(f.run("rita", "nrpe_list", json!({})).await);
        for name in ["check_ok", "check_crit", "check_arg", "check_secret"] {
            assert!(text.contains(name), "{name} missing in:\n{text}");
        }
        assert!(
            !text.contains("hunter2"),
            "arguments must not be shown:\n{text}"
        );
        // a check that takes arguments is marked as not runnable here
        let arg_line = text.lines().find(|l| l.contains("check_arg")).unwrap();
        assert!(arg_line.contains("argument"), "{arg_line}");
    }

    #[tokio::test]
    async fn nrpe_check_reports_the_status_and_output_of_a_check() {
        let f = fixture();
        let text = ok_text(
            f.run("rita", "nrpe_check", json!({"name": "check_ok"}))
                .await,
        );
        assert!(text.starts_with("OK"), "{text}");
        assert!(text.contains("DISK OK - 10% used"), "{text}");
        // a failing check is still an answer, not an error
        let text = ok_text(
            f.run("rita", "nrpe_check", json!({"name": "check_crit"}))
                .await,
        );
        assert!(text.starts_with("CRITICAL"), "{text}");
        assert!(text.contains("CRITICAL - service down"), "{text}");
        assert_eq!(f.audit.records().last().unwrap()["resource"], "check_crit");
    }

    #[tokio::test]
    async fn nrpe_check_runs_the_command_line_through_a_shell_as_nrpe_does() {
        let f = fixture();
        let text = ok_text(
            f.run("rita", "nrpe_check", json!({"name": "check_pipe"}))
                .await,
        );
        assert!(text.contains("second=two"), "{text}");
    }

    #[tokio::test]
    async fn nrpe_check_flags_results_that_are_not_a_nagios_status() {
        let f = fixture();
        let output = f
            .run("rita", "nrpe_check", json!({"name": "check_weird"}))
            .await
            .unwrap();
        assert!(output.is_error());
        assert!(output.text().contains('7'), "{}", output.text());
    }

    #[tokio::test]
    async fn nrpe_check_refuses_unknown_checks_bad_names_and_checks_with_arguments() {
        let f = fixture();
        assert!(matches!(
            f.run("rita", "nrpe_check", json!({"name": "check_nope"}))
                .await,
            Err(ToolError::Failed(_))
        ));
        assert!(matches!(
            f.run("rita", "nrpe_check", json!({"name": "check ok; id"}))
                .await,
            Err(ToolError::Invalid(_))
        ));
        match f
            .run("rita", "nrpe_check", json!({"name": "check_arg"}))
            .await
        {
            Err(ToolError::Failed(message)) => assert!(message.contains("argument"), "{message}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn nrpe_check_runs_only_the_checks_a_caller_is_granted() {
        let f = fixture();
        ok_text(
            f.run("nora", "nrpe_check", json!({"name": "check_ok"}))
                .await,
        );
        let result = f
            .run("nora", "nrpe_check", json!({"name": "check_mark"}))
            .await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        assert!(
            !f.dir.path().join("marker").exists(),
            "a refused check must not run"
        );
        // the same check, for someone allowed to run it
        ok_text(
            f.run("rita", "nrpe_check", json!({"name": "check_mark"}))
                .await,
        );
        assert!(f.dir.path().join("marker").exists());
    }

    #[tokio::test]
    async fn a_host_without_nrpe_says_so() {
        let (host, _audit) = host(
            "[roles.reader]\nallow = [\"@read\"]\n[unix_users.rita]\nroles = [\"reader\"]\n[nrpe]\nconfig = \"/nonexistent/nrpe.cfg\"\n",
        );
        let result = call(&host, "rita", &find(tools(), "nrpe_list"), json!({})).await;
        match result {
            Err(ToolError::Failed(message)) => {
                assert!(message.contains("/nonexistent/nrpe.cfg"), "{message}")
            }
            other => panic!("expected a failure, got {other:?}"),
        }
    }
}
