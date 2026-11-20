//! Operator-defined tools: commands the host's administrator lists in the configuration
//! (`[custom.NAME]`), offered to agents like any built-in tool.
//!
//! AIDEV-NOTE: the administrator decides the program and the shape of its command line;
//! a caller only supplies parameter values. Every value is validated (a string against
//! its pattern, by default one that cannot start with `-`), each lands inside a single
//! argument, and no shell is involved, so a value can neither add arguments nor run
//! anything else. See `template`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use nix::unistd::User;
use regex::Regex;

use super::args::{Args, Param};
use super::{Ctx, Tool, ToolError, ToolResult, command_text};
use crate::config::{CustomCfg, CustomParamType, anchored};
use crate::exec::RunAs;
use crate::template::{self, Piece, Value};

/// What a string parameter may contain unless the operator gives a pattern: it starts
/// with a letter or digit (so it is never read as an option) and has no whitespace or
/// shell punctuation.
pub const DEFAULT_PATTERN: &str = "[A-Za-z0-9][A-Za-z0-9_.:@/=+,-]*";

/// Builds the tool for one `[custom.NAME]` entry.
pub fn tool(name: &str, cfg: &CustomCfg) -> Result<Tool, String> {
    let at = format!("custom.{name}");
    let program = cfg
        .command
        .first()
        .ok_or_else(|| format!("{at}.command: is empty"))?;
    let elements = cfg
        .command
        .iter()
        .skip(1)
        .map(|element| template::parse(element))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{at}.command: {e}"))?;

    let mut params = Vec::new();
    let mut checks = BTreeMap::new();
    for (param_name, declared) in &cfg.params {
        let description = declared.description.as_str();
        let (param, check) = match declared.kind {
            CustomParamType::String => {
                let pattern = declared.pattern.as_deref().unwrap_or(DEFAULT_PATTERN);
                // Anchored: the pattern has to describe the whole value, not part of it.
                let regex = Regex::new(&anchored(pattern))
                    .map_err(|e| format!("{at}.params.{param_name}.pattern: {e}"))?;
                let param =
                    Param::str(param_name, description).max_len(declared.max_len.unwrap_or(256));
                (param, Check::Text(regex))
            }
            CustomParamType::Integer => {
                // Not negative unless the operator says so: "-5" would look like an option.
                let (min, max) = (declared.min.unwrap_or(0), declared.max.unwrap_or(i64::MAX));
                (
                    Param::int(param_name, description, min, max),
                    Check::Integer,
                )
            }
            CustomParamType::Boolean => (Param::bool(param_name, description), Check::Flag),
            CustomParamType::Enum => {
                let values: Vec<&str> = declared.values.iter().map(String::as_str).collect();
                (
                    Param::choice(param_name, description, &values),
                    Check::Choice,
                )
            }
        };
        params.push(if declared.required {
            param.required()
        } else {
            param
        });
        checks.insert(param_name.clone(), check);
    }

    let custom = Arc::new(Custom {
        program: PathBuf::from(program),
        elements,
        checks,
        run_as: cfg.run_as.clone(),
        timeout: cfg.timeout_secs.map(Duration::from_secs),
        ok_exit_codes: cfg.ok_exit_codes.clone(),
        env: cfg
            .env
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    });
    Ok(Tool::new(
        name,
        &cfg.description,
        cfg.access,
        &format!("custom.{name}"),
        params,
        move |ctx: Ctx, args: Args| run(custom.clone(), ctx, args),
    ))
}

/// A custom tool, ready to run.
struct Custom {
    program: PathBuf,
    /// One template per command-line element after the program.
    elements: Vec<Vec<Piece>>,
    checks: BTreeMap<String, Check>,
    run_as: Option<String>,
    timeout: Option<Duration>,
    ok_exit_codes: Vec<i32>,
    env: Vec<(String, String)>,
}

/// How a parameter's value is taken from the arguments.
enum Check {
    /// A string that must match this (anchored) pattern.
    Text(Regex),
    Integer,
    Flag,
    Choice,
}

async fn run(custom: Arc<Custom>, ctx: Ctx, args: Args) -> ToolResult {
    let mut values = BTreeMap::new();
    for (name, check) in &custom.checks {
        let value = match check {
            Check::Text(pattern) => args.str(name).map(|text| {
                if pattern.is_match(text) {
                    Ok(Value::Text(text.to_string()))
                } else {
                    Err(ToolError::Invalid(format!(
                        "argument {name:?} is not in the form this tool accepts"
                    )))
                }
            }),
            Check::Integer => args.int(name).map(|n| Ok(Value::Text(n.to_string()))),
            Check::Flag => args.bool(name).map(|b| Ok(Value::Flag(b))),
            Check::Choice => args.str(name).map(|text| Ok(Value::Text(text.to_string()))),
        };
        if let Some(value) = value {
            values.insert(name.clone(), value?);
        }
    }
    let argv: Vec<String> = custom
        .elements
        .iter()
        .filter_map(|pieces| template::render(pieces, &values))
        .collect();

    let auth = ctx.authorize(None)?;
    ctx.bins()
        .check_program(&custom.program)
        .map_err(ToolError::Failed)?;
    let mut cmd = ctx.command_at(custom.program.clone()).args(argv);
    if let Some(timeout) = custom.timeout {
        cmd = cmd.timeout(timeout);
    }
    cmd.env.extend(custom.env.iter().cloned());
    if let Some(user) = &custom.run_as {
        let account = User::from_name(user).ok().flatten().ok_or_else(|| {
            ToolError::Failed(format!(
                "the user {user}, which this tool is set to run as, does not exist"
            ))
        })?;
        let euid = rustix::process::geteuid();
        if account.uid.as_raw() != euid.as_raw() {
            if !euid.is_root() {
                return Err(ToolError::Failed(format!(
                    "this tool is set to run as {user}, which needs opsmcp itself to run as root"
                )));
            }
            cmd.run_as = Some(RunAs {
                uid: account.uid.as_raw(),
                gid: account.gid.as_raw(),
            });
            cmd.env.extend([
                (
                    "HOME".to_string(),
                    account.dir.to_string_lossy().into_owned(),
                ),
                ("USER".to_string(), account.name.clone()),
                ("LOGNAME".to_string(), account.name.clone()),
            ]);
        }
    }
    let out = ctx.run(cmd).await?;
    let succeeded = !out.timed_out
        && out
            .code
            .is_some_and(|code| custom.ok_exit_codes.contains(&code));
    auth.done(command_text(&out), succeeded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::policy::Access;
    use crate::tools::testing::{call, host, host_with_trust, ok_text, write_executable};
    use serde_json::{Value as Json, json};
    use std::path::Path;

    /// A script that prints each of its arguments on its own line, then `$EXTRA`.
    fn script(dir: &Path, name: &str, body: &str) -> String {
        let path = dir.join(name);
        write_executable(&path, &format!("#!/bin/sh\n{body}\n"));
        path.to_string_lossy().into_owned()
    }

    const ROLES: &str = r#"
[roles.admin]
allow = ["@all"]
[roles.reader]
allow = ["@read"]
[unix_users.adam]
roles = ["admin"]
[unix_users.rita]
roles = ["reader"]
"#;

    /// Runs custom tool `name` from `config` as `user`.
    async fn run(config: &str, name: &str, user: &str, arguments: Json) -> ToolResult {
        let (host, _audit) = host(&format!("{ROLES}{config}"));
        let tool = tool(name, &host.cfg.custom[name]).unwrap();
        call(&host, user, &tool, arguments).await
    }

    fn haproxy(dir: &Path) -> String {
        let program = script(dir, "haproxystatus", "printf '%s\\n' \"$@\"");
        format!(
            r#"
[custom.haproxy_set]
description = "Set this host's state in HAProxy"
access = "write"
command = ["{program}", "set", "{{state}}", "--weight={{weight}}", "{{force?--force}}", "{{comment}}"]
[custom.haproxy_set.params.state]
type = "enum"
description = "Desired state"
values = ["up", "down", "drain"]
required = true
[custom.haproxy_set.params.weight]
type = "integer"
description = "Weight"
max = 100
[custom.haproxy_set.params.force]
type = "boolean"
description = "Skip the safety check"
[custom.haproxy_set.params.comment]
type = "string"
description = "Why"
"#
        )
    }

    #[tokio::test]
    async fn the_tool_carries_the_configured_description_permission_and_access() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::parse(&haproxy(dir.path())).unwrap();
        let tool = tool("haproxy_set", &cfg.custom["haproxy_set"]).unwrap();
        assert_eq!(tool.name, "haproxy_set");
        assert_eq!(tool.description, "Set this host's state in HAProxy");
        assert_eq!(tool.permission, "custom.haproxy_set");
        assert_eq!(tool.access, Access::Write);
        let names: Vec<&str> = tool.params.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["comment", "force", "state", "weight"]);
        assert!(
            tool.params
                .iter()
                .find(|p| p.name == "state")
                .unwrap()
                .required
        );
    }

    #[tokio::test]
    async fn only_the_given_parameters_appear_on_the_command_line() {
        let dir = tempfile::tempdir().unwrap();
        let config = haproxy(dir.path());
        let text = ok_text(run(&config, "haproxy_set", "adam", json!({"state": "up"})).await);
        assert_eq!(text, "set\nup\n");
        let all = json!({"state": "down", "weight": 50, "force": true, "comment": "maint"});
        let text = ok_text(run(&config, "haproxy_set", "adam", all).await);
        assert_eq!(text, "set\ndown\n--weight=50\n--force\nmaint\n");
        let text = ok_text(
            run(
                &config,
                "haproxy_set",
                "adam",
                json!({"state": "up", "force": false}),
            )
            .await,
        );
        assert_eq!(text, "set\nup\n");
    }

    #[tokio::test]
    async fn values_outside_what_the_operator_declared_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let config = haproxy(dir.path());
        for arguments in [
            json!({"state": "sideways"}),
            json!({}),
            json!({"state": "up", "weight": 101}),
            json!({"state": "up", "weight": -1}),
            json!({"state": "up", "comment": "-rf"}),
            json!({"state": "up", "comment": "two words"}),
            json!({"state": "up", "comment": "$(reboot)"}),
            json!({"state": "up", "comment": "a;b"}),
            json!({"state": "up", "comment": ""}),
            json!({"state": "up", "extra": "x"}),
        ] {
            let result = run(&config, "haproxy_set", "adam", arguments.clone()).await;
            assert!(
                matches!(result, Err(ToolError::Invalid(_))),
                "{arguments}: {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn an_operator_pattern_must_match_the_whole_value() {
        let dir = tempfile::tempdir().unwrap();
        let program = script(dir.path(), "cert", "printf '%s\\n' \"$@\"");
        let config = format!(
            r#"
[custom.cert_request]
description = "Request a certificate"
access = "write"
command = ["{program}", "--host", "{{host}}"]
[custom.cert_request.params.host]
type = "string"
description = "Host name"
pattern = "[a-z0-9.-]+"
max_len = 20
required = true
"#
        );
        let text = ok_text(
            run(
                &config,
                "cert_request",
                "adam",
                json!({"host": "web1.example.com"}),
            )
            .await,
        );
        assert_eq!(text, "--host\nweb1.example.com\n");
        for bad in [
            "Web1",
            "web1;id",
            "web1 --force",
            "a-very-long-host-name.example.com",
        ] {
            let result = run(&config, "cert_request", "adam", json!({"host": bad})).await;
            assert!(
                matches!(result, Err(ToolError::Invalid(_))),
                "{bad}: {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_caller_without_the_tools_permission_does_not_run_it() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("ran");
        let program = script(dir.path(), "mark", &format!(": > {}", marker.display()));
        let config = format!(
            "[custom.mark]\ndescription = \"Leaves a mark\"\naccess = \"write\"\ncommand = [\"{program}\"]\n"
        );
        // rita has @read; this tool is tagged write
        let result = run(&config, "mark", "rita", json!({})).await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        assert!(!marker.exists());
        ok_text(run(&config, "mark", "adam", json!({})).await);
        assert!(marker.exists());
    }

    #[tokio::test]
    async fn a_read_tool_is_covered_by_the_read_group() {
        let dir = tempfile::tempdir().unwrap();
        let program = script(dir.path(), "galera", "echo 'wsrep_cluster_size 3'");
        let config = format!(
            "[custom.galera_status]\ndescription = \"Galera status\"\naccess = \"read\"\ncommand = [\"{program}\"]\n"
        );
        assert_eq!(
            ok_text(run(&config, "galera_status", "rita", json!({})).await),
            "wsrep_cluster_size 3\n"
        );
    }

    #[tokio::test]
    async fn exit_codes_listed_as_ok_are_not_errors() {
        let dir = tempfile::tempdir().unwrap();
        let program = script(dir.path(), "state", "echo draining; exit 3");
        let base = format!(
            "[custom.state]\ndescription = \"State\"\naccess = \"read\"\ncommand = [\"{program}\"]\n"
        );
        let strict = run(&base, "state", "rita", json!({})).await.unwrap();
        assert!(strict.is_error());
        assert!(
            strict.text().contains("draining") && strict.text().contains("exit status 3"),
            "{}",
            strict.text()
        );
        let lenient = run(
            &format!("{base}ok_exit_codes = [0, 3]\n"),
            "state",
            "rita",
            json!({}),
        )
        .await
        .unwrap();
        assert!(!lenient.is_error(), "{}", lenient.text());
    }

    #[tokio::test]
    async fn configured_environment_reaches_the_command() {
        let dir = tempfile::tempdir().unwrap();
        let program = script(dir.path(), "env", "echo \"[$REGION][$HOME]\"");
        let config = format!(
            "[custom.env]\ndescription = \"Env\"\naccess = \"read\"\ncommand = [\"{program}\"]\n[custom.env.env]\nREGION = \"eu-west\"\n"
        );
        assert_eq!(
            ok_text(run(&config, "env", "rita", json!({})).await),
            "[eu-west][]\n"
        );
    }

    #[tokio::test]
    async fn a_command_that_overruns_its_time_limit_is_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let program = script(dir.path(), "slow", "echo started; sleep 30");
        let config = format!(
            "[custom.slow]\ndescription = \"Slow\"\naccess = \"read\"\ncommand = [\"{program}\"]\ntimeout_secs = 1\n"
        );
        let started = std::time::Instant::now();
        let output = run(&config, "slow", "rita", json!({})).await.unwrap();
        assert!(output.is_error());
        assert!(output.text().contains("time limit"), "{}", output.text());
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[tokio::test]
    async fn run_as_another_user_needs_root() {
        if rustix::process::geteuid().is_root() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let program = script(dir.path(), "who", "echo ran");
        let config = |user: &str| {
            format!(
                "[custom.who]\ndescription = \"Who\"\naccess = \"read\"\ncommand = [\"{program}\"]\nrun_as = \"{user}\"\n"
            )
        };
        match run(&config("root"), "who", "rita", json!({})).await {
            Err(ToolError::Failed(message)) => assert!(message.contains("root"), "{message}"),
            other => panic!("expected a failure, got {other:?}"),
        }
        match run(&config("no-such-user-xyz"), "who", "rita", json!({})).await {
            Err(ToolError::Failed(message)) => {
                assert!(message.contains("no-such-user-xyz"), "{message}")
            }
            other => panic!("expected a failure, got {other:?}"),
        }
        // running as the user we already are is fine
        let me = crate::identity::current().unwrap().user;
        assert_eq!(
            ok_text(run(&config(&me), "who", "rita", json!({})).await),
            "ran\n"
        );
    }

    #[tokio::test]
    async fn a_program_others_could_replace_is_not_run_when_trust_is_required() {
        if rustix::process::geteuid().is_root() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("ran");
        let program = script(dir.path(), "mark", &format!(": > {}", marker.display()));
        let config = format!(
            "{ROLES}[custom.mark]\ndescription = \"Mark\"\naccess = \"read\"\ncommand = [\"{program}\"]\n"
        );
        // as when the server runs as root: only root-owned programs are trusted, and
        // this script belongs to the user running the tests
        let (host, _audit) = host_with_trust(&config, Some(vec![]));
        let tool = tool("mark", &host.cfg.custom["mark"]).unwrap();
        match call(&host, "rita", &tool, json!({})).await {
            Err(ToolError::Failed(message)) => assert!(message.contains("refusing"), "{message}"),
            other => panic!("expected a failure, got {other:?}"),
        }
        assert!(!marker.exists());
    }
}
