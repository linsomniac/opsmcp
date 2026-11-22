//! Configuration checks: a service's own syntax check, before a reload.

use super::args::{Args, Param};
use super::{Ctx, Tool, ToolError, ToolResult, command_text, required};
use crate::exec::{Cmd, CmdOutput};
use crate::policy::Access;
use crate::sanitize::{keep_tail, redact_text};

/// One configuration check: the name the caller asks for (and the resource a grant
/// names), and the commands that perform it, in order of preference. The first one
/// that is installed is run.
pub struct Check {
    pub name: &'static str,
    pub commands: &'static [(&'static str, &'static [&'static str])],
}

/// The checks on offer.
///
/// AIDEV-NOTE: every entry is a fixed program with fixed arguments; nothing from the
/// caller reaches a command line. Each must be the service's own CHECK: it reads the
/// configuration and reports, and must never apply it, reload or restart anything. Some
/// of these are not strictly read-only, which is accepted because it is what running
/// the check by hand does: `nginx -t` creates a missing log or temp directory, and
/// `postfix check` creates missing queue directories. Look at what a check really does
/// before adding one (`mysqld --validate-config`, for example, is left out: on some
/// versions it starts enough of the server to touch the data directory).
pub const CHECKS: &[Check] = &[
    Check {
        name: "nginx",
        commands: &[("nginx", &["-t"])],
    },
    Check {
        name: "haproxy",
        commands: &[("haproxy", &["-c", "-f", "/etc/haproxy/haproxy.cfg"])],
    },
    Check {
        name: "sshd",
        commands: &[("sshd", &["-t"])],
    },
    Check {
        name: "sudoers",
        commands: &[("visudo", &["-c"])],
    },
    Check {
        name: "apache",
        commands: &[
            ("apache2ctl", &["configtest"]),
            ("apachectl", &["configtest"]),
        ],
    },
    Check {
        name: "named",
        commands: &[("named-checkconf", &[])],
    },
    Check {
        name: "postfix",
        commands: &[("postfix", &["check"])],
    },
    Check {
        name: "nftables",
        commands: &[("nft", &["-c", "-f", "/etc/nftables.conf"])],
    },
    Check {
        name: "rsyslog",
        commands: &[("rsyslogd", &["-N1"])],
    },
    Check {
        name: "keepalived",
        commands: &[("keepalived", &["-t"])],
    },
    Check {
        name: "dnsmasq",
        commands: &[("dnsmasq", &["--test"])],
    },
    Check {
        name: "squid",
        commands: &[("squid", &["-k", "parse"])],
    },
    Check {
        name: "fstab",
        commands: &[("findmnt", &["--verify"])],
    },
    Check {
        name: "logrotate",
        commands: &[("logrotate", &["-d", "/etc/logrotate.conf"])],
    },
];

pub fn tools() -> Vec<Tool> {
    let names: Vec<&str> = CHECKS.iter().map(|check| check.name).collect();
    vec![Tool::new(
        "config_validate",
        "Check a service's configuration with the service's own syntax check, without \
         loading or applying it (nginx -t, haproxy -c, sshd -t, visudo -c and the like). \
         Use it after a configuration change and before reloading or restarting the \
         service. The first line of the result is the verdict. Only the checks listed \
         are built in; an operator can add others as custom tools.",
        Access::Read,
        "config.validate",
        vec![
            Param::choice(
                "service",
                "Which configuration to check. fstab checks /etc/fstab; sudoers checks \
                 /etc/sudoers and what it includes; nftables checks /etc/nftables.conf",
                &names,
            )
            .required(),
        ],
        config_validate,
    )]
}

/// The verdict line for a finished check. `said` is what the checker printed.
fn verdict(out: &CmdOutput, said: &str) -> String {
    if out.timed_out {
        "Result: unknown (the check did not finish within its time limit)".to_string()
    } else if let Some(signal) = out.signal {
        format!("Result: unknown (the check was killed by signal {signal})")
    } else {
        match out.code {
            // AIDEV-NOTE: an exit status of 0 is not always a clean bill of health.
            // `postfix check` reports a mistyped parameter as a warning and exits 0, and
            // haproxy and nginx warn about things that will bite later. The verdict stays
            // "valid" (the checker did not refuse the configuration), but says to read on.
            Some(0) if has_warning(said) => "Result: valid, with warnings (read them: some \
                                             checkers report mistakes only as warnings)"
                .to_string(),
            Some(0) => "Result: valid".to_string(),
            Some(code) => format!("Result: INVALID (exit {code})"),
            None => "Result: unknown (the check did not report an exit status)".to_string(),
        }
    }
}

/// What a finished check says about the configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    /// The checker accepted it.
    Valid,
    /// The checker refused it.
    Invalid,
    /// The checker gave no verdict: it did not finish, or was killed.
    Unknown,
}

fn outcome(out: &CmdOutput) -> Outcome {
    if out.timed_out || out.signal.is_some() {
        return Outcome::Unknown;
    }
    match out.code {
        Some(0) => Outcome::Valid,
        Some(_) => Outcome::Invalid,
        None => Outcome::Unknown,
    }
}

/// Whether a checker's output has a line that calls itself a warning: `warning:` (postfix,
/// sshd, most others), `[WARNING]` (haproxy) or `[warn]` (nginx), in any case.
fn has_warning(output: &str) -> bool {
    output.lines().any(|line| {
        let line = line.to_ascii_lowercase();
        let warns =
            line.contains("warning:") || line.contains("[warning]") || line.contains("[warn]");
        // `logrotate -d` says on every run that debug mode changes nothing: that is about
        // how it was run, not about the configuration.
        warns && !line.contains("logrotate in debug mode")
    })
}

/// The check with this name, if there is one.
pub(super) fn find_check(name: &str) -> Option<&'static Check> {
    CHECKS.iter().find(|check| check.name == name)
}

/// The command that performs `check` on this host: the first of its commands that is
/// installed. A caller about to depend on the check (config_edit) asks for this before
/// changing anything, so that a missing program is found out first.
pub(super) fn check_command(ctx: &Ctx, check: &Check) -> Result<Cmd, ToolError> {
    let mut missing = Vec::new();
    for (program, argv) in check.commands {
        match ctx.command(program) {
            Ok(cmd) => return Ok(cmd.args(argv.iter().copied())),
            Err(ToolError::Failed(problem)) => missing.push(problem),
            Err(other) => return Err(other),
        }
    }
    Err(ToolError::Failed(format!(
        "cannot check {}: {}",
        check.name,
        missing.join("; ")
    )))
}

/// Runs a check's command. Returns what to show (the verdict first) and what the check
/// says about the configuration. `reserve` is how much of the output limit the caller
/// needs for text of its own.
pub(super) async fn run_check(
    ctx: &Ctx,
    cmd: Cmd,
    reserve: usize,
) -> Result<(String, Outcome), ToolError> {
    let out = ctx.run(cmd).await?;
    // AIDEV-NOTE: the verdict is the FIRST line, so it survives whatever happens to a
    // long output; of the checker's own text the end is kept, which is where checkers
    // put the error that made them give up. Checkers echo the offending configuration
    // line, which can hold a password: mask what looks like a secret.
    let said = redact_text(&command_text(&out));
    let head = verdict(&out, &said);
    let room = ctx
        .output_budget()
        .saturating_sub(head.len() + 120 + reserve);
    let (body, dropped) = keep_tail(&said, room);
    let mut text = format!("{head}\n");
    if dropped > 0 {
        text.push_str(&format!(
            "[{dropped} earlier lines of the checker's output left out to fit the output limit]\n"
        ));
    }
    text.push_str(&body);
    Ok((text, outcome(&out)))
}

async fn config_validate(ctx: Ctx, args: Args) -> ToolResult {
    let asked = required(&args, "service")?;
    let Some(check) = find_check(asked) else {
        return Err(ToolError::Invalid(format!(
            "{asked:?} is not a known check"
        )));
    };
    // The resource is the check's name, so a grant can cover some checks and not others.
    let auth = ctx.authorize(Some(check.name))?;
    let cmd = check_command(&ctx, check)?;
    let (text, outcome) = run_check(&ctx, cmd, 0).await?;
    auth.done(text, outcome == Outcome::Valid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::testing::{FakeBins, call, find, host, ok_text};
    use crate::tools::{Host, ToolError, ToolResult};
    use serde_json::{Value, json};
    use std::sync::Arc;

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn fixture(fake: &FakeBins) -> (Arc<Host>, MemorySink) {
        host(&format!(
            r#"
[roles.reader]
allow = ["@read"]
[roles.web]
allow = ["config.validate:nginx", "config.validate:haproxy"]
[unix_users.rita]
roles = ["reader"]
[unix_users.wendy]
roles = ["web"]
{}"#,
            fake.config_only()
        ))
    }

    async fn run(host: &Arc<Host>, user: &str, arguments: Value) -> ToolResult {
        call(host, user, &find(tools(), "config_validate"), arguments).await
    }

    #[test]
    fn every_check_offered_has_a_command_and_every_command_is_offered() {
        let tool = find(tools(), "config_validate");
        let offered = match &tool.params[0].kind {
            crate::tools::args::Kind::Choice(values) => values.clone(),
            other => panic!("service should be a choice, got {other:?}"),
        };
        let table: Vec<String> = CHECKS.iter().map(|c| c.name.to_string()).collect();
        assert_eq!(offered, table);
        for check in CHECKS {
            assert!(!check.commands.is_empty(), "{}", check.name);
            for (program, args) in check.commands {
                assert!(
                    !program.is_empty() && !program.contains('/'),
                    "{}: {program:?} must be a bare command name",
                    check.name
                );
                // fixed arguments only: nothing that could be mistaken for a placeholder
                assert!(
                    args.iter().all(|a| !a.is_empty() && !a.contains('{')),
                    "{}: {args:?}",
                    check.name
                );
            }
        }
        // names are unique, and usable as the resource in a grant
        let mut names = table.clone();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), table.len());
    }

    #[tokio::test]
    async fn a_valid_configuration_is_reported_as_valid() {
        let fake = FakeBins::new().add_script(
            "nginx",
            "echo 'nginx: the configuration file /etc/nginx/nginx.conf syntax is ok' >&2\n\
             echo 'nginx: configuration file /etc/nginx/nginx.conf test is successful' >&2",
        );
        let (host, audit) = fixture(&fake);
        let text = ok_text(run(&host, "rita", json!({"service": "nginx"})).await);
        assert!(
            text.starts_with("Result: valid\n"),
            "the verdict comes first: {text}"
        );
        assert!(text.contains("test is successful"), "{text}");
        assert_eq!(fake.calls("nginx"), [strings(&["-t"])]);
        assert_eq!(audit.records().last().unwrap()["resource"], "nginx");
    }

    #[tokio::test]
    async fn an_invalid_configuration_is_an_error_result_with_the_checkers_message() {
        let fake = FakeBins::new().add_script(
            "haproxy",
            "echo \"[ALERT] parsing [/etc/haproxy/haproxy.cfg:12] : unknown keyword 'bnd'\" >&2\nexit 1",
        );
        let (host, _audit) = fixture(&fake);
        let output = run(&host, "rita", json!({"service": "haproxy"}))
            .await
            .unwrap();
        assert!(output.is_error());
        assert!(
            output.text().starts_with("Result: INVALID (exit 1)\n"),
            "{}",
            output.text()
        );
        assert!(
            output.text().contains("unknown keyword"),
            "{}",
            output.text()
        );
        assert_eq!(
            fake.calls("haproxy"),
            [strings(&["-c", "-f", "/etc/haproxy/haproxy.cfg"])]
        );
    }

    #[tokio::test]
    async fn the_second_candidate_command_is_used_when_the_first_is_not_installed() {
        let fake = FakeBins::new().add("apachectl", "Syntax OK\n", 0);
        let (host, _audit) = fixture(&fake);
        let text = ok_text(run(&host, "rita", json!({"service": "apache"})).await);
        assert!(text.contains("Syntax OK"), "{text}");
        assert_eq!(fake.calls("apachectl"), [strings(&["configtest"])]);
    }

    #[tokio::test]
    async fn a_checker_that_is_not_installed_is_a_clear_failure() {
        let fake = FakeBins::new().add("nginx", "", 0);
        let (host, _audit) = fixture(&fake);
        match run(&host, "rita", json!({"service": "apache"})).await {
            Err(ToolError::Failed(message)) => {
                assert!(
                    message.contains("apache2ctl") && message.contains("apachectl"),
                    "{message}"
                );
            }
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_grant_for_one_check_does_not_cover_another() {
        let fake = FakeBins::new().add("nginx", "ok\n", 0).add("sshd", "", 0);
        let (host, audit) = fixture(&fake);
        ok_text(run(&host, "wendy", json!({"service": "nginx"})).await);
        let result = run(&host, "wendy", json!({"service": "sshd"})).await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        assert_eq!(audit.records().last().unwrap()["decision"], "deny");
        assert_eq!(audit.records().last().unwrap()["resource"], "sshd");
        assert_eq!(fake.calls("sshd"), Vec::<Vec<String>>::new());
    }

    #[tokio::test]
    async fn a_check_that_is_not_in_the_list_is_refused_before_anything_runs() {
        let fake = FakeBins::new().add("nginx", "ok\n", 0);
        let (host, _audit) = fixture(&fake);
        for bad in ["", "nginx; id", "../nginx", "mysql"] {
            let result = run(&host, "rita", json!({"service": bad})).await;
            assert!(matches!(result, Err(ToolError::Invalid(_))), "{bad:?}");
        }
        assert_eq!(fake.calls("nginx"), Vec::<Vec<String>>::new());
    }

    #[tokio::test]
    async fn secrets_echoed_by_a_checker_are_masked() {
        let fake = FakeBins::new().add_script(
            "nginx",
            "echo 'nginx: [emerg] invalid value in proxy_set_header --password=hunter2' >&2\nexit 1",
        );
        let (host, _audit) = fixture(&fake);
        let output = run(&host, "rita", json!({"service": "nginx"}))
            .await
            .unwrap();
        assert!(!output.text().contains("hunter2"), "{}", output.text());
        assert!(output.text().contains("<redacted>"), "{}", output.text());
    }

    #[tokio::test]
    async fn long_output_keeps_the_verdict_and_the_end_of_what_the_checker_said() {
        let fake = FakeBins::new().add_script(
            "logrotate",
            "i=0; while [ $i -lt 3000 ]; do echo \"considering log /var/log/app/file-$i.log\" >&2; i=$((i+1)); done\n\
             echo 'error: found error in /etc/logrotate.d/app, skipping' >&2\nexit 1",
        );
        let (host, _audit) = host(&format!(
            "[roles.reader]\nallow = [\"@read\"]\n[unix_users.rita]\nroles = [\"reader\"]\n\
             [limits]\nmax_output_bytes = 8192\n{}",
            fake.config_only()
        ));
        let output = run(&host, "rita", json!({"service": "logrotate"}))
            .await
            .unwrap();
        let text = output.text();
        assert!(text.len() <= 8192, "{} bytes", text.len());
        assert!(text.starts_with("Result: INVALID (exit 1)\n"), "{text}");
        assert!(
            text.contains("found error in /etc/logrotate.d/app"),
            "{text}"
        );
        assert!(text.contains("left out"), "{text}");
        assert_eq!(
            fake.calls("logrotate"),
            [strings(&["-d", "/etc/logrotate.conf"])]
        );
    }

    /// AIDEV-NOTE: `postfix check` reports a mistyped parameter as a warning and exits
    /// 0. "Result: valid" over that would read as a clean bill of health.
    #[tokio::test]
    async fn warnings_from_a_checker_that_exits_cleanly_are_pointed_out() {
        let fake = FakeBins::new()
            .add_script(
                "postfix",
                "echo 'postfix: warning: /etc/postfix/main.cf: unused parameter: smtpd_tls_cert_fle=/x' >&2\nexit 0",
            )
            .add_script("nginx", "echo 'nginx: the configuration file syntax is ok' >&2");
        let (host, _audit) = fixture(&fake);
        let output = run(&host, "rita", json!({"service": "postfix"}))
            .await
            .unwrap();
        // still a success: the checker did not refuse the configuration
        assert!(!output.is_error());
        assert!(
            output.text().starts_with(
                "Result: valid, with warnings (read them: some checkers report mistakes only as warnings)\n"
            ),
            "{}",
            output.text()
        );
        assert!(
            output.text().contains("unused parameter"),
            "{}",
            output.text()
        );
        // a checker that says nothing of the kind keeps the plain verdict
        let text = ok_text(run(&host, "rita", json!({"service": "nginx"})).await);
        assert!(text.starts_with("Result: valid\n"), "{text}");
    }

    #[test]
    fn a_warning_is_a_line_that_says_it_is_one() {
        for line in [
            "postfix: warning: /etc/postfix/main.cf: unused parameter: x=y",
            "Warning: the ECDSA host key is not readable",
            "[WARNING]  (12) : config : missing timeouts for backend 'web'.",
            "nginx: [warn] conflicting server name \"a\" on 0.0.0.0:80, ignored",
            "first line\nsecond: WARNING: something",
        ] {
            assert!(has_warning(line), "{line}");
        }
        for line in [
            "",
            "syntax is ok",
            "no warnings were found",
            "error: found error in /etc/logrotate.d/app, skipping",
            // logrotate -d says this on every run: it is about the mode, not the configuration
            "warning: logrotate in debug mode does nothing except printing debug messages!  \
             Consider using verbose mode (-v) instead if this is not what you want.",
        ] {
            assert!(!has_warning(line), "{line}");
        }
    }

    #[test]
    fn the_outcome_of_a_check_is_valid_invalid_or_unknown() {
        let out = |code: Option<i32>, timed_out: bool| CmdOutput {
            code,
            signal: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            truncated: false,
            timed_out,
        };
        assert_eq!(outcome(&out(Some(0), false)), Outcome::Valid);
        assert_eq!(outcome(&out(Some(1), false)), Outcome::Invalid);
        assert_eq!(outcome(&out(None, true)), Outcome::Unknown);
        assert_eq!(outcome(&out(None, false)), Outcome::Unknown);
        let killed = CmdOutput {
            signal: Some(9),
            ..out(None, false)
        };
        assert_eq!(outcome(&killed), Outcome::Unknown);
    }

    #[tokio::test]
    async fn a_checker_that_does_not_finish_is_a_failure_not_a_verdict() {
        // a shell loop: the stand-in commands have no PATH to find `sleep` on
        let fake = FakeBins::new().add_script("sshd", "while :; do :; done");
        let (host, _audit) = host(&format!(
            "[roles.reader]\nallow = [\"@read\"]\n[unix_users.rita]\nroles = [\"reader\"]\n\
             [limits]\ncommand_timeout_secs = 1\ncall_timeout_secs = 5\n{}",
            fake.config_only()
        ));
        let output = run(&host, "rita", json!({"service": "sshd"}))
            .await
            .unwrap();
        assert!(output.is_error());
        assert!(
            output.text().starts_with("Result: unknown"),
            "{}",
            output.text()
        );
        assert!(!output.text().contains("INVALID"), "{}", output.text());
    }
}
