//! systemd units: list, status, start/stop/restart, enable/disable.

use std::time::Duration;

use super::args::{Args, Param};
use super::{Authorized, Ctx, Tool, ToolError, ToolResult, command_ok, command_text, required};
use crate::config::ServicesCfg;
use crate::exec::Cmd;
use crate::glob::glob_match;
use crate::policy::Access;
use crate::sanitize::redact_text;

const UNIT_TYPES: [&str; 6] = ["service", "timer", "socket", "mount", "target", "path"];
const UNIT_STATES: [&str; 8] = [
    "active",
    "inactive",
    "failed",
    "running",
    "exited",
    "dead",
    "activating",
    "deactivating",
];
const CONTROL_ACTIONS: [&str; 6] = [
    "start",
    "stop",
    "restart",
    "reload",
    "try-restart",
    "reload-or-restart",
];

pub fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "service_list",
            "List systemd units and their state (systemctl list-units). Lists services \
             unless another unit type is asked for; can be narrowed to a state such as \
             failed, or to names matching a pattern such as 'nginx*'.",
            Access::Read,
            "service.view",
            vec![
                Param::choice("type", "Unit type (default service)", &UNIT_TYPES),
                Param::choice("state", "Only units in this state", &UNIT_STATES),
                Param::str(
                    "pattern",
                    "Only units whose name matches this glob, e.g. 'nginx*'",
                )
                .max_len(255),
            ],
            service_list,
        ),
        Tool::new(
            "service_status",
            "Show the status of one systemd unit (systemctl status): state, main process, \
             memory, and its most recent log lines.",
            Access::Read,
            "service.view",
            vec![
                Param::str("unit", "Unit name, e.g. nginx or nginx.service")
                    .max_len(255)
                    .required(),
                Param::int("lines", "Recent log lines to include (default 20)", 0, 200),
            ],
            service_status,
        ),
        Tool::new(
            "service_control",
            "Start, stop, restart or reload a systemd unit. Waits for the job to finish and \
             reports the unit's state afterwards. Units the host's configuration marks as \
             protected cannot be controlled.",
            Access::Write,
            "service.control",
            vec![
                Param::str("unit", "Unit name, e.g. nginx or nginx.service")
                    .max_len(255)
                    .required(),
                Param::choice("action", "What to do", &CONTROL_ACTIONS).required(),
            ],
            service_control,
        ),
        Tool::new(
            "service_enable",
            "Enable or disable a systemd unit, so that it does or does not start at boot. \
             This change persists across reboots.",
            Access::Write,
            "service.enable",
            vec![
                Param::str("unit", "Unit name, e.g. nginx or nginx.service")
                    .max_len(255)
                    .required(),
                Param::choice("action", "enable or disable", &["enable", "disable"]).required(),
                Param::bool(
                    "now",
                    "Also start (when enabling) or stop (when disabling) it now",
                ),
            ],
            service_enable,
        ),
    ]
}

const UNIT_SUFFIXES: [&str; 11] = [
    ".service",
    ".socket",
    ".device",
    ".mount",
    ".automount",
    ".swap",
    ".target",
    ".path",
    ".timer",
    ".slice",
    ".scope",
];

/// Checks a unit name and completes it the way systemctl does (`nginx` means
/// `nginx.service`).
///
/// AIDEV-NOTE: only the characters systemd allows in unit names are accepted. That keeps
/// out option-like names (a leading `-`), paths, and above all glob characters: systemctl
/// expands `ssh*` itself, which would act on units the caller was never checked against.
pub fn normalize_unit(name: &str) -> Result<String, ToolError> {
    let allowed = |c: char| c.is_ascii_alphanumeric() || ":_.@\\-".contains(c);
    if name.is_empty() || name.len() > 255 || name.starts_with('-') || !name.chars().all(allowed) {
        return Err(ToolError::Invalid(format!(
            "{name:?} is not a unit name (letters, digits and : _ . @ \\ - only; no wildcards)"
        )));
    }
    if UNIT_SUFFIXES.iter().any(|suffix| name.ends_with(suffix)) {
        Ok(name.to_string())
    } else {
        Ok(format!("{name}.service"))
    }
}

/// The canonical name (`Id`) and `LoadState` from `systemctl show` output.
pub fn parse_show(text: &str) -> Option<(String, String)> {
    let mut id = None;
    let mut load_state = None;
    for line in text.lines() {
        match line.split_once('=') {
            Some(("Id", value)) => id = Some(value.to_string()),
            Some(("LoadState", value)) => load_state = Some(value.to_string()),
            _ => {}
        }
    }
    Some((id?, load_state?))
}

/// The pattern in `services.protected` that covers one of `names`, if any does.
pub fn protected_by(cfg: &ServicesCfg, names: &[&str]) -> Option<String> {
    cfg.protected
        .iter()
        .find(|pattern| names.iter().any(|name| glob_match(pattern, name)))
        .cloned()
}

/// Asks systemd for a unit's real name (`Id`) and whether it exists (`LoadState`).
pub(super) async fn lookup(ctx: &Ctx, unit: &str) -> Result<(String, String), ToolError> {
    let show = ctx
        .run(ctx.command("systemctl")?.args([
            "show",
            "--property=Id",
            "--property=LoadState",
            "--",
            unit,
        ]))
        .await?;
    let looked_up =
        parse_show(&String::from_utf8_lossy(&show.stdout)).filter(|_| command_ok(&show));
    let Some((id, load_state)) = looked_up else {
        return Err(ToolError::Failed(format!(
            "cannot look up {unit}: {}",
            command_text(&show).trim()
        )));
    };
    // What systemd reports is used as an argument next: hold it to the same rules.
    let id = normalize_unit(&id)
        .map_err(|_| ToolError::Failed(format!("systemd reported an unusable name for {unit}")))?;
    Ok((id, load_state))
}

/// Everything that must be true before a unit is changed. Returns the unit's canonical
/// name and the proof of authorization.
///
/// AIDEV-NOTE: a unit can be reached by more than one name (aliases such as sshd for
/// ssh.service). systemd is asked for the unit's real name first; the protected list is
/// checked against both names, and the caller's grant and the action itself use the real
/// one. Grants should therefore be written with real unit names.
pub(super) async fn authorize_change(
    ctx: &Ctx,
    asked: &str,
) -> Result<(String, Authorized), ToolError> {
    let unit = normalize_unit(asked)?;
    let (id, load_state) = lookup(ctx, &unit).await?;

    if let Some(pattern) = protected_by(&ctx.cfg().services, &[unit.as_str(), id.as_str()]) {
        let reason =
            format!("{id} is a protected unit on this host (services.protected: {pattern})");
        return Err(ctx.deny(Some(&id), &reason));
    }
    let auth = ctx.authorize(Some(&id))?;
    if load_state == "not-found" {
        return Err(ToolError::Failed(format!(
            "{id}: there is no such unit on this host"
        )));
    }
    Ok((id, auth))
}

/// A systemctl command for a change, with time for a slow unit to start or stop.
fn change_command(ctx: &Ctx) -> Result<Cmd, ToolError> {
    let limits = &ctx.cfg().limits;
    let wait = limits.call_timeout_secs.saturating_sub(10).min(90);
    let wait = wait.max(limits.command_timeout_secs);
    Ok(ctx.command("systemctl")?.timeout(Duration::from_secs(wait)))
}

/// `active`, `inactive`, `failed`... or `unknown` if systemd would not say.
async fn active_state(ctx: &Ctx, unit: &str) -> String {
    let Ok(cmd) = ctx.command("systemctl") else {
        return "unknown".to_string();
    };
    match ctx.run(cmd.args(["is-active", "--", unit])).await {
        Ok(out) if !out.stdout.is_empty() => {
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }
        _ => "unknown".to_string(),
    }
}

/// Runs a change that has been authorized and reports how it went.
async fn apply_change(
    ctx: &Ctx,
    auth: Authorized,
    argv: Vec<String>,
    what: &str,
    unit: &str,
) -> ToolResult {
    let out = ctx.run(change_command(ctx)?.args(argv)).await?;
    let succeeded = command_ok(&out);
    let state = active_state(ctx, unit).await;
    let mut text = command_text(&out);
    let verdict = if succeeded { "done" } else { "FAILED" };
    text.push_str(&format!(
        "{what} {unit}: {verdict}. The unit is now: {state}\n"
    ));
    auth.done(text, succeeded)
}

async fn service_list(ctx: Ctx, args: Args) -> ToolResult {
    let mut argv: Vec<String> = [
        "list-units",
        "--all",
        "--no-pager",
        "--no-legend",
        "--plain",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    argv.push(format!("--type={}", args.str("type").unwrap_or("service")));
    if let Some(state) = args.str("state") {
        argv.push(format!("--state={state}"));
    }
    if let Some(pattern) = args.str("pattern") {
        // A unit name, plus the glob characters systemctl understands here.
        let allowed = |c: char| c.is_ascii_alphanumeric() || ":_.@\\-*?[]".contains(c);
        if pattern.is_empty() || pattern.starts_with('-') || !pattern.chars().all(allowed) {
            return Err(ToolError::Invalid(format!(
                "{pattern:?} is not a unit name pattern (unit name characters and * ? [ ] only)"
            )));
        }
        argv.push("--".to_string());
        argv.push(pattern.to_string());
    }
    let auth = ctx.authorize(None)?;
    let out = ctx.run(ctx.command("systemctl")?.args(argv)).await?;
    let listing = command_text(&out);
    let text = if listing.trim().is_empty() {
        "(no matching units)\n".to_string()
    } else {
        format!("UNIT LOAD ACTIVE SUB DESCRIPTION\n{listing}")
    };
    auth.done(text, command_ok(&out))
}

async fn service_status(ctx: Ctx, args: Args) -> ToolResult {
    let asked = normalize_unit(required(&args, "unit")?)?;
    let lines = args.int("lines").unwrap_or(20);
    // Judged, like a change, by the unit's real name: asking by an alias must not get
    // around a grant or a deny written for the unit itself.
    let (unit, load_state) = lookup(&ctx, &asked).await?;
    let auth = ctx.authorize(Some(&unit))?;
    if load_state == "not-found" {
        return Err(ToolError::Failed(format!(
            "{unit}: there is no such unit on this host"
        )));
    }
    let mut out = ctx
        .run(ctx.command("systemctl")?.args([
            "status".to_string(),
            "--no-pager".to_string(),
            "--full".to_string(),
            format!("--lines={lines}"),
            "--".to_string(),
            unit,
        ]))
        .await?;
    // systemctl status exits 1 to 3 for a unit that is dead, failed or not running. That
    // is the answer to the question, not a failure to answer it.
    if matches!(out.code, Some(1..=3)) && !out.timed_out {
        out.code = Some(0);
    }
    // AIDEV-NOTE: status shows the unit's processes with their full command lines (and
    // its recent log lines). Mask secrets in them as process_list does; without this,
    // service.view would show what process.view takes care to hide.
    auth.done(redact_text(&command_text(&out)), command_ok(&out))
}

async fn service_control(ctx: Ctx, args: Args) -> ToolResult {
    let action = required(&args, "action")?.to_string();
    let (unit, auth) = authorize_change(&ctx, required(&args, "unit")?).await?;
    let argv = vec![
        "--no-ask-password".to_string(),
        action.clone(),
        "--".to_string(),
        unit.clone(),
    ];
    apply_change(&ctx, auth, argv, &action, &unit).await
}

async fn service_enable(ctx: Ctx, args: Args) -> ToolResult {
    let action = required(&args, "action")?.to_string();
    let (unit, auth) = authorize_change(&ctx, required(&args, "unit")?).await?;
    let mut argv = vec!["--no-ask-password".to_string(), action.clone()];
    if args.bool("now") == Some(true) {
        argv.push("--now".to_string());
    }
    argv.push("--".to_string());
    argv.push(unit.clone());
    apply_change(&ctx, auth, argv, &action, &unit).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::Host;
    use crate::tools::testing::{FakeBins, call, find, host, ok_text};
    use serde_json::{Value, json};
    use std::sync::Arc;

    #[test]
    fn parse_show_reads_properties_in_any_order() {
        let want = Some(("ssh.service".to_string(), "loaded".to_string()));
        assert_eq!(parse_show("Id=ssh.service\nLoadState=loaded\n"), want);
        assert_eq!(parse_show("LoadState=loaded\nId=ssh.service\n"), want);
        assert_eq!(parse_show("LoadState=loaded\n"), None);
        assert_eq!(parse_show(""), None);
    }

    #[test]
    fn protected_by_matches_any_of_the_names_a_unit_goes_by() {
        let cfg = ServicesCfg {
            protected: vec!["dbus*".to_string(), "ssh.service".to_string()],
        };
        assert_eq!(
            protected_by(&cfg, &["sshd.service", "ssh.service"]),
            Some("ssh.service".to_string())
        );
        assert_eq!(
            protected_by(&cfg, &["dbus-broker.service"]),
            Some("dbus*".to_string())
        );
        assert_eq!(protected_by(&cfg, &["nginx.service"]), None);
    }

    /// A stand-in systemctl. `show` describes whatever unit is asked about, mapping the
    /// alias sshd.service to ssh.service and reporting ghost.service as not found;
    /// `is-active` says active; `status` exits 3 like an inactive unit; any action on
    /// broken.service fails.
    fn fake_systemctl() -> FakeBins {
        FakeBins::new().add_script(
            "systemctl",
            r#"
for last; do :; done
case "$1" in
  show)
    case "$last" in
      sshd.service) printf 'Id=ssh.service\nLoadState=loaded\n' ;;
      ghost.service) printf 'Id=ghost.service\nLoadState=not-found\n' ;;
      *) printf 'Id=%s\nLoadState=loaded\n' "$last" ;;
    esac ;;
  is-active) echo active ;;
  status)
    echo "* $last - a unit"
    echo "     CGroup: /system.slice/$last"
    echo "             |-1234 /usr/bin/app --password=hunter2 --port 80"
    exit 3 ;;
  list-units) echo "nginx.service loaded active running A web server" ;;
  *)
    if [ "$last" = broken.service ]; then echo "Job for broken.service failed." >&2; exit 1; fi ;;
esac
"#,
        )
    }

    fn fixture(fake: &FakeBins) -> (Arc<Host>, MemorySink) {
        host(&format!(
            r#"
[roles.admin]
allow = ["@all"]
[roles.web]
allow = ["service.view", "service.control:nginx.service", "service.control:ssh.service"]
[roles.alias]
allow = ["service.control:sshd.service"]
[unix_users.adam]
roles = ["admin"]
[unix_users.wendy]
roles = ["web"]
[unix_users.alice]
roles = ["alias"]
[services]
protected = ["dbus*", "critical.service"]
{}"#,
            fake.config()
        ))
    }

    async fn run(host: &Arc<Host>, user: &str, tool: &str, arguments: Value) -> ToolResult {
        call(host, user, &find(tools(), tool), arguments).await
    }

    fn argv(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// The systemctl runs that changed something (not `show` or `is-active`).
    fn actions(fake: &FakeBins) -> Vec<Vec<String>> {
        fake.calls("systemctl")
            .into_iter()
            .filter(|call| !matches!(call.first().map(String::as_str), Some("show" | "is-active")))
            .collect()
    }

    #[tokio::test]
    async fn service_control_runs_the_action_on_the_canonical_unit_and_reports_its_state() {
        let fake = fake_systemctl();
        let (host, audit) = fixture(&fake);
        let text = ok_text(
            run(
                &host,
                "wendy",
                "service_control",
                json!({"unit": "nginx", "action": "restart"}),
            )
            .await,
        );
        assert!(
            text.contains("nginx.service") && text.contains("active"),
            "{text}"
        );
        assert_eq!(
            fake.calls("systemctl"),
            vec![
                argv(&[
                    "show",
                    "--property=Id",
                    "--property=LoadState",
                    "--",
                    "nginx.service"
                ]),
                argv(&["--no-ask-password", "restart", "--", "nginx.service"]),
                argv(&["is-active", "--", "nginx.service"]),
            ]
        );
        let record = audit.records().last().unwrap().clone();
        assert_eq!(
            (record["decision"].as_str(), record["resource"].as_str()),
            (Some("allow"), Some("nginx.service"))
        );
    }

    #[tokio::test]
    async fn service_control_checks_the_grant_before_touching_anything() {
        let fake = fake_systemctl();
        let (host, audit) = fixture(&fake);
        let result = run(
            &host,
            "wendy",
            "service_control",
            json!({"unit": "postgresql", "action": "stop"}),
        )
        .await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        assert_eq!(actions(&fake), Vec::<Vec<String>>::new());
        let record = audit.records().last().unwrap().clone();
        assert_eq!(
            (record["decision"].as_str(), record["resource"].as_str()),
            (Some("deny"), Some("postgresql.service"))
        );
    }

    #[tokio::test]
    async fn an_alias_is_judged_and_acted_on_by_the_unit_it_stands_for() {
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake);
        // wendy is granted ssh.service; asking by its alias sshd works and acts on ssh.service
        ok_text(
            run(
                &host,
                "wendy",
                "service_control",
                json!({"unit": "sshd", "action": "reload"}),
            )
            .await,
        );
        assert_eq!(
            actions(&fake),
            vec![argv(&["--no-ask-password", "reload", "--", "ssh.service"])]
        );
        // alice's grant names only the alias, which is not the unit's real name
        let result = run(
            &host,
            "alice",
            "service_control",
            json!({"unit": "sshd", "action": "reload"}),
        )
        .await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        assert_eq!(actions(&fake).len(), 1);
    }

    #[tokio::test]
    async fn protected_units_are_refused_whatever_the_caller_is_granted() {
        let fake = fake_systemctl();
        let (host, audit) = fixture(&fake);
        for unit in ["dbus", "dbus-broker.service", "critical"] {
            for (tool, action) in [
                ("service_control", "restart"),
                ("service_enable", "disable"),
            ] {
                match run(&host, "adam", tool, json!({"unit": unit, "action": action})).await {
                    Err(ToolError::Denied(message)) => {
                        assert!(message.contains("protected"), "{message}")
                    }
                    other => panic!("{unit}: expected a denial, got {other:?}"),
                }
            }
        }
        assert_eq!(actions(&fake), Vec::<Vec<String>>::new());
        assert_eq!(audit.records().last().unwrap()["decision"], "deny");
    }

    #[tokio::test]
    async fn a_unit_that_does_not_exist_is_reported_without_running_the_action() {
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake);
        match run(
            &host,
            "adam",
            "service_control",
            json!({"unit": "ghost", "action": "start"}),
        )
        .await
        {
            Err(ToolError::Failed(message)) => {
                assert!(message.contains("ghost.service"), "{message}")
            }
            other => panic!("expected a failure, got {other:?}"),
        }
        assert_eq!(actions(&fake), Vec::<Vec<String>>::new());
    }

    #[tokio::test]
    async fn a_failed_action_is_reported_as_an_error_with_systemctls_message() {
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake);
        let output = run(
            &host,
            "adam",
            "service_control",
            json!({"unit": "broken", "action": "start"}),
        )
        .await
        .unwrap();
        assert!(output.is_error());
        assert!(
            output.text().contains("Job for broken.service failed."),
            "{}",
            output.text()
        );
    }

    #[tokio::test]
    async fn invalid_unit_names_never_reach_systemctl() {
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake);
        for unit in ["nginx*", "--now", "a b", "../x"] {
            let result = run(
                &host,
                "adam",
                "service_control",
                json!({"unit": unit, "action": "stop"}),
            )
            .await;
            assert!(
                matches!(result, Err(ToolError::Invalid(_))),
                "{unit}: {result:?}"
            );
        }
        assert_eq!(fake.calls("systemctl"), Vec::<Vec<String>>::new());
    }

    #[tokio::test]
    async fn service_enable_passes_now_only_when_asked() {
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake);
        ok_text(
            run(
                &host,
                "adam",
                "service_enable",
                json!({"unit": "nginx", "action": "enable"}),
            )
            .await,
        );
        ok_text(
            run(
                &host,
                "adam",
                "service_enable",
                json!({"unit": "nginx", "action": "disable", "now": true}),
            )
            .await,
        );
        assert_eq!(
            actions(&fake),
            vec![
                argv(&["--no-ask-password", "enable", "--", "nginx.service"]),
                argv(&[
                    "--no-ask-password",
                    "disable",
                    "--now",
                    "--",
                    "nginx.service"
                ]),
            ]
        );
        // the web role has service.control but not service.enable
        let result = run(
            &host,
            "wendy",
            "service_enable",
            json!({"unit": "nginx", "action": "enable"}),
        )
        .await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
    }

    #[tokio::test]
    async fn service_status_treats_an_inactive_unit_as_an_answer_not_an_error() {
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake);
        let text = ok_text(
            run(
                &host,
                "wendy",
                "service_status",
                json!({"unit": "nginx", "lines": 5}),
            )
            .await,
        );
        assert!(text.contains("nginx.service - a unit"), "{text}");
        assert_eq!(
            fake.calls("systemctl"),
            vec![
                argv(&[
                    "show",
                    "--property=Id",
                    "--property=LoadState",
                    "--",
                    "nginx.service"
                ]),
                argv(&[
                    "status",
                    "--no-pager",
                    "--full",
                    "--lines=5",
                    "--",
                    "nginx.service"
                ]),
            ]
        );
    }

    #[tokio::test]
    async fn service_status_masks_secrets_in_the_process_command_lines_it_shows() {
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake);
        let text = ok_text(run(&host, "wendy", "service_status", json!({"unit": "nginx"})).await);
        assert!(text.contains("--password=<redacted> --port 80"), "{text}");
        assert!(!text.contains("hunter2"), "{text}");
    }

    #[tokio::test]
    async fn service_status_is_judged_by_the_units_real_name_too() {
        let fake = fake_systemctl();
        let (host, audit) = host(&format!(
            "[roles.most]\nallow = [\"service.view\"]\ndeny = [\"service.view:ssh.service\"]\n\
             [unix_users.mo]\nroles = [\"most\"]\n{}",
            fake.config()
        ));
        ok_text(run(&host, "mo", "service_status", json!({"unit": "nginx"})).await);
        // ssh.service is denied, and asking for it by its alias does not get around that
        for unit in ["ssh", "sshd"] {
            let result = run(&host, "mo", "service_status", json!({"unit": unit})).await;
            assert!(
                matches!(result, Err(ToolError::Denied(_))),
                "{unit}: {result:?}"
            );
            assert_eq!(audit.records().last().unwrap()["resource"], "ssh.service");
        }
        let statuses: Vec<Vec<String>> = fake
            .calls("systemctl")
            .into_iter()
            .filter(|c| c[0] == "status")
            .collect();
        assert_eq!(
            statuses.len(),
            1,
            "only nginx's status may have been fetched"
        );
    }

    #[tokio::test]
    async fn service_list_builds_the_listing_command() {
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake);
        let text = ok_text(run(&host, "wendy", "service_list", json!({})).await);
        assert!(
            text.contains("nginx.service loaded active running"),
            "{text}"
        );
        ok_text(
            run(
                &host,
                "wendy",
                "service_list",
                json!({"type": "timer", "state": "failed", "pattern": "log*"}),
            )
            .await,
        );
        assert_eq!(
            fake.calls("systemctl"),
            vec![
                argv(&[
                    "list-units",
                    "--all",
                    "--no-pager",
                    "--no-legend",
                    "--plain",
                    "--type=service"
                ]),
                argv(&[
                    "list-units",
                    "--all",
                    "--no-pager",
                    "--no-legend",
                    "--plain",
                    "--type=timer",
                    "--state=failed",
                    "--",
                    "log*"
                ]),
            ]
        );
        let result = run(
            &host,
            "wendy",
            "service_list",
            json!({"pattern": "--root=/x"}),
        )
        .await;
        assert!(matches!(result, Err(ToolError::Invalid(_))), "{result:?}");
    }

    #[test]
    fn normalize_unit_completes_bare_names_and_keeps_full_ones() {
        let cases: &[(&str, &str)] = &[
            ("nginx", "nginx.service"),
            ("nginx.service", "nginx.service"),
            ("logrotate.timer", "logrotate.timer"),
            ("getty@tty1", "getty@tty1.service"),
            ("user@1000.service", "user@1000.service"),
            (
                "dev-disk-by\\x2duuid-abc.swap",
                "dev-disk-by\\x2duuid-abc.swap",
            ),
            ("foo.bar", "foo.bar.service"),
            ("multi-user.target", "multi-user.target"),
        ];
        for (name, want) in cases {
            assert_eq!(normalize_unit(name).ok().as_deref(), Some(*want), "{name}");
        }
    }

    #[test]
    fn normalize_unit_rejects_anything_that_is_not_a_unit_name() {
        let too_long = "x".repeat(300);
        for bad in [
            "",
            "-x",
            "--now",
            "nginx*",
            "ssh?",
            "[a]",
            "a b",
            "a/b",
            "../x",
            "a;b",
            "a$b",
            too_long.as_str(),
        ] {
            assert!(normalize_unit(bad).is_err(), "{bad:?} should be rejected");
        }
    }
}
