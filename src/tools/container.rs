//! Containers under podman and docker: list, inspect, logs, resource use, start/stop.

use serde_json::Value;

use super::args::{Args, Param};
use super::{
    Ctx, Tool, ToolError, ToolResult, command_ok, command_text, command_text_tail, required,
};
use crate::policy::Access;
use crate::sanitize::{redact_args, redact_env, redact_text};

const RUNTIMES: [&str; 2] = ["podman", "docker"];
const LIST_FORMAT: &str = "table {{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}";
const IDENTITY_FORMAT: &str = "{{.Id}} {{.Name}}";

pub fn tools() -> Vec<Tool> {
    let runtime = || {
        Param::choice(
            "runtime",
            "podman or docker (default: whichever is installed)",
            &RUNTIMES,
        )
    };
    let name = || {
        Param::str("name", "Container name or id")
            .max_len(128)
            .required()
    };
    vec![
        Tool::new(
            "container_list",
            "List containers (podman and docker): id, name, image, status and ports. \
             Includes stopped containers unless running_only is set.",
            Access::Read,
            "container.view",
            vec![
                runtime(),
                Param::bool("running_only", "Leave out containers that are not running"),
            ],
            container_list,
        ),
        Tool::new(
            "container_inspect",
            "Show a container's full configuration and state as JSON (inspect). The values \
             of environment variables are hidden, and secrets in the command line are masked.",
            Access::Read,
            "container.view",
            vec![name(), runtime()],
            container_inspect,
        ),
        Tool::new(
            "container_logs",
            "Show the most recent output of a container: its stdout, then its stderr (the two \
             are captured separately, so their relative order is not preserved).",
            Access::Read,
            "container.logs",
            vec![
                name(),
                runtime(),
                Param::int(
                    "lines",
                    "Number of lines from the end (default 100)",
                    1,
                    5000,
                ),
                Param::str(
                    "since",
                    "Only output since this time, e.g. 10m, 2h or 2026-11-19T10:00:00",
                )
                .max_len(40),
                Param::bool("timestamps", "Prefix each line with its timestamp"),
            ],
            container_logs,
        ),
        Tool::new(
            "container_stats",
            "Show current CPU, memory, network and disk use of running containers.",
            Access::Read,
            "container.view",
            vec![runtime()],
            container_stats,
        ),
        Tool::new(
            "container_control",
            "Start, stop, restart, pause, unpause or kill a container.",
            Access::Write,
            "container.control",
            vec![
                name(),
                Param::choice(
                    "action",
                    "What to do",
                    &["start", "stop", "restart", "pause", "unpause", "kill"],
                )
                .required(),
                runtime(),
            ],
            container_control,
        ),
    ]
}

/// Checks a container name or id as given by the caller.
pub fn check_reference(reference: &str) -> Result<(), ToolError> {
    let mut chars = reference.chars();
    let valid = reference.len() <= 128
        && chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c));
    if valid {
        Ok(())
    } else {
        Err(ToolError::Invalid(format!(
            "{reference:?} is not a container name or id"
        )))
    }
}

/// Parses the output of `inspect --format '{{.Id}} {{.Name}}'`: the full id and the
/// name (docker writes the name with a leading slash).
pub fn parse_identity(line: &str) -> Option<(String, String)> {
    let (id, name) = line.trim().split_once(' ')?;
    let name = name.strip_prefix('/').unwrap_or(name);
    let id_ok = (12..=64).contains(&id.len()) && id.chars().all(|c| c.is_ascii_hexdigit());
    (id_ok && check_reference(name).is_ok()).then(|| (id.to_string(), name.to_string()))
}

/// Hides secrets in `inspect` output, in place: every environment value, and anything
/// that looks like a secret in command lines.
pub fn redact_inspect(value: &mut Value) {
    fn strings_of(value: &Value) -> Option<Vec<String>> {
        value
            .as_array()?
            .iter()
            .map(|item| item.as_str().map(str::to_string))
            .collect()
    }
    match value {
        Value::Array(items) => items.iter_mut().for_each(redact_inspect),
        Value::Object(fields) => {
            for (key, field) in fields.iter_mut() {
                match (key.as_str(), strings_of(field)) {
                    ("Env", Some(entries)) => {
                        *field = entries
                            .iter()
                            .map(|e| Value::String(redact_env(e)))
                            .collect();
                    }
                    ("Cmd" | "Args" | "Entrypoint" | "Test", Some(words)) => {
                        *field = redact_args(&words).into_iter().map(Value::String).collect();
                    }
                    // some runtimes give these as one string rather than a list
                    ("Cmd" | "Args" | "Entrypoint" | "Test", None) if field.is_string() => {
                        let line = field.as_str().unwrap_or_default();
                        *field = Value::String(redact_text(line));
                    }
                    // podman records the whole `podman run ...` line, -e values included
                    ("CreateCommand", _) => *field = Value::String("<redacted>".to_string()),
                    _ => redact_inspect(field),
                }
            }
        }
        _ => {}
    }
}

/// The runtimes to use: the one asked for, or each one installed.
fn runtimes(ctx: &Ctx, asked: Option<&str>) -> Result<Vec<&'static str>, ToolError> {
    let installed: Vec<&'static str> = RUNTIMES
        .iter()
        .copied()
        .filter(|runtime| ctx.bins().find(runtime).is_ok())
        .collect();
    match asked {
        Some(asked) => match installed.iter().find(|runtime| **runtime == asked) {
            Some(runtime) => Ok(vec![runtime]),
            None => Err(ToolError::Failed(format!(
                "{asked} is not installed on this host"
            ))),
        },
        None if installed.is_empty() => Err(ToolError::Failed(
            "neither podman nor docker is installed on this host".to_string(),
        )),
        None => Ok(installed),
    }
}

/// A container that has been looked up.
struct Target {
    runtime: &'static str,
    /// The full id: what commands are given, so they act on exactly this container.
    id: String,
    /// The container's name: what grants are written against.
    name: String,
}

/// Finds the container a caller means.
///
/// AIDEV-NOTE: a caller may give a name or any prefix of an id. The runtime is asked
/// which container that is; from then on the NAME is used for the permission check and
/// the full ID for every command, so the two cannot refer to different containers.
async fn resolve(
    ctx: &Ctx,
    asked_runtime: Option<&str>,
    reference: &str,
) -> Result<Target, ToolError> {
    check_reference(reference)?;
    let mut found = Vec::new();
    for runtime in runtimes(ctx, asked_runtime)? {
        let lookup = ctx.command(runtime)?.args([
            "inspect",
            "--type",
            "container",
            "--format",
            IDENTITY_FORMAT,
            "--",
            reference,
        ]);
        let out = ctx.run(lookup).await?;
        if !command_ok(&out) {
            continue;
        }
        if let Some((id, name)) = parse_identity(&String::from_utf8_lossy(&out.stdout)) {
            found.push(Target { runtime, id, name });
        }
    }
    // Where `docker` is a wrapper around podman, both commands report the very same
    // container: that is one container, reached through the first runtime (podman).
    found.dedup_by(|later, first| later.id == first.id);
    if found.len() > 1 {
        let names: Vec<&str> = found.iter().map(|t| t.runtime).collect();
        return Err(ToolError::Invalid(format!(
            "{reference:?} exists under {}; say which with the runtime argument",
            names.join(" and ")
        )));
    }
    match found.pop() {
        Some(target) => Ok(target),
        None => {
            // "No such container" is only told to a caller who could have acted on a
            // container of that name; anyone else gets the usual refusal, so the tool
            // cannot be used to probe for containers.
            ctx.authorize(Some(reference))?;
            Err(ToolError::Failed(format!(
                "there is no container {reference:?}"
            )))
        }
    }
}

/// Runs `subcommand` under each runtime in use and labels the output by runtime.
async fn each_runtime(ctx: &Ctx, args: &Args, subcommand: &[&str]) -> ToolResult {
    let runtimes = runtimes(ctx, args.str("runtime"))?;
    let auth = ctx.authorize(None)?;
    let mut text = String::new();
    let mut any_ok = false;
    for runtime in runtimes {
        let out = ctx
            .run(ctx.command(runtime)?.args(subcommand.iter().copied()))
            .await?;
        any_ok |= command_ok(&out);
        text.push_str(&format!("== {runtime} ==\n{}", command_text(&out)));
    }
    auth.done(text, any_ok)
}

async fn container_list(ctx: Ctx, args: Args) -> ToolResult {
    // An explicit format: the default one includes each container's command line.
    if args.bool("running_only") == Some(true) {
        each_runtime(&ctx, &args, &["ps", "--format", LIST_FORMAT]).await
    } else {
        each_runtime(&ctx, &args, &["ps", "--all", "--format", LIST_FORMAT]).await
    }
}

async fn container_stats(ctx: Ctx, args: Args) -> ToolResult {
    each_runtime(&ctx, &args, &["stats", "--no-stream"]).await
}

async fn container_inspect(ctx: Ctx, args: Args) -> ToolResult {
    let target = resolve(&ctx, args.str("runtime"), required(&args, "name")?).await?;
    let auth = ctx.authorize(Some(&target.name))?;
    let inspect = ctx.command(target.runtime)?.args([
        "inspect",
        "--type",
        "container",
        "--",
        target.id.as_str(),
    ]);
    let out = ctx.run(inspect).await?;
    if !command_ok(&out) {
        return auth.failed(String::from_utf8_lossy(&out.stderr));
    }
    // AIDEV-NOTE: the raw output holds every environment variable of the container. If
    // it cannot be parsed it cannot be redacted, so it is not shown at all.
    let Ok(mut value) = serde_json::from_slice::<Value>(&out.stdout) else {
        return Err(ToolError::Failed(format!(
            "the inspect output of {} could not be parsed, and is not shown unredacted",
            target.name
        )));
    };
    redact_inspect(&mut value);
    let text = serde_json::to_string_pretty(&value)
        .map_err(|e| ToolError::Internal(format!("encoding inspect output: {e}")))?;
    auth.ok(text)
}

async fn container_logs(ctx: Ctx, args: Args) -> ToolResult {
    let mut argv = vec![
        "logs".to_string(),
        "--tail".to_string(),
        args.int("lines").unwrap_or(100).to_string(),
    ];
    if let Some(since) = args.str("since") {
        let plain = |c: char| c.is_ascii_alphanumeric() || ":.+-".contains(c);
        if since.is_empty() || since.starts_with('-') || !since.chars().all(plain) {
            return Err(ToolError::Invalid(
                "since must be a duration such as 10m or a time such as 2026-11-19T10:00:00"
                    .to_string(),
            ));
        }
        argv.extend(["--since".to_string(), since.to_string()]);
    }
    if args.bool("timestamps") == Some(true) {
        argv.push("--timestamps".to_string());
    }
    let target = resolve(&ctx, args.str("runtime"), required(&args, "name")?).await?;
    let auth = ctx.authorize(Some(&target.name))?;
    argv.extend(["--".to_string(), target.id.clone()]);
    let out = ctx.run(ctx.command(target.runtime)?.args(argv)).await?;
    // `logs --tail` is about the newest output: if there is too much, keep that.
    auth.done(
        command_text_tail(&out, ctx.output_budget()),
        command_ok(&out),
    )
}

async fn container_control(ctx: Ctx, args: Args) -> ToolResult {
    let action = required(&args, "action")?.to_string();
    let target = resolve(&ctx, args.str("runtime"), required(&args, "name")?).await?;
    let auth = ctx.authorize(Some(&target.name))?;

    // Stopping waits for the container's own grace period: allow for it.
    let limits = &ctx.cfg().limits;
    let wait = limits
        .call_timeout_secs
        .saturating_sub(10)
        .min(60)
        .max(limits.command_timeout_secs);
    let change = ctx
        .command(target.runtime)?
        .timeout(std::time::Duration::from_secs(wait))
        .args([action.as_str(), "--", target.id.as_str()]);
    let out = ctx.run(change).await?;
    let succeeded = command_ok(&out);

    let state_query = ctx.command(target.runtime)?.args([
        "inspect",
        "--type",
        "container",
        "--format",
        "{{.State.Status}}",
        "--",
        target.id.as_str(),
    ]);
    let state = match ctx.run(state_query).await {
        Ok(out) if command_ok(&out) => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        _ => "unknown".to_string(),
    };
    let mut text = String::from_utf8_lossy(&out.stderr).into_owned();
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    let verdict = if succeeded { "done" } else { "FAILED" };
    text.push_str(&format!(
        "{action} {} ({}): {verdict}. The container is now: {state}\n",
        target.name, target.runtime
    ));
    auth.done(text, succeeded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::Host;
    use crate::tools::testing::{FakeBins, call, find, host, ok_text};
    use serde_json::json;
    use std::sync::Arc;

    const WEB_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const DB_ID: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    #[test]
    fn check_reference_accepts_names_and_ids_only() {
        for good in ["web-1", "0123456789ab", "my.app_1", WEB_ID] {
            assert!(check_reference(good).is_ok(), "{good}");
        }
        let long = "x".repeat(129);
        for bad in [
            "",
            "-x",
            "--help",
            "a b",
            "a/b",
            "$(x)",
            ".hidden",
            long.as_str(),
        ] {
            assert!(check_reference(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn parse_identity_reads_the_id_and_strips_dockers_slash() {
        let want = Some((WEB_ID.to_string(), "web-1".to_string()));
        assert_eq!(parse_identity(&format!("{WEB_ID} /web-1\n")), want);
        assert_eq!(parse_identity(&format!("{WEB_ID} web-1")), want);
        for bad in [
            "",
            "web-1",
            "nothex /web-1",
            &format!("{WEB_ID} "),
            &format!("{WEB_ID} /a b"),
            "0123 /short-id",
        ] {
            assert_eq!(parse_identity(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn redact_inspect_hides_environment_values_and_masks_command_secrets() {
        let mut value = json!([{
            "Id": "abc",
            "Args": ["--password=pw", "serve"],
            "Config": {
                "Env": ["DB_PASSWORD=hunter2", "PATH=/bin"],
                "Cmd": ["server", "--token", "s3cret"],
                "Entrypoint": ["/entry"],
                "Image": "registry/app:1"
            },
            "HostConfig": {"Binds": ["/a:/b"]}
        }]);
        redact_inspect(&mut value);
        assert_eq!(
            value,
            json!([{
                "Id": "abc",
                "Args": ["--password=<redacted>", "serve"],
                "Config": {
                    "Env": ["DB_PASSWORD=<redacted>", "PATH=<redacted>"],
                    "Cmd": ["server", "--token", "<redacted>"],
                    "Entrypoint": ["/entry"],
                    "Image": "registry/app:1"
                },
                "HostConfig": {"Binds": ["/a:/b"]}
            }])
        );
    }

    /// A stand-in runtime that knows two containers, web-1 and db.
    fn runtime_script() -> String {
        runtime_script_with(WEB_ID)
    }

    /// The same, with web-1 under another id (a different container of that name).
    fn runtime_script_with(web_id: &str) -> String {
        format!(
            r#"
for last; do :; done
case "$1" in
  inspect)
    case "$*" in
      *'{{{{.Id}}}} {{{{.Name}}}}'*)
        case "$last" in
          web-1|0123456789ab|{web_id}) echo "{web_id} /web-1" ;;
          db|{DB_ID}) echo "{DB_ID} /db" ;;
          *) echo "Error: No such container: $last" >&2; exit 1 ;;
        esac ;;
      *'{{{{.State.Status}}}}'*) echo running ;;
      *) echo '[{{"Id":"{web_id}","Name":"/web-1","Config":{{"Env":["API_SECRET=hunter2"],"Cmd":["run"]}}}}]' ;;
    esac ;;
  ps) echo "CONTAINER ID   NAMES   IMAGE   STATUS   PORTS" ;;
  logs) echo "a log line" ;;
  stats) echo "NAME   CPU %" ;;
  kill) echo "Error: cannot kill container" >&2; exit 125 ;;
esac
"#
        )
    }

    fn fixture(fake: &FakeBins) -> (Arc<Host>, MemorySink) {
        host(&format!(
            r#"
[roles.admin]
allow = ["@all"]
[roles.web]
allow = ["container.view:web-*", "container.logs:web-*", "container.control:web-*"]
[unix_users.adam]
roles = ["admin"]
[unix_users.wendy]
roles = ["web"]
{}"#,
            fake.config_only()
        ))
    }

    async fn run(host: &Arc<Host>, user: &str, tool: &str, arguments: Value) -> ToolResult {
        call(host, user, &find(tools(), tool), arguments).await
    }

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn resolve_call(reference: &str) -> Vec<String> {
        strings(&[
            "inspect",
            "--type",
            "container",
            "--format",
            IDENTITY_FORMAT,
            "--",
            reference,
        ])
    }

    #[tokio::test]
    async fn container_control_acts_on_the_full_id_of_the_named_container() {
        let fake = FakeBins::new().add_script("docker", &runtime_script());
        let (host, audit) = fixture(&fake);
        let text = ok_text(
            run(
                &host,
                "wendy",
                "container_control",
                json!({"name": "web-1", "action": "restart"}),
            )
            .await,
        );
        assert!(text.contains("web-1") && text.contains("running"), "{text}");
        assert_eq!(
            fake.calls("docker"),
            vec![
                resolve_call("web-1"),
                strings(&["restart", "--", WEB_ID]),
                strings(&[
                    "inspect",
                    "--type",
                    "container",
                    "--format",
                    "{{.State.Status}}",
                    "--",
                    WEB_ID
                ]),
            ]
        );
        assert_eq!(audit.records().last().unwrap()["resource"], "web-1");
    }

    #[tokio::test]
    async fn a_container_given_by_id_is_judged_by_its_name() {
        let fake = FakeBins::new().add_script("docker", &runtime_script());
        let (host, _audit) = fixture(&fake);
        // the id of web-1: wendy's grant for web-* applies
        ok_text(
            run(
                &host,
                "wendy",
                "container_control",
                json!({"name": "0123456789ab", "action": "stop"}),
            )
            .await,
        );
        // the id of db: it does not, however the container is referred to
        for reference in ["db", DB_ID] {
            let result = run(
                &host,
                "wendy",
                "container_control",
                json!({"name": reference, "action": "stop"}),
            )
            .await;
            assert!(
                matches!(result, Err(ToolError::Denied(_))),
                "{reference}: {result:?}"
            );
        }
        let stops: Vec<Vec<String>> = fake
            .calls("docker")
            .into_iter()
            .filter(|c| c[0] == "stop")
            .collect();
        assert_eq!(stops, vec![strings(&["stop", "--", WEB_ID])]);
    }

    #[tokio::test]
    async fn unknown_and_malformed_references_are_refused() {
        let fake = FakeBins::new().add_script("docker", &runtime_script());
        let (host, _audit) = fixture(&fake);
        let result = run(
            &host,
            "adam",
            "container_control",
            json!({"name": "ghost", "action": "stop"}),
        )
        .await;
        assert!(matches!(result, Err(ToolError::Failed(_))), "{result:?}");
        let result = run(
            &host,
            "adam",
            "container_control",
            json!({"name": "--all", "action": "stop"}),
        )
        .await;
        assert!(matches!(result, Err(ToolError::Invalid(_))), "{result:?}");
        assert_eq!(fake.calls("docker"), vec![resolve_call("ghost")]);
    }

    #[tokio::test]
    async fn a_failed_action_is_reported_as_an_error() {
        let fake = FakeBins::new().add_script("docker", &runtime_script());
        let (host, _audit) = fixture(&fake);
        let output = run(
            &host,
            "adam",
            "container_control",
            json!({"name": "web-1", "action": "kill"}),
        )
        .await
        .unwrap();
        assert!(output.is_error());
        assert!(
            output.text().contains("cannot kill container"),
            "{}",
            output.text()
        );
    }

    #[tokio::test]
    async fn container_inspect_never_shows_environment_values() {
        let fake = FakeBins::new().add_script("docker", &runtime_script());
        let (host, _audit) = fixture(&fake);
        let text = ok_text(
            run(
                &host,
                "wendy",
                "container_inspect",
                json!({"name": "web-1"}),
            )
            .await,
        );
        assert!(text.contains("API_SECRET=<redacted>"), "{text}");
        assert!(!text.contains("hunter2"), "{text}");
        let result = run(&host, "wendy", "container_inspect", json!({"name": "db"})).await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
    }

    #[tokio::test]
    async fn container_logs_asks_for_the_tail_of_the_resolved_container() {
        let fake = FakeBins::new().add_script("docker", &runtime_script());
        let (host, _audit) = fixture(&fake);
        let arguments = json!({"name": "web-1", "lines": 50, "since": "10m", "timestamps": true});
        assert_eq!(
            ok_text(run(&host, "wendy", "container_logs", arguments).await),
            "a log line\n"
        );
        assert_eq!(
            fake.calls("docker").last().unwrap(),
            &strings(&[
                "logs",
                "--tail",
                "50",
                "--since",
                "10m",
                "--timestamps",
                "--",
                WEB_ID
            ])
        );
        let result = run(
            &host,
            "wendy",
            "container_logs",
            json!({"name": "web-1", "since": "$(x)"}),
        )
        .await;
        assert!(matches!(result, Err(ToolError::Invalid(_))), "{result:?}");
    }

    #[tokio::test]
    async fn container_list_and_stats_need_an_unscoped_grant() {
        let fake = FakeBins::new().add_script("docker", &runtime_script());
        let (host, _audit) = fixture(&fake);
        let text = ok_text(run(&host, "adam", "container_list", json!({})).await);
        assert!(text.contains("CONTAINER ID"), "{text}");
        ok_text(
            run(
                &host,
                "adam",
                "container_list",
                json!({"running_only": true}),
            )
            .await,
        );
        ok_text(run(&host, "adam", "container_stats", json!({})).await);
        assert_eq!(
            fake.calls("docker"),
            vec![
                strings(&["ps", "--all", "--format", LIST_FORMAT]),
                strings(&["ps", "--format", LIST_FORMAT]),
                strings(&["stats", "--no-stream"]),
            ]
        );
        // wendy's grants are all limited to web-*: listing everything is not covered
        for tool in ["container_list", "container_stats"] {
            let result = run(&host, "wendy", tool, json!({})).await;
            assert!(
                matches!(result, Err(ToolError::Denied(_))),
                "{tool}: {result:?}"
            );
        }
    }

    const OTHER_WEB_ID: &str = "aaaa456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[tokio::test]
    async fn with_two_runtimes_an_ambiguous_name_needs_the_runtime_to_be_given() {
        // two different containers called web-1, one under each runtime
        let fake = FakeBins::new()
            .add_script("docker", &runtime_script())
            .add_script("podman", &runtime_script_with(OTHER_WEB_ID));
        let (host, _audit) = fixture(&fake);
        let result = run(
            &host,
            "adam",
            "container_control",
            json!({"name": "web-1", "action": "stop"}),
        )
        .await;
        match result {
            Err(ToolError::Invalid(message)) => assert!(message.contains("runtime"), "{message}"),
            other => panic!("expected a request to choose, got {other:?}"),
        }
        ok_text(
            run(
                &host,
                "adam",
                "container_control",
                json!({"name": "web-1", "action": "stop", "runtime": "podman"}),
            )
            .await,
        );
        assert!(
            fake.calls("podman")
                .contains(&strings(&["stop", "--", OTHER_WEB_ID]))
        );
        assert!(!fake.calls("docker").iter().any(|c| c[0] == "stop"));
    }

    #[tokio::test]
    async fn one_container_seen_through_two_commands_is_not_ambiguous() {
        // where `docker` is a wrapper around podman, both report the very same container
        let fake = FakeBins::new()
            .add_script("docker", &runtime_script())
            .add_script("podman", &runtime_script());
        let (host, _audit) = fixture(&fake);
        ok_text(
            run(
                &host,
                "adam",
                "container_control",
                json!({"name": "web-1", "action": "stop"}),
            )
            .await,
        );
        let stops = |runtime: &str| {
            fake.calls(runtime)
                .into_iter()
                .filter(|c| c[0] == "stop")
                .count()
        };
        assert_eq!(
            (stops("podman"), stops("docker")),
            (1, 0),
            "it is acted on once, through podman"
        );
    }

    #[tokio::test]
    async fn whether_a_container_exists_is_not_told_to_a_caller_who_could_not_touch_it() {
        let fake = FakeBins::new().add_script("docker", &runtime_script());
        let (host, _audit) = fixture(&fake);
        // wendy's grants cover web-*: "ghost" is refused whether or not it exists
        let result = run(
            &host,
            "wendy",
            "container_control",
            json!({"name": "ghost", "action": "stop"}),
        )
        .await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        // a name her grant does cover is simply reported as missing
        let result = run(
            &host,
            "wendy",
            "container_control",
            json!({"name": "web-9", "action": "stop"}),
        )
        .await;
        assert!(matches!(result, Err(ToolError::Failed(_))), "{result:?}");
    }

    #[test]
    fn redact_inspect_handles_command_lines_given_as_one_string() {
        let mut value =
            json!({"Config": {"Entrypoint": "/entry --api-key=abc123 serve", "Env": "not a list"}});
        redact_inspect(&mut value);
        assert_eq!(
            value,
            json!({"Config": {"Entrypoint": "/entry --api-key=<redacted> serve", "Env": "not a list"}})
        );
    }

    #[tokio::test]
    async fn with_no_runtime_installed_the_tools_say_so() {
        let fake = FakeBins::new();
        let (host, _audit) = fixture(&fake);
        let result = run(&host, "adam", "container_list", json!({})).await;
        match result {
            Err(ToolError::Failed(message)) => assert!(
                message.contains("podman") && message.contains("docker"),
                "{message}"
            ),
            other => panic!("expected a failure, got {other:?}"),
        }
    }
}
