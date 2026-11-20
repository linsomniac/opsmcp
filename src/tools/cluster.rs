//! Pacemaker and Corosync: cluster status, and changes to resources, nodes and
//! maintenance mode.
//!
//! Uses Pacemaker's own low-level commands (crm_mon, crm_resource, crm_attribute) and
//! Corosync's (corosync-quorumtool, corosync-cfgtool), which are present whichever shell
//! (pcs or crmsh) a distribution prefers. Fencing is deliberately not offered.

use super::args::{Args, Param};
use super::{Ctx, Tool, ToolError, ToolResult, command_ok, command_text, required};
use crate::policy::Access;

const RESOURCE_ACTIONS: [&str; 8] = [
    "cleanup", "refresh", "restart", "start", "stop", "move", "ban", "clear",
];
const NODE_ACTIONS: [&str; 4] = ["standby", "unstandby", "maintenance", "unmaintenance"];

pub fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "cluster_status",
            "Show the Pacemaker cluster status (crm_mon): nodes, resources and where they \
             run, inactive resources, fail counts and failed actions.",
            Access::Read,
            "cluster.view",
            vec![Param::bool("by_node", "Group resources by the node they run on")],
            cluster_status,
        ),
        Tool::new(
            "corosync_status",
            "Show Corosync membership and quorum (corosync-quorumtool) and the state of its \
             network links (corosync-cfgtool).",
            Access::Read,
            "cluster.view",
            vec![],
            corosync_status,
        ),
        Tool::new(
            "cluster_resource",
            "Act on a Pacemaker resource: cleanup or refresh its state, restart it, start or \
             stop it (sets target-role), move it to another node or ban it from one (both \
             create a location constraint), or clear such constraints. Changes are stored \
             in the cluster configuration.",
            Access::Write,
            "cluster.modify",
            vec![
                Param::str("resource", "Resource (or group, clone) id").max_len(128).required(),
                Param::choice("action", "What to do", &RESOURCE_ACTIONS).required(),
                Param::str("node", "Node to act on: for cleanup, refresh, move, ban and clear").max_len(255),
                Param::str("lifetime", "For move and ban: how long the constraint lasts, as an ISO 8601 duration such as PT1H or P1D").max_len(17),
            ],
            cluster_resource,
        ),
        Tool::new(
            "cluster_node",
            "Put a cluster node into standby (its resources move away) or bring it back, or \
             put a node into maintenance (its resources are left unmanaged) or take it out.",
            Access::Write,
            "cluster.modify",
            vec![
                Param::str("node", "Node name").max_len(255).required(),
                Param::choice("action", "What to do", &NODE_ACTIONS).required(),
            ],
            cluster_node,
        ),
        Tool::new(
            "cluster_maintenance_mode",
            "Turn maintenance mode on or off for the whole cluster. While on, Pacemaker \
             neither starts, stops nor monitors any resource.",
            Access::Write,
            "cluster.modify",
            vec![Param::bool("enabled", "true to turn maintenance mode on, false to turn it off").required()],
            cluster_maintenance_mode,
        ),
    ]
}

/// One change to a resource, as parsed from the tool's arguments.
pub struct ResourceChange<'a> {
    pub resource: &'a str,
    pub action: &'a str,
    pub node: Option<&'a str>,
    pub lifetime: Option<&'a str>,
}

/// The crm_resource arguments for a change.
pub fn resource_argv(change: &ResourceChange) -> Result<Vec<String>, ToolError> {
    let invalid = |problem: String| Err(ToolError::Invalid(problem));
    check_id("resource", change.resource, 128, ":")?;
    if let Some(node) = change.node {
        check_id("node", node, 255, "")?;
    }
    if let Some(lifetime) = change.lifetime {
        // ISO 8601 duration, e.g. PT1H, P1D, P1DT12H
        let mut chars = lifetime.chars();
        let valid = chars.next() == Some('P')
            && lifetime.len() >= 3
            && chars.all(|c| c.is_ascii_digit() || c.is_ascii_uppercase());
        if !valid {
            return invalid(format!(
                "{lifetime:?} is not an ISO 8601 duration (for example PT1H or P1D)"
            ));
        }
    }
    let action = change.action;
    if change.node.is_some() && !matches!(action, "cleanup" | "refresh" | "move" | "ban" | "clear")
    {
        return invalid(format!("{action} does not take a node"));
    }
    if change.lifetime.is_some() && !matches!(action, "move" | "ban") {
        return invalid(format!("{action} does not take a lifetime"));
    }

    let on_resource = |flag: &str| {
        vec![
            flag.to_string(),
            "--resource".to_string(),
            change.resource.to_string(),
        ]
    };
    let target_role = |role: &str| -> Vec<String> {
        [
            "--resource",
            change.resource,
            "--meta",
            "--set-parameter",
            "target-role",
            "--parameter-value",
            role,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    };
    let mut argv = match action {
        "cleanup" => on_resource("--cleanup"),
        "refresh" => on_resource("--refresh"),
        "restart" => on_resource("--restart"),
        "move" => on_resource("--move"),
        "ban" => on_resource("--ban"),
        "clear" => on_resource("--clear"),
        "start" => target_role("Started"),
        "stop" => target_role("Stopped"),
        other => return invalid(format!("unknown action {other:?}")),
    };
    if let Some(node) = change.node {
        argv.extend(["--node".to_string(), node.to_string()]);
    }
    if let Some(lifetime) = change.lifetime {
        argv.extend(["--lifetime".to_string(), lifetime.to_string()]);
    }
    Ok(argv)
}

/// Checks a resource or node name: letters, digits, `_`, `.`, `-` (and `extra`), not
/// starting with `-` so that it can never be read as an option.
fn check_id(kind: &str, value: &str, max: usize, extra: &str) -> Result<(), ToolError> {
    let allowed = |c: char| c.is_ascii_alphanumeric() || "_.-".contains(c) || extra.contains(c);
    if value.is_empty()
        || value.len() > max
        || value.starts_with('-')
        || !value.chars().all(allowed)
    {
        return Err(ToolError::Invalid(format!(
            "{value:?} is not a valid {kind} name"
        )));
    }
    Ok(())
}

/// The crm_attribute arguments for a change to a node.
pub fn node_argv(node: &str, action: &str) -> Result<Vec<String>, ToolError> {
    check_id("node", node, 255, "")?;
    let (attribute, value) = match action {
        "standby" => ("standby", "on"),
        "unstandby" => ("standby", "off"),
        "maintenance" => ("maintenance", "true"),
        "unmaintenance" => ("maintenance", "false"),
        other => return Err(ToolError::Invalid(format!("unknown action {other:?}"))),
    };
    Ok(["--node", node, "--name", attribute, "--update", value]
        .iter()
        .map(|s| s.to_string())
        .collect())
}

/// Runs an authorized cluster change and reports how it went.
async fn apply(
    ctx: &Ctx,
    auth: super::Authorized,
    program: &str,
    argv: Vec<String>,
    what: &str,
) -> ToolResult {
    // crm_resource --restart waits for the resource to stop and start again.
    let limits = &ctx.cfg().limits;
    let wait = limits
        .call_timeout_secs
        .saturating_sub(10)
        .min(90)
        .max(limits.command_timeout_secs);
    let cmd = ctx
        .command(program)?
        .timeout(std::time::Duration::from_secs(wait))
        .args(argv);
    let out = ctx.run(cmd).await?;
    let succeeded = command_ok(&out);
    let mut text = command_text(&out);
    let verdict = if succeeded { "done" } else { "FAILED" };
    text.push_str(&format!(
        "{what}: {verdict}. Use cluster_status to see the effect.\n"
    ));
    auth.done(text, succeeded)
}

async fn cluster_status(ctx: Ctx, args: Args) -> ToolResult {
    // one shot, with inactive resources and fail counts
    let mut argv = vec!["-1", "-r", "-f"];
    if args.bool("by_node") == Some(true) {
        argv.push("-n");
    }
    let auth = ctx.authorize(None)?;
    let out = ctx.run(ctx.command("crm_mon")?.args(argv)).await?;
    auth.done(command_text(&out), command_ok(&out))
}

async fn corosync_status(ctx: Ctx, _args: Args) -> ToolResult {
    let auth = ctx.authorize(None)?;
    let mut text = String::new();
    let mut answered = false;
    for program in ["corosync-quorumtool", "corosync-cfgtool"] {
        text.push_str(&format!("== {program} -s ==\n"));
        match ctx.command(program) {
            Ok(cmd) => {
                let out = ctx.run(cmd.args(["-s"])).await?;
                // A non-zero exit here usually means "not quorate" or "a link is down",
                // which is exactly what the caller is asking about.
                answered |= !out.stdout.is_empty();
                text.push_str(&command_text(&out));
            }
            Err(ToolError::Failed(problem)) => text.push_str(&format!("[{problem}]\n")),
            Err(other) => return Err(other),
        }
    }
    auth.done(text, answered)
}

async fn cluster_resource(ctx: Ctx, args: Args) -> ToolResult {
    let (resource, action) = (required(&args, "resource")?, required(&args, "action")?);
    let argv = resource_argv(&ResourceChange {
        resource,
        action,
        node: args.str("node"),
        lifetime: args.str("lifetime"),
    })?;
    let auth = ctx.authorize(Some(&format!("resource/{resource}")))?;
    apply(
        &ctx,
        auth,
        "crm_resource",
        argv,
        &format!("{action} {resource}"),
    )
    .await
}

async fn cluster_node(ctx: Ctx, args: Args) -> ToolResult {
    let (node, action) = (required(&args, "node")?, required(&args, "action")?);
    let argv = node_argv(node, action)?;
    let auth = ctx.authorize(Some(&format!("node/{node}")))?;
    apply(
        &ctx,
        auth,
        "crm_attribute",
        argv,
        &format!("{action} {node}"),
    )
    .await
}

async fn cluster_maintenance_mode(ctx: Ctx, args: Args) -> ToolResult {
    let enabled = args
        .bool("enabled")
        .ok_or_else(|| ToolError::Invalid("missing required argument \"enabled\"".to_string()))?;
    let argv = [
        "--name",
        "maintenance-mode",
        "--update",
        if enabled { "true" } else { "false" },
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let auth = ctx.authorize(Some("property/maintenance-mode"))?;
    let what = format!("maintenance mode {}", if enabled { "on" } else { "off" });
    apply(&ctx, auth, "crm_attribute", argv, &what).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::Host;
    use crate::tools::testing::{FakeBins, call, find, host, ok_text};
    use serde_json::{Value, json};
    use std::sync::Arc;

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn resource(
        action: &str,
        node: Option<&'static str>,
        lifetime: Option<&'static str>,
    ) -> Result<Vec<String>, ToolError> {
        resource_argv(&ResourceChange {
            resource: "web-vip",
            action,
            node,
            lifetime,
        })
    }

    #[test]
    fn resource_argv_builds_each_action() {
        type Case = (Result<Vec<String>, ToolError>, &'static [&'static str]);
        let cases: Vec<Case> = vec![
            (
                resource("cleanup", None, None),
                &["--cleanup", "--resource", "web-vip"],
            ),
            (
                resource("cleanup", Some("node1"), None),
                &["--cleanup", "--resource", "web-vip", "--node", "node1"],
            ),
            (
                resource("refresh", None, None),
                &["--refresh", "--resource", "web-vip"],
            ),
            (
                resource("restart", None, None),
                &["--restart", "--resource", "web-vip"],
            ),
            (
                resource("start", None, None),
                &[
                    "--resource",
                    "web-vip",
                    "--meta",
                    "--set-parameter",
                    "target-role",
                    "--parameter-value",
                    "Started",
                ],
            ),
            (
                resource("stop", None, None),
                &[
                    "--resource",
                    "web-vip",
                    "--meta",
                    "--set-parameter",
                    "target-role",
                    "--parameter-value",
                    "Stopped",
                ],
            ),
            (
                resource("move", Some("node2"), None),
                &["--move", "--resource", "web-vip", "--node", "node2"],
            ),
            (
                resource("ban", Some("node1"), Some("PT1H")),
                &[
                    "--ban",
                    "--resource",
                    "web-vip",
                    "--node",
                    "node1",
                    "--lifetime",
                    "PT1H",
                ],
            ),
            (
                resource("move", None, None),
                &["--move", "--resource", "web-vip"],
            ),
            (
                resource("clear", None, None),
                &["--clear", "--resource", "web-vip"],
            ),
        ];
        for (got, want) in cases {
            assert_eq!(got.unwrap(), strings(want));
        }
    }

    #[test]
    fn resource_argv_refuses_arguments_that_do_not_belong_to_the_action() {
        for (action, node, lifetime) in [
            ("restart", Some("node1"), None),
            ("start", Some("node1"), None),
            ("stop", None, Some("PT1H")),
            ("cleanup", None, Some("PT1H")),
            ("move", Some("--force"), None),
            ("move", Some("node 1"), None),
            ("ban", Some("node1"), Some("1 hour")),
            ("ban", Some("node1"), Some("--force")),
            ("explode", None, None),
        ] {
            let result = resource(action, node, lifetime);
            assert!(
                matches!(result, Err(ToolError::Invalid(_))),
                "{action} {node:?} {lifetime:?}: {result:?}"
            );
        }
        for bad in ["", "-r", "--force", "a b", "a;b", "a/b"] {
            let result = resource_argv(&ResourceChange {
                resource: bad,
                action: "cleanup",
                node: None,
                lifetime: None,
            });
            assert!(
                matches!(result, Err(ToolError::Invalid(_))),
                "resource {bad:?}: {result:?}"
            );
        }
    }

    #[test]
    fn node_argv_sets_the_node_attribute_for_each_action() {
        let cases: &[(&str, &[&str])] = &[
            (
                "standby",
                &["--node", "node1", "--name", "standby", "--update", "on"],
            ),
            (
                "unstandby",
                &["--node", "node1", "--name", "standby", "--update", "off"],
            ),
            (
                "maintenance",
                &[
                    "--node",
                    "node1",
                    "--name",
                    "maintenance",
                    "--update",
                    "true",
                ],
            ),
            (
                "unmaintenance",
                &[
                    "--node",
                    "node1",
                    "--name",
                    "maintenance",
                    "--update",
                    "false",
                ],
            ),
        ];
        for (action, want) in cases {
            assert_eq!(
                node_argv("node1", action).unwrap(),
                strings(want),
                "{action}"
            );
        }
        for bad in ["", "-N", "node 1", "a;b"] {
            assert!(
                matches!(node_argv(bad, "standby"), Err(ToolError::Invalid(_))),
                "{bad:?}"
            );
        }
        assert!(matches!(
            node_argv("node1", "reboot"),
            Err(ToolError::Invalid(_))
        ));
    }

    fn fakes() -> FakeBins {
        FakeBins::new()
            .add("crm_mon", "Cluster Summary:\n  * 2 nodes configured\n", 0)
            .add("crm_resource", "", 0)
            .add("crm_attribute", "", 0)
            .add("corosync-quorumtool", "Quorate: Yes\n", 0)
            .add("corosync-cfgtool", "LINK ID 0 udp\n", 0)
    }

    fn fixture(fake: &FakeBins) -> (Arc<Host>, MemorySink) {
        host(&format!(
            r#"
[roles.admin]
allow = ["@all"]
[roles.reader]
allow = ["@read"]
[roles.webops]
allow = ["cluster.modify:resource/web-*", "cluster.modify:node/node2"]
[unix_users.adam]
roles = ["admin"]
[unix_users.rita]
roles = ["reader"]
[unix_users.wendy]
roles = ["webops"]
{}"#,
            fake.config_only()
        ))
    }

    async fn run(host: &Arc<Host>, user: &str, tool: &str, arguments: Value) -> ToolResult {
        call(host, user, &find(tools(), tool), arguments).await
    }

    #[tokio::test]
    async fn cluster_status_runs_crm_mon_once() {
        let fake = fakes();
        let (host, _audit) = fixture(&fake);
        let text = ok_text(run(&host, "rita", "cluster_status", json!({})).await);
        assert!(text.contains("2 nodes configured"), "{text}");
        ok_text(run(&host, "rita", "cluster_status", json!({"by_node": true})).await);
        assert_eq!(
            fake.calls("crm_mon"),
            [
                strings(&["-1", "-r", "-f"]),
                strings(&["-1", "-r", "-f", "-n"])
            ]
        );
    }

    #[tokio::test]
    async fn corosync_status_shows_quorum_and_links() {
        let fake = fakes();
        let (host, _audit) = fixture(&fake);
        let text = ok_text(run(&host, "rita", "corosync_status", json!({})).await);
        assert!(
            text.contains("Quorate: Yes") && text.contains("LINK ID 0"),
            "{text}"
        );
        assert_eq!(fake.calls("corosync-quorumtool"), [strings(&["-s"])]);
        assert_eq!(fake.calls("corosync-cfgtool"), [strings(&["-s"])]);
    }

    #[tokio::test]
    async fn corosync_status_still_answers_when_one_command_fails() {
        let fake = FakeBins::new()
            .add("corosync-quorumtool", "Quorate: No\n", 1)
            .add("corosync-cfgtool", "LINK ID 0 udp\n", 0);
        let (host, _audit) = fixture(&fake);
        // quorumtool exits non-zero when the cluster is not quorate: that is the answer
        let text = ok_text(run(&host, "rita", "corosync_status", json!({})).await);
        assert!(
            text.contains("Quorate: No") && text.contains("LINK ID 0"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn cluster_resource_runs_the_change_for_a_granted_resource() {
        let fake = fakes();
        let (host, audit) = fixture(&fake);
        let arguments = json!({"resource": "web-vip", "action": "move", "node": "node2"});
        ok_text(run(&host, "wendy", "cluster_resource", arguments).await);
        assert_eq!(
            fake.calls("crm_resource"),
            [strings(&[
                "--move",
                "--resource",
                "web-vip",
                "--node",
                "node2"
            ])]
        );
        assert_eq!(
            audit.records().last().unwrap()["resource"],
            "resource/web-vip"
        );
    }

    #[tokio::test]
    async fn cluster_changes_run_nothing_outside_the_grant() {
        let fake = fakes();
        let (host, audit) = fixture(&fake);
        let denied = [
            (
                "cluster_resource",
                json!({"resource": "db-master", "action": "stop"}),
            ),
            (
                "cluster_node",
                json!({"node": "node1", "action": "standby"}),
            ),
            ("cluster_maintenance_mode", json!({"enabled": true})),
        ];
        for (tool, arguments) in denied {
            let result = run(&host, "wendy", tool, arguments).await;
            assert!(
                matches!(result, Err(ToolError::Denied(_))),
                "{tool}: {result:?}"
            );
            assert_eq!(audit.records().last().unwrap()["decision"], "deny");
        }
        // a read-only caller cannot change anything either
        let result = run(
            &host,
            "rita",
            "cluster_resource",
            json!({"resource": "web-vip", "action": "cleanup"}),
        )
        .await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        assert_eq!(fake.calls("crm_resource"), Vec::<Vec<String>>::new());
        assert_eq!(fake.calls("crm_attribute"), Vec::<Vec<String>>::new());
    }

    #[tokio::test]
    async fn cluster_node_and_maintenance_mode_set_attributes() {
        let fake = fakes();
        let (host, audit) = fixture(&fake);
        ok_text(
            run(
                &host,
                "wendy",
                "cluster_node",
                json!({"node": "node2", "action": "standby"}),
            )
            .await,
        );
        assert_eq!(audit.records().last().unwrap()["resource"], "node/node2");
        ok_text(
            run(
                &host,
                "adam",
                "cluster_maintenance_mode",
                json!({"enabled": true}),
            )
            .await,
        );
        assert_eq!(
            audit.records().last().unwrap()["resource"],
            "property/maintenance-mode"
        );
        ok_text(
            run(
                &host,
                "adam",
                "cluster_maintenance_mode",
                json!({"enabled": false}),
            )
            .await,
        );
        assert_eq!(
            fake.calls("crm_attribute"),
            [
                strings(&["--node", "node2", "--name", "standby", "--update", "on"]),
                strings(&["--name", "maintenance-mode", "--update", "true"]),
                strings(&["--name", "maintenance-mode", "--update", "false"]),
            ]
        );
    }

    #[tokio::test]
    async fn a_failing_cluster_command_is_reported_as_an_error() {
        let fake = FakeBins::new().add(
            "crm_resource",
            "Error performing operation: No such device or address\n",
            105,
        );
        let (host, _audit) = fixture(&fake);
        let output = run(
            &host,
            "adam",
            "cluster_resource",
            json!({"resource": "ghost", "action": "cleanup"}),
        )
        .await
        .unwrap();
        assert!(output.is_error());
        assert!(
            output.text().contains("No such device or address"),
            "{}",
            output.text()
        );
    }

    #[tokio::test]
    async fn a_host_without_pacemaker_says_so() {
        let fake = FakeBins::new();
        let (host, _audit) = fixture(&fake);
        match run(&host, "rita", "cluster_status", json!({})).await {
            Err(ToolError::Failed(message)) => assert!(message.contains("crm_mon"), "{message}"),
            other => panic!("expected a failure, got {other:?}"),
        }
    }
}
