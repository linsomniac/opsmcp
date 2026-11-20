//! Scheduling and cancelling a reboot of this host.

use std::collections::BTreeMap;
use std::path::PathBuf;

use super::args::{Args, Param};
use super::package::{plain_name, read_small};
use super::{
    Authorized, Ctx, Tool, ToolError, ToolResult, blocking, command_ok, command_text,
    one_line_cell, required,
};
use crate::policy::Access;
use crate::timefmt::{human_duration, now_secs, rfc3339_utc};

const ACTIONS: [&str; 3] = ["schedule", "cancel", "status"];

/// Where the state this tool reads lives. Tests point these at a temporary directory.
#[derive(Clone, Debug)]
pub struct Paths {
    /// Written by systemd while a shutdown is scheduled.
    pub scheduled: PathBuf,
    /// Created by the package tools (Debian, Ubuntu) when an update needs a reboot.
    pub reboot_required: PathBuf,
    /// The kernel's host name, used when crm_node cannot say what this node is called.
    pub hostname: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Paths {
            scheduled: PathBuf::from("/run/systemd/shutdown/scheduled"),
            reboot_required: PathBuf::from("/var/run/reboot-required"),
            hostname: PathBuf::from("/proc/sys/kernel/hostname"),
        }
    }
}

pub fn tools() -> Vec<Tool> {
    vec![Tool::new(
        "host_reboot",
        "Schedule a reboot of this host, cancel a scheduled one, or show whether one is \
         pending. A reboot is scheduled one minute ahead by default, so that it can still \
         be cancelled, and logged-in users are warned. On a Pacemaker cluster node the \
         reboot is refused while resources run or could run on the node: put it in standby \
         first (cluster_node) and wait for them to move, or pass force. Maintenance mode \
         is not enough: it leaves resources running. Only a reboot is offered, never \
         power-off or halt.",
        Access::Write,
        "host.reboot",
        vec![
            Param::choice(
                "action",
                "schedule a reboot, cancel the scheduled one, or show the status",
                &ACTIONS,
            )
            .required(),
            Param::int(
                "delay_minutes",
                "Minutes until the reboot (default 1; 0 reboots at once)",
                0,
                10080,
            ),
            Param::str(
                "message",
                "Why: shown to logged-in users and kept in the audit trail",
            )
            .max_len(200),
            Param::bool(
                "force",
                "Reboot even though this node is an active cluster member",
            ),
        ],
        |ctx, args| host_reboot_at(ctx, args, Paths::default()),
    )]
}

/// A shutdown that systemd has been asked to carry out later.
#[derive(Debug, PartialEq, Eq)]
pub struct Scheduled {
    /// `reboot`, `poweroff`, `halt`...
    pub mode: String,
    pub at_unix_secs: i64,
}

/// Reads systemd's record of a scheduled shutdown (`USEC=`, `MODE=` lines).
pub fn parse_scheduled(text: &str) -> Option<Scheduled> {
    let mut usec: Option<u64> = None;
    let mut mode = None;
    for line in text.lines() {
        match line.split_once('=') {
            Some(("USEC", value)) => usec = value.trim().parse().ok(),
            Some(("MODE", value)) => mode = Some(value.trim().to_string()),
            _ => {}
        }
    }
    let at_unix_secs = i64::try_from(usec? / 1_000_000).ok()?;
    let plain = |mode: &String| !mode.is_empty() && mode.chars().all(|c| c.is_ascii_lowercase());
    Some(Scheduled {
        mode: mode.filter(plain).unwrap_or_else(|| "shutdown".to_string()),
        at_unix_secs,
    })
}

/// One sentence describing a scheduled shutdown, as seen at `now`.
pub fn describe_scheduled(scheduled: &Scheduled, now: i64) -> String {
    let when = match u64::try_from(scheduled.at_unix_secs.saturating_sub(now)) {
        Ok(left) if left > 0 => format!("in {}", human_duration(left)),
        _ => "due now".to_string(),
    };
    format!(
        "A {} is scheduled for {} ({when}).",
        scheduled.mode,
        rfc3339_utc(scheduled.at_unix_secs)
    )
}

/// A cluster node as `crm_mon` reports it.
#[derive(Debug, PartialEq, Eq)]
pub struct Node {
    pub name: String,
    pub online: bool,
    /// In standby, whether set by an operator or because of a failure.
    pub standby: bool,
    pub maintenance: bool,
    /// How many resources run on it, if the cluster said.
    pub resources_running: Option<u64>,
}

/// The attributes of one XML start tag, e.g. `<node name="a" online="true"/>`. Reads
/// what it can of a malformed tag. Values are not unescaped: the ones used here (node
/// names, true/false) never need it.
pub fn attributes(tag: &str) -> BTreeMap<String, String> {
    let mut found = BTreeMap::new();
    let ends_name = |c: char| c.is_whitespace() || c == '>' || c == '/';
    let mut rest = tag
        .trim_start_matches('<')
        .trim_start_matches(|c| !ends_name(c));
    while let Some((key, after)) = rest.split_once('=') {
        let key = key.trim();
        if key.is_empty() || key.contains(|c: char| ends_name(c) || c == '"' || c == '\'') {
            break;
        }
        let after = after.trim_start();
        let Some(quote) = after.chars().next().filter(|c| *c == '"' || *c == '\'') else {
            break;
        };
        let Some((value, tail)) = after[quote.len_utf8()..].split_once(quote) else {
            break;
        };
        found.insert(key.to_string(), value.to_string());
        rest = tail;
    }
    found
}

/// The nodes in the `<nodes>` section of `crm_mon`'s XML output (the same in Pacemaker
/// 1.1's `--as-xml` and 2.x's `--output-as=xml`).
///
/// AIDEV-NOTE: `<node>` elements also appear elsewhere in that output (under a resource,
/// saying where it runs; under node_attributes). Only the `<nodes>` section describes
/// node state, and an element there without an `online` attribute is not counted: an
/// answer we do not understand must end up as "unknown", never as "not active".
pub fn parse_nodes(xml: &str) -> Vec<Node> {
    const OPEN: &str = "<nodes>";
    let Some(start) = xml.find(OPEN) else {
        return Vec::new();
    };
    let section = &xml[start + OPEN.len()..];
    let Some(end) = section.find("</nodes>") else {
        return Vec::new();
    };
    let mut nodes = Vec::new();
    let mut rest = &section[..end];
    while let Some(at) = rest.find("<node") {
        let tag = &rest[at..];
        let Some(close) = tag.find('>') else {
            break;
        };
        // `<node ...>` itself, not a longer element name
        if tag["<node".len()..].starts_with(char::is_whitespace) {
            let attrs = attributes(&tag[..=close]);
            let flag = |key: &str| attrs.get(key).is_some_and(|value| value == "true");
            if let (Some(name), true) = (attrs.get("name"), attrs.contains_key("online")) {
                nodes.push(Node {
                    name: name.clone(),
                    online: flag("online"),
                    standby: flag("standby") || flag("standby_onfail"),
                    maintenance: flag("maintenance"),
                    resources_running: attrs
                        .get("resources_running")
                        .and_then(|count| count.parse().ok()),
                });
            }
        }
        rest = &tag[close + 1..];
    }
    nodes
}

/// What the cluster says about this host.
#[derive(Debug, PartialEq, Eq)]
pub enum Membership {
    /// A reboot now would take resources down (or could): the node's name in the
    /// cluster, and what is in the way.
    Busy { name: String, why: String },
    /// Known to the cluster, with nothing running here that a reboot would stop.
    Inactive,
    /// The cluster lists no node by this name.
    Unknown,
}

/// Finds this host among the cluster's nodes: by its exact name, else without regard to
/// case, else by the part before the first dot (a host may call itself db1.example.com
/// where the cluster says db1).
pub fn membership(nodes: &[Node], this: &str) -> Membership {
    let this = this.trim();
    if this.is_empty() {
        return Membership::Unknown;
    }
    let short = |name: &str| {
        name.split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase()
    };
    let exact: Vec<&Node> = nodes.iter().filter(|n| n.name == this).collect();
    let any_case: Vec<&Node> = nodes
        .iter()
        .filter(|n| n.name.eq_ignore_ascii_case(this))
        .collect();
    let by_short: Vec<&Node> = nodes
        .iter()
        .filter(|n| short(&n.name) == short(this))
        .collect();
    let matches = [exact, any_case, by_short]
        .into_iter()
        .find(|found| !found.is_empty())
        .unwrap_or_default();
    // Should more than one node match, a busy one decides: refusing is the safe side.
    match matches
        .iter()
        .find_map(|node| Some((node, in_the_way(node)?)))
    {
        Some((node, why)) => Membership::Busy {
            name: node.name.clone(),
            why,
        },
        None if matches.is_empty() => Membership::Unknown,
        None => Membership::Inactive,
    }
}

/// What a reboot of this node would disturb, if anything.
///
/// AIDEV-NOTE: only two states are safe: offline, or emptied. Standby empties a node
/// (once its resources have moved, which takes a while). Maintenance mode does NOT: it
/// leaves resources running and merely stops the cluster managing them, so a reboot
/// would stop them and nothing would move them elsewhere. An online node that is in
/// neither state can be given resources at any moment, so it counts as busy even when
/// nothing runs on it yet.
fn in_the_way(node: &Node) -> Option<String> {
    if !node.online {
        return None;
    }
    if node.maintenance {
        return match node.resources_running {
            Some(0) => None,
            _ => Some(
                "is in maintenance mode: its resources are still running here, unmanaged, \
                 and a reboot would stop them without the cluster moving them. Take it out \
                 of maintenance and put it in standby first (cluster_node)"
                    .to_string(),
            ),
        };
    }
    if !node.standby {
        return Some(
            "is an active cluster member: put it in standby first (cluster_node)".to_string(),
        );
    }
    match node.resources_running {
        Some(running) if running > 0 => Some(format!(
            "is in standby, but {running} resource(s) are still running here: wait until \
             they have stopped or moved (cluster_status)"
        )),
        _ => None,
    }
}

/// The message given to `shutdown`, which shows it to logged-in users.
pub fn wall_message(principal: &str, message: Option<&str>) -> String {
    let mut text = format!("opsmcp: reboot requested by {}", plain_name(principal));
    if let Some(reason) = message.map(str::trim).filter(|reason| !reason.is_empty()) {
        text.push_str(": ");
        text.push_str(reason);
    }
    text
}

struct State {
    scheduled: Option<Scheduled>,
    reboot_required: bool,
}

async fn read_state(ctx: &Ctx, paths: &Paths) -> Result<State, ToolError> {
    let paths = paths.clone();
    blocking(ctx.clone(), move || {
        Ok(State {
            scheduled: read_small(&paths.scheduled, 4096).and_then(|text| parse_scheduled(&text)),
            reboot_required: paths.reboot_required.exists(),
        })
    })
    .await
}

/// What this node is called in the cluster: what `crm_node -n` says, else the host name.
async fn node_name(ctx: &Ctx, paths: &Paths) -> Result<String, ToolError> {
    if let Ok(crm_node) = ctx.command("crm_node") {
        let out = ctx.run(crm_node.args(["-n"])).await?;
        let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if command_ok(&out) && !name.is_empty() {
            return Ok(name);
        }
    }
    let path = paths.hostname.clone();
    blocking(ctx.clone(), move || {
        Ok(read_small(&path, 4096)
            .unwrap_or_default()
            .trim()
            .to_string())
    })
    .await
}

/// What Pacemaker has to say about rebooting this host now.
enum Guard {
    /// This host is not in a running cluster.
    NotMember,
    /// A cluster node with nothing on it that a reboot would stop, as of now.
    SafeNow,
    /// Do not reboot: why.
    Blocked(String),
}

/// How far ahead a reboot may be scheduled on a cluster node without `force`.
const CLUSTER_MAX_DELAY_MINUTES: i64 = 10;

/// crm_mon's exit status for "not connected to the cluster": Pacemaker 2 and later
/// (CRM_EX_DISCONNECTED), and Pacemaker 1.1, which exits with ENOTCONN.
const NOT_CONNECTED: [i32; 2] = [102, 107];

/// Whether pacemaker.service is running, if systemd will say.
async fn pacemaker_running(ctx: &Ctx) -> Option<bool> {
    let systemctl = ctx.optional_command("systemctl").ok()??;
    let out = ctx
        .run(systemctl.args(["is-active", "--", "pacemaker.service"]))
        .await
        .ok()?;
    if out.timed_out {
        return None;
    }
    match String::from_utf8_lossy(&out.stdout).trim() {
        "active" | "activating" | "reloading" | "deactivating" => Some(true),
        "inactive" | "failed" | "unknown" => Some(false),
        _ => None,
    }
}

/// Asks the cluster whether this host can be rebooted now.
///
/// AIDEV-NOTE: when in doubt this must block (until the caller passes `force`). "Not a
/// cluster member, go ahead" is the answer in exactly these cases:
/// - no `crm_mon` is installed;
/// - `crm_mon` could not reach a cluster AND the cluster stack is not running here:
///   systemd says pacemaker.service is not active, or, where systemd cannot be asked,
///   crm_mon's exit status is the one that means "not connected".
///
/// A node the cluster knows is safe only when it is offline or emptied by standby (see
/// `in_the_way`). Everything else blocks: a busy node, a `crm_mon` that is there but may
/// not be run, one that fails for any other reason or does not answer in time, a
/// cluster stack that is running but cannot be asked, an answer that does not list this
/// host or cannot be read.
async fn cluster_guard(ctx: &Ctx, paths: &Paths) -> Result<Guard, ToolError> {
    match ctx.bins().lookup("crm_mon") {
        Ok(None) => return Ok(Guard::NotMember),
        Ok(Some(_)) => {}
        Err(e) => {
            return Ok(Guard::Blocked(format!(
                "crm_mon is on this host but cannot be used ({e}), so it is not known \
                 whether this node is an active cluster member; pass force if you are sure"
            )));
        }
    }
    let mut nodes = None;
    let mut not_connected = false;
    let mut said = String::new();
    // Pacemaker 2 and later, then the spelling Pacemaker 1.1 understands.
    for format in ["--output-as=xml", "--as-xml"] {
        let out = ctx
            .run(ctx.command("crm_mon")?.args(["-1", format]))
            .await?;
        if out.timed_out {
            return Ok(Guard::Blocked(
                "the cluster did not answer in time, so it is not known whether this node \
                 is an active cluster member; try again, or pass force"
                    .to_string(),
            ));
        }
        if command_ok(&out) {
            nodes = Some(parse_nodes(&String::from_utf8_lossy(&out.stdout)));
            break;
        }
        not_connected |= out.code.is_some_and(|code| NOT_CONNECTED.contains(&code));
        if said.is_empty() {
            said = command_text(&out).trim().to_string();
        }
    }
    let Some(nodes) = nodes else {
        let unknown = |why: &str| {
            Guard::Blocked(format!(
                "{why}, so it is not known whether this node is an active cluster member; \
                 pass force if you are sure. crm_mon said: {}",
                one_line_cell(&said.chars().take(300).collect::<String>())
            ))
        };
        return Ok(match pacemaker_running(ctx).await {
            Some(true) => unknown(
                "the cluster stack is running here (pacemaker.service is active) but \
                 crm_mon could not read its status",
            ),
            Some(false) => Guard::NotMember,
            None if not_connected => Guard::NotMember,
            None => {
                unknown("crm_mon failed, and not in the way that means no cluster is running here")
            }
        });
    };
    let this = node_name(ctx, paths).await?;
    Ok(match membership(&nodes, &this) {
        Membership::Busy { name, why } => {
            Guard::Blocked(format!("this node ({name}) {why}; or pass force"))
        }
        Membership::Inactive => Guard::SafeNow,
        Membership::Unknown => Guard::Blocked(format!(
            "the cluster is running here but its status lists no node called {this:?}, so \
             it is not known whether this node is an active cluster member; pass force if \
             you are sure"
        )),
    })
}

async fn schedule(ctx: &Ctx, auth: Authorized, args: &Args, paths: &Paths) -> ToolResult {
    let delay = args.int("delay_minutes").unwrap_or(1);
    let shutdown = ctx.command("shutdown")?;
    if args.bool("force") != Some(true) {
        match cluster_guard(ctx, paths).await? {
            Guard::NotMember => {}
            Guard::Blocked(reason) => {
                return auth.failed(format!("Not rebooting: {reason}.\n"));
            }
            // AIDEV-NOTE: the node's state was checked just now. A reboot scheduled far
            // ahead would meet whatever state the node is in then (someone may have
            // taken it out of standby), so on a cluster node it has to be soon.
            Guard::SafeNow if delay > CLUSTER_MAX_DELAY_MINUTES => {
                return auth.failed(format!(
                    "Not scheduled: this is a cluster node, and its state was checked \
                     now, not when the reboot would happen. Schedule it at most \
                     {CLUSTER_MAX_DELAY_MINUTES} minutes ahead, or pass force.\n"
                ));
            }
            Guard::SafeNow => {}
        }
    }
    // Only ever `-r`: this tool reboots, it does not power off or halt.
    let message = wall_message(&ctx.principal().name, args.str("message"));
    let out = ctx
        .run(shutdown.args(["-r".to_string(), format!("+{delay}"), message]))
        .await?;
    let mut text = command_text(&out);
    if !command_ok(&out) {
        text.push_str("Scheduling the reboot FAILED.\n");
        return auth.failed(text);
    }
    if delay == 0 {
        text.push_str("The reboot has been started now.\n");
    } else {
        let at = now_secs().saturating_add(delay.saturating_mul(60));
        let plural = if delay == 1 { "" } else { "s" };
        text.push_str(&format!(
            "Reboot scheduled for {} (in {delay} minute{plural}).\n\
             To cancel it: host_reboot with action=cancel.\n",
            rfc3339_utc(at)
        ));
    }
    auth.ok(text)
}

async fn cancel(ctx: &Ctx, auth: Authorized, paths: &Paths) -> ToolResult {
    let before = read_state(ctx, paths).await?.scheduled;
    let out = ctx.run(ctx.command("shutdown")?.args(["-c"])).await?;
    let mut text = command_text(&out);
    if !command_ok(&out) {
        text.push_str("Cancelling FAILED.\n");
        return auth.failed(text);
    }
    match before {
        Some(scheduled) => text.push_str(&format!(
            "Cancelled: the {} that was scheduled for {} will not happen.\n",
            scheduled.mode,
            rfc3339_utc(scheduled.at_unix_secs)
        )),
        None => text.push_str("No scheduled shutdown was found; `shutdown -c` was run anyway.\n"),
    }
    auth.ok(text)
}

async fn status(ctx: &Ctx, auth: Authorized, paths: &Paths) -> ToolResult {
    let state = read_state(ctx, paths).await?;
    let mut text = match &state.scheduled {
        Some(scheduled) => format!("{}\n", describe_scheduled(scheduled, now_secs())),
        None => "No reboot is scheduled.\n".to_string(),
    };
    text.push_str(if state.reboot_required {
        "A reboot is required by installed updates (the reboot-required flag is set).\n"
    } else {
        "A reboot is not flagged as required by installed updates.\n"
    });
    auth.ok(text)
}

pub async fn host_reboot_at(ctx: Ctx, args: Args, paths: Paths) -> ToolResult {
    let action = required(&args, "action")?.to_string();
    let auth = ctx.authorize(None)?;
    match action.as_str() {
        "status" => status(&ctx, auth, &paths).await,
        "cancel" => cancel(&ctx, auth, &paths).await,
        _ => schedule(&ctx, auth, &args, &paths).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::Host;
    use crate::tools::testing::{self, FakeBins, find, host, ok_text};
    use serde_json::{Value, json};
    use std::sync::Arc;

    #[test]
    fn parse_scheduled_reads_the_time_and_the_kind() {
        assert_eq!(
            parse_scheduled("USEC=1700000060000000\nWARN_WALL=1\nMODE=reboot\n"),
            Some(Scheduled {
                mode: "reboot".to_string(),
                at_unix_secs: 1_700_000_060
            })
        );
        assert_eq!(
            parse_scheduled("MODE=poweroff\nUSEC=1700000000999999\n"),
            Some(Scheduled {
                mode: "poweroff".to_string(),
                at_unix_secs: 1_700_000_000
            })
        );
        // no kind recorded: still a pending shutdown
        assert_eq!(
            parse_scheduled("USEC=1700000000000000\n").map(|s| s.mode),
            Some("shutdown".to_string())
        );
        for bad in ["", "MODE=reboot\n", "USEC=soon\nMODE=reboot\n", "USEC=\n"] {
            assert_eq!(parse_scheduled(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn describe_scheduled_says_when_and_how_long_until_then() {
        let scheduled = Scheduled {
            mode: "reboot".to_string(),
            at_unix_secs: 1_700_000_300,
        };
        let text = describe_scheduled(&scheduled, 1_700_000_000);
        assert!(text.contains("reboot"), "{text}");
        assert!(text.contains("2023-11-14T22:18:20Z"), "{text}");
        assert!(text.contains("5m 0s"), "{text}");
        // already due
        let text = describe_scheduled(&scheduled, 1_700_000_400);
        assert!(text.contains("due now"), "{text}");
    }

    #[test]
    fn attributes_reads_quoted_values_of_either_kind() {
        let got = attributes(r#"<node name="node-1" id='1' online="true"  standby="false" />"#);
        let want: BTreeMap<String, String> = [
            ("name", "node-1"),
            ("id", "1"),
            ("online", "true"),
            ("standby", "false"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        assert_eq!(got, want);
        assert_eq!(attributes("<node>"), BTreeMap::new());
        // a broken tag gives what could be read, and never panics
        assert_eq!(attributes(r#"<node name="a" online="#).len(), 1);
        assert_eq!(attributes(r#"<node name="#).len(), 0);
    }

    /// `crm_mon -1 --output-as=xml` from Pacemaker 2.x, shortened. Note the `<node>`
    /// elements outside `<nodes>`: they say where a resource runs, not what state a node
    /// is in.
    const PACEMAKER_2: &str = r#"<pacemaker-result api-version="2.30" request="crm_mon -1 --output-as=xml">
  <summary>
    <stack type="corosync"/>
    <nodes_configured number="3"/>
  </summary>
  <nodes>
    <node name="db1" id="1" online="true" standby="false" standby_onfail="false" maintenance="false" pending="false" unclean="false" health="green" feature_set="3.17.4" shutdown="false" expected_up="true" is_dc="true" resources_running="2" type="member"/>
    <node name="db2" id="2" online="true" standby="true" standby_onfail="false" maintenance="false" pending="false" unclean="false" health="green" feature_set="3.17.4" shutdown="false" expected_up="true" is_dc="false" resources_running="0" type="member"/>
    <node name="db3" id="3" online="false" standby="false" standby_onfail="false" maintenance="false" pending="false" unclean="false" health="green" shutdown="false" expected_up="false" is_dc="false" resources_running="0" type="member"/>
  </nodes>
  <resources>
    <resource id="vip" resource_agent="ocf:heartbeat:IPaddr2" role="Started" active="true" nodes_running_on="1">
      <node name="db2" id="2" cached="true"/>
    </resource>
  </resources>
  <node_attributes>
    <node name="db1">
      <attribute name="master-galera" value="100"/>
    </node>
  </node_attributes>
  <status code="0" message="OK"/>
</pacemaker-result>
"#;

    /// `crm_mon -1 --as-xml` from Pacemaker 1.1, shortened.
    const PACEMAKER_1: &str = r#"<?xml version="1.0"?>
<crm_mon version="1.1.18">
    <summary>
        <stack type="corosync" />
    </summary>
    <nodes>
        <node name="web1" id="1084783105" online="true" standby="false" standby_onfail="false" maintenance="true" pending="false" unclean="false" shutdown="false" expected_up="true" is_dc="true" resources_running="2" type="member" />
        <node name="web2" id="1084783106" online="true" standby="false" standby_onfail="false" maintenance="false" pending="false" unclean="false" shutdown="false" expected_up="true" is_dc="false" resources_running="1" type="member" />
    </nodes>
    <resources>
        <resource id="p_vip" resource_agent="ocf::heartbeat:IPaddr2" role="Started" active="true" nodes_running_on="1" >
            <node name="web1" id="1084783105" cached="false" />
        </resource>
    </resources>
</crm_mon>
"#;

    fn node(name: &str, online: bool, standby: bool, maintenance: bool, running: u64) -> Node {
        Node {
            name: name.to_string(),
            online,
            standby,
            maintenance,
            resources_running: Some(running),
        }
    }

    #[test]
    fn parse_nodes_reads_only_the_node_states_of_either_pacemaker() {
        assert_eq!(
            parse_nodes(PACEMAKER_2),
            vec![
                node("db1", true, false, false, 2),
                node("db2", true, true, false, 0),
                node("db3", false, false, false, 0),
            ]
        );
        assert_eq!(
            parse_nodes(PACEMAKER_1),
            vec![
                node("web1", true, false, true, 2),
                node("web2", true, false, false, 1),
            ]
        );
        assert_eq!(parse_nodes(""), vec![]);
        assert_eq!(parse_nodes("<crm_mon><nodes/></crm_mon>"), vec![]);
        assert_eq!(parse_nodes("<nodes><node name=\"a\""), vec![]);
    }

    fn busy(nodes: &[Node], this: &str) -> Option<(String, String)> {
        match membership(nodes, this) {
            Membership::Busy { name, why } => Some((name, why)),
            _ => None,
        }
    }

    #[test]
    fn membership_is_busy_for_a_node_whose_reboot_would_take_resources_down() {
        let nodes = parse_nodes(PACEMAKER_2);
        let (name, why) = busy(&nodes, "db1").unwrap();
        assert_eq!(name, "db1");
        assert!(why.contains("active cluster member"), "{why}");
        assert_eq!(membership(&nodes, "db2"), Membership::Inactive);
        assert_eq!(membership(&nodes, "db3"), Membership::Inactive);
        assert_eq!(membership(&nodes, "db9"), Membership::Unknown);
        // the host may know itself by a longer or differently-cased name than the cluster
        assert_eq!(busy(&nodes, "DB1.example.com").unwrap().0, "db1");
        assert_eq!(membership(&[], "db1"), Membership::Unknown);
    }

    #[test]
    fn a_node_in_maintenance_still_runs_its_resources_and_is_busy() {
        // AIDEV-NOTE: maintenance mode leaves resources RUNNING, only unmanaged. A reboot
        // would stop them and the cluster would not move them. Only standby empties a node.
        let (name, why) = busy(&parse_nodes(PACEMAKER_1), "web1").unwrap();
        assert_eq!(name, "web1");
        assert!(why.contains("maintenance"), "{why}");
        // in maintenance with nothing running here: nothing to take down
        assert_eq!(
            membership(&[node("a", true, false, true, 0)], "a"),
            Membership::Inactive
        );
        // if the cluster does not say how many are running, assume some are
        let mut unknown = node("a", true, false, true, 0);
        unknown.resources_running = None;
        assert!(busy(&[unknown], "a").is_some());
    }

    #[test]
    fn a_node_in_standby_is_busy_until_its_resources_have_left() {
        let (_, why) = busy(&[node("a", true, true, false, 3)], "a").unwrap();
        assert!(why.contains("3 resource"), "{why}");
        assert!(why.contains("standby"), "{why}");
        assert_eq!(
            membership(&[node("a", true, true, false, 0)], "a"),
            Membership::Inactive
        );
        // standby because of a failure counts as standby
        let xml = r#"<nodes><node name="a" online="true" standby="false" standby_onfail="true" maintenance="false" resources_running="0"/></nodes>"#;
        assert_eq!(membership(&parse_nodes(xml), "a"), Membership::Inactive);
        // an online node that is not in standby is busy even with nothing running yet:
        // the cluster may start something there at any moment
        assert!(busy(&[node("a", true, false, false, 0)], "a").is_some());
    }

    #[test]
    fn wall_message_names_the_requester_and_keeps_odd_names_harmless() {
        assert_eq!(
            wall_message("adam", None),
            "opsmcp: reboot requested by adam"
        );
        assert_eq!(
            wall_message("token:claude-ci", Some("  kernel update ")),
            "opsmcp: reboot requested by token:claude-ci: kernel update"
        );
        assert_eq!(
            wall_message("we ird\u{1b}name", Some("")),
            "opsmcp: reboot requested by we_ird_name"
        );
    }

    const CONFIG: &str = r#"
[roles.admin]
allow = ["@all"]
[roles.reader]
allow = ["@read"]
[unix_users.adam]
roles = ["admin"]
[unix_users.rita]
roles = ["reader"]
"#;

    struct Fixture {
        host: Arc<Host>,
        audit: MemorySink,
        paths: Paths,
        _dir: tempfile::TempDir,
    }

    fn fixture(fake: &FakeBins) -> Fixture {
        fixture_with(fake, "")
    }

    fn fixture_with(fake: &FakeBins, extra: &str) -> Fixture {
        let (host, audit) = host(&format!("{CONFIG}{extra}{}", fake.config_only()));
        let dir = tempfile::tempdir().unwrap();
        let at = |name: &str| dir.path().join(name);
        std::fs::write(at("hostname"), "db1\n").unwrap();
        let paths = Paths {
            scheduled: at("scheduled"),
            reboot_required: at("reboot-required"),
            hostname: at("hostname"),
        };
        Fixture {
            host,
            audit,
            paths,
            _dir: dir,
        }
    }

    async fn run(fixture: &Fixture, user: &str, arguments: Value) -> ToolResult {
        let tool = find(tools(), "host_reboot");
        let args = Args::parse(&tool.params, Some(&arguments)).map_err(ToolError::Invalid)?;
        let ctx = testing::ctx(&fixture.host, user, "host.reboot", Access::Write);
        host_reboot_at(ctx, args, fixture.paths.clone()).await
    }

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// A crm_mon that prints `xml` when asked with `flag`, and fails otherwise.
    fn crm_mon_for(fake: FakeBins, flag: &str, xml: &str) -> FakeBins {
        let script = format!(
            // shell built-ins only: stand-ins run with a PATH that holds nothing else
            "case \"$2\" in\n{flag}) while IFS= read -r line; do printf '%s\\n' \"$line\"; done <<'XML'\n{xml}\nXML\n;;\n*) echo 'unknown option' >&2; exit 64 ;;\nesac"
        );
        fake.add_script("crm_mon", &script)
    }

    /// A crm_mon from Pacemaker 2: answers `--output-as=xml`.
    fn crm_mon(fake: FakeBins, xml: &str) -> FakeBins {
        crm_mon_for(fake, "--output-as=xml", xml)
    }

    #[tokio::test]
    async fn schedule_asks_shutdown_for_a_reboot_one_minute_ahead_by_default() {
        let fake = FakeBins::new().add("shutdown", "", 0);
        let fixture = fixture(&fake);
        let text = ok_text(run(&fixture, "adam", json!({"action": "schedule"})).await);
        assert_eq!(
            fake.calls("shutdown"),
            vec![strings(&["-r", "+1", "opsmcp: reboot requested by adam"])]
        );
        assert!(text.contains("in 1 minute"), "{text}");
        assert!(text.contains("action=cancel"), "{text}");
        let records = fixture.audit.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["permission"], "host.reboot");
        assert_eq!(records[0]["decision"], "allow");
    }

    #[tokio::test]
    async fn schedule_passes_the_delay_and_the_reason() {
        let fake = FakeBins::new().add("shutdown", "", 0);
        let fixture = fixture(&fake);
        let arguments = json!({"action": "schedule", "delay_minutes": 30, "message": "new kernel"});
        let text = ok_text(run(&fixture, "adam", arguments).await);
        assert_eq!(
            fake.calls("shutdown"),
            vec![strings(&[
                "-r",
                "+30",
                "opsmcp: reboot requested by adam: new kernel"
            ])]
        );
        assert!(text.contains("in 30 minutes"), "{text}");

        let now = json!({"action": "schedule", "delay_minutes": 0});
        let text = ok_text(run(&fixture, "adam", now).await);
        assert_eq!(fake.calls("shutdown")[1][1], "+0");
        assert!(text.contains("now"), "{text}");
    }

    #[tokio::test]
    async fn a_failing_shutdown_command_is_reported_as_an_error() {
        let fake = FakeBins::new().add_script("shutdown", "echo 'Failed to connect' >&2; exit 1");
        let fixture = fixture(&fake);
        let output = run(&fixture, "adam", json!({"action": "schedule"}))
            .await
            .unwrap();
        assert!(output.is_error());
        assert!(output.text().contains("Failed to connect"), "{output:?}");
        assert!(output.text().contains("FAILED"), "{output:?}");
    }

    #[tokio::test]
    async fn a_caller_without_the_grant_is_refused_and_nothing_runs() {
        let fake = crm_mon(FakeBins::new().add("shutdown", "", 0), PACEMAKER_2);
        let fixture = fixture(&fake);
        for action in ["schedule", "cancel", "status"] {
            let result = run(&fixture, "rita", json!({"action": action})).await;
            assert!(matches!(result, Err(ToolError::Denied(_))), "{action}");
        }
        assert_eq!(fake.calls("shutdown"), Vec::<Vec<String>>::new());
        assert_eq!(fake.calls("crm_mon"), Vec::<Vec<String>>::new());
        assert_eq!(fixture.audit.records().len(), 3);
    }

    #[tokio::test]
    async fn an_active_cluster_member_is_not_rebooted_unless_forced() {
        // this host is db1 (see the fixture), which is online and not in standby
        let fake = crm_mon(FakeBins::new().add("shutdown", "", 0), PACEMAKER_2);
        let fixture = fixture(&fake);
        let output = run(&fixture, "adam", json!({"action": "schedule"}))
            .await
            .unwrap();
        assert!(output.is_error());
        assert!(
            output.text().contains("active cluster member"),
            "{output:?}"
        );
        assert!(output.text().contains("standby"), "{output:?}");
        assert!(output.text().contains("force"), "{output:?}");
        assert_eq!(fake.calls("shutdown"), Vec::<Vec<String>>::new());

        let forced = json!({"action": "schedule", "force": true});
        ok_text(run(&fixture, "adam", forced).await);
        assert_eq!(fake.calls("shutdown").len(), 1);
        // with force the cluster is not even asked
        assert_eq!(fake.calls("crm_mon").len(), 1);
    }

    #[tokio::test]
    async fn a_node_in_maintenance_is_not_rebooted_unless_forced() {
        let fake = crm_mon(FakeBins::new().add("shutdown", "", 0), PACEMAKER_1);
        let fixture = fixture(&fake);
        std::fs::write(&fixture.paths.hostname, "web1\n").unwrap();
        let output = run(&fixture, "adam", json!({"action": "schedule"}))
            .await
            .unwrap();
        assert!(output.is_error());
        assert!(output.text().contains("maintenance"), "{output:?}");
        assert_eq!(fake.calls("shutdown"), Vec::<Vec<String>>::new());
    }

    #[tokio::test]
    async fn a_crm_mon_that_is_present_but_may_not_be_run_blocks_the_reboot() {
        use std::os::unix::fs::PermissionsExt;
        // The server (as root) only runs programs nobody else could have replaced. A
        // crm_mon that fails that check is not "no cluster here": we simply do not know.
        let fake = FakeBins::new().add("shutdown", "", 0);
        let open_dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(open_dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let untrusted = open_dir.path().join("crm_mon");
        testing::write_executable(&untrusted, "#!/bin/sh\nexit 0\n");
        let config = format!(
            "{CONFIG}{}\"crm_mon\" = \"{}\"\n",
            fake.config_only(),
            untrusted.display()
        );
        let me = rustix::process::getuid().as_raw();
        let (host, audit) = testing::host_with_trust(&config, Some(vec![me]));
        let mut fixture = fixture(&fake);
        fixture.host = host;
        fixture.audit = audit;

        let output = run(&fixture, "adam", json!({"action": "schedule"}))
            .await
            .unwrap();
        assert!(output.is_error());
        assert!(output.text().contains("crm_mon"), "{output:?}");
        assert!(output.text().contains("force"), "{output:?}");
        assert_eq!(fake.calls("shutdown"), Vec::<Vec<String>>::new());
    }

    #[tokio::test]
    async fn the_cluster_is_asked_what_this_node_is_called() {
        // crm_node says this host is db2, which is in standby: the reboot goes ahead
        let fake = crm_mon(FakeBins::new().add("shutdown", "", 0), PACEMAKER_2)
            .add("crm_node", "db2\n", 0);
        let fixture = fixture(&fake);
        ok_text(run(&fixture, "adam", json!({"action": "schedule"})).await);
        assert_eq!(fake.calls("crm_node"), vec![strings(&["-n"])]);
        assert_eq!(fake.calls("shutdown").len(), 1);
    }

    #[tokio::test]
    async fn an_older_pacemaker_is_asked_in_its_own_way() {
        let fake = crm_mon_for(
            FakeBins::new().add("shutdown", "", 0),
            "--as-xml",
            PACEMAKER_1,
        )
        .add("crm_node", "web2\n", 0);
        let fixture = fixture(&fake);
        let output = run(&fixture, "adam", json!({"action": "schedule"}))
            .await
            .unwrap();
        assert!(output.is_error(), "{output:?}");
        assert!(output.text().contains("web2"), "{output:?}");
        assert_eq!(
            fake.calls("crm_mon"),
            vec![
                strings(&["-1", "--output-as=xml"]),
                strings(&["-1", "--as-xml"])
            ]
        );
        assert_eq!(fake.calls("shutdown"), Vec::<Vec<String>>::new());
    }

    #[tokio::test]
    async fn a_host_where_the_cluster_is_not_running_may_be_rebooted() {
        let fake = FakeBins::new().add("shutdown", "", 0).add_script(
            "crm_mon",
            "echo 'Connection to cluster failed' >&2; exit 102",
        );
        let fixture = fixture(&fake);
        ok_text(run(&fixture, "adam", json!({"action": "schedule"})).await);
        assert_eq!(fake.calls("shutdown").len(), 1);
    }

    #[tokio::test]
    async fn a_crm_mon_that_fails_for_another_reason_blocks_the_reboot() {
        // AIDEV-NOTE: "the cluster is not running here" is one particular answer (not
        // connected). Any other failure (the cluster busy, no rights, a broken reply)
        // means we do not know, and not knowing must block.
        let fake = FakeBins::new()
            .add("shutdown", "", 0)
            .add_script("crm_mon", "echo 'Error: cluster is busy' >&2; exit 1");
        let fixture = fixture(&fake);
        let output = run(&fixture, "adam", json!({"action": "schedule"}))
            .await
            .unwrap();
        assert!(output.is_error(), "{output:?}");
        assert!(output.text().contains("cluster is busy"), "{output:?}");
        assert!(output.text().contains("force"), "{output:?}");
        assert_eq!(fake.calls("shutdown"), Vec::<Vec<String>>::new());
    }

    #[tokio::test]
    async fn systemd_settles_whether_the_cluster_stack_is_running_here() {
        // crm_mon fails in a way that says nothing; pacemaker.service is not running:
        // the tools are installed but this host is not in a cluster right now
        let stopped = FakeBins::new()
            .add("shutdown", "", 0)
            .add_script("crm_mon", "echo 'something odd' >&2; exit 1")
            .add_script("systemctl", "echo inactive; exit 3");
        let fixture = fixture(&stopped);
        ok_text(run(&fixture, "adam", json!({"action": "schedule"})).await);
        assert_eq!(
            stopped.calls("systemctl"),
            vec![strings(&["is-active", "--", "pacemaker.service"])]
        );
        assert_eq!(stopped.calls("shutdown").len(), 1);

        // the same failure while pacemaker.service IS running: the cluster is there and
        // could not be asked, so the reboot is blocked, even if crm_mon said "not connected"
        let running = FakeBins::new()
            .add("shutdown", "", 0)
            .add_script(
                "crm_mon",
                "echo 'Connection to cluster failed' >&2; exit 102",
            )
            .add_script("systemctl", "echo active");
        let second = self::fixture(&running);
        let output = run(&second, "adam", json!({"action": "schedule"}))
            .await
            .unwrap();
        assert!(output.is_error(), "{output:?}");
        assert!(output.text().contains("pacemaker.service"), "{output:?}");
        assert_eq!(running.calls("shutdown"), Vec::<Vec<String>>::new());
    }

    #[tokio::test]
    async fn on_a_cluster_node_a_reboot_cannot_be_scheduled_far_ahead() {
        // AIDEV-NOTE: the node's state is checked now. Scheduled days ahead, the reboot
        // would hit whatever state the node is in then (taken out of standby, perhaps).
        let xml = PACEMAKER_2; // this host is db1; make it db2, which is in standby
        let fake = crm_mon(FakeBins::new().add("shutdown", "", 0), xml);
        let fixture = fixture(&fake);
        std::fs::write(&fixture.paths.hostname, "db2\n").unwrap();
        let far = json!({"action": "schedule", "delay_minutes": 600});
        let output = run(&fixture, "adam", far).await.unwrap();
        assert!(output.is_error(), "{output:?}");
        assert!(output.text().contains("cluster"), "{output:?}");
        assert!(output.text().contains("10 minutes"), "{output:?}");
        assert_eq!(fake.calls("shutdown"), Vec::<Vec<String>>::new());

        // soon is fine, and so is far ahead with force
        ok_text(
            run(
                &fixture,
                "adam",
                json!({"action": "schedule", "delay_minutes": 5}),
            )
            .await,
        );
        let forced = json!({"action": "schedule", "delay_minutes": 600, "force": true});
        ok_text(run(&fixture, "adam", forced).await);
        assert_eq!(fake.calls("shutdown").len(), 2);
    }

    #[tokio::test]
    async fn a_cluster_that_does_not_list_this_host_blocks_the_reboot() {
        // the cluster is running but knows no node called db1: we cannot tell, so no
        let xml = PACEMAKER_2.replace("name=\"db1\"", "name=\"other\"");
        let fake = crm_mon(FakeBins::new().add("shutdown", "", 0), &xml);
        let fixture = fixture(&fake);
        let output = run(&fixture, "adam", json!({"action": "schedule"}))
            .await
            .unwrap();
        assert!(output.is_error());
        assert!(output.text().contains("db1"), "{output:?}");
        assert!(output.text().contains("force"), "{output:?}");
        assert_eq!(fake.calls("shutdown"), Vec::<Vec<String>>::new());
    }

    #[tokio::test]
    async fn a_cluster_answer_that_cannot_be_read_blocks_the_reboot() {
        let fake = crm_mon(FakeBins::new().add("shutdown", "", 0), "<something-new/>\n");
        let fixture = fixture(&fake);
        let output = run(&fixture, "adam", json!({"action": "schedule"}))
            .await
            .unwrap();
        assert!(output.is_error());
        assert!(output.text().contains("force"), "{output:?}");
        assert_eq!(fake.calls("shutdown"), Vec::<Vec<String>>::new());
    }

    #[tokio::test]
    async fn a_cluster_that_does_not_answer_in_time_blocks_the_reboot() {
        // a crm_mon that hangs (a busy loop: stand-ins have only shell built-ins)
        let fake = FakeBins::new()
            .add("shutdown", "", 0)
            .add_script("crm_mon", "while :; do :; done");
        let limits = "[limits]\ncommand_timeout_secs = 1\ncall_timeout_secs = 10\n";
        let fixture = fixture_with(&fake, limits);
        let output = run(&fixture, "adam", json!({"action": "schedule"}))
            .await
            .unwrap();
        assert!(output.is_error());
        assert!(output.text().contains("in time"), "{output:?}");
        assert!(output.text().contains("force"), "{output:?}");
        assert_eq!(fake.calls("shutdown"), Vec::<Vec<String>>::new());
    }

    #[tokio::test]
    async fn cancel_runs_shutdown_c_and_says_what_was_cancelled() {
        let fake = FakeBins::new().add("shutdown", "", 0);
        let fixture = fixture(&fake);
        std::fs::write(
            &fixture.paths.scheduled,
            "USEC=1700000060000000\nMODE=reboot\n",
        )
        .unwrap();
        let text = ok_text(run(&fixture, "adam", json!({"action": "cancel"})).await);
        assert_eq!(fake.calls("shutdown"), vec![strings(&["-c"])]);
        assert!(text.contains("Cancelled"), "{text}");
        assert!(text.contains("2023-11-14T22:14:20Z"), "{text}");

        std::fs::remove_file(&fixture.paths.scheduled).unwrap();
        let text = ok_text(run(&fixture, "adam", json!({"action": "cancel"})).await);
        assert!(text.contains("No scheduled"), "{text}");
        assert_eq!(fake.calls("shutdown").len(), 2);
    }

    #[tokio::test]
    async fn status_reports_what_is_pending_and_runs_nothing() {
        let fake = FakeBins::new().add("shutdown", "", 0);
        let fixture = fixture(&fake);
        let text = ok_text(run(&fixture, "adam", json!({"action": "status"})).await);
        assert!(text.contains("No reboot is scheduled"), "{text}");
        assert!(text.contains("not flagged"), "{text}");

        let soon = crate::timefmt::now_secs() + 600;
        std::fs::write(
            &fixture.paths.scheduled,
            format!("USEC={soon}000000\nMODE=reboot\n"),
        )
        .unwrap();
        std::fs::write(
            &fixture.paths.reboot_required,
            "*** System restart required ***\n",
        )
        .unwrap();
        let text = ok_text(run(&fixture, "adam", json!({"action": "status"})).await);
        assert!(text.contains("A reboot is scheduled"), "{text}");
        assert!(text.contains(&crate::timefmt::rfc3339_utc(soon)), "{text}");
        assert!(text.contains("reboot is required"), "{text}");
        assert_eq!(fake.calls("shutdown"), Vec::<Vec<String>>::new());
    }
}
