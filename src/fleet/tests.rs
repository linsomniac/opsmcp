//! Tests of the fleet server as a whole: real opsmcp servers stand behind it, each with
//! its own configuration, tools and audit trail, reached over in-process pipes (for
//! SSH) or over real TLS on the loopback interface (for HTTPS).

use super::*;
use crate::audit::testing::MemorySink;
use crate::config::Config;
use crate::fleet::inventory::Format;
use crate::fleet::link::Link;
use crate::http::testing::{CI_TOKEN, OPS_TOKEN, Web, web};
use crate::mcp::testing::{CONFIG as HOST_CONFIG, Effects, registry as host_registry};
use crate::mcp::{OwnSsh, Server};
use crate::policy::Access;
use crate::tools::args::{Args, Param};
use crate::tools::testing::host as make_host;
use crate::tools::{Ctx, Tool};
use serde_json::json;
use std::collections::HashSet;
use std::sync::Mutex;
use std::time::Duration;

// ---- the machines behind the fleet ----

/// One machine: a real opsmcp server with the test tools of `mcp::testing`, where rita
/// may read, walt may also touch things called alpha*, and adam may do anything.
struct Machine {
    server: Arc<Server>,
    effects: Arc<Effects>,
    audit: MemorySink,
}

impl Machine {
    fn new() -> Machine {
        // A machine reads requests of at most 4096 bytes: less than the fleet server
        // itself accepts, as when a host's limits are set lower than the fleet's.
        let config = format!(
            "{}\n[roles.admin]\nallow = [\"@all\"]\n[unix_users.adam]\nroles = [\"admin\"]\n",
            HOST_CONFIG.replace(
                "max_concurrent_calls = 2",
                "max_concurrent_calls = 2\nmax_request_bytes = 4096"
            )
        );
        let (host, audit) = make_host(&config);
        let effects = Arc::new(Effects::default());
        let mut registry = host_registry(&effects);
        // Tools the fleet server has never heard of, as an operator's custom tools are.
        registry
            .add(Tool::new(
                "galera_status",
                "Shows the state of the Galera cluster.\nSecond line.",
                Access::Read,
                "custom.galera_status",
                vec![Param::str("node", "Which node to ask about")],
                |ctx: Ctx, args: Args| async move {
                    let node = args.str("node").unwrap_or("all").to_string();
                    ctx.authorize(None)?.ok(format!("synced ({node})"))
                },
            ))
            .unwrap();
        let fx = effects.clone();
        registry
            .add(Tool::new(
                "failover",
                "Moves the primary to another node.",
                Access::Write,
                "custom.failover",
                vec![],
                move |ctx: Ctx, _args: Args| {
                    let fx = fx.clone();
                    async move {
                        let auth = ctx.authorize(None)?;
                        fx.touched.lock().unwrap().push("failover".to_string());
                        auth.ok("moved")
                    }
                },
            ))
            .unwrap();
        // A change that takes a while, so that a test can interrupt it.
        let fx = effects.clone();
        registry
            .add(Tool::new(
                "slow_touch",
                "Records a name, slowly.",
                Access::Write,
                "custom.slow_touch",
                vec![Param::str("name", "What to touch").required()],
                move |ctx: Ctx, args: Args| {
                    let fx = fx.clone();
                    async move {
                        let name = args.str("name").unwrap_or_default().to_string();
                        let auth = ctx.authorize(Some(&name))?;
                        fx.touched.lock().unwrap().push(name);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        auth.ok("touched, slowly")
                    }
                },
            ))
            .unwrap();
        Machine {
            server: Arc::new(Server::new(host, registry)),
            effects,
            audit,
        }
    }

    fn touched(&self) -> Vec<String> {
        self.effects.touched.lock().unwrap().clone()
    }

    fn audited(&self, event: &str) -> Vec<Value> {
        self.audit
            .records()
            .into_iter()
            .filter(|r| r["event"] == event)
            .collect()
    }
}

/// Stands in for `ssh`: connects to the machine of that name as the user the rule (or
/// the caller) says, the way sshd and sudo would hand opsmcp the logged-in user.
#[derive(Default)]
struct TestDialer {
    machines: HashMap<String, Arc<Machine>>,
    /// Hosts that do not answer.
    down: Mutex<HashSet<String>>,
    /// Every session opened: (host, as which user on it).
    dials: Mutex<Vec<(String, String)>>,
    /// The server side of every session, so that a test can cut one.
    sessions: Mutex<Vec<(String, tokio::task::JoinHandle<()>)>>,
    /// The largest message accepted from a machine, if a test sets one.
    max_line: std::sync::atomic::AtomicUsize,
}

impl TestDialer {
    fn dials(&self) -> Vec<(String, String)> {
        self.dials.lock().unwrap().clone()
    }

    fn dials_to(&self, host: &str) -> usize {
        self.dials().iter().filter(|(h, _)| h == host).count()
    }

    /// The connections to `host` drop, as when the machine reboots or the network goes.
    fn cut(&self, host: &str) {
        for (name, task) in self.sessions.lock().unwrap().iter() {
            if name == host {
                task.abort();
            }
        }
    }
}

impl Dialer for TestDialer {
    fn dial(&self, rule: &Rule, host: &HostEntry, identity: &DialAs) -> Dialing {
        let user = match identity {
            DialAs::Caller { principal, .. } => principal.clone(),
            DialAs::Fleet => rule.ssh_user.clone().unwrap(),
        };
        if self.down.lock().unwrap().contains(&host.name) {
            return Box::pin(async {
                Err(
                    "ssh could not connect or log in: connect to host: No route to host"
                        .to_string(),
                )
            });
        }
        let machine = self.machines.get(&host.name).unwrap().clone();
        let Some(principal) = machine.server.host().cfg.principal_for_unix(&user, &[]) else {
            // what `opsmcp serve` says to an account that holds no role there
            return Box::pin(async move {
                Err(format!(
                    "the command on the host ended with status 1: opsmcp: user {user} has no role"
                ))
            });
        };
        self.dials.lock().unwrap().push((host.name.clone(), user));
        let (ours, theirs) = tokio::io::duplex(1 << 20);
        let (their_read, their_write) = tokio::io::split(theirs);
        let server = machine.server.clone();
        let session = Session::new(principal, "stdio", None);
        let task = tokio::spawn(async move {
            let reader = tokio::io::BufReader::new(their_read);
            let _ =
                crate::stdio::serve(server, session, reader, their_write, std::future::pending())
                    .await;
        });
        self.sessions
            .lock()
            .unwrap()
            .push((host.name.clone(), task));
        let (read, write) = tokio::io::split(ours);
        let max_line = match self.max_line.load(std::sync::atomic::Ordering::SeqCst) {
            0 => 1 << 20,
            set => set,
        };
        Box::pin(async move { Ok(HostLink::over(Link::start(read, write, max_line))) })
    }
}

// ---- the fleet server under test ----

const FLEET_CONFIG: &str = r#"
[roles.ops]
allow = ["@all"]
[roles.dev]
allow = ["@read"]
[roles.dba]
allow = ["test.view", "custom.failover", "custom.galera_status"]
[roles.nobody]
allow = ["@all"]
[roles.empty]
allow = []

[unix_users.adam]
roles = ["ops"]
[unix_users.walt]
roles = ["ops"]
[unix_users.rita]
roles = ["dev"]
[unix_users.dora]
roles = ["dba"]
[unix_users.both]
roles = ["dev", "ops"]
[unix_users.lost]
roles = ["nobody"]
[unix_users.nell]
roles = ["empty"]

[limits]
max_output_bytes = 8192
command_timeout_secs = 2
call_timeout_secs = 2
max_concurrent_calls = 4

[fleet]
name = "bastion1"
inventory = "/unused/hosts.toml"
max_hosts_per_call = 4
max_parallel = 2
retry_secs = 60

[[fleet.access]]
name = "dev-web"
roles = ["dev"]
hosts = ["group:web"]
via = "ssh"
identity = "fleet"
ssh_user = "rita"
ssh_key = "/unused/dev_key"
read_only = true

[[fleet.access]]
name = "ops-own"
roles = ["ops"]
hosts = ["*"]
via = "ssh"
identity = "caller"

[[fleet.access]]
name = "dba-db"
roles = ["dba"]
hosts = ["group:db"]
via = "ssh"
identity = "fleet"
ssh_user = "adam"
ssh_key = "/unused/dba_key"

[[fleet.access]]
name = "empty-web"
roles = ["empty"]
hosts = ["group:web"]
via = "ssh"
identity = "fleet"
ssh_user = "adam"
ssh_key = "/unused/dba_key"
"#;

const INVENTORY: &str = r#"
[groups]
web = ["web1", "web2", "web3"]
db = ["db1", "db2"]
"#;

struct World {
    fleet: Arc<Fleet>,
    audit: MemorySink,
    dialer: Arc<TestDialer>,
}

fn world_with(
    config: &str,
    inventory: &str,
    https: Option<HttpsClient>,
    tokens: HashMap<usize, Secret>,
) -> World {
    let (host, audit) = make_host(config);
    let inventory = Inventory::parse(inventory, Format::Toml).unwrap();
    let machines = inventory
        .hosts()
        .map(|h| (h.name.clone(), Arc::new(Machine::new())))
        .collect();
    let dialer = Arc::new(TestDialer {
        machines,
        ..TestDialer::default()
    });
    let rules = AccessRules::compile(host.cfg.fleet.as_ref().unwrap()).unwrap();
    // The fleet server knows the standard test tools (as it knows the built-in tools),
    // and not the three extra ones each machine has.
    let registry = host_registry(&Arc::new(Effects::default()));
    let fleet = Fleet::assemble(
        Parts {
            host,
            registry,
            rules,
            name: "bastion1".to_string(),
            dialer: dialer.clone(),
            https,
            tokens,
        },
        inventory,
    );
    World {
        fleet,
        audit,
        dialer,
    }
}

fn world() -> World {
    world_with(FLEET_CONFIG, INVENTORY, None, HashMap::new())
}

impl World {
    fn cfg(&self) -> &Config {
        &self.fleet.parts.host.cfg
    }

    /// A caller who runs the fleet server as themselves (stdio), so has their own SSH
    /// identity.
    fn session(&self, user: &str) -> Session {
        let principal = self.cfg().principal_for_unix(user, &[]).unwrap();
        let mut session = Session::new(principal, "stdio", None);
        session.own_ssh = Some(OwnSsh::default());
        session
    }

    async fn call_as(&self, session: &Session, tool: &str, arguments: Value) -> (String, bool) {
        let params = json!({"name": tool, "arguments": arguments});
        let result = self
            .fleet
            .call_tool(session, Some(&params))
            .await
            .unwrap_or_else(|e| panic!("{tool}: {e:?}"));
        (
            result["content"][0]["text"].as_str().unwrap().to_string(),
            result["isError"].as_bool().unwrap(),
        )
    }

    async fn call(&self, user: &str, tool: &str, arguments: Value) -> (String, bool) {
        self.call_as(&self.session(user), tool, arguments).await
    }

    fn machine(&self, host: &str) -> &Machine {
        self.dialer.machines.get(host).unwrap()
    }

    fn audited(&self, event: &str) -> Vec<Value> {
        self.audit
            .records()
            .into_iter()
            .filter(|r| r["event"] == event)
            .collect()
    }

    fn listed(&self, user: &str) -> Vec<Value> {
        let result = self.fleet.list_tools(&self.session(user), None).unwrap();
        result["tools"].as_array().unwrap().clone()
    }

    fn tool_names(&self, user: &str) -> Vec<String> {
        self.listed(user)
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect()
    }

    /// No machine has been contacted at all.
    fn nothing_sent(&self) -> bool {
        self.dialer.dials().is_empty()
    }
}

// ---- what the agent is shown ----

#[tokio::test]
async fn every_tool_is_listed_once_with_the_argument_that_names_the_host() {
    let w = world();
    let tools = w.listed("adam");
    let find = |name: &str| {
        tools
            .iter()
            .find(|t| t["name"] == name)
            .unwrap_or_else(|| panic!("{name}"))
    };
    let echo = find("echo");
    assert_eq!(
        echo["inputSchema"]["required"],
        json!(["fleet_host", "text"])
    );
    assert_eq!(
        echo["inputSchema"]["properties"]["fleet_host"]["type"],
        "string"
    );
    assert_eq!(echo["inputSchema"]["properties"]["text"]["type"], "string");
    assert_eq!(echo["inputSchema"]["additionalProperties"], false);
    assert_eq!(echo["annotations"]["readOnlyHint"], true);
    assert_eq!(find("touch")["annotations"]["readOnlyHint"], false);
    assert_eq!(find("touch")["annotations"]["destructiveHint"], true);
    // a tool that reads may be sent to several hosts, one that changes things to one
    let reads = echo["inputSchema"]["properties"]["fleet_host"]["description"]
        .as_str()
        .unwrap();
    assert!(reads.contains("group:"), "{reads}");
    let writes = find("touch")["inputSchema"]["properties"]["fleet_host"]["description"]
        .as_str()
        .unwrap();
    assert!(
        writes.contains("one host") && !writes.contains("group:"),
        "{writes}"
    );
    // the fleet's own tools
    for name in ["fleet_hosts", "fleet_tools", "fleet_call"] {
        find(name);
    }
    assert_eq!(find("fleet_hosts")["annotations"]["readOnlyHint"], true);
    assert_eq!(find("fleet_call")["annotations"]["readOnlyHint"], false);
}

#[tokio::test]
async fn a_caller_is_only_shown_tools_a_rule_of_theirs_allows() {
    let w = world();
    // rita's rule is read-only and her role grants only reads
    let rita = w.tool_names("rita");
    assert!(rita.contains(&"echo".to_string()));
    assert!(!rita.contains(&"touch".to_string()), "{rita:?}");
    // dora's role names one read permission and two custom tools
    let dora = w.tool_names("dora");
    assert!(
        dora.contains(&"echo".to_string()) && !dora.contains(&"touch".to_string()),
        "{dora:?}"
    );
    // a caller no rule mentions is shown nothing at all
    assert!(w.tool_names("lost").is_empty());
    // listing asks no host anything
    assert!(w.nothing_sent());
}

#[tokio::test]
async fn a_read_only_session_is_not_shown_tools_that_change_things() {
    let w = world();
    let mut session = w.session("adam");
    session.read_only = true;
    let listed = w.fleet.list_tools(&session, None).unwrap();
    let names: Vec<&str> = listed["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"echo") && !names.contains(&"touch"),
        "{names:?}"
    );
    // and a request can ask for the same, as it can of a host
    let listed = w
        .fleet
        .list_tools(
            &w.session("adam"),
            Some(&json!({"_meta": {"opsmcp/via": {"read_only": true}}})),
        )
        .unwrap();
    assert!(
        !listed["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "touch")
    );
}

// ---- one host ----

#[tokio::test]
async fn a_call_is_passed_to_the_host_and_its_answer_returned() {
    let w = world();
    let (text, is_error) = w
        .call(
            "walt",
            "echo",
            json!({"fleet_host": "web1", "text": "hello"}),
        )
        .await;
    assert_eq!((text.as_str(), is_error), ("hello", false));
    // walt reached web1 as himself, and only web1
    assert_eq!(w.dialer.dials(), [("web1".to_string(), "walt".to_string())]);
}

#[tokio::test]
async fn the_host_sees_the_person_and_what_the_fleet_says_about_the_call() {
    let w = world();
    w.call(
        "walt",
        "echo",
        json!({"fleet_host": "web1", "text": "hello"}),
    )
    .await;
    let record = &w.machine("web1").audited("tool_call")[0];
    assert_eq!(record["principal"], "walt");
    assert_eq!(record["tool"], "echo");
    // the argument that named the host is the fleet's, not the tool's
    assert_eq!(record["args"], json!({"text": "hello"}));
    assert_eq!(record["via"]["gateway"], "bastion1");
    assert_eq!(record["via"]["caller"], "walt");
    // and the fleet's own trail has the same call id, so the two can be joined
    let ours = &w.audited("fleet_call")[0];
    assert_eq!(record["via"]["call"], ours["call"]);
    assert_eq!(ours["principal"], "walt");
    assert_eq!(ours["host"], "web1");
    assert_eq!(ours["tool"], "echo");
    assert_eq!(ours["rule"], "ops-own");
    assert_eq!(ours["over"], "ssh");
    assert_eq!(ours["identity"], "caller");
    assert_eq!(ours["decision"], "allow");
    assert_eq!(ours["roles"], json!(["ops"]));
    assert_eq!(ours["args"], json!({"fleet_host": "web1", "text": "hello"}));
    let result = &w.audited("fleet_result")[0];
    assert_eq!(result["call"], ours["call"]);
    assert_eq!(result["host"], "web1");
    assert_eq!(result["outcome"], "ok");
}

#[tokio::test]
async fn a_change_happens_on_the_one_host_named() {
    let w = world();
    let (text, is_error) = w
        .call(
            "walt",
            "touch",
            json!({"fleet_host": "web2", "name": "alpha7"}),
        )
        .await;
    assert_eq!((text.as_str(), is_error), ("touched alpha7", false));
    assert_eq!(w.machine("web2").touched(), ["alpha7"]);
    for other in ["web1", "web3", "db1", "db2"] {
        assert!(w.machine(other).touched().is_empty(), "{other}");
    }
    assert_eq!(w.dialer.dials().len(), 1);
}

#[tokio::test]
async fn the_host_has_the_last_word_on_what_its_own_account_may_do() {
    let w = world();
    // the fleet lets walt (ops, @all) through; web1 only lets its walt touch alpha*
    let (text, is_error) = w
        .call(
            "walt",
            "touch",
            json!({"fleet_host": "web1", "name": "beta"}),
        )
        .await;
    assert!(is_error);
    assert!(
        text.contains("Permission denied") && text.contains("walt"),
        "{text}"
    );
    assert!(w.machine("web1").touched().is_empty());
    assert_eq!(w.audited("fleet_result")[0]["outcome"], "failed");
}

#[tokio::test]
async fn a_tool_the_rules_role_does_not_grant_is_refused_here_and_never_sent() {
    let w = world();
    // dora is dba: test.view and two custom tools, no test.modify
    let (text, is_error) = w
        .call(
            "dora",
            "touch",
            json!({"fleet_host": "db1", "name": "alpha1"}),
        )
        .await;
    assert!(is_error);
    assert!(
        text.contains("refused") && text.contains("test.modify") && text.contains("dba"),
        "{text}"
    );
    assert!(w.nothing_sent());
    let record = &w.audited("fleet_call")[0];
    assert_eq!(record["decision"], "deny");
    assert_eq!(record["host"], "db1");
    assert!(
        record["reason"].as_str().unwrap().contains("test.modify"),
        "{record}"
    );
    assert_eq!(w.audited("fleet_result")[0]["outcome"], "denied");
}

#[tokio::test]
async fn a_read_only_rule_refuses_changes_and_tells_the_host_to_refuse_them_too() {
    let w = world();
    // rita's role is @read, so a change is refused by the role already; make sure of the
    // rule itself with a caller whose role would allow it
    let config = FLEET_CONFIG.replace(
        "[roles.dev]\nallow = [\"@read\"]",
        "[roles.dev]\nallow = [\"@all\"]",
    );
    let w2 = world_with(&config, INVENTORY, None, HashMap::new());
    let (text, is_error) = w2
        .call(
            "rita",
            "touch",
            json!({"fleet_host": "web1", "name": "alpha1"}),
        )
        .await;
    assert!(is_error && text.contains("read-only"), "{text}");
    assert!(w2.nothing_sent());
    // a read through the rule goes out marked read-only, as the fleet's own account
    let (text, is_error) = w
        .call("rita", "echo", json!({"fleet_host": "web1", "text": "x"}))
        .await;
    assert_eq!((text.as_str(), is_error), ("x", false));
    assert_eq!(w.dialer.dials(), [("web1".to_string(), "rita".to_string())]);
    let record = &w.machine("web1").audited("tool_call")[0];
    assert_eq!(record["read_only"], true);
    assert_eq!(record["via"]["caller"], "rita");
    let ours = &w.audited("fleet_call")[0];
    assert_eq!(
        (ours["rule"].as_str(), ours["identity"].as_str()),
        (Some("dev-web"), Some("fleet"))
    );
}

#[tokio::test]
async fn a_read_only_session_refuses_changes_through_any_rule() {
    let w = world();
    let mut session = w.session("walt");
    session.read_only = true;
    let (text, is_error) = w
        .call_as(
            &session,
            "touch",
            json!({"fleet_host": "web1", "name": "alpha1"}),
        )
        .await;
    assert!(is_error && text.contains("read-only"), "{text}");
    assert!(w.nothing_sent());
    // reads go out marked read-only
    w.call_as(&session, "echo", json!({"fleet_host": "web1", "text": "x"}))
        .await;
    assert_eq!(w.machine("web1").audited("tool_call")[0]["read_only"], true);
    // without the flag nothing of the kind is said to the host
    w.call("walt", "echo", json!({"fleet_host": "web2", "text": "x"}))
        .await;
    assert!(
        w.machine("web2").audited("tool_call")[0]
            .get("read_only")
            .is_none()
    );
}

#[tokio::test]
async fn only_the_roles_of_the_rule_that_matched_count() {
    let w = world();
    // "both" is dev and ops. On the web hosts the dev rule comes first: reached as the
    // read-only account, and being ops as well adds nothing there.
    let (text, is_error) = w
        .call(
            "both",
            "touch",
            json!({"fleet_host": "web1", "name": "alpha1"}),
        )
        .await;
    assert!(is_error && text.contains("refused"), "{text}");
    assert!(w.nothing_sent());
    // on a database host only the ops rule covers them: there they are ops, as themselves
    // (db1 has no account of that name, which is the host's business, not the rule's)
    w.call(
        "both",
        "touch",
        json!({"fleet_host": "db1", "name": "alpha1"}),
    )
    .await;
    let record = w.audited("fleet_call").last().unwrap().clone();
    assert_eq!(record["host"], "db1");
    assert_eq!(record["rule"], "ops-own");
    assert_eq!(record["identity"], "caller");
    assert_eq!(record["roles"], json!(["ops"]));
    assert_eq!(record["decision"], "allow");
}

#[tokio::test]
async fn a_host_outside_the_callers_rules_looks_like_one_that_does_not_exist() {
    let w = world();
    // rita's rule covers the web group only
    let (hidden, _) = w
        .call("rita", "echo", json!({"fleet_host": "db1", "text": "x"}))
        .await;
    let (missing, _) = w
        .call("rita", "echo", json!({"fleet_host": "db9", "text": "x"}))
        .await;
    assert_eq!(
        hidden.replace("db1", "HOST"),
        missing.replace("db9", "HOST")
    );
    assert!(hidden.contains("no host you can reach"), "{hidden}");
    assert!(w.nothing_sent());
    // the attempt is on record
    let records = w.audited("fleet_result");
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["outcome"], "invalid");
    assert_eq!(records[0]["principal"], "rita");
    assert_eq!(records[0]["args"]["fleet_host"], "db1");
}

#[tokio::test]
async fn the_host_argument_only_ever_picks_from_the_inventory() {
    let w = world();
    for bad in [
        json!("-oProxyCommand=id"),
        json!("web1; id"),
        json!("root@web1"),
        json!("10.0.0.1"),
        json!(""),
        json!(7),
        json!(["web1"]),
        Value::Null,
    ] {
        let (text, is_error) = w
            .call("adam", "echo", json!({"fleet_host": bad, "text": "x"}))
            .await;
        assert!(is_error, "{bad}: {text}");
    }
    let (text, is_error) = w.call("adam", "echo", json!({"text": "x"})).await;
    assert!(is_error && text.contains("fleet_host"), "{text}");
    assert!(w.nothing_sent());
}

#[tokio::test]
async fn arguments_are_checked_before_anything_is_sent() {
    let w = world();
    for arguments in [
        json!({"fleet_host": "web1"}),
        json!({"fleet_host": "web1", "text": 5}),
        json!({"fleet_host": "web1", "text": "x", "surprise": true}),
        json!({"fleet_host": "web1", "text": "line\nbreak"}),
    ] {
        let (text, is_error) = w.call("adam", "echo", arguments.clone()).await;
        assert!(
            is_error && text.contains("Invalid arguments"),
            "{arguments}: {text}"
        );
    }
    assert!(w.nothing_sent());
    // a tool nobody has is a protocol error, as it is on a host
    let params = json!({"name": "no_such_tool", "arguments": {"fleet_host": "web1"}});
    let error = w
        .fleet
        .call_tool(&w.session("adam"), Some(&params))
        .await
        .unwrap_err();
    assert_eq!(error.0, -32602);
}

#[tokio::test]
async fn nothing_is_sent_when_the_decision_cannot_be_audited() {
    let w = world();
    w.audit.set_failing(true);
    let (text, is_error) = w
        .call(
            "walt",
            "touch",
            json!({"fleet_host": "web1", "name": "alpha1"}),
        )
        .await;
    assert!(is_error && text.contains("audit"), "{text}");
    assert!(w.nothing_sent());
    assert!(w.machine("web1").touched().is_empty());
}

#[tokio::test]
async fn a_change_whose_arguments_cannot_be_recorded_in_full_is_not_sent() {
    let w = world();
    let tags: Vec<String> = (0..60).map(|n| format!("{n:0>80}")).collect();
    let (text, is_error) = w
        .call(
            "walt",
            "touch",
            json!({"fleet_host": "web1", "name": "alpha1", "tags": tags}),
        )
        .await;
    assert!(is_error && text.contains("audit"), "{text}");
    assert!(w.nothing_sent());
}

// ---- several hosts ----

#[tokio::test]
async fn a_read_can_be_sent_to_a_group_and_the_answers_come_back_together() {
    let w = world();
    let (text, is_error) = w
        .call(
            "adam",
            "echo",
            json!({"fleet_host": "group:web", "text": "same"}),
        )
        .await;
    assert!(!is_error);
    assert!(text.starts_with("3 hosts asked: 3 answered."), "{text}");
    assert!(
        text.contains("== web1, web2, web3 (3 hosts, same answer) ==\n| same\n"),
        "{text}"
    );
    for host in ["web1", "web2", "web3"] {
        assert_eq!(w.dialer.dials_to(host), 1, "{host}");
        // a call that names several hosts goes out read-only
        assert_eq!(
            w.machine(host).audited("tool_call")[0]["read_only"],
            true,
            "{host}"
        );
    }
    assert_eq!(w.dialer.dials_to("db1"), 0);
    // one decision and one result per host, under one call id
    let calls = w.audited("fleet_call");
    assert_eq!(calls.len(), 3);
    assert!(calls.iter().all(|c| c["call"] == calls[0]["call"]));
    assert_eq!(w.audited("fleet_result").len(), 3);
}

#[tokio::test]
async fn a_change_is_never_sent_to_more_than_one_host() {
    let w = world();
    for selector in ["group:web", "web1,web2", "web*"] {
        let (text, is_error) = w
            .call(
                "adam",
                "touch",
                json!({"fleet_host": selector, "name": "alpha1"}),
            )
            .await;
        assert!(is_error && text.contains("one host"), "{selector}: {text}");
    }
    assert!(w.nothing_sent());
    // a selector that comes down to one host is one host
    let (_, is_error) = w
        .call(
            "walt",
            "touch",
            json!({"fleet_host": "web1,web1", "name": "alpha1"}),
        )
        .await;
    assert!(!is_error);
    assert_eq!(w.machine("web1").touched(), ["alpha1"]);
}

#[tokio::test]
async fn more_hosts_than_one_call_may_name_is_refused_with_the_count() {
    let w = world();
    let (text, is_error) = w
        .call("adam", "echo", json!({"fleet_host": "*", "text": "x"}))
        .await;
    assert!(is_error);
    assert!(text.contains('5') && text.contains('4'), "{text}");
    assert!(w.nothing_sent());
}

#[tokio::test]
async fn hosts_that_do_not_answer_are_reported_beside_those_that_do() {
    let w = world();
    w.dialer.down.lock().unwrap().insert("web2".to_string());
    let (text, is_error) = w
        .call(
            "adam",
            "echo",
            json!({"fleet_host": "group:web", "text": "up"}),
        )
        .await;
    assert!(!is_error);
    assert!(
        text.starts_with("3 hosts asked: 2 answered, 1 gave no answer."),
        "{text}"
    );
    assert!(
        text.contains("web2: could not be reached:") && text.contains("No route to host"),
        "{text}"
    );
    assert!(
        text.contains("== web1, web3 (2 hosts, same answer) =="),
        "{text}"
    );
    let outcomes: Vec<(String, String)> = w
        .audited("fleet_result")
        .iter()
        .map(|r| {
            (
                r["host"].as_str().unwrap().to_string(),
                r["outcome"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert!(
        outcomes.contains(&("web2".to_string(), "unreachable".to_string())),
        "{outcomes:?}"
    );
}

#[tokio::test]
async fn each_hosts_own_rule_decides_within_one_call() {
    // "both" on the web group: the dev rule (the fleet's read-only account). The call is
    // a read, so it goes; and each host was reached as rita, not as the caller.
    let w = world();
    let (text, is_error) = w
        .call(
            "both",
            "echo",
            json!({"fleet_host": "web1,web2", "text": "x"}),
        )
        .await;
    assert!(!is_error, "{text}");
    let mut dials = w.dialer.dials();
    dials.sort();
    assert_eq!(
        dials,
        [
            ("web1".to_string(), "rita".to_string()),
            ("web2".to_string(), "rita".to_string())
        ]
    );
}

#[tokio::test]
async fn text_from_one_host_cannot_pass_for_another_hosts_answer() {
    let w = world();
    // `raw` answers with an escape sequence, as a hostile log line might
    let (text, _) = w
        .call("adam", "raw", json!({"fleet_host": "web1,web2"}))
        .await;
    // every line a host sent is marked as host text; the escape sequence is made visible
    assert!(text.contains("| a\\x1b[2Jb"), "{text:?}");
    assert!(!text.contains('\u{1b}'));
}

// ---- when hosts misbehave ----

#[tokio::test]
async fn a_host_that_cannot_be_reached_is_reported_and_then_left_alone() {
    let w = world();
    w.dialer.down.lock().unwrap().insert("web1".to_string());
    let (text, is_error) = w
        .call("adam", "echo", json!({"fleet_host": "web1", "text": "x"}))
        .await;
    assert!(is_error);
    assert!(
        text.starts_with("web1: could not be reached:") && text.contains("No route to host"),
        "{text}"
    );
    assert_eq!(w.audited("fleet_result")[0]["outcome"], "unreachable");
    // it comes back; it is still left alone until the pause is over, and the answer says so
    w.dialer.down.lock().unwrap().clear();
    let (text, is_error) = w
        .call("adam", "echo", json!({"fleet_host": "web1", "text": "x"}))
        .await;
    assert!(is_error && text.contains("not tried again"), "{text}");
    assert_eq!(w.dialer.dials_to("web1"), 0);
    // another caller's identity has its own memory: rita's rule reaches web1 as someone else
    let (text, is_error) = w
        .call("rita", "echo", json!({"fleet_host": "web1", "text": "x"}))
        .await;
    assert_eq!((text.as_str(), is_error), ("x", false));
}

#[tokio::test]
async fn an_account_the_host_does_not_know_is_refused_by_the_host_and_nothing_else_is_tried() {
    let w = world();
    // "both" is ops here, but db1 has no account of that name: no role there
    let (text, is_error) = w
        .call("both", "echo", json!({"fleet_host": "db1", "text": "x"}))
        .await;
    assert!(is_error);
    assert!(
        text.contains("could not be reached") && text.contains("has no role"),
        "{text}"
    );
    // no other rule and no other identity was tried in its place
    assert!(w.nothing_sent());
    assert_eq!(w.audited("fleet_call").len(), 1);
}

/// Waits until `what` is true, for at most a few seconds.
async fn eventually(what: impl Fn() -> bool) {
    for _ in 0..400 {
        if what() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the condition never became true");
}

#[tokio::test]
async fn a_read_interrupted_by_a_lost_connection_is_asked_once_more() {
    let w = world();
    let asking = {
        let (fleet, session) = (w.fleet.clone(), w.session("adam"));
        tokio::spawn(async move {
            let params = json!({"name": "gate", "arguments": {"fleet_host": "web1"}});
            fleet.call_tool(&session, Some(&params)).await.unwrap()
        })
    };
    // gate takes a second; cut the connection once it is certainly running on the host
    let active = || {
        w.machine("web1")
            .effects
            .active
            .load(std::sync::atomic::Ordering::SeqCst)
    };
    eventually(|| active() == 1).await;
    w.dialer.cut("web1");
    let result = asking.await.unwrap();
    assert_eq!(result["content"][0]["text"], "through");
    assert_eq!(result["isError"], false);
    // it was sent, the connection was lost, and it was sent once more on a new one
    assert_eq!(w.dialer.dials_to("web1"), 2);
    assert_eq!(w.machine("web1").audited("tool_call").len(), 2);
}

#[tokio::test]
async fn a_change_interrupted_by_a_lost_connection_is_not_sent_again() {
    let w = world();
    let asking = {
        let (fleet, session) = (w.fleet.clone(), w.session("adam"));
        tokio::spawn(async move {
            let params = json!({"name": "fleet_call", "arguments":
                {"fleet_host": "web1", "tool": "slow_touch", "arguments": {"name": "alpha1"}}});
            fleet.call_tool(&session, Some(&params)).await.unwrap()
        })
    };
    // the tool records the name, then takes a second: cut once it has certainly started
    eventually(|| w.machine("web1").touched() == ["alpha1"]).await;
    w.dialer.cut("web1");
    let result = asking.await.unwrap();
    assert_eq!(result["isError"], true);
    let text = result["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("connection") && text.contains("may have run"),
        "{text}"
    );
    // it ran once, and was not sent a second time
    assert_eq!(w.machine("web1").touched(), ["alpha1"]);
    assert_eq!(w.dialer.dials_to("web1"), 1);
    assert_eq!(w.audited("fleet_result").last().unwrap()["outcome"], "lost");
}

#[tokio::test]
async fn a_request_too_long_for_the_host_fails_at_once_and_is_not_said_to_have_run() {
    let w = world();
    // the fleet takes this; the machines read at most 4096 bytes
    let padding: Vec<String> = (0..40).map(|n| format!("{n:0>200}")).collect();
    let started = std::time::Instant::now();
    let (text, is_error) = w
        .call(
            "adam",
            "echo",
            json!({"fleet_host": "web1", "text": "x", "extra": padding}),
        )
        .await;
    assert!(is_error);
    // the host's own words about it, well inside the two seconds a call may take
    assert!(text.contains("4096"), "{text}");
    assert!(
        !text.contains("may have run") && !text.contains("in time"),
        "{text}"
    );
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(
        w.audited("fleet_result").last().unwrap()["outcome"],
        "failed"
    );
    assert!(w.machine("web1").audited("tool_call").is_empty());
    // the session is still good for the next call
    let (text, is_error) = w
        .call("adam", "echo", json!({"fleet_host": "web1", "text": "y"}))
        .await;
    assert_eq!((text.as_str(), is_error), ("y", false));
    assert_eq!(w.dialer.dials_to("web1"), 1);
}

#[tokio::test]
async fn an_answer_too_long_for_the_fleet_is_reported_and_the_tool_is_not_run_again() {
    let w = world();
    // `big` answers with about two thousand bytes; accept fewer than that here
    w.dialer
        .max_line
        .store(512, std::sync::atomic::Ordering::SeqCst);
    let (text, is_error) = w.call("adam", "big", json!({"fleet_host": "web1"})).await;
    assert!(is_error);
    assert!(
        text.contains("larger than") && text.contains("may have run"),
        "{text}"
    );
    // a read is normally asked once more when its connection ends; not for this, which
    // would only make the host do the work twice for the same result
    let ran = || w.machine("web1").audited("tool_call").len();
    eventually(|| ran() >= 1).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(ran(), 1);
    assert_eq!(w.dialer.dials_to("web1"), 1);
}

#[tokio::test]
async fn a_host_that_takes_too_long_is_given_up_on_and_told_to_stop() {
    let w = world();
    let started = std::time::Instant::now();
    let (text, is_error) = w.call("adam", "slow", json!({"fleet_host": "web1"})).await;
    assert!(is_error);
    assert!(
        text.contains("did not answer in time") && text.contains("may have run"),
        "{text}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(w.audited("fleet_result")[0]["outcome"], "timeout");
    // the host was told to stop, and says so in its own trail
    let mut outcome = None;
    for _ in 0..100 {
        if let Some(record) = w.machine("web1").audited("tool_result").first() {
            outcome = Some(record["outcome"].clone());
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(outcome, Some(json!("cancelled")));
}

#[tokio::test]
async fn a_caller_who_gives_up_stops_the_call_on_the_host() {
    let w = world();
    let asking = {
        let (fleet, session) = (w.fleet.clone(), w.session("adam"));
        tokio::spawn(async move {
            let params = json!({"name": "slow", "arguments": {"fleet_host": "web1"}});
            let _ = fleet.call_tool(&session, Some(&params)).await;
        })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    asking.abort();
    let mut outcome = None;
    for _ in 0..100 {
        if let Some(record) = w.machine("web1").audited("tool_result").first() {
            outcome = Some(record["outcome"].clone());
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(outcome, Some(json!("cancelled")));
    // and our own trail says how the call ended
    let ours = w.audited("fleet_result");
    assert_eq!(ours.last().unwrap()["outcome"], "cancelled");
}

#[tokio::test]
async fn sessions_to_hosts_are_reused_between_calls() {
    let w = world();
    for n in 0..5 {
        w.call(
            "adam",
            "echo",
            json!({"fleet_host": "web1", "text": format!("{n}")}),
        )
        .await;
    }
    assert_eq!(w.dialer.dials_to("web1"), 1);
    // another caller's own identity is another session
    w.call("walt", "echo", json!({"fleet_host": "web1", "text": "x"}))
        .await;
    assert_eq!(
        w.dialer.dials(),
        [
            ("web1".to_string(), "adam".to_string()),
            ("web1".to_string(), "walt".to_string())
        ]
    );
    // callers of a rule with the fleet's identity share its session
    w.fleet.shutdown().await;
}

// ---- tools the fleet does not know: an operator's custom tools ----

#[tokio::test]
async fn fleet_tools_shows_what_a_host_offers_the_identity_it_is_reached_as() {
    let w = world();
    let (text, is_error) = w
        .call("adam", "fleet_tools", json!({"fleet_host": "db1"}))
        .await;
    assert!(!is_error, "{text}");
    assert!(
        text.contains("galera_status") && text.contains("failover") && text.contains("slow_touch"),
        "{text}"
    );
    assert!(
        text.contains("Shows the state of the Galera cluster."),
        "{text}"
    );
    assert!(text.contains("node"), "{text}");
    // a description is one line of host text, whatever the host put in it
    assert!(!text.contains("\nSecond line."), "{text}");
    // what the fleet knows by name is listed by name only
    assert!(text.contains("echo"), "{text}");
    // through a read-only rule, only what changes nothing
    let (text, _) = w
        .call("rita", "fleet_tools", json!({"fleet_host": "web1"}))
        .await;
    assert!(
        text.contains("galera_status") && !text.contains("failover"),
        "{text}"
    );
    // it is for one host
    let (text, is_error) = w
        .call("adam", "fleet_tools", json!({"fleet_host": "group:web"}))
        .await;
    assert!(is_error && text.contains("one host"), "{text}");
}

#[tokio::test]
async fn what_a_host_says_about_its_own_tools_is_marked_as_its_text() {
    let w = world();
    let (text, _) = w
        .call("adam", "fleet_tools", json!({"fleet_host": "db1"}))
        .await;
    for line in text.lines() {
        if line.contains("Shows the state of the Galera cluster") || line.contains("Which node") {
            assert!(line.starts_with("| "), "{line}");
        }
    }
    // the names, which this server has checked are plain names, are on its own lines
    assert!(
        text.lines().any(|l| l.starts_with("galera_status")),
        "{text}"
    );
}

#[tokio::test]
async fn asking_a_host_what_it_offers_is_decided_and_recorded_before_it_is_contacted() {
    let w = world();
    w.call("adam", "fleet_tools", json!({"fleet_host": "db1"}))
        .await;
    let records = w.audited("fleet_call");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["tool"], "fleet_tools");
    assert_eq!(records[0]["host"], "db1");
    assert_eq!(records[0]["decision"], "allow");
    assert_eq!(records[0]["rule"], "ops-own");

    // with the audit trail unavailable, no host is contacted: not for the listing, and
    // not for the look a call to a host's own tool begins with
    let w = world();
    w.audit.set_failing(true);
    let (text, is_error) = w
        .call("adam", "fleet_tools", json!({"fleet_host": "db1"}))
        .await;
    assert!(is_error && text.contains("audit"), "{text}");
    let (text, is_error) = w
        .call(
            "adam",
            "fleet_call",
            json!({"fleet_host": "db1", "tool": "galera_status"}),
        )
        .await;
    assert!(is_error && text.contains("audit"), "{text}");
    assert!(w.nothing_sent());
}

#[tokio::test]
async fn a_caller_whose_roles_grant_nothing_cannot_make_the_fleet_contact_a_host() {
    let w = world();
    // nell has a rule for the web hosts, and a role that allows nothing
    assert!(w.tool_names("nell").is_empty());
    let (text, is_error) = w
        .call("nell", "fleet_tools", json!({"fleet_host": "web1"}))
        .await;
    assert!(is_error && text.contains("refused"), "{text}");
    let (text, is_error) = w
        .call(
            "nell",
            "fleet_call",
            json!({"fleet_host": "web1", "tool": "galera_status"}),
        )
        .await;
    assert!(is_error && text.contains("refused"), "{text}");
    let (text, is_error) = w
        .call("nell", "echo", json!({"fleet_host": "web1", "text": "x"}))
        .await;
    assert!(is_error && text.contains("refused"), "{text}");
    assert!(w.nothing_sent());
    // a caller with grants, but none for this tool, does not get a look either
    let (text, is_error) = w
        .call(
            "dora",
            "fleet_call",
            json!({"fleet_host": "db1", "tool": "slow_touch", "arguments": {"name": "alpha1"}}),
        )
        .await;
    assert!(is_error && text.contains("custom.slow_touch"), "{text}");
    assert!(w.nothing_sent());
}

#[tokio::test]
async fn a_tool_only_the_host_knows_is_called_through_fleet_call() {
    let w = world();
    let (text, is_error) = w
        .call(
            "adam",
            "fleet_call",
            json!({"fleet_host": "db1", "tool": "galera_status", "arguments": {"node": "db2"}}),
        )
        .await;
    assert_eq!((text.as_str(), is_error), ("synced (db2)", false));
    let ours = w.audited("fleet_call");
    let ours = ours.last().unwrap();
    assert_eq!(ours["tool"], "galera_status");
    assert_eq!(ours["permission"], "custom.galera_status");
    assert_eq!(ours["access"], "read");
    // a change through it
    let (text, is_error) = w
        .call(
            "adam",
            "fleet_call",
            json!({"fleet_host": "db1", "tool": "failover"}),
        )
        .await;
    assert_eq!((text.as_str(), is_error), ("moved", false));
    assert_eq!(w.machine("db1").touched(), ["failover"]);
    assert_eq!(w.audited("fleet_call").last().unwrap()["access"], "write");
}

#[tokio::test]
async fn a_custom_tool_needs_a_grant_here_like_any_other() {
    let w = world();
    // dora (dba) is granted custom.failover and custom.galera_status by name
    let (text, is_error) = w
        .call(
            "dora",
            "fleet_call",
            json!({"fleet_host": "db1", "tool": "failover"}),
        )
        .await;
    assert_eq!((text.as_str(), is_error), ("moved", false));
    // and not custom.slow_touch
    let (text, is_error) = w
        .call(
            "dora",
            "fleet_call",
            json!({"fleet_host": "db1", "tool": "slow_touch", "arguments": {"name": "alpha1"}}),
        )
        .await;
    assert!(is_error && text.contains("custom.slow_touch"), "{text}");
    assert_eq!(w.machine("db1").touched(), ["failover"]);
    // rita (@read, read-only rule) may use the one that reads, not the one that changes
    let (text, is_error) = w
        .call(
            "rita",
            "fleet_call",
            json!({"fleet_host": "web1", "tool": "galera_status"}),
        )
        .await;
    assert_eq!((text.as_str(), is_error), ("synced (all)", false));
    let (text, is_error) = w
        .call(
            "rita",
            "fleet_call",
            json!({"fleet_host": "web1", "tool": "failover"}),
        )
        .await;
    assert!(is_error, "{text}");
    assert!(w.machine("web1").touched().is_empty());
}

#[tokio::test]
async fn fleet_call_holds_a_known_tool_to_the_same_checks_as_calling_it_by_name() {
    let w = world();
    let (text, is_error) = w
        .call(
            "adam",
            "fleet_call",
            json!({"fleet_host": "web1", "tool": "echo", "arguments": {"text": "x"}}),
        )
        .await;
    assert_eq!((text.as_str(), is_error), ("x", false));
    // arguments are checked here, a change goes to one host, the role must grant it
    let (text, is_error) = w
        .call(
            "adam",
            "fleet_call",
            json!({"fleet_host": "web1", "tool": "echo"}),
        )
        .await;
    assert!(is_error && text.contains("Invalid arguments"), "{text}");
    let (text, is_error) = w
        .call(
            "adam",
            "fleet_call",
            json!({"fleet_host": "group:web", "tool": "touch", "arguments": {"name": "alpha1"}}),
        )
        .await;
    assert!(is_error && text.contains("one host"), "{text}");
    let (text, is_error) = w
        .call(
            "dora",
            "fleet_call",
            json!({"fleet_host": "db1", "tool": "touch", "arguments": {"name": "alpha1"}}),
        )
        .await;
    assert!(is_error && text.contains("test.modify"), "{text}");
    for bad in [
        json!("no such"),
        json!("Echo"),
        json!("fleet_call"),
        json!("fleet_hosts"),
        json!(""),
        json!(5),
    ] {
        let (text, is_error) = w
            .call(
                "adam",
                "fleet_call",
                json!({"fleet_host": "web1", "tool": bad}),
            )
            .await;
        assert!(is_error, "{bad}: {text}");
    }
}

#[tokio::test]
async fn a_custom_tool_sent_to_several_hosts_can_only_read() {
    let w = world();
    let (text, is_error) = w
        .call(
            "adam",
            "fleet_call",
            json!({"fleet_host": "group:db", "tool": "galera_status"}),
        )
        .await;
    assert!(!is_error, "{text}");
    assert!(
        text.contains("== db1, db2 (2 hosts, same answer) ==\n| synced (all)\n"),
        "{text}"
    );
    let (text, is_error) = w
        .call(
            "adam",
            "fleet_call",
            json!({"fleet_host": "group:db", "tool": "failover"}),
        )
        .await;
    assert!(is_error, "{text}");
    assert!(text.contains("one host"), "{text}");
    for host in ["db1", "db2"] {
        assert!(w.machine(host).touched().is_empty(), "{host}");
    }
}

#[tokio::test]
async fn a_tool_the_host_does_not_offer_is_said_to_be_missing_there() {
    let w = world();
    let (text, is_error) = w
        .call(
            "adam",
            "fleet_call",
            json!({"fleet_host": "web1", "tool": "nothing_here"}),
        )
        .await;
    assert!(is_error);
    assert!(
        text.contains("web1") && text.contains("nothing_here") && text.contains("fleet_tools"),
        "{text}"
    );
}

// ---- the inventory read again while the server runs ----

fn inventory_of(text: &str) -> Inventory {
    Inventory::parse(text, Format::Toml).unwrap()
}

const WITHOUT_WEB3: &str = "[groups]\nweb = [\"web1\", \"web2\"]\ndb = [\"db1\", \"db2\"]\n";
const WEB1_MOVED: &str = "[hosts.web1]\naddress = \"10.0.0.99\"\ngroups = [\"web\"]\n\
                          [groups]\nweb = [\"web2\", \"web3\"]\ndb = [\"db1\", \"db2\"]\n";

async fn echo(w: &World, host: &str) -> (String, bool) {
    w.call("adam", "echo", json!({"fleet_host": host, "text": "hi"}))
        .await
}

#[tokio::test]
async fn a_host_dropped_from_the_inventory_is_gone_and_one_added_can_be_called() {
    let w = world();
    let (text, is_error) = echo(&w, "web3").await;
    assert!(!is_error, "{text}");

    let changes = w
        .fleet
        .replace_inventory(inventory_of(WITHOUT_WEB3))
        .unwrap();
    assert_eq!(changes.removed, ["web3"]);
    let (text, is_error) = echo(&w, "web3").await;
    assert!(
        is_error && text.contains("no host you can reach matches"),
        "{text}"
    );
    let (text, _) = w.call("adam", "fleet_hosts", json!({})).await;
    assert!(text.contains("4 hosts") && !text.contains("web3"), "{text}");
    // a call for a group reaches the hosts that are in it now
    let (text, is_error) = echo(&w, "group:web").await;
    assert!(!is_error && text.contains("2 hosts asked"), "{text}");

    let changes = w.fleet.replace_inventory(inventory_of(INVENTORY)).unwrap();
    assert_eq!(changes.added, ["web3"]);
    let (text, is_error) = echo(&w, "web3").await;
    assert!(!is_error, "{text}");
}

#[tokio::test]
async fn a_host_that_moved_is_reached_afresh_and_the_others_keep_their_sessions() {
    let w = world();
    for host in ["web1", "web2"] {
        assert!(!echo(&w, host).await.1);
    }
    assert_eq!(
        (w.dialer.dials_to("web1"), w.dialer.dials_to("web2")),
        (1, 1)
    );
    let changes = w.fleet.replace_inventory(inventory_of(WEB1_MOVED)).unwrap();
    assert_eq!(changes.moved, ["web1"]);
    for host in ["web1", "web2"] {
        assert!(!echo(&w, host).await.1);
    }
    // AIDEV-NOTE: the session that was open to where web1 used to be is to another
    // machine now, as far as anyone knows. It must not carry a call meant for web1.
    assert_eq!(
        (w.dialer.dials_to("web1"), w.dialer.dials_to("web2")),
        (2, 1)
    );
}

#[tokio::test]
async fn a_host_that_was_not_answering_is_tried_at_once_where_it_moved_to() {
    let w = world();
    w.dialer.down.lock().unwrap().insert("web1".to_string());
    let (text, is_error) = echo(&w, "web1").await;
    assert!(is_error && text.contains("No route to host"), "{text}");
    // still left alone, as any host that did not answer is for a while
    w.dialer.down.lock().unwrap().clear();
    let (text, is_error) = echo(&w, "web1").await;
    assert!(is_error && text.contains("not tried again"), "{text}");

    w.fleet.replace_inventory(inventory_of(WEB1_MOVED)).unwrap();
    let (text, is_error) = echo(&w, "web1").await;
    assert!(!is_error, "{text}");
}

#[tokio::test]
async fn a_change_of_inventory_is_on_record_with_the_addresses() {
    let w = world();
    let both = "[hosts.web1]\naddress = \"10.0.0.99\"\nssh_port = 2222\ngroups = [\"web\"]\n\
                [hosts.cache1]\naddress = \"10.0.4.17\"\n\
                [groups]\nweb = [\"web2\"]\ndb = [\"db1\", \"db2\", \"web2\"]\n";
    w.fleet.replace_inventory(inventory_of(both)).unwrap();
    let records = w.audited("fleet_inventory");
    assert_eq!(records.len(), 1, "{records:?}");
    let record = &records[0];
    assert_eq!(record["outcome"], "replaced");
    assert_eq!(record["hosts"], 5);
    assert_eq!(
        record["added"],
        json!([{"host": "cache1", "at": "10.0.4.17", "groups": []}])
    );
    assert_eq!(record["removed"], json!(["web3"]));
    assert_eq!(
        record["moved"],
        json!([{"host": "web1", "from": "web1", "to": "10.0.0.99 ssh port 2222"}])
    );
    // AIDEV-NOTE: which groups a host is in decides which rule, and so which
    // credential, it is reached with. A host that joins a group is as much a change
    // to where credentials go as one that changes its address.
    assert_eq!(
        record["regrouped"],
        json!([{"host": "web2", "joined": ["db"], "left": []}])
    );

    // read again and found the same: nothing to record
    let changes = w.fleet.replace_inventory(inventory_of(both)).unwrap();
    assert!(changes.is_empty());
    assert_eq!(w.audited("fleet_inventory").len(), 1);
}

#[tokio::test]
async fn a_long_list_of_changes_is_recorded_in_part_with_its_size() {
    let w = world();
    let many: Vec<String> = (0..80).map(|n| format!("\"extra{n}\"")).collect();
    let text = format!(
        "[groups]\nweb = [\"web1\", \"web2\", \"web3\"]\ndb = [\"db1\", \"db2\"]\nextra = [{}]\n",
        many.join(", ")
    );
    w.fleet.replace_inventory(inventory_of(&text)).unwrap();
    let record = w.audited("fleet_inventory").pop().unwrap();
    assert_eq!(record["hosts"], 85);
    assert_eq!(record["added_count"], 80);
    // as many as fit in a record that any syslog takes whole
    let listed = record["added"].as_array().unwrap().len();
    assert!((20..80).contains(&listed), "{listed}");
    assert!(
        record.to_string().len() < 4000,
        "{}",
        record.to_string().len()
    );
    // the first of them, in name order, with the group it came in
    assert_eq!(
        record["added"][0],
        json!({"host": "extra0", "at": "extra0", "groups": ["extra"]})
    );
}

#[tokio::test]
async fn a_record_of_many_kinds_of_change_keeps_room_for_the_ones_that_matter_most() {
    // 400 hosts leave, which alone would fill the record, and one moves: where a host
    // went is listed before who left.
    let w = world();
    let many: Vec<String> = (0..400).map(|n| format!("\"extra{n}\"")).collect();
    let with_extra = format!(
        "[groups]\nweb = [\"web1\", \"web2\", \"web3\"]\ndb = [\"db1\", \"db2\"]\nextra = [{}]\n",
        many.join(", ")
    );
    w.fleet
        .replace_inventory(inventory_of(&with_extra))
        .unwrap();
    w.fleet.replace_inventory(inventory_of(WEB1_MOVED)).unwrap();
    let record = w.audited("fleet_inventory").pop().unwrap();
    assert_eq!(record["removed_count"], 400);
    assert!(record["removed"].as_array().unwrap().len() < 400);
    assert_eq!(
        record["moved"],
        json!([{"host": "web1", "from": "web1", "to": "10.0.0.99"}])
    );
    assert!(
        record.to_string().len() < 4000,
        "{}",
        record.to_string().len()
    );
}

#[tokio::test]
async fn an_inventory_is_not_replaced_when_that_cannot_be_recorded() {
    let w = world();
    w.audit.set_failing(true);
    let problem = w
        .fleet
        .replace_inventory(inventory_of(WITHOUT_WEB3))
        .unwrap_err();
    assert!(problem.contains("audit"), "{problem}");
    w.audit.set_failing(false);
    // the hosts are the ones from before
    let (text, is_error) = echo(&w, "web3").await;
    assert!(!is_error, "{text}");
}

#[tokio::test]
async fn fleet_hosts_says_when_its_list_could_not_be_read_again() {
    let w = world();
    let (text, _) = w.call("adam", "fleet_hosts", json!({})).await;
    assert!(!text.contains("read again"), "{text}");

    w.fleet.inventory_not_read(
        "fleet.inventory_command failed (exit status 3): cannot reach the CMDB",
    );
    let (text, is_error) = w.call("adam", "fleet_hosts", json!({})).await;
    assert!(!is_error);
    assert!(text.contains("could not be read again"), "{text}");
    // the hosts known are still listed and can still be called
    assert!(text.contains("5 hosts") && text.contains("web1"), "{text}");
    assert!(!echo(&w, "web1").await.1);
    // why it failed is for whoever runs the server: it is in the audit trail (and the
    // log), and is not shown to the agent
    assert!(!text.contains("CMDB"), "{text}");
    let record = w.audited("fleet_inventory").pop().unwrap();
    assert_eq!(record["outcome"], "failed");
    assert_eq!(record["hosts"], 5);
    assert!(record["reason"].as_str().unwrap().contains("CMDB"));

    // read again, even with nothing different in it: the note goes, and that is on record
    let changes = w.fleet.replace_inventory(inventory_of(INVENTORY)).unwrap();
    assert!(changes.is_empty());
    let (text, _) = w.call("adam", "fleet_hosts", json!({})).await;
    assert!(!text.contains("read again"), "{text}");
    let record = w.audited("fleet_inventory").pop().unwrap();
    assert_eq!(record["outcome"], "unchanged");
}

// ---- the inventory tool ----

#[tokio::test]
async fn fleet_hosts_lists_the_hosts_a_caller_can_reach_and_how() {
    let w = world();
    let (text, is_error) = w.call("adam", "fleet_hosts", json!({})).await;
    assert!(!is_error);
    assert!(text.contains("5 hosts"), "{text}");
    for host in ["web1", "web2", "web3", "db1", "db2"] {
        assert!(text.contains(host), "{host}: {text}");
    }
    assert!(
        text.contains("group:web") || text.contains("web (3)"),
        "{text}"
    );
    assert!(text.contains("ssh as you"), "{text}");
    // rita sees the web group only, and how she reaches it
    let (text, _) = w.call("rita", "fleet_hosts", json!({})).await;
    assert!(text.contains("3 hosts") && !text.contains("db1"), "{text}");
    assert!(
        text.contains("ssh as rita") && text.contains("read-only"),
        "{text}"
    );
    // a filter narrows it
    let (text, _) = w
        .call("adam", "fleet_hosts", json!({"filter": "group:db"}))
        .await;
    assert!(text.contains("db1") && !text.contains("web1"), "{text}");
    let (text, is_error) = w
        .call("rita", "fleet_hosts", json!({"filter": "group:db"}))
        .await;
    assert!(is_error && text.contains("no host you can reach"), "{text}");
    assert!(w.nothing_sent());
}

#[tokio::test]
async fn fleet_hosts_says_which_hosts_are_not_answering() {
    let w = world();
    w.dialer.down.lock().unwrap().insert("web2".to_string());
    w.call("adam", "echo", json!({"fleet_host": "web2", "text": "x"}))
        .await;
    let (text, _) = w.call("adam", "fleet_hosts", json!({})).await;
    let line = text.lines().find(|l| l.starts_with("web2")).unwrap();
    assert!(line.contains("not answering"), "{line}");
    let line = text.lines().find(|l| l.starts_with("web1")).unwrap();
    assert!(!line.contains("not answering"), "{line}");
    // why, which is largely what ssh and the host said, is on a marked line of its own
    let reasons: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("No route to host"))
        .collect();
    assert_eq!(reasons.len(), 1, "{text}");
    assert!(reasons[0].starts_with("| "), "{text}");
}

// ---- over HTTPS ----

/// A fleet whose hosts run `opsmcp serve-http`: `web` is one real server on a loopback
/// port, known to the fleet as host "localhost".
async fn https_world(identity: &str) -> (World, Web) {
    let web = web("token", "").await;
    let token_line = if identity == "fleet" {
        "token_file = \"/unused/token\""
    } else {
        ""
    };
    let config = format!(
        r#"
[roles.ops]
allow = ["@all"]
[roles.dev]
allow = ["@read"]
[unix_users.adam]
roles = ["ops"]
[unix_users.rita]
roles = ["dev"]
[tokens.adam]
sha256 = "{}"
roles = ["ops"]
[limits]
max_output_bytes = 8192
command_timeout_secs = 2
call_timeout_secs = 2
[fleet]
name = "bastion1"
inventory = "/unused/hosts.toml"
retry_secs = 60
[[fleet.access]]
name = "by-token"
roles = ["ops", "dev"]
hosts = ["*"]
via = "https"
identity = "{identity}"
{token_line}
[fleet.https]
client_cert = "/unused/client.pem"
client_key = "/unused/client.key"
"#,
        crate::token::sha256_hex(b"opsmcp_adam_at_the_bastion")
    );
    let inventory = format!("[hosts.localhost]\nhttps_port = {}\n", web.addr.port());
    let https_cfg = crate::config::FleetHttpsCfg {
        ca: Some(web.dir.path().join("ca.pem")),
        ..crate::config::FleetHttpsCfg::default()
    };
    let client = HttpsClient::new(&https_cfg, &[], Duration::from_secs(5), 1 << 20).unwrap();
    let mut tokens = HashMap::new();
    if identity == "fleet" {
        // the fleet's own token is "ci" on the host: a reader there
        tokens.insert(0, Secret::new(CI_TOKEN));
    }
    (world_with(&config, &inventory, Some(client), tokens), web)
}

fn host_calls(web: &Web) -> Vec<Value> {
    web.audit
        .records()
        .into_iter()
        .filter(|r| r["event"] == "tool_call")
        .collect()
}

#[tokio::test]
async fn a_rule_can_present_a_token_of_the_fleets_own() {
    let (w, web) = https_world("fleet").await;
    let (text, is_error) = w
        .call(
            "adam",
            "echo",
            json!({"fleet_host": "localhost", "text": "hi"}),
        )
        .await;
    assert_eq!((text.as_str(), is_error), ("hi", false));
    let record = &host_calls(&web)[0];
    // the host sees the fleet's token, and beside it who the fleet says it was for
    assert_eq!(record["principal"], "token:ci");
    assert_eq!(record["via"]["caller"], "adam");
    assert_eq!(record["via"]["gateway"], "bastion1");
    let ours = &w.audited("fleet_call")[0];
    assert_eq!(
        (ours["over"].as_str(), ours["identity"].as_str()),
        (Some("https"), Some("fleet"))
    );
    // the token itself is nowhere in either trail
    for record in w.audit.records().iter().chain(web.audit.records().iter()) {
        assert!(!record.to_string().contains(CI_TOKEN), "{record}");
    }
}

#[tokio::test]
async fn the_hosts_roles_for_the_fleets_token_still_apply() {
    let (w, web) = https_world("fleet").await;
    // adam is ops at the fleet; the fleet's token is only a reader on the host
    let (text, is_error) = w
        .call(
            "adam",
            "touch",
            json!({"fleet_host": "localhost", "name": "alpha1"}),
        )
        .await;
    assert!(
        is_error && text.contains("Permission denied") && text.contains("token:ci"),
        "{text}"
    );
    assert!(web.effects.touched.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_request_the_host_will_not_take_does_not_get_the_host_left_alone() {
    let (w, web) = https_world("fleet").await;
    // more than the host reads in one request (4096 bytes)
    let padding: Vec<String> = (0..40).map(|n| format!("{n:0>200}")).collect();
    let (text, is_error) = w
        .call(
            "adam",
            "echo",
            json!({"fleet_host": "localhost", "text": "x", "extra": padding}),
        )
        .await;
    assert!(is_error && text.contains("413"), "{text}");
    assert!(!text.contains("may have run"), "{text}");
    assert_eq!(
        w.audited("fleet_result").last().unwrap()["outcome"],
        "failed"
    );
    // the host is there, and everyone who shares the fleet's token can still use it
    let (text, is_error) = w
        .call(
            "rita",
            "echo",
            json!({"fleet_host": "localhost", "text": "y"}),
        )
        .await;
    assert_eq!((text.as_str(), is_error), ("y", false));
    let (hosts, _) = w.call("adam", "fleet_hosts", json!({})).await;
    assert!(!hosts.contains("not answering"), "{hosts}");
    assert_eq!(host_calls(&web).len(), 1);
}

#[tokio::test]
async fn a_rule_can_pass_on_the_callers_own_token() {
    let (w, web) = https_world("caller").await;
    // the caller came in over HTTPS with a token that the host also knows (as "ops")
    let principal = w.cfg().principal_for_unix("adam", &[]).unwrap();
    let mut session = Session::new(principal, "https", Some("192.0.2.9:4711".to_string()));
    session.bearer = Some(Secret::new(OPS_TOKEN));
    let (text, is_error) = w
        .call_as(
            &session,
            "touch",
            json!({"fleet_host": "localhost", "name": "alpha1"}),
        )
        .await;
    assert_eq!((text.as_str(), is_error), ("touched alpha1", false));
    // the host knows the person by their own token and applied its own roles for them
    assert_eq!(host_calls(&web)[0]["principal"], "token:ops");
    let ours = &w.audited("fleet_call")[0];
    assert_eq!(
        (ours["over"].as_str(), ours["identity"].as_str()),
        (Some("https"), Some("caller"))
    );
    assert_eq!(ours["peer"], "192.0.2.9:4711");
    for record in w.audit.records().iter().chain(web.audit.records().iter()) {
        assert!(!record.to_string().contains(OPS_TOKEN), "{record}");
    }
}

#[tokio::test]
async fn a_caller_with_no_token_of_their_own_has_no_route_through_a_rule_that_passes_one_on() {
    let (w, web) = https_world("caller").await;
    // adam over stdio: an SSH identity, but no token to pass on
    let (text, is_error) = w
        .call(
            "adam",
            "echo",
            json!({"fleet_host": "localhost", "text": "x"}),
        )
        .await;
    assert!(is_error && text.contains("no host you can reach"), "{text}");
    assert!(w.tool_names("adam").is_empty());
    assert!(host_calls(&web).is_empty());
}

#[tokio::test]
async fn a_token_the_host_refuses_is_the_answer_and_the_host_is_then_left_alone() {
    let (w, web) = https_world("caller").await;
    let principal = w.cfg().principal_for_unix("adam", &[]).unwrap();
    let mut session = Session::new(principal, "https", None);
    session.bearer = Some(Secret::new("opsmcp_known_here_but_not_on_the_host"));
    let (text, is_error) = w
        .call_as(
            &session,
            "echo",
            json!({"fleet_host": "localhost", "text": "x"}),
        )
        .await;
    assert!(is_error);
    assert!(
        text.contains("could not be reached") && text.contains("refused the credential"),
        "{text}"
    );
    assert!(!text.contains("opsmcp_known_here"), "{text}");
    let failures = web
        .audit
        .records()
        .iter()
        .filter(|r| r["event"] == "auth_failure")
        .count();
    assert_eq!(failures, 1);
    // asked again at once: the host is not bothered a second time
    let (text, _) = w
        .call_as(
            &session,
            "echo",
            json!({"fleet_host": "localhost", "text": "x"}),
        )
        .await;
    assert!(text.contains("not tried again"), "{text}");
    let failures = web
        .audit
        .records()
        .iter()
        .filter(|r| r["event"] == "auth_failure")
        .count();
    assert_eq!(failures, 1);
}
