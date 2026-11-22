//! Which rule decides how a caller reaches a host, and what they may do through it.
//!
//! AIDEV-NOTE: the rules, which are the fleet server's whole authorization story:
//!   1. the FIRST `[[fleet.access]]` rule that names one of the caller's roles, covers
//!      the host, and (for `identity = "caller"`) reuses a kind of credential the caller
//!      actually has, decides everything about how that caller reaches that host;
//!   2. only the grants of the roles that rule names count for the call. A caller's
//!      other roles do not add to them: otherwise a role meant for one rule would widen
//!      what can be done with the credential of another;
//!   3. there is no second try. If the chosen rule's grants refuse the tool, or the host
//!      refuses the credential, the answer is no; a later rule is never tried instead.
//!
//! Whether a caller has an SSH identity or a bearer token of their own is a fact about
//! how they connected, known before anything is sent anywhere, so rule 1 never depends
//! on what a host answered.

use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::config::{Config, FleetCfg, IdentityMode, Via};
use crate::fleet::inventory::{HostEntry, Selector};
use crate::policy::{Access, Rules};

/// One `[[fleet.access]]` rule, checked and ready to match.
#[derive(Clone, Debug)]
pub struct Rule {
    /// Position in the configuration, from 0.
    pub index: usize,
    /// Its name, or `access[N]`.
    pub label: String,
    pub roles: BTreeSet<String>,
    pub hosts: Selector,
    pub via: Via,
    pub identity: IdentityMode,
    pub read_only: bool,
    pub ssh_user: Option<String>,
    pub ssh_key: Option<PathBuf>,
    pub token_file: Option<PathBuf>,
}

/// The credentials of their own that a caller came with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CallerCreds {
    /// The fleet server runs as the caller (stdio, locally or over SSH), so `ssh`
    /// started by it uses the caller's own keys and agent.
    pub ssh: bool,
    /// The caller presented a bearer token, which can be passed on.
    pub bearer: bool,
}

/// How one caller reaches one host.
#[derive(Clone, Debug)]
pub struct Route<'a> {
    pub rule: &'a Rule,
    /// The caller's roles that the rule names, in name order.
    pub roles: Vec<String>,
    /// The grants of those roles.
    pub grants: Rules,
}

impl Route<'_> {
    /// Whether a tool with this permission may be used through this route. `Err` says
    /// why not, for the audit trail and the caller.
    pub fn permits(
        &self,
        permission: &str,
        access: Access,
        session_read_only: bool,
    ) -> Result<(), String> {
        if access == Access::Write {
            if session_read_only {
                return Err("this session is read-only".to_string());
            }
            if self.rule.read_only {
                return Err(format!("the rule {} is read-only", self.rule.label));
            }
        }
        if !self.grants.may_use(permission, access) {
            return Err(format!(
                "{} ({} access) is not granted by {} {}, which the rule {} applies",
                permission,
                access.as_str(),
                if self.roles.len() == 1 {
                    "role"
                } else {
                    "roles"
                },
                self.roles.join(", "),
                self.rule.label
            ));
        }
        Ok(())
    }
}

/// Every rule, in the order of the configuration.
#[derive(Clone, Debug, Default)]
pub struct AccessRules {
    rules: Vec<Rule>,
}

impl Rule {
    /// Whether the rule can apply to a caller who came with `creds`: a rule that reuses
    /// the caller's own credential needs the caller to have one of that kind.
    fn usable_with(&self, creds: CallerCreds) -> bool {
        match (self.identity, self.via) {
            (IdentityMode::Fleet, _) => true,
            (IdentityMode::Caller, Via::Ssh) => creds.ssh,
            (IdentityMode::Caller, Via::Https) => creds.bearer,
        }
    }

    fn names_one_of(&self, roles: &[String]) -> bool {
        roles.iter().any(|role| self.roles.contains(role))
    }
}

impl AccessRules {
    /// Builds the rules from a configuration that has passed `Config::validate`.
    pub fn compile(fleet: &FleetCfg) -> Result<AccessRules, String> {
        let mut rules = Vec::new();
        for (index, rule) in fleet.access.iter().enumerate() {
            let label = rule.label(index);
            let hosts = Selector::parse_list(&rule.hosts)
                .map_err(|problem| format!("fleet.access[{}].hosts: {problem}", index + 1))?;
            rules.push(Rule {
                index,
                label,
                roles: rule.roles.iter().cloned().collect(),
                hosts,
                via: rule.via,
                identity: rule.identity,
                read_only: rule.read_only,
                ssh_user: rule.ssh_user.clone(),
                ssh_key: rule.ssh_key.clone(),
                token_file: rule.token_file.clone(),
            });
        }
        Ok(AccessRules { rules })
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// The rule that decides how a caller holding `roles` reaches `host`, if any does.
    pub fn route<'a>(
        &'a self,
        cfg: &Config,
        roles: &[String],
        creds: CallerCreds,
        host: &HostEntry,
    ) -> Option<Route<'a>> {
        let rule = self.rules.iter().find(|rule| {
            rule.names_one_of(roles) && rule.usable_with(creds) && rule.hosts.matches(host)
        })?;
        let named: BTreeSet<String> = roles
            .iter()
            .filter(|role| rule.roles.contains(*role))
            .cloned()
            .collect();
        let grants = cfg.rules_for(&named);
        Some(Route {
            rule,
            roles: named.into_iter().collect(),
            grants,
        })
    }

    /// Every rule that could apply to a caller holding `roles` who came with `creds`,
    /// on whatever host: for deciding which tools to show them.
    pub fn routes_for<'a>(
        &'a self,
        cfg: &Config,
        roles: &[String],
        creds: CallerCreds,
    ) -> Vec<Route<'a>> {
        self.rules
            .iter()
            .filter(|rule| rule.names_one_of(roles) && rule.usable_with(creds))
            .map(|rule| {
                let named: BTreeSet<String> = roles
                    .iter()
                    .filter(|role| rule.roles.contains(*role))
                    .cloned()
                    .collect();
                Route {
                    rule,
                    grants: cfg.rules_for(&named),
                    roles: named.into_iter().collect(),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet::inventory::{Format, Inventory};

    const INVENTORY: &str = r#"
[groups]
web = ["web1", "web2"]
db = ["db1"]
"#;

    const CONFIG: &str = r#"
[roles.ops]
allow = ["@all"]
[roles.dev]
allow = ["@read"]
[roles.dba]
allow = ["@read", "service.control"]
[roles.auditor]
allow = ["@read"]
deny = ["journal.view"]

[fleet]
inventory = "/etc/opsmcp/hosts.toml"

[[fleet.access]]
name = "dba-db"
roles = ["dba"]
hosts = ["group:db"]
via = "ssh"
identity = "fleet"
ssh_user = "fleet-dba"
ssh_key = "/etc/opsmcp/dba_key"

[[fleet.access]]
name = "ops-own-ssh"
roles = ["ops"]
hosts = ["*"]
via = "ssh"
identity = "caller"

[[fleet.access]]
name = "ops-own-token"
roles = ["ops"]
hosts = ["*"]
via = "https"
identity = "caller"

[[fleet.access]]
name = "dev-web"
roles = ["dev", "auditor"]
hosts = ["group:web"]
via = "https"
identity = "fleet"
token_file = "/etc/opsmcp/dev.token"
read_only = true

[fleet.https]
client_cert = "/etc/opsmcp/fleet/client.crt"
client_key = "/etc/opsmcp/fleet/client.key"
"#;

    struct Fixture {
        cfg: Config,
        rules: AccessRules,
        inventory: Inventory,
    }

    fn fixture() -> Fixture {
        let cfg = Config::parse(CONFIG).unwrap();
        let rules = AccessRules::compile(cfg.fleet.as_ref().unwrap()).unwrap();
        let inventory = Inventory::parse(INVENTORY, Format::Toml).unwrap();
        Fixture {
            cfg,
            rules,
            inventory,
        }
    }

    const SSH: CallerCreds = CallerCreds {
        ssh: true,
        bearer: false,
    };
    const TOKEN: CallerCreds = CallerCreds {
        ssh: false,
        bearer: true,
    };
    const NEITHER: CallerCreds = CallerCreds {
        ssh: false,
        bearer: false,
    };

    impl Fixture {
        fn route(&self, roles: &[&str], creds: CallerCreds, host: &str) -> Option<Route<'_>> {
            let roles: Vec<String> = roles.iter().map(|r| r.to_string()).collect();
            let host = self.inventory.get(host).unwrap();
            self.rules.route(&self.cfg, &roles, creds, host)
        }

        fn rule_name(&self, roles: &[&str], creds: CallerCreds, host: &str) -> Option<String> {
            self.route(roles, creds, host).map(|r| r.rule.label.clone())
        }
    }

    #[test]
    fn rules_keep_their_order_and_their_settings() {
        let f = fixture();
        let labels: Vec<&str> = f.rules.rules().iter().map(|r| r.label.as_str()).collect();
        assert_eq!(
            labels,
            ["dba-db", "ops-own-ssh", "ops-own-token", "dev-web"]
        );
        let dba = &f.rules.rules()[0];
        assert_eq!(
            (dba.index, dba.via, dba.identity),
            (0, Via::Ssh, IdentityMode::Fleet)
        );
        assert_eq!(dba.ssh_user.as_deref(), Some("fleet-dba"));
        assert!(f.rules.rules()[3].read_only);
    }

    #[test]
    fn the_first_rule_for_the_callers_role_and_the_host_decides() {
        let f = fixture();
        assert_eq!(
            f.rule_name(&["ops"], SSH, "web1").as_deref(),
            Some("ops-own-ssh")
        );
        assert_eq!(f.rule_name(&["dba"], SSH, "db1").as_deref(), Some("dba-db"));
        // someone who is both gets the earlier rule on the hosts it covers...
        assert_eq!(
            f.rule_name(&["dba", "ops"], SSH, "db1").as_deref(),
            Some("dba-db")
        );
        // ...and the later one elsewhere
        assert_eq!(
            f.rule_name(&["dba", "ops"], SSH, "web1").as_deref(),
            Some("ops-own-ssh")
        );
    }

    #[test]
    fn a_caller_with_no_rule_for_the_host_has_no_route() {
        let f = fixture();
        assert!(f.route(&["dba"], SSH, "web1").is_none());
        assert!(f.route(&["dev"], SSH, "db1").is_none());
        assert!(f.route(&["stranger"], SSH, "web1").is_none());
        assert!(f.route(&[], SSH, "web1").is_none());
    }

    #[test]
    fn a_rule_that_reuses_a_credential_the_caller_lacks_is_passed_over() {
        let f = fixture();
        // over HTTPS with a token there is no SSH identity to reuse: the token rule fits
        assert_eq!(
            f.rule_name(&["ops"], TOKEN, "web1").as_deref(),
            Some("ops-own-token")
        );
        // with neither, nothing of the caller's own can be reused at all
        assert!(f.route(&["ops"], NEITHER, "web1").is_none());
        // a credential of the fleet's own needs nothing from the caller
        assert_eq!(
            f.rule_name(&["dev"], NEITHER, "web1").as_deref(),
            Some("dev-web")
        );
        assert_eq!(
            f.rule_name(&["dba"], NEITHER, "db1").as_deref(),
            Some("dba-db")
        );
    }

    #[test]
    fn only_the_roles_the_rule_names_count() {
        let f = fixture();
        // dba is read plus service control; ops is everything. On db1 the dba rule comes
        // first, and it is reached with the dba key: being ops as well adds nothing.
        let route = f.route(&["dba", "ops"], SSH, "db1").unwrap();
        assert_eq!(route.roles, ["dba"]);
        assert!(
            route
                .permits("service.control", Access::Write, false)
                .is_ok()
        );
        assert!(route.permits("system.view", Access::Read, false).is_ok());
        let refused = route
            .permits("host.reboot", Access::Write, false)
            .unwrap_err();
        assert!(
            refused.contains("dba") && !refused.contains("ops"),
            "{refused}"
        );
        // on web1 the same person is ops
        let route = f.route(&["dba", "ops"], SSH, "web1").unwrap();
        assert_eq!(route.roles, ["ops"]);
        assert!(route.permits("host.reboot", Access::Write, false).is_ok());
    }

    #[test]
    fn roles_named_by_one_rule_combine_as_roles_do_everywhere() {
        let f = fixture();
        // dev allows every read; auditor denies the journal; a deny wins
        let route = f.route(&["auditor", "dev"], NEITHER, "web1").unwrap();
        assert_eq!(route.roles, ["auditor", "dev"]);
        assert!(route.permits("system.view", Access::Read, false).is_ok());
        assert!(route.permits("journal.view", Access::Read, false).is_err());
    }

    #[test]
    fn a_read_only_rule_or_session_refuses_tools_that_change_things() {
        let f = fixture();
        let cfg = Config::parse(&CONFIG.replace(
            "allow = [\"@read\"]\n[roles.dba]",
            "allow = [\"@all\"]\n[roles.dba]",
        ))
        .unwrap();
        let rules = AccessRules::compile(cfg.fleet.as_ref().unwrap()).unwrap();
        // dev now holds @all, but its rule is read-only
        let host = f.inventory.get("web1").unwrap();
        let route = rules
            .route(&cfg, &["dev".to_string()], NEITHER, host)
            .unwrap();
        assert!(route.permits("system.view", Access::Read, false).is_ok());
        let refused = route
            .permits("service.control", Access::Write, false)
            .unwrap_err();
        assert!(refused.contains("read-only"), "{refused}");
        // a session that was opened read-only refuses changes through any rule
        let route = f.route(&["ops"], SSH, "web1").unwrap();
        assert!(
            route
                .permits("service.control", Access::Write, false)
                .is_ok()
        );
        let refused = route
            .permits("service.control", Access::Write, true)
            .unwrap_err();
        assert!(refused.contains("read-only"), "{refused}");
        assert!(route.permits("system.view", Access::Read, true).is_ok());
    }
}
