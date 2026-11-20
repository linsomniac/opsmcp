//! Permission model: tools carry a permission name and an access class; roles hold grants.
//!
//! A grant is `PERMISSION[:RESOURCE]`:
//!
//! - `PERMISSION` is a permission name (`service.control`), a glob over names (`service.*`),
//!   `@read` (every tool tagged read-only) or `@all` (everything).
//! - `RESOURCE` is an optional glob over the thing acted on (a unit, a path, a container...).
//!   Without it the grant covers every resource.
//!
//! AIDEV-NOTE: the rules here are the whole authorization story. Keep them few:
//!   1. nothing is allowed unless an allow grant matches (deny by default);
//!   2. a matching deny grant always wins, whichever role it came from;
//!   3. a resource-scoped allow never authorizes an operation that names no resource;
//!   4. an operation that names no resource (list every process, query the whole
//!      journal) covers everything, so ANY deny for its permission refuses it, scoped
//!      or not: otherwise it would show or touch the very thing that was denied.

use serde::{Deserialize, Serialize};

use crate::glob::glob_match;

/// Access class a tool is tagged with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    Read,
    Write,
}

impl Access {
    pub fn as_str(self) -> &'static str {
        match self {
            Access::Read => "read",
            Access::Write => "write",
        }
    }
}

/// One parsed grant. See the module docs for the syntax.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    permission: PermissionPattern,
    resource: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PermissionPattern {
    /// `@all`
    All,
    /// `@read`
    AllRead,
    /// A permission name or a glob over permission names.
    Glob(String),
}

impl Grant {
    /// Parses a grant, rejecting anything that is not clearly well-formed.
    pub fn parse(source: &str) -> Result<Grant, String> {
        let (permission_part, resource) = match source.split_once(':') {
            Some((permission, resource)) => (permission, Some(resource)),
            None => (source, None),
        };
        if permission_part.is_empty() {
            return Err(format!("grant {source:?}: the permission is empty"));
        }
        if resource == Some("") {
            return Err(format!("grant {source:?}: the resource after ':' is empty"));
        }
        let permission = if permission_part.starts_with('@') {
            let group = match permission_part {
                "@all" => PermissionPattern::All,
                "@read" => PermissionPattern::AllRead,
                other => {
                    return Err(format!(
                        "grant {source:?}: unknown group {other:?} (the groups are @read and @all)"
                    ));
                }
            };
            if resource.is_some() {
                return Err(format!(
                    "grant {source:?}: a group grant cannot be limited to a resource"
                ));
            }
            group
        } else {
            let valid = permission_part
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "_.-*".contains(c));
            if !valid {
                return Err(format!(
                    "grant {source:?}: a permission may only contain a-z, 0-9, '_', '.', '-' and '*'"
                ));
            }
            PermissionPattern::Glob(permission_part.to_string())
        };
        Ok(Grant {
            permission,
            resource: resource.map(str::to_string),
        })
    }

    /// True when the permission part covers this permission, ignoring any resource.
    pub fn covers_permission(&self, permission: &str, access: Access) -> bool {
        match &self.permission {
            PermissionPattern::All => true,
            PermissionPattern::AllRead => access == Access::Read,
            PermissionPattern::Glob(pattern) => glob_match(pattern, permission),
        }
    }

    /// True when this grant, as an ALLOW, authorizes the operation. A resource-scoped
    /// grant never authorizes an operation that names no resource (rule 3).
    fn allows(&self, permission: &str, access: Access, resource: Option<&str>) -> bool {
        if !self.covers_permission(permission, access) {
            return false;
        }
        match (&self.resource, resource) {
            (None, _) => true,
            (Some(pattern), Some(resource)) => glob_match(pattern, resource),
            (Some(_), None) => false,
        }
    }

    /// True when this grant, as a DENY, refuses the operation. Any deny for the
    /// permission refuses an operation that names no resource (rule 4).
    fn refuses(&self, permission: &str, access: Access, resource: Option<&str>) -> bool {
        if !self.covers_permission(permission, access) {
            return false;
        }
        match (&self.resource, resource) {
            (None, _) | (Some(_), None) => true,
            (Some(pattern), Some(resource)) => glob_match(pattern, resource),
        }
    }
}

/// The combined allow and deny grants of every role a principal holds.
#[derive(Clone, Debug, Default)]
pub struct Rules {
    allow: Vec<Grant>,
    deny: Vec<Grant>,
}

impl Rules {
    pub fn new(allow: Vec<Grant>, deny: Vec<Grant>) -> Rules {
        Rules { allow, deny }
    }

    /// Whether a deny grant covers this resource. For filtering what a collection
    /// operation returns: it says nothing about whether anything is allowed.
    pub fn denies(&self, permission: &str, access: Access, resource: &str) -> bool {
        self.deny
            .iter()
            .any(|g| g.refuses(permission, access, Some(resource)))
    }

    /// Whether the principal could use this permission for at least some resource.
    /// Used to decide which tools to list, and as an early check before a tool runs.
    pub fn may_use(&self, permission: &str, access: Access) -> bool {
        let denied_outright = self
            .deny
            .iter()
            .any(|g| g.resource.is_none() && g.covers_permission(permission, access));
        !denied_outright
            && self
                .allow
                .iter()
                .any(|g| g.covers_permission(permission, access))
    }

    /// The authorization decision for one operation. `resource` is `None` for operations
    /// that do not act on a named thing (listing all services, for example).
    pub fn check(&self, permission: &str, access: Access, resource: Option<&str>) -> bool {
        let denied = self
            .deny
            .iter()
            .any(|g| g.refuses(permission, access, resource));
        !denied
            && self
                .allow
                .iter()
                .any(|g| g.allows(permission, access, resource))
    }
}

/// An authenticated caller and what they are allowed to do.
#[derive(Clone, Debug)]
pub struct Principal {
    /// Name used in the audit log: a Unix user name, `token:NAME` or `cert:NAME`.
    pub name: String,
    pub roles: Vec<String>,
    pub rules: Rules,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(allow: &[&str], deny: &[&str]) -> Rules {
        let parse = |list: &[&str]| -> Vec<Grant> {
            list.iter().map(|g| Grant::parse(g).unwrap()).collect()
        };
        Rules::new(parse(allow), parse(deny))
    }

    #[test]
    fn malformed_grants_are_rejected() {
        for bad in [
            "",
            "@write",
            "@read:/var/log/**",
            "@all:x",
            "service.control:",
            "Service.Control",
            "service control",
            ":nginx.service",
            "service/control",
        ] {
            assert!(Grant::parse(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn well_formed_grants_parse() {
        for good in [
            "@read",
            "@all",
            "service.control",
            "service.*",
            "service.control:nginx.service",
            "fs.read:/etc/haproxy/**",
            "custom.haproxy_set",
            "kernel_log.view",
        ] {
            assert!(Grant::parse(good).is_ok(), "{good:?} should parse");
        }
    }

    #[test]
    fn nothing_is_allowed_without_a_grant() {
        let r = rules(&[], &[]);
        assert!(!r.may_use("system.view", Access::Read));
        assert!(!r.check("system.view", Access::Read, None));
    }

    #[test]
    fn read_group_covers_read_tools_only() {
        let r = rules(&["@read"], &[]);
        assert!(r.check("service.view", Access::Read, None));
        assert!(r.check("fs.read", Access::Read, Some("/etc/hosts")));
        assert!(!r.check("service.control", Access::Write, Some("nginx.service")));
        assert!(!r.may_use("service.control", Access::Write));
    }

    #[test]
    fn all_group_covers_write_tools() {
        let r = rules(&["@all"], &[]);
        assert!(r.check("service.control", Access::Write, Some("nginx.service")));
        assert!(r.check("service.view", Access::Read, None));
    }

    #[test]
    fn a_named_permission_grants_only_that_permission() {
        let r = rules(&["service.control"], &[]);
        assert!(r.check("service.control", Access::Write, Some("nginx.service")));
        assert!(!r.check("service.enable", Access::Write, Some("nginx.service")));
        assert!(!r.check("service.view", Access::Read, None));
    }

    #[test]
    fn a_permission_glob_stops_at_the_name_it_was_written_for() {
        let r = rules(&["service.*"], &[]);
        assert!(r.check("service.control", Access::Write, Some("x.service")));
        assert!(r.check("service.view", Access::Read, None));
        assert!(!r.check("servicex.view", Access::Read, None));
        assert!(!r.check("process.view", Access::Read, None));
    }

    #[test]
    fn a_scoped_grant_covers_only_matching_resources() {
        let r = rules(&["service.control:nginx.service"], &[]);
        assert!(r.check("service.control", Access::Write, Some("nginx.service")));
        assert!(!r.check("service.control", Access::Write, Some("postgres.service")));
        // rule 3: a scoped allow cannot authorize an operation with no resource
        assert!(!r.check("service.control", Access::Write, None));
        // but the tool is still one this principal can use
        assert!(r.may_use("service.control", Access::Write));
    }

    #[test]
    fn the_resource_is_everything_after_the_first_colon() {
        let r = rules(&["fs.read:/srv/a:b/*"], &[]);
        assert!(r.check("fs.read", Access::Read, Some("/srv/a:b/file")));
        assert!(!r.check("fs.read", Access::Read, Some("/srv/a")));
    }

    #[test]
    fn an_unscoped_deny_wins_over_any_allow() {
        let r = rules(&["@all"], &["process.signal"]);
        assert!(!r.check("process.signal", Access::Write, Some("root/sshd")));
        assert!(!r.may_use("process.signal", Access::Write));
        assert!(r.check("process.view", Access::Read, None));
    }

    #[test]
    fn a_scoped_deny_blocks_matching_resources_and_whole_collection_operations() {
        let r = rules(&["@read"], &["fs.read:/etc/ssl/private/**"]);
        assert!(!r.check("fs.read", Access::Read, Some("/etc/ssl/private/server.key")));
        assert!(r.check("fs.read", Access::Read, Some("/etc/hosts")));
        // the tool is still one this caller can use, for other resources
        assert!(r.may_use("fs.read", Access::Read));
        // rule 4: an operation that names no resource covers everything, the denied
        // thing included, so it is refused
        assert!(!r.check("fs.read", Access::Read, None));
        // other permissions are not affected
        assert!(r.check("fs.view", Access::Read, None));
    }

    #[test]
    fn denies_reports_explicit_denials_only() {
        let r = rules(&["sysctl.view:net.ipv4"], &["sysctl.view:net.ipv4.secret*"]);
        assert!(r.denies("sysctl.view", Access::Read, "net.ipv4.secret_key"));
        // not denied, even though no allow grant names it either
        assert!(!r.denies("sysctl.view", Access::Read, "net.ipv4.ip_forward"));
        assert!(!r.denies("sysctl.modify", Access::Write, "net.ipv4.secret_key"));
    }

    #[test]
    fn a_deny_group_can_remove_everything() {
        let r = rules(&["@all"], &["@all"]);
        assert!(!r.check("system.view", Access::Read, None));
        assert!(!r.may_use("service.control", Access::Write));
    }

    #[test]
    fn covers_permission_ignores_the_resource_part() {
        let g = Grant::parse("service.control:nginx.service").unwrap();
        assert!(g.covers_permission("service.control", Access::Write));
        assert!(!g.covers_permission("service.view", Access::Read));
        let read = Grant::parse("@read").unwrap();
        assert!(read.covers_permission("anything.view", Access::Read));
        assert!(!read.covers_permission("anything.modify", Access::Write));
    }
}
