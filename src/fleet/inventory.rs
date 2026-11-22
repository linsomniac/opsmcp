//! The hosts a fleet server knows about, and how a caller names some of them.
//!
//! AIDEV-NOTE: a host can only ever be reached by a name that is in the inventory. What
//! the agent sends is a selector that picks inventory entries; it is never used as an
//! address or put on a command line. That is what keeps a caller from making the fleet
//! server connect to a machine of their choosing, or smuggling an option to `ssh`.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::Deserialize;

use crate::config::is_host_name;
use crate::glob::glob_match;
use crate::sanitize::clean_text;

/// Most hosts an inventory may hold.
pub const MAX_HOSTS: usize = 10_000;
/// Most terms in one selector.
const MAX_TERMS: usize = 64;
/// Longest term, in characters (a DNS name is at most 253).
const MAX_TERM_LEN: usize = 253;
/// Longest group name. Ansible inventories that make groups out of cloud tags have
/// long ones.
const MAX_GROUP_LEN: usize = 128;

/// One host in the inventory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostEntry {
    /// The name callers use, in lower case.
    pub name: String,
    /// What to connect to: a DNS name or an IP address. The name, unless set.
    pub address: String,
    pub groups: BTreeSet<String>,
    pub ssh_port: Option<u16>,
    pub https_port: Option<u16>,
}

/// How inventory text is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Toml,
    Json,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawInventory {
    hosts: BTreeMap<String, RawHost>,
    /// Group name to the hosts in it: a shorter way to list hosts that need no settings.
    groups: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawHost {
    address: Option<String>,
    groups: Vec<String>,
    ssh_port: Option<u16>,
    https_port: Option<u16>,
}

/// The entry of `ansible-inventory --list` that holds every host's variables.
const ANSIBLE_META: &str = "_meta";
/// How much work is put into finding out which hosts each Ansible group holds: one
/// step per group gone into and per host seen there. An inventory of 10,000 hosts in a
/// hundred groups each stays well below it.
const MAX_GROUP_STEPS: usize = 4_000_000;
/// Most hosts and groups left out of an Ansible inventory that are named one by one.
const MAX_LEFT_OUT_SHOWN: usize = 20;

/// One entry of what `ansible-inventory --list` prints: a group (its own hosts and the
/// groups below it), or `_meta` (every host's variables).
///
/// AIDEV-NOTE: only these fields are read. Everything else in that output (the other
/// variables of every host, which can include passwords) is skipped as it goes by and
/// is never held in memory, logged or repeated.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct AnsibleEntry {
    hosts: Vec<String>,
    children: Vec<String>,
    hostvars: BTreeMap<String, AnsibleVars>,
}

/// The variables of a host that say where it is. The `ansible_ssh_` names are the ones
/// Ansible used before 2.0 and still understands.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct AnsibleVars {
    ansible_host: Option<serde_json::Value>,
    ansible_port: Option<serde_json::Value>,
    ansible_ssh_host: Option<serde_json::Value>,
    ansible_ssh_port: Option<serde_json::Value>,
}

/// What was left out of an Ansible inventory: the first of it line by line, the rest
/// as a number, so that an inventory full of unusable entries costs no memory for it.
#[derive(Default)]
struct LeftOut {
    shown: Vec<String>,
    more: usize,
}

impl LeftOut {
    fn add(&mut self, line: impl FnOnce() -> String) {
        if self.shown.len() < MAX_LEFT_OUT_SHOWN {
            self.shown.push(line());
        } else {
            self.more += 1;
        }
    }

    fn lines(mut self) -> Vec<String> {
        if self.more > 0 {
            self.shown
                .push(format!("{} more hosts or groups", self.more));
        }
        self.shown
    }
}

/// A port as Ansible lets it be written: a number, or a number as text.
fn ansible_port(value: &serde_json::Value) -> Option<u16> {
    let port = match value {
        serde_json::Value::Number(number) => u16::try_from(number.as_u64()?).ok()?,
        serde_json::Value::String(text) => text.parse::<u16>().ok()?,
        _ => return None,
    };
    (port != 0).then_some(port)
}

/// Every host the fleet server may reach, by name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Inventory {
    hosts: BTreeMap<String, HostEntry>,
}

/// How an inventory differs from the one before it: host names, in order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Changes {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    /// The address or a port is different.
    pub moved: Vec<String>,
    /// Only the groups are different.
    pub regrouped: Vec<String>,
}

impl Changes {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && self.moved.is_empty()
            && self.regrouped.is_empty()
    }
}

/// A host name as the inventory accepts it, in lower case.
///
/// AIDEV-NOTE: DNS labels only (letters, digits, `-`, dots between labels; never a
/// leading `-`). A name ends up as an argument of `ssh` when the host has no separate
/// address, so nothing that `ssh` or a shell could read as anything but a name may pass.
fn host_name(name: &str) -> Option<String> {
    is_host_name(name).then(|| name.to_ascii_lowercase())
}

/// A group name, in lower case: letters, digits, `_`, `-` and `.`.
fn group_name(name: &str) -> Option<String> {
    let ok = !name.is_empty()
        && name.len() <= MAX_GROUP_LEN
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c));
    ok.then(|| name.to_ascii_lowercase())
}

/// Text from a file or a caller, made safe to quote in a message.
fn shown(text: &str) -> String {
    let cut: String = text.chars().take(80).collect();
    format!("{:?}", clean_text(cut.as_bytes()))
}

impl Inventory {
    /// Parses and checks inventory text. Every problem found is reported.
    pub fn parse(text: &str, format: Format) -> Result<Inventory, Vec<String>> {
        let raw: RawInventory = match format {
            Format::Toml => toml::from_str(text).map_err(|e| vec![e.to_string()])?,
            Format::Json => serde_json::from_str(text).map_err(|e| vec![e.to_string()])?,
        };
        let mut errors = Vec::new();
        let mut hosts: BTreeMap<String, HostEntry> = BTreeMap::new();

        for (written, settings) in &raw.hosts {
            let at = format!("hosts.{}", shown(written));
            let Some(name) = host_name(written) else {
                errors.push(format!(
                    "{at}: a host name is letters, digits and '-' in parts separated by dots"
                ));
                continue;
            };
            if hosts.contains_key(&name) {
                errors.push(format!("{at}: {name} is listed more than once"));
                continue;
            }
            let address = match &settings.address {
                None => name.clone(),
                Some(address) if is_host_name(address) || address.parse::<IpAddr>().is_ok() => {
                    address.to_ascii_lowercase()
                }
                Some(address) => {
                    errors.push(format!(
                        "{at}.address: {} is not a host name or an IP address",
                        shown(address)
                    ));
                    name.clone()
                }
            };
            for (setting, port) in [
                ("ssh_port", settings.ssh_port),
                ("https_port", settings.https_port),
            ] {
                if port == Some(0) {
                    errors.push(format!("{at}.{setting}: must be between 1 and 65535"));
                }
            }
            let mut groups = BTreeSet::new();
            for group in &settings.groups {
                match group_name(group) {
                    Some(group) => {
                        groups.insert(group);
                    }
                    None => errors.push(format!(
                        "{at}.groups: {} is not a group name (letters, digits, '_', '-', '.')",
                        shown(group)
                    )),
                }
            }
            hosts.insert(
                name.clone(),
                HostEntry {
                    name,
                    address,
                    groups,
                    ssh_port: settings.ssh_port,
                    https_port: settings.https_port,
                },
            );
        }

        for (written, members) in &raw.groups {
            let at = format!("groups.{}", shown(written));
            let Some(group) = group_name(written) else {
                errors.push(format!(
                    "{at}: a group name is letters, digits, '_', '-' and '.'"
                ));
                continue;
            };
            for member in members {
                let Some(name) = host_name(member) else {
                    errors.push(format!(
                        "{at}: {} is not a host name (letters, digits and '-' in parts \
                         separated by dots)",
                        shown(member)
                    ));
                    continue;
                };
                hosts
                    .entry(name.clone())
                    .or_insert_with(|| HostEntry {
                        address: name.clone(),
                        name,
                        groups: BTreeSet::new(),
                        ssh_port: None,
                        https_port: None,
                    })
                    .groups
                    .insert(group.clone());
            }
        }

        if hosts.len() > MAX_HOSTS {
            errors.push(format!(
                "the inventory lists {} hosts; at most {MAX_HOSTS} are supported",
                hosts.len()
            ));
        }
        if hosts.is_empty() && errors.is_empty() {
            errors.push("the inventory lists no hosts".to_string());
        }
        if errors.is_empty() {
            Ok(Inventory { hosts })
        } else {
            Err(errors)
        }
    }

    /// Reads what `ansible-inventory --list` prints. Returns the inventory and, for each
    /// host or group in it that opsmcp cannot use, a line that says which and why.
    ///
    /// AIDEV-NOTE: an Ansible inventory is written for Ansible, not for opsmcp, so an
    /// entry that cannot be used here (a name with `_` in it, an address that is still
    /// a template) is LEFT OUT and pointed out; it does not stop the server, as a
    /// mistake in opsmcp's own format does. Leaving out is the only thing done with
    /// such an entry: nothing is guessed or repaired, so a host is still only ever
    /// reached at a name or address that passed the same checks as in `parse`.
    pub fn from_ansible(text: &str) -> Result<(Inventory, Vec<String>), Vec<String>> {
        Inventory::from_ansible_within(text, MAX_GROUP_STEPS)
    }

    /// `from_ansible`, giving up on the groups after `max_steps`.
    fn from_ansible_within(
        text: &str,
        max_steps: usize,
    ) -> Result<(Inventory, Vec<String>), Vec<String>> {
        // AIDEV-NOTE: the reason is built from where the problem is and what kind it
        // is, never from serde's own message, which can quote a value. This output
        // holds every variable of every host, secrets included.
        let raw: BTreeMap<String, AnsibleEntry> = serde_json::from_str(text).map_err(|e| {
            use serde_json::error::Category;
            let what = match e.classify() {
                Category::Syntax | Category::Io => "it is not JSON",
                Category::Eof => "it ends too early",
                Category::Data => "a value there is not of the kind expected",
            };
            vec![format!(
                "not what `ansible-inventory --list` prints: {what} (line {}, column {})",
                e.line(),
                e.column()
            )]
        })?;
        let no_vars = BTreeMap::new();
        let vars = raw
            .get(ANSIBLE_META)
            .map_or(&no_vars, |meta| &meta.hostvars);
        let groups = || raw.iter().filter(|(name, _)| name.as_str() != ANSIBLE_META);

        let mut left_out = LeftOut::default();
        // Every name a host goes by, under the lower-case name it would have here.
        let mut spellings: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
        let mut unusable: BTreeSet<&str> = BTreeSet::new();
        let written = groups()
            .flat_map(|(_, group)| group.hosts.iter())
            .chain(vars.keys());
        for written in written {
            match host_name(written) {
                Some(name) => {
                    spellings.entry(name).or_default().insert(written);
                }
                None => {
                    unusable.insert(written);
                }
            }
        }
        if spellings.len() > MAX_HOSTS {
            return Err(vec![format!(
                "the inventory lists {} hosts; at most {MAX_HOSTS} are supported",
                spellings.len()
            )]);
        }
        for written in unusable {
            left_out.add(|| {
                format!(
                    "the host {}: its name is not letters, digits and '-' in parts \
                     separated by dots",
                    shown(written)
                )
            });
        }

        let mut hosts: BTreeMap<String, HostEntry> = BTreeMap::new();
        for (name, spelled) in spellings {
            let mut spelled = spelled.into_iter();
            let (Some(written), None) = (spelled.next(), spelled.next()) else {
                // Which machine the name means cannot be known, so it means none.
                left_out
                    .add(|| format!("the host {name}: it is listed under more than one spelling"));
                continue;
            };
            let settings = vars.get(written);
            let address = settings.and_then(|vars| {
                vars.ansible_host
                    .as_ref()
                    .or(vars.ansible_ssh_host.as_ref())
            });
            let address = match address {
                None => name.clone(),
                Some(serde_json::Value::String(address))
                    if is_host_name(address) || address.parse::<IpAddr>().is_ok() =>
                {
                    address.to_ascii_lowercase()
                }
                Some(serde_json::Value::String(address)) => {
                    left_out.add(|| {
                        format!(
                            "the host {name}: its ansible_host, {}, is not a host name or an \
                             IP address",
                            shown(address)
                        )
                    });
                    continue;
                }
                Some(_) => {
                    left_out.add(|| format!("the host {name}: its ansible_host is not text"));
                    continue;
                }
            };
            let port = settings.and_then(|vars| {
                vars.ansible_port
                    .as_ref()
                    .or(vars.ansible_ssh_port.as_ref())
            });
            let ssh_port = match port.map(ansible_port) {
                None => None,
                Some(Some(port)) => Some(port),
                Some(None) => {
                    left_out.add(|| {
                        format!(
                            "the host {name}: its ansible_port is not a number between 1 and \
                             65535"
                        )
                    });
                    continue;
                }
            };
            hosts.insert(
                name.clone(),
                HostEntry {
                    name,
                    address,
                    groups: BTreeSet::new(),
                    ssh_port,
                    https_port: None,
                },
            );
        }

        // AIDEV-NOTE: a group holds its own hosts and those of every group below it,
        // found by going down from each group in turn. That costs more the deeper the
        // groups are nested (a chain of N groups costs N*N/2), and it is done again at
        // every reload inside a running server, so the work is counted and given up on
        // at `max_steps`: an inventory nested like that is refused, not waited for.
        let mut steps = 0_usize;
        for (written, _) in groups() {
            let Some(group) = group_name(written) else {
                left_out.add(|| {
                    format!(
                        "the group {}: its name is not letters, digits, '_', '-' and '.'",
                        shown(written)
                    )
                });
                continue;
            };
            // A group that has been seen is not gone into again, so a loop ends.
            let mut seen: BTreeSet<&str> = BTreeSet::new();
            let mut to_see: Vec<&str> = vec![written.as_str()];
            while let Some(current) = to_see.pop() {
                if current == ANSIBLE_META || !seen.insert(current) {
                    continue;
                }
                let Some(entry) = raw.get(current) else {
                    continue;
                };
                steps = steps.saturating_add(1 + entry.hosts.len());
                if steps > max_steps {
                    return Err(vec![format!(
                        "its groups are nested too deeply, or hold too many hosts too many \
                         times over, to work out which hosts each one holds (more than \
                         {max_steps} steps)"
                    )]);
                }
                to_see.extend(entry.children.iter().map(String::as_str));
                for member in &entry.hosts {
                    if let Some(host) = host_name(member).and_then(|name| hosts.get_mut(&name)) {
                        host.groups.insert(group.clone());
                    }
                }
            }
        }

        let left_out = left_out.lines();
        if hosts.is_empty() {
            let mut errors = vec![
                "no host that opsmcp can use is listed (it reads what `ansible-inventory \
                 --list` prints)"
                    .to_string(),
            ];
            errors.extend(left_out.into_iter().map(|line| format!("left out: {line}")));
            return Err(errors);
        }
        Ok((Inventory { hosts }, left_out))
    }

    /// How `newer` differs from this inventory.
    pub fn changes_to(&self, newer: &Inventory) -> Changes {
        let mut changes = Changes::default();
        for (name, old) in &self.hosts {
            match newer.hosts.get(name) {
                None => changes.removed.push(name.clone()),
                Some(new) if new == old => {}
                Some(new)
                    if (&new.address, new.ssh_port, new.https_port)
                        != (&old.address, old.ssh_port, old.https_port) =>
                {
                    changes.moved.push(name.clone());
                }
                Some(_) => changes.regrouped.push(name.clone()),
            }
        }
        changes.added = newer
            .hosts
            .keys()
            .filter(|name| !self.hosts.contains_key(*name))
            .cloned()
            .collect();
        changes
    }

    /// The host of that name (names are kept in lower case).
    pub fn get(&self, name: &str) -> Option<&HostEntry> {
        self.hosts.get(name)
    }

    /// Every host, in name order.
    pub fn hosts(&self) -> impl Iterator<Item = &HostEntry> {
        self.hosts.values()
    }

    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    /// Each group with the number of hosts in it.
    pub fn groups(&self) -> BTreeMap<&str, usize> {
        let mut counts = BTreeMap::new();
        for host in self.hosts.values() {
            for group in &host.groups {
                *counts.entry(group.as_str()).or_insert(0) += 1;
            }
        }
        counts
    }
}

/// Picks hosts from the inventory: names, patterns over names, and `group:NAME`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selector {
    terms: Vec<Term>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Term {
    Group(String),
    /// A host name, or a glob over host names (`*` and `?`).
    Pattern(String),
}

impl Term {
    fn parse(text: &str) -> Result<Term, String> {
        if text.is_empty() {
            return Err("a host selector has an empty part".to_string());
        }
        if text.chars().count() > MAX_TERM_LEN {
            return Err(format!(
                "a host selector part is longer than {MAX_TERM_LEN} characters"
            ));
        }
        if let Some(group) = text
            .strip_prefix("group:")
            .or_else(|| text.strip_prefix("GROUP:"))
        {
            return group_name(group).map(Term::Group).ok_or_else(|| {
                format!(
                    "{} is not a group: write group:NAME, where NAME is letters, digits, \
                     '_', '-' and '.'",
                    shown(text)
                )
            });
        }
        // What a host name can contain, plus the two pattern characters. A leading '-'
        // is never a name, and is what an option to a command looks like.
        let plain = !text.starts_with('-')
            && text
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || ".-*?".contains(c));
        if !plain {
            return Err(format!(
                "{} is not a host selector: use a host name, a pattern such as web*, or \
                 group:NAME",
                shown(text)
            ));
        }
        Ok(Term::Pattern(text.to_ascii_lowercase()))
    }

    fn matches(&self, host: &HostEntry) -> bool {
        match self {
            Term::Group(group) => host.groups.contains(group),
            // A term with no pattern character is a name: compared as one, so that
            // what matching costs does not grow with every name a caller lists.
            Term::Pattern(pattern) if !pattern.contains(['*', '?']) => host.name == *pattern,
            Term::Pattern(pattern) => glob_match(pattern, &host.name),
        }
    }

    fn written(&self) -> String {
        match self {
            Term::Group(group) => format!("group:{group}"),
            Term::Pattern(pattern) => pattern.clone(),
        }
    }
}

impl Selector {
    /// Parses what a caller sends: one term, or several separated by commas.
    pub fn parse(text: &str) -> Result<Selector, String> {
        let parts: Vec<&str> = text.split(',').map(|part| part.trim_matches(' ')).collect();
        if parts.len() > MAX_TERMS {
            return Err(format!(
                "a host selector may have at most {MAX_TERMS} parts"
            ));
        }
        let terms = parts
            .into_iter()
            .map(Term::parse)
            .collect::<Result<Vec<Term>, String>>()?;
        Ok(Selector { terms })
    }

    /// Parses a list from the configuration: one term per item.
    pub fn parse_list(items: &[String]) -> Result<Selector, String> {
        if items.is_empty() {
            return Err("the list of hosts is empty".to_string());
        }
        if items.len() > MAX_TERMS {
            return Err(format!("at most {MAX_TERMS} host selectors may be listed"));
        }
        let terms = items
            .iter()
            .map(|item| Term::parse(item))
            .collect::<Result<Vec<Term>, String>>()?;
        Ok(Selector { terms })
    }

    pub fn matches(&self, host: &HostEntry) -> bool {
        self.terms.iter().any(|term| term.matches(host))
    }

    /// The hosts among `hosts` that the selector picks, in name order, each once. A term
    /// that picks none of them is an error that names it.
    ///
    /// AIDEV-NOTE: callers pass only the hosts the caller may reach, so that a host
    /// outside them gets the same answer as a host that does not exist.
    pub fn resolve<'a>(
        &self,
        hosts: impl Iterator<Item = &'a HostEntry>,
    ) -> Result<Vec<&'a HostEntry>, String> {
        let offered: Vec<&HostEntry> = hosts.collect();
        let mut picked: BTreeMap<&str, &HostEntry> = BTreeMap::new();
        for term in &self.terms {
            let mut any = false;
            for host in offered.iter().filter(|host| term.matches(host)) {
                any = true;
                picked.insert(host.name.as_str(), host);
            }
            if !any {
                return Err(nothing_matches(term, &offered));
            }
        }
        Ok(picked.into_values().collect())
    }

    /// The terms that pick none of `hosts`, as written: for a warning about a
    /// configuration that names something the inventory does not have.
    pub fn unmatched<'a>(&self, hosts: impl Iterator<Item = &'a HostEntry>) -> Vec<String> {
        let offered: Vec<&HostEntry> = hosts.collect();
        self.terms
            .iter()
            .filter(|term| !offered.iter().any(|host| term.matches(host)))
            .map(Term::written)
            .collect()
    }
}

/// What to say about a term that picked no host.
fn nothing_matches(term: &Term, offered: &[&HostEntry]) -> String {
    match term {
        Term::Group(group) => format!(
            "no host you can reach is in group:{group} (fleet_hosts lists hosts and groups)"
        ),
        Term::Pattern(pattern) => {
            let is_group = offered.iter().any(|host| host.groups.contains(pattern));
            let hint = if is_group {
                format!("; there is a group of that name: write group:{pattern}")
            } else {
                " (fleet_hosts lists hosts and groups)".to_string()
            };
            format!("no host you can reach matches {pattern:?}{hint}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOML: &str = r#"
[hosts.web1]
address = "10.0.0.11"
groups = ["web", "prod"]
ssh_port = 2222

[hosts.web2]
groups = ["web"]

[hosts."db1.example.com"]
https_port = 9443

[groups]
db = ["db1.example.com", "db2.example.com"]
prod = ["db2.example.com"]
"#;

    fn inventory() -> Inventory {
        Inventory::parse(TOML, Format::Toml).unwrap()
    }

    fn names(hosts: &[&HostEntry]) -> Vec<String> {
        hosts.iter().map(|h| h.name.clone()).collect()
    }

    fn pick(inventory: &Inventory, selector: &str) -> Result<Vec<String>, String> {
        Selector::parse(selector)?
            .resolve(inventory.hosts())
            .map(|hosts| names(&hosts))
    }

    #[test]
    fn hosts_have_an_address_groups_and_ports() {
        let inv = inventory();
        assert_eq!(inv.len(), 4);
        let web1 = inv.get("web1").unwrap();
        assert_eq!(web1.address, "10.0.0.11");
        assert_eq!(web1.ssh_port, Some(2222));
        assert_eq!(
            web1.groups.iter().map(String::as_str).collect::<Vec<_>>(),
            ["prod", "web"]
        );
        // the address is the name unless one is given
        assert_eq!(inv.get("web2").unwrap().address, "web2");
        assert_eq!(inv.get("db1.example.com").unwrap().https_port, Some(9443));
    }

    #[test]
    fn a_host_named_only_in_a_group_exists() {
        let inv = inventory();
        let db2 = inv.get("db2.example.com").unwrap();
        assert_eq!(db2.address, "db2.example.com");
        assert_eq!(
            db2.groups.iter().map(String::as_str).collect::<Vec<_>>(),
            ["db", "prod"]
        );
        // and a host with its own entry also gets the groups that list it
        assert!(inv.get("db1.example.com").unwrap().groups.contains("db"));
    }

    #[test]
    fn groups_are_counted() {
        let inv = inventory();
        let groups = inv.groups();
        assert_eq!(groups.get("web"), Some(&2));
        assert_eq!(groups.get("db"), Some(&2));
        assert_eq!(groups.get("prod"), Some(&2));
        assert_eq!(groups.len(), 3);
    }

    #[test]
    fn json_describes_the_same_inventory() {
        let json = r#"{
            "hosts": {
                "web1": {"address": "10.0.0.11", "groups": ["web", "prod"], "ssh_port": 2222},
                "web2": {"groups": ["web"]},
                "db1.example.com": {"https_port": 9443}
            },
            "groups": {"db": ["db1.example.com", "db2.example.com"], "prod": ["db2.example.com"]}
        }"#;
        let from_json = Inventory::parse(json, Format::Json).unwrap();
        let from_toml = inventory();
        assert_eq!(
            from_json.hosts().collect::<Vec<_>>(),
            from_toml.hosts().collect::<Vec<_>>()
        );
    }

    #[test]
    fn names_are_kept_in_lower_case() {
        let inv = Inventory::parse("[hosts.Web1]\ngroups = [\"WEB\"]\n", Format::Toml).unwrap();
        assert!(inv.get("web1").unwrap().groups.contains("web"));
        assert_eq!(pick(&inv, "WEB1").unwrap(), ["web1"]);
        assert_eq!(pick(&inv, "group:Web").unwrap(), ["web1"]);
    }

    #[test]
    fn what_cannot_be_a_host_or_an_address_is_refused() {
        for (text, needle) in [
            // a name that ssh would read as an option
            ("[hosts.\"-oProxyCommand=id\"]\n", "-oproxycommand=id"),
            ("[hosts.\"web 1\"]\n", "web 1"),
            ("[hosts.\"web1;id\"]\n", "web1;id"),
            ("[hosts.\"group:web\"]\n", "group:web"),
            ("[hosts.web1]\naddress = \"-oProxyCommand=id\"\n", "address"),
            ("[hosts.web1]\naddress = \"10.0.0.1 -p 22\"\n", "address"),
            ("[hosts.web1]\naddress = \"\"\n", "address"),
            ("[hosts.web1]\nssh_port = 0\n", "ssh_port"),
            ("[hosts.web1]\ngroups = [\"we b\"]\n", "we b"),
            ("[groups]\n\"a/b\" = [\"web1\"]\n", "a/b"),
            ("[groups]\nweb = [\"web1;id\"]\n", "web1;id"),
            // a misspelled setting is an error, not ignored
            ("[hosts.web1]\nadress = \"10.0.0.1\"\n", "adress"),
        ] {
            let errors = Inventory::parse(text, Format::Toml).unwrap_err();
            assert!(
                errors.iter().any(|e| e.to_lowercase().contains(needle)),
                "{text:?}: {errors:?}"
            );
        }
    }

    #[test]
    fn an_address_may_be_a_name_or_an_ip_address() {
        let text = "[hosts.a]\naddress = \"a.internal.example.com\"\n\
                    [hosts.b]\naddress = \"192.0.2.7\"\n\
                    [hosts.c]\naddress = \"2001:db8::7\"\n";
        let inv = Inventory::parse(text, Format::Toml).unwrap();
        assert_eq!(inv.get("c").unwrap().address, "2001:db8::7");
    }

    #[test]
    fn every_problem_is_reported_not_just_the_first() {
        let text = "[hosts.\"bad name\"]\n[hosts.web1]\naddress = \"-x\"\nssh_port = 0\n";
        let errors = Inventory::parse(text, Format::Toml).unwrap_err();
        assert_eq!(errors.len(), 3, "{errors:?}");
    }

    #[test]
    fn two_spellings_of_one_host_are_an_error() {
        let text = "[hosts.web1]\naddress = \"10.0.0.1\"\n[hosts.WEB1]\naddress = \"10.0.0.2\"\n";
        let errors = Inventory::parse(text, Format::Toml).unwrap_err();
        assert!(errors[0].contains("web1"), "{errors:?}");
    }

    #[test]
    fn an_empty_inventory_is_an_error() {
        assert!(Inventory::parse("", Format::Toml).is_err());
        assert!(Inventory::parse("{}", Format::Json).is_err());
    }

    #[test]
    fn a_selector_picks_by_name_pattern_and_group() {
        let inv = inventory();
        assert_eq!(pick(&inv, "web1").unwrap(), ["web1"]);
        assert_eq!(pick(&inv, "web*").unwrap(), ["web1", "web2"]);
        assert_eq!(pick(&inv, "web?").unwrap(), ["web1", "web2"]);
        assert_eq!(
            pick(&inv, "group:db").unwrap(),
            ["db1.example.com", "db2.example.com"]
        );
        assert_eq!(pick(&inv, "*").unwrap().len(), 4);
        assert_eq!(pick(&inv, "*.example.com").unwrap().len(), 2);
    }

    #[test]
    fn several_terms_give_each_host_once_in_name_order() {
        let inv = inventory();
        assert_eq!(
            pick(&inv, "web2, group:web ,web1,group:prod").unwrap(),
            ["db2.example.com", "web1", "web2"]
        );
    }

    #[test]
    fn a_term_that_picks_nothing_is_an_error_that_names_it() {
        let inv = inventory();
        let error = pick(&inv, "web1,web9").unwrap_err();
        assert!(
            error.contains("web9") && !error.contains("web1,"),
            "{error}"
        );
        let error = pick(&inv, "group:cache").unwrap_err();
        assert!(error.contains("group:cache"), "{error}");
        // a bare word that is the name of a group gets a pointer to the right spelling
        let error = pick(&inv, "db").unwrap_err();
        assert!(error.contains("group:db"), "{error}");
    }

    #[test]
    fn a_selector_only_sees_the_hosts_it_is_given() {
        let inv = inventory();
        let visible = inv.hosts().filter(|h| h.groups.contains("web"));
        let picked = Selector::parse("*").unwrap().resolve(visible).unwrap();
        assert_eq!(names(&picked), ["web1", "web2"]);
        // a host that exists but is not among those offered is "nothing", like any other
        let visible = inv.hosts().filter(|h| h.groups.contains("web"));
        assert!(
            Selector::parse("db1.example.com")
                .unwrap()
                .resolve(visible)
                .is_err()
        );
    }

    #[test]
    fn malformed_selectors_are_refused() {
        for bad in [
            "",
            " ",
            ",",
            "web1,,web2",
            "-oProxyCommand=id",
            "web1 web2",
            "web1;id",
            "$(id)",
            "group:",
            "group:we b",
            "group:a/b",
            "user@web1",
            "web1\n",
            "../etc",
        ] {
            assert!(Selector::parse(bad).is_err(), "{bad:?} was accepted");
        }
        // what it says is safe to show: the term is quoted, control characters escaped
        let error = Selector::parse("web\u{1b}[31m").unwrap_err();
        assert!(!error.contains('\u{1b}'), "{error:?}");
    }

    #[test]
    fn a_selector_is_bounded() {
        let many = vec!["web1"; 65].join(",");
        assert!(Selector::parse(&many).is_err());
        let long = "a".repeat(300);
        assert!(Selector::parse(&long).is_err());
    }

    #[test]
    fn a_list_from_the_configuration_is_one_term_per_item() {
        let inv = inventory();
        let selector =
            Selector::parse_list(&["group:web".to_string(), "db1*".to_string()]).unwrap();
        let picked = selector.resolve(inv.hosts()).unwrap();
        assert_eq!(names(&picked), ["db1.example.com", "web1", "web2"]);
        assert!(selector.matches(inv.get("web1").unwrap()));
        assert!(!selector.matches(inv.get("db2.example.com").unwrap()));
        // an item is one term: a comma does not start another
        assert!(Selector::parse_list(&["web1,web2".to_string()]).is_err());
        assert!(Selector::parse_list(&[]).is_err());
    }

    #[test]
    fn terms_of_a_configured_list_that_pick_nothing_can_be_found() {
        let inv = inventory();
        let selector =
            Selector::parse_list(&["group:web".to_string(), "cache*".to_string()]).unwrap();
        assert_eq!(selector.unmatched(inv.hosts()), ["cache*"]);
    }

    // ---- an Ansible inventory ----

    /// What `ansible-inventory --list` prints: every host's variables under `_meta`,
    /// then one entry per group with its own hosts and its child groups.
    const ANSIBLE: &str = r#"{
        "_meta": {
            "hostvars": {
                "web1.example.com": {
                    "ansible_host": "10.0.0.11",
                    "ansible_port": 2222,
                    "ansible_user": "deploy",
                    "db_password": "hunter2",
                    "nested": {"ansible_host": "10.9.9.9", "list": [1, 2, {"a": null}]}
                },
                "db1.example.com": {"ansible_host": "db1.internal.example.com", "ansible_port": "2200"},
                "db2.example.com": {"ansible_host": "2001:db8::7"}
            },
            "profile": "inventory_legacy"
        },
        "all": {"children": ["ungrouped", "web", "db", "prod"]},
        "web": {"hosts": ["web1.example.com", "Web2.example.com"], "vars": {"http_port": 80}},
        "db": {"hosts": ["db1.example.com", "db2.example.com"]},
        "db_primary": {"hosts": ["db1.example.com"]},
        "prod": {"children": ["web", "db_primary"]},
        "ungrouped": {"hosts": ["bastion.example.com"]}
    }"#;

    fn ansible(text: &str) -> (Inventory, Vec<String>) {
        Inventory::from_ansible(text).unwrap_or_else(|e| panic!("{e:?}"))
    }

    fn groups_of<'a>(inv: &'a Inventory, host: &str) -> Vec<&'a str> {
        inv.get(host)
            .unwrap_or_else(|| panic!("{host} is missing"))
            .groups
            .iter()
            .map(String::as_str)
            .collect()
    }

    #[test]
    fn an_ansible_inventory_gives_hosts_with_their_addresses_and_ports() {
        let (inv, left_out) = ansible(ANSIBLE);
        assert_eq!(left_out, Vec::<String>::new());
        assert_eq!(inv.len(), 5);
        let web1 = inv.get("web1.example.com").unwrap();
        assert_eq!(web1.address, "10.0.0.11");
        assert_eq!(web1.ssh_port, Some(2222));
        // Ansible has no setting for the port opsmcp serves HTTPS on
        assert_eq!(web1.https_port, None);
        // a host with no variables of its own is reached by its name, in lower case
        let web2 = inv.get("web2.example.com").unwrap();
        assert_eq!(
            (web2.address.as_str(), web2.ssh_port),
            ("web2.example.com", None)
        );
        // a port may be written as text, and an address may be a name or an IPv6 address
        let db1 = inv.get("db1.example.com").unwrap();
        assert_eq!(
            (db1.address.as_str(), db1.ssh_port),
            ("db1.internal.example.com", Some(2200))
        );
        assert_eq!(inv.get("db2.example.com").unwrap().address, "2001:db8::7");
        assert_eq!(
            inv.get("bastion.example.com").unwrap().address,
            "bastion.example.com"
        );
    }

    #[test]
    fn an_ansible_group_holds_the_hosts_of_its_child_groups_too() {
        let (inv, _) = ansible(ANSIBLE);
        assert_eq!(groups_of(&inv, "web1.example.com"), ["all", "prod", "web"]);
        assert_eq!(
            groups_of(&inv, "db1.example.com"),
            ["all", "db", "db_primary", "prod"]
        );
        // db2 is in db, which prod does not include
        assert_eq!(groups_of(&inv, "db2.example.com"), ["all", "db"]);
        assert_eq!(groups_of(&inv, "bastion.example.com"), ["all", "ungrouped"]);
        // and the groups can be named in a selector, underscores and all
        assert_eq!(pick(&inv, "group:db_primary").unwrap(), ["db1.example.com"]);
        assert_eq!(pick(&inv, "group:prod").unwrap().len(), 3);
        assert_eq!(pick(&inv, "group:all").unwrap().len(), 5);
    }

    #[test]
    fn the_older_names_of_the_address_and_port_variables_are_understood() {
        let text = r#"{
            "_meta": {"hostvars": {
                "old1": {"ansible_ssh_host": "10.0.0.1", "ansible_ssh_port": 2022},
                "both1": {"ansible_ssh_host": "10.0.0.2", "ansible_host": "10.0.0.3",
                          "ansible_ssh_port": 1, "ansible_port": 2}
            }},
            "all": {"hosts": ["old1", "both1"]}
        }"#;
        let (inv, left_out) = ansible(text);
        assert_eq!(left_out, Vec::<String>::new());
        let old = inv.get("old1").unwrap();
        assert_eq!(
            (old.address.as_str(), old.ssh_port),
            ("10.0.0.1", Some(2022))
        );
        // the current names win
        let both = inv.get("both1").unwrap();
        assert_eq!(
            (both.address.as_str(), both.ssh_port),
            ("10.0.0.3", Some(2))
        );
    }

    #[test]
    fn a_host_that_only_has_variables_is_still_a_host() {
        let text = r#"{"_meta": {"hostvars": {"lonely1": {"ansible_host": "10.0.0.9"}}}}"#;
        let (inv, _) = ansible(text);
        assert_eq!(inv.get("lonely1").unwrap().address, "10.0.0.9");
        assert!(inv.get("lonely1").unwrap().groups.is_empty());
    }

    #[test]
    fn ansible_hosts_that_opsmcp_cannot_use_are_left_out_and_named() {
        // AIDEV-NOTE: an Ansible inventory is written for Ansible, so one odd entry in
        // it must not keep the whole fleet from starting: the entry is left out and
        // pointed out. Nothing is ever made of an entry that is not plainly usable.
        let text = r#"{
            "_meta": {"hostvars": {
                "web1": {},
                "web_2": {},
                "templated": {"ansible_host": "{{ inventory_hostname }}.internal"},
                "optioned": {"ansible_host": "-oProxyCommand=id"},
                "spaced": {"ansible_host": "10.0.0.1 -p 22"},
                "odd-address": {"ansible_host": ["10.0.0.1"]},
                "port0": {"ansible_port": 0},
                "port-big": {"ansible_port": 70000},
                "port-text": {"ansible_port": "ssh"},
                "port-frac": {"ansible_port": 22.5},
                "port-neg": {"ansible_port": -22},
                "DB9": {"ansible_host": "10.0.0.8"},
                "db9": {"ansible_host": "10.0.0.9"}
            }},
            "all": {"hosts": ["web1", "web_2", "templated", "optioned", "spaced", "odd-address",
                              "port0", "port-big", "port-text", "port-frac", "port-neg",
                              "DB9", "db9", "-oProxyCommand=id", "user@web3", "web 4"]}
        }"#;
        let (inv, left_out) = ansible(text);
        assert_eq!(
            inv.hosts().map(|h| h.name.as_str()).collect::<Vec<_>>(),
            ["web1"]
        );
        for (who, why) in [
            ("web_2", "name"),
            ("templated", "ansible_host"),
            ("optioned", "ansible_host"),
            ("spaced", "ansible_host"),
            ("odd-address", "ansible_host"),
            ("port0", "ansible_port"),
            ("port-big", "ansible_port"),
            ("port-text", "ansible_port"),
            ("port-frac", "ansible_port"),
            ("port-neg", "ansible_port"),
            // two spellings of one name: which machine "db9" means cannot be known
            ("db9", "more than one"),
            ("-oProxyCommand=id", "name"),
            ("user@web3", "name"),
            ("web 4", "name"),
        ] {
            assert!(
                left_out
                    .iter()
                    .any(|line| line.contains(who) && line.contains(why)),
                "{who} ({why}): {left_out:?}"
            );
        }
        assert_eq!(left_out.len(), 14, "{left_out:?}");
    }

    #[test]
    fn an_ansible_group_that_cannot_be_named_is_left_out_and_its_hosts_kept() {
        let text = r#"{
            "all": {"children": ["web", "tag:Name=web server"]},
            "web": {"hosts": ["web1"]},
            "tag:Name=web server": {"hosts": ["web1", "web2"]}
        }"#;
        let (inv, left_out) = ansible(text);
        assert_eq!(inv.len(), 2);
        assert_eq!(groups_of(&inv, "web1"), ["all", "web"]);
        assert_eq!(groups_of(&inv, "web2"), ["all"]);
        assert_eq!(left_out.len(), 1, "{left_out:?}");
        assert!(left_out[0].contains("tag:Name=web server") && left_out[0].contains("group"));
    }

    #[test]
    fn ansible_groups_that_loop_or_name_a_missing_child_do_no_harm() {
        let text = r#"{
            "a": {"hosts": ["web1"], "children": ["b", "nowhere"]},
            "b": {"hosts": ["web2"], "children": ["a", "b"]}
        }"#;
        let (inv, left_out) = ansible(text);
        assert_eq!(left_out, Vec::<String>::new());
        assert_eq!(groups_of(&inv, "web1"), ["a", "b"]);
        assert_eq!(groups_of(&inv, "web2"), ["a", "b"]);
    }

    /// `depth` groups, each holding the next, with one host in the last.
    fn nested(depth: usize) -> String {
        let mut groups: Vec<String> = (0..depth)
            .map(|n| format!("\"g{n}\": {{\"children\": [\"g{}\"]}}", n + 1))
            .collect();
        groups.push(format!("\"g{depth}\": {{\"hosts\": [\"web1\"]}}"));
        format!("{{{}}}", groups.join(", "))
    }

    #[test]
    fn ansible_groups_nested_beyond_reason_are_an_error_and_not_a_long_wait() {
        // AIDEV-NOTE: working out which hosts a group holds costs more the deeper the
        // groups are nested. Read again every few minutes inside a running server,
        // that must not be able to take minutes: it is given up on, and said.
        let (inv, _) = Inventory::from_ansible_within(&nested(20), 1000).unwrap();
        assert_eq!(inv.get("web1").unwrap().groups.len(), 21);
        let errors = Inventory::from_ansible_within(&nested(200), 1000).unwrap_err();
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(
            errors[0].contains("groups") && errors[0].contains("nested"),
            "{errors:?}"
        );
        // what an inventory of ordinary shape costs is far below what is allowed
        let (inv, _) = Inventory::from_ansible(&nested(200)).unwrap();
        assert_eq!(inv.get("web1").unwrap().groups.len(), 201);
    }

    #[test]
    fn many_unusable_ansible_entries_are_summed_up() {
        let names: Vec<String> = (0..60).map(|n| format!("\"bad_{n}\"")).collect();
        let text = format!(r#"{{"all": {{"hosts": ["web1", {}]}}}}"#, names.join(", "));
        let (inv, left_out) = ansible(&text);
        assert_eq!(inv.len(), 1);
        assert_eq!(left_out.len(), 21, "{left_out:?}");
        assert!(left_out[20].contains("40 more"), "{:?}", left_out[20]);
    }

    #[test]
    fn what_is_not_an_ansible_inventory_is_an_error() {
        for (text, needle) in [
            ("", "ansible-inventory --list"),
            ("not json", "ansible-inventory --list"),
            ("[]", "ansible-inventory --list"),
            // the shape of opsmcp's own inventory is not Ansible's
            (
                r#"{"groups": {"web": ["web1"]}}"#,
                "ansible-inventory --list",
            ),
            (r#"{"web": {"hosts": "web1"}}"#, "ansible-inventory --list"),
            // nothing in it that can be used
            ("{}", "no host"),
            (
                r#"{"_meta": {"hostvars": {}}, "all": {"children": ["ungrouped"]}}"#,
                "no host",
            ),
            (r#"{"all": {"hosts": ["web_1"]}}"#, "no host"),
        ] {
            let errors = Inventory::from_ansible(text).unwrap_err();
            assert!(
                errors.iter().any(|e| e.contains(needle)),
                "{text:?}: {errors:?}"
            );
        }
        // when nothing is usable, why is said as well
        let errors = Inventory::from_ansible(r#"{"all": {"hosts": ["web_1"]}}"#).unwrap_err();
        assert!(errors.iter().any(|e| e.contains("web_1")), "{errors:?}");
    }

    #[test]
    fn the_other_variables_of_an_ansible_host_are_never_repeated() {
        // `ansible-inventory --list` prints every variable of every host, passwords
        // included. None of that may end up in a message.
        let broken = r#"{
            "_meta": {"hostvars": {"web1": {"db_password": "hunter2", "ansible_port": 22}}},
            "web": {"hosts": {"db_password": "hunter2"}}
        }"#;
        let errors = Inventory::from_ansible(broken).unwrap_err();
        assert!(!format!("{errors:?}").contains("hunter2"), "{errors:?}");
        let odd = r#"{
            "_meta": {"hostvars": {"web_1": {"db_password": "hunter2"},
                                   "web2": {"ansible_host": "hunter2 hunter2"}}},
            "all": {"hosts": ["web_1", "web2", "web3"]}
        }"#;
        let (_, left_out) = ansible(odd);
        // what was written as the address is quoted (an operator has to find it); the
        // rest is not
        assert_eq!(
            format!("{left_out:?}").matches("hunter2").count(),
            2,
            "{left_out:?}"
        );
    }

    #[test]
    fn an_ansible_inventory_is_bounded() {
        let names: Vec<String> = (0..=MAX_HOSTS).map(|n| format!("\"h{n}\"")).collect();
        let text = format!(r#"{{"all": {{"hosts": [{}]}}}}"#, names.join(","));
        let errors = Inventory::from_ansible(&text).unwrap_err();
        assert!(errors[0].contains("at most"), "{errors:?}");
    }

    // ---- telling two inventories apart ----

    #[test]
    fn what_changed_between_two_inventories_is_told_apart() {
        let before = inventory();
        assert!(before.changes_to(&before).is_empty());
        let after = Inventory::parse(
            r#"
[hosts.web1]
address = "10.0.0.99"
groups = ["web", "prod"]
ssh_port = 2222

[hosts.web2]
groups = ["web", "canary"]

[hosts."db1.example.com"]
https_port = 9444

[hosts.cache1]

[groups]
db = ["db1.example.com"]
"#,
            Format::Toml,
        )
        .unwrap();
        let changes = before.changes_to(&after);
        assert_eq!(changes.added, ["cache1"]);
        assert_eq!(changes.removed, ["db2.example.com"]);
        // a different address or port: a session to the old one is no use
        assert_eq!(changes.moved, ["db1.example.com", "web1"]);
        assert_eq!(changes.regrouped, ["web2"]);
        assert!(!changes.is_empty());
    }
}
