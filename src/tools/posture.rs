//! A hardening summary.
//!
//! One screen, the same sections in the same order on every host, so that hosts can be
//! compared. Each line is a `[WARN]`, an `[ok]` or an `[info]`; the first line counts the
//! warnings.
//!
//! AIDEV-NOTE: like incident_snapshot this tool gathers what other tools own, so a
//! section whose content belongs to another permission (the firewall, pending updates,
//! the accounts, the listening ports) is produced only for a caller who holds that
//! permission in full. For anyone else nothing is run or read for it.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::args::Args;
use super::net::{address_of, parse_socket, port_of};
use super::package::{parse_simulation, read_small};
use super::users::{PasswordState, Shadow, parse_group, parse_passwd, parse_shadow};
use super::{CallClock, Ctx, Tool, ToolError, ToolResult, blocking, command_ok, command_text};
use crate::config::is_account_name;
use crate::exec::CmdOutput;
use crate::policy::Access;
use crate::sanitize::keep_head;
use crate::timefmt::now_secs;

/// Where the facts are read from. A parameter so that tests can use a temporary
/// directory; the server always uses `Roots::default()`.
#[derive(Clone, Debug)]
pub struct Roots {
    pub passwd: PathBuf,
    pub group: PathBuf,
    pub shadow: PathBuf,
    /// apt's configuration snippets, where unattended upgrades are switched on.
    pub apt_conf_dir: PathBuf,
    /// Exists when an installed update needs a reboot (Debian, Ubuntu).
    pub reboot_required: PathBuf,
    pub selinux_config: PathBuf,
    /// `/proc/sys`.
    pub proc_sys: PathBuf,
    /// `/sys`.
    pub sys: PathBuf,
    /// Touched by apt each time the package lists are refreshed successfully.
    pub lists_stamp: PathBuf,
    /// The package lists themselves: used when there is no stamp.
    pub lists_dir: PathBuf,
    /// Where dnf and yum keep the repository data they have fetched.
    pub rpm_caches: Vec<PathBuf>,
}

impl Default for Roots {
    fn default() -> Self {
        Roots {
            passwd: PathBuf::from("/etc/passwd"),
            group: PathBuf::from("/etc/group"),
            shadow: PathBuf::from("/etc/shadow"),
            apt_conf_dir: PathBuf::from("/etc/apt/apt.conf.d"),
            reboot_required: PathBuf::from("/var/run/reboot-required"),
            selinux_config: PathBuf::from("/etc/selinux/config"),
            proc_sys: PathBuf::from("/proc/sys"),
            sys: PathBuf::from("/sys"),
            lists_stamp: PathBuf::from("/var/lib/apt/periodic/update-success-stamp"),
            lists_dir: PathBuf::from("/var/lib/apt/lists"),
            rpm_caches: vec![
                PathBuf::from("/var/cache/dnf"),
                PathBuf::from("/var/cache/yum"),
            ],
        }
    }
}

pub fn tools() -> Vec<Tool> {
    tools_with(Roots::default())
}

pub fn tools_with(roots: Roots) -> Vec<Tool> {
    let roots = Arc::new(roots);
    vec![Tool::new(
        "security_posture",
        "One-screen hardening summary of this host, in the same shape on every host so \
         that hosts can be compared: the effective sshd settings, whether a firewall is in \
         place, pending security updates and whether a reboot is needed, risky accounts, \
         AppArmor or SELinux, kernel hardening settings and CPU vulnerabilities, and the \
         ports that listen beyond loopback. Each line is [WARN], [ok] or [info]; the first \
         line counts the warnings. A section whose content belongs to another permission \
         is left out unless the caller holds it. It reports; it changes nothing.",
        Access::Read,
        "security.view",
        vec![],
        move |ctx, args| security_posture(ctx, args, roots.clone()),
    )]
}

/// How much a finding matters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Warn,
    Ok,
    Info,
    /// The check could not be made.
    Unchecked,
}

/// One line of the summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub level: Level,
    pub text: String,
}

impl Finding {
    pub fn render(&self) -> String {
        let label = match self.level {
            Level::Warn => "[WARN]",
            Level::Ok => "[ok]",
            Level::Info => "[info]",
            Level::Unchecked => "[not checked]",
        };
        format!("{label} {}", self.text)
    }
}

fn warn(text: impl Into<String>) -> Finding {
    Finding {
        level: Level::Warn,
        text: text.into(),
    }
}

fn fine(text: impl Into<String>) -> Finding {
    Finding {
        level: Level::Ok,
        text: text.into(),
    }
}

fn info(text: impl Into<String>) -> Finding {
    Finding {
        level: Level::Info,
        text: text.into(),
    }
}

fn unchecked(text: impl Into<String>) -> Finding {
    Finding {
        level: Level::Unchecked,
        text: text.into(),
    }
}

/// Most characters of something a program or a file said that are repeated.
const MAX_SAID: usize = 160;

/// One line of what a program or a kernel file said, made safe to repeat: printable
/// ASCII only, and not long.
fn said(text: &str) -> String {
    let line = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("");
    let plain: String = line
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .take(MAX_SAID)
        .collect();
    if plain.is_empty() {
        "it said nothing".to_string()
    } else {
        plain
    }
}

fn count(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

/// A list of names for one line: the first `most`, then how many more there are.
fn name_list(names: &[String], most: usize) -> String {
    let shown: Vec<&str> = names.iter().take(most).map(String::as_str).collect();
    match names.len().saturating_sub(shown.len()) {
        0 => shown.join(", "),
        more => format!("{} and {more} more", shown.join(", ")),
    }
}

// ---- ssh --------------------------------------------------------------------------------

/// A value of an sshd setting that can be repeated as it is: a word, a number, or a
/// user or group pattern.
fn plain_ssh_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.@:/,+*?!-".contains(c))
}

/// `sshd -T` output (the effective settings) as findings.
///
/// AIDEV-NOTE: sshd prints every setting, one `keyword value...` per line, the keyword
/// in lower case. Only the handful that matter are looked at, and a value is repeated
/// only if it is one of the values that setting can have (or, for the allow lists, a
/// plain pattern): this text ends up in the tool's own lines.
///
/// AIDEV-NOTE: AllowUsers and AllowGroups hold account and group names, which belong to
/// `user.view`. `show_names` is whether the caller holds it; without it only the number
/// of entries is shown, as every other part of this tool keeps to the permission that
/// owns its data.
pub fn ssh_findings(effective: &str, show_names: bool) -> Vec<Finding> {
    let mut settings: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for line in effective.lines().take(2000) {
        let mut words = line.split_whitespace();
        let Some(keyword) = words.next() else {
            continue;
        };
        if keyword
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        {
            settings.entry(keyword).or_default().extend(words);
        }
    }
    let single = |keyword: &str, allowed: &[&str]| -> Option<&str> {
        let value = settings.get(keyword)?.first().copied()?;
        allowed.contains(&value).then_some(value)
    };
    let yes_no = ["yes", "no"];
    let known = [
        "permitrootlogin",
        "passwordauthentication",
        "permitemptypasswords",
        "pubkeyauthentication",
        "maxauthtries",
    ];
    if !known.iter().any(|keyword| settings.contains_key(keyword)) {
        return vec![unchecked(
            "sshd -T did not print its settings (it needs to run as root)",
        )];
    }

    let mut findings = Vec::new();
    let root_values = [
        "yes",
        "no",
        "prohibit-password",
        "without-password",
        "forced-commands-only",
    ];
    match single("permitrootlogin", &root_values) {
        Some("yes") => findings.push(warn(
            "PermitRootLogin yes: root may log in directly, with a password if passwords are accepted",
        )),
        Some(value) => findings.push(fine(format!("PermitRootLogin {value}"))),
        None => {}
    }
    match single("passwordauthentication", &yes_no) {
        Some("yes") => findings.push(warn(
            "PasswordAuthentication yes: passwords are accepted, which invites guessing; keys only is safer",
        )),
        Some(value) => findings.push(fine(format!("PasswordAuthentication {value}"))),
        None => {}
    }
    match single("permitemptypasswords", &yes_no) {
        Some("yes") => findings.push(warn(
            "PermitEmptyPasswords yes: an account with an empty password can log in",
        )),
        Some(value) => findings.push(fine(format!("PermitEmptyPasswords {value}"))),
        None => {}
    }
    // Called ChallengeResponseAuthentication before OpenSSH 8.7.
    let keyboard_interactive = single("kbdinteractiveauthentication", &yes_no)
        .or_else(|| single("challengeresponseauthentication", &yes_no));
    // AIDEV-NOTE: `PasswordAuthentication no` does not by itself stop password logins.
    // With keyboard-interactive authentication on and UsePAM yes, sshd hands the
    // conversation to PAM, whose usual stack asks for the account's password. Only an
    // AuthenticationMethods line that names the methods allowed rules that out (sshd -T
    // prints `any` when there is none). Without this check the green line above says
    // the opposite of what is true.
    let methods_restricted = settings
        .get("authenticationmethods")
        .is_some_and(|methods| !methods.is_empty() && methods.as_slice() != ["any"]);
    if single("passwordauthentication", &yes_no) == Some("no")
        && keyboard_interactive == Some("yes")
        && single("usepam", &yes_no) == Some("yes")
        && !methods_restricted
    {
        findings.push(warn(
            "PasswordAuthentication is no, but passwords may still be accepted: \
             KbdInteractiveAuthentication yes with UsePAM yes lets PAM ask for one; set \
             KbdInteractiveAuthentication no, or name the methods in AuthenticationMethods",
        ));
    }
    if let Some(value) = keyboard_interactive {
        findings.push(info(format!("KbdInteractiveAuthentication {value}")));
    }
    if let Some(value) = single("pubkeyauthentication", &yes_no) {
        findings.push(info(format!("PubkeyAuthentication {value}")));
    }
    if let Some(tries) = settings
        .get("maxauthtries")
        .and_then(|values| values.first())
        .filter(|value| value.len() <= 4 && value.bytes().all(|b| b.is_ascii_digit()))
    {
        findings.push(info(format!("MaxAuthTries {tries}")));
    }
    let mut any_allow_list = false;
    for (keyword, shown) in [("allowusers", "AllowUsers"), ("allowgroups", "AllowGroups")] {
        let Some(values) = settings.get(keyword) else {
            continue;
        };
        any_allow_list = true;
        if !show_names {
            findings.push(info(format!(
                "{shown} is set ({}; the names need user.view)",
                if values.len() == 1 {
                    "1 entry".to_string()
                } else {
                    format!("{} entries", values.len())
                }
            )));
            continue;
        }
        let plain: Vec<&str> = values
            .iter()
            .copied()
            .filter(|value| plain_ssh_value(value))
            .collect();
        let hidden = values.len().saturating_sub(plain.len());
        let mut text = format!(
            "{shown} {}",
            plain.iter().take(20).copied().collect::<Vec<_>>().join(" ")
        );
        let more = plain.len().saturating_sub(20).saturating_add(hidden);
        if more > 0 {
            text.push_str(&format!(" and {more} more"));
        }
        findings.push(info(text));
    }
    if !any_allow_list {
        findings.push(info(
            "no AllowUsers or AllowGroups: any account that can authenticate may log in",
        ));
    }
    findings.push(info(
        "Match blocks are not evaluated: settings inside them can differ for some users or addresses",
    ));
    findings
}

// ---- firewall ---------------------------------------------------------------------------

/// One chain that sees incoming traffic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputChain {
    /// `FAMILY TABLE/CHAIN`.
    pub name: String,
    pub policy: String,
    pub rules: usize,
}

/// What `nft list ruleset` shows, as far as a summary needs it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NftRuleset {
    pub tables: usize,
    /// Rules in all chains.
    pub rules: usize,
    pub input: Vec<InputChain>,
}

/// A table or chain name from the ruleset, if it is one that can be repeated.
fn plain_name(name: &str) -> &str {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c));
    if ok { name } else { "?" }
}

/// Reads the output of `nft list ruleset`: how many tables and rules there are, and for
/// each chain hooked to `input` its policy and how many rules it has.
///
/// The listing is nested with braces: `table F NAME {`, inside it `chain NAME {`, and
/// inside that the hook line and one rule per line. Sets and maps are blocks too, and a
/// list of elements may run over several lines, so depth is counted by the braces on
/// each line rather than assumed.
pub fn parse_nft_ruleset(text: &str) -> NftRuleset {
    struct Chain {
        name: String,
        hook: Option<String>,
        policy: Option<String>,
        rules: usize,
    }
    let mut ruleset = NftRuleset::default();
    let mut depth = 0usize;
    let mut table = String::new();
    let mut chain: Option<Chain> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        let words: Vec<&str> = trimmed.split_whitespace().collect();
        match (depth, words.as_slice()) {
            (0, ["table", family, name, ..]) => {
                ruleset.tables = ruleset.tables.saturating_add(1);
                table = format!("{} {}", plain_name(family), plain_name(name));
            }
            (1, ["chain", name, ..]) => {
                chain = Some(Chain {
                    name: plain_name(name).to_string(),
                    hook: None,
                    policy: None,
                    rules: 0,
                });
            }
            (2, ["type", ..]) if chain.is_some() && words.contains(&"hook") => {
                if let Some(chain) = chain.as_mut() {
                    chain.hook = words
                        .iter()
                        .position(|word| *word == "hook")
                        .and_then(|at| words.get(at.saturating_add(1)))
                        .map(|hook| hook.trim_end_matches(';').to_string());
                    chain.policy = words
                        .iter()
                        .position(|word| *word == "policy")
                        .and_then(|at| words.get(at.saturating_add(1)))
                        .map(|policy| policy.trim_end_matches(';').to_string());
                }
            }
            (2, [first, ..]) if *first != "}" => {
                if let Some(chain) = chain.as_mut() {
                    chain.rules = chain.rules.saturating_add(1);
                    ruleset.rules = ruleset.rules.saturating_add(1);
                }
            }
            _ => {}
        }
        let opens = trimmed.matches('{').count();
        let closes = trimmed.matches('}').count();
        depth = depth.saturating_add(opens).saturating_sub(closes);
        if depth <= 1
            && let Some(done) = chain.take()
            && done.hook.as_deref() == Some("input")
        {
            let policy = match done.policy.as_deref() {
                Some("drop") => "drop",
                // a base chain without a stated policy accepts
                Some("accept") | None => "accept",
                Some(_) => "?",
            };
            ruleset.input.push(InputChain {
                name: format!("{table}/{}", done.name),
                policy: policy.to_string(),
                rules: done.rules,
            });
        }
    }
    ruleset
}

/// The policy of iptables' INPUT chain and the number of rules in it, from
/// `iptables -S INPUT`.
pub fn parse_iptables_input(text: &str) -> Option<(String, usize)> {
    let mut lines = text.lines();
    let policy = lines.next()?.strip_prefix("-P INPUT ")?.trim();
    let plain =
        !policy.is_empty() && policy.len() <= 16 && policy.bytes().all(|b| b.is_ascii_uppercase());
    if !plain {
        return None;
    }
    let rules = lines.filter(|line| line.starts_with("-A INPUT")).count();
    Some((policy.to_string(), rules))
}

/// The firewall findings, from whichever of the two views there is.
///
/// AIDEV-NOTE: the one warning is for a host with no rule at all whose input policy
/// accepts: nothing stands between the network and what listens. An accepting policy
/// WITH rules is only information, because whether traffic is refused then depends on
/// rules this summary does not try to understand (a final `reject`, as ufw and
/// firewalld write, is as good as a dropping policy).
pub fn firewall_findings(
    nft: Option<&NftRuleset>,
    iptables: Option<&(String, usize)>,
) -> Vec<Finding> {
    if nft.is_none() && iptables.is_none() {
        return vec![unchecked("the packet filter could not be looked at")];
    }
    let input: &[InputChain] = nft.map_or(&[], |ruleset| ruleset.input.as_slice());
    let nft_rules = nft.map_or(0, |ruleset| ruleset.rules);
    let nft_filters = input
        .iter()
        .any(|chain| chain.policy != "accept" || chain.rules > 0);
    let iptables_filters = iptables.is_some_and(|(policy, rules)| policy != "ACCEPT" || *rules > 0);
    if !nft_filters && !iptables_filters && nft_rules == 0 {
        return vec![warn(
            "no firewall: no rule is loaded and incoming traffic is accepted",
        )];
    }
    let rules = |n: usize| match n {
        0 => "no rules".to_string(),
        n => count(n, "rule", "rules"),
    };
    let mut findings = Vec::new();
    for chain in input {
        let text = format!(
            "nftables: {}: policy {}, {}",
            chain.name,
            chain.policy,
            rules(chain.rules)
        );
        if chain.policy == "drop" {
            findings.push(fine(text));
        } else if chain.rules > 0 {
            findings.push(info(format!(
                "{text} (what is refused depends on the rules)"
            )));
        } else {
            findings.push(info(text));
        }
    }
    if let Some((policy, count)) = iptables {
        let text = format!("iptables: INPUT policy {policy}, {}", rules(*count));
        if policy != "ACCEPT" {
            findings.push(fine(text));
        } else if *count > 0 {
            findings.push(info(format!(
                "{text} (what is refused depends on the rules)"
            )));
        } else {
            findings.push(info(text));
        }
    }
    if input.is_empty() && iptables.is_none() {
        findings.push(info(format!(
            "nftables: no chain filters incoming traffic ({} in other chains)",
            rules(nft_rules)
        )));
    }
    findings
}

// ---- updates ----------------------------------------------------------------------------

/// Pending updates from a simulated `apt-get dist-upgrade`.
pub fn apt_update_findings(simulation: &str) -> Vec<Finding> {
    let (pending, _removals) = parse_simulation(simulation);
    let security = pending.iter().filter(|update| update.security).count();
    let total = pending.len();
    let are = |n: usize| if n == 1 { "is" } else { "are" };
    let finding = if security > 0 {
        warn(format!(
            "{} {} pending ({} in all)",
            count(security, "security update", "security updates"),
            are(security),
            count(total, "update", "updates")
        ))
    } else if total > 0 {
        info(format!(
            "{} {} pending, none of them marked as a security update",
            count(total, "update", "updates"),
            are(total)
        ))
    } else {
        fine("no updates are pending")
    };
    vec![finding]
}

/// The quoted value a line of apt configuration gives the setting `key` under
/// `APT::Periodic`: written in full (`APT::Periodic::KEY "1";`) or, where `bare` allows
/// it, as it stands inside an `APT::Periodic { }` block (`KEY "1";`).
fn periodic_value<'a>(line: &'a str, key: &str, bare: bool) -> Option<&'a str> {
    let at = line.find(key)?;
    let before = line.get(..at)?;
    if !(before.ends_with("APT::Periodic::") || (bare && before.is_empty())) {
        return None;
    }
    let rest = line.get(at.saturating_add(key.len())..)?;
    // the name must end here: this is `KEY "1"`, not `KEY-Something "1"`
    if !rest.starts_with([' ', '\t', '"']) {
        return None;
    }
    let mut quoted = rest.split('"');
    quoted.next()?;
    let value = quoted.next()?.trim();
    (!value.is_empty()).then_some(value)
}

/// Whether apt's configuration switches unattended upgrades on. `files` are the
/// snippets as (name, text); the last one that sets it, in name order, decides.
/// `APT::Periodic::Enable "0"` (container images ship it) switches all of apt's
/// periodic work off, unattended upgrades included.
pub fn unattended_upgrades(files: &[(String, String)]) -> Option<bool> {
    let mut ordered: Vec<&(String, String)> = files.iter().collect();
    ordered.sort_by(|a, b| a.0.cmp(&b.0));
    let (mut unattended, mut enabled) = (None, None);
    for (_name, text) in ordered {
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with("//") || line.starts_with('#') {
                continue;
            }
            if let Some(value) = periodic_value(line, "Unattended-Upgrade", true) {
                unattended = Some(value != "0");
            }
            if let Some(value) = periodic_value(line, "Enable", false) {
                enabled = Some(value != "0");
            }
        }
    }
    unattended.map(|on| on && enabled != Some(false))
}

// ---- accounts ---------------------------------------------------------------------------

/// A name for an account in a line of ours: the name itself if it is a plain one.
fn account_label(name: &str) -> String {
    if is_account_name(name) {
        name.to_string()
    } else {
        "an account whose name is not a plain one".to_string()
    }
}

/// Findings about the accounts. `shadow` is `None` when the shadow file cannot be read.
///
/// AIDEV-NOTE: nothing here can show a password hash. `Shadow` does not hold one (see
/// `users.rs`), and of the passwd file's password field only "is it empty" is looked at.
pub fn account_findings(
    passwd: &str,
    group: &str,
    shadow: Option<&HashMap<String, Shadow>>,
) -> Vec<Finding> {
    let accounts = parse_passwd(passwd);
    let mut findings = Vec::new();

    let extra_roots: Vec<&str> = accounts
        .iter()
        .filter(|account| account.uid == 0 && account.name != "root")
        .map(|account| account.name.as_str())
        .collect();
    if extra_roots.is_empty() {
        findings.push(fine("root is the only account with uid 0"));
    }
    for name in extra_roots.iter().take(10) {
        findings.push(warn(format!(
            "{} has uid 0 as well as root: it is root under another name",
            account_label(name)
        )));
    }

    // An empty second field in passwd means "no password", whatever shadow says.
    let mut open = 0usize;
    for line in passwd.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if let [name, password, _uid, _gid, _gecos, _home, _shell] = fields.as_slice()
            && password.is_empty()
            && !name.is_empty()
            && !name.starts_with(['#', '+', '-'])
            && open < 10
        {
            open = open.saturating_add(1);
            findings.push(warn(format!(
                "{} has an empty password field in the passwd file: it needs no password",
                account_label(name)
            )));
        }
    }
    match shadow {
        Some(shadow) => {
            let mut empty: Vec<&str> = accounts
                .iter()
                .filter(|account| {
                    shadow
                        .get(&account.name)
                        .is_some_and(|entry| entry.state == PasswordState::None)
                })
                .map(|account| account.name.as_str())
                .collect();
            empty.sort_unstable();
            for name in empty.iter().take(10) {
                findings.push(warn(format!(
                    "{} has an empty password: it needs no password",
                    account_label(name)
                )));
            }
            if empty.is_empty() && open == 0 {
                findings.push(fine("no account has an empty password"));
            }
        }
        None => findings.push(unchecked(
            "empty passwords were not looked for: the shadow file cannot be read by the server's user",
        )),
    }

    // Who may use sudo by being in one of the usual groups (sudoers rules that name
    // users directly are not read here; user_list shows them per user).
    let mut members: BTreeSet<String> = BTreeSet::new();
    for entry in parse_group(group) {
        if !["sudo", "wheel", "admin"].contains(&entry.name.as_str()) {
            continue;
        }
        members.extend(entry.members.iter().cloned());
        members.extend(
            accounts
                .iter()
                .filter(|account| account.gid == entry.gid)
                .map(|account| account.name.clone()),
        );
    }
    let members: Vec<String> = members
        .into_iter()
        .filter(|name| is_account_name(name))
        .collect();
    if members.is_empty() {
        findings.push(info("nobody is in the sudo, wheel or admin group"));
    } else {
        findings.push(info(format!(
            "may use sudo through the sudo, wheel or admin group: {}",
            name_list(&members, 30)
        )));
    }
    findings
}

// ---- mandatory access control -----------------------------------------------------------

/// What the kernel says about mandatory access control.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MacFacts {
    /// `/sys/module/apparmor/parameters/enabled`.
    pub apparmor_enabled: Option<String>,
    /// `/sys/kernel/security/apparmor/profiles`, when it can be read.
    pub apparmor_profiles: Option<String>,
    /// `/sys/fs/selinux/enforce`.
    pub selinux_enforce: Option<String>,
    /// `/etc/selinux/config`.
    pub selinux_config: Option<String>,
}

pub fn mac_findings(facts: &MacFacts) -> Vec<Finding> {
    let mut findings = Vec::new();
    if facts.apparmor_enabled.as_deref().map(str::trim) == Some("Y") {
        match &facts.apparmor_profiles {
            Some(profiles) => {
                let ending = |mode: &str| {
                    profiles
                        .lines()
                        .filter(|line| line.trim_end().ends_with(mode))
                        .count()
                };
                let (enforce, complain) = (ending("(enforce)"), ending("(complain)"));
                let mut text = format!(
                    "AppArmor is on: {}",
                    match enforce {
                        1 => "1 profile enforces".to_string(),
                        n => format!("{n} profiles enforce"),
                    }
                );
                match complain {
                    0 => {}
                    1 => text.push_str(", 1 only complains"),
                    n => text.push_str(&format!(", {n} only complain")),
                }
                findings.push(fine(text));
            }
            None => findings.push(fine(
                "AppArmor is on (its list of profiles can only be read by root)",
            )),
        }
    }
    match facts.selinux_enforce.as_deref().map(str::trim) {
        Some("1") => findings.push(fine("SELinux is enforcing")),
        Some("0") => findings.push(warn(
            "SELinux is present but permissive: what it would refuse is only logged",
        )),
        Some(_) => {}
        None => {
            // Not active in the running kernel. Is that because it was switched off?
            let configured = facts.selinux_config.as_deref().and_then(|config| {
                config
                    .lines()
                    .map(str::trim)
                    .find_map(|line| line.strip_prefix("SELINUX="))
            });
            if configured.map(str::trim) == Some("disabled") {
                findings.push(warn(
                    "SELinux is installed but disabled (SELINUX=disabled in its configuration)",
                ));
            }
        }
    }
    if findings.is_empty() {
        findings.push(info("neither AppArmor nor SELinux is active"));
    }
    findings
}

/// An age in the largest unit that fits: `23d`, `3h`, `12m`.
fn coarse_age(secs: u64) -> String {
    if secs >= 2 * 86_400 {
        format!("{}d", secs / 86_400)
    } else if secs >= 3600 {
        format!("{}h", secs / 3600)
    } else if secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        "under a minute".to_string()
    }
}

/// How old the package lists may be before the counts made from them are doubted.
const LISTS_STALE_SECS: u64 = 7 * 86_400;

/// What to say about the age of the package lists (`None`: it could not be told).
///
/// AIDEV-NOTE: the counts of pending updates are worked out from the package lists as
/// they were last fetched; this tool never refreshes them. "No updates are pending"
/// from lists that are months old means little, so their age is always said.
pub fn lists_age_finding(age_secs: Option<u64>) -> Finding {
    match age_secs {
        None => info("it is not known when the package lists were last refreshed"),
        Some(age) if age > LISTS_STALE_SECS => info(format!(
            "the package lists were last refreshed {} ago: the counts of pending updates \
             may be out of date (package_upgrade with refresh updates the lists)",
            coarse_age(age)
        )),
        Some(age) => info(format!(
            "the package lists were last refreshed {} ago",
            coarse_age(age)
        )),
    }
}

/// When a path was last modified, in Unix seconds. A link is not followed.
fn modified(path: &Path) -> Option<i64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path)
        .ok()
        .map(|meta| meta.mtime())
}

/// The modification time of the newest regular file under `dirs` (three levels deep at
/// most, and a bounded number of entries): for dnf and yum, when repository data was
/// last fetched.
pub fn newest_file(dirs: &[PathBuf]) -> Option<i64> {
    use std::os::unix::fs::MetadataExt;
    const MAX_ENTRIES: usize = 5000;
    const MAX_DEPTH: usize = 3;
    let mut newest: Option<i64> = None;
    let mut seen = 0usize;
    let mut pending: Vec<(PathBuf, usize)> = dirs.iter().map(|dir| (dir.clone(), 1)).collect();
    while let Some((dir, depth)) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            seen = seen.saturating_add(1);
            if seen > MAX_ENTRIES {
                return newest;
            }
            // symlink_metadata: a link is neither followed nor counted
            let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
                continue;
            };
            if meta.is_file() {
                newest = Some(newest.map_or(meta.mtime(), |so_far| so_far.max(meta.mtime())));
            } else if meta.is_dir() && depth < MAX_DEPTH {
                pending.push((entry.path(), depth.saturating_add(1)));
            }
        }
    }
    newest
}

// ---- kernel -----------------------------------------------------------------------------

/// The settings read from `/proc/sys`, by dotted name.
const SYSCTLS: [&str; 8] = [
    "kernel.randomize_va_space",
    "fs.protected_symlinks",
    "fs.protected_hardlinks",
    "kernel.kptr_restrict",
    "kernel.dmesg_restrict",
    "kernel.yama.ptrace_scope",
    "kernel.unprivileged_bpf_disabled",
    "fs.suid_dumpable",
];

/// Findings about the kernel: `vulnerabilities` are the files of
/// `/sys/devices/system/cpu/vulnerabilities` as (name, text), `sysctls` the values read
/// from `/proc/sys` by dotted name.
pub fn kernel_findings(
    vulnerabilities: &[(String, String)],
    sysctls: &BTreeMap<String, String>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let plain_name = |name: &str| {
        !name.is_empty()
            && name.len() <= 40
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    };
    let mut known: Vec<&(String, String)> = vulnerabilities
        .iter()
        .filter(|(name, _)| plain_name(name))
        .collect();
    known.sort_by(|a, b| a.0.cmp(&b.0));
    let vulnerable: Vec<&&(String, String)> = known
        .iter()
        .filter(|(_, text)| text.trim_start().starts_with("Vulnerable"))
        .collect();
    for (name, text) in vulnerable.iter().map(|entry| (&entry.0, &entry.1)) {
        findings.push(warn(format!("CPU vulnerability {name}: {}", said(text))));
    }
    // AIDEV-NOTE: neither vulnerable nor a clean bill: a mitigation is on but the kernel
    // names something still open ("Mitigation: Clear CPU buffers; SMT vulnerable"), or
    // it does not know ("Unknown: ..."). These used to be counted as mitigated. They
    // are information, not a warning: the kernel has done what it can on this hardware.
    let partly: Vec<&&(String, String)> = known
        .iter()
        .filter(|(_, text)| {
            let text = text.trim_start();
            !text.starts_with("Vulnerable")
                && (text.starts_with("Unknown") || text.to_ascii_lowercase().contains("vulnerable"))
        })
        .collect();
    if !partly.is_empty() {
        let named: Vec<String> = partly
            .iter()
            .take(8)
            .map(|entry| format!("{} ({})", entry.0, said(&entry.1)))
            .collect();
        let more = partly.len().saturating_sub(named.len());
        let mut text = format!(
            "{} only partly mitigated or unknown: {}",
            match partly.len() {
                1 => "1 CPU vulnerability is".to_string(),
                n => format!("{n} CPU vulnerabilities are"),
            },
            named.join(", ")
        );
        if more > 0 {
            text.push_str(&format!(" and {more} more"));
        }
        findings.push(info(text));
    }
    let handled = known
        .len()
        .saturating_sub(vulnerable.len())
        .saturating_sub(partly.len());
    if handled > 0 {
        let other = if vulnerable.is_empty() && partly.is_empty() {
            ""
        } else {
            "other "
        };
        findings.push(fine(match handled {
            1 => format!("1 {other}CPU vulnerability is mitigated or does not affect this CPU"),
            n => format!("{n} {other}CPU vulnerabilities are mitigated or do not affect this CPU"),
        }));
    }

    // A value is a small number; anything else is not repeated.
    let value = |name: &str| -> Option<&str> {
        let value = sysctls.get(name)?.trim();
        (!value.is_empty() && value.len() <= 6 && value.bytes().all(|b| b.is_ascii_digit()))
            .then_some(value)
    };
    if let Some(aslr) = value("kernel.randomize_va_space") {
        if aslr == "2" {
            findings.push(fine("kernel.randomize_va_space is 2"));
        } else {
            findings.push(warn(format!(
                "kernel.randomize_va_space is {aslr}: address space layout randomisation is not fully on"
            )));
        }
    }
    for name in ["fs.protected_symlinks", "fs.protected_hardlinks"] {
        match value(name) {
            Some("0") => findings.push(warn(format!(
                "{name} is 0: links in shared directories such as /tmp can be used to trick privileged programs"
            ))),
            Some(set) => findings.push(fine(format!("{name} is {set}"))),
            None => {}
        }
    }
    let others: Vec<String> = [
        "kernel.kptr_restrict",
        "kernel.dmesg_restrict",
        "kernel.yama.ptrace_scope",
        "kernel.unprivileged_bpf_disabled",
        "fs.suid_dumpable",
    ]
    .iter()
    .filter_map(|name| value(name).map(|set| format!("{name}={set}")))
    .collect();
    if !others.is_empty() {
        findings.push(info(others.join(", ")));
    }
    if findings.is_empty() {
        findings.push(unchecked("nothing about the kernel could be read"));
    }
    findings
}

// ---- listening --------------------------------------------------------------------------

/// Most ports listed.
const MAX_PORTS: usize = 30;

/// True when a listening address is one only this host can reach.
fn is_loopback(address: &str) -> bool {
    // `127.0.0.53%lo`, `[::1]`: the interface and the brackets are decoration.
    let address = address.split('%').next().unwrap_or(address);
    let address = address.trim_start_matches('[').trim_end_matches(']');
    address
        .parse::<IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}

/// What listens on an address other than loopback, from `ss -H -ltnu`.
pub fn listening_findings(sockets: &str) -> Vec<Finding> {
    let mut open: BTreeSet<(String, u16)> = BTreeSet::new();
    for line in sockets.lines().take(20_000) {
        let Some(socket) = parse_socket(line, "tcp") else {
            continue;
        };
        let Some(port) = port_of(&socket.local) else {
            continue;
        };
        let protocol = match socket.netid.as_str() {
            "tcp" | "udp" => socket.netid,
            _ => continue,
        };
        if !is_loopback(address_of(&socket.local)) {
            open.insert((protocol, port));
        }
    }
    if open.is_empty() {
        return vec![fine("nothing listens on an address other than loopback")];
    }
    let mut parts: Vec<String> = Vec::new();
    let mut shown = 0usize;
    for protocol in ["tcp", "udp"] {
        let ports: Vec<String> = open
            .iter()
            .filter(|(p, _)| p == protocol)
            .map(|(_, port)| port.to_string())
            .take(MAX_PORTS.saturating_sub(shown))
            .collect();
        if !ports.is_empty() {
            shown = shown.saturating_add(ports.len());
            parts.push(format!("{protocol} {}", ports.join(", ")));
        }
    }
    let mut text = format!("listening beyond loopback: {}", parts.join("; "));
    let more = open.len().saturating_sub(shown);
    if more > 0 {
        text.push_str(&format!(" and {more} more"));
    }
    vec![info(text)]
}

// ---- the summary ------------------------------------------------------------------------

/// One section of the summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub title: &'static str,
    /// `Err` holds the permission whose absence left the section out.
    pub findings: Result<Vec<Finding>, &'static str>,
}

/// The first line: how many warnings, and which.
pub fn verdict(sections: &[Section]) -> String {
    let mut warnings: Vec<String> = Vec::new();
    let (mut left_out, mut not_made) = (0usize, 0usize);
    for section in sections {
        match &section.findings {
            Err(_) => left_out = left_out.saturating_add(1),
            Ok(findings) => {
                for finding in findings {
                    match finding.level {
                        Level::Warn => {
                            let text: String = finding.text.chars().take(100).collect();
                            warnings.push(format!("{}: {text}", section.title));
                        }
                        Level::Unchecked => not_made = not_made.saturating_add(1),
                        Level::Ok | Level::Info => {}
                    }
                }
            }
        }
    }
    let mut gaps = Vec::new();
    if left_out > 0 {
        gaps.push(format!(
            "{} left out",
            count(left_out, "section", "sections")
        ));
    }
    if not_made > 0 {
        gaps.push(format!("{} not made", count(not_made, "check", "checks")));
    }
    let gaps = match gaps.is_empty() {
        true => String::new(),
        false => format!(" ({})", gaps.join(", ")),
    };
    if warnings.is_empty() {
        return if gaps.is_empty() {
            "No warnings.".to_string()
        } else {
            format!("No warnings in what was checked{gaps}")
        };
    }
    let mut line = format!(
        "{}: {}",
        count(warnings.len(), "warning", "warnings"),
        warnings
            .iter()
            .take(5)
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join("; ")
    );
    let more = warnings.len().saturating_sub(5);
    if more > 0 {
        line.push_str(&format!("; and {more} more"));
    }
    line.push_str(&gaps);
    line
}

/// The account databases, as far as they are kept.
struct AccountFiles {
    passwd: String,
    group: String,
    /// `None` when the shadow file cannot be read.
    shadow: Option<HashMap<String, Shadow>>,
}

/// What is read from files, in one blocking job.
struct Facts {
    /// `None` if not wanted, `Err` if the passwd file cannot be read.
    accounts: Option<Result<AccountFiles, String>>,
    apt_snippets: Vec<(String, String)>,
    reboot_required: bool,
    /// How long ago apt's package lists were refreshed, in seconds, if that can be told.
    apt_lists_age: Option<u64>,
    /// The same for the repository data dnf or yum has fetched.
    rpm_cache_age: Option<u64>,
    mac: MacFacts,
    vulnerabilities: Vec<(String, String)>,
    sysctls: BTreeMap<String, String>,
}

/// The small regular files directly inside `dir`, as (name, text).
fn small_files(dir: &Path, most: usize, max: u64) -> Vec<(String, String)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files = Vec::new();
    for entry in entries.flatten().take(most) {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if !entry.path().is_file() {
            continue;
        }
        if let Some(text) = read_small(&entry.path(), max) {
            files.push((name, text));
        }
    }
    files
}

fn read_facts(roots: &Roots, want_accounts: bool, want_updates: bool) -> Facts {
    let accounts = want_accounts.then(|| {
        let passwd = read_small(&roots.passwd, 4 * 1024 * 1024)
            .ok_or_else(|| "the passwd file cannot be read".to_string())?;
        let group = read_small(&roots.group, 4 * 1024 * 1024).unwrap_or_default();
        // AIDEV-NOTE: the shadow text lives only inside this expression; what is kept
        // (`Shadow`) has no hash in it.
        let shadow = read_small(&roots.shadow, 4 * 1024 * 1024).map(|text| parse_shadow(&text));
        Ok(AccountFiles {
            passwd,
            group,
            shadow,
        })
    });
    let (apt_snippets, reboot_required) = if want_updates {
        (
            small_files(&roots.apt_conf_dir, 500, 64 * 1024),
            roots.reboot_required.exists(),
        )
    } else {
        (Vec::new(), false)
    };
    let age = |written: Option<i64>| {
        written.map(|written| u64::try_from(now_secs().saturating_sub(written)).unwrap_or(0))
    };
    let (apt_lists_age, rpm_cache_age) = if want_updates {
        (
            age(modified(&roots.lists_stamp).or_else(|| modified(&roots.lists_dir))),
            age(newest_file(&roots.rpm_caches)),
        )
    } else {
        (None, None)
    };
    let sys = &roots.sys;
    let mac = MacFacts {
        apparmor_enabled: read_small(&sys.join("module/apparmor/parameters/enabled"), 16),
        apparmor_profiles: read_small(&sys.join("kernel/security/apparmor/profiles"), 1024 * 1024),
        selinux_enforce: read_small(&sys.join("fs/selinux/enforce"), 16),
        selinux_config: read_small(&roots.selinux_config, 16 * 1024),
    };
    let vulnerabilities = small_files(&sys.join("devices/system/cpu/vulnerabilities"), 100, 512);
    let mut sysctls = BTreeMap::new();
    for name in SYSCTLS {
        if let Some(value) = read_small(&roots.proc_sys.join(name.replace('.', "/")), 64) {
            sysctls.insert(name.to_string(), value);
        }
    }
    Facts {
        accounts,
        apt_snippets,
        reboot_required,
        apt_lists_age,
        rpm_cache_age,
        mac,
        vulnerabilities,
        sysctls,
    }
}

/// How asking a program went.
enum Asked {
    Answered(CmdOutput),
    NotInstalled,
    /// It could not be asked, or did not answer; why.
    Failed(String),
}

/// Runs one question, within what is left of the call's time.
async fn ask(ctx: &Ctx, clock: &CallClock, program: &str, args: &[&str]) -> Asked {
    let cmd = match ctx.optional_command(program) {
        Ok(Some(cmd)) => cmd,
        Ok(None) => return Asked::NotInstalled,
        Err(ToolError::Failed(why)) => return Asked::Failed(said(&why)),
        Err(_) => return Asked::Failed("it could not be run".to_string()),
    };
    let Some(limit) = clock.next() else {
        return Asked::Failed("the call ran out of time".to_string());
    };
    let mut cmd = cmd.args(args.iter().copied()).timeout(limit);
    // a firewall's ruleset can be long, and its rules are counted
    cmd.max_output = 4 * 1024 * 1024;
    // Boxed: a running command's future is large, and many are awaited in a row.
    match Box::pin(ctx.run(cmd)).await {
        Ok(out) if out.timed_out => Asked::Failed("it did not finish in time".to_string()),
        Ok(out) => Asked::Answered(out),
        Err(ToolError::Failed(why)) => Asked::Failed(said(&why)),
        Err(_) => Asked::Failed("it could not be run".to_string()),
    }
}

async fn ssh_section(ctx: &Ctx, clock: &CallClock) -> Vec<Finding> {
    match ask(ctx, clock, "sshd", &["-T"]).await {
        Asked::NotInstalled => vec![info("sshd is not installed")],
        Asked::Failed(why) => vec![unchecked(format!("sshd -T: {why}"))],
        Asked::Answered(out) if !command_ok(&out) => {
            vec![unchecked(format!("sshd -T: {}", said(&command_text(&out))))]
        }
        Asked::Answered(out) => ssh_findings(
            &String::from_utf8_lossy(&out.stdout),
            ctx.holds_read("user.view"),
        ),
    }
}

async fn firewall_section(ctx: &Ctx, clock: &CallClock) -> Vec<Finding> {
    let mut problems = Vec::new();
    let mut installed = 0usize;
    let mut truncated = false;
    let nft = match ask(ctx, clock, "nft", &["list", "ruleset"]).await {
        Asked::NotInstalled => None,
        Asked::Failed(why) => {
            installed = installed.saturating_add(1);
            problems.push(unchecked(format!("nft list ruleset: {why}")));
            None
        }
        Asked::Answered(out) if !command_ok(&out) => {
            installed = installed.saturating_add(1);
            problems.push(unchecked(format!(
                "nft list ruleset: {}",
                said(&command_text(&out))
            )));
            None
        }
        Asked::Answered(out) => {
            installed = installed.saturating_add(1);
            truncated = out.truncated;
            Some(parse_nft_ruleset(&String::from_utf8_lossy(&out.stdout)))
        }
    };
    // iptables is asked where nft shows nothing: rules loaded through the older
    // iptables interface are not in nft's listing.
    let mut iptables = None;
    if nft.as_ref().is_none_or(|ruleset| ruleset.tables == 0) {
        match ask(ctx, clock, "iptables", &["-w", "5", "-S", "INPUT"]).await {
            Asked::NotInstalled => {}
            Asked::Failed(why) => {
                installed = installed.saturating_add(1);
                problems.push(unchecked(format!("iptables -S INPUT: {why}")));
            }
            Asked::Answered(out) => {
                installed = installed.saturating_add(1);
                iptables = parse_iptables_input(&String::from_utf8_lossy(&out.stdout))
                    .filter(|_| command_ok(&out));
                if iptables.is_none() {
                    problems.push(unchecked(format!(
                        "iptables -S INPUT: {}",
                        said(&command_text(&out))
                    )));
                }
            }
        }
    }
    if installed == 0 {
        return vec![unchecked(
            "neither nft nor iptables is installed, so the packet filter cannot be looked at",
        )];
    }
    let mut findings = if nft.is_some() || iptables.is_some() {
        firewall_findings(nft.as_ref(), iptables.as_ref())
    } else {
        Vec::new()
    };
    if truncated {
        findings.push(info(
            "the ruleset is longer than is read, so the rule counts are low",
        ));
    }
    findings.extend(problems);
    findings
}

async fn updates_section(ctx: &Ctx, clock: &CallClock, facts: &Facts) -> Vec<Finding> {
    let reboot = |needed: bool| {
        if needed {
            warn("a reboot is needed to finish installed updates")
        } else {
            fine("no reboot is needed")
        }
    };
    let has = |program: &str| matches!(ctx.optional_command(program), Ok(Some(_)));
    let mut findings = Vec::new();
    if has("dpkg-query") {
        // A simulation: it changes nothing, takes no lock, and works for any user.
        let simulate = ["-s", "-o", "Debug::NoLocking=true", "dist-upgrade"];
        match ask(ctx, clock, "apt-get", &simulate).await {
            Asked::NotInstalled => {
                findings.push(unchecked("pending updates: apt-get is not installed"));
            }
            Asked::Failed(why) => findings.push(unchecked(format!("pending updates: {why}"))),
            Asked::Answered(out) if !command_ok(&out) => findings.push(unchecked(format!(
                "pending updates: {}",
                said(&command_text(&out))
            ))),
            Asked::Answered(out) => {
                findings.extend(apt_update_findings(&String::from_utf8_lossy(&out.stdout)));
                if out.truncated {
                    findings.push(info(
                        "apt printed more than is read: more updates may be pending than are counted",
                    ));
                }
            }
        }
        findings.push(lists_age_finding(facts.apt_lists_age));
        findings.push(reboot(facts.reboot_required));
        findings.push(match unattended_upgrades(&facts.apt_snippets) {
            Some(true) => fine("unattended upgrades are switched on"),
            _ => info("unattended upgrades are off"),
        });
    } else if has("rpm") {
        let manager = if has("dnf") { "dnf" } else { "yum" };
        // -C: from the cache. Refreshing it is a change, which this tool never makes.
        match ask(
            ctx,
            clock,
            manager,
            &["-q", "-C", "check-update", "--security"],
        )
        .await
        {
            Asked::NotInstalled => findings.push(unchecked(
                "pending updates: neither dnf nor yum is installed",
            )),
            Asked::Failed(why) => findings.push(unchecked(format!("pending updates: {why}"))),
            Asked::Answered(out) => match out.code {
                Some(0) => findings.push(fine(format!(
                    "no security updates are pending (going by {manager}'s cache)"
                ))),
                // check-update exits 100 when there are updates
                Some(100) => {
                    let pending = String::from_utf8_lossy(&out.stdout)
                        .lines()
                        .take_while(|line| !line.starts_with("Obsoleting"))
                        .filter(|line| line.split_whitespace().count() == 3)
                        .count();
                    let are = if pending == 1 { "is" } else { "are" };
                    findings.push(warn(format!(
                        "{} {are} pending (going by {manager}'s cache)",
                        count(pending, "security update", "security updates")
                    )));
                }
                _ => findings.push(unchecked(format!(
                    "pending updates: {}",
                    said(&command_text(&out))
                ))),
            },
        }
        findings.push(lists_age_finding(facts.rpm_cache_age));
        // exits 1 when a reboot is needed
        match ask(ctx, clock, "needs-restarting", &["-r"]).await {
            Asked::Answered(out) if out.code == Some(0) => findings.push(reboot(false)),
            Asked::Answered(out) if out.code == Some(1) => findings.push(reboot(true)),
            Asked::NotInstalled => findings.push(unchecked(
                "whether a reboot is needed: needs-restarting is not installed (package dnf-utils or yum-utils)",
            )),
            Asked::Answered(out) => findings.push(unchecked(format!(
                "whether a reboot is needed: {}",
                said(&command_text(&out))
            ))),
            Asked::Failed(why) => {
                findings.push(unchecked(format!("whether a reboot is needed: {why}")));
            }
        }
        let timer = ["is-enabled", "--", "dnf-automatic.timer"];
        match ask(ctx, clock, "systemctl", &timer).await {
            Asked::Answered(out) if String::from_utf8_lossy(&out.stdout).trim() == "enabled" => {
                findings.push(fine(
                    "unattended upgrades are switched on (dnf-automatic.timer)",
                ));
            }
            _ => findings.push(info(
                "unattended upgrades are off (dnf-automatic.timer is not enabled)",
            )),
        }
    } else {
        findings.push(unchecked(
            "no supported package manager (dpkg or rpm) was found",
        ));
    }
    findings
}

async fn listening_section(ctx: &Ctx, clock: &CallClock) -> Vec<Finding> {
    match ask(ctx, clock, "ss", &["-H", "-ltnu"]).await {
        Asked::NotInstalled => vec![unchecked("ss is not installed (package iproute2)")],
        Asked::Failed(why) => vec![unchecked(format!("ss: {why}"))],
        Asked::Answered(out) if !command_ok(&out) => {
            vec![unchecked(format!("ss: {}", said(&command_text(&out))))]
        }
        Asked::Answered(out) => listening_findings(&String::from_utf8_lossy(&out.stdout)),
    }
}

async fn security_posture(ctx: Ctx, _args: Args, roots: Arc<Roots>) -> ToolResult {
    let auth = ctx.authorize(None)?;
    let clock = CallClock::start(&ctx);
    // AIDEV-NOTE: decided once, before anything is read or run. A section the caller's
    // other permissions do not cover costs nothing and shows nothing.
    let see_firewall = ctx.holds_read("firewall.view");
    let see_updates = ctx.holds_read("package.view");
    let see_accounts = ctx.holds_read("user.view");
    let see_listening = ctx.holds_read("net.view");

    let facts = {
        let roots = roots.clone();
        blocking(ctx.clone(), move || {
            Ok(read_facts(&roots, see_accounts, see_updates))
        })
        .await?
    };

    let ssh = Box::pin(ssh_section(&ctx, &clock)).await;
    let firewall = if see_firewall {
        Ok(Box::pin(firewall_section(&ctx, &clock)).await)
    } else {
        Err("firewall.view")
    };
    let updates = if see_updates {
        Ok(Box::pin(updates_section(&ctx, &clock, &facts)).await)
    } else {
        Err("package.view")
    };
    let accounts = match &facts.accounts {
        None => Err("user.view"),
        Some(Err(why)) => Ok(vec![unchecked(why.clone())]),
        Some(Ok(files)) => Ok(account_findings(
            &files.passwd,
            &files.group,
            files.shadow.as_ref(),
        )),
    };
    let listening = if see_listening {
        Ok(Box::pin(listening_section(&ctx, &clock)).await)
    } else {
        Err("net.view")
    };
    let sections = [
        Section {
            title: "ssh",
            findings: Ok(ssh),
        },
        Section {
            title: "firewall",
            findings: firewall,
        },
        Section {
            title: "updates",
            findings: updates,
        },
        Section {
            title: "accounts",
            findings: accounts,
        },
        Section {
            title: "mandatory access control",
            findings: Ok(mac_findings(&facts.mac)),
        },
        Section {
            title: "kernel",
            findings: Ok(kernel_findings(&facts.vulnerabilities, &facts.sysctls)),
        },
        Section {
            title: "listening",
            findings: listening,
        },
    ];

    let mut text = verdict(&sections);
    text.push('\n');
    for section in &sections {
        text.push_str(&format!("== {} ==\n", section.title));
        match &section.findings {
            Ok(findings) => {
                for finding in findings {
                    text.push_str(&finding.render());
                    text.push('\n');
                }
            }
            Err(permission) => {
                text.push_str(&format!("[section left out: needs {permission}]\n"));
            }
        }
    }
    let (kept, dropped) = keep_head(&text, ctx.output_budget());
    if dropped > 0 {
        return auth.ok(format!(
            "{kept}[{dropped} more lines left out to fit the output limit]\n"
        ));
    }
    auth.ok(kept)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::Host;
    use crate::tools::testing::{FakeBins, call, find, host, ok_text};
    use crate::tools::users::parse_shadow;
    use serde_json::json;

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn rendered(findings: &[Finding]) -> Vec<String> {
        findings.iter().map(Finding::render).collect()
    }

    fn levels(findings: &[Finding]) -> Vec<Level> {
        findings.iter().map(|f| f.level).collect()
    }

    fn warnings(findings: &[Finding]) -> Vec<String> {
        findings
            .iter()
            .filter(|f| f.level == Level::Warn)
            .map(|f| f.text.clone())
            .collect()
    }

    #[test]
    fn a_finding_is_shown_with_its_level_in_brackets() {
        let show = |level| {
            Finding {
                level,
                text: "something".to_string(),
            }
            .render()
        };
        assert_eq!(show(Level::Warn), "[WARN] something");
        assert_eq!(show(Level::Ok), "[ok] something");
        assert_eq!(show(Level::Info), "[info] something");
        assert_eq!(show(Level::Unchecked), "[not checked] something");
    }

    const SSHD_WEAK: &str = "port 22\naddressfamily any\npermitrootlogin yes\npasswordauthentication yes\npermitemptypasswords yes\nkbdinteractiveauthentication no\npubkeyauthentication yes\nmaxauthtries 6\nx11forwarding no\n";
    const SSHD_GOOD: &str = "port 22\npermitrootlogin without-password\npasswordauthentication no\npermitemptypasswords no\nchallengeresponseauthentication no\npubkeyauthentication yes\nmaxauthtries 3\nallowusers alice\nallowusers bob\nallowgroups ssh-users\n";

    #[test]
    fn weak_ssh_settings_are_warnings() {
        let findings = ssh_findings(SSHD_WEAK, true);
        let warned = warnings(&findings);
        assert_eq!(warned.len(), 3, "{warned:?}");
        assert!(warned[0].starts_with("PermitRootLogin yes"), "{warned:?}");
        assert!(
            warned[1].starts_with("PasswordAuthentication yes"),
            "{warned:?}"
        );
        assert!(
            warned[2].starts_with("PermitEmptyPasswords yes"),
            "{warned:?}"
        );
        let all = rendered(&findings).join("\n");
        assert!(
            all.contains("[info] KbdInteractiveAuthentication no"),
            "{all}"
        );
        assert!(all.contains("[info] PubkeyAuthentication yes"), "{all}");
        assert!(all.contains("[info] MaxAuthTries 6"), "{all}");
        assert!(all.contains("[info] no AllowUsers or AllowGroups"), "{all}");
        assert!(all.contains("Match blocks are not evaluated"), "{all}");
        // settings nobody asked about are not repeated
        assert!(
            !all.contains("x11forwarding") && !all.contains("addressfamily"),
            "{all}"
        );
    }

    /// AIDEV-NOTE: `PasswordAuthentication no` alone does not stop password logins. With
    /// KbdInteractiveAuthentication yes and UsePAM yes, sshd hands the conversation to
    /// PAM, which asks for the account's password. The green "[ok] PasswordAuthentication
    /// no" then says the opposite of what is true.
    #[test]
    fn passwords_still_accepted_through_pam_are_a_warning() {
        let base = "permitrootlogin no\npasswordauthentication no\npermitemptypasswords no\npubkeyauthentication yes\nmaxauthtries 6\n";
        let warned = |extra: &str| warnings(&ssh_findings(&format!("{base}{extra}"), true));
        let through_pam =
            warned("kbdinteractiveauthentication yes\nusepam yes\nauthenticationmethods any\n");
        assert_eq!(through_pam.len(), 1, "{through_pam:?}");
        assert!(
            through_pam[0].starts_with(
                "PasswordAuthentication is no, but passwords may still be accepted: \
                 KbdInteractiveAuthentication yes with UsePAM yes"
            ),
            "{through_pam:?}"
        );
        // the older name of the setting, and no AuthenticationMethods line at all
        assert_eq!(
            warned("challengeresponseauthentication yes\nusepam yes\n").len(),
            1
        );
        // not when any one of the three is otherwise
        for sound in [
            "kbdinteractiveauthentication no\nusepam yes\nauthenticationmethods any\n",
            "kbdinteractiveauthentication yes\nusepam no\nauthenticationmethods any\n",
            "kbdinteractiveauthentication yes\nusepam yes\nauthenticationmethods publickey\n",
            "kbdinteractiveauthentication yes\nusepam yes\nauthenticationmethods publickey,keyboard-interactive\n",
            "usepam yes\n",
        ] {
            assert!(warned(sound).is_empty(), "{sound:?}: {:?}", warned(sound));
        }
        // with passwords accepted outright there is one warning, the plain one
        let both = warnings(&ssh_findings(
            "permitrootlogin no\npasswordauthentication yes\nkbdinteractiveauthentication yes\nusepam yes\n",
            true,
        ));
        assert_eq!(both.len(), 1, "{both:?}");
        assert!(
            both[0].starts_with("PasswordAuthentication yes"),
            "{both:?}"
        );
    }

    #[test]
    fn sound_ssh_settings_are_ok_and_the_allow_lists_are_shown() {
        let findings = ssh_findings(SSHD_GOOD, true);
        assert!(warnings(&findings).is_empty(), "{findings:?}");
        let all = rendered(&findings).join("\n");
        assert!(
            all.contains("[ok] PermitRootLogin without-password"),
            "{all}"
        );
        assert!(all.contains("[ok] PasswordAuthentication no"), "{all}");
        assert!(all.contains("[ok] PermitEmptyPasswords no"), "{all}");
        // the older name of the keyboard-interactive setting
        assert!(
            all.contains("[info] KbdInteractiveAuthentication no"),
            "{all}"
        );
        assert!(all.contains("[info] AllowUsers alice bob"), "{all}");
        assert!(all.contains("[info] AllowGroups ssh-users"), "{all}");
    }

    /// AIDEV-NOTE: sshd's AllowUsers is a list of account names. Shown to a caller who
    /// holds security.view but not user.view, it would give away what user_list refuses.
    #[test]
    fn the_names_in_the_allow_lists_are_kept_from_a_caller_without_user_view() {
        let findings = ssh_findings(SSHD_GOOD, false);
        let all = rendered(&findings).join("\n");
        assert!(
            all.contains("[info] AllowUsers is set (2 entries; the names need user.view)"),
            "{all}"
        );
        assert!(
            all.contains("[info] AllowGroups is set (1 entry; the names need user.view)"),
            "{all}"
        );
        assert!(!all.contains("alice") && !all.contains("bob"), "{all}");
        assert!(!all.contains("ssh-users"), "{all}");
        // everything else is as before
        assert!(all.contains("[ok] PasswordAuthentication no"), "{all}");
    }

    #[test]
    fn ssh_values_are_repeated_only_when_they_are_plain() {
        let findings = ssh_findings(
            "permitrootlogin yes\u{1b}[31m\nmaxauthtries six hundred and a great deal more than could ever be a number\nallowusers a]b\n",
            true,
        );
        let all = rendered(&findings).join("\n");
        assert!(!all.contains('\u{1b}'), "{all:?}");
        assert!(!all.contains("six hundred"), "{all}");
        assert!(!all.contains("a]b"), "{all}");
        // output that is not sshd's settings at all gives one line saying so
        let findings = ssh_findings("sshd: no hostkeys available -- exiting.\n", true);
        assert_eq!(levels(&findings), vec![Level::Unchecked]);
    }

    const NFT_DROP: &str = "table inet filter {
	set blocklist {
		type ipv4_addr
		flags timeout
		elements = { 10.0.0.5 timeout 30m expires 29m,
			     10.0.0.6 }
	}

	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		iif \"lo\" accept
		tcp dport 22 accept
	}

	chain forward {
		type filter hook forward priority filter; policy accept;
	}
}
table ip nat {
	chain POSTROUTING {
		type nat hook postrouting priority srcnat; policy accept;
		oifname \"eth0\" masquerade
	}
}
";

    #[test]
    fn the_nft_ruleset_is_reduced_to_its_input_chains_and_rule_count() {
        let ruleset = parse_nft_ruleset(NFT_DROP);
        assert_eq!(ruleset.tables, 2);
        assert_eq!(ruleset.rules, 4);
        assert_eq!(
            ruleset.input,
            vec![InputChain {
                name: "inet filter/input".to_string(),
                policy: "drop".to_string(),
                rules: 3,
            }]
        );
        assert_eq!(parse_nft_ruleset(""), NftRuleset::default());
        // iptables-nft on a host with nothing configured: chains, but no rule
        let empty = "table ip filter {\n\tchain INPUT {\n\t\ttype filter hook input priority filter; policy accept;\n\t}\n}\n";
        let ruleset = parse_nft_ruleset(empty);
        assert_eq!((ruleset.tables, ruleset.rules), (1, 0));
        assert_eq!(ruleset.input[0].policy, "accept");
        assert_eq!(ruleset.input[0].rules, 0);
    }

    #[test]
    fn iptables_input_gives_its_policy_and_rule_count() {
        assert_eq!(
            parse_iptables_input(
                "-P INPUT DROP\n-A INPUT -i lo -j ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT\n"
            ),
            Some(("DROP".to_string(), 2))
        );
        assert_eq!(
            parse_iptables_input("-P INPUT ACCEPT\n"),
            Some(("ACCEPT".to_string(), 0))
        );
        assert_eq!(parse_iptables_input("iptables: Permission denied\n"), None);
        assert_eq!(parse_iptables_input("-P INPUT $(reboot)\n"), None);
    }

    #[test]
    fn no_rule_at_all_with_an_accepting_policy_is_the_firewall_warning() {
        // nothing loaded anywhere
        let none = NftRuleset::default();
        let findings = firewall_findings(Some(&none), None);
        assert_eq!(levels(&findings), vec![Level::Warn], "{findings:?}");
        assert!(findings[0].text.contains("no firewall"), "{findings:?}");
        // chains exist, policy accept, not one rule
        let open = parse_nft_ruleset(
            "table ip filter {\n\tchain INPUT {\n\t\ttype filter hook input priority filter; policy accept;\n\t}\n}\n",
        );
        assert_eq!(
            levels(&firewall_findings(Some(&open), None)),
            vec![Level::Warn]
        );
        // the same through iptables
        let accept = ("ACCEPT".to_string(), 0);
        assert_eq!(
            levels(&firewall_findings(None, Some(&accept))),
            vec![Level::Warn]
        );
        assert_eq!(
            levels(&firewall_findings(Some(&none), Some(&accept))),
            vec![Level::Warn]
        );
    }

    #[test]
    fn a_dropping_policy_is_ok_and_an_accepting_one_with_rules_is_only_information() {
        let drop = parse_nft_ruleset(NFT_DROP);
        let findings = firewall_findings(Some(&drop), None);
        assert_eq!(levels(&findings), vec![Level::Ok], "{findings:?}");
        assert!(
            findings[0].text.contains("inet filter/input")
                && findings[0].text.contains("policy drop")
                && findings[0].text.contains("3 rules"),
            "{findings:?}"
        );
        let accept_rules = parse_nft_ruleset(
            "table inet fw {\n\tchain in {\n\t\ttype filter hook input priority 0; policy accept;\n\t\ttcp dport 22 accept\n\t\treject\n\t}\n}\n",
        );
        let findings = firewall_findings(Some(&accept_rules), None);
        assert_eq!(levels(&findings), vec![Level::Info], "{findings:?}");
        // iptables
        let dropping = ("DROP".to_string(), 4);
        assert_eq!(
            levels(&firewall_findings(None, Some(&dropping))),
            vec![Level::Ok]
        );
        let accepting = ("ACCEPT".to_string(), 4);
        assert_eq!(
            levels(&firewall_findings(None, Some(&accepting))),
            vec![Level::Info]
        );
        // nft rules elsewhere but nothing on input: there are rules, so no warning
        let nat_only = parse_nft_ruleset(
            "table ip nat {\n\tchain POSTROUTING {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n\t\tmasquerade\n\t}\n}\n",
        );
        let findings = firewall_findings(Some(&nat_only), None);
        assert_eq!(levels(&findings), vec![Level::Info], "{findings:?}");
        assert!(
            findings[0]
                .text
                .contains("no chain filters incoming traffic"),
            "{findings:?}"
        );
        // neither view
        assert_eq!(
            levels(&firewall_findings(None, None)),
            vec![Level::Unchecked]
        );
    }

    #[test]
    fn pending_security_updates_are_a_warning_and_other_updates_information() {
        let both = "Inst openssl [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-security [amd64])\nInst vim [2:9.1.0016-1ubuntu7] (2:9.1.0016-1ubuntu7.3 Ubuntu:24.04/noble-updates [amd64])\nConf openssl (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-security [amd64])\n";
        let findings = apt_update_findings(both);
        assert_eq!(levels(&findings), vec![Level::Warn], "{findings:?}");
        assert!(
            findings[0].text.contains("1 security update")
                && findings[0].text.contains("2 updates in all"),
            "{findings:?}"
        );
        let plain = "Inst vim [2:9.1.0016-1ubuntu7] (2:9.1.0016-1ubuntu7.3 Ubuntu:24.04/noble-updates [amd64])\n";
        assert_eq!(levels(&apt_update_findings(plain)), vec![Level::Info]);
        let none = "Reading package lists...\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n";
        assert_eq!(levels(&apt_update_findings(none)), vec![Level::Ok]);
    }

    #[test]
    fn unattended_upgrades_are_read_from_the_apt_snippets_last_one_winning() {
        let file = |name: &str, text: &str| (name.to_string(), text.to_string());
        let on = file(
            "20auto-upgrades",
            "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n",
        );
        let off = file(
            "99local",
            "// switched off here\nAPT::Periodic::Unattended-Upgrade \"0\";\n",
        );
        assert_eq!(unattended_upgrades(std::slice::from_ref(&on)), Some(true));
        assert_eq!(unattended_upgrades(&[on.clone(), off.clone()]), Some(false));
        // name order decides, not the order given
        assert_eq!(unattended_upgrades(&[off, on]), Some(false));
        assert_eq!(
            unattended_upgrades(&[file(
                "10periodic",
                "APT::Periodic::Update-Package-Lists \"1\";\n"
            )]),
            None
        );
        assert_eq!(
            unattended_upgrades(&[file(
                "20auto-upgrades",
                "# APT::Periodic::Unattended-Upgrade \"1\";\n// APT::Periodic::Unattended-Upgrade \"1\";\n"
            )]),
            None
        );
        assert_eq!(unattended_upgrades(&[]), None);
    }

    #[test]
    fn periodic_work_switched_off_as_a_whole_switches_unattended_upgrades_off() {
        let file = |name: &str, text: &str| (name.to_string(), text.to_string());
        let on = file(
            "20auto-upgrades",
            "APT::Periodic::Unattended-Upgrade \"1\";\n",
        );
        // as container images ship it
        let disabled = file(
            "docker-disable-periodic-update",
            "APT::Periodic::Enable \"0\";\n",
        );
        assert_eq!(
            unattended_upgrades(&[on.clone(), disabled.clone()]),
            Some(false)
        );
        let enabled = file("10enable", "APT::Periodic::Enable \"1\";\n");
        assert_eq!(unattended_upgrades(&[on, enabled.clone()]), Some(true));
        // on its own the switch says nothing about unattended upgrades
        assert_eq!(unattended_upgrades(&[enabled]), None);
        assert_eq!(unattended_upgrades(&[disabled]), None);
    }

    const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nalice:x:1000:1000:Alice:/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/bash\ncarol:x:1002:27::/home/carol:/bin/bash\n";
    const GROUP: &str =
        "root:x:0:\nsudo:x:27:alice\nwheel:x:10:\nadmin:x:110:bob\nusers:x:100:alice,bob\n";
    const HASH: &str = "$6$rounds=5000$saltsaltsalt$hashhashhashhashhashhashhashhashhashhash";

    fn shadow(text: &str) -> HashMap<String, Shadow> {
        parse_shadow(text)
    }

    #[test]
    fn ordinary_accounts_give_no_warning_and_the_sudo_members_are_listed() {
        let shadow = shadow(&format!(
            "root:!:19000:0:99999:7:::\ndaemon:*:19000:0:99999:7:::\nalice:{HASH}:19000:0:99999:7:::\nbob:{HASH}:19000:0:99999:7:::\ncarol:!{HASH}:19000:0:99999:7:::\n"
        ));
        let findings = account_findings(PASSWD, GROUP, Some(&shadow));
        assert!(warnings(&findings).is_empty(), "{findings:?}");
        let all = rendered(&findings).join("\n");
        assert!(
            all.contains("[ok] root is the only account with uid 0"),
            "{all}"
        );
        assert!(
            all.contains("[ok] no account has an empty password"),
            "{all}"
        );
        // by membership, and by a primary group that is one of them
        assert!(
            all.contains(
                "[info] may use sudo through the sudo, wheel or admin group: alice, bob, carol"
            ),
            "{all}"
        );
        assert!(!all.contains("$6$") && !all.contains("hashhash"), "{all}");
    }

    #[test]
    fn a_second_root_and_empty_passwords_are_warnings() {
        let passwd = format!(
            "{PASSWD}toor:x:0:0::/root:/bin/sh\nguest::1003:1003::/home/guest:/bin/sh\ndave:x:1004:1004::/home/dave:/bin/sh\n"
        );
        let shadow = shadow(&format!(
            "root:{HASH}:19000::::::\ntoor:{HASH}:19000::::::\nalice:{HASH}:1::::::\ndave::19000::::::\n"
        ));
        let findings = account_findings(&passwd, GROUP, Some(&shadow));
        let warned = warnings(&findings);
        assert_eq!(warned.len(), 3, "{warned:?}");
        assert!(
            warned[0].contains("toor") && warned[0].contains("uid 0"),
            "{warned:?}"
        );
        assert!(
            warned
                .iter()
                .any(|w| w.contains("guest") && w.contains("passwd")),
            "{warned:?}"
        );
        assert!(
            warned
                .iter()
                .any(|w| w.contains("dave") && w.contains("empty password")),
            "{warned:?}"
        );
        let all = rendered(&findings).join("\n");
        assert!(!all.contains("$6$") && !all.contains("hashhash"), "{all}");
    }

    #[test]
    fn without_the_shadow_file_empty_passwords_are_not_called_absent() {
        let findings = account_findings(PASSWD, GROUP, None);
        let all = rendered(&findings).join("\n");
        assert!(all.contains("[not checked]"), "{all}");
        assert!(all.contains("shadow"), "{all}");
        assert!(!all.contains("no account has an empty password"), "{all}");
        // an account name that is not a plain name is never repeated
        let odd = "root:x:0:0::/root:/bin/sh\nev\u{1b}il:x:0:0::/:/bin/sh\n";
        let all = rendered(&account_findings(odd, "", None)).join("\n");
        assert!(!all.contains('\u{1b}'), "{all:?}");
        assert!(all.contains("uid 0"), "{all}");
    }

    #[test]
    fn mandatory_access_control_is_reported_from_what_the_kernel_says() {
        let apparmor = MacFacts {
            apparmor_enabled: Some("Y\n".to_string()),
            apparmor_profiles: Some("/usr/sbin/nginx (enforce)\n/usr/bin/man (enforce)\nfirefox (complain)\nsnap.x (unconfined)\n".to_string()),
            ..MacFacts::default()
        };
        let findings = mac_findings(&apparmor);
        assert_eq!(levels(&findings), vec![Level::Ok], "{findings:?}");
        assert!(
            findings[0].text.contains("AppArmor")
                && findings[0].text.contains("2 profiles enforce")
                && findings[0].text.contains("1 only complains"),
            "{findings:?}"
        );
        // the profile list needs root
        let hidden = MacFacts {
            apparmor_enabled: Some("Y".to_string()),
            ..MacFacts::default()
        };
        assert_eq!(levels(&mac_findings(&hidden)), vec![Level::Ok]);

        let enforcing = MacFacts {
            selinux_enforce: Some("1".to_string()),
            selinux_config: Some("SELINUX=enforcing\nSELINUXTYPE=targeted\n".to_string()),
            ..MacFacts::default()
        };
        let findings = mac_findings(&enforcing);
        assert_eq!(levels(&findings), vec![Level::Ok]);
        assert!(
            findings[0].text.contains("SELinux is enforcing"),
            "{findings:?}"
        );
        let permissive = MacFacts {
            selinux_enforce: Some("0\n".to_string()),
            ..MacFacts::default()
        };
        let findings = mac_findings(&permissive);
        assert_eq!(levels(&findings), vec![Level::Warn]);
        assert!(findings[0].text.contains("permissive"), "{findings:?}");
        let disabled = MacFacts {
            selinux_config: Some("# comment\nSELINUX=disabled\n".to_string()),
            ..MacFacts::default()
        };
        let findings = mac_findings(&disabled);
        assert_eq!(levels(&findings), vec![Level::Warn]);
        assert!(findings[0].text.contains("disabled"), "{findings:?}");

        let neither = mac_findings(&MacFacts::default());
        assert_eq!(levels(&neither), vec![Level::Info]);
        assert!(
            neither[0].text.contains("neither AppArmor nor SELinux"),
            "{neither:?}"
        );
        // AppArmor built in but switched off
        let off = MacFacts {
            apparmor_enabled: Some("N".to_string()),
            ..MacFacts::default()
        };
        assert_eq!(levels(&mac_findings(&off)), vec![Level::Info]);
    }

    fn sysctls(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn kernel_findings_warn_about_what_is_plainly_weak() {
        let vulnerabilities = vec![
            ("meltdown".to_string(), "Mitigation: PTI\n".to_string()),
            (
                "spectre_v2".to_string(),
                "Vulnerable: eIBRS with unprivileged eBPF\n".to_string(),
            ),
            ("retbleed".to_string(), "Not affected\n".to_string()),
            (
                "mds".to_string(),
                "Vulnerable; SMT Host state unknown\n".to_string(),
            ),
        ];
        let weak = sysctls(&[
            ("kernel.randomize_va_space", "1"),
            ("fs.protected_symlinks", "0"),
            ("fs.protected_hardlinks", "1"),
            ("kernel.kptr_restrict", "0"),
            ("kernel.yama.ptrace_scope", "1"),
        ]);
        let findings = kernel_findings(&vulnerabilities, &weak);
        let warned = warnings(&findings);
        assert_eq!(warned.len(), 4, "{warned:?}");
        // in name order, each with what the kernel says
        assert!(
            warned[0].starts_with("CPU vulnerability mds: Vulnerable; SMT Host state unknown"),
            "{warned:?}"
        );
        assert!(
            warned[1].starts_with("CPU vulnerability spectre_v2: Vulnerable: eIBRS"),
            "{warned:?}"
        );
        assert!(
            warned[2].contains("kernel.randomize_va_space is 1"),
            "{warned:?}"
        );
        assert!(
            warned[3].contains("fs.protected_symlinks is 0"),
            "{warned:?}"
        );
        let all = rendered(&findings).join("\n");
        assert!(
            all.contains(
                "[ok] 2 other CPU vulnerabilities are mitigated or do not affect this CPU"
            ),
            "{all}"
        );
        assert!(all.contains("[ok] fs.protected_hardlinks is 1"), "{all}");
        assert!(
            all.contains("[info] kernel.kptr_restrict=0, kernel.yama.ptrace_scope=1"),
            "{all}"
        );
    }

    /// AIDEV-NOTE: "Mitigation: Clear CPU buffers; SMT vulnerable" and "Unknown: ..." do
    /// not start with "Vulnerable" and were counted as mitigated.
    #[test]
    fn partly_mitigated_and_unknown_cpu_vulnerabilities_are_named_not_counted_as_mitigated() {
        let vulnerabilities = vec![
            ("meltdown".to_string(), "Mitigation: PTI\n".to_string()),
            (
                "mmio_stale_data".to_string(),
                "Mitigation: Clear CPU buffers; SMT vulnerable\n".to_string(),
            ),
            ("retbleed".to_string(), "Not affected\n".to_string()),
            (
                "spec_rstack_overflow".to_string(),
                "Unknown: Dependent on hypervisor status\n".to_string(),
            ),
        ];
        let findings = kernel_findings(&vulnerabilities, &BTreeMap::new());
        // information, not a warning: the kernel has done what it can
        assert!(warnings(&findings).is_empty(), "{findings:?}");
        let all = rendered(&findings).join("\n");
        assert!(
            all.contains(
                "[info] 2 CPU vulnerabilities are only partly mitigated or unknown: \
                 mmio_stale_data (Mitigation: Clear CPU buffers; SMT vulnerable), \
                 spec_rstack_overflow (Unknown: Dependent on hypervisor status)"
            ),
            "{all}"
        );
        assert!(
            all.contains(
                "[ok] 2 other CPU vulnerabilities are mitigated or do not affect this CPU"
            ),
            "{all}"
        );
    }

    #[test]
    fn the_age_of_the_package_lists_is_said_and_an_old_one_is_pointed_out() {
        let fresh = lists_age_finding(Some(3 * 3600));
        assert_eq!(fresh.level, Level::Info);
        assert_eq!(fresh.text, "the package lists were last refreshed 3h ago");
        let week = lists_age_finding(Some(7 * 86_400));
        assert!(!week.text.contains("out of date"), "{}", week.text);
        let old = lists_age_finding(Some(23 * 86_400));
        assert_eq!(old.level, Level::Info);
        assert_eq!(
            old.text,
            "the package lists were last refreshed 23d ago: the counts of pending updates \
             may be out of date (package_upgrade with refresh updates the lists)"
        );
        let unknown = lists_age_finding(None);
        assert_eq!(unknown.level, Level::Info);
        assert!(unknown.text.contains("not known"), "{}", unknown.text);
    }

    #[test]
    fn the_newest_file_in_a_package_cache_says_when_it_was_refreshed() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(newest_file(&[dir.path().join("nowhere")]), None);
        let repo = dir.path().join("dnf/baseos-0123abcd/repodata");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("repomd.xml"), "x").unwrap();
        std::fs::write(dir.path().join("dnf/last_makecache"), "").unwrap();
        set_mtime(&repo.join("repomd.xml"), 1_700_000_000);
        set_mtime(&dir.path().join("dnf/last_makecache"), 1_700_500_000);
        // a directory's own time does not count, and a link is not followed
        std::os::unix::fs::symlink("/etc/hostname", dir.path().join("dnf/link")).unwrap();
        assert_eq!(
            newest_file(&[dir.path().join("yum"), dir.path().join("dnf")]),
            Some(1_700_500_000)
        );
    }

    #[test]
    fn a_sound_kernel_gives_no_warning_and_missing_settings_are_left_out() {
        let vulnerabilities = vec![("meltdown".to_string(), "Not affected".to_string())];
        let good = sysctls(&[
            ("kernel.randomize_va_space", "2"),
            ("fs.protected_symlinks", "1"),
        ]);
        let findings = kernel_findings(&vulnerabilities, &good);
        assert!(warnings(&findings).is_empty(), "{findings:?}");
        let all = rendered(&findings).join("\n");
        assert!(
            all.contains("[ok] 1 CPU vulnerability is mitigated or does not affect this CPU"),
            "{all}"
        );
        assert!(
            !all.contains("protected_hardlinks") && !all.contains("[info]"),
            "{all}"
        );
        // nothing readable at all
        let nothing = kernel_findings(&[], &BTreeMap::new());
        assert_eq!(levels(&nothing), vec![Level::Unchecked]);
        // a value that is not a small number is not repeated
        let odd = kernel_findings(&[], &sysctls(&[("kernel.randomize_va_space", "2; reboot")]));
        assert!(!rendered(&odd).join("\n").contains("reboot"));
    }

    const SS: &str = "udp   UNCONN 0      0         127.0.0.53%lo:53        0.0.0.0:*\nudp   UNCONN 0      0               0.0.0.0:123       0.0.0.0:*\ntcp   LISTEN 0      4096      127.0.0.53%lo:53        0.0.0.0:*\ntcp   LISTEN 0      128             0.0.0.0:22        0.0.0.0:*\ntcp   LISTEN 0      511                   *:443             *:*\ntcp   LISTEN 0      128                [::]:22           [::]:*\ntcp   LISTEN 0      4096              [::1]:6010         [::]:*\ntcp   LISTEN 0      100           127.0.0.1:25        0.0.0.0:*\ntcp   LISTEN 0      4096           10.0.0.7:5432      0.0.0.0:*\n";

    #[test]
    fn ports_listening_beyond_loopback_are_listed_once_each() {
        let findings = listening_findings(SS);
        assert_eq!(levels(&findings), vec![Level::Info], "{findings:?}");
        assert_eq!(
            findings[0].text,
            "listening beyond loopback: tcp 22, 443, 5432; udp 123"
        );
        let local = "tcp   LISTEN 0      100           127.0.0.1:25        0.0.0.0:*\ntcp   LISTEN 0      4096              [::1]:6010         [::]:*\n";
        let findings = listening_findings(local);
        assert_eq!(levels(&findings), vec![Level::Ok]);
        assert_eq!(levels(&listening_findings("")), vec![Level::Ok]);
    }

    #[test]
    fn a_long_list_of_ports_is_shortened() {
        let many: String = (0..45)
            .map(|n| {
                format!(
                    "tcp   LISTEN 0      128             0.0.0.0:{}        0.0.0.0:*\n",
                    8000 + n
                )
            })
            .collect();
        let findings = listening_findings(&many);
        assert!(findings[0].text.ends_with("and 15 more"), "{findings:?}");
        assert!(
            findings[0].text.contains("8029") && !findings[0].text.contains("8030"),
            "{findings:?}"
        );
    }

    fn finding(level: Level, text: &str) -> Finding {
        Finding {
            level,
            text: text.to_string(),
        }
    }

    #[test]
    fn the_first_line_counts_the_warnings_and_names_them() {
        let none = [Section {
            title: "ssh",
            findings: Ok(vec![finding(Level::Ok, "fine")]),
        }];
        assert_eq!(verdict(&none), "No warnings.");
        let one = [
            Section {
                title: "ssh",
                findings: Ok(vec![
                    finding(
                        Level::Warn,
                        "PasswordAuthentication yes: passwords are accepted",
                    ),
                    finding(Level::Ok, "fine"),
                ]),
            },
            Section {
                title: "firewall",
                findings: Err("firewall.view"),
            },
            Section {
                title: "kernel",
                findings: Ok(vec![finding(Level::Unchecked, "nothing could be read")]),
            },
        ];
        assert_eq!(
            verdict(&one),
            "1 warning: ssh: PasswordAuthentication yes: passwords are accepted (1 section left out, 1 check not made)"
        );
        let many: Vec<Section> = vec![Section {
            title: "kernel",
            findings: Ok((0..8)
                .map(|n| finding(Level::Warn, &format!("thing {n}")))
                .collect()),
        }];
        let line = verdict(&many);
        assert!(
            line.starts_with("8 warnings: kernel: thing 0; kernel: thing 1;"),
            "{line}"
        );
        assert!(line.ends_with("kernel: thing 4; and 3 more"), "{line}");
        assert!(!line.contains('\n'));
    }

    // ---- the tool ----------------------------------------------------------------------

    const TITLES: [&str; 7] = [
        "== ssh ==",
        "== firewall ==",
        "== updates ==",
        "== accounts ==",
        "== mandatory access control ==",
        "== kernel ==",
        "== listening ==",
    ];

    struct Fixture {
        dir: tempfile::TempDir,
        host: Arc<Host>,
        sink: MemorySink,
    }

    impl Fixture {
        fn new(fake: &FakeBins) -> Fixture {
            let dir = tempfile::tempdir().unwrap();
            let (host, sink) = host(&format!(
                "[roles.reader]\nallow = [\"@read\"]\n[roles.narrow]\nallow = [\"security.view\"]\n[roles.other]\nallow = [\"system.view\"]\n\
                 [unix_users.rita]\nroles = [\"reader\"]\n[unix_users.nan]\nroles = [\"narrow\"]\n[unix_users.nora]\nroles = [\"other\"]\n{}",
                fake.config_only()
            ));
            let fixture = Fixture { dir, host, sink };
            fixture.write("passwd", PASSWD);
            fixture.write("group", GROUP);
            fixture.write(
                "shadow",
                &format!("root:!:19000::::::\nalice:{HASH}:19000::::::\nbob:{HASH}:19000::::::\n"),
            );
            fixture.write("proc_sys/kernel/randomize_va_space", "2\n");
            fixture.write("proc_sys/fs/protected_symlinks", "1\n");
            fixture.write("proc_sys/fs/protected_hardlinks", "1\n");
            fixture.write("proc_sys/kernel/kptr_restrict", "1\n");
            fixture.write(
                "sys/devices/system/cpu/vulnerabilities/meltdown",
                "Mitigation: PTI\n",
            );
            fixture.write("sys/module/apparmor/parameters/enabled", "Y\n");
            fixture.write(
                "apt.conf.d/20auto-upgrades",
                "APT::Periodic::Unattended-Upgrade \"1\";\n",
            );
            fixture
        }

        fn path(&self, name: &str) -> PathBuf {
            self.dir.path().join(name)
        }

        fn write(&self, name: &str, text: &str) {
            let path = self.path(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }

        fn roots(&self) -> Roots {
            Roots {
                passwd: self.path("passwd"),
                group: self.path("group"),
                shadow: self.path("shadow"),
                apt_conf_dir: self.path("apt.conf.d"),
                reboot_required: self.path("reboot-required"),
                selinux_config: self.path("selinux-config"),
                proc_sys: self.path("proc_sys"),
                sys: self.path("sys"),
                lists_stamp: self.path("apt-stamp"),
                lists_dir: self.path("apt-lists"),
                rpm_caches: vec![self.path("dnf-cache")],
            }
        }

        async fn run(&self, user: &str) -> ToolResult {
            let tool = find(tools_with(self.roots()), "security_posture");
            call(&self.host, user, &tool, json!({})).await
        }
    }

    fn set_mtime(path: &Path, unix: i64) {
        let file = std::fs::File::options().write(true).open(path).unwrap();
        let when = std::time::UNIX_EPOCH + std::time::Duration::from_secs(unix as u64);
        file.set_modified(when).unwrap();
    }

    /// A stand-in that prints `text` (which must hold no single quote).
    fn prints(text: &str) -> String {
        assert!(!text.contains('\''));
        format!("printf '%s' '{text}'")
    }

    fn sound_host() -> FakeBins {
        FakeBins::new()
            .add_script("sshd", &prints(SSHD_GOOD))
            .add_script("nft", &prints(NFT_DROP))
            .add("dpkg-query", "", 0)
            .add_script(
                "apt-get",
                &prints("Reading package lists...\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"),
            )
            .add_script("ss", &prints(SS))
    }

    fn section<'a>(text: &'a str, title: &str) -> &'a str {
        let start = text
            .find(title)
            .unwrap_or_else(|| panic!("no {title} in:\n{text}"))
            + title.len();
        let rest = &text[start..];
        let end = rest.find("\n== ").map_or(rest.len(), |at| at + 1);
        &rest[..end]
    }

    #[test]
    fn it_is_a_read_tool_under_security_view_and_takes_no_arguments() {
        let tool = find(tools(), "security_posture");
        assert_eq!(tool.access, Access::Read);
        assert_eq!(tool.permission, "security.view");
        assert!(tool.params.is_empty());
    }

    #[tokio::test]
    async fn a_sound_host_has_no_warnings_and_every_section_in_order() {
        let fake = sound_host();
        let fixture = Fixture::new(&fake);
        let text = ok_text(fixture.run("rita").await);
        assert_eq!(text.lines().next().unwrap(), "No warnings.", "{text}");
        let mut at = 0;
        for title in TITLES {
            let found = text[at..]
                .find(title)
                .unwrap_or_else(|| panic!("{title} missing or out of order in:\n{text}"));
            at += found;
        }
        assert!(!text.contains("[WARN]"), "{text}");
        assert!(
            section(&text, "== ssh ==").contains("[ok] PasswordAuthentication no"),
            "{text}"
        );
        assert!(
            section(&text, "== firewall ==").contains("[ok] nftables: inet filter/input"),
            "{text}"
        );
        let updates = section(&text, "== updates ==");
        assert!(updates.contains("[ok] no updates are pending"), "{text}");
        // nothing says when the lists were refreshed on this stand-in: that is said
        assert!(
            updates.contains("[info] it is not known when the package lists were last refreshed"),
            "{text}"
        );
        assert!(updates.contains("[ok] no reboot is needed"), "{text}");
        assert!(
            updates.contains("[ok] unattended upgrades are switched on"),
            "{text}"
        );
        assert!(
            section(&text, "== accounts ==").contains("[ok] root is the only account with uid 0"),
            "{text}"
        );
        assert!(
            section(&text, "== mandatory access control ==").contains("[ok] AppArmor"),
            "{text}"
        );
        assert!(
            section(&text, "== kernel ==").contains("[ok] kernel.randomize_va_space is 2"),
            "{text}"
        );
        assert!(
            section(&text, "== listening ==").contains("tcp 22, 443, 5432; udp 123"),
            "{text}"
        );
        // what was run, and that each is only a question
        assert_eq!(fake.calls("sshd"), vec![strings(&["-T"])]);
        assert_eq!(fake.calls("nft"), vec![strings(&["list", "ruleset"])]);
        assert_eq!(
            fake.calls("apt-get"),
            vec![strings(&[
                "-s",
                "-o",
                "Debug::NoLocking=true",
                "dist-upgrade"
            ])]
        );
        assert_eq!(fake.calls("ss"), vec![strings(&["-H", "-ltnu"])]);
        // one audited decision
        let records = fixture.sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["decision"], "allow");
        assert!(
            !text.contains("$6$") && !text.contains("hashhash"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn a_weak_host_is_told_what_is_wrong_first() {
        let fake = FakeBins::new()
            .add_script("sshd", &prints(SSHD_WEAK))
            .add("nft", "", 0)
            .add_script("iptables", &prints("-P INPUT ACCEPT\n"))
            .add("dpkg-query", "", 0)
            .add_script(
                "apt-get",
                &prints("Inst openssl [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-security [amd64])\n"),
            )
            .add_script("ss", &prints(SS));
        let fixture = Fixture::new(&fake);
        fixture.write("reboot-required", "*** System restart required ***\n");
        fixture.write(
            "apt.conf.d/20auto-upgrades",
            "APT::Periodic::Unattended-Upgrade \"0\";\n",
        );
        fixture.write("passwd", &format!("{PASSWD}toor:x:0:0::/root:/bin/sh\n"));
        fixture.write("proc_sys/kernel/randomize_va_space", "0\n");
        fixture.write("sys/devices/system/cpu/vulnerabilities/mds", "Vulnerable\n");
        fixture.write("sys/module/apparmor/parameters/enabled", "N\n");
        let text = ok_text(fixture.run("rita").await);
        let first = text.lines().next().unwrap();
        assert!(
            first.starts_with("9 warnings: ssh: PermitRootLogin yes"),
            "{text}"
        );
        assert_eq!(text.matches("[WARN]").count(), 9, "{text}");
        assert!(
            section(&text, "== firewall ==").contains("[WARN] no firewall"),
            "{text}"
        );
        let updates = section(&text, "== updates ==");
        assert!(
            updates.contains("[WARN] 1 security update is pending"),
            "{text}"
        );
        assert!(updates.contains("[WARN] a reboot is needed"), "{text}");
        assert!(
            updates.contains("[info] unattended upgrades are off"),
            "{text}"
        );
        assert!(
            section(&text, "== accounts ==").contains("[WARN] toor has uid 0"),
            "{text}"
        );
        assert!(
            section(&text, "== kernel ==").contains("[WARN] CPU vulnerability mds"),
            "{text}"
        );
        // the nft ruleset was empty, so iptables was asked as well
        assert_eq!(
            fake.calls("iptables"),
            vec![strings(&["-w", "5", "-S", "INPUT"])]
        );
    }

    #[tokio::test]
    async fn sections_that_belong_to_other_permissions_need_them() {
        let fake = sound_host();
        let fixture = Fixture::new(&fake);
        // nan holds security.view and nothing else
        let text = ok_text(fixture.run("nan").await);
        for (title, permission) in [
            ("== firewall ==", "firewall.view"),
            ("== updates ==", "package.view"),
            ("== accounts ==", "user.view"),
            ("== listening ==", "net.view"),
        ] {
            assert_eq!(
                section(&text, title),
                format!("\n[section left out: needs {permission}]\n"),
                "{text}"
            );
        }
        assert!(
            text.lines().next().unwrap().contains("4 sections left out"),
            "{text}"
        );
        // its own sections are there
        assert!(
            section(&text, "== ssh ==").contains("PasswordAuthentication"),
            "{text}"
        );
        assert!(
            section(&text, "== kernel ==").contains("randomize_va_space"),
            "{text}"
        );
        // and nothing was run or read for the others
        assert!(fake.calls("nft").is_empty());
        assert!(fake.calls("apt-get").is_empty());
        assert!(fake.calls("ss").is_empty());
        // (carol is only in the passwd file; alice is also in sshd's own AllowUsers)
        assert!(
            !text.contains("carol") && !text.contains("uid 0") && !text.contains("sudo"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn a_check_that_cannot_be_made_says_so_and_the_rest_goes_on() {
        // as an ordinary user sees it: sshd and nft refuse, apt-get fails
        let fake = FakeBins::new()
            .add_script(
                "sshd",
                "echo 'sshd: no hostkeys available -- exiting.' >&2\nexit 1",
            )
            .add_script(
                "nft",
                "echo 'Operation not permitted (you must be root)' >&2\nexit 1",
            )
            .add("dpkg-query", "", 0)
            .add_script(
                "apt-get",
                "echo 'E: Could not open lock file' >&2\nexit 100",
            )
            .add_script("ss", &prints(SS));
        let fixture = Fixture::new(&fake);
        std::fs::remove_file(fixture.path("shadow")).unwrap();
        let text = ok_text(fixture.run("rita").await);
        assert!(
            section(&text, "== ssh ==")
                .contains("[not checked] sshd -T: sshd: no hostkeys available"),
            "{text}"
        );
        assert!(
            section(&text, "== firewall ==").contains("[not checked]"),
            "{text}"
        );
        assert!(
            section(&text, "== updates ==")
                .contains("[not checked] pending updates: E: Could not open lock file"),
            "{text}"
        );
        assert!(
            section(&text, "== accounts ==").contains("[not checked]"),
            "{text}"
        );
        assert!(
            section(&text, "== listening ==").contains("tcp 22"),
            "{text}"
        );
        let first = text.lines().next().unwrap();
        assert!(
            first.starts_with("No warnings in what was checked"),
            "{text}"
        );
        assert!(first.contains("checks not made"), "{text}");
    }

    #[tokio::test]
    async fn a_host_without_the_programs_still_gets_every_section() {
        let fake = FakeBins::new();
        let fixture = Fixture::new(&fake);
        let text = ok_text(fixture.run("rita").await);
        for title in TITLES {
            assert!(text.contains(title), "{title} missing in:\n{text}");
        }
        assert!(
            section(&text, "== ssh ==").contains("[info] sshd is not installed"),
            "{text}"
        );
        assert!(
            section(&text, "== firewall ==")
                .contains("[not checked] neither nft nor iptables is installed"),
            "{text}"
        );
        assert!(
            section(&text, "== updates ==").contains("[not checked] no supported package manager"),
            "{text}"
        );
        assert!(
            section(&text, "== listening ==").contains("[not checked]"),
            "{text}"
        );
    }

    /// AIDEV-NOTE: "no updates are pending" is read from package lists that may not have
    /// been refreshed for months. Their age is said, so the count is not taken for more
    /// than it is.
    #[tokio::test]
    async fn the_updates_section_says_how_old_the_package_lists_are() {
        let fake = sound_host();
        let fixture = Fixture::new(&fake);
        let now = crate::timefmt::now_secs();
        // apt's stamp, touched an hour ago
        fixture.write("apt-stamp", "");
        set_mtime(&fixture.path("apt-stamp"), now - 3600);
        let text = ok_text(fixture.run("rita").await);
        let updates = section(&text, "== updates ==");
        assert!(
            updates.contains("[info] the package lists were last refreshed 1h ago\n"),
            "{text}"
        );
        assert_eq!(text.lines().next().unwrap(), "No warnings.", "{text}");

        // no stamp: the lists directory itself; and a month old
        std::fs::remove_file(fixture.path("apt-stamp")).unwrap();
        fixture.write("apt-lists/lock", "");
        let lists = std::fs::File::open(fixture.path("apt-lists")).unwrap();
        lists
            .set_modified(
                std::time::UNIX_EPOCH + std::time::Duration::from_secs((now - 30 * 86_400) as u64),
            )
            .unwrap();
        let text = ok_text(fixture.run("rita").await);
        let updates = section(&text, "== updates ==");
        assert!(
            updates.contains(
                "[info] the package lists were last refreshed 30d ago: the counts of pending \
                 updates may be out of date"
            ),
            "{text}"
        );
    }

    #[tokio::test]
    async fn an_rpm_host_says_how_old_its_cache_is() {
        let fake = FakeBins::new()
            .add("rpm", "", 0)
            .add_script("dnf", "exit 0")
            .add_script("systemctl", "echo disabled")
            .add_script("needs-restarting", "exit 0");
        let fixture = Fixture::new(&fake);
        fixture.write("dnf-cache/baseos-0123abcd/repodata/repomd.xml", "x");
        let now = crate::timefmt::now_secs();
        set_mtime(
            &fixture.path("dnf-cache/baseos-0123abcd/repodata/repomd.xml"),
            now - 12 * 86_400,
        );
        let text = ok_text(fixture.run("rita").await);
        let updates = section(&text, "== updates ==");
        assert!(
            updates.contains("[ok] no security updates are pending (going by dnf's cache)"),
            "{text}"
        );
        assert!(
            updates.contains(
                "[info] the package lists were last refreshed 12d ago: the counts of pending \
                 updates may be out of date"
            ),
            "{text}"
        );
    }

    #[tokio::test]
    async fn an_rpm_host_is_asked_through_dnf_and_systemctl() {
        let fake = FakeBins::new()
            .add("rpm", "", 0)
            .add_script(
                "dnf",
                "printf '\\nopenssl-libs.x86_64   1:3.0.7-28.el9_4   baseos\\nkernel.x86_64   5.14.0-427.el9   baseos\\n'\nexit 100",
            )
            .add_script("systemctl", "echo enabled")
            .add_script("needs-restarting", "echo 'Reboot is required to fully utilize these updates.'\nexit 1");
        let fixture = Fixture::new(&fake);
        let text = ok_text(fixture.run("rita").await);
        let updates = section(&text, "== updates ==");
        assert!(
            updates.contains("[WARN] 2 security updates are pending"),
            "{text}"
        );
        assert!(updates.contains("[WARN] a reboot is needed"), "{text}");
        assert!(
            updates.contains("[ok] unattended upgrades are switched on (dnf-automatic.timer)"),
            "{text}"
        );
        assert_eq!(
            fake.calls("dnf"),
            vec![strings(&["-q", "-C", "check-update", "--security"])]
        );
        assert_eq!(
            fake.calls("systemctl"),
            vec![strings(&["is-enabled", "--", "dnf-automatic.timer"])]
        );
        assert_eq!(fake.calls("needs-restarting"), vec![strings(&["-r"])]);
    }

    #[tokio::test]
    async fn it_needs_security_view() {
        let fake = sound_host();
        let fixture = Fixture::new(&fake);
        match fixture.run("nora").await {
            Err(ToolError::Denied(message)) => {
                assert!(message.contains("security.view"), "{message}")
            }
            other => panic!("expected a denial, got {other:?}"),
        }
        assert!(fake.calls("sshd").is_empty());
    }

    #[tokio::test]
    async fn a_hung_command_costs_one_check_not_the_answer() {
        let fake = FakeBins::new()
            .add_script("sshd", "while :; do :; done")
            .add_script("ss", &prints(SS));
        let dir = tempfile::tempdir().unwrap();
        let (host, _sink) = host(&format!(
            "[roles.reader]\nallow = [\"@read\"]\n[unix_users.rita]\nroles = [\"reader\"]\n[limits]\ncommand_timeout_secs = 1\ncall_timeout_secs = 20\n{}",
            fake.config_only()
        ));
        let roots = Roots {
            passwd: dir.path().join("passwd"),
            group: dir.path().join("group"),
            shadow: dir.path().join("shadow"),
            apt_conf_dir: dir.path().join("apt"),
            reboot_required: dir.path().join("reboot"),
            selinux_config: dir.path().join("selinux"),
            proc_sys: dir.path().join("proc"),
            sys: dir.path().join("sys"),
            lists_stamp: dir.path().join("stamp"),
            lists_dir: dir.path().join("lists"),
            rpm_caches: vec![dir.path().join("dnf")],
        };
        let tool = find(tools_with(roots), "security_posture");
        let text = ok_text(call(&host, "rita", &tool, json!({})).await);
        assert!(
            section(&text, "== ssh ==")
                .contains("[not checked] sshd -T: it did not finish in time"),
            "{text}"
        );
        assert!(
            section(&text, "== listening ==").contains("tcp 22"),
            "{text}"
        );
    }
}
