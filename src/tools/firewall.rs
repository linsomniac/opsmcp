//! Firewall: view and change iptables/ip6tables and nftables rules and counters.
//!
//! Changes act on the running ruleset only; nothing is saved, so a reboot (or whatever
//! manages the firewall on the host) brings the configured rules back.
//!
//! AIDEV-NOTE: a grant for `firewall.modify` is scoped by chain, e.g.
//! `firewall.modify:iptables/filter/OPSMCP-*`. That scoping only means something if a
//! caller cannot smuggle a different table, chain or command into the rule itself, which
//! is what `check_iptables_spec` and `check_nft_tokens` are for. Both are allowlists in
//! spirit: keep them strict.

use super::args::{Args, Param};
use super::{Ctx, Tool, ToolError, ToolResult, command_ok, command_text, required};
use crate::policy::Access;

const IPTABLES_TABLES: [&str; 5] = ["filter", "nat", "mangle", "raw", "security"];
const NFT_FAMILIES: [&str; 6] = ["inet", "ip", "ip6", "arp", "bridge", "netdev"];

pub fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "iptables_list",
            "Show iptables (or ip6tables) rules with packet and byte counters and rule \
             numbers. format=save gives iptables-save output instead, which shows each rule \
             exactly as it would be written.",
            Access::Read,
            "firewall.view",
            vec![
                Param::choice(
                    "family",
                    "ipv4 (iptables, the default) or ipv6 (ip6tables)",
                    &["ipv4", "ipv6"],
                ),
                Param::choice("table", "Table (default filter)", &IPTABLES_TABLES),
                Param::str("chain", "Only this chain").max_len(29),
                Param::choice("format", "rules (the default) or save", &["rules", "save"]),
            ],
            iptables_list,
        ),
        Tool::new(
            "nft_list",
            "Show nftables rules with their handles (needed to delete a rule): the whole \
             ruleset, one table, or one chain.",
            Access::Read,
            "firewall.view",
            vec![
                Param::choice("family", "Address family of the table", &NFT_FAMILIES),
                Param::str("table", "Only this table (needs family)").max_len(64),
                Param::str("chain", "Only this chain (needs family and table)").max_len(64),
            ],
            nft_list,
        ),
        Tool::new(
            "iptables_rule",
            "Change iptables (or ip6tables) rules in one chain of the running firewall: \
             append, insert or delete a rule, or flush the chain. Give the rule as a list of \
             arguments exactly as on an iptables command line after the chain name, e.g. \
             [\"-p\",\"tcp\",\"--dport\",\"8080\",\"-j\",\"ACCEPT\"]. Not saved: a reboot or \
             firewall reload restores the configured rules. Take care not to cut off your \
             own access.",
            Access::Write,
            "firewall.modify",
            vec![
                Param::choice(
                    "family",
                    "ipv4 (iptables, the default) or ipv6 (ip6tables)",
                    &["ipv4", "ipv6"],
                ),
                Param::choice("table", "Table (default filter)", &IPTABLES_TABLES),
                Param::str("chain", "Chain to change")
                    .max_len(29)
                    .required(),
                Param::choice(
                    "action",
                    "What to do",
                    &["append", "insert", "delete", "flush"],
                )
                .required(),
                Param::list(
                    "rule",
                    "The rule, as a list of iptables arguments (append, insert, or delete by rule)",
                ),
                Param::int(
                    "position",
                    "Rule number: where to insert, or which rule to delete",
                    1,
                    100_000,
                ),
            ],
            iptables_rule,
        ),
        Tool::new(
            "nft_rule",
            "Change nftables rules in one chain of the running firewall: add or insert a \
             rule, delete a rule by its handle (see nft_list), or flush the chain. Give the \
             rule as a list of words, e.g. [\"tcp\",\"dport\",\"8080\",\"accept\"]. Not saved: \
             a reboot or firewall reload restores the configured rules. Take care not to cut \
             off your own access.",
            Access::Write,
            "firewall.modify",
            vec![
                Param::choice("family", "Address family of the table", &NFT_FAMILIES).required(),
                Param::str("table", "Table").max_len(64).required(),
                Param::str("chain", "Chain to change")
                    .max_len(64)
                    .required(),
                Param::choice(
                    "action",
                    "What to do",
                    &["add", "insert", "delete", "flush"],
                )
                .required(),
                Param::list("rule", "The rule, as a list of words (add or insert)"),
                Param::int("handle", "Handle of the rule to delete", 1, i64::MAX),
            ],
            nft_rule,
        ),
        Tool::new(
            "firewall_reset_counters",
            "Reset firewall packet and byte counters to zero: an iptables/ip6tables table or \
             one of its chains, or the named counters of nftables (all, or one table's).",
            Access::Write,
            "firewall.modify",
            vec![
                Param::choice(
                    "backend",
                    "Which firewall",
                    &["iptables", "ip6tables", "nft"],
                )
                .required(),
                Param::str(
                    "table",
                    "Table (iptables: default filter; nft: needs family)",
                )
                .max_len(64),
                Param::str("chain", "iptables only: just this chain").max_len(29),
                Param::choice(
                    "family",
                    "nft only: address family of the table",
                    &NFT_FAMILIES,
                ),
            ],
            firewall_reset_counters,
        ),
    ]
}

/// Checks a table or chain name: letters, digits, `_`, `.` and `-`, not starting with `-`.
pub fn check_name(kind: &str, name: &str, max: usize) -> Result<(), ToolError> {
    let valid = !name.is_empty()
        && name.len() <= max
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c));
    if valid {
        Ok(())
    } else {
        Err(ToolError::Invalid(format!(
            "{name:?} is not a valid {kind} name"
        )))
    }
}

/// The short options that belong to a rule. Every other argument starting with a single
/// `-` is refused, which also rules out clustered options such as `-nF`.
const RULE_SHORT_OPTIONS: [&str; 12] = [
    "-p", "-s", "-d", "-i", "-o", "-j", "-g", "-m", "-f", "-c", "-4", "-6",
];

/// Long options that are commands, select a table, or run a program. iptables accepts
/// any unambiguous abbreviation of a long option, so abbreviations are refused too.
const FORBIDDEN_LONG_OPTIONS: [&str; 17] = [
    "table",
    "append",
    "delete",
    "insert",
    "replace",
    "list",
    "list-rules",
    "flush",
    "zero",
    "new-chain",
    "delete-chain",
    "policy",
    "rename-chain",
    "check",
    "modprobe",
    "help",
    "version",
];

/// Checks an iptables rule given as arguments. Refuses anything that is not part of a
/// rule: another command, another table, or an option that makes iptables run a program.
pub fn check_iptables_spec(tokens: &[&str]) -> Result<(), String> {
    if tokens.is_empty() {
        return Err("the rule is empty".to_string());
    }
    for token in tokens {
        if token.is_empty() {
            return Err("the rule contains an empty argument".to_string());
        }
        if let Some(long) = token.strip_prefix("--") {
            let name = long.split('=').next().unwrap_or(long);
            if name.is_empty() || FORBIDDEN_LONG_OPTIONS.iter().any(|f| f.starts_with(name)) {
                return Err(format!("{token:?} is not allowed in a rule"));
            }
        } else if token.starts_with('-') && !RULE_SHORT_OPTIONS.contains(token) {
            return Err(format!(
                "{token:?} is not allowed in a rule (give each option separately, long options in full)"
            ));
        }
    }
    Ok(())
}

/// One iptables change, as parsed from the tool's arguments.
pub struct IptablesChange<'a> {
    pub table: &'a str,
    pub chain: &'a str,
    pub action: &'a str,
    pub rule: Option<Vec<&'a str>>,
    pub position: Option<i64>,
}

/// The arguments for iptables (after the program name) that carry out a change.
pub fn iptables_argv(change: &IptablesChange) -> Result<Vec<String>, ToolError> {
    check_name("chain", change.chain, 29)?;
    if let Some(rule) = &change.rule {
        check_iptables_spec(rule).map_err(|e| ToolError::Invalid(format!("rule: {e}")))?;
    }
    let invalid = |problem: &str| Err(ToolError::Invalid(problem.to_string()));
    // -w: wait for the xtables lock rather than fail if another tool holds it.
    let mut argv: Vec<String> = ["-w", "5", "-t", change.table]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let chain = change.chain.to_string();
    let rule = change
        .rule
        .as_ref()
        .map(|r| r.iter().map(|s| s.to_string()));
    match (change.action, rule, change.position) {
        ("append", Some(rule), None) => {
            argv.extend(["-A".to_string(), chain]);
            argv.extend(rule);
        }
        ("insert", Some(rule), position) => {
            argv.extend(["-I".to_string(), chain]);
            argv.extend(position.map(|p| p.to_string()));
            argv.extend(rule);
        }
        ("delete", Some(rule), None) => {
            argv.extend(["-D".to_string(), chain]);
            argv.extend(rule);
        }
        ("delete", None, Some(position)) => {
            argv.extend(["-D".to_string(), chain, position.to_string()])
        }
        ("flush", None, None) => argv.extend(["-F".to_string(), chain]),
        ("append", ..) => return invalid("append needs a rule and takes no position"),
        ("insert", ..) => return invalid("insert needs a rule"),
        ("delete", ..) => {
            return invalid(
                "delete needs either a rule or a position (the rule's number), not both",
            );
        }
        ("flush", ..) => return invalid("flush takes neither a rule nor a position"),
        _ => return invalid("unknown action"),
    }
    Ok(argv)
}

/// Checks an nftables rule given as words. nft joins its arguments and parses the result
/// as a script, so a `;` or a newline would start a second command.
pub fn check_nft_tokens(tokens: &[&str]) -> Result<(), String> {
    if tokens.is_empty() {
        return Err("the rule is empty".to_string());
    }
    for token in tokens {
        let refused = || Err(format!("{token:?} is not allowed in a rule"));
        if token.is_empty() || token.starts_with('-') || token.eq_ignore_ascii_case("include") {
            return refused();
        }
        // A word, or one double-quoted string (which may contain spaces).
        let quoted = token.len() >= 2 && token.starts_with('"') && token.ends_with('"');
        let inner = if quoted {
            &token[1..token.len() - 1]
        } else {
            token
        };
        let dangerous =
            |c: char| c.is_control() || ";\\`$#\"".contains(c) || (!quoted && c.is_whitespace());
        if inner.chars().any(dangerous) {
            return refused();
        }
    }
    Ok(())
}

/// One nftables change, as parsed from the tool's arguments.
pub struct NftChange<'a> {
    pub family: &'a str,
    pub table: &'a str,
    pub chain: &'a str,
    pub action: &'a str,
    pub rule: Option<Vec<&'a str>>,
    pub handle: Option<i64>,
}

/// The arguments for nft (after the program name) that carry out a change.
pub fn nft_argv(change: &NftChange) -> Result<Vec<String>, ToolError> {
    check_name("table", change.table, 64)?;
    check_name("chain", change.chain, 64)?;
    if let Some(rule) = &change.rule {
        check_nft_tokens(rule).map_err(|e| ToolError::Invalid(format!("rule: {e}")))?;
    }
    let invalid = |problem: &str| Err(ToolError::Invalid(problem.to_string()));
    let place: Vec<String> = [change.family, change.table, change.chain]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let rule = change
        .rule
        .as_ref()
        .map(|r| r.iter().map(|s| s.to_string()));
    let mut argv = Vec::new();
    match (change.action, rule, change.handle) {
        ("add" | "insert", Some(rule), None) => {
            argv.extend([change.action.to_string(), "rule".to_string()]);
            argv.extend(place);
            argv.extend(rule);
        }
        ("delete", None, Some(handle)) => {
            argv.extend(["delete".to_string(), "rule".to_string()]);
            argv.extend(place);
            argv.extend(["handle".to_string(), handle.to_string()]);
        }
        ("flush", None, None) => {
            argv.extend(["flush".to_string(), "chain".to_string()]);
            argv.extend(place);
        }
        ("add" | "insert", ..) => return invalid("add and insert need a rule and take no handle"),
        ("delete", ..) => {
            return invalid("delete needs the rule's handle (see nft_list) and takes no rule");
        }
        ("flush", ..) => return invalid("flush takes neither a rule nor a handle"),
        _ => return invalid("unknown action"),
    }
    Ok(argv)
}

const NOT_SAVED: &str = "[changed in the running firewall only; not saved]\n";

async fn iptables_list(ctx: Ctx, args: Args) -> ToolResult {
    let ipv6 = args.str("family") == Some("ipv6");
    let table = args.str("table").unwrap_or("filter");
    let chain = args.str("chain");
    if let Some(chain) = chain {
        check_name("chain", chain, 29)?;
    }
    let save = args.str("format") == Some("save");
    if save && chain.is_some() {
        return Err(ToolError::Invalid(
            "format=save shows a whole table; leave out chain".to_string(),
        ));
    }
    let auth = ctx.authorize(None)?;
    let cmd = if save {
        let program = if ipv6 {
            "ip6tables-save"
        } else {
            "iptables-save"
        };
        ctx.command(program)?.args(["-c", "-t", table])
    } else {
        let program = if ipv6 { "ip6tables" } else { "iptables" };
        let mut argv = vec!["-w", "5", "-t", table, "-L"];
        argv.extend(chain);
        argv.extend(["-n", "-v", "-x", "--line-numbers"]);
        ctx.command(program)?.args(argv)
    };
    let out = ctx.run(cmd).await?;
    auth.done(command_text(&out), command_ok(&out))
}

async fn nft_list(ctx: Ctx, args: Args) -> ToolResult {
    let mut argv = vec!["-a", "list"];
    match (args.str("family"), args.str("table"), args.str("chain")) {
        (None, None, None) => argv.push("ruleset"),
        (Some(family), None, None) => argv.extend(["ruleset", family]),
        (Some(family), Some(table), None) => {
            check_name("table", table, 64)?;
            argv.extend(["table", family, table]);
        }
        (Some(family), Some(table), Some(chain)) => {
            check_name("table", table, 64)?;
            check_name("chain", chain, 64)?;
            argv.extend(["chain", family, table, chain]);
        }
        _ => {
            return Err(ToolError::Invalid(
                "a table needs its family, and a chain needs its family and table".to_string(),
            ));
        }
    }
    let auth = ctx.authorize(None)?;
    let out = ctx.run(ctx.command("nft")?.args(argv)).await?;
    auth.done(command_text(&out), command_ok(&out))
}

async fn iptables_rule(ctx: Ctx, args: Args) -> ToolResult {
    let program = if args.str("family") == Some("ipv6") {
        "ip6tables"
    } else {
        "iptables"
    };
    let table = args.str("table").unwrap_or("filter");
    let chain = required(&args, "chain")?;
    let argv = iptables_argv(&IptablesChange {
        table,
        chain,
        action: required(&args, "action")?,
        rule: args.list("rule"),
        position: args.int("position"),
    })?;
    let auth = ctx.authorize(Some(&format!("{program}/{table}/{chain}")))?;
    let out = ctx.run(ctx.command(program)?.args(argv)).await?;
    let succeeded = command_ok(&out);
    let mut text = command_text(&out);
    if succeeded {
        text.push_str(NOT_SAVED);
    }
    auth.done(text, succeeded)
}

async fn nft_rule(ctx: Ctx, args: Args) -> ToolResult {
    let (family, table, chain) = (
        required(&args, "family")?,
        required(&args, "table")?,
        required(&args, "chain")?,
    );
    let argv = nft_argv(&NftChange {
        family,
        table,
        chain,
        action: required(&args, "action")?,
        rule: args.list("rule"),
        handle: args.int("handle"),
    })?;
    let auth = ctx.authorize(Some(&format!("nft/{family}/{table}/{chain}")))?;
    let out = ctx.run(ctx.command("nft")?.args(argv)).await?;
    let succeeded = command_ok(&out);
    let mut text = command_text(&out);
    if succeeded {
        text.push_str(NOT_SAVED);
    }
    auth.done(text, succeeded)
}

async fn firewall_reset_counters(ctx: Ctx, args: Args) -> ToolResult {
    let backend = required(&args, "backend")?;
    let (table, chain, family) = (args.str("table"), args.str("chain"), args.str("family"));
    let invalid = |problem: &str| Err(ToolError::Invalid(problem.to_string()));
    let mut argv: Vec<&str> = Vec::new();
    // "*" stands for "every chain": only a grant that covers every chain matches it.
    let resource = if backend == "nft" {
        if chain.is_some() {
            return invalid("nft counters are reset per table, not per chain");
        }
        argv.extend(["reset", "counters"]);
        match (family, table) {
            (None, None) => "nft/*".to_string(),
            (Some(family), Some(table)) => {
                check_name("table", table, 64)?;
                argv.extend(["table", family, table]);
                format!("nft/{family}/{table}/*")
            }
            _ => return invalid("give both family and table, or neither for every counter"),
        }
    } else {
        if family.is_some() {
            return invalid(
                "family is for nft; choose iptables or ip6tables as the backend instead",
            );
        }
        let table = table.unwrap_or("filter");
        if !IPTABLES_TABLES.contains(&table) {
            return invalid("table must be one of filter, nat, mangle, raw, security");
        }
        argv.extend(["-w", "5", "-t", table, "-Z"]);
        if let Some(chain) = chain {
            check_name("chain", chain, 29)?;
            argv.push(chain);
        }
        format!("{backend}/{table}/{}", chain.unwrap_or("*"))
    };
    let auth = ctx.authorize(Some(&resource))?;
    let out = ctx.run(ctx.command(backend)?.args(argv)).await?;
    let succeeded = command_ok(&out);
    let mut text = command_text(&out);
    if succeeded {
        text.push_str("Counters reset.\n");
    }
    auth.done(text, succeeded)
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
    fn check_name_accepts_ordinary_names_only() {
        for good in ["INPUT", "OPSMCP-IN", "f2b-sshd", "my_chain.1", "filter"] {
            assert!(check_name("chain", good, 29).is_ok(), "{good}");
        }
        let long = "X".repeat(30);
        for bad in [
            "",
            "-j",
            "--flush",
            "IN PUT",
            "INPUT;x",
            "a/b",
            "{x}",
            long.as_str(),
        ] {
            assert!(check_name("chain", bad, 29).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn ordinary_iptables_rules_are_accepted() {
        let rules: &[&[&str]] = &[
            &["-p", "tcp", "--dport", "8080", "-j", "ACCEPT"],
            &[
                "-s",
                "10.0.0.0/8",
                "-m",
                "comment",
                "--comment",
                "allow the lan",
                "-j",
                "DROP",
            ],
            &["!", "-i", "lo", "-j", "LOG", "--log-prefix", "fw: "],
            &[
                "-p",
                "tcp",
                "-m",
                "multiport",
                "--dports",
                "80,443",
                "-m",
                "conntrack",
                "--ctstate",
                "NEW",
                "-j",
                "ACCEPT",
            ],
            &[
                "-d",
                "2001:db8::/32",
                "-j",
                "REJECT",
                "--reject-with",
                "icmp6-adm-prohibited",
            ],
            &[
                "--protocol",
                "udp",
                "--destination-port",
                "53",
                "--jump",
                "ACCEPT",
            ],
            &[
                "-p",
                "tcp",
                "--tcp-flags",
                "SYN,ACK",
                "SYN",
                "-j",
                "TCPMSS",
                "--set-mss",
                "1400",
            ],
            &[
                "-i",
                "eth0",
                "-o",
                "eth1",
                "-j",
                "MASQUERADE",
                "--to-ports",
                "1024-65535",
            ],
            &[
                "-m",
                "statistic",
                "--mode",
                "random",
                "--probability",
                "0.5",
                "-g",
                "OTHER",
            ],
        ];
        for rule in rules {
            assert_eq!(check_iptables_spec(rule), Ok(()), "{rule:?}");
        }
    }

    #[test]
    fn iptables_rules_that_reach_beyond_the_rule_are_refused() {
        let rules: &[&[&str]] = &[
            // another table
            &["-t", "nat", "-j", "ACCEPT"],
            &["--table", "nat"],
            &["--table=nat"],
            &["--tab", "nat"],
            &["-tnat"],
            // another command or chain
            &["-A", "INPUT", "-j", "ACCEPT"],
            &["-D", "INPUT", "1"],
            &["-I", "INPUT"],
            &["-F"],
            &["--flush"],
            &["--flu"],
            &["-P", "INPUT", "ACCEPT"],
            &["--policy", "INPUT", "ACCEPT"],
            &["-N", "x"],
            &["-X"],
            &["-Z"],
            &["-E", "a", "b"],
            &["-R", "INPUT", "1"],
            &["-L"],
            &["-S"],
            &["-C", "INPUT"],
            &["--append", "INPUT"],
            &["--delete-chain"],
            &["--new-chain", "x"],
            &["--rename-chain", "a", "b"],
            // clustered short options hide a command behind a harmless one
            &["-nF"],
            &["-vL"],
            // options that make iptables run a program
            &["--modprobe=/tmp/evil"],
            &["--modprobe", "/tmp/evil"],
            &["--modp=/tmp/evil"],
            &["-M", "/tmp/evil"],
            // not a rule at all
            &[],
            &[""],
            &["-j", ""],
            &["-h"],
            &["--help"],
            &["-V"],
        ];
        for rule in rules {
            assert!(
                check_iptables_spec(rule).is_err(),
                "{rule:?} should be refused"
            );
        }
    }

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn iptables(
        action: &str,
        rule: Option<&[&'static str]>,
        position: Option<i64>,
    ) -> Result<Vec<String>, ToolError> {
        iptables_argv(&IptablesChange {
            table: "filter",
            chain: "INPUT",
            action,
            rule: rule.map(<[&str]>::to_vec),
            position,
        })
    }

    #[test]
    fn iptables_argv_builds_each_kind_of_change() {
        let rule: &[&str] = &["-p", "tcp", "-j", "ACCEPT"];
        assert_eq!(
            iptables("append", Some(rule), None).unwrap(),
            strings(&[
                "-w", "5", "-t", "filter", "-A", "INPUT", "-p", "tcp", "-j", "ACCEPT"
            ])
        );
        assert_eq!(
            iptables("insert", Some(rule), Some(3)).unwrap(),
            strings(&[
                "-w", "5", "-t", "filter", "-I", "INPUT", "3", "-p", "tcp", "-j", "ACCEPT"
            ])
        );
        assert_eq!(
            iptables("insert", Some(rule), None).unwrap(),
            strings(&[
                "-w", "5", "-t", "filter", "-I", "INPUT", "-p", "tcp", "-j", "ACCEPT"
            ])
        );
        assert_eq!(
            iptables("delete", Some(rule), None).unwrap(),
            strings(&[
                "-w", "5", "-t", "filter", "-D", "INPUT", "-p", "tcp", "-j", "ACCEPT"
            ])
        );
        assert_eq!(
            iptables("delete", None, Some(4)).unwrap(),
            strings(&["-w", "5", "-t", "filter", "-D", "INPUT", "4"])
        );
        assert_eq!(
            iptables("flush", None, None).unwrap(),
            strings(&["-w", "5", "-t", "filter", "-F", "INPUT"])
        );
    }

    #[test]
    fn iptables_argv_refuses_combinations_that_make_no_sense() {
        let rule: &[&str] = &["-j", "ACCEPT"];
        for (action, rule, position) in [
            ("append", None, None),
            ("append", Some(rule), Some(2)),
            ("insert", None, Some(1)),
            ("delete", None, None),
            ("delete", Some(rule), Some(2)),
            ("flush", Some(rule), None),
            ("flush", None, Some(1)),
            ("append", Some(&["-t", "nat"][..]), None),
        ] {
            let result = iptables(action, rule, position);
            assert!(
                matches!(result, Err(ToolError::Invalid(_))),
                "{action} {rule:?} {position:?}: {result:?}"
            );
        }
    }

    #[test]
    fn ordinary_nft_rules_are_accepted() {
        let rules: &[&[&str]] = &[
            &["tcp", "dport", "8080", "accept"],
            &["ip", "saddr", "10.0.0.0/8", "counter", "drop"],
            &[
                "tcp", "dport", "{", "80,", "443", "}", "ct", "state", "new", "accept",
            ],
            &[
                "iifname",
                "\"eth0\"",
                "comment",
                "\"web traffic\"",
                "accept",
            ],
            &[
                "ip6",
                "saddr",
                "2001:db8::/32",
                "log",
                "prefix",
                "\"fw:\"",
                "reject",
            ],
            &[
                "meta",
                "l4proto",
                "icmp",
                "limit",
                "rate",
                "10/second",
                "accept",
            ],
        ];
        for rule in rules {
            assert_eq!(check_nft_tokens(rule), Ok(()), "{rule:?}");
        }
    }

    #[test]
    fn nft_rules_that_could_start_another_command_are_refused() {
        let rules: &[&[&str]] = &[
            &["accept", ";", "flush", "ruleset"],
            &["accept;", "flush", "ruleset"],
            &["accept;flush"],
            &["-f", "/etc/passwd"],
            &["--file", "/etc/passwd"],
            &["$evil"],
            &["a\\b"],
            &["include", "\"/etc/nftables.conf\""],
            &["#", "comment"],
            &["two words"],
            &["\"unterminated"],
            &["\"a\"b\""],
            &["`x`"],
            &[""],
            &[],
        ];
        for rule in rules {
            assert!(
                check_nft_tokens(rule).is_err(),
                "{rule:?} should be refused"
            );
        }
    }

    fn nft(
        action: &str,
        rule: Option<&[&'static str]>,
        handle: Option<i64>,
    ) -> Result<Vec<String>, ToolError> {
        nft_argv(&NftChange {
            family: "inet",
            table: "filter",
            chain: "input",
            action,
            rule: rule.map(<[&str]>::to_vec),
            handle,
        })
    }

    #[test]
    fn nft_argv_builds_each_kind_of_change() {
        let rule: &[&str] = &["tcp", "dport", "8080", "accept"];
        assert_eq!(
            nft("add", Some(rule), None).unwrap(),
            strings(&[
                "add", "rule", "inet", "filter", "input", "tcp", "dport", "8080", "accept"
            ])
        );
        assert_eq!(
            nft("insert", Some(rule), None).unwrap(),
            strings(&[
                "insert", "rule", "inet", "filter", "input", "tcp", "dport", "8080", "accept"
            ])
        );
        assert_eq!(
            nft("delete", None, Some(12)).unwrap(),
            strings(&["delete", "rule", "inet", "filter", "input", "handle", "12"])
        );
        assert_eq!(
            nft("flush", None, None).unwrap(),
            strings(&["flush", "chain", "inet", "filter", "input"])
        );
    }

    #[test]
    fn nft_argv_refuses_combinations_that_make_no_sense() {
        let rule: &[&str] = &["accept"];
        for (action, rule, handle) in [
            ("add", None, None),
            ("add", Some(rule), Some(3)),
            ("delete", None, None),
            ("delete", Some(rule), Some(3)),
            ("flush", Some(rule), None),
            ("add", Some(&["accept;", "flush", "ruleset"][..]), None),
        ] {
            let result = nft(action, rule, handle);
            assert!(
                matches!(result, Err(ToolError::Invalid(_))),
                "{action} {rule:?} {handle:?}: {result:?}"
            );
        }
    }

    fn fakes() -> FakeBins {
        FakeBins::new()
            .add("iptables", "Chain INPUT (policy ACCEPT)\n", 0)
            .add("ip6tables", "Chain INPUT (policy ACCEPT)\n", 0)
            .add("iptables-save", "*filter\nCOMMIT\n", 0)
            .add("ip6tables-save", "*filter\nCOMMIT\n", 0)
            .add("nft", "table inet filter {\n}\n", 0)
    }

    fn fixture(fake: &FakeBins) -> (Arc<Host>, MemorySink) {
        host(&format!(
            r#"
[roles.admin]
allow = ["@all"]
[roles.reader]
allow = ["@read"]
[roles.scoped]
allow = ["firewall.modify:iptables/filter/OPSMCP-*", "firewall.modify:nft/inet/filter/opsmcp"]
[unix_users.adam]
roles = ["admin"]
[unix_users.rita]
roles = ["reader"]
[unix_users.sid]
roles = ["scoped"]
{}"#,
            fake.config()
        ))
    }

    async fn run(host: &Arc<Host>, user: &str, tool: &str, arguments: Value) -> ToolResult {
        call(host, user, &find(tools(), tool), arguments).await
    }

    #[tokio::test]
    async fn iptables_list_runs_the_listing_for_the_chosen_family_and_table() {
        let fake = fakes();
        let (host, _audit) = fixture(&fake);
        let text = ok_text(run(&host, "rita", "iptables_list", json!({})).await);
        assert!(text.contains("Chain INPUT"), "{text}");
        ok_text(
            run(
                &host,
                "rita",
                "iptables_list",
                json!({"family": "ipv6", "table": "nat", "chain": "PREROUTING"}),
            )
            .await,
        );
        ok_text(
            run(
                &host,
                "rita",
                "iptables_list",
                json!({"format": "save", "table": "mangle"}),
            )
            .await,
        );
        assert_eq!(
            fake.calls("iptables"),
            [strings(&[
                "-w",
                "5",
                "-t",
                "filter",
                "-L",
                "-n",
                "-v",
                "-x",
                "--line-numbers"
            ])]
        );
        assert_eq!(
            fake.calls("ip6tables"),
            [strings(&[
                "-w",
                "5",
                "-t",
                "nat",
                "-L",
                "PREROUTING",
                "-n",
                "-v",
                "-x",
                "--line-numbers"
            ])]
        );
        assert_eq!(
            fake.calls("iptables-save"),
            [strings(&["-c", "-t", "mangle"])]
        );
    }

    #[tokio::test]
    async fn nft_list_shows_the_ruleset_a_table_or_a_chain_with_handles() {
        let fake = fakes();
        let (host, _audit) = fixture(&fake);
        ok_text(run(&host, "rita", "nft_list", json!({})).await);
        ok_text(
            run(
                &host,
                "rita",
                "nft_list",
                json!({"family": "inet", "table": "filter"}),
            )
            .await,
        );
        ok_text(
            run(
                &host,
                "rita",
                "nft_list",
                json!({"family": "inet", "table": "filter", "chain": "input"}),
            )
            .await,
        );
        assert_eq!(
            fake.calls("nft"),
            [
                strings(&["-a", "list", "ruleset"]),
                strings(&["-a", "list", "table", "inet", "filter"]),
                strings(&["-a", "list", "chain", "inet", "filter", "input"]),
            ]
        );
        // a table needs its family, a chain needs its table
        for bad in [
            json!({"table": "filter"}),
            json!({"family": "inet", "chain": "input"}),
        ] {
            let result = run(&host, "rita", "nft_list", bad).await;
            assert!(matches!(result, Err(ToolError::Invalid(_))), "{result:?}");
        }
    }

    #[tokio::test]
    async fn iptables_rule_changes_a_chain_the_caller_is_granted() {
        let fake = fakes();
        let (host, audit) = fixture(&fake);
        let arguments = json!({"chain": "OPSMCP-IN", "action": "append", "rule": ["-p", "tcp", "--dport", "8080", "-j", "ACCEPT"]});
        ok_text(run(&host, "sid", "iptables_rule", arguments).await);
        assert_eq!(
            fake.calls("iptables"),
            [strings(&[
                "-w",
                "5",
                "-t",
                "filter",
                "-A",
                "OPSMCP-IN",
                "-p",
                "tcp",
                "--dport",
                "8080",
                "-j",
                "ACCEPT"
            ])]
        );
        assert_eq!(
            audit.records().last().unwrap()["resource"],
            "iptables/filter/OPSMCP-IN"
        );
    }

    #[tokio::test]
    async fn iptables_rule_runs_nothing_outside_the_granted_chains() {
        let fake = fakes();
        let (host, audit) = fixture(&fake);
        for arguments in [
            json!({"chain": "INPUT", "action": "flush"}),
            json!({"chain": "OPSMCP-IN", "table": "nat", "action": "flush"}),
            json!({"chain": "OPSMCP-IN", "family": "ipv6", "action": "flush"}),
        ] {
            let result = run(&host, "sid", "iptables_rule", arguments.clone()).await;
            assert!(
                matches!(result, Err(ToolError::Denied(_))),
                "{arguments}: {result:?}"
            );
        }
        // and a rule cannot be used to reach another table or chain
        let sneaky = json!({"chain": "OPSMCP-IN", "action": "append", "rule": ["-t", "nat", "-A", "PREROUTING", "-j", "ACCEPT"]});
        assert!(matches!(
            run(&host, "sid", "iptables_rule", sneaky).await,
            Err(ToolError::Invalid(_))
        ));
        assert_eq!(fake.calls("iptables"), Vec::<Vec<String>>::new());
        assert_eq!(fake.calls("ip6tables"), Vec::<Vec<String>>::new());
        assert_eq!(audit.records().last().unwrap()["decision"], "deny");
    }

    #[tokio::test]
    async fn nft_rule_changes_only_the_granted_chain() {
        let fake = fakes();
        let (host, audit) = fixture(&fake);
        let base = json!({"family": "inet", "table": "filter", "chain": "opsmcp", "action": "add", "rule": ["tcp", "dport", "8080", "accept"]});
        ok_text(run(&host, "sid", "nft_rule", base).await);
        assert_eq!(
            fake.calls("nft"),
            [strings(&[
                "add", "rule", "inet", "filter", "opsmcp", "tcp", "dport", "8080", "accept"
            ])]
        );
        assert_eq!(
            audit.records().last().unwrap()["resource"],
            "nft/inet/filter/opsmcp"
        );

        let other =
            json!({"family": "inet", "table": "filter", "chain": "input", "action": "flush"});
        assert!(matches!(
            run(&host, "sid", "nft_rule", other).await,
            Err(ToolError::Denied(_))
        ));
        assert_eq!(fake.calls("nft").len(), 1);
    }

    #[tokio::test]
    async fn firewall_reset_counters_zeroes_the_chosen_counters() {
        let fake = fakes();
        let (host, audit) = fixture(&fake);
        ok_text(
            run(
                &host,
                "adam",
                "firewall_reset_counters",
                json!({"backend": "iptables"}),
            )
            .await,
        );
        assert_eq!(
            audit.records().last().unwrap()["resource"],
            "iptables/filter/*"
        );
        ok_text(
            run(
                &host,
                "adam",
                "firewall_reset_counters",
                json!({"backend": "ip6tables", "table": "mangle", "chain": "FORWARD"}),
            )
            .await,
        );
        ok_text(
            run(
                &host,
                "adam",
                "firewall_reset_counters",
                json!({"backend": "nft"}),
            )
            .await,
        );
        ok_text(
            run(
                &host,
                "adam",
                "firewall_reset_counters",
                json!({"backend": "nft", "family": "inet", "table": "filter"}),
            )
            .await,
        );
        assert_eq!(
            fake.calls("iptables"),
            [strings(&["-w", "5", "-t", "filter", "-Z"])]
        );
        assert_eq!(
            fake.calls("ip6tables"),
            [strings(&["-w", "5", "-t", "mangle", "-Z", "FORWARD"])]
        );
        assert_eq!(
            fake.calls("nft"),
            [
                strings(&["reset", "counters"]),
                strings(&["reset", "counters", "table", "inet", "filter"])
            ]
        );
        // a grant for some chains does not cover resetting a whole table
        let result = run(
            &host,
            "sid",
            "firewall_reset_counters",
            json!({"backend": "iptables"}),
        )
        .await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        // readers cannot change anything
        let result = run(
            &host,
            "rita",
            "firewall_reset_counters",
            json!({"backend": "nft"}),
        )
        .await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
    }
}
