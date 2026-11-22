//! Adding and removing addresses in firewall sets.
//!
//! A set is a named list of addresses that the firewall's rules refer to (a blocklist,
//! an allowlist). Changing its members blocks or allows one address without touching
//! any rule. Like the other firewall tools this acts on the running firewall only.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::args::{Args, Param};
use super::firewall::{NFT_FAMILIES, check_name};
use super::{Ctx, Tool, ToolError, ToolResult, command_ok, command_text, required};
use crate::glob::glob_match;
use crate::policy::Access;
use crate::sanitize::keep_head;

/// ipset counts a timeout in seconds and holds no more than this.
const MAX_IPSET_TIMEOUT_SECS: i64 = 2_147_483;

const NOT_SAVED: &str = "[changed in the running firewall only; not saved: a reboot or a reload of the \
                         firewall brings back the members the configuration gives the set]\n";

pub fn tools() -> Vec<Tool> {
    vec![Tool::new(
        "firewall_set_member",
        "Add or remove one address or network in a named firewall set (an nftables set or \
         an ipset), or list the set's members. Use it to block or allow an address without \
         touching any rule: the rules that refer to the set stay as they are. An added \
         member can be given a timeout, after which it leaves the set by itself (the set \
         must have been created with timeouts). Only the sets this host's configuration \
         names can be used. The change is to the running firewall only and is not saved. \
         Take care not to cut off your own access: the tool cannot know whether a set \
         blocks or allows.",
        Access::Write,
        "firewall.set",
        vec![
            Param::choice(
                "action",
                "add or remove a member, or list the set's members",
                &["add", "remove", "list"],
            )
            .required(),
            Param::choice(
                "kind",
                "nft (a set in an nftables table, the default) or ipset",
                &["nft", "ipset"],
            ),
            Param::choice(
                "family",
                "nft only: address family of the table (default inet)",
                &NFT_FAMILIES,
            ),
            Param::str("table", "nft only: the table the set is in").max_len(64),
            Param::str("set", "Name of the set").max_len(64).required(),
            Param::str(
                "address",
                "The member to add or remove: an IPv4 or IPv6 address, or a network written \
                 ADDRESS/PREFIX (at most a /8, or a /16 for IPv6). An ipset takes a network \
                 only if it is a set of networks (type hash:net)",
            )
            .max_len(64),
            Param::int(
                "timeout_minutes",
                "add only: the member leaves the set by itself after this many minutes",
                1,
                43_200,
            ),
            Param::bool(
                "force",
                "Go ahead even though the member covers the address this call comes from",
            ),
        ],
        firewall_set_member,
    )]
}

/// One member of a set: a single address, or a network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Member {
    /// The address; for a network, its first address (host bits cleared).
    pub address: IpAddr,
    /// The prefix length of a network. `None` for a single address.
    pub prefix: Option<u8>,
}

/// `address` with everything after the first `prefix` bits cleared.
fn network(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(v4) => {
            let mask = u32::MAX
                .checked_shl(32u32.saturating_sub(u32::from(prefix)))
                .unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask))
        }
        IpAddr::V6(v6) => {
            let mask = u128::MAX
                .checked_shl(128u32.saturating_sub(u32::from(prefix)))
                .unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
        }
    }
}

/// Reads an address or `ADDRESS/PREFIX` as the caller wrote it.
///
/// AIDEV-NOTE: this is the only door from the caller's text to the firewall's command
/// line, and nothing of that text goes through it: the text is parsed into numbers, and
/// what is later printed (`Display`) is built from those numbers. nft joins its
/// arguments and parses them as a script, so a `;`, a `}` or a second element in the
/// text would otherwise be a second command; here they are simply not an address.
pub fn parse_member(text: &str) -> Result<Member, String> {
    let text = text.trim();
    let shown: String = text.chars().take(64).collect();
    let (address_text, prefix_text) = match text.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (text, None),
    };
    let address: IpAddr = address_text.parse().map_err(|_| {
        format!(
            "{shown:?} is not an IPv4 or IPv6 address, nor a network written ADDRESS/PREFIX \
             (one member at a time; no names, ranges or ports)"
        )
    })?;
    if let IpAddr::V6(v6) = address
        && v6.to_ipv4_mapped().is_some()
    {
        return Err(format!(
            "{shown:?} is an IPv4 address written as IPv6: give the IPv4 address itself"
        ));
    }
    let (bits, smallest_prefix) = match address {
        IpAddr::V4(_) => (32u8, 8u8),
        IpAddr::V6(_) => (128u8, 16u8),
    };
    let Some(prefix_text) = prefix_text else {
        return Ok(Member {
            address,
            prefix: None,
        });
    };
    // Digits only: `parse` alone would accept a sign.
    let prefix = Some(prefix_text)
        .filter(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|p| p.parse::<u8>().ok())
        .filter(|prefix| *prefix <= bits)
        .ok_or_else(|| format!("{shown:?}: the prefix length must be a number from 0 to {bits}"))?;
    // AIDEV-NOTE: a member that covers a large part of the address space is far more
    // likely a slip (a blocklist that blocks everyone) than intended, and `force` does
    // not lift this: such a change belongs in the firewall's configuration.
    if prefix < smallest_prefix {
        return Err(format!(
            "{shown:?} is too large a network to put in a set through opsmcp: the prefix \
             must be at least /{smallest_prefix}"
        ));
    }
    if prefix == bits {
        return Ok(Member {
            address,
            prefix: None,
        });
    }
    Ok(Member {
        address: network(address, prefix),
        prefix: Some(prefix),
    })
}

impl Member {
    /// True when `address` is this member or lies inside this network. An IPv4 address is
    /// never inside an IPv6 network, nor the other way round.
    pub fn contains(&self, address: IpAddr) -> bool {
        if self.address.is_ipv4() != address.is_ipv4() {
            return false;
        }
        match self.prefix {
            None => self.address == address,
            Some(prefix) => network(address, prefix) == self.address,
        }
    }
}

impl std::fmt::Display for Member {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.prefix {
            None => write!(f, "{}", self.address),
            Some(prefix) => write!(f, "{}/{prefix}", self.address),
        }
    }
}

/// Which set, and in which firewall.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Nft {
        family: String,
        table: String,
        set: String,
    },
    Ipset {
        set: String,
    },
}

impl Target {
    /// The name grants and `firewall.sets` use for this set.
    pub fn resource(&self) -> String {
        match self {
            Target::Nft { family, table, set } => format!("nft/{family}/{table}/{set}"),
            Target::Ipset { set } => format!("ipset/{set}"),
        }
    }
}

/// What to do to the set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    Add {
        member: Member,
        timeout_minutes: Option<i64>,
    },
    Remove {
        member: Member,
    },
    List,
}

/// The program and its arguments for a change.
///
/// AIDEV-NOTE: every argument is either a fixed word, a name that passed
/// `firewall::check_name` (letters, digits, `_`, `.`, `-`; no leading `-`), a family from
/// the fixed list, a `Member` printed from parsed numbers, or a number of ours. Keep it
/// that way: nft parses its joined arguments as a script.
pub fn argv(target: &Target, change: &Change) -> Result<(&'static str, Vec<String>), ToolError> {
    let words = |list: &[&str]| -> Vec<String> { list.iter().map(|s| s.to_string()).collect() };
    match target {
        Target::Nft { family, table, set } => {
            let place = [family.as_str(), table.as_str(), set.as_str()];
            let mut argv = match change {
                Change::Add { .. } => words(&["add", "element"]),
                Change::Remove { .. } => words(&["delete", "element"]),
                Change::List => words(&["list", "set"]),
            };
            argv.extend(words(&place));
            match change {
                Change::Add {
                    member,
                    timeout_minutes,
                } => {
                    argv.extend(["{".to_string(), member.to_string()]);
                    if let Some(minutes) = timeout_minutes {
                        argv.extend(["timeout".to_string(), format!("{minutes}m")]);
                    }
                    argv.push("}".to_string());
                }
                Change::Remove { member } => {
                    argv.extend(["{".to_string(), member.to_string(), "}".to_string()]);
                }
                Change::List => {}
            }
            Ok(("nft", argv))
        }
        Target::Ipset { set } => {
            let argv = match change {
                Change::Add {
                    member,
                    timeout_minutes,
                } => {
                    // -exist: adding a member that is already there is not an error (and
                    // gives it the new timeout), as with nft.
                    let mut argv = words(&["add", "-exist", set]);
                    argv.push(member.to_string());
                    if let Some(minutes) = timeout_minutes {
                        let seconds = minutes
                            .checked_mul(60)
                            .filter(|seconds| *seconds <= MAX_IPSET_TIMEOUT_SECS)
                            .ok_or_else(|| {
                                ToolError::Invalid(format!(
                                    "a member of an ipset can last at most {} minutes",
                                    MAX_IPSET_TIMEOUT_SECS / 60
                                ))
                            })?;
                        argv.extend(["timeout".to_string(), seconds.to_string()]);
                    }
                    argv
                }
                Change::Remove { member } => {
                    let mut argv = words(&["del", set]);
                    argv.push(member.to_string());
                    argv
                }
                Change::List => words(&["list", set]),
            };
            Ok(("ipset", argv))
        }
    }
}

/// The type of an ipset (`hash:ip`, `hash:net`...), from the `Type:` line of
/// `ipset list -terse NAME`.
pub fn ipset_type(terse: &str) -> Option<String> {
    terse
        .lines()
        .find_map(|line| line.strip_prefix("Type:"))
        .map(|kind| kind.trim().to_string())
        .filter(|kind| {
            !kind.is_empty()
                && kind.len() <= 64
                && kind
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || ":,_-".contains(c))
        })
}

/// Whether an ipset of this type holds a network as ONE member: the types whose first
/// (for this tool: only) dimension is `net`, such as `hash:net`.
///
/// AIDEV-NOTE: given `10.0.0.0/8`, a set of single addresses (`hash:ip`, `bitmap:ip`)
/// does not refuse: ipset adds, or deletes, every address of the network one by one.
/// The set fills up (65536 members by default) and the command fails half-way, having
/// already changed part of it. So a network only goes to a set that stores networks.
pub fn holds_networks(kind: &str) -> bool {
    kind.split_once(':')
        .and_then(|(_, dimensions)| dimensions.split(',').next())
        == Some("net")
}

/// The address a call over HTTPS came from. `Ok(None)` for local and SSH use, where the
/// server is not told one. An IPv4 caller that a dual-stack listener reports in IPv6
/// form (`::ffff:a.b.c.d`) is given as the IPv4 address, which is what a set would hold.
pub fn caller_address(peer: Option<&str>) -> Result<Option<IpAddr>, String> {
    let Some(peer) = peer else {
        return Ok(None);
    };
    let socket: SocketAddr = peer
        .parse()
        .map_err(|_| "the address this call comes from could not be read".to_string())?;
    Ok(Some(socket.ip().to_canonical()))
}

/// Refuses a change that could cut the caller off, unless they insist.
///
/// AIDEV-NOTE: the tool cannot know what a set means. Adding the caller's address to a
/// blocklist locks them out, and so does removing it from an allowlist, so both
/// directions are stopped, and `force` is the caller saying they know which kind of set
/// this is. Only calls over HTTPS carry an address; for local and SSH use the server
/// does not know where the caller sits, and nothing is checked. The address is the one
/// the server sees: behind a proxy or NAT that is the proxy's, so this guard catches the
/// plain slip and is no substitute for care.
fn lockout_guard(ctx: &Ctx, resource: &str, member: Member, adding: bool) -> Result<(), ToolError> {
    let verb = if adding { "adding" } else { "removing" };
    match caller_address(ctx.peer()) {
        Ok(None) => Ok(()),
        Ok(Some(own)) if member.contains(own) => {
            let reason = format!(
                "{verb} {member} would act on your own address ({own}); if {resource} decides \
                 what is blocked or allowed, that can cut this connection off. Pass force to \
                 do it anyway"
            );
            Err(ctx.deny(Some(resource), &reason))
        }
        Ok(Some(_)) => Ok(()),
        Err(why) => {
            let reason = format!(
                "{why}, so it cannot be checked that {verb} {member} leaves your own address \
                 alone. Pass force to do it anyway"
            );
            Err(ctx.deny(Some(resource), &reason))
        }
    }
}

async fn firewall_set_member(ctx: Ctx, args: Args) -> ToolResult {
    let invalid = |problem: &str| Err(ToolError::Invalid(problem.to_string()));
    let action = required(&args, "action")?;
    let set = required(&args, "set")?;
    let target = if args.str("kind") == Some("ipset") {
        if args.str("table").is_some() || args.str("family").is_some() {
            return invalid("an ipset has no table and no family: leave both out");
        }
        // ipset's own limit on the length of a set's name
        check_name("set", set, 31)?;
        Target::Ipset {
            set: set.to_string(),
        }
    } else {
        let Some(table) = args.str("table") else {
            return invalid("an nftables set is named by its table as well: give table");
        };
        check_name("table", table, 64)?;
        check_name("set", set, 64)?;
        Target::Nft {
            family: args.str("family").unwrap_or("inet").to_string(),
            table: table.to_string(),
            set: set.to_string(),
        }
    };
    let member = match (action, args.str("address")) {
        ("list", Some(_)) => return invalid("list shows every member and takes no address"),
        ("list", None) => None,
        (_, None) => return invalid("add and remove need the address"),
        (_, Some(text)) => Some(parse_member(text).map_err(ToolError::Invalid)?),
    };
    let timeout_minutes = args.int("timeout_minutes");
    if timeout_minutes.is_some() && action != "add" {
        return invalid("timeout_minutes only applies when a member is added");
    }
    if let (Target::Nft { family, .. }, Some(member)) = (&target, member) {
        match (family.as_str(), member.address) {
            ("ip", IpAddr::V6(_)) => {
                return invalid("a set in an ip table holds IPv4 addresses; this is an IPv6 one");
            }
            ("ip6", IpAddr::V4(_)) => {
                return invalid("a set in an ip6 table holds IPv6 addresses; this is an IPv4 one");
            }
            _ => {}
        }
    }
    let change = match (action, member) {
        ("add", Some(member)) => Change::Add {
            member,
            timeout_minutes,
        },
        ("remove", Some(member)) => Change::Remove { member },
        ("list", None) => Change::List,
        _ => return invalid("unknown action"),
    };
    let (program, argv) = argv(&target, &change)?;

    // The host-wide limit comes before the caller's own grant, and covers listing too:
    // a set this host does not name is simply not this tool's business.
    let resource = target.resource();
    let listed = ctx
        .cfg()
        .firewall
        .sets
        .iter()
        .any(|pattern| glob_match(pattern, &resource));
    if !listed {
        let reason =
            format!("{resource} is not one of the sets that firewall.sets names on this host");
        return Err(ctx.deny(Some(&resource), &reason));
    }
    let auth = ctx.authorize(Some(&resource))?;
    if args.bool("force") != Some(true) {
        match change {
            Change::Add { member, .. } => lockout_guard(&ctx, &resource, member, true)?,
            Change::Remove { member } => lockout_guard(&ctx, &resource, member, false)?,
            Change::List => {}
        }
    }

    // A network goes only into an ipset that stores networks (see `holds_networks`).
    if let (Target::Ipset { set }, Change::Add { member, .. } | Change::Remove { member }) =
        (&target, &change)
        && member.prefix.is_some()
    {
        let look = ctx.command("ipset")?.args(["list", "-terse", set.as_str()]);
        let out = ctx.run(look).await?;
        if !command_ok(&out) {
            return auth.failed(format!(
                "Nothing was changed: {resource} could not be looked at first, to see \
                 whether it takes a network.\n{}",
                command_text(&out)
            ));
        }
        match ipset_type(&String::from_utf8_lossy(&out.stdout)) {
            Some(kind) if holds_networks(&kind) => {}
            Some(kind) => {
                return auth.failed(format!(
                    "Nothing was changed: {resource} is a set of type {kind}, which holds \
                     single addresses. Given the network {member}, ipset would add or remove \
                     its addresses one address at a time, and can stop half-way with part \
                     of them done. Give single addresses, or use a set of type hash:net.\n"
                ));
            }
            None => {
                return auth.failed(format!(
                    "Nothing was changed: ipset did not say what type of set {resource} is, \
                     so it cannot be told whether it takes the network {member} as one \
                     member.\n"
                ));
            }
        }
    }

    let out = ctx.run(ctx.command(program)?.args(argv)).await?;
    let succeeded = command_ok(&out);
    let mut text = command_text(&out);
    if let Change::List = change {
        let (kept, dropped) = keep_head(&text, ctx.output_budget().saturating_sub(160));
        text = kept;
        if dropped > 0 {
            text.push_str(&format!(
                "[{dropped} more lines left out to fit the output limit]\n"
            ));
        }
        return auth.done(text, succeeded);
    }
    if succeeded {
        match change {
            Change::Add {
                member,
                timeout_minutes: Some(minutes),
            } => text.push_str(&format!(
                "Added {member} to {resource}; it leaves the set by itself after {minutes} minutes.\n"
            )),
            Change::Add { member, .. } => {
                text.push_str(&format!("Added {member} to {resource}.\n"));
            }
            Change::Remove { member } => {
                text.push_str(&format!("Removed {member} from {resource}.\n"));
            }
            Change::List => {}
        }
        text.push_str(NOT_SAVED);
    }
    auth.done(text, succeeded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::testing::{FakeBins, call, find, host, ok_text};
    use crate::tools::{Call, Host};
    use serde_json::{Value, json};
    use std::sync::Arc;

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn member(text: &str) -> Member {
        parse_member(text).unwrap_or_else(|e| panic!("{text}: {e}"))
    }

    #[test]
    fn a_member_is_printed_from_what_was_parsed_not_from_what_was_typed() {
        let cases = [
            ("10.0.0.5", "10.0.0.5"),
            ("10.1.2.3/8", "10.0.0.0/8"),
            ("192.168.7.77/24", "192.168.7.0/24"),
            ("192.168.7.77/32", "192.168.7.77"),
            ("2001:DB8::1", "2001:db8::1"),
            ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
            ("2001:db8:abcd:1234::9/48", "2001:db8:abcd::/48"),
            ("2001:db8::1/128", "2001:db8::1"),
            ("fe80::1/64", "fe80::/64"),
            ("  10.0.0.5  ", "10.0.0.5"),
            ("10.0.0.0/8", "10.0.0.0/8"),
            ("2001:db8::/16", "2001::/16"),
        ];
        for (typed, printed) in cases {
            assert_eq!(member(typed).to_string(), printed, "{typed}");
        }
    }

    #[test]
    fn what_is_not_one_address_or_network_is_refused() {
        let bad = [
            "",
            " ",
            "example.com",
            "10.0.0",
            "10.0.0.256",
            "010.0.0.1",
            "10.0.0.1/",
            "10.0.0.1/33",
            "10.0.0.1/-1",
            "10.0.0.1/8/8",
            "10.0.0.1/ 8",
            "10.0.0.1/+8",
            "10.0.0.1/08x",
            "2001:db8::1/129",
            "fe80::1%eth0",
            "[::1]",
            "10.0.0.1:80",
            "10.0.0.1-10.0.0.9",
            "10.0.0.1,10.0.0.2",
            "10.0.0.1 10.0.0.2",
            "10.0.0.1 } ; flush ruleset",
            "10.0.0.1;",
            "{ 10.0.0.1 }",
            "10.0.0.1\n10.0.0.2",
            "-exist",
            "timeout",
            "@other_set",
            "$var",
            "10.0.0.1 timeout 1s",
        ];
        for text in bad {
            assert!(parse_member(text).is_err(), "{text:?} should be refused");
        }
    }

    #[test]
    fn a_network_that_covers_too_much_is_always_refused() {
        for text in [
            "0.0.0.0/0",
            "10.0.0.0/7",
            "128.0.0.0/1",
            "::/0",
            "2001:db8::/15",
            "2000::/3",
        ] {
            let problem = parse_member(text).unwrap_err();
            assert!(problem.contains("too large"), "{text}: {problem}");
        }
        // the smallest prefixes that are accepted
        assert!(parse_member("10.0.0.0/8").is_ok());
        assert!(parse_member("2001:db8::/16").is_ok());
    }

    #[test]
    fn an_ipv4_address_written_as_ipv6_is_refused_with_a_reason() {
        for text in ["::ffff:10.0.0.5", "::ffff:10.0.0.0/104", "::ffff:a00:5"] {
            let problem = parse_member(text).unwrap_err();
            assert!(problem.contains("IPv4"), "{text}: {problem}");
        }
    }

    #[test]
    fn a_member_contains_itself_and_what_lies_inside_its_network() {
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        assert!(member("10.0.0.5").contains(ip("10.0.0.5")));
        assert!(!member("10.0.0.5").contains(ip("10.0.0.6")));
        assert!(member("10.0.0.0/8").contains(ip("10.255.255.255")));
        assert!(!member("10.0.0.0/8").contains(ip("11.0.0.0")));
        assert!(member("192.168.7.0/24").contains(ip("192.168.7.200")));
        assert!(!member("192.168.7.0/24").contains(ip("192.168.8.1")));
        assert!(member("2001:db8::/32").contains(ip("2001:db8:ffff::1")));
        assert!(!member("2001:db8::/32").contains(ip("2001:db9::1")));
        assert!(member("2001:db8::1").contains(ip("2001:db8::1")));
        // an IPv4 address is never inside an IPv6 network, or the other way round
        assert!(!member("10.0.0.0/8").contains(ip("::ffff:10.0.0.1")));
        assert!(!member("2001:db8::/32").contains(ip("32.1.13.184")));
    }

    fn nft_target() -> Target {
        Target::Nft {
            family: "inet".to_string(),
            table: "filter".to_string(),
            set: "blocklist".to_string(),
        }
    }

    fn ipset_target() -> Target {
        Target::Ipset {
            set: "blocklist".to_string(),
        }
    }

    #[test]
    fn a_set_is_named_by_firewall_family_table_and_set() {
        assert_eq!(nft_target().resource(), "nft/inet/filter/blocklist");
        assert_eq!(ipset_target().resource(), "ipset/blocklist");
    }

    #[test]
    fn nft_gets_the_element_between_braces_as_separate_arguments() {
        let add = Change::Add {
            member: member("10.0.0.5"),
            timeout_minutes: None,
        };
        assert_eq!(
            argv(&nft_target(), &add).unwrap(),
            (
                "nft",
                strings(&[
                    "add",
                    "element",
                    "inet",
                    "filter",
                    "blocklist",
                    "{",
                    "10.0.0.5",
                    "}"
                ])
            )
        );
        let timed = Change::Add {
            member: member("2001:db8::/32"),
            timeout_minutes: Some(90),
        };
        assert_eq!(
            argv(&nft_target(), &timed).unwrap().1,
            strings(&[
                "add",
                "element",
                "inet",
                "filter",
                "blocklist",
                "{",
                "2001:db8::/32",
                "timeout",
                "90m",
                "}"
            ])
        );
        let remove = Change::Remove {
            member: member("10.0.0.0/8"),
        };
        assert_eq!(
            argv(&nft_target(), &remove).unwrap().1,
            strings(&[
                "delete",
                "element",
                "inet",
                "filter",
                "blocklist",
                "{",
                "10.0.0.0/8",
                "}"
            ])
        );
        assert_eq!(
            argv(&nft_target(), &Change::List).unwrap().1,
            strings(&["list", "set", "inet", "filter", "blocklist"])
        );
    }

    #[test]
    fn ipset_gets_seconds_and_never_fails_on_a_member_that_is_already_there() {
        let add = Change::Add {
            member: member("10.0.0.5"),
            timeout_minutes: Some(30),
        };
        assert_eq!(
            argv(&ipset_target(), &add).unwrap(),
            (
                "ipset",
                strings(&["add", "-exist", "blocklist", "10.0.0.5", "timeout", "1800"])
            )
        );
        let plain = Change::Add {
            member: member("10.0.0.0/24"),
            timeout_minutes: None,
        };
        assert_eq!(
            argv(&ipset_target(), &plain).unwrap().1,
            strings(&["add", "-exist", "blocklist", "10.0.0.0/24"])
        );
        let remove = Change::Remove {
            member: member("10.0.0.5"),
        };
        assert_eq!(
            argv(&ipset_target(), &remove).unwrap().1,
            strings(&["del", "blocklist", "10.0.0.5"])
        );
        assert_eq!(
            argv(&ipset_target(), &Change::List).unwrap().1,
            strings(&["list", "blocklist"])
        );
    }

    #[test]
    fn ipset_refuses_a_timeout_longer_than_it_can_hold() {
        let change = |minutes| Change::Add {
            member: member("10.0.0.5"),
            timeout_minutes: Some(minutes),
        };
        // ipset counts in seconds and stops at 2147483
        assert!(argv(&ipset_target(), &change(35_791)).is_ok());
        match argv(&ipset_target(), &change(35_792)) {
            Err(ToolError::Invalid(problem)) => assert!(problem.contains("35791"), "{problem}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
        // nft has no such limit
        assert!(argv(&nft_target(), &change(43_200)).is_ok());
    }

    #[test]
    fn the_callers_address_is_read_from_the_peer_of_an_https_call() {
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        assert_eq!(caller_address(None), Ok(None));
        assert_eq!(
            caller_address(Some("10.0.0.5:51234")),
            Ok(Some(ip("10.0.0.5")))
        );
        assert_eq!(
            caller_address(Some("[2001:db8::7]:443")),
            Ok(Some(ip("2001:db8::7")))
        );
        // a dual-stack listener reports an IPv4 caller in IPv6 form
        assert_eq!(
            caller_address(Some("[::ffff:10.0.0.5]:51234")),
            Ok(Some(ip("10.0.0.5")))
        );
        for unreadable in ["", "10.0.0.5", "somewhere:1", "10.0.0.5:port"] {
            assert!(caller_address(Some(unreadable)).is_err(), "{unreadable:?}");
        }
    }

    // ---- the tool, against stand-in commands ------------------------------------------

    const NFT_SET: &str = "table inet filter {\n\tset blocklist {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t\telements = { 10.0.0.5 timeout 30m expires 29m58s }\n\t}\n}\n";

    fn fake() -> FakeBins {
        FakeBins::new()
            .add_script(
                "nft",
                &format!("case \"$1\" in list) printf '%s' '{NFT_SET}';; esac\nexit 0"),
            )
            .add_script(
                "ipset",
                "case \"$1\" in list) printf 'Name: blocklist\\nMembers:\\n10.0.0.5\\n';; esac\nexit 0",
            )
    }

    fn fixture_with(fake: &FakeBins, sets: &str) -> (Arc<Host>, MemorySink) {
        host(&format!(
            r#"
[roles.admin]
allow = ["@all"]
[roles.blocker]
allow = ["firewall.set:nft/inet/filter/blocklist", "firewall.set:ipset/block*"]
[roles.reader]
allow = ["@read"]
[unix_users.ada]
roles = ["admin"]
[unix_users.bo]
roles = ["blocker"]
[unix_users.rita]
roles = ["reader"]
[firewall]
sets = [{sets}]
{}"#,
            fake.config_only()
        ))
    }

    fn fixture(fake: &FakeBins) -> (Arc<Host>, MemorySink) {
        fixture_with(
            fake,
            r#""nft/inet/filter/blocklist", "nft/ip/*/allow-*", "ipset/blocklist""#,
        )
    }

    async fn run(host: &Arc<Host>, user: &str, arguments: Value) -> ToolResult {
        call(host, user, &find(tools(), "firewall_set_member"), arguments).await
    }

    /// A call that arrived over HTTPS from `peer`.
    async fn run_from(host: &Arc<Host>, user: &str, peer: &str, arguments: Value) -> ToolResult {
        let tool = find(tools(), "firewall_set_member");
        let args = Args::parse(&tool.params, Some(&arguments)).map_err(ToolError::Invalid)?;
        let principal = host.cfg.principal_for_unix(user, &[]).unwrap();
        let call = Call {
            id: "test-1".to_string(),
            transport: "https",
            peer: Some(peer.to_string()),
            principal: Arc::new(principal),
            tool: tool.name.clone(),
            permission: tool.permission.clone(),
            access: tool.access,
            args: arguments,
            args_sha256: None,
            read_only: false,
            via: None,
        };
        tool.run(Ctx::new(host.clone(), Arc::new(call)), args).await
    }

    fn denied(result: ToolResult) -> String {
        match result {
            Err(ToolError::Denied(message)) => message,
            other => panic!("expected a denial, got {other:?}"),
        }
    }

    fn invalid(result: ToolResult) -> String {
        match result {
            Err(ToolError::Invalid(message)) => message,
            other => panic!("expected invalid arguments, got {other:?}"),
        }
    }

    fn add(address: &str) -> Value {
        json!({"action": "add", "table": "filter", "set": "blocklist", "address": address})
    }

    #[test]
    fn it_is_a_write_tool_with_its_own_permission() {
        let tool = find(tools(), "firewall_set_member");
        assert_eq!(tool.access, Access::Write);
        assert_eq!(tool.permission, "firewall.set");
    }

    #[tokio::test]
    async fn nothing_may_be_changed_until_the_host_lists_the_set() {
        let fake = fake();
        let (host, sink) = fixture_with(&fake, "");
        let message = denied(run(&host, "ada", add("10.0.0.5")).await);
        assert!(message.contains("firewall.sets"), "{message}");
        assert!(fake.calls("nft").is_empty());
        let records = sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["decision"], "deny");
        assert_eq!(records[0]["resource"], "nft/inet/filter/blocklist");
    }

    #[tokio::test]
    async fn a_set_the_host_does_not_list_is_refused_whatever_the_grant() {
        let fake = fake();
        let (host, _sink) = fixture(&fake);
        for arguments in [
            json!({"action": "add", "table": "filter", "set": "other", "address": "10.0.0.5"}),
            json!({"action": "add", "family": "ip6", "table": "filter", "set": "blocklist", "address": "2001:db8::1"}),
            json!({"action": "list", "table": "nat", "set": "blocklist"}),
            json!({"action": "add", "kind": "ipset", "set": "allowlist", "address": "10.0.0.5"}),
        ] {
            let message = denied(run(&host, "ada", arguments.clone()).await);
            assert!(message.contains("firewall.sets"), "{arguments}: {message}");
        }
        assert!(fake.calls("nft").is_empty());
        assert!(fake.calls("ipset").is_empty());
    }

    #[tokio::test]
    async fn a_grant_for_one_set_does_not_reach_another() {
        let fake = fake();
        let (host, sink) = fixture(&fake);
        // bo holds nft/inet/filter/blocklist and ipset/block*, but not the allow sets
        let other = json!({"action": "add", "family": "ip", "table": "filter", "set": "allow-office", "address": "10.0.0.5"});
        let message = denied(run(&host, "bo", other).await);
        assert!(message.contains("Permission denied"), "{message}");
        assert!(fake.calls("nft").is_empty());
        // a reader holds no write permission at all
        denied(run(&host, "rita", add("10.0.0.5")).await);
        assert!(fake.calls("nft").is_empty());
        // what bo does hold works, and is audited under the set's name
        ok_text(run(&host, "bo", add("10.0.0.5")).await);
        let last = sink.records().pop().unwrap();
        assert_eq!(last["decision"], "allow");
        assert_eq!(last["resource"], "nft/inet/filter/blocklist");
    }

    #[tokio::test]
    async fn adding_runs_nft_with_the_parsed_address_and_says_it_is_not_saved() {
        let fake = fake();
        let (host, _sink) = fixture(&fake);
        let text = ok_text(run(&host, "ada", add("10.1.2.3/8")).await);
        assert_eq!(
            fake.calls("nft"),
            vec![strings(&[
                "add",
                "element",
                "inet",
                "filter",
                "blocklist",
                "{",
                "10.0.0.0/8",
                "}"
            ])]
        );
        assert!(
            text.contains("Added 10.0.0.0/8 to nft/inet/filter/blocklist"),
            "{text}"
        );
        assert!(text.contains("not saved"), "{text}");
    }

    #[tokio::test]
    async fn a_timeout_is_passed_on_and_reported() {
        let fake = fake();
        let (host, _sink) = fixture(&fake);
        let mut arguments = add("10.0.0.5");
        arguments["timeout_minutes"] = json!(30);
        let text = ok_text(run(&host, "ada", arguments).await);
        assert_eq!(
            fake.calls("nft")[0],
            strings(&[
                "add",
                "element",
                "inet",
                "filter",
                "blocklist",
                "{",
                "10.0.0.5",
                "timeout",
                "30m",
                "}"
            ])
        );
        assert!(text.contains("30 minutes"), "{text}");
    }

    #[tokio::test]
    async fn removing_and_listing_work_for_both_kinds_of_set() {
        let fake = fake();
        let (host, _sink) = fixture(&fake);
        let text = ok_text(
            run(
                &host,
                "ada",
                json!({"action": "remove", "table": "filter", "set": "blocklist", "address": "10.0.0.5"}),
            )
            .await,
        );
        assert!(
            text.contains("Removed 10.0.0.5 from nft/inet/filter/blocklist"),
            "{text}"
        );
        let text = ok_text(
            run(
                &host,
                "ada",
                json!({"action": "list", "table": "filter", "set": "blocklist"}),
            )
            .await,
        );
        assert!(text.contains("elements = { 10.0.0.5"), "{text}");
        assert!(!text.contains("not saved"), "{text}");

        let text = ok_text(
            run(
                &host,
                "ada",
                json!({"action": "add", "kind": "ipset", "set": "blocklist", "address": "10.0.0.9", "timeout_minutes": 5}),
            )
            .await,
        );
        assert!(text.contains("Added 10.0.0.9 to ipset/blocklist"), "{text}");
        let text = ok_text(
            run(
                &host,
                "ada",
                json!({"action": "list", "kind": "ipset", "set": "blocklist"}),
            )
            .await,
        );
        assert!(text.contains("Members:"), "{text}");
        ok_text(
            run(
                &host,
                "ada",
                json!({"action": "remove", "kind": "ipset", "set": "blocklist", "address": "10.0.0.9"}),
            )
            .await,
        );
        assert_eq!(
            fake.calls("ipset"),
            vec![
                strings(&["add", "-exist", "blocklist", "10.0.0.9", "timeout", "300"]),
                strings(&["list", "blocklist"]),
                strings(&["del", "blocklist", "10.0.0.9"]),
            ]
        );
    }

    /// An ipset stand-in whose `list -terse` says the set is of `kind`.
    fn ipset_of(kind: &str) -> FakeBins {
        FakeBins::new().add_script(
            "ipset",
            &format!(
                "case \"$1\" in list) printf '%s\\n' 'Name: blocklist' 'Type: {kind}' 'Revision: 4' \\\n\
                 'Header: family inet hashsize 1024 maxelem 65536' 'Size in memory: 200' \\\n\
                 'References: 0' 'Number of entries: 0';; esac\nexit 0"
            ),
        )
    }

    #[test]
    fn only_a_set_of_networks_takes_a_network() {
        let terse = |kind: &str| format!("Name: blocklist\nType: {kind}\nRevision: 4\n");
        assert_eq!(ipset_type(&terse("hash:net")), Some("hash:net".to_string()));
        assert_eq!(ipset_type("Name: x\nMembers:\n"), None);
        assert_eq!(ipset_type(""), None);
        for kind in [
            "hash:net",
            "hash:net,port",
            "hash:net,iface",
            "hash:net,net",
        ] {
            assert!(holds_networks(kind), "{kind}");
        }
        for kind in [
            "hash:ip",
            "hash:ip,port",
            "hash:ip,port,net",
            "bitmap:ip",
            "list:set",
            "hash:mac",
            "",
        ] {
            assert!(!holds_networks(kind), "{kind}");
        }
    }

    /// AIDEV-NOTE: given a network, a `hash:ip` ipset adds every address of it one by
    /// one. A /8 is sixteen million of them: the set fills (65536 by default) and the
    /// command fails half-way, with the first part already added.
    #[tokio::test]
    async fn a_network_goes_only_into_an_ipset_that_holds_networks() {
        let fake = ipset_of("hash:ip");
        let (host, _sink) = fixture(&fake);
        let network =
            json!({"action": "add", "kind": "ipset", "set": "blocklist", "address": "10.1.0.0/16"});
        let output = run(&host, "ada", network.clone()).await.unwrap();
        assert!(output.is_error(), "{output:?}");
        let text = output.text().to_string();
        assert!(text.starts_with("Nothing was changed"), "{text}");
        assert!(text.contains("hash:ip"), "{text}");
        assert!(text.contains("one address at a time"), "{text}");
        // the set was looked at, and nothing was added
        assert_eq!(
            fake.calls("ipset"),
            vec![strings(&["list", "-terse", "blocklist"])]
        );
        // nor is a network taken out of such a set address by address
        let remove = json!({"action": "remove", "kind": "ipset", "set": "blocklist", "address": "10.1.0.0/16"});
        let output = run(&host, "ada", remove).await.unwrap();
        assert!(output.is_error(), "{output:?}");
        assert_eq!(fake.calls("ipset").len(), 2);

        // a single address needs no look at the set
        ok_text(
            run(
                &host,
                "ada",
                json!({"action": "add", "kind": "ipset", "set": "blocklist", "address": "10.1.2.3"}),
            )
            .await,
        );
        assert_eq!(
            fake.calls("ipset")[2],
            strings(&["add", "-exist", "blocklist", "10.1.2.3"])
        );

        // a set of networks takes it
        let fake = ipset_of("hash:net");
        let (host, _sink) = fixture(&fake);
        let text = ok_text(run(&host, "ada", network).await);
        assert!(
            text.contains("Added 10.1.0.0/16 to ipset/blocklist"),
            "{text}"
        );
        assert_eq!(
            fake.calls("ipset"),
            vec![
                strings(&["list", "-terse", "blocklist"]),
                strings(&["add", "-exist", "blocklist", "10.1.0.0/16"]),
            ]
        );
    }

    #[tokio::test]
    async fn an_ipset_that_cannot_be_looked_at_gets_no_network() {
        // the set does not exist
        let fake = FakeBins::new().add_script(
            "ipset",
            "printf '%s\\n' 'ipset v7.19: The set with the given name does not exist' >&2; exit 1",
        );
        let (host, _sink) = fixture(&fake);
        let network =
            json!({"action": "add", "kind": "ipset", "set": "blocklist", "address": "10.1.0.0/16"});
        let output = run(&host, "ada", network.clone()).await.unwrap();
        assert!(output.is_error(), "{output:?}");
        assert!(output.text().contains("does not exist"), "{output:?}");
        assert!(output.text().contains("Nothing was changed"), "{output:?}");
        assert_eq!(fake.calls("ipset").len(), 1);
        // an answer without a type
        let fake = FakeBins::new().add("ipset", "Name: blocklist\n", 0);
        let (host, _sink) = fixture(&fake);
        let output = run(&host, "ada", network).await.unwrap();
        assert!(output.is_error(), "{output:?}");
        assert!(output.text().contains("Nothing was changed"), "{output:?}");
        assert_eq!(fake.calls("ipset").len(), 1);
    }

    #[tokio::test]
    async fn arguments_that_do_not_fit_together_are_refused_before_anything_runs() {
        let fake = fake();
        let (host, sink) = fixture(&fake);
        let cases = [
            // an address is needed to add or remove, and means nothing to list
            json!({"action": "add", "table": "filter", "set": "blocklist"}),
            json!({"action": "remove", "table": "filter", "set": "blocklist"}),
            json!({"action": "list", "table": "filter", "set": "blocklist", "address": "10.0.0.5"}),
            // only an added member can expire
            json!({"action": "remove", "table": "filter", "set": "blocklist", "address": "10.0.0.5", "timeout_minutes": 5}),
            json!({"action": "list", "table": "filter", "set": "blocklist", "timeout_minutes": 5}),
            // nft needs a table; ipset has neither table nor family
            json!({"action": "add", "set": "blocklist", "address": "10.0.0.5"}),
            json!({"action": "add", "kind": "ipset", "table": "filter", "set": "blocklist", "address": "10.0.0.5"}),
            json!({"action": "add", "kind": "ipset", "family": "inet", "set": "blocklist", "address": "10.0.0.5"}),
            // the address must suit the table's family
            json!({"action": "add", "family": "ip", "table": "filter", "set": "allow-x", "address": "2001:db8::1"}),
            json!({"action": "add", "family": "ip6", "table": "filter", "set": "blocklist", "address": "10.0.0.5"}),
            // names
            json!({"action": "add", "table": "filter", "set": "block list", "address": "10.0.0.5"}),
            json!({"action": "add", "table": "filter", "set": "blocklist;flush", "address": "10.0.0.5"}),
            json!({"action": "add", "table": "filter", "set": "{", "address": "10.0.0.5"}),
            json!({"action": "add", "table": "-f", "set": "blocklist", "address": "10.0.0.5"}),
            json!({"action": "add", "table": "filter", "set": "@blocklist", "address": "10.0.0.5"}),
            json!({"action": "add", "kind": "ipset", "set": "-exist", "address": "10.0.0.5"}),
            json!({"action": "add", "kind": "ipset", "set": "a-name-longer-than-ipset-allows-x", "address": "10.0.0.5"}),
            // not an address
            add("10.0.0.5 } ; flush ruleset ; add element inet filter blocklist { 10.0.0.6"),
            add("10.0.0.5, 10.0.0.6"),
            add("@allowlist"),
            add("0.0.0.0/0"),
        ];
        for arguments in cases {
            invalid(run(&host, "ada", arguments.clone()).await);
        }
        assert!(fake.calls("nft").is_empty());
        assert!(fake.calls("ipset").is_empty());
        assert!(sink.records().is_empty());
    }

    #[tokio::test]
    async fn a_refusal_by_the_firewall_is_a_failure_and_claims_no_change() {
        let fake = FakeBins::new().add_script(
            "nft",
            "echo 'Error: Could not process rule: No such file or directory' >&2\nexit 1",
        );
        let (host, _sink) = fixture(&fake);
        let result = run(
            &host,
            "ada",
            json!({"action": "remove", "table": "filter", "set": "blocklist", "address": "10.0.0.77"}),
        )
        .await
        .unwrap();
        assert!(result.is_error());
        assert!(result.text().contains("Could not process rule"));
        assert!(!result.text().contains("Removed"), "{}", result.text());
        assert!(!result.text().contains("not saved"), "{}", result.text());
    }

    #[tokio::test]
    async fn a_missing_program_is_named() {
        let fake = FakeBins::new();
        let (host, _sink) = fixture(&fake);
        match run(&host, "ada", add("10.0.0.5")).await {
            Err(ToolError::Failed(message)) => assert!(message.contains("nft"), "{message}"),
            other => panic!("expected a failure, got {other:?}"),
        }
        match run(
            &host,
            "ada",
            json!({"action": "list", "kind": "ipset", "set": "blocklist"}),
        )
        .await
        {
            Err(ToolError::Failed(message)) => assert!(message.contains("ipset"), "{message}"),
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_long_listing_is_cut_to_the_output_limit_with_a_note() {
        let fake = FakeBins::new().add_script(
            "ipset",
            "i=0\nwhile [ $i -lt 4000 ]; do echo \"10.9.$((i / 250)).$((i % 250))\"; i=$((i + 1)); done",
        );
        let (host, _sink) = host_small(&fake);
        let text = ok_text(
            run(
                &host,
                "ada",
                json!({"action": "list", "kind": "ipset", "set": "blocklist"}),
            )
            .await,
        );
        assert!(text.len() <= 4096, "{}", text.len());
        assert!(text.contains("more lines left out"), "{text}");
        assert!(text.starts_with("10.9.0.0\n"), "{text}");
    }

    fn host_small(fake: &FakeBins) -> (Arc<Host>, MemorySink) {
        host(&format!(
            "[roles.admin]\nallow = [\"@all\"]\n[unix_users.ada]\nroles = [\"admin\"]\n\
             [firewall]\nsets = [\"ipset/*\"]\n[limits]\nmax_output_bytes = 4096\n{}",
            fake.config_only()
        ))
    }

    // ---- the lockout guard ------------------------------------------------------------

    #[tokio::test]
    async fn an_https_caller_cannot_add_or_remove_their_own_address_by_accident() {
        let fake = fake();
        let (host, sink) = fixture(&fake);
        let remove = |address: &str| json!({"action": "remove", "table": "filter", "set": "blocklist", "address": address});
        for arguments in [
            add("10.0.0.5"),
            add("10.0.0.0/24"),
            add("10.0.0.0/8"),
            remove("10.0.0.5"),
            remove("10.0.0.0/16"),
        ] {
            let message = denied(run_from(&host, "ada", "10.0.0.5:51234", arguments).await);
            assert!(message.contains("10.0.0.5"), "{message}");
            assert!(message.contains("force"), "{message}");
        }
        assert!(fake.calls("nft").is_empty());
        // the refusal is on record, with its reason
        let last = sink.records().pop().unwrap();
        assert_eq!(last["decision"], "deny");
        assert!(
            last["reason"].as_str().unwrap().contains("own address"),
            "{last}"
        );
    }

    #[tokio::test]
    async fn the_guard_knows_an_ipv4_caller_seen_through_an_ipv6_listener() {
        let fake = fake();
        let (host, _sink) = fixture(&fake);
        denied(run_from(&host, "ada", "[::ffff:10.0.0.5]:51234", add("10.0.0.0/24")).await);
        assert!(fake.calls("nft").is_empty());
    }

    #[tokio::test]
    async fn force_overrides_the_guard_and_other_addresses_never_meet_it() {
        let fake = fake();
        let (host, _sink) = fixture(&fake);
        let mut forced = add("10.0.0.5");
        forced["force"] = json!(true);
        ok_text(run_from(&host, "ada", "10.0.0.5:51234", forced).await);
        ok_text(run_from(&host, "ada", "10.0.0.5:51234", add("10.0.0.6")).await);
        ok_text(run_from(&host, "ada", "10.0.0.5:51234", add("192.168.0.0/16")).await);
        ok_text(run_from(&host, "ada", "[2001:db8::7]:443", add("10.0.0.0/8")).await);
        // listing changes nothing, so the guard has nothing to say
        ok_text(
            run_from(
                &host,
                "ada",
                "10.0.0.5:51234",
                json!({"action": "list", "table": "filter", "set": "blocklist"}),
            )
            .await,
        );
        assert_eq!(fake.calls("nft").len(), 5);
    }

    #[tokio::test]
    async fn the_guard_does_not_let_an_unauthorized_caller_past_the_policy_first() {
        let fake = fake();
        let (host, _sink) = fixture(&fake);
        // rita may not use the tool at all: she is told that, not about the guard
        let message = denied(run_from(&host, "rita", "10.0.0.5:51234", add("10.0.0.5")).await);
        assert!(message.contains("Permission denied"), "{message}");
    }

    #[tokio::test]
    async fn a_caller_whose_address_cannot_be_read_needs_force() {
        let fake = fake();
        let (host, _sink) = fixture(&fake);
        let message = denied(run_from(&host, "ada", "somewhere", add("10.0.0.6")).await);
        assert!(message.contains("force"), "{message}");
        assert!(fake.calls("nft").is_empty());
    }

    #[tokio::test]
    async fn a_local_caller_is_not_guarded() {
        let fake = fake();
        let (host, _sink) = fixture(&fake);
        ok_text(run(&host, "ada", add("127.0.0.1")).await);
        assert_eq!(fake.calls("nft").len(), 1);
    }
}
