//! Clock synchronisation status.

use std::time::Duration;

use super::args::Args;
use super::{Ctx, Tool, ToolError, ToolResult, command_ok, command_text};
use crate::exec::{Cmd, CmdOutput};
use crate::policy::Access;

pub fn tools() -> Vec<Tool> {
    vec![Tool::new(
        "time_sync_status",
        "Show whether this host's clock is synchronised, and by how much it is off: the \
         system's own view (timedatectl) and the time service's (chrony, systemd-timesyncd \
         or ntpd, whichever is in use), with its sources. The first line is the verdict. \
         Check this when a cluster (Galera, Corosync), TLS or authentication misbehaves: \
         clock drift is a common cause.",
        Access::Read,
        "time.view",
        vec![],
        time_sync_status,
    )]
}

/// What timedatectl says about the clock.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Timedate {
    /// Whether a time service is switched on.
    pub ntp: Option<bool>,
    /// The kernel's "the clock is synchronised" flag.
    pub synchronised: Option<bool>,
    pub timezone: Option<String>,
}

fn yes_no(value: &str) -> Option<bool> {
    match value.trim() {
        "yes" | "active" => Some(true),
        "no" | "inactive" => Some(false),
        _ => None,
    }
}

/// A time zone as timedatectl prints it, if it looks like one.
fn zone(value: &str) -> Option<String> {
    let value = value.trim();
    let plain = |c: char| c.is_ascii_alphanumeric() || " /_+-,()".contains(c);
    (!value.is_empty() && value.len() <= 64 && value.chars().all(plain)).then(|| value.to_string())
}

/// `timedatectl show` output (`KEY=value` lines; systemd 239 and later).
pub fn parse_timedatectl_show(text: &str) -> Timedate {
    let mut seen = Timedate::default();
    for line in text.lines() {
        match line.split_once('=') {
            Some(("NTP", value)) => seen.ntp = yes_no(value),
            Some(("NTPSynchronized", value)) => seen.synchronised = yes_no(value),
            Some(("Timezone", value)) => seen.timezone = zone(value),
            _ => {}
        }
    }
    seen
}

/// `timedatectl status` output, whose wording has changed between systemd versions.
pub fn parse_timedatectl_status(text: &str) -> Timedate {
    let mut seen = Timedate::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key.trim() {
            "System clock synchronized" | "NTP synchronized" => seen.synchronised = yes_no(value),
            "NTP service"
            | "Network time on"
            | "NTP enabled"
            | "systemd-timesyncd.service active" => seen.ntp = yes_no(value),
            "Time zone" | "Timezone" => seen.timezone = zone(value),
            _ => {}
        }
    }
    seen
}

/// A plain decimal number, optionally signed: what an offset must look like before it is
/// repeated in the verdict line.
fn is_number(text: &str) -> bool {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    !digits.is_empty()
        && digits.len() <= 24
        && digits.starts_with(|c: char| c.is_ascii_digit())
        && digits.chars().all(|c| c.is_ascii_digit() || c == '.')
        && digits.matches('.').count() <= 1
}

/// What `chronyc tracking` says.
#[derive(Debug, PartialEq, Eq)]
pub struct Tracking {
    pub synchronised: bool,
    /// chrony's "Leap status": Normal, Insert second, Delete second or Not synchronised.
    pub leap: String,
    /// How far the system clock is from true time, e.g. `+0.000012345 s` (positive: ahead).
    pub offset: Option<String>,
}

/// Reads `chronyc tracking` output. `None` if this is not tracking output (for example
/// the message that the daemon cannot be reached).
pub fn parse_chrony_tracking(text: &str) -> Option<Tracking> {
    let field = |name: &str| {
        text.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim() == name).then(|| value.trim().to_string())
        })
    };
    let leap = field("Leap status")?;
    let plain = |c: char| c.is_ascii_alphanumeric() || c == ' ';
    if leap.is_empty() || leap.len() > 32 || !leap.chars().all(plain) {
        return None;
    }
    // "0.000012345 seconds fast of NTP time"
    let offset = field("System time").and_then(|value| {
        let amount = value.split_whitespace().next()?;
        let sign = if value.contains(" slow ") {
            '-'
        } else if value.contains(" fast ") {
            '+'
        } else {
            return None;
        };
        is_number(amount).then(|| format!("{sign}{amount} s"))
    });
    Some(Tracking {
        synchronised: leap != "Not synchronised",
        leap,
        offset,
    })
}

/// What `ntpq -pn` says.
#[derive(Debug, PartialEq, Eq)]
pub struct Peers {
    /// ntpd has selected a peer to follow (the line marked `*`).
    pub synchronised: bool,
    /// The offset to that peer, e.g. `-0.250 ms`.
    pub offset: Option<String>,
}

/// Reads the peer table of `ntpq -pn`. `None` if there is no peer table.
pub fn parse_ntpq_peers(text: &str) -> Option<Peers> {
    let mut lines = text.lines();
    lines.find(|line| line.contains("remote") && line.contains("refid"))?;
    let selected = lines.find(|line| line.starts_with('*'));
    // remote refid st t when poll reach delay offset jitter
    let offset = selected
        .and_then(|line| line.split_whitespace().nth(8))
        .filter(|value| is_number(value))
        .map(|value| format!("{value} ms"));
    Some(Peers {
        synchronised: selected.is_some(),
        offset,
    })
}

/// The `Offset:` line of `timedatectl timesync-status`, e.g. `+1.234ms`.
pub fn timesync_offset(text: &str) -> Option<String> {
    let value = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("Offset:"))?
        .trim();
    let amount = value.trim_end_matches(|c: char| c.is_ascii_alphabetic() || c == 'μ');
    let unit = &value[amount.len()..];
    (is_number(amount) && unit.chars().count() <= 3).then(|| value.to_string())
}

/// A command that may well not be installed. `None` when it is not there; when it is
/// there but may not be used (see `Bins::lookup`), the reason is added to `notes`.
fn available(ctx: &Ctx, name: &str, notes: &mut Vec<String>) -> Option<Cmd> {
    match ctx.optional_command(name) {
        Ok(Some(cmd)) => {
            // These answer at once or not at all; do not let one that hangs use up the call.
            let limit = ctx.cfg().limits.command_timeout_secs.min(10);
            Some(cmd.timeout(Duration::from_secs(limit)))
        }
        Ok(None) => None,
        Err(ToolError::Failed(problem)) => {
            notes.push(problem);
            None
        }
        Err(_) => None,
    }
}

fn stdout_of(out: &CmdOutput) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn section(body: &mut String, title: &str, out: &CmdOutput) {
    body.push_str(&format!("== {title} ==\n"));
    let text = command_text(out);
    body.push_str(&text);
    if !text.is_empty() && !text.ends_with('\n') {
        body.push('\n');
    }
}

async fn time_sync_status(ctx: Ctx, _args: Args) -> ToolResult {
    let auth = ctx.authorize(None)?;
    let mut body = String::new();
    let mut notes = Vec::new();

    // The system's own view: is a time service switched on, and has the kernel been told
    // that the clock is synchronised.
    let timedatectl = available(&ctx, "timedatectl", &mut notes);
    let mut timedate = None;
    if let Some(cmd) = &timedatectl {
        let shown = ctx.run(cmd.clone().args(["show"])).await?;
        let seen = if command_ok(&shown) {
            parse_timedatectl_show(&stdout_of(&shown))
        } else {
            // systemd before 239 has no `show`: read the human-readable status instead.
            let status = ctx.run(cmd.clone().args(["status"])).await?;
            if !command_ok(&status) {
                section(&mut body, "timedatectl status", &status);
            }
            parse_timedatectl_status(&stdout_of(&status))
        };
        body.push_str("== timedatectl ==\n");
        let word = |flag: Option<bool>, yes: &'static str, no: &'static str| match flag {
            Some(true) => yes,
            Some(false) => no,
            None => "unknown",
        };
        body.push_str(&format!(
            "NTP service: {}\nSynchronised: {}\nTime zone: {}\n",
            word(seen.ntp, "active", "inactive"),
            word(seen.synchronised, "yes", "no"),
            seen.timezone.as_deref().unwrap_or("unknown"),
        ));
        timedate = Some(seen);
    }

    // The time service's view: the first of chrony, systemd-timesyncd and ntpd that
    // answers. A host normally runs one of them; one that is installed but not running
    // says so, and the next is tried.
    let mut answered = false;
    let mut chrony = None;
    let mut timesyncd_offset = None;
    let mut peers = None;
    let chronyc = available(&ctx, "chronyc", &mut notes);
    if let Some(cmd) = &chronyc {
        // -n: addresses as they are, no reverse lookups
        let out = ctx.run(cmd.clone().args(["-n", "tracking"])).await?;
        section(&mut body, "chronyc tracking", &out);
        chrony = parse_chrony_tracking(&stdout_of(&out)).filter(|_| command_ok(&out));
        if chrony.is_some() {
            answered = true;
            let out = ctx.run(cmd.clone().args(["-n", "sources"])).await?;
            section(&mut body, "chronyc sources", &out);
        }
    }
    if !answered && let Some(cmd) = &timedatectl {
        let out = ctx.run(cmd.clone().args(["timesync-status"])).await?;
        section(&mut body, "timedatectl timesync-status", &out);
        if command_ok(&out) {
            answered = true;
            timesyncd_offset = timesync_offset(&stdout_of(&out));
        }
    }
    let ntpq = if answered {
        None
    } else {
        available(&ctx, "ntpq", &mut notes)
    };
    if let Some(cmd) = &ntpq {
        let out = ctx.run(cmd.clone().args(["-pn"])).await?;
        section(&mut body, "ntpq -pn", &out);
        peers = parse_ntpq_peers(&stdout_of(&out)).filter(|_| command_ok(&out));
    }

    // AIDEV-NOTE: the verdict prefers the time service's own statement (chrony), then the
    // kernel flag that timedatectl reports, then ntpd's peer selection. "Not
    // synchronised" is an answer to the question asked, not a failed call.
    let with_offset = |source: &str, offset: &Option<String>| match offset {
        Some(offset) => format!("{source}; offset {offset}"),
        None => source.to_string(),
    };
    let kernel_flag = timedate.as_ref().and_then(|seen| seen.synchronised);
    let verdict = if let Some(tracking) = &chrony {
        if tracking.synchronised {
            format!(
                "Clock: synchronised ({})",
                with_offset("chrony", &tracking.offset)
            )
        } else {
            format!("Clock: NOT synchronised (chrony: {})", tracking.leap)
        }
    } else if let Some(synchronised) = kernel_flag {
        let detail = with_offset("timedatectl", &timesyncd_offset);
        if synchronised {
            format!("Clock: synchronised ({detail})")
        } else {
            format!("Clock: NOT synchronised ({detail})")
        }
    } else if let Some(peers) = &peers {
        if peers.synchronised {
            format!(
                "Clock: synchronised ({})",
                with_offset("ntpq", &peers.offset)
            )
        } else {
            "Clock: NOT synchronised (ntpq: no peer is selected)".to_string()
        }
    } else if timedatectl.is_none() && chronyc.is_none() && ntpq.is_none() && notes.is_empty() {
        "Clock: unknown (none of timedatectl, chronyc or ntpq is installed on this host)"
            .to_string()
    } else {
        "Clock: unknown (no time service gave a usable answer)".to_string()
    };

    let mut text = format!("{verdict}\n{body}");
    for note in notes {
        text.push_str(&format!("[{note}]\n"));
    }
    auth.ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::testing::{FakeBins, call, find, host, ok_text};
    use crate::tools::{Host, ToolError, ToolResult};
    use serde_json::json;
    use std::sync::Arc;

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    const NO_CALLS: Vec<Vec<String>> = Vec::new();

    const SHOW: &str = "Timezone=Etc/UTC\nLocalRTC=no\nCanNTP=yes\nNTP=yes\nNTPSynchronized=yes\n\
                        TimeUSec=Fri 2026-11-20 10:00:00 UTC\n";

    const TRACKING: &str = "\
Reference ID    : C0A80001 (192.168.0.1)
Stratum         : 3
Ref time (UTC)  : Fri Nov 20 09:59:12 2026
System time     : 0.000012345 seconds fast of NTP time
Last offset     : +0.000004321 seconds
RMS offset      : 0.000020000 seconds
Frequency       : 12.345 ppm slow
Leap status     : Normal
";

    const UNSYNCED_TRACKING: &str = "\
Reference ID    : 00000000 ()
Stratum         : 0
System time     : 0.000000000 seconds fast of NTP time
Leap status     : Not synchronised
";

    const SOURCES: &str = "\
MS Name/IP address         Stratum Poll Reach LastRx Last sample
===============================================================================
^* 192.168.0.1                   2   6   377    35    +12us[  +16us] +/-   15ms
";

    const TIMESYNC: &str = "\
       Server: 91.189.91.157 (ntp.ubuntu.com)
Poll interval: 34min 8s (min: 32s; max 34min 8s)
         Leap: normal
      Stratum: 2
       Offset: +1.234ms
        Delay: 20.123ms
";

    const NTPQ: &str = "\
     remote           refid      st t when poll reach   delay   offset  jitter
==============================================================================
+192.168.0.2     10.0.0.1         2 u   33   64  377    0.512    0.101   0.040
*192.168.0.1     10.0.0.1         2 u   12   64  377    0.432   -0.250   0.031
";

    fn fixture(fake: &FakeBins) -> (Arc<Host>, MemorySink) {
        host(&format!(
            r#"
[roles.reader]
allow = ["@read"]
[roles.other]
allow = ["system.view"]
[unix_users.rita]
roles = ["reader"]
[unix_users.otto]
roles = ["other"]
{}"#,
            fake.config_only()
        ))
    }

    async fn run(host: &Arc<Host>, user: &str) -> ToolResult {
        call(host, user, &find(tools(), "time_sync_status"), json!({})).await
    }

    /// A shell fragment that prints `text`, using builtins only: the stand-in commands
    /// have no PATH to find `cat` on.
    fn emit(text: &str) -> String {
        format!(
            "while IFS= read -r line; do printf '%s\\n' \"$line\"; done <<'EOF'\n{}\nEOF\n",
            text.trim_end()
        )
    }

    /// A stand-in timedatectl: `show` prints `show`, `timesync-status` prints
    /// `timesync`, `status` prints `status`; each fails instead if its text is empty.
    fn timedatectl(show: &str, timesync: &str, status: &str) -> String {
        let reply = |text: &str| {
            if text.is_empty() {
                "echo 'Failed to query: not available' >&2; exit 1\n".to_string()
            } else {
                emit(text)
            }
        };
        format!(
            "case \"$1\" in\n show) {} ;;\n timesync-status) {} ;;\n status) {} ;;\nesac",
            reply(show),
            reply(timesync),
            reply(status)
        )
    }

    /// A stand-in chronyc answering `tracking` and `sources`.
    fn chronyc(tracking: &str) -> String {
        format!(
            "case \"$2\" in\n tracking) {} ;;\n sources) {} ;;\nesac",
            emit(tracking),
            emit(SOURCES)
        )
    }

    #[test]
    fn timedatectl_show_is_read_by_key() {
        assert_eq!(
            parse_timedatectl_show(SHOW),
            Timedate {
                ntp: Some(true),
                synchronised: Some(true),
                timezone: Some("Etc/UTC".to_string()),
            }
        );
        assert_eq!(
            parse_timedatectl_show("NTP=no\nNTPSynchronized=no\n"),
            Timedate {
                ntp: Some(false),
                synchronised: Some(false),
                timezone: None,
            }
        );
        assert_eq!(parse_timedatectl_show("garbage\n"), Timedate::default());
    }

    #[test]
    fn timedatectl_status_is_read_in_its_old_and_new_wording() {
        let new = "               Local time: Fri 2026-11-20 10:00:00 UTC\n\
                   \x20               Time zone: Etc/UTC (UTC, +0000)\n\
                   System clock synchronized: yes\n\
                   \x20             NTP service: active\n";
        assert_eq!(
            parse_timedatectl_status(new),
            Timedate {
                ntp: Some(true),
                synchronised: Some(true),
                timezone: Some("Etc/UTC (UTC, +0000)".to_string()),
            }
        );
        let old = "       Time zone: Europe/Paris (CET, +0100)\n\
                   \x20Network time on: yes\nNTP synchronized: no\n";
        assert_eq!(
            parse_timedatectl_status(old),
            Timedate {
                ntp: Some(true),
                synchronised: Some(false),
                timezone: Some("Europe/Paris (CET, +0100)".to_string()),
            }
        );
        let inactive = "System clock synchronized: no\n              NTP service: inactive\n";
        assert_eq!(parse_timedatectl_status(inactive).ntp, Some(false));
    }

    #[test]
    fn chrony_tracking_gives_the_state_and_the_signed_offset() {
        assert_eq!(
            parse_chrony_tracking(TRACKING),
            Some(Tracking {
                synchronised: true,
                leap: "Normal".to_string(),
                offset: Some("+0.000012345 s".to_string()),
            })
        );
        let slow = TRACKING.replace("fast of NTP time", "slow of NTP time");
        assert_eq!(
            parse_chrony_tracking(&slow).unwrap().offset,
            Some("-0.000012345 s".to_string())
        );
        let unsynced = parse_chrony_tracking(UNSYNCED_TRACKING).unwrap();
        assert!(!unsynced.synchronised);
        assert_eq!(unsynced.leap, "Not synchronised");
        // not tracking output at all (the daemon is not running)
        assert_eq!(parse_chrony_tracking("506 Cannot talk to daemon\n"), None);
        // a value that is not a number is not passed on as an offset
        let odd = TRACKING.replace("0.000012345 seconds fast", "$(id) seconds fast");
        assert_eq!(parse_chrony_tracking(&odd).unwrap().offset, None);
    }

    #[test]
    fn ntpq_peers_show_whether_a_source_is_selected() {
        assert_eq!(
            parse_ntpq_peers(NTPQ),
            Some(Peers {
                synchronised: true,
                offset: Some("-0.250 ms".to_string()),
            })
        );
        let unselected = NTPQ.replace("*192.168.0.1", " 192.168.0.1");
        assert_eq!(
            parse_ntpq_peers(&unselected),
            Some(Peers {
                synchronised: false,
                offset: None,
            })
        );
        assert_eq!(parse_ntpq_peers("ntpq: read: Connection refused\n"), None);
    }

    #[test]
    fn the_timesyncd_offset_is_picked_out() {
        assert_eq!(timesync_offset(TIMESYNC), Some("+1.234ms".to_string()));
        assert_eq!(timesync_offset("Server: x\n"), None);
        assert_eq!(timesync_offset("Offset: $(id)\n"), None);
    }

    #[tokio::test]
    async fn a_chrony_host_reports_the_daemons_view_and_its_offset() {
        let fake = FakeBins::new()
            .add_script("timedatectl", &timedatectl(SHOW, TIMESYNC, ""))
            .add_script("chronyc", &chronyc(TRACKING));
        let (host, audit) = fixture(&fake);
        let text = ok_text(run(&host, "rita").await);
        assert!(
            text.starts_with("Clock: synchronised (chrony; offset +0.000012345 s)\n"),
            "{text}"
        );
        assert!(text.contains("Time zone: Etc/UTC"), "{text}");
        assert!(text.contains("NTP service: active"), "{text}");
        assert!(text.contains("== chronyc tracking =="), "{text}");
        assert!(text.contains("Leap status     : Normal"), "{text}");
        assert!(text.contains("== chronyc sources =="), "{text}");
        assert!(text.contains("^* 192.168.0.1"), "{text}");
        assert_eq!(fake.calls("timedatectl"), [strings(&["show"])]);
        assert_eq!(
            fake.calls("chronyc"),
            [strings(&["-n", "tracking"]), strings(&["-n", "sources"])]
        );
        let record = audit.records().last().unwrap().clone();
        assert_eq!(record["decision"], "allow");
        assert!(record.get("resource").is_none(), "{record}");
    }

    #[tokio::test]
    async fn an_unsynchronised_chrony_is_said_loudly_and_is_still_an_answer() {
        let fake = FakeBins::new()
            .add_script("timedatectl", &timedatectl(SHOW, "", ""))
            .add_script("chronyc", &chronyc(UNSYNCED_TRACKING));
        let (host, _audit) = fixture(&fake);
        let text = ok_text(run(&host, "rita").await);
        assert!(
            text.starts_with("Clock: NOT synchronised (chrony: Not synchronised)\n"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn a_timesyncd_host_uses_timedatectl_alone() {
        let fake = FakeBins::new().add_script("timedatectl", &timedatectl(SHOW, TIMESYNC, ""));
        let (host, _audit) = fixture(&fake);
        let text = ok_text(run(&host, "rita").await);
        assert!(
            text.starts_with("Clock: synchronised (timedatectl; offset +1.234ms)\n"),
            "{text}"
        );
        assert!(text.contains("== timedatectl timesync-status =="), "{text}");
        assert!(text.contains("ntp.ubuntu.com"), "{text}");
        assert_eq!(
            fake.calls("timedatectl"),
            [strings(&["show"]), strings(&["timesync-status"])]
        );
    }

    #[tokio::test]
    async fn an_older_timedatectl_without_show_falls_back_to_status() {
        let status = "System clock synchronized: no\n              NTP service: inactive\n";
        let fake = FakeBins::new().add_script("timedatectl", &timedatectl("", "", status));
        let (host, _audit) = fixture(&fake);
        let text = ok_text(run(&host, "rita").await);
        assert!(
            text.starts_with("Clock: NOT synchronised (timedatectl)\n"),
            "{text}"
        );
        assert!(text.contains("NTP service: inactive"), "{text}");
        assert_eq!(
            fake.calls("timedatectl"),
            [
                strings(&["show"]),
                strings(&["status"]),
                strings(&["timesync-status"])
            ]
        );
    }

    #[tokio::test]
    async fn a_stopped_chrony_is_shown_and_the_next_source_is_tried() {
        let unsynced = "NTP=yes\nNTPSynchronized=no\nTimezone=Etc/UTC\n";
        let fake = FakeBins::new()
            .add_script("timedatectl", &timedatectl(unsynced, TIMESYNC, ""))
            .add_script("chronyc", "echo '506 Cannot talk to daemon'; exit 1");
        let (host, _audit) = fixture(&fake);
        let text = ok_text(run(&host, "rita").await);
        assert!(
            text.starts_with("Clock: NOT synchronised (timedatectl"),
            "{text}"
        );
        assert!(text.contains("506 Cannot talk to daemon"), "{text}");
        assert!(text.contains("== timedatectl timesync-status =="), "{text}");
        // sources is not asked for once tracking has failed
        assert_eq!(fake.calls("chronyc"), [strings(&["-n", "tracking"])]);
    }

    #[tokio::test]
    async fn an_ntpd_host_is_judged_by_its_selected_peer() {
        let fake = FakeBins::new().add("ntpq", NTPQ, 0);
        let (host, _audit) = fixture(&fake);
        let text = ok_text(run(&host, "rita").await);
        assert!(
            text.starts_with("Clock: synchronised (ntpq; offset -0.250 ms)\n"),
            "{text}"
        );
        assert!(text.contains("== ntpq -pn =="), "{text}");
        assert_eq!(fake.calls("ntpq"), [strings(&["-pn"])]);

        let unselected = NTPQ.replace("*192.168.0.1", " 192.168.0.1");
        let fake = FakeBins::new().add("ntpq", &unselected, 0);
        let (host, _audit) = fixture(&fake);
        let text = ok_text(run(&host, "rita").await);
        assert!(text.starts_with("Clock: NOT synchronised (ntpq"), "{text}");
    }

    #[tokio::test]
    async fn a_host_with_no_time_tools_gets_an_answer_not_an_error() {
        let fake = FakeBins::new().add("unrelated", "", 0);
        let (host, _audit) = fixture(&fake);
        let text = ok_text(run(&host, "rita").await);
        assert!(text.starts_with("Clock: unknown"), "{text}");
        for name in ["timedatectl", "chronyc", "ntpq"] {
            assert!(text.contains(name), "should name {name}: {text}");
        }
    }

    #[tokio::test]
    async fn nothing_runs_without_the_permission() {
        let fake = FakeBins::new()
            .add_script("timedatectl", &timedatectl(SHOW, TIMESYNC, ""))
            .add_script("chronyc", &chronyc(TRACKING));
        let (host, audit) = fixture(&fake);
        let result = run(&host, "otto").await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        assert_eq!(audit.records().last().unwrap()["decision"], "deny");
        assert_eq!(fake.calls("timedatectl"), NO_CALLS);
        assert_eq!(fake.calls("chronyc"), NO_CALLS);
    }
}
