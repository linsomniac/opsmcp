//! Processes: list them, look at one, send one a signal.

use rustix::process::{Pid, PidfdFlags, Signal};

use super::args::{Args, Param};
use super::fs::Names;
use super::logs::uptime_secs;
use super::{Ctx, Tool, ToolError, ToolResult, blocking, format_table, required};
use crate::policy::Access;
use crate::sanitize::redact_args;
use crate::timefmt::{human_bytes, human_duration, now_secs, rfc3339_utc};

/// The signals `process_signal` can send, by the name the agent uses.
const SIGNALS: [(&str, Signal); 9] = [
    ("TERM", Signal::TERM),
    ("KILL", Signal::KILL),
    ("HUP", Signal::HUP),
    ("INT", Signal::INT),
    ("QUIT", Signal::QUIT),
    ("USR1", Signal::USR1),
    ("USR2", Signal::USR2),
    ("STOP", Signal::STOP),
    ("CONT", Signal::CONT),
];

/// Set in a process's flags when it is a kernel thread.
const PF_KTHREAD: u64 = 0x0020_0000;

pub fn tools() -> Vec<Tool> {
    let signal_names: Vec<&str> = SIGNALS.iter().map(|(name, _)| *name).collect();
    vec![
        Tool::new(
            "process_list",
            "List running processes (like ps): pid, user, CPU share, resident memory, state, \
             age and command line. Sorted by CPU use unless told otherwise; can be filtered by \
             user or by a word in the command.",
            Access::Read,
            "process.view",
            vec![
                Param::choice(
                    "sort",
                    "Order (default cpu)",
                    &["cpu", "mem", "pid", "time"],
                ),
                Param::int("limit", "Most processes to show (default 30)", 1, 1000),
                Param::str("user", "Only processes of this user").max_len(64),
                Param::str(
                    "name",
                    "Only processes whose name or command line contains this",
                )
                .max_len(128),
                Param::int(
                    "width",
                    "Longest command line to show (default 160)",
                    20,
                    2000,
                ),
            ],
            process_list,
        ),
        Tool::new(
            "process_info",
            "Details of one process: owner, state, parent, start time, CPU time, memory, \
             threads, open files, executable, working directory, cgroup and command line. \
             The environment is never shown.",
            Access::Read,
            "process.view",
            vec![
                Param::int("pid", "Process id", 1, 4_194_304).required(),
                Param::bool("limits", "Also show the process's resource limits"),
            ],
            process_info,
        ),
        Tool::new(
            "process_signal",
            "Send a signal to a process. You must also give the process's name as you \
             believe it to be; if it does not match, nothing is sent (a guard against \
             signalling the wrong process). pid 1 and opsmcp itself cannot be signalled.",
            Access::Write,
            "process.signal",
            vec![
                Param::int("pid", "Process id", 1, 4_194_304).required(),
                Param::choice("signal", "Signal to send", &signal_names).required(),
                Param::str(
                    "expected_name",
                    "The process's name (as in process_list), to confirm the target",
                )
                .max_len(64)
                .required(),
            ],
            process_signal,
        ),
    ]
}

/// The fields of /proc/PID/stat that the tools use.
#[derive(Debug, PartialEq, Eq)]
pub struct Stat {
    pub pid: i32,
    pub comm: String,
    pub state: char,
    pub ppid: i32,
    pub flags: u64,
    /// CPU time in user and kernel mode, in clock ticks.
    pub utime: u64,
    pub stime: u64,
    pub threads: i64,
    /// When the process started, in clock ticks after boot.
    pub starttime: u64,
    pub vsize: u64,
    pub rss_pages: i64,
}

/// Parses /proc/PID/stat. The process name sits in parentheses and may itself contain
/// spaces and parentheses, so everything is located relative to the LAST `)`.
pub fn parse_stat(text: &str) -> Option<Stat> {
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    if close < open {
        return None;
    }
    let rest: Vec<&str> = text[close + 1..].split_whitespace().collect();
    // proc(5) numbers the fields from 1; the name is field 2, so `rest` starts at field 3.
    let field = |number: usize| rest.get(number - 3).copied();
    Some(Stat {
        pid: text[..open].trim().parse().ok()?,
        comm: text[open + 1..close].to_string(),
        state: field(3)?.chars().next()?,
        ppid: field(4)?.parse().ok()?,
        flags: field(9)?.parse().ok()?,
        utime: field(14)?.parse().ok()?,
        stime: field(15)?.parse().ok()?,
        threads: field(20)?.parse().ok()?,
        starttime: field(22)?.parse().ok()?,
        vsize: field(23)?.parse().ok()?,
        rss_pages: field(24)?.parse().ok()?,
    })
}

/// The real uid from /proc/PID/status.
pub fn parse_uid(status: &str) -> Option<u32> {
    let line = status.lines().find_map(|l| l.strip_prefix("Uid:"))?;
    line.split_whitespace().next()?.parse().ok()
}

/// Splits /proc/PID/cmdline (NUL-separated) into arguments.
pub fn split_cmdline(raw: &[u8]) -> Vec<String> {
    raw.split(|b| *b == 0)
        .filter(|arg| !arg.is_empty())
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect()
}

/// One process, as read from /proc.
struct Proc {
    stat: Stat,
    uid: u32,
    args: Vec<String>,
}

impl Proc {
    /// `None` if the process is gone (or hidden from us).
    fn read(pid: i32) -> Option<Proc> {
        let stat = parse_stat(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)?;
        let uid = parse_uid(&std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?)?;
        let args = split_cmdline(&read_capped(&format!("/proc/{pid}/cmdline"), 16 * 1024));
        Some(Proc { stat, uid, args })
    }

    fn is_kernel_thread(&self) -> bool {
        self.stat.flags & PF_KTHREAD != 0
    }

    /// The command line with likely secrets masked, or `[name]` for a kernel thread.
    fn command(&self) -> String {
        if self.args.is_empty() {
            format!("[{}]", self.stat.comm)
        } else {
            redact_args(&self.args).join(" ")
        }
    }

    /// Seconds of CPU time used, and seconds since it started.
    fn times(&self, clock: &Clock) -> (f64, f64) {
        let cpu = (self.stat.utime + self.stat.stime) as f64 / clock.ticks;
        let age = (clock.uptime - self.stat.starttime as f64 / clock.ticks).max(0.0);
        (cpu, age)
    }

    fn rss_bytes(&self, clock: &Clock) -> u64 {
        u64::try_from(self.stat.rss_pages)
            .unwrap_or(0)
            .saturating_mul(clock.page_size)
    }
}

/// What is needed to turn the kernel's tick counts into seconds.
struct Clock {
    ticks: f64,
    page_size: u64,
    uptime: f64,
}

impl Clock {
    fn now() -> Clock {
        Clock {
            ticks: rustix::param::clock_ticks_per_second().max(1) as f64,
            page_size: rustix::param::page_size() as u64,
            uptime: uptime_secs().unwrap_or(0.0),
        }
    }
}

fn read_capped(path: &str, max: u64) -> Vec<u8> {
    use std::io::Read;
    let mut data = Vec::new();
    if let Ok(file) = std::fs::File::open(path) {
        let _ = file.take(max).read_to_end(&mut data);
    }
    data
}

fn all_pids() -> Vec<i32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
        .collect()
}

fn state_name(state: char) -> &'static str {
    match state {
        'R' => "running",
        'S' => "sleeping",
        'D' => "waiting on I/O",
        'Z' => "zombie",
        'T' | 't' => "stopped",
        'I' => "idle",
        'X' | 'x' => "dead",
        _ => "?",
    }
}

/// The name a process goes by in grants: `OWNER/NAME`.
fn resource_of(owner: &str, process: &Proc) -> String {
    format!("{owner}/{}", process.stat.comm)
}

/// Sends a signal by pid on a kernel without pidfds (before Linux 5.3), after checking
/// that the pid still belongs to the process that was examined: `starttime` is that
/// process's start time, which a later process with the same pid cannot share.
fn signal_unpinned(pid: Pid, starttime: u64, signal: Signal) -> Result<(), String> {
    let number = pid.as_raw_nonzero().get();
    let now = Proc::read(number).ok_or_else(|| format!("process {number} no longer exists"))?;
    if now.stat.starttime != starttime {
        return Err(format!(
            "process {number} is no longer the process that was checked; nothing was sent"
        ));
    }
    rustix::process::kill_process(pid, signal)
        .map_err(|e| format!("signalling process {number}: {}", std::io::Error::from(e)))
}

async fn process_list(ctx: Ctx, args: Args) -> ToolResult {
    let sort = args.str("sort").unwrap_or("cpu").to_string();
    let limit = usize::try_from(args.int("limit").unwrap_or(30)).unwrap_or(30);
    let width = usize::try_from(args.int("width").unwrap_or(160)).unwrap_or(160);
    let only_user = args.str("user").map(str::to_string);
    let only_name = args.str("name").map(str::to_lowercase);
    let auth = ctx.authorize(None)?;
    blocking(ctx.clone(), move || {
        let clock = Clock::now();
        let mut names = Names::default();
        let mut found: Vec<(Proc, String, String)> = Vec::new();
        for pid in all_pids() {
            // A process can exit between the directory listing and the read: skip it.
            let Some(process) = Proc::read(pid) else {
                continue;
            };
            let owner = names.user(process.uid).to_string();
            if only_user.as_ref().is_some_and(|u| *u != owner) {
                continue;
            }
            let command = process.command();
            if let Some(needle) = &only_name
                && !process.stat.comm.to_lowercase().contains(needle)
                && !command.to_lowercase().contains(needle)
            {
                continue;
            }
            found.push((process, owner, command));
        }
        let cpu_share = |p: &Proc| {
            let (cpu, age) = p.times(&clock);
            if age > 0.0 { cpu * 100.0 / age } else { 0.0 }
        };
        match sort.as_str() {
            "mem" => found.sort_by_key(|(p, _, _)| std::cmp::Reverse(p.stat.rss_pages)),
            "pid" => found.sort_by_key(|(p, _, _)| p.stat.pid),
            "time" => found.sort_by_key(|(p, _, _)| std::cmp::Reverse(p.stat.utime + p.stat.stime)),
            _ => found.sort_by(|(a, _, _), (b, _, _)| cpu_share(b).total_cmp(&cpu_share(a))),
        }
        let total = found.len();
        let rows: Vec<Vec<String>> = found
            .iter()
            .take(limit)
            .map(|(process, owner, command)| {
                let (_, age) = process.times(&clock);
                vec![
                    process.stat.pid.to_string(),
                    owner.clone(),
                    format!("{:.1}", cpu_share(process)),
                    human_bytes(process.rss_bytes(&clock)),
                    process.stat.state.to_string(),
                    human_duration(age as u64),
                    process.stat.threads.to_string(),
                    command.chars().take(width).collect(),
                ]
            })
            .collect();
        let headers = ["PID", "USER", "%CPU", "RSS", "S", "AGE", "THR", "COMMAND"];
        let right = [true, false, true, true, false, true, true, false];
        let mut text = format_table(&headers, &rows, &right);
        text.push_str(&format!(
            "[{} of {total} matching processes shown; %CPU is the share of its lifetime spent on CPU]\n",
            rows.len()
        ));
        auth.ok(text)
    })
    .await
}

async fn process_info(ctx: Ctx, args: Args) -> ToolResult {
    let pid = i32::try_from(args.int("pid").unwrap_or(0)).unwrap_or(0);
    let with_limits = args.bool("limits") == Some(true);
    blocking(ctx.clone(), move || {
        let gone = || ToolError::Failed(format!("there is no process {pid}"));
        let process = Proc::read(pid).ok_or_else(gone)?;
        let mut names = Names::default();
        let owner = names.user(process.uid).to_string();
        // The caller gave a pid, not a name: a refusal must not tell them the name.
        let auth = ctx.authorize_hidden(Some(&resource_of(&owner, &process)))?;

        let clock = Clock::now();
        let (cpu, age) = process.times(&clock);
        let link = |name: &str| match std::fs::read_link(format!("/proc/{pid}/{name}")) {
            Ok(target) => target.display().to_string(),
            Err(e) => format!("({e})"),
        };
        let open_files = match std::fs::read_dir(format!("/proc/{pid}/fd")) {
            Ok(entries) => entries.count().to_string(),
            Err(e) => format!("({e})"),
        };
        let parent = Proc::read(process.stat.ppid)
            .map(|p| format!(" ({})", p.stat.comm))
            .unwrap_or_default();
        let read =
            |name: &str| std::fs::read_to_string(format!("/proc/{pid}/{name}")).unwrap_or_default();
        let mut text = format!(
            "pid:        {pid}\n\
             name:       {}\n\
             user:       {owner} ({})\n\
             state:      {} ({})\n\
             parent:     {}{parent}\n\
             started:    {} ({} ago)\n\
             cpu time:   {} ({:.1}% of its lifetime)\n\
             memory:     resident {}, virtual {}\n\
             threads:    {}\n\
             open files: {open_files}\n\
             exe:        {}\n\
             cwd:        {}\n\
             cgroup:     {}\n\
             oom score:  {}\n\
             command:    {}\n",
            process.stat.comm,
            process.uid,
            process.stat.state,
            state_name(process.stat.state),
            process.stat.ppid,
            rfc3339_utc(now_secs() - age as i64),
            human_duration(age as u64),
            human_duration(cpu as u64),
            if age > 0.0 { cpu * 100.0 / age } else { 0.0 },
            human_bytes(process.rss_bytes(&clock)),
            human_bytes(process.stat.vsize),
            process.stat.threads,
            link("exe"),
            link("cwd"),
            read("cgroup").trim().replace('\n', "; "),
            read("oom_score").trim(),
            process.command(),
        );
        if with_limits {
            text.push_str("\nResource limits:\n");
            text.push_str(&read("limits"));
        }
        auth.ok(text)
    })
    .await
}

async fn process_signal(ctx: Ctx, args: Args) -> ToolResult {
    let pid = i32::try_from(args.int("pid").unwrap_or(0)).unwrap_or(0);
    let signal_name = required(&args, "signal")?.to_string();
    let expected = required(&args, "expected_name")?.to_string();
    let signal = SIGNALS
        .iter()
        .find(|(name, _)| *name == signal_name)
        .map(|(_, signal)| *signal)
        .ok_or_else(|| ToolError::Invalid(format!("unknown signal {signal_name}")))?;
    blocking(ctx.clone(), move || {
        let target = Pid::from_raw(pid)
            .ok_or_else(|| ToolError::Invalid(format!("{pid} is not a process id")))?;
        // AIDEV-NOTE: pin the process FIRST. A pidfd refers to this exact process for as
        // long as we hold it; if the process exits and its pid is given to another, the
        // signal below goes nowhere instead of to the newcomer. Everything read from
        // /proc after this point can only make us refuse, never signal something else.
        let pinned = match rustix::process::pidfd_open(target, PidfdFlags::empty()) {
            Ok(pidfd) => Some(pidfd),
            // Kernels before 5.3 have no pidfd. `signal_unpinned` is used instead: it
            // rechecks the process's start time just before signalling, which leaves
            // only the instant between that check and the signal unguarded.
            Err(rustix::io::Errno::NOSYS) => None,
            Err(e) => {
                return Err(ToolError::Failed(format!(
                    "process {pid}: {}",
                    std::io::Error::from(e)
                )));
            }
        };
        let process = Proc::read(pid)
            .ok_or_else(|| ToolError::Failed(format!("process {pid} no longer exists")))?;
        let owner = Names::default().user(process.uid).to_string();
        let resource = resource_of(&owner, &process);
        let refusal = if pid == 1 {
            Some("pid 1 (init) cannot be signalled through opsmcp")
        } else if u32::try_from(pid).is_ok_and(|p| p == std::process::id()) {
            Some("opsmcp will not signal itself")
        } else if process.is_kernel_thread() {
            Some("kernel threads cannot be signalled")
        } else {
            None
        };
        if let Some(reason) = refusal {
            return Err(ctx.deny(Some(&resource), reason));
        }
        // AIDEV-NOTE: the permission check comes before the name check, and its refusal
        // does not name the process. Otherwise a caller allowed to signal only some
        // processes could use wrong guesses to read off the name of any pid.
        let auth = ctx.authorize_hidden(Some(&resource))?;
        if process.stat.comm != expected {
            return Err(ToolError::Invalid(format!(
                "process {pid} is named {:?}, not {expected:?}; nothing was sent",
                process.stat.comm
            )));
        }
        match &pinned {
            Some(pidfd) => rustix::process::pidfd_send_signal(pidfd, signal).map_err(|e| {
                ToolError::Failed(format!(
                    "signalling process {pid}: {}",
                    std::io::Error::from(e)
                ))
            })?,
            None => signal_unpinned(target, process.stat.starttime, signal)
                .map_err(ToolError::Failed)?,
        }
        auth.ok(format!(
            "Sent SIG{signal_name} to process {pid} ({}, owned by {owner}).\n",
            process.stat.comm
        ))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::Host;
    use crate::tools::testing::{call, find, host, ok_text};
    use serde_json::{Value, json};
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Child, Command, Stdio};
    use std::sync::Arc;

    #[test]
    fn parse_stat_copes_with_spaces_and_parentheses_in_the_name() {
        let line = "1234 (tmux: server (x)) S 1 1234 1234 0 -1 4194560 1000 0 0 0 150 50 0 0 20 0 3 0 98765 12345678 2500 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0";
        assert_eq!(
            parse_stat(line),
            Some(Stat {
                pid: 1234,
                comm: "tmux: server (x)".to_string(),
                state: 'S',
                ppid: 1,
                flags: 4_194_560,
                utime: 150,
                stime: 50,
                threads: 3,
                starttime: 98765,
                vsize: 12_345_678,
                rss_pages: 2500,
            })
        );
    }

    #[test]
    fn parse_stat_rejects_truncated_or_garbled_input() {
        for bad in [
            "",
            "1234",
            "1234 (bash",
            "1234 (bash) S 1 2 3",
            "x (bash) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5 6 7",
        ] {
            assert_eq!(parse_stat(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn parse_uid_takes_the_real_uid() {
        assert_eq!(
            parse_uid("Name:\tbash\nUid:\t1000\t0\t0\t0\nGid:\t100\t100\t100\t100\n"),
            Some(1000)
        );
        assert_eq!(parse_uid("Name:\tbash\n"), None);
    }

    #[test]
    fn split_cmdline_separates_arguments_at_nul_bytes() {
        assert_eq!(
            split_cmdline(b"nginx\0-g\0daemon off;\0"),
            ["nginx", "-g", "daemon off;"]
        );
        assert_eq!(split_cmdline(b""), Vec::<String>::new());
        assert_eq!(split_cmdline(b"single"), ["single"]);
    }

    fn me() -> String {
        crate::identity::current().unwrap().user
    }

    fn fixture() -> Arc<Host> {
        let me = me();
        host(&format!(
            r#"
[roles.admin]
allow = ["@all"]
[roles.reader]
allow = ["@read"]
[roles.sleepkiller]
allow = ["process.signal:{me}/sleep"]
[roles.nginxkiller]
allow = ["process.signal:{me}/nginx", "process.signal:nobody/*"]
[unix_users.adam]
roles = ["admin"]
[unix_users.rita]
roles = ["reader"]
[unix_users.sam]
roles = ["sleepkiller"]
[unix_users.nina]
roles = ["nginxkiller"]
"#
        ))
        .0
    }

    async fn run(host: &Arc<Host>, user: &str, tool: &str, arguments: Value) -> ToolResult {
        call(host, user, &find(tools(), tool), arguments).await
    }

    fn own_name() -> String {
        std::fs::read_to_string("/proc/self/comm")
            .unwrap()
            .trim()
            .to_string()
    }

    #[tokio::test]
    async fn process_list_includes_this_test_process() {
        let host = fixture();
        let text = ok_text(
            run(
                &host,
                "rita",
                "process_list",
                json!({"name": own_name(), "limit": 1000, "sort": "pid"}),
            )
            .await,
        );
        let pid = std::process::id().to_string();
        let line = text
            .lines()
            .find(|l| l.split_whitespace().next() == Some(pid.as_str()));
        let line = line.unwrap_or_else(|| panic!("pid {pid} not listed in:\n{text}"));
        assert!(line.contains(&me()), "{line}");
        assert!(text.lines().next().unwrap().contains("PID"), "{text}");
    }

    #[tokio::test]
    async fn process_list_filters_by_user_and_respects_the_limit() {
        let host = fixture();
        let text = ok_text(
            run(
                &host,
                "rita",
                "process_list",
                json!({"user": me(), "limit": 3}),
            )
            .await,
        );
        let rows: Vec<&str> = text
            .lines()
            .skip(1)
            .filter(|l| !l.starts_with('['))
            .collect();
        assert!(!rows.is_empty() && rows.len() <= 3, "{text}");
        for row in rows {
            assert_eq!(row.split_whitespace().nth(1), Some(me().as_str()), "{row}");
        }
        let nobody = ok_text(
            run(
                &host,
                "rita",
                "process_list",
                json!({"user": "no-such-user-xyz"}),
            )
            .await,
        );
        assert_eq!(
            nobody
                .lines()
                .skip(1)
                .filter(|l| !l.starts_with('['))
                .count(),
            0,
            "{nobody}"
        );
    }

    #[tokio::test]
    async fn process_info_describes_a_process_but_not_its_environment() {
        let host = fixture();
        let text = ok_text(
            run(
                &host,
                "rita",
                "process_info",
                json!({"pid": std::process::id()}),
            )
            .await,
        );
        assert!(
            text.contains(&format!("pid:        {}", std::process::id())),
            "{text}"
        );
        assert!(text.contains(&own_name()), "{text}");
        assert!(text.contains("exe:"), "{text}");
        assert!(
            !text.contains("CARGO_MANIFEST_DIR"),
            "the environment must not be shown:\n{text}"
        );
    }

    #[tokio::test]
    async fn process_info_reports_a_missing_process() {
        let host = fixture();
        let result = run(&host, "rita", "process_info", json!({"pid": 4_194_303})).await;
        assert!(matches!(result, Err(ToolError::Failed(_))), "{result:?}");
    }

    fn sleeper() -> Child {
        Command::new("sleep")
            .arg("60")
            .stdin(Stdio::null())
            .spawn()
            .unwrap()
    }

    fn still_running(child: &mut Child) -> bool {
        child.try_wait().unwrap().is_none()
    }

    #[tokio::test]
    async fn process_signal_delivers_the_signal_to_a_confirmed_process() {
        let host = fixture();
        let mut child = sleeper();
        let arguments = json!({"pid": child.id(), "signal": "TERM", "expected_name": "sleep"});
        let text = ok_text(run(&host, "sam", "process_signal", arguments).await);
        assert!(
            text.contains("TERM") && text.contains(&child.id().to_string()),
            "{text}"
        );
        let status = child.wait().unwrap();
        assert_eq!(status.signal(), Some(15));
    }

    #[tokio::test]
    async fn process_signal_sends_nothing_when_the_name_does_not_match() {
        let host = fixture();
        let mut child = sleeper();
        let arguments = json!({"pid": child.id(), "signal": "KILL", "expected_name": "nginx"});
        match run(&host, "adam", "process_signal", arguments).await {
            Err(ToolError::Invalid(message)) => assert!(message.contains("sleep"), "{message}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(still_running(&mut child));
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[tokio::test]
    async fn process_signal_honours_a_grant_limited_to_other_processes() {
        let host = fixture();
        let mut child = sleeper();
        let arguments = json!({"pid": child.id(), "signal": "KILL", "expected_name": "sleep"});
        let result = run(&host, "nina", "process_signal", arguments).await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        assert!(still_running(&mut child));
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[tokio::test]
    async fn a_refusal_does_not_reveal_the_name_of_a_process_the_caller_may_not_touch() {
        let host = fixture();
        let mut child = sleeper();
        // nina may signal other processes, not this one, and guesses at its name
        let arguments = json!({"pid": child.id(), "signal": "KILL", "expected_name": "guess"});
        match run(&host, "nina", "process_signal", arguments).await {
            Err(ToolError::Denied(message)) => assert!(!message.contains("sleep"), "{message}"),
            other => panic!("expected a denial, got {other:?}"),
        }
        // sam may look at nothing: process_info refuses without naming the process
        match run(&host, "sam", "process_info", json!({"pid": child.id()})).await {
            Err(ToolError::Denied(message)) => assert!(!message.contains("sleep"), "{message}"),
            other => panic!("expected a denial, got {other:?}"),
        }
        assert!(still_running(&mut child));
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[tokio::test]
    async fn process_signal_never_targets_init_or_itself() {
        let host = fixture();
        let init = std::fs::read_to_string("/proc/1/comm")
            .unwrap()
            .trim()
            .to_string();
        for (pid, name) in [(1, init), (std::process::id(), own_name())] {
            let arguments = json!({"pid": pid, "signal": "CONT", "expected_name": name});
            match run(&host, "adam", "process_signal", arguments).await {
                Err(ToolError::Denied(_)) => {}
                other => panic!("pid {pid}: expected a denial, got {other:?}"),
            }
        }
    }

    #[test]
    fn without_pidfds_a_signal_still_only_goes_to_the_process_that_was_checked() {
        // the fallback for kernels older than 5.3, which have no pidfd
        let mut child = sleeper();
        let pid = Pid::from_raw(child.id() as i32).unwrap();
        let checked = Proc::read(child.id() as i32).unwrap();
        // a different process now has that pid (a different start time): nothing is sent
        let result = signal_unpinned(pid, checked.stat.starttime + 1, Signal::TERM);
        assert!(result.is_err(), "{result:?}");
        assert!(still_running(&mut child));
        // the process that was checked: delivered
        signal_unpinned(pid, checked.stat.starttime, Signal::TERM).unwrap();
        assert_eq!(child.wait().unwrap().signal(), Some(15));
    }

    #[tokio::test]
    async fn process_signal_reports_a_process_that_is_gone() {
        let host = fixture();
        let mut child = Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        let arguments = json!({"pid": pid, "signal": "TERM", "expected_name": "true"});
        let result = run(&host, "adam", "process_signal", arguments).await;
        assert!(matches!(result, Err(ToolError::Failed(_))), "{result:?}");
    }
}
