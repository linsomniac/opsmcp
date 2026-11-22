//! How close the host is to its exhaustible limits.
//!
//! AIDEV-NOTE: everything here is read from /proc (and statvfs on local filesystems).
//! Nothing is run. A figure whose files are missing on this kernel is simply left out:
//! the tool must work on any host, with or without conntrack, swap or inotify users.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::args::Args;
use super::fs::Names;
use super::process::parse_uid;
use super::system::{Listing, listing, parse_meminfo, parse_mountinfo};
use super::{Ctx, Tool, ToolResult, blocking, format_table, one_line_cell};
use crate::policy::Access;
use crate::sanitize::keep_head;
use crate::timefmt::human_bytes;

/// A limit used to this share or more is marked `!`.
const WARN_PERCENT: u64 = 75;
/// A limit used to this share or more is marked `!!`.
const ALARM_PERCENT: u64 = 90;
/// Most filesystem rows shown (the fullest are kept).
const MAX_FS_ROWS: usize = 40;
/// How many processes are listed as nearest their open-file limit.
const TOP_PROCESSES: usize = 5;
/// Most limits named in the first line.
const NAMED_IN_VERDICT: usize = 5;
/// Lines of one fdinfo file that are looked at.
const MAX_FDINFO_LINES: usize = 5_000_000;

/// How far the walk over every process's open files may go.
#[derive(Clone, Copy, Debug)]
pub struct ScanBounds {
    pub max_fds: usize,
    pub max_time: Duration,
}

/// The bounds used on a real host.
pub const SCAN_BOUNDS: ScanBounds = ScanBounds {
    max_fds: 200_000,
    max_time: Duration::from_secs(3),
};

pub fn tools() -> Vec<Tool> {
    tools_at(PathBuf::from("/proc"))
}

/// The tools, reading from `proc` instead of /proc (for tests).
pub fn tools_at(proc: PathBuf) -> Vec<Tool> {
    vec![Tool::new(
        "limits_headroom",
        "Show how close this host is to every limit that can run out: open files, process \
         ids and threads, connection tracking, inotify watches, asynchronous I/O, the ARP \
         table, TCP memory and orphans, memory, swap, and space and inodes on \
         each filesystem; plus the counters that show a limit was hit since boot. The \
         first line says what is above 75%. Use it when something fails with 'too many \
         open files', 'cannot allocate', 'no space left' or 'table full', or when a \
         failure has no obvious cause.",
        Access::Read,
        "system.view",
        vec![],
        move |ctx, args| limits_headroom(ctx, args, proc.clone()),
    )]
}

// ---- one limit --------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unit {
    Count,
    Bytes,
    Pages,
}

/// One limit and how much of it is used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub name: String,
    pub used: u64,
    pub limit: u64,
    pub unit: Unit,
}

impl Row {
    /// `None` for a limit of zero: there is nothing to measure against.
    pub fn new(name: impl Into<String>, used: u64, limit: u64, unit: Unit) -> Option<Row> {
        (limit > 0).then(|| Row {
            name: name.into(),
            used,
            limit,
            unit,
        })
    }

    /// The share used, rounded DOWN, so that a row is never shown as having reached a
    /// mark it has not reached.
    pub fn percent(&self) -> u64 {
        percent(self.used, self.limit)
    }
}

fn percent(used: u64, limit: u64) -> u64 {
    if limit == 0 {
        return 0;
    }
    u64::try_from(u128::from(used) * 100 / u128::from(limit)).unwrap_or(u64::MAX)
}

/// `!!` at 90% and above, `!` at 75% and above.
pub fn mark(percent: u64) -> &'static str {
    if percent >= ALARM_PERCENT {
        "!!"
    } else if percent >= WARN_PERCENT {
        "!"
    } else {
        ""
    }
}

fn amount(value: u64, unit: Unit) -> String {
    match unit {
        Unit::Count => value.to_string(),
        Unit::Bytes => human_bytes(value),
        Unit::Pages => format!("{value} pages"),
    }
}

// ---- the kernel's files -----------------------------------------------------------------

/// `/proc/sys/fs/file-nr`: file handles in use and the most there can be.
pub fn parse_file_nr(text: &str) -> Option<(u64, u64)> {
    let mut fields = text.split_whitespace().map(|field| field.parse::<u64>());
    let allocated = fields.next()?.ok()?;
    let free = fields.next()?.ok()?;
    let max = fields.next()?.ok()?;
    Some((allocated.saturating_sub(free), max))
}

/// `/proc/loadavg`: how many processes and threads exist (the number after the `/`).
pub fn parse_tasks(loadavg: &str) -> Option<u64> {
    let field = loadavg.split_whitespace().nth(3)?;
    field.split_once('/')?.1.parse().ok()
}

/// The TCP line of `/proc/net/sockstat`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Sockstat {
    pub orphans: Option<u64>,
    /// Memory used by TCP buffers, in pages.
    pub mem_pages: Option<u64>,
}

pub fn parse_sockstat(text: &str) -> Sockstat {
    let mut stat = Sockstat::default();
    let Some(line) = text.lines().find_map(|line| line.strip_prefix("TCP:")) else {
        return stat;
    };
    let fields: Vec<&str> = line.split_whitespace().collect();
    for pair in fields.chunks(2) {
        let (Some(key), Some(value)) = (pair.first(), pair.get(1)) else {
            continue;
        };
        let value = value.parse::<u64>().ok();
        match *key {
            "orphan" => stat.orphans = value,
            "mem" => stat.mem_pages = value,
            _ => {}
        }
    }
    stat
}

/// The third number of `tcp_mem`: the most pages TCP may use.
pub fn tcp_mem_max(text: &str) -> Option<u64> {
    text.split_whitespace().nth(2)?.parse().ok()
}

/// The entries in `/proc/net/arp` (one line each, after a heading).
pub fn count_arp(text: &str) -> u64 {
    text.lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
        .count() as u64
}

/// One counter of the `TcpExt` group in `/proc/net/netstat` (a line of names followed by
/// a line of values).
pub fn tcp_ext(text: &str, name: &str) -> Option<u64> {
    let mut lines = text.lines().filter(|line| line.starts_with("TcpExt:"));
    let names = lines.next()?;
    let values = lines.next()?;
    let at = names.split_whitespace().position(|field| field == name)?;
    values.split_whitespace().nth(at)?.parse().ok()
}

/// One column of `/proc/net/stat/nf_conntrack` added up over the CPUs (a line of names,
/// then a line of hexadecimal values for each CPU).
pub fn conntrack_stat(text: &str, name: &str) -> Option<u64> {
    let mut lines = text.lines();
    let at = lines
        .next()?
        .split_whitespace()
        .position(|field| field == name)?;
    let mut total: Option<u64> = None;
    for line in lines {
        let Some(value) = line
            .split_whitespace()
            .nth(at)
            .and_then(|field| u64::from_str_radix(field, 16).ok())
        else {
            continue;
        };
        total = Some(total.unwrap_or(0).saturating_add(value));
    }
    total
}

/// One `name value` line of `/proc/vmstat`.
pub fn vmstat_value(text: &str, name: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let (key, value) = line.split_once(' ')?;
        (key == name).then(|| value.trim().parse().ok())?
    })
}

/// The soft limit on open files from `/proc/PID/limits`. `None` when it is unlimited.
pub fn max_open_files(limits: &str) -> Option<u64> {
    let line = limits
        .lines()
        .find_map(|line| line.strip_prefix("Max open files"))?;
    line.split_whitespace().next()?.parse().ok()
}

fn read_text(path: &Path) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let mut data = Vec::new();
    file.take(4 << 20).read_to_end(&mut data).ok()?;
    Some(String::from_utf8_lossy(&data).into_owned())
}

/// The first number in a file such as `/proc/sys/kernel/pid_max`.
fn read_number(path: &Path) -> Option<u64> {
    read_text(path)?.split_whitespace().next()?.parse().ok()
}

// ---- the walk over every process's open files -------------------------------------------

/// A process and how many of the files it may open it has open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcFds {
    pub pid: i32,
    pub name: String,
    pub open: u64,
    pub limit: u64,
}

/// The most bytes a process name has (the kernel's TASK_COMM_LEN, less its final NUL).
const COMM_BYTES: usize = 15;

/// A process's name as read from `/proc/PID/comm`, safe to put in a line of the tool's.
///
/// AIDEV-NOTE: a process sets its own name (prctl PR_SET_NAME), and the kernel takes any
/// bytes, line breaks included. The name is made safe HERE, once, so that the verdict
/// line, the table and anything added later cannot be given lines of the process's
/// making. Only the newline that ends the file is dropped; one inside the name is
/// shown as `\n`.
pub fn process_name(comm: &str) -> String {
    let name = comm.strip_suffix('\n').unwrap_or(comm);
    let mut end = name.len().min(COMM_BYTES);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    one_line_cell(name.get(..end).unwrap_or(""))
}

/// What the walk found.
#[derive(Debug, Default)]
pub struct Scan {
    /// For each user (real uid): inotify watches and inotify instances.
    pub inotify: HashMap<u32, (u64, u64)>,
    /// Every process that has files open and a limit on them.
    pub processes: Vec<ProcFds>,
    /// Processes whose open files could be listed.
    pub examined: usize,
    /// Processes whose open files this server may not list (it is not root).
    pub unreadable: usize,
    /// The walk reached one of its bounds before the last process.
    pub cut_short: bool,
}

/// The inotify watches of one descriptor: the `inotify wd:` lines of its fdinfo file.
fn count_watches(fdinfo: &Path) -> u64 {
    let Ok(file) = std::fs::File::open(fdinfo) else {
        return 0;
    };
    let mut watches = 0u64;
    for line in BufReader::new(file).split(b'\n').take(MAX_FDINFO_LINES) {
        let Ok(line) = line else {
            break;
        };
        if line.starts_with(b"inotify wd:") {
            watches += 1;
        }
    }
    watches
}

/// Walks every process's open files once, for two things: who holds inotify watches and
/// instances, and which processes are near their limit on open files.
///
/// AIDEV-NOTE: an inotify instance that forked processes share is counted once for each
/// process holding it; the kernel offers no cheap way to tell that two descriptors are
/// the same instance. So a figure here can be too high, never too low, for the
/// processes that could be read.
pub fn scan_processes(proc: &Path, bounds: ScanBounds) -> Scan {
    let started = Instant::now();
    let mut scan = Scan::default();
    let mut pids: Vec<i32> = match std::fs::read_dir(proc) {
        Ok(entries) => entries
            .flatten()
            .filter_map(|entry| entry.file_name().to_str()?.parse::<i32>().ok())
            .collect(),
        Err(_) => return scan,
    };
    pids.sort_unstable();
    let mut fds_seen = 0usize;
    'processes: for pid in pids {
        let dir = proc.join(pid.to_string());
        let entries = match std::fs::read_dir(dir.join("fd")) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                scan.unreadable += 1;
                continue;
            }
            // it has ended since /proc was listed
            Err(_) => continue,
        };
        let (mut open, mut watches, mut instances) = (0u64, 0u64, 0u64);
        for entry in entries.flatten() {
            if fds_seen >= bounds.max_fds || started.elapsed() >= bounds.max_time {
                scan.cut_short = true;
                break 'processes;
            }
            fds_seen += 1;
            open += 1;
            let Ok(target) = std::fs::read_link(entry.path()) else {
                continue;
            };
            if target.as_os_str() == "anon_inode:inotify" {
                instances += 1;
                watches += count_watches(&dir.join("fdinfo").join(entry.file_name()));
            }
        }
        scan.examined += 1;
        if instances > 0
            && let Some(uid) = read_text(&dir.join("status")).and_then(|text| parse_uid(&text))
        {
            let user = scan.inotify.entry(uid).or_default();
            user.0 = user.0.saturating_add(watches);
            user.1 = user.1.saturating_add(instances);
        }
        if open > 0
            && let Some(limit) =
                read_text(&dir.join("limits")).and_then(|text| max_open_files(&text))
        {
            let name = read_text(&dir.join("comm")).unwrap_or_default();
            scan.processes.push(ProcFds {
                pid,
                name: process_name(&name),
                open,
                limit,
            });
        }
    }
    scan
}

// ---- putting it together ----------------------------------------------------------------

/// How much of the check of every process's open files was done.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProcessCheck {
    /// Every process was examined.
    #[default]
    Whole,
    /// Some could not be read (the server is not root), or the walk was cut short.
    Part,
    /// None was examined.
    NotDone,
}

/// Everything the tool reports.
#[derive(Debug, Default)]
pub struct Report {
    pub rows: Vec<Row>,
    /// The processes nearest their limit on open files, nearest first.
    pub processes: Vec<ProcFds>,
    /// Counters that are not zero: each means a limit was hit since boot.
    pub hit: Vec<(&'static str, u64)>,
    pub notes: Vec<String>,
    pub process_check: ProcessCheck,
}

/// The counters that only move when a limit is hit, and what each one means.
const HIT_COUNTERS: [(&str, &str); 7] = [
    (
        "ListenOverflows",
        "connections turned away because a listening socket's queue was full \
         (the program's backlog, net.core.somaxconn)",
    ),
    (
        "ListenDrops",
        "incoming connections dropped at a listening socket",
    ),
    (
        "TCPAbortOnMemory",
        "connections aborted because TCP was out of memory (net.ipv4.tcp_mem)",
    ),
    (
        "conntrack drop",
        "packets dropped because the connection-tracking table was full",
    ),
    (
        "conntrack insert_failed",
        "connections that could not be added to the connection-tracking table",
    ),
    (
        "conntrack early_drop",
        "tracked connections thrown out early to make room (nf_conntrack_max)",
    ),
    ("oom_kill", "processes killed for lack of memory"),
];

/// Whether a mounted filesystem can run out of room in a way worth reporting.
///
/// AIDEV-NOTE: a read-only filesystem cannot fill up, and being full is its normal state
/// (an image, or the empty read-only tmpfs a container runtime mounts over /proc/acpi,
/// which is "100% of 1 inode"). A single file mounted over another (a container's
/// /etc/hostname) is not a place that fills either: it only repeats the figures of the
/// disk the file lives on.
fn worth_a_row(is_dir: bool, read_only: bool, blocks: u64) -> bool {
    is_dir && !read_only && blocks > 0
}

/// Space and inodes of the local filesystems among the mounts in `mountinfo`.
fn filesystem_rows(mountinfo: &str) -> Vec<Row> {
    let mut mounts = parse_mountinfo(mountinfo);
    mounts.sort_by(|a, b| a.point.cmp(&b.point));
    let mut seen = HashSet::new();
    let mut rows = Vec::new();
    for mount in &mounts {
        // As disk_usage: a network or user-space filesystem is not touched (statting one
        // whose server is gone never returns), and pseudo filesystems have no limit.
        if listing(mount, false, false) != Listing::Shown {
            continue;
        }
        let Ok(vfs) = rustix::fs::statvfs(mount.point.as_str()) else {
            continue;
        };
        let meta = std::fs::metadata(&mount.point).ok();
        let is_dir = meta.as_ref().is_some_and(|meta| meta.is_dir());
        let read_only = vfs.f_flag.contains(rustix::fs::StatVfsMountFlags::RDONLY);
        if !worth_a_row(is_dir, read_only, vfs.f_blocks) {
            continue;
        }
        let device = meta.map(|meta| meta.dev());
        if device.is_some_and(|device| !seen.insert(device)) {
            continue;
        }
        // as df does: used out of what an unprivileged user could use
        let used = vfs
            .f_blocks
            .saturating_sub(vfs.f_bfree)
            .saturating_mul(vfs.f_frsize);
        let avail = vfs.f_bavail.saturating_mul(vfs.f_frsize);
        rows.extend(Row::new(
            format!("space on {}", mount.point),
            used,
            used.saturating_add(avail),
            Unit::Bytes,
        ));
        rows.extend(Row::new(
            format!("inodes on {}", mount.point),
            vfs.f_files.saturating_sub(vfs.f_ffree),
            vfs.f_files,
            Unit::Count,
        ));
    }
    rows.sort_by_key(|row| std::cmp::Reverse(row.percent()));
    rows.truncate(MAX_FS_ROWS);
    rows
}

/// Reads everything. `proc` is /proc.
///
/// AIDEV-NOTE: `show_accounts` is whether the caller holds `user.view`. The inotify rows
/// say which user holds the most watches; an account name is user_list's to show, so
/// without that permission the user is given by number.
pub fn gather(proc: &Path, bounds: ScanBounds, show_accounts: bool) -> Report {
    let mut report = Report::default();
    let text = |name: &str| read_text(&proc.join(name));
    let number = |name: &str| read_number(&proc.join(name));
    let mut add = |name: String, used: Option<u64>, limit: Option<u64>, unit: Unit| {
        if let (Some(used), Some(limit)) = (used, limit) {
            report.rows.extend(Row::new(name, used, limit, unit));
        }
    };

    if let Some((used, max)) = text("sys/fs/file-nr").and_then(|t| parse_file_nr(&t)) {
        add(
            "open files, whole system (fs.file-max)".to_string(),
            Some(used),
            Some(max),
            Unit::Count,
        );
    }
    let tasks = text("loadavg").and_then(|t| parse_tasks(&t));
    add(
        "processes and threads (kernel.pid_max)".to_string(),
        tasks,
        number("sys/kernel/pid_max"),
        Unit::Count,
    );
    add(
        "processes and threads (kernel.threads-max)".to_string(),
        tasks,
        number("sys/kernel/threads-max"),
        Unit::Count,
    );
    add(
        "tracked connections (net.netfilter.nf_conntrack_max)".to_string(),
        number("sys/net/netfilter/nf_conntrack_count"),
        number("sys/net/netfilter/nf_conntrack_max"),
        Unit::Count,
    );
    add(
        "asynchronous I/O requests (fs.aio-max-nr)".to_string(),
        number("sys/fs/aio-nr"),
        number("sys/fs/aio-max-nr"),
        Unit::Count,
    );
    add(
        "ARP entries (net.ipv4.neigh.default.gc_thresh3)".to_string(),
        text("net/arp").map(|t| count_arp(&t)),
        number("sys/net/ipv4/neigh/default/gc_thresh3"),
        Unit::Count,
    );
    let sockets = text("net/sockstat")
        .map(|t| parse_sockstat(&t))
        .unwrap_or_default();
    add(
        "TCP buffer memory (net.ipv4.tcp_mem)".to_string(),
        sockets.mem_pages,
        text("sys/net/ipv4/tcp_mem").and_then(|t| tcp_mem_max(&t)),
        Unit::Pages,
    );
    add(
        "orphaned TCP sockets (net.ipv4.tcp_max_orphans)".to_string(),
        sockets.orphans,
        number("sys/net/ipv4/tcp_max_orphans"),
        Unit::Count,
    );
    // AIDEV-NOTE: no row for local (ephemeral) ports. The only cheap figure, the TCP
    // sockets in use, counts listeners and incoming connections too, which take no local
    // port: a busy server read as far over the limit. Counting outgoing connections
    // per destination would mean reading every socket.
    if let Some(meminfo) = text("meminfo") {
        let mem = parse_meminfo(&meminfo);
        let get = |key: &str| mem.get(key).copied();
        if let (Some(total), Some(available)) = (get("MemTotal"), get("MemAvailable")) {
            add(
                "memory".to_string(),
                Some(total.saturating_sub(available)),
                Some(total),
                Unit::Bytes,
            );
        }
        if let (Some(total), Some(free)) = (get("SwapTotal"), get("SwapFree")) {
            add(
                "swap".to_string(),
                Some(total.saturating_sub(free)),
                Some(total),
                Unit::Bytes,
            );
        }
    }

    let scan = scan_processes(proc, bounds);
    let mut names = Names::default();
    let mut user = |uid: u32| {
        if show_accounts {
            one_line_cell(names.user(uid))
        } else {
            format!("uid {uid}")
        }
    };
    let watches = scan
        .inotify
        .iter()
        .max_by_key(|(uid, used)| (used.0, **uid));
    if let Some((uid, used)) = watches {
        add(
            format!(
                "inotify watches of {}, the user with most (fs.inotify.max_user_watches)",
                user(*uid)
            ),
            Some(used.0),
            number("sys/fs/inotify/max_user_watches"),
            Unit::Count,
        );
    }
    let instances = scan
        .inotify
        .iter()
        .max_by_key(|(uid, used)| (used.1, **uid));
    if let Some((uid, used)) = instances {
        add(
            format!(
                "inotify instances of {}, the user with most (fs.inotify.max_user_instances)",
                user(*uid)
            ),
            Some(used.1),
            number("sys/fs/inotify/max_user_instances"),
            Unit::Count,
        );
    }
    if let Some(mountinfo) = text("self/mountinfo") {
        report.rows.extend(filesystem_rows(&mountinfo));
    }
    // Highest first; rows that tie keep the order above.
    report
        .rows
        .sort_by_key(|row| std::cmp::Reverse(row.percent()));

    let mut processes = scan.processes;
    processes.sort_by(|a, b| {
        // nearest its limit first: compare open/limit as fractions, without division
        let left = u128::from(a.open) * u128::from(b.limit);
        let right = u128::from(b.open) * u128::from(a.limit);
        right.cmp(&left).then(a.pid.cmp(&b.pid))
    });
    processes.truncate(TOP_PROCESSES);
    report.processes = processes;

    let netstat = text("net/netstat").unwrap_or_default();
    let conntrack = text("net/stat/nf_conntrack").unwrap_or_default();
    let vmstat = text("vmstat").unwrap_or_default();
    for (name, _) in HIT_COUNTERS {
        let value = match name.strip_prefix("conntrack ") {
            Some(column) => conntrack_stat(&conntrack, column),
            None if name == "oom_kill" => vmstat_value(&vmstat, name),
            None => tcp_ext(&netstat, name),
        };
        if let Some(value) = value.filter(|value| *value > 0) {
            report.hit.push((name, value));
        }
    }

    report.process_check = if scan.examined == 0 {
        ProcessCheck::NotDone
    } else if scan.cut_short || scan.unreadable > 0 {
        ProcessCheck::Part
    } else {
        ProcessCheck::Whole
    };
    if scan.cut_short {
        report.notes.push(format!(
            "[the walk over every process's open files was cut short after {} processes: \
             the inotify figures and the list of processes are from those only, and may be too low]",
            scan.examined
        ));
    }
    if scan.unreadable > 0 {
        report.notes.push(format!(
            "[the open files of {} processes could not be read (the server does not run as \
             root): the inotify figures and the list of processes cover the other {}]",
            scan.unreadable, scan.examined
        ));
    }
    report
}

/// The report as text. The processes are only shown to a caller who may list processes.
pub fn render(report: &Report, show_processes: bool, budget: usize) -> String {
    // What is above the mark, for the first line.
    let mut above: Vec<(u64, String)> = report
        .rows
        .iter()
        .filter(|row| row.percent() >= WARN_PERCENT)
        .map(|row| (row.percent(), format!("{} {}%", row.name, row.percent())))
        .collect();
    if show_processes {
        for process in &report.processes {
            let share = percent(process.open, process.limit);
            if share >= WARN_PERCENT {
                above.push((
                    share,
                    format!(
                        "open files of {} (pid {}) {share}%",
                        process.name, process.pid
                    ),
                ));
            }
        }
    }
    above.sort_by_key(|(share, _)| std::cmp::Reverse(*share));
    let mut text = if above.is_empty() {
        "Nothing is close to a limit.".to_string()
    } else {
        let named: Vec<&str> = above
            .iter()
            .take(NAMED_IN_VERDICT)
            .map(|(_, what)| what.as_str())
            .collect();
        let more = above.len().saturating_sub(named.len());
        let mut line = format!(
            "{} {} above {WARN_PERCENT}%: {}",
            above.len(),
            if above.len() == 1 {
                "limit is"
            } else {
                "limits are"
            },
            named.join("; ")
        );
        if more > 0 {
            line.push_str(&format!("; and {more} more"));
        }
        line.push('.');
        line
    };
    if !report.hit.is_empty() {
        text.push_str(&format!(
            " {} {} hit since boot (see the end).",
            report.hit.len(),
            if report.hit.len() == 1 {
                "limit was"
            } else {
                "limits were"
            }
        ));
    }
    // AIDEV-NOTE: a process at its limit on open files is the commonest of these
    // outages, so the first line never reads as an all-clear when processes were left
    // out of it (the caller may not list them) or could only be examined in part (the
    // server is not root, or the walk ran out of time). The notes at the end say why.
    match (show_processes, report.process_check) {
        (false, _) | (true, ProcessCheck::NotDone) => {
            text.push_str(" (open files per process not checked)");
        }
        (true, ProcessCheck::Part) => {
            text.push_str(" (open files per process checked only in part)");
        }
        (true, ProcessCheck::Whole) => {}
    }
    text.push_str("\n\n");

    let rows: Vec<Vec<String>> = report
        .rows
        .iter()
        .map(|row| {
            vec![
                mark(row.percent()).to_string(),
                row.name.clone(),
                amount(row.used, row.unit),
                amount(row.limit, row.unit),
                format!("{}%", row.percent()),
            ]
        })
        .collect();
    let table = format_table(
        &["", "RESOURCE", "USED", "LIMIT", "PERCENT"],
        &rows,
        &[false, false, true, true, true],
    );

    let mut tail = String::from("\nProcesses nearest their limit on open files:\n");
    if !show_processes {
        tail.push_str("[not shown: needs process.view]\n");
    } else if report.processes.is_empty() {
        tail.push_str("none could be examined\n");
    } else {
        let rows: Vec<Vec<String>> = report
            .processes
            .iter()
            .map(|process| {
                let share = percent(process.open, process.limit);
                vec![
                    mark(share).to_string(),
                    process.pid.to_string(),
                    process.name.clone(),
                    process.open.to_string(),
                    process.limit.to_string(),
                    format!("{share}%"),
                ]
            })
            .collect();
        tail.push_str(&format_table(
            &["", "PID", "NAME", "OPEN", "LIMIT", "PERCENT"],
            &rows,
            &[false, true, false, true, true, true],
        ));
    }
    tail.push_str("\nLimits that were hit since boot:\n");
    if report.hit.is_empty() {
        tail.push_str("none\n");
    }
    for (name, value) in &report.hit {
        let meaning = HIT_COUNTERS
            .iter()
            .find(|(counter, _)| counter == name)
            .map_or("", |(_, meaning)| meaning);
        tail.push_str(&format!("  {name}: {value}  ({meaning})\n"));
    }
    for note in &report.notes {
        tail.push_str(note);
        tail.push('\n');
    }

    // The table is what gives way if there is too much; it is sorted, so what is left
    // out is what is furthest from its limit.
    let room = budget.saturating_sub(text.len() + tail.len() + 80);
    let (kept, dropped) = keep_head(&table, room);
    text.push_str(&kept);
    if dropped > 0 {
        text.push_str(&format!(
            "[{dropped} more rows left out, all further from their limit]\n"
        ));
    }
    text.push_str(&tail);
    text
}

async fn limits_headroom(ctx: Ctx, _args: Args, proc: PathBuf) -> ToolResult {
    let auth = ctx.authorize(None)?;
    // AIDEV-NOTE: the list of processes names processes, which is process_list's to
    // show. It is included only for a caller who holds process.view for everything, so
    // that this tool never shows what a missing grant or a deny keeps back there.
    let show_processes = ctx.holds_read("process.view");
    // Likewise an account name is user_list's to show.
    let show_accounts = ctx.holds_read("user.view");
    let budget = ctx.output_budget();
    blocking(ctx.clone(), move || {
        let report = gather(&proc, SCAN_BOUNDS, show_accounts);
        auth.ok(render(&report, show_processes, budget))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::Host;
    use crate::tools::testing::{call, find, host, ok_text};
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;

    const WIDE: ScanBounds = ScanBounds {
        max_fds: 1_000_000,
        max_time: Duration::from_secs(60),
    };

    fn row(name: &str, used: u64, limit: u64) -> Row {
        Row::new(name, used, limit, Unit::Count).unwrap()
    }

    // ---- the kernel's files ---------------------------------------------------------

    #[test]
    fn a_percentage_is_rounded_down_and_marked_at_75_and_90() {
        assert_eq!(row("x", 0, 100).percent(), 0);
        assert_eq!(row("x", 749, 1000).percent(), 74);
        assert_eq!(row("x", 750, 1000).percent(), 75);
        assert_eq!(row("x", 899, 1000).percent(), 89);
        assert_eq!(row("x", 1000, 1000).percent(), 100);
        // more than the limit, and numbers too large to multiply naively
        assert_eq!(row("x", 300, 200).percent(), 150);
        assert_eq!(row("x", u64::MAX / 2, u64::MAX).percent(), 49);
        assert_eq!(mark(74), "");
        assert_eq!(mark(75), "!");
        assert_eq!(mark(89), "!");
        assert_eq!(mark(90), "!!");
        assert_eq!(mark(150), "!!");
        // a limit of zero is no limit to measure against
        assert_eq!(Row::new("x", 5, 0, Unit::Count), None);
    }

    #[test]
    fn file_nr_gives_handles_in_use_and_the_most_there_can_be() {
        assert_eq!(
            parse_file_nr("4800\t0\t9223372036854775807\n"),
            Some((4800, 9223372036854775807))
        );
        // old kernels report free handles in the middle
        assert_eq!(parse_file_nr("5000 200 65536\n"), Some((4800, 65536)));
        for bad in ["", "4800", "4800 0", "a b c"] {
            assert_eq!(parse_file_nr(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn loadavg_gives_the_number_of_processes_and_threads() {
        assert_eq!(parse_tasks("0.52 0.58 0.59 3/1234 56789\n"), Some(1234));
        for bad in [
            "",
            "0.52 0.58 0.59",
            "0.52 0.58 0.59 31234 5",
            "0.5 0.5 0.5 3/x 5",
        ] {
            assert_eq!(parse_tasks(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn sockstat_gives_tcp_sockets_orphans_and_memory() {
        let text = "sockets: used 512\nTCP: inuse 44 orphan 3 tw 12 alloc 60 mem 931\n\
                    UDP: inuse 9 mem 4\nFRAG: inuse 0 memory 0\n";
        assert_eq!(
            parse_sockstat(text),
            Sockstat {
                orphans: Some(3),
                mem_pages: Some(931),
            }
        );
        assert_eq!(parse_sockstat("sockets: used 1\n"), Sockstat::default());
        assert_eq!(parse_sockstat("TCP: inuse 4 orphan x").orphans, None);
        assert_eq!(tcp_mem_max("93141\t124189\t186282\n"), Some(186282));
        assert_eq!(tcp_mem_max("93141 124189"), None);
    }

    #[test]
    fn arp_entries_are_the_lines_after_the_heading() {
        let text = "IP address       HW type     Flags       HW address            Mask     Device\n\
                    10.0.0.1         0x1         0x2         52:54:00:12:34:56     *        eth0\n\
                    10.0.0.7         0x1         0x2         52:54:00:12:34:57     *        eth0\n";
        assert_eq!(count_arp(text), 2);
        assert_eq!(count_arp("IP address HW type\n"), 0);
        assert_eq!(count_arp(""), 0);
    }

    #[test]
    fn a_netstat_counter_is_found_by_name_under_its_group() {
        let text = "TcpExt: SyncookiesSent ListenOverflows ListenDrops TCPAbortOnMemory\n\
                    TcpExt: 0 12 15 2\n\
                    IpExt: InNoRoutes ListenOverflows\n\
                    IpExt: 7 999\n";
        assert_eq!(tcp_ext(text, "ListenOverflows"), Some(12));
        assert_eq!(tcp_ext(text, "ListenDrops"), Some(15));
        assert_eq!(tcp_ext(text, "TCPAbortOnMemory"), Some(2));
        assert_eq!(tcp_ext(text, "InNoRoutes"), None);
        assert_eq!(tcp_ext("TcpExt: A B\n", "A"), None);
        assert_eq!(tcp_ext("", "A"), None);
    }

    #[test]
    fn conntrack_counters_are_hexadecimal_and_added_up_over_the_cpus() {
        let text = "entries  clashres found new invalid ignore delete delete_list insert insert_failed drop early_drop icmp_error  expect_new expect_create expect_delete search_restart\n\
                    000000a3  00000000 00000000 00000000 0000001f 00000000 00000000 00000000 00000000 00000002 0000000a 00000000 00000000  00000000 00000000 00000000 00000001\n\
                    000000a3  00000000 00000000 00000000 00000004 00000000 00000000 00000000 00000000 00000001 00000010 00000003 00000000  00000000 00000000 00000000 00000000\n";
        assert_eq!(conntrack_stat(text, "insert_failed"), Some(3));
        assert_eq!(conntrack_stat(text, "drop"), Some(26));
        assert_eq!(conntrack_stat(text, "early_drop"), Some(3));
        assert_eq!(conntrack_stat(text, "no_such_column"), None);
        assert_eq!(conntrack_stat("entries drop\n", "drop"), None);
        assert_eq!(conntrack_stat("", "drop"), None);
    }

    #[test]
    fn a_vmstat_value_is_found_by_its_exact_name() {
        let text = "nr_free_pages 12345\noom_kill 3\noom_kill_extra 99\n";
        assert_eq!(vmstat_value(text, "oom_kill"), Some(3));
        assert_eq!(vmstat_value(text, "oom"), None);
        assert_eq!(vmstat_value("oom_kill x\n", "oom_kill"), None);
    }

    #[test]
    fn the_open_file_limit_is_the_soft_one() {
        let limits = "Limit                     Soft Limit           Hard Limit           Units     \n\
                      Max cpu time              unlimited            unlimited            seconds   \n\
                      Max open files            1024                 524288               files     \n";
        assert_eq!(max_open_files(limits), Some(1024));
        assert_eq!(
            max_open_files(
                "Max open files            unlimited            unlimited            files\n"
            ),
            None
        );
        assert_eq!(
            max_open_files("Max cpu time unlimited unlimited seconds\n"),
            None
        );
    }

    // ---- a stand-in for /proc -------------------------------------------------------

    fn put(root: &Path, name: &str, content: &str) {
        let path = root.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    /// A process in the stand-in /proc: `fds` are what its descriptors point at, and a
    /// descriptor pointing at an inotify instance gets `watches` watches.
    fn process(
        root: &Path,
        pid: i32,
        uid: u32,
        name: &str,
        limit: &str,
        fds: &[&str],
        watches: usize,
    ) {
        let dir = root.join(pid.to_string());
        std::fs::create_dir_all(dir.join("fd")).unwrap();
        std::fs::create_dir_all(dir.join("fdinfo")).unwrap();
        put(
            root,
            &format!("{pid}/status"),
            &format!("Name:\t{name}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"),
        );
        put(root, &format!("{pid}/comm"), &format!("{name}\n"));
        put(
            root,
            &format!("{pid}/limits"),
            &format!(
                "Limit                     Soft Limit           Hard Limit           Units     \nMax open files            {limit}                 524288               files     \n"
            ),
        );
        for (number, target) in fds.iter().enumerate() {
            std::os::unix::fs::symlink(target, dir.join("fd").join(number.to_string())).unwrap();
            let mut info = "pos:\t0\nflags:\t02000000\nmnt_id:\t15\nino:\t1057\n".to_string();
            if *target == "anon_inode:inotify" {
                for wd in 1..=watches {
                    info.push_str(&format!(
                        "inotify wd:{wd} ino:{wd:x} sdev:800001 mask:fce ignored_mask:0 fhandle-bytes:8 fhandle-type:1 f_handle:0000\n"
                    ));
                }
            }
            put(root, &format!("{pid}/fdinfo/{number}"), &info);
        }
    }

    /// A stand-in /proc for a small, healthy machine.
    fn healthy() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        put(root, "sys/fs/file-nr", "4800\t0\t100000\n");
        put(root, "loadavg", "0.10 0.20 0.30 1/800 4242\n");
        put(root, "sys/kernel/pid_max", "4194304\n");
        put(root, "sys/kernel/threads-max", "126000\n");
        put(root, "sys/fs/aio-nr", "0\n");
        put(root, "sys/fs/aio-max-nr", "65536\n");
        put(root, "sys/fs/inotify/max_user_watches", "1000\n");
        put(root, "sys/fs/inotify/max_user_instances", "128\n");
        put(
            root,
            "net/arp",
            "IP address HW type Flags HW address Mask Device\n10.0.0.1 0x1 0x2 52:54:00:12:34:56 * eth0\n",
        );
        put(root, "sys/net/ipv4/neigh/default/gc_thresh3", "1024\n");
        put(
            root,
            "net/sockstat",
            "sockets: used 512\nTCP: inuse 44 orphan 3 tw 12 alloc 60 mem 931\n",
        );
        put(root, "sys/net/ipv4/tcp_mem", "93141\t124189\t186282\n");
        put(root, "sys/net/ipv4/tcp_max_orphans", "65536\n");
        put(root, "sys/net/ipv4/ip_local_port_range", "32768\t60999\n");
        put(
            root,
            "meminfo",
            "MemTotal:       16000000 kB\nMemAvailable:   12000000 kB\nSwapTotal:       2000000 kB\nSwapFree:        2000000 kB\n",
        );
        put(
            root,
            "net/netstat",
            "TcpExt: ListenOverflows ListenDrops TCPAbortOnMemory\nTcpExt: 0 0 0\n",
        );
        put(root, "vmstat", "oom_kill 0\n");
        process(
            root,
            100,
            0,
            "systemd",
            "1024",
            &["/dev/null", "socket:[1]", "anon_inode:inotify"],
            40,
        );
        process(
            root,
            200,
            33,
            "nginx",
            "1024",
            &["/dev/null", "/var/log/nginx/access.log"],
            0,
        );
        dir
    }

    fn find_row<'a>(report: &'a Report, start: &str) -> &'a Row {
        report
            .rows
            .iter()
            .find(|row| row.name.starts_with(start))
            .unwrap_or_else(|| panic!("no row starting {start:?} in {:?}", report.rows))
    }

    #[test]
    fn every_limit_is_read_from_proc() {
        let proc = healthy();
        let report = gather(proc.path(), WIDE, true);
        let used = |start: &str| {
            let row = find_row(&report, start);
            (row.used, row.limit, row.unit)
        };
        assert_eq!(
            used("open files, whole system"),
            (4800, 100000, Unit::Count)
        );
        assert_eq!(
            used("processes and threads (kernel.pid_max)"),
            (800, 4194304, Unit::Count)
        );
        assert_eq!(
            used("processes and threads (kernel.threads-max)"),
            (800, 126000, Unit::Count)
        );
        assert_eq!(used("asynchronous I/O"), (0, 65536, Unit::Count));
        assert_eq!(used("ARP entries"), (1, 1024, Unit::Count));
        assert_eq!(used("TCP buffer memory"), (931, 186282, Unit::Pages));
        assert_eq!(used("orphaned TCP sockets"), (3, 65536, Unit::Count));
        // AIDEV-NOTE: there is no "local ports" row. The kernel's count of TCP sockets in
        // use includes listeners and incoming connections, which take no local port, so
        // on a busy server it read as "141% of the port range" and headed the verdict.
        assert!(
            !report
                .rows
                .iter()
                .any(|row| row.name.contains("local port")),
            "{:?}",
            report.rows
        );
        assert_eq!(
            used("memory"),
            (4_000_000 * 1024, 16_000_000 * 1024, Unit::Bytes)
        );
        assert_eq!(used("swap"), (0, 2_000_000 * 1024, Unit::Bytes));
        assert_eq!(used("inotify watches of root"), (40, 1000, Unit::Count));
        assert_eq!(used("inotify instances of root"), (1, 128, Unit::Count));
        // conntrack is not loaded on this machine: no row, and no complaint
        assert!(
            !report
                .rows
                .iter()
                .any(|row| row.name.contains("tracked connections"))
        );
        assert!(report.hit.is_empty(), "{:?}", report.hit);
        assert!(report.notes.is_empty(), "{:?}", report.notes);
        // highest first
        let shares: Vec<u64> = report.rows.iter().map(Row::percent).collect();
        let mut sorted = shares.clone();
        sorted.sort_by(|a, b| b.cmp(a));
        assert_eq!(shares, sorted);
    }

    #[test]
    fn conntrack_and_the_counters_of_limits_hit_are_reported_when_present() {
        let proc = healthy();
        let root = proc.path();
        put(root, "sys/net/netfilter/nf_conntrack_count", "243000\n");
        put(root, "sys/net/netfilter/nf_conntrack_max", "262144\n");
        put(
            root,
            "net/netstat",
            "TcpExt: ListenOverflows ListenDrops TCPAbortOnMemory\nTcpExt: 12 15 0\n",
        );
        put(
            root,
            "net/stat/nf_conntrack",
            "entries insert_failed drop early_drop\n000000a3 00000001 0000000a 00000000\n000000a3 00000001 00000000 00000000\n",
        );
        put(root, "vmstat", "oom_kill 2\n");
        let report = gather(root, WIDE, true);
        let row = find_row(&report, "tracked connections");
        assert_eq!((row.used, row.limit, row.percent()), (243000, 262144, 92));
        assert_eq!(report.rows[0].name, row.name, "the fullest comes first");
        assert_eq!(
            report.hit,
            [
                ("ListenOverflows", 12),
                ("ListenDrops", 15),
                ("conntrack drop", 10),
                ("conntrack insert_failed", 2),
                ("oom_kill", 2),
            ]
        );
    }

    #[test]
    fn inotify_use_is_added_up_per_user_and_the_busiest_is_shown() {
        let proc = healthy();
        let root = proc.path();
        // uid 33 holds two instances in two processes, with 700 + 150 watches
        process(
            root,
            300,
            33,
            "node",
            "4096",
            &["anon_inode:inotify", "/dev/null"],
            700,
        );
        process(
            root,
            301,
            33,
            "node",
            "4096",
            &["/dev/null", "anon_inode:inotify", "anon_inode:[eventpoll]"],
            150,
        );
        let scan = scan_processes(root, WIDE);
        assert_eq!(scan.inotify.get(&33), Some(&(850, 2)));
        assert_eq!(scan.inotify.get(&0), Some(&(40, 1)));
        assert_eq!(scan.examined, 4);
        assert!(!scan.cut_short);
        let report = gather(root, WIDE, true);
        let watches = report
            .rows
            .iter()
            .find(|row| row.name.starts_with("inotify watches of "))
            .unwrap();
        assert_eq!(
            (watches.used, watches.limit, watches.percent()),
            (850, 1000, 85)
        );
        assert!(!watches.name.contains("root"), "{}", watches.name);
        let instances = report
            .rows
            .iter()
            .find(|row| row.name.starts_with("inotify instances of "))
            .unwrap();
        assert_eq!((instances.used, instances.limit), (2, 128));
    }

    #[test]
    fn the_processes_nearest_their_open_file_limit_come_first() {
        let proc = healthy();
        let root = proc.path();
        let many: Vec<&str> = vec!["/dev/null"; 60];
        process(root, 400, 33, "leaky", "64", &many, 0);
        process(root, 401, 33, "roomy", "100000", &many, 0);
        process(root, 402, 33, "free", "unlimited", &many, 0);
        // a kernel thread has nothing open
        process(root, 2, 0, "kthreadd", "1024", &[], 0);
        let report = gather(root, WIDE, true);
        assert_eq!(
            report.processes[0],
            ProcFds {
                pid: 400,
                name: "leaky".to_string(),
                open: 60,
                limit: 64,
            }
        );
        assert!(report.processes.len() <= 5);
        let names: Vec<&str> = report.processes.iter().map(|p| p.name.as_str()).collect();
        assert!(
            !names.contains(&"free"),
            "no limit, nothing to be near: {names:?}"
        );
        assert!(!names.contains(&"kthreadd"), "{names:?}");
        // roomy has as many open as leaky but is far from its limit: it comes later
        let at = |name: &str| names.iter().position(|n| *n == name);
        assert!(at("roomy").is_none_or(|roomy| roomy > 0));
    }

    #[test]
    fn the_walk_stops_at_its_bound_and_says_so() {
        let proc = healthy();
        let root = proc.path();
        let many: Vec<&str> = vec!["/dev/null"; 50];
        for pid in 500..520 {
            process(root, pid, 33, "worker", "1024", &many, 0);
        }
        let bounds = ScanBounds {
            max_fds: 120,
            max_time: Duration::from_secs(60),
        };
        let scan = scan_processes(root, bounds);
        assert!(scan.cut_short);
        assert!(scan.examined < 22, "{}", scan.examined);
        let report = gather(root, bounds, true);
        assert!(
            report.notes.iter().any(|note| note.contains("cut short")),
            "{:?}",
            report.notes
        );
        // no time at all: nothing is examined, and that is said too
        let none = ScanBounds {
            max_fds: 1_000_000,
            max_time: Duration::ZERO,
        };
        assert!(scan_processes(root, none).cut_short);
    }

    #[test]
    fn processes_that_cannot_be_read_are_counted_not_guessed() {
        if rustix::process::geteuid().is_root() {
            return; // root can read everything: nothing to test
        }
        let proc = healthy();
        let root = proc.path();
        process(root, 600, 0, "sshd", "1024", &["/dev/null"], 0);
        let locked = root.join("600/fd");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let scan = scan_processes(root, WIDE);
        let report = gather(root, WIDE, true);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(scan.unreadable, 1);
        assert_eq!(scan.examined, 2);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("1 processes could not be read")),
            "{:?}",
            report.notes
        );
    }

    #[test]
    fn a_machine_with_nothing_readable_gives_an_empty_report_not_an_error() {
        let empty = tempfile::tempdir().unwrap();
        let report = gather(empty.path(), WIDE, true);
        assert!(report.rows.is_empty() && report.processes.is_empty() && report.hit.is_empty());
        let text = render(&report, true, 60_000);
        assert!(text.starts_with("Nothing is close to a limit."), "{text}");
        let missing = gather(&empty.path().join("nowhere"), WIDE, true);
        assert!(missing.rows.is_empty());
    }

    // ---- how it is shown ------------------------------------------------------------

    fn sample() -> Report {
        Report {
            rows: vec![
                row(
                    "tracked connections (net.netfilter.nf_conntrack_max)",
                    243000,
                    262144,
                ),
                row(
                    "inotify watches of www-data, the user with most (fs.inotify.max_user_watches)",
                    850,
                    1000,
                ),
                Row::new("memory", 4 << 30, 16 << 30, Unit::Bytes).unwrap(),
                Row::new(
                    "TCP buffer memory (net.ipv4.tcp_mem)",
                    931,
                    186282,
                    Unit::Pages,
                )
                .unwrap(),
            ],
            processes: vec![
                ProcFds {
                    pid: 400,
                    name: "leaky".to_string(),
                    open: 60,
                    limit: 64,
                },
                ProcFds {
                    pid: 200,
                    name: "nginx".to_string(),
                    open: 2,
                    limit: 1024,
                },
            ],
            hit: vec![("ListenOverflows", 12), ("oom_kill", 2)],
            notes: vec!["[a note]".to_string()],
            process_check: ProcessCheck::Whole,
        }
    }

    /// AIDEV-NOTE: a process at 99% of its open files is the classic outage. The first
    /// line must not read as an all-clear when that was not looked at, or only in part.
    #[test]
    fn the_first_line_says_when_processes_were_not_checked_or_only_in_part() {
        let mut calm = sample();
        calm.rows.clear();
        calm.processes.clear();
        calm.hit.clear();
        let first = |report: &Report, show: bool| {
            render(report, show, 60_000)
                .lines()
                .next()
                .unwrap()
                .to_string()
        };
        // checked in full: nothing to add
        assert_eq!(first(&calm, true), "Nothing is close to a limit.");
        // the caller may not see processes: they were left out of the verdict
        assert_eq!(
            first(&calm, false),
            "Nothing is close to a limit. (open files per process not checked)"
        );
        // not every process could be read
        calm.process_check = ProcessCheck::Part;
        assert_eq!(
            first(&calm, true),
            "Nothing is close to a limit. (open files per process checked only in part)"
        );
        calm.process_check = ProcessCheck::NotDone;
        assert_eq!(
            first(&calm, true),
            "Nothing is close to a limit. (open files per process not checked)"
        );
        // and the same when something IS above the mark
        let mut busy = sample();
        busy.process_check = ProcessCheck::Part;
        let line = first(&busy, true);
        assert!(line.starts_with("3 limits are above 75%: "), "{line}");
        assert!(
            line.ends_with(
                "2 limits were hit since boot (see the end). \
                 (open files per process checked only in part)"
            ),
            "{line}"
        );
    }

    #[test]
    fn the_walk_says_how_much_of_the_processes_it_covered() {
        let proc = healthy();
        let root = proc.path();
        assert_eq!(gather(root, WIDE, true).process_check, ProcessCheck::Whole);
        // room for the first process's three descriptors, not for the second process
        let bounds = ScanBounds {
            max_fds: 4,
            max_time: Duration::from_secs(60),
        };
        assert_eq!(gather(root, bounds, true).process_check, ProcessCheck::Part);
        // no room even for the first: nothing was examined
        let bounds = ScanBounds {
            max_fds: 2,
            max_time: Duration::from_secs(60),
        };
        assert_eq!(
            gather(root, bounds, true).process_check,
            ProcessCheck::NotDone
        );
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(
            gather(empty.path(), WIDE, true).process_check,
            ProcessCheck::NotDone
        );
    }

    /// AIDEV-NOTE: a process chooses its own name (prctl PR_SET_NAME), line breaks
    /// included. Unescaped, a name such as "x\nPROBLEM: all ok" put lines of its own
    /// into the verdict.
    #[test]
    fn a_process_name_cannot_start_a_line_of_its_own() {
        let proc = healthy();
        let root = proc.path();
        let many: Vec<&str> = vec!["/dev/null"; 19];
        process(root, 777, 33, "x\nPROBLEM: ok", "20", &many, 0);
        let report = gather(root, WIDE, true);
        let forged = &report.processes[0];
        assert_eq!(forged.pid, 777);
        assert_eq!(forged.name, "x\\nPROBLEM: ok");
        let text = render(&report, true, 60_000);
        let mut lines = text.lines();
        let first = lines.next().unwrap();
        assert!(
            first.contains("open files of x\\nPROBLEM: ok (pid 777) 95%"),
            "{first}"
        );
        assert_eq!(lines.next(), Some(""), "the verdict is one line");
        assert!(
            !text.lines().any(|line| line.starts_with("PROBLEM")),
            "{text}"
        );
    }

    #[test]
    fn a_process_name_is_cut_to_the_length_the_kernel_allows() {
        assert_eq!(process_name("nginx\n"), "nginx");
        assert_eq!(
            process_name("abcdefghijklmnopqrstuvwxyz\n"),
            "abcdefghijklmno"
        );
        // cut on a character boundary, never inside one
        assert_eq!(
            process_name("aaaaaaaaaaaaaa\u{e9}\u{e9}\n"),
            "aaaaaaaaaaaaaa"
        );
        assert_eq!(process_name("a\tb\rc\n"), "a\\tb\\rc");
        assert_eq!(process_name(""), "");
    }

    /// AIDEV-NOTE: an account name belongs to user.view. The inotify rows say WHICH user
    /// holds the most watches; without that permission they say it by number.
    #[test]
    fn the_inotify_rows_name_an_account_only_when_accounts_may_be_shown() {
        let proc = healthy();
        let root = proc.path();
        let named = gather(root, WIDE, true);
        assert!(
            named
                .rows
                .iter()
                .any(|row| row.name.starts_with("inotify watches of root,")),
            "{:?}",
            named.rows
        );
        let numbered = gather(root, WIDE, false);
        let names: Vec<&str> = numbered.rows.iter().map(|row| row.name.as_str()).collect();
        assert!(
            names
                .iter()
                .any(|name| name.starts_with("inotify watches of uid 0,")),
            "{names:?}"
        );
        assert!(
            names
                .iter()
                .any(|name| name.starts_with("inotify instances of uid 0,")),
            "{names:?}"
        );
        assert!(!names.iter().any(|name| name.contains("root")), "{names:?}");
    }

    #[test]
    fn the_first_line_names_what_is_above_75_percent() {
        let text = render(&sample(), true, 60_000);
        let first = text.lines().next().unwrap();
        assert_eq!(
            first,
            "3 limits are above 75%: open files of leaky (pid 400) 93%; \
             tracked connections (net.netfilter.nf_conntrack_max) 92%; \
             inotify watches of www-data, the user with most (fs.inotify.max_user_watches) 85%. \
             2 limits were hit since boot (see the end)."
        );
        let mut calm = sample();
        calm.rows.clear();
        calm.processes.clear();
        calm.hit.clear();
        assert!(render(&calm, true, 60_000).starts_with("Nothing is close to a limit.\n"));
        let mut one = sample();
        one.rows.truncate(1);
        one.processes.clear();
        one.hit.truncate(1);
        let text = render(&one, true, 60_000);
        assert!(
            text.starts_with("1 limit is above 75%: tracked connections (net.netfilter.nf_conntrack_max) 92%. 1 limit was hit since boot (see the end).\n"),
            "{text}"
        );
    }

    #[test]
    fn the_table_marks_each_row_and_shows_amounts_in_their_own_units() {
        let text = render(&sample(), true, 60_000);
        let line = |needle: &str| {
            text.lines()
                .find(|line| line.contains(needle))
                .unwrap_or_else(|| panic!("no line with {needle:?} in:\n{text}"))
                .to_string()
        };
        assert!(
            text.contains("RESOURCE") && text.contains("USED") && text.contains("PERCENT"),
            "{text}"
        );
        let conntrack = line("tracked connections (net.netfilter.nf_conntrack_max)  ");
        assert!(conntrack.starts_with("!!  "), "{conntrack}");
        let fields: Vec<&str> = conntrack.split_whitespace().collect();
        assert_eq!(fields[fields.len() - 3..], ["243000", "262144", "92%"]);
        assert!(
            line("inotify watches of www-data, the user with most (fs.inotify.max_user_watches)  ")
                .starts_with("!   ")
        );
        let memory = line("memory  ");
        assert!(memory.starts_with("    memory"), "{memory:?}");
        assert!(
            memory.contains("4.0 GiB") && memory.contains("16.0 GiB") && memory.ends_with("25%"),
            "{memory:?}"
        );
        assert!(line("TCP buffer memory").contains("931 pages"), "{text}");
        // no line ends in spaces
        assert!(text.lines().all(|line| line == line.trim_end()), "{text:?}");
    }

    #[test]
    fn processes_are_shown_only_to_a_caller_who_may_list_processes() {
        let shown = render(&sample(), true, 60_000);
        assert!(shown.contains("leaky"), "{shown}");
        assert!(
            shown.contains("Processes nearest their limit on open files:"),
            "{shown}"
        );
        let hidden = render(&sample(), false, 60_000);
        assert!(
            !hidden.contains("leaky") && !hidden.contains("nginx"),
            "{hidden}"
        );
        assert!(
            hidden.contains("[not shown: needs process.view]"),
            "{hidden}"
        );
        // and the first line does not give a process away either
        assert!(
            hidden.starts_with("2 limits are above 75%: tracked connections"),
            "{hidden}"
        );
    }

    #[test]
    fn limits_that_were_hit_are_listed_with_what_they_mean() {
        let text = render(&sample(), true, 60_000);
        assert!(
            text.contains(
                "Limits that were hit since boot:\n  ListenOverflows: 12  (connections turned away"
            ),
            "{text}"
        );
        assert!(
            text.contains("  oom_kill: 2  (processes killed for lack of memory)"),
            "{text}"
        );
        assert!(text.ends_with("[a note]\n"), "{text}");
        let mut calm = sample();
        calm.hit.clear();
        assert!(render(&calm, true, 60_000).contains("Limits that were hit since boot:\nnone\n"));
    }

    #[test]
    fn a_long_table_gives_way_from_its_far_end() {
        let mut report = sample();
        report.rows = (0..400u64)
            .map(|n| row(&format!("space on /srv/volume{n:03}"), 400 - n, 1000))
            .collect();
        let text = render(&report, true, 3000);
        assert!(text.len() <= 3000, "{}", text.len());
        assert!(text.contains("space on /srv/volume000"), "{text}");
        assert!(!text.contains("space on /srv/volume399"), "{text}");
        assert!(
            text.contains("more rows left out, all further from their limit]"),
            "{text}"
        );
        // what comes after the table is still there
        assert!(text.contains("Limits that were hit since boot:"), "{text}");
        assert!(text.ends_with("[a note]\n"), "{text}");
    }

    // ---- the tool -------------------------------------------------------------------

    fn fixture() -> Arc<Host> {
        host(
            r#"
[roles.reader]
allow = ["@read"]
[roles.system]
allow = ["system.view"]
[roles.other]
allow = ["process.view"]
[unix_users.rita]
roles = ["reader"]
[unix_users.sid]
roles = ["system"]
[unix_users.olga]
roles = ["other"]
"#,
        )
        .0
    }

    #[tokio::test]
    async fn limits_headroom_reports_a_stand_in_machine() {
        let proc = healthy();
        process(
            proc.path(),
            400,
            33,
            "leaky",
            "64",
            &vec!["/dev/null"; 60],
            0,
        );
        let tool = find(tools_at(proc.path().to_path_buf()), "limits_headroom");
        let text = ok_text(call(&fixture(), "rita", &tool, json!({})).await);
        assert!(
            text.starts_with("1 limit is above 75%: open files of leaky (pid 400) 93%.\n"),
            "{text}"
        );
        assert!(
            text.contains("open files, whole system (fs.file-max)"),
            "{text}"
        );
        // sid may see the system but not list processes
        assert!(text.contains("inotify watches of root,"), "{text}");
        let text = ok_text(call(&fixture(), "sid", &tool, json!({})).await);
        assert!(
            text.starts_with("Nothing is close to a limit. (open files per process not checked)\n"),
            "{text}"
        );
        assert!(!text.contains("leaky"), "{text}");
        assert!(text.contains("[not shown: needs process.view]"), "{text}");
        // sid holds neither process.view nor user.view: no account name either
        assert!(text.contains("inotify watches of uid 0,"), "{text}");
        assert!(!text.contains("of root"), "{text}");
    }

    #[tokio::test]
    async fn limits_headroom_needs_system_view() {
        let proc = healthy();
        let tool = find(tools_at(proc.path().to_path_buf()), "limits_headroom");
        let result = call(&fixture(), "olga", &tool, json!({})).await;
        assert!(
            matches!(result, Err(crate::tools::ToolError::Denied(_))),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn limits_headroom_works_on_this_machine() {
        let tool = find(tools(), "limits_headroom");
        assert_eq!(
            (tool.access, tool.permission.as_str()),
            (Access::Read, "system.view")
        );
        let text = ok_text(call(&fixture(), "rita", &tool, json!({})).await);
        let first = text.lines().next().unwrap();
        assert!(
            first.starts_with("Nothing is close to a limit.") || first.contains("above 75%"),
            "{first}"
        );
        assert!(
            text.contains("open files, whole system (fs.file-max)"),
            "{text}"
        );
        assert!(
            text.contains("processes and threads (kernel.pid_max)"),
            "{text}"
        );
        assert!(text.contains("memory"), "{text}");
        assert!(text.contains("Limits that were hit since boot:"), "{text}");
    }
    /// AIDEV-NOTE: found in a container: a read-only tmpfs that masks /proc/acpi showed
    /// as "inodes 100%", and the file that is bind-mounted over /etc/hostname showed the
    /// host disk's figures a second time.
    #[test]
    fn a_read_only_filesystem_or_a_mounted_file_gets_no_row() {
        // a directory on a writable filesystem with blocks: worth a row
        assert!(worth_a_row(true, false, 1000));
        // read-only: it cannot fill up, and full is its normal state
        assert!(!worth_a_row(true, true, 1000));
        // a single file mounted over another: not a place that fills
        assert!(!worth_a_row(false, false, 1000));
        // no blocks at all: a pseudo filesystem
        assert!(!worth_a_row(true, false, 0));
    }

    #[test]
    fn a_file_used_as_a_mount_point_is_left_out_of_the_filesystem_rows() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("hostname");
        std::fs::write(&file, "web1\n").unwrap();
        let line = |point: &Path| {
            format!(
                "36 35 8:1 / {} rw,relatime shared:1 - ext4 /dev/sda1 rw\n",
                point.display()
            )
        };
        assert!(filesystem_rows(&line(&file)).is_empty());
        // the same line for the directory does give rows (space and inodes)
        let rows = filesystem_rows(&line(dir.path()));
        assert!(!rows.is_empty());
    }
}
