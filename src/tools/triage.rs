//! Triage: who is using the machine now, crashes, log summaries, one-call snapshot.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use regex::{Captures, Regex};
use serde_json::Value;

use super::args::{Args, Param};
use super::fs::Names;
use super::logs::LEVELS;
use super::process::{parse_stat, parse_uid, split_cmdline};
use super::service::normalize_unit;
use super::system::{Listing, listing, parse_meminfo, parse_mountinfo, percent_up};
use super::{
    Authorized, Ctx, Tool, ToolError, ToolResult, blocking, command_ok, command_text, format_table,
};
use crate::exec::CmdOutput;
use crate::policy::Access;
use crate::sanitize::{keep_head, keep_tail, redact_args, redact_text};
use crate::timefmt::{human_bytes, human_duration, now_secs, rfc3339_utc};

pub fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "resource_top",
            "Show what is using the machine right now. Samples for a few seconds, then lists \
             the processes that used the most CPU, memory or storage I/O in that time, the \
             system-wide CPU split (user, system, iowait, steal), pressure-stall figures, and \
             the busiest systemd units. Use it when a host is slow or loaded; process_list \
             shows lifetime averages instead.",
            Access::Read,
            "process.view",
            vec![
                Param::int("seconds", "How long to sample for (default 3)", 1, 10),
                Param::choice(
                    "sort",
                    "What to rank by (default cpu)",
                    &["cpu", "mem", "io"],
                ),
                Param::int(
                    "limit",
                    "Most processes, and most units, to show (default 15)",
                    1,
                    50,
                ),
            ],
            resource_top,
        ),
        Tool::new(
            "crash_events",
            "List recent crashes: processes the kernel killed for lack of memory (OOM kills), \
             segfaults and other faults the kernel reported, core dumps recorded by \
             systemd-coredump, and crash reports in /var/crash. Pass pid for the details of \
             one core dump. Use it to find out what died, and when.",
            Access::Read,
            "crash.view",
            vec![
                Param::int("hours", "How far back to look (default 24)", 1, 720),
                Param::int(
                    "pid",
                    "Show the details of the core dump of this process id instead of the lists",
                    1,
                    4_194_304,
                ),
            ],
            crash_events,
        ),
        Tool::new(
            "log_summary",
            "Summarise the systemd journal over a period instead of reading it: how many \
             entries each unit logged, how many were errors or warnings, and the most \
             repeated messages, each with an example (numbers, addresses and ids are ignored \
             when grouping). Use it first on a noisy host, then journal_query for the \
             entries themselves.",
            Access::Read,
            "journal.view",
            vec![
                Param::int("minutes", "How far back to look (default 60)", 1, 10_080),
                Param::str("unit", "Only entries of this unit, e.g. nginx.service").max_len(255),
                Param::choice(
                    "priority",
                    "Only entries at this severity or worse (default: all)",
                    &LEVELS,
                ),
                Param::int(
                    "entries",
                    "Most entries to examine, newest first (default 10000)",
                    100,
                    50_000,
                ),
                Param::int(
                    "top",
                    "How many sources and how many message groups to show (default 15)",
                    1,
                    50,
                ),
            ],
            log_summary,
        ),
        Tool::new(
            "incident_snapshot",
            "One bounded overview for triage, in the same shape on every host: load and \
             pressure, memory, nearly full filesystems, top processes by CPU and by memory, \
             failed units, recent journal errors, kernel kills and crashes, and network \
             interfaces with errors. A section the caller has no permission for is left out \
             and says which permission it needs. A good first call during an incident.",
            Access::Read,
            "system.view",
            vec![],
            incident_snapshot,
        ),
    ]
}

/// Where the kernel's and the system's files are. Tests point these at a temporary
/// directory.
#[derive(Clone, Debug)]
pub struct Roots {
    /// `/proc`
    pub proc: PathBuf,
    /// `/sys/fs/cgroup`
    pub cgroup: PathBuf,
    /// `/sys/class/net`
    pub net: PathBuf,
    /// `/var/crash`
    pub crash: PathBuf,
}

impl Default for Roots {
    fn default() -> Self {
        Roots {
            proc: PathBuf::from("/proc"),
            cgroup: PathBuf::from("/sys/fs/cgroup"),
            net: PathBuf::from("/sys/class/net"),
            crash: PathBuf::from("/var/crash"),
        }
    }
}

/// At most `max` bytes of a file. `None` if it cannot be read.
fn read_bytes(path: &Path, max: u64) -> Option<Vec<u8>> {
    let file = std::fs::File::open(path).ok()?;
    let mut data = Vec::new();
    file.take(max).read_to_end(&mut data).ok()?;
    Some(data)
}

/// At most `max` bytes of a file, as text. `None` if it cannot be read.
fn read_text(path: &Path, max: u64) -> Option<String> {
    read_bytes(path, max).map(|data| String::from_utf8_lossy(&data).into_owned())
}

/// Text on one line: every run of white space (line breaks included) becomes one space.
fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// `text` cut to `max` characters, with a mark if anything was cut.
fn cut(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut kept: String = text.chars().take(max).collect();
    kept.push_str("...");
    kept
}

/// What a `ToolError` says, for a note inside a larger result.
fn reason(error: ToolError) -> String {
    match error {
        ToolError::Denied(message) | ToolError::Invalid(message) | ToolError::Failed(message) => {
            one_line(&message)
        }
        ToolError::Internal(_) => "an internal error".to_string(),
    }
}

/// `text`, or as many whole lines from its start as fit in `budget`, with a note saying
/// how many were left out.
fn fit(text: &str, budget: usize) -> String {
    const NOTE_ROOM: usize = 80;
    let (kept, dropped) = keep_head(text, budget.saturating_sub(NOTE_ROOM));
    if dropped == 0 {
        return kept;
    }
    format!("{kept}[{dropped} more lines left out to fit the output limit]\n")
}

/// The note that stands in for a part that could not be produced.
fn unavailable(error: ToolError) -> String {
    format!("[not available: {}]\n", reason(error))
}

// ---- resource_top ---------------------------------------------------------------------

/// What is needed to turn the kernel's units into seconds and bytes.
#[derive(Clone, Copy, Debug)]
pub struct Clock {
    /// Clock ticks per second.
    pub ticks: f64,
    pub page_size: u64,
}

impl Clock {
    fn system() -> Clock {
        Clock {
            ticks: rustix::param::clock_ticks_per_second().max(1) as f64,
            page_size: rustix::param::page_size() as u64,
        }
    }
}

/// The system-wide CPU counters of /proc/stat, in clock ticks, grouped the way people
/// ask about them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuTimes {
    /// user + nice
    pub user: u64,
    /// system + irq + softirq
    pub system: u64,
    pub iowait: u64,
    pub steal: u64,
    pub idle: u64,
}

/// The `cpu` line (all CPUs together) of /proc/stat.
pub fn parse_cpu_times(stat: &str) -> Option<CpuTimes> {
    let line = stat.lines().find(|line| line.starts_with("cpu "))?;
    let fields: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .map_while(|field| field.parse().ok())
        .collect();
    // user nice system idle [iowait irq softirq steal ...]; the first four always exist.
    if fields.len() < 4 {
        return None;
    }
    let get = |index: usize| fields.get(index).copied().unwrap_or(0);
    Some(CpuTimes {
        user: get(0).saturating_add(get(1)),
        system: get(2).saturating_add(get(5)).saturating_add(get(6)),
        idle: get(3),
        iowait: get(4),
        steal: get(7),
    })
}

/// How many CPUs /proc/stat has a line for.
pub fn count_cpus(stat: &str) -> usize {
    stat.lines()
        .filter(|line| {
            line.strip_prefix("cpu")
                .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
        })
        .count()
}

/// How the CPUs' time between two samples was spent, in percent: user, system, iowait,
/// steal, idle. `None` if no time passed.
pub fn cpu_split(before: CpuTimes, after: CpuTimes) -> Option<[f64; 5]> {
    let spent = |now: u64, earlier: u64| now.saturating_sub(earlier) as f64;
    let parts = [
        spent(after.user, before.user),
        spent(after.system, before.system),
        spent(after.iowait, before.iowait),
        spent(after.steal, before.steal),
        spent(after.idle, before.idle),
    ];
    let total: f64 = parts.iter().sum();
    (total > 0.0).then(|| parts.map(|part| part * 100.0 / total))
}

/// Bytes read from and written to storage, from /proc/PID/io.
pub fn parse_io(text: &str) -> Option<(u64, u64)> {
    let field = |name: &str| -> Option<u64> {
        let value = text.lines().find_map(|line| line.strip_prefix(name))?;
        value.trim().parse().ok()
    };
    Some((field("read_bytes:")?, field("write_bytes:")?))
}

/// The 10-second averages of one /proc/pressure file: the `some` line's and the `full`
/// line's.
pub fn parse_pressure(text: &str) -> (Option<String>, Option<String>) {
    let avg10 = |kind: &str| -> Option<String> {
        let line = text
            .lines()
            .find(|line| line.split_whitespace().next() == Some(kind))?;
        let value = line
            .split_whitespace()
            .find_map(|field| field.strip_prefix("avg10="))?;
        let numeric = !value.is_empty() && value.chars().all(|c| c.is_ascii_digit() || c == '.');
        numeric.then(|| value.to_string())
    };
    (avg10("some"), avg10("full"))
}

/// Pressure-stall figures for CPU, memory and I/O on one line, if the kernel has them.
fn pressure_line(roots: &Roots) -> Option<String> {
    let mut parts = Vec::new();
    for name in ["cpu", "memory", "io"] {
        let Some(text) = read_text(&roots.proc.join("pressure").join(name), 4096) else {
            continue;
        };
        match parse_pressure(&text) {
            (Some(some), Some(full)) => parts.push(format!("{name} {some} (full {full})")),
            (Some(some), None) => parts.push(format!("{name} {some}")),
            _ => {}
        }
    }
    (!parts.is_empty()).then(|| parts.join(", "))
}

/// CPU time a cgroup has used, in microseconds, from its cpu.stat.
pub fn parse_usage_usec(text: &str) -> Option<u64> {
    let value = text
        .lines()
        .find_map(|line| line.strip_prefix("usage_usec "))?;
    value.trim().parse().ok()
}

/// One process at one moment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcSample {
    /// When it started, in ticks after boot: tells two processes with one pid apart.
    pub starttime: u64,
    pub comm: String,
    /// CPU time used so far, user and kernel, in ticks.
    pub cpu_ticks: u64,
    pub rss_pages: i64,
    /// Bytes read from and written to storage so far, where we may see them.
    pub io: Option<(u64, u64)>,
}

/// One systemd unit's cgroup at one moment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UnitSample {
    pub cpu_usec: Option<u64>,
    pub memory: Option<u64>,
}

/// The machine at one moment.
pub struct Snapshot {
    pub taken: Instant,
    pub procs: HashMap<i32, ProcSample>,
    pub cpu: Option<CpuTimes>,
    pub cpus: usize,
    /// `None` on a host without the unified (v2) cgroup hierarchy.
    pub units: Option<BTreeMap<String, UnitSample>>,
}

/// The slices whose services and scopes are reported: the system's own units, and
/// containers and virtual machines.
const UNIT_SLICES: [&str; 2] = ["system.slice", "machine.slice"];
const MAX_UNITS: usize = 5000;
const MAX_SLICE_DEPTH: usize = 4;

/// Reads the counters. Fast (two small files per process), but it is file I/O: call it
/// from a blocking job.
pub fn snapshot(roots: &Roots) -> Snapshot {
    let mut procs = HashMap::new();
    if let Ok(entries) = std::fs::read_dir(&roots.proc) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(pid) = name.to_str().and_then(|n| n.parse::<i32>().ok()) else {
                continue;
            };
            let dir = entry.path();
            // A process can exit between the listing and the read: skip it.
            let Some(stat) = read_text(&dir.join("stat"), 4096).and_then(|t| parse_stat(&t)) else {
                continue;
            };
            let io = read_text(&dir.join("io"), 4096).and_then(|t| parse_io(&t));
            procs.insert(
                pid,
                ProcSample {
                    starttime: stat.starttime,
                    comm: stat.comm,
                    cpu_ticks: stat.utime.saturating_add(stat.stime),
                    rss_pages: stat.rss_pages,
                    io,
                },
            );
        }
    }
    // The cpu lines come first in /proc/stat; the interrupt line after them can be long.
    let stat = read_text(&roots.proc.join("stat"), 1 << 20).unwrap_or_default();
    let unified = roots.cgroup.join("cgroup.controllers").exists();
    let units = unified.then(|| {
        let mut units = BTreeMap::new();
        for slice in UNIT_SLICES {
            read_units(&roots.cgroup.join(slice), 0, &mut units);
        }
        units
    });
    Snapshot {
        taken: Instant::now(),
        procs,
        cpu: parse_cpu_times(&stat),
        cpus: count_cpus(&stat),
        units,
    }
}

/// Collects the services and scopes under a slice. Instances of a template unit live in
/// a slice of their own inside it (postgresql@14-main.service is in
/// system-postgresql.slice), so nested slices are followed.
fn read_units(dir: &Path, depth: usize, units: &mut BTreeMap<String, UnitSample>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if units.len() >= MAX_UNITS {
            return;
        }
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        if name.ends_with(".service") || name.ends_with(".scope") {
            let cpu_usec =
                read_text(&path.join("cpu.stat"), 4096).and_then(|t| parse_usage_usec(&t));
            let memory =
                read_text(&path.join("memory.current"), 64).and_then(|t| t.trim().parse().ok());
            units.insert(name, UnitSample { cpu_usec, memory });
        } else if name.ends_with(".slice") && depth < MAX_SLICE_DEPTH {
            read_units(&path, depth + 1, units);
        }
    }
}

/// What one process did between two samples.
#[derive(Clone, Debug, PartialEq)]
pub struct TopRow {
    pub pid: i32,
    pub starttime: u64,
    pub comm: String,
    /// Share of ONE CPU used over the interval.
    pub cpu_percent: f64,
    pub rss_pages: i64,
    /// Bytes per second read from and written to storage; `None` where it cannot be seen.
    pub read_rate: Option<f64>,
    pub write_rate: Option<f64>,
}

/// One row per process alive at the second sample.
pub fn top_rows(before: &Snapshot, after: &Snapshot, secs: f64, ticks: f64) -> Vec<TopRow> {
    let secs = secs.max(0.001);
    let ticks = ticks.max(1.0);
    after
        .procs
        .iter()
        .map(|(pid, now)| {
            // AIDEV-NOTE: a pid seen in both samples is the same process only if its start
            // time is the same. Otherwise the pid was reused: the process began during
            // the interval, so everything it has used so far was used in the interval.
            // Subtracting the old process's totals would give nonsense.
            let earlier = before
                .procs
                .get(pid)
                .filter(|then| then.starttime == now.starttime);
            let cpu_before = earlier.map_or(0, |then| then.cpu_ticks);
            let cpu_secs = now.cpu_ticks.saturating_sub(cpu_before) as f64 / ticks;
            let io_before = match earlier {
                Some(then) => then.io,
                None => Some((0, 0)),
            };
            let rates = now
                .io
                .zip(io_before)
                .map(|((read, written), (read0, written0))| {
                    (
                        read.saturating_sub(read0) as f64 / secs,
                        written.saturating_sub(written0) as f64 / secs,
                    )
                });
            TopRow {
                pid: *pid,
                starttime: now.starttime,
                comm: now.comm.clone(),
                cpu_percent: cpu_secs * 100.0 / secs,
                rss_pages: now.rss_pages,
                read_rate: rates.map(|(read, _)| read),
                write_rate: rates.map(|(_, written)| written),
            }
        })
        .collect()
}

/// What `resource_top` ranks by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sort {
    Cpu,
    Mem,
    Io,
}

impl Sort {
    pub fn parse(name: &str) -> Sort {
        match name {
            "mem" => Sort::Mem,
            "io" => Sort::Io,
            _ => Sort::Cpu,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Sort::Cpu => "cpu",
            Sort::Mem => "mem",
            Sort::Io => "io",
        }
    }
}

/// Puts the rows that used the most first. Ties fall back to CPU, then memory, then pid,
/// so the order never depends on how the processes happened to be listed.
pub fn sort_rows(rows: &mut [TopRow], sort: Sort) {
    // A process whose I/O cannot be seen ranks below one that did none.
    let io = |row: &TopRow| match (row.read_rate, row.write_rate) {
        (Some(read), Some(written)) => read + written,
        _ => -1.0,
    };
    rows.sort_by(|a, b| {
        let first = match sort {
            Sort::Cpu => b.cpu_percent.total_cmp(&a.cpu_percent),
            Sort::Mem => b.rss_pages.cmp(&a.rss_pages),
            Sort::Io => io(b).total_cmp(&io(a)),
        };
        first
            .then(b.cpu_percent.total_cmp(&a.cpu_percent))
            .then(b.rss_pages.cmp(&a.rss_pages))
            .then(a.pid.cmp(&b.pid))
    });
}

/// What one unit did between two samples.
#[derive(Clone, Debug, PartialEq)]
pub struct UnitRow {
    pub name: String,
    pub cpu_percent: Option<f64>,
    pub memory: Option<u64>,
}

/// One row per unit present at the second sample; `None` where units cannot be measured.
pub fn unit_rows(before: &Snapshot, after: &Snapshot, secs: f64) -> Option<Vec<UnitRow>> {
    let now = after.units.as_ref()?;
    let secs = secs.max(0.001);
    let rows = now
        .iter()
        .map(|(name, unit)| {
            // A unit that was not there at the first sample started during the interval
            // (a restarted unit gets a fresh cgroup, counting from zero).
            let earlier = before
                .units
                .as_ref()
                .and_then(|units| units.get(name))
                .and_then(|then| then.cpu_usec)
                .unwrap_or(0);
            let cpu_percent = unit
                .cpu_usec
                .map(|usec| usec.saturating_sub(earlier) as f64 / (secs * 1e6) * 100.0);
            UnitRow {
                name: name.clone(),
                cpu_percent,
                memory: unit.memory,
            }
        })
        .collect();
    Some(rows)
}

const COMMAND_WIDTH: usize = 120;

/// A storage I/O rate for a table cell.
fn rate_cell(rate: Option<f64>) -> String {
    match rate {
        Some(bytes) => human_bytes(bytes.max(0.0) as u64),
        None => "-".to_string(),
    }
}

/// The table of processes for rows already chosen and ordered. Owner and command line
/// are read now, for these rows only.
fn process_table(
    roots: &Roots,
    rows: &[TopRow],
    clock: Clock,
    with_io: bool,
    width: usize,
) -> String {
    let mut names = Names::default();
    let mut table = Vec::with_capacity(rows.len());
    for row in rows {
        let dir = roots.proc.join(row.pid.to_string());
        // AIDEV-NOTE: the process may have exited since the sample, and its pid may
        // already belong to something else. Owner and command line are only taken from
        // /proc if the process there has the start time that was sampled.
        let same = read_text(&dir.join("stat"), 4096)
            .and_then(|text| parse_stat(&text))
            .is_some_and(|now| now.starttime == row.starttime);
        let (user, command) = if same {
            let user = read_text(&dir.join("status"), 8192)
                .and_then(|text| parse_uid(&text))
                .map_or_else(|| "?".to_string(), |uid| names.user(uid).to_string());
            let args =
                split_cmdline(&read_bytes(&dir.join("cmdline"), 16 * 1024).unwrap_or_default());
            let command = if args.is_empty() {
                // a kernel thread, or a process that has cleared its arguments
                format!("[{}]", row.comm)
            } else {
                // secrets on the command line are masked, as process_list masks them
                redact_args(&args).join(" ")
            };
            (user, command)
        } else {
            ("?".to_string(), format!("[{}] (exited)", row.comm))
        };
        let rss = u64::try_from(row.rss_pages)
            .unwrap_or(0)
            .saturating_mul(clock.page_size);
        let mut cells = vec![
            row.pid.to_string(),
            user,
            format!("{:.1}", row.cpu_percent),
            human_bytes(rss),
        ];
        if with_io {
            cells.push(rate_cell(row.read_rate));
            cells.push(rate_cell(row.write_rate));
        }
        cells.push(command.chars().take(width).collect());
        table.push(cells);
    }
    if with_io {
        let headers = ["PID", "USER", "%CPU", "RSS", "READ/s", "WRITE/s", "COMMAND"];
        format_table(
            &headers,
            &table,
            &[true, false, true, true, true, true, false],
        )
    } else {
        let headers = ["PID", "USER", "%CPU", "RSS", "COMMAND"];
        format_table(&headers, &table, &[true, false, true, true, false])
    }
}

/// The whole `resource_top` report for two samples `secs` apart. `show_units`: the
/// caller may see units (holds service.view), so the per-unit figures are included.
#[allow(clippy::too_many_arguments)]
pub fn render_top(
    roots: &Roots,
    before: &Snapshot,
    after: &Snapshot,
    secs: f64,
    clock: Clock,
    sort: Sort,
    limit: usize,
    show_units: bool,
) -> String {
    let mut text = match after.cpus {
        0 => format!("Sampled for {secs:.1} s.\n"),
        1 => format!("Sampled for {secs:.1} s on 1 CPU.\n"),
        cpus => format!("Sampled for {secs:.1} s on {cpus} CPUs.\n"),
    };
    let split = before
        .cpu
        .zip(after.cpu)
        .and_then(|(before, after)| cpu_split(before, after));
    if let Some([user, system, iowait, steal, idle]) = split {
        text.push_str(&format!(
            "CPU:      {user:.1}% user, {system:.1}% system, {iowait:.1}% iowait, {steal:.1}% steal, {idle:.1}% idle\n"
        ));
    }
    if let Some(pressure) = pressure_line(roots) {
        text.push_str(&format!(
            "Pressure: {pressure}  [% of the last 10 s in which tasks were stalled]\n"
        ));
    }
    text.push('\n');

    let mut rows = top_rows(before, after, secs, clock.ticks);
    sort_rows(&mut rows, sort);
    let total = rows.len();
    rows.truncate(limit);
    text.push_str(&process_table(roots, &rows, clock, true, COMMAND_WIDTH));
    text.push_str(&format!(
        "[top {} of {total} processes by {}; %CPU is the share of ONE CPU over the interval; \
         READ/s and WRITE/s are storage I/O, shown as - where it cannot be read]\n",
        rows.len(),
        sort.as_str()
    ));
    text.push('\n');

    // AIDEV-NOTE: unit names, including container scopes, are what service.view governs.
    // This tool's own permission is process.view, so the per-unit part is added only for
    // a caller who could have listed the units with service_list.
    if !show_units {
        text.push_str("[per-unit figures are not shown: they need service.view]\n");
        return text;
    }
    match unit_rows(before, after, secs) {
        None => text.push_str(
            "[per-unit figures are not shown: this host does not use the unified (v2) cgroup hierarchy]\n",
        ),
        Some(mut units) => {
            let by_memory = sort == Sort::Mem;
            units.sort_by(|a, b| {
                let cpu = b
                    .cpu_percent
                    .unwrap_or(-1.0)
                    .total_cmp(&a.cpu_percent.unwrap_or(-1.0));
                let memory = b.memory.cmp(&a.memory);
                let first = if by_memory { memory.then(cpu) } else { cpu.then(memory) };
                first.then_with(|| a.name.cmp(&b.name))
            });
            let total = units.len();
            units.truncate(limit);
            let table: Vec<Vec<String>> = units
                .iter()
                .map(|unit| {
                    vec![
                        unit.name.clone(),
                        unit.cpu_percent
                            .map_or_else(|| "-".to_string(), |cpu| format!("{cpu:.1}")),
                        unit.memory.map_or_else(|| "-".to_string(), human_bytes),
                    ]
                })
                .collect();
            text.push_str(&format_table(
                &["UNIT", "%CPU", "MEMORY"],
                &table,
                &[false, true, true],
            ));
            text.push_str(&format!(
                "[top {} of {total} units by {}: services and scopes of the system and machine slices]\n",
                units.len(),
                if by_memory { "mem" } else { "cpu" }
            ));
        }
    }
    text
}

/// Two snapshots `interval` apart. The wait is an async sleep, so a cancelled call stops
/// waiting at once; only the reads are blocking jobs.
async fn sample(
    ctx: &Ctx,
    roots: &Roots,
    interval: Duration,
) -> Result<(Snapshot, Snapshot), ToolError> {
    let first = {
        let roots = roots.clone();
        blocking(ctx.clone(), move || Ok(snapshot(&roots))).await?
    };
    tokio::time::sleep(interval).await;
    let second = {
        let roots = roots.clone();
        blocking(ctx.clone(), move || Ok(snapshot(&roots))).await?
    };
    Ok((first, second))
}

async fn resource_top(ctx: Ctx, args: Args) -> ToolResult {
    // Leave the rest of the call's time limit for reading and formatting.
    let longest = ctx.cfg().limits.call_timeout_secs.saturating_sub(5).max(1);
    let seconds = u64::try_from(args.int("seconds").unwrap_or(3))
        .unwrap_or(3)
        .min(longest);
    let sort = Sort::parse(args.str("sort").unwrap_or("cpu"));
    let limit = usize::try_from(args.int("limit").unwrap_or(15)).unwrap_or(15);
    // Like process_list this shows every process, so it needs an unscoped grant.
    let auth = ctx.authorize(None)?;
    let roots = Roots::default();
    let (before, after) = sample(&ctx, &roots, Duration::from_secs(seconds)).await?;
    let budget = ctx.output_budget();
    let show_units = ctx.holds_read("service.view");
    blocking(ctx.clone(), move || {
        let secs = after.taken.duration_since(before.taken).as_secs_f64();
        let clock = Clock::system();
        let text = render_top(
            &roots, &before, &after, secs, clock, sort, limit, show_units,
        );
        auth.ok(fit(&text, budget))
    })
    .await
}

// ---- log_summary ------------------------------------------------------------------------

/// What to summarise.
#[derive(Clone, Debug)]
pub struct LogOpts {
    pub minutes: i64,
    pub unit: Option<String>,
    /// Only entries at this severity or worse.
    pub priority: Option<String>,
    /// Most entries to examine.
    pub entries: usize,
    /// Sources and message groups to show.
    pub top: usize,
}

impl LogOpts {
    /// `, unit X, P or worse`: how the query was narrowed, for headings.
    fn scope(&self) -> String {
        let mut scope = String::new();
        if let Some(unit) = &self.unit {
            scope.push_str(&format!(", unit {unit}"));
        }
        if let Some(priority) = &self.priority {
            scope.push_str(&format!(", {priority} or worse"));
        }
        scope
    }
}

/// The journalctl arguments for a summary.
///
/// AIDEV-NOTE: `--reverse` matters. Without it, journalctl versions differ on whether
/// `--since` with `--lines=N` gives the first or the last N entries of the window. In
/// reverse it always starts at the newest entry and stops after N or at `--since`, so
/// the entries examined are the newest ones, and if the output is cut at the size limit
/// it is the oldest that are lost. `--all` is there because in JSON output a field longer
/// than 4096 bytes is otherwise printed as null, and long messages (a crash with its
/// stack trace) are among the ones that matter; `MAX_ENTRY_BYTES` and `MESSAGE_CHARS`
/// bound what is done with them. Every value is passed as `--option=value` in one
/// argument, so none can be read as an option of its own.
pub fn summary_argv(opts: &LogOpts) -> Vec<String> {
    let mut argv = vec![
        "--no-pager".to_string(),
        "--quiet".to_string(),
        "--reverse".to_string(),
        "--all".to_string(),
        "--output=json".to_string(),
        "--output-fields=MESSAGE,PRIORITY,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER".to_string(),
        format!("--since=-{}min", opts.minutes),
        format!("--lines={}", opts.entries),
    ];
    if let Some(unit) = &opts.unit {
        argv.push(format!("--unit={unit}"));
    }
    if let Some(priority) = &opts.priority {
        argv.push(format!("--priority={priority}"));
    }
    argv
}

/// Runs journalctl for a summary, with room for the entries asked for.
async fn run_summary(
    ctx: &Ctx,
    opts: &LogOpts,
    limit: Option<Duration>,
) -> Result<CmdOutput, ToolError> {
    let mut cmd = ctx.command("journalctl")?.args(summary_argv(opts));
    // An entry is a few hundred bytes plus its message; 2 KiB each is generous.
    // AIDEV-NOTE: this much is held in memory per call, and several calls can run at
    // once: keep the ceiling modest. Entries are a few hundred bytes with the fields
    // asked for; if the cap is reached the summary says that it covers less.
    cmd.max_output = opts.entries.saturating_mul(2048).clamp(1 << 20, 32 << 20);
    if let Some(limit) = limit {
        cmd = cmd.timeout(limit);
    }
    ctx.run(cmd).await
}

/// journalctl --quiet prints nothing (and may exit 1) when nothing matched.
pub(super) fn no_entries(out: &CmdOutput) -> bool {
    out.stdout.iter().all(u8::is_ascii_whitespace)
        && out.stderr.iter().all(u8::is_ascii_whitespace)
        && !out.timed_out
        && matches!(out.code, Some(0) | Some(1))
}

/// An entry whose JSON is longer than this is counted but not parsed.
///
/// AIDEV-NOTE: a message that is not valid UTF-8 comes as a JSON array of byte values,
/// which takes many times its length in memory once parsed. A program that logs binary
/// data must not be able to make a summary use hundreds of megabytes.
const MAX_ENTRY_BYTES: usize = 256 * 1024;
/// Characters of a message that are examined; the rest of a huge message is ignored.
const MESSAGE_CHARS: usize = 2000;
/// Characters of a message's normal form, and of the example shown for a group.
const GROUP_CHARS: usize = 200;
const SOURCE_CHARS: usize = 64;

/// Finds the parts of a message that vary from one occurrence to the next.
static NORMALISER: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?P<uuid>\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b)",
        r"|(?P<ip>\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b)",
        r"|(?P<hex>\b(?:0x)?[0-9a-fA-F]{8,}\b)",
        r"|(?P<num>[0-9]+)",
    ))
    .ok()
});

/// The shape of a message: what is left when the parts that differ between occurrences
/// (numbers, addresses, ids) are replaced by placeholders. Messages with the same shape
/// are counted as one group.
pub fn normalize_message(message: &str) -> String {
    let replaced = match NORMALISER.as_ref() {
        Some(pattern) => pattern
            .replace_all(message, |found: &Captures| {
                if found.name("uuid").is_some() {
                    return "UUID".to_string();
                }
                if found.name("ip").is_some() {
                    return "IP".to_string();
                }
                match found.name("hex").map(|hex| hex.as_str()) {
                    // a long number is a number, whether or not it could be read as hex
                    Some(text) if text.chars().all(|c| c.is_ascii_digit()) => "N".to_string(),
                    // a word that happens to consist of the letters a to f
                    Some(text) if !text.chars().any(|c| c.is_ascii_digit()) => text.to_string(),
                    Some(_) => "H".to_string(),
                    None => "N".to_string(),
                }
            })
            .into_owned(),
        None => message.to_string(),
    };
    one_line(&replaced).chars().take(GROUP_CHARS).collect()
}

/// A journal field as text. In JSON output a field is a string, an array of byte values
/// (when it is not valid UTF-8), an array of values (when the entry has the field more
/// than once: the first is taken), or null.
pub(super) fn field_text(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(text) => Some(text.clone()),
        Value::Array(items) => {
            let bytes: Option<Vec<u8>> = items
                .iter()
                .map(|item| item.as_u64().and_then(|byte| u8::try_from(byte).ok()))
                .collect();
            match bytes {
                Some(bytes) if !bytes.is_empty() => {
                    Some(String::from_utf8_lossy(&bytes).into_owned())
                }
                _ => items.iter().find_map(|item| match item {
                    Value::String(text) => Some(text.clone()),
                    _ => None,
                }),
            }
        }
        _ => None,
    }
}

/// How many entries a unit (or program) logged.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SourceCount {
    /// Severity err or worse.
    pub errors: u64,
    pub warnings: u64,
    pub total: u64,
}

/// Messages of one source with the same shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    pub source: String,
    pub count: u64,
    /// The most severe level seen (0 is the most severe).
    pub worst: u8,
    /// One of the messages, as logged (secrets masked).
    pub example: String,
    first_seen: u64,
}

/// What a stretch of the journal contained.
#[derive(Debug, Default)]
pub struct Summary {
    pub total: u64,
    pub errors: u64,
    pub warnings: u64,
    /// Lines of output that were not a journal entry (a line cut at the size limit).
    pub unreadable: u64,
    /// Entries too large to examine (see `MAX_ENTRY_BYTES`). Not part of `total`.
    pub oversized: u64,
    pub sources: BTreeMap<String, SourceCount>,
    groups: HashMap<(String, String), Group>,
    /// Time of the oldest entry examined, in microseconds since the epoch.
    pub oldest_usec: Option<u64>,
}

impl Summary {
    /// The message groups: errors and worse first, then warnings, then the rest; within
    /// each, the most repeated first.
    pub fn ranked_groups(&self) -> Vec<&Group> {
        let class = |group: &Group| match group.worst {
            0..=3 => 0,
            4 => 1,
            _ => 2,
        };
        let mut groups: Vec<&Group> = self.groups.values().collect();
        groups.sort_by(|a, b| {
            class(a)
                .cmp(&class(b))
                .then(b.count.cmp(&a.count))
                .then(a.first_seen.cmp(&b.first_seen))
        });
        groups
    }
}

/// Counts and groups the entries in `journalctl --output=json` output (one JSON object
/// per line).
pub fn summarize(stdout: &[u8]) -> Summary {
    let mut summary = Summary::default();
    for line in stdout.split(|byte| *byte == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if line.len() > MAX_ENTRY_BYTES {
            summary.oversized += 1;
            continue;
        }
        let Ok(Value::Object(entry)) = serde_json::from_slice::<Value>(line) else {
            summary.unreadable += 1;
            continue;
        };
        // AIDEV-NOTE: _SYSTEMD_UNIT is set by journald from the sender's cgroup and can
        // be trusted. SYSLOG_IDENTIFIER is whatever the sender called itself: an entry
        // filed under it is marked, so that `logger -t nginx.service` cannot pass for
        // the unit of that name.
        let clean =
            |name: String| Some(cut(&one_line(&name), SOURCE_CHARS)).filter(|n| !n.is_empty());
        let source = field_text(entry.get("_SYSTEMD_UNIT"))
            .and_then(clean)
            .or_else(|| {
                field_text(entry.get("SYSLOG_IDENTIFIER"))
                    .and_then(clean)
                    .map(|name| format!("{name} (syslog id)"))
            })
            .unwrap_or_else(|| "(unknown)".to_string());
        let priority = field_text(entry.get("PRIORITY"))
            .and_then(|level| level.trim().parse::<u8>().ok())
            .filter(|level| *level <= 7);
        let message: String = field_text(entry.get("MESSAGE"))
            .unwrap_or_default()
            .chars()
            .take(MESSAGE_CHARS)
            .collect();
        // AIDEV-NOTE: programs log their command lines, connection strings and the like.
        // Secrets are masked before anything is kept, so neither an example nor a group
        // key can carry one.
        let message = redact_text(&message);
        if let Some(when) = field_text(entry.get("__REALTIME_TIMESTAMP"))
            .and_then(|usec| usec.trim().parse::<u64>().ok())
        {
            summary.oldest_usec = Some(summary.oldest_usec.map_or(when, |old| old.min(when)));
        }

        let is_error = priority.is_some_and(|level| level <= 3);
        let is_warning = priority == Some(4);
        summary.total += 1;
        summary.errors += u64::from(is_error);
        summary.warnings += u64::from(is_warning);
        let count = summary.sources.entry(source.clone()).or_default();
        count.total += 1;
        count.errors += u64::from(is_error);
        count.warnings += u64::from(is_warning);

        // An entry without a level is treated as informational, as journalctl shows it.
        let level = priority.unwrap_or(6);
        let key = (source.clone(), normalize_message(&message));
        let first_seen = summary.total;
        let group = summary.groups.entry(key).or_insert_with(|| Group {
            source,
            count: 0,
            worst: level,
            example: match one_line(&message) {
                text if text.is_empty() => "(no message)".to_string(),
                text => cut(&text, GROUP_CHARS),
            },
            first_seen,
        });
        group.count += 1;
        group.worst = group.worst.min(level);
    }
    summary
}

/// The table of the most repeated message groups.
fn groups_table(summary: &Summary, top: usize) -> String {
    let rows: Vec<Vec<String>> = summary
        .ranked_groups()
        .iter()
        .take(top)
        .map(|group| {
            vec![
                group.count.to_string(),
                LEVELS
                    .get(usize::from(group.worst))
                    .copied()
                    .unwrap_or("?")
                    .to_string(),
                group.source.clone(),
                group.example.clone(),
            ]
        })
        .collect();
    format_table(
        &["COUNT", "LEVEL", "SOURCE", "EXAMPLE"],
        &rows,
        &[true, false, false, false],
    )
}

/// The `log_summary` report. `cut_short` says journalctl's output was larger than was
/// kept.
pub fn render_summary(summary: &Summary, opts: &LogOpts, cut_short: bool) -> String {
    let mut text = format!(
        "Journal, last {} minutes{}: {} entries ({} at err or worse, {} at warning) from {} {}.\n",
        opts.minutes,
        opts.scope(),
        summary.total,
        summary.errors,
        summary.warnings,
        summary.sources.len(),
        if summary.sources.len() == 1 {
            "source"
        } else {
            "sources"
        }
    );
    let back_to = summary
        .oldest_usec
        .and_then(|usec| i64::try_from(usec / 1_000_000).ok())
        .map(|secs| format!(": they go back to {}", rfc3339_utc(secs)))
        .unwrap_or_default();
    let entries = u64::try_from(opts.entries).unwrap_or(u64::MAX);
    if cut_short {
        text.push_str(&format!(
            "[journalctl printed more than is kept, so only the newest {} entries were \
             examined{back_to}; narrow the query (a unit, a priority, fewer minutes)]\n",
            summary.total
        ));
    } else if summary.total >= entries {
        text.push_str(&format!(
            "[only the newest {} entries were examined{back_to}, which may not be the whole \
             {} minutes; raise entries or narrow the query]\n",
            summary.total, opts.minutes
        ));
    }
    if summary.oversized > 0 {
        text.push_str(&format!(
            "[{} very large entries were not examined or counted]\n",
            summary.oversized
        ));
    }
    if summary.unreadable > 0 {
        text.push_str(&format!(
            "[{} lines of journal output could not be read and were not counted]\n",
            summary.unreadable
        ));
    }
    text.push('\n');

    let mut sources: Vec<(&String, &SourceCount)> = summary.sources.iter().collect();
    sources.sort_by(|a, b| b.1.total.cmp(&a.1.total).then(a.0.cmp(b.0)));
    let rows: Vec<Vec<String>> = sources
        .iter()
        .take(opts.top)
        .map(|(name, count)| {
            vec![
                (*name).clone(),
                count.errors.to_string(),
                count.warnings.to_string(),
                count.total.to_string(),
            ]
        })
        .collect();
    text.push_str(&format_table(
        &["SOURCE", "ERRORS", "WARNINGS", "TOTAL"],
        &rows,
        &[false, true, true, true],
    ));
    if sources.len() > rows.len() {
        text.push_str(&format!(
            "[the {} busiest of {} sources]\n",
            rows.len(),
            sources.len()
        ));
    }
    text.push('\n');

    text.push_str(
        "Most repeated messages, errors first (numbers, addresses and ids are ignored when grouping):\n",
    );
    text.push_str(&groups_table(summary, opts.top));
    let groups = summary.groups.len();
    if groups > opts.top {
        text.push_str(&format!(
            "[{} of {groups} message groups shown]\n",
            opts.top
        ));
    }
    text
}

async fn log_summary(ctx: Ctx, args: Args) -> ToolResult {
    let opts = LogOpts {
        minutes: args.int("minutes").unwrap_or(60),
        unit: args.str("unit").map(normalize_unit).transpose()?,
        priority: args.str("priority").map(str::to_string),
        entries: usize::try_from(args.int("entries").unwrap_or(10_000)).unwrap_or(10_000),
        top: usize::try_from(args.int("top").unwrap_or(15)).unwrap_or(15),
    };
    // As for journal_query: a summary of one unit needs a grant covering that unit; any
    // other needs an unscoped grant, because it reports on every unit.
    let auth = ctx.authorize(opts.unit.as_deref())?;
    let mut out = run_summary(&ctx, &opts, None).await?;
    if no_entries(&out) {
        return auth.ok(format!(
            "(no journal entries in the last {} minutes{})\n",
            opts.minutes,
            opts.scope()
        ));
    }
    if out.stdout.iter().all(u8::is_ascii_whitespace) {
        return auth.failed(command_text(&out));
    }
    let succeeded = command_ok(&out);
    // The journal's output is large: it is summarised and dropped, never copied.
    let entries = std::mem::take(&mut out.stdout);
    let summary = summarize(&entries);
    drop(entries);
    let mut text = render_summary(&summary, &opts, out.truncated);
    // What went wrong, if anything (stderr, a time limit, an exit status), after the
    // summary of what was read.
    out.truncated = false;
    let trouble = command_text(&out);
    if !trouble.trim().is_empty() {
        text.push('\n');
        text.push_str(&trouble);
    }
    auth.done(fit(&text, ctx.output_budget()), succeeded)
}

// ---- crash_events ---------------------------------------------------------------------

/// What marks a kill or a crash in the kernel's messages (a PCRE2 pattern, as
/// `journalctl --grep` takes; the capital letters make the match case-sensitive).
/// `oom-kill:` is the record that names the cgroup (the unit) of the killed task; the
/// colon keeps out the "invoked oom-killer" line that precedes every kill.
const CRASH_PATTERN: &str = "Out of memory|oom-kill:|Killed process|segfault at|general protection fault|traps: |kernel BUG|Oops|Kernel panic";

/// The journalctl arguments for the kernel's messages about kills and crashes.
///
/// AIDEV-NOTE: the match `_TRANSPORT=kernel` is used rather than `--dmesg`, because
/// `--dmesg` also means "this boot only" and the kill that came before a reboot is often
/// the one being looked for. `--reverse` makes journalctl start at the newest entry, so
/// that if the search reaches its time limit or the output its size limit, it is the
/// oldest lines that are missing, not the newest.
pub fn crash_argv(hours: i64) -> Vec<String> {
    vec![
        "--no-pager".to_string(),
        "--quiet".to_string(),
        "--reverse".to_string(),
        "--output=short-iso".to_string(),
        format!("--since=-{hours}h"),
        format!("--grep={CRASH_PATTERN}"),
        "_TRANSPORT=kernel".to_string(),
    ]
}

/// The lines of output that was printed newest first, put back in time order (the
/// newest last), without the padding some commands add at the end of a line.
fn in_time_order(stdout: &[u8]) -> Vec<String> {
    let mut lines: Vec<String> = String::from_utf8_lossy(stdout)
        .lines()
        .map(|line| line.trim_end().to_string())
        .filter(|line| !line.is_empty())
        .collect();
    lines.reverse();
    lines
}

/// The kernel's lines about kills and crashes, oldest first, and anything journalctl
/// complained about while producing them (a time limit reached, for example: then the
/// oldest lines are missing).
struct KernelLines {
    lines: Vec<String>,
    trouble: Option<String>,
}

/// Asks the journal for the kernel's kill and crash lines. `Err` is the reason there is
/// no answer.
async fn kernel_crash_lines(
    ctx: &Ctx,
    hours: i64,
    limit: Option<Duration>,
) -> Result<KernelLines, String> {
    let mut cmd = ctx
        .command("journalctl")
        .map_err(reason)?
        .args(crash_argv(hours));
    cmd.max_output = 4 << 20;
    if let Some(limit) = limit {
        cmd = cmd.timeout(limit);
    }
    let out = ctx.run(cmd).await.map_err(reason)?;
    let lines = in_time_order(&out.stdout);
    if no_entries(&out) {
        return Ok(KernelLines {
            lines,
            trouble: None,
        });
    }
    let mut silent = out.clone();
    silent.stdout.clear();
    let trouble = one_line(&command_text(&silent));
    if lines.is_empty() {
        return Err(format!("journalctl failed: {trouble}"));
    }
    Ok(KernelLines {
        lines,
        trouble: (!trouble.is_empty()).then_some(trouble),
    })
}

/// The kernel logs one "Killed process" line for each process it kills for lack of
/// memory (whether the machine or a cgroup ran out).
pub fn count_oom_kills(lines: &[String]) -> usize {
    lines
        .iter()
        .filter(|line| line.contains("Killed process"))
        .count()
}

/// A file in the crash directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrashFile {
    pub name: String,
    pub size: u64,
    pub mtime: i64,
}

const MAX_CRASH_ENTRIES: usize = 10_000;
const MAX_CRASH_FILES: usize = 50;

/// The regular files in a crash directory changed at or after `since`, newest first, and
/// how many older ones there are. `None` if there is no such directory.
pub fn list_crash_dir(dir: &Path, since: i64) -> Option<(Vec<CrashFile>, usize)> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut recent = Vec::new();
    let mut older = 0;
    for entry in entries.flatten().take(MAX_CRASH_ENTRIES) {
        // Not followed: on Ubuntu any user may create entries here.
        let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        if meta.mtime() < since {
            older += 1;
            continue;
        }
        recent.push(CrashFile {
            name: entry.file_name().to_string_lossy().into_owned(),
            size: meta.len(),
            mtime: meta.mtime(),
        });
    }
    recent.sort_by(|a, b| b.mtime.cmp(&a.mtime).then_with(|| a.name.cmp(&b.name)));
    Some((recent, older))
}

/// The core dumps systemd-coredump recorded, as the body of a report section.
async fn coredump_list(ctx: &Ctx, hours: i64, budget: usize) -> String {
    let Ok(cmd) = ctx.command("coredumpctl") else {
        return "[coredumpctl is not installed: systemd does not record core dumps on this host (package systemd-coredump)]\n"
            .to_string();
    };
    // Newest first, for the same reason as the kernel's lines: what is lost to a limit
    // is then the oldest.
    let argv = [
        "list".to_string(),
        "--no-pager".to_string(),
        "--no-legend".to_string(),
        "--reverse".to_string(),
        format!("--since=-{hours}h"),
    ];
    let out = match ctx.run(cmd.args(argv)).await {
        Ok(out) => out,
        Err(error) => return unavailable(error),
    };
    let lines = in_time_order(&out.stdout);
    if lines.is_empty() {
        // coredumpctl exits 1 and says "No coredumps found." when there are none.
        let stderr = String::from_utf8_lossy(&out.stderr);
        let none = stderr.trim().is_empty() || stderr.contains("No coredumps found");
        if none && !out.timed_out {
            return "none recorded\n".to_string();
        }
        return format!("[not available: {}]\n", one_line(&command_text(&out)));
    }
    let mut text = "TIME PID UID GID SIG COREFILE EXE SIZE\n".to_string();
    let (kept, dropped) = keep_tail(&(lines.join("\n") + "\n"), budget);
    if dropped > 0 {
        text.push_str(&format!("[{dropped} earlier lines left out]\n"));
    }
    text.push_str(&kept);
    let mut silent = out.clone();
    silent.stdout.clear();
    let trouble = one_line(&command_text(&silent));
    if !trouble.is_empty() {
        text.push_str(&format!("[coredumpctl: {trouble}]\n"));
    }
    text.push_str("[pass pid to see the details of one]\n");
    text
}

/// The lists: kernel kills and crashes, core dumps, crash report files.
pub async fn crash_events_in(ctx: &Ctx, auth: Authorized, roots: &Roots, hours: i64) -> ToolResult {
    let budget = ctx.output_budget();
    let dir = roots.crash.clone();
    let since = now_secs().saturating_sub(hours.saturating_mul(3600));
    let listing = blocking(ctx.clone(), {
        let dir = dir.clone();
        move || Ok(list_crash_dir(&dir, since))
    });
    // Side by side: each command has its own time limit, and they do not add up. Boxed
    // for the reason given in `incident_snapshot_in`.
    let (kernel, dumps, files) = tokio::join!(
        Box::pin(kernel_crash_lines(ctx, hours, None)),
        Box::pin(coredump_list(ctx, hours, budget / 4)),
        Box::pin(listing),
    );

    let mut text = format!(
        "Kernel-reported kills and crashes, last {hours} h (out-of-memory kills, segfaults, faults):\n"
    );
    match kernel {
        Err(why) => text.push_str(&format!("[not available: {why}]\n")),
        Ok(found) if found.lines.is_empty() => text.push_str("none found\n"),
        Ok(found) => {
            text.push_str(&format!(
                "{} lines, {} out-of-memory kills\n",
                found.lines.len(),
                count_oom_kills(&found.lines)
            ));
            // In time order: if there is too much, it is the newest that is kept.
            let (kept, dropped) = keep_tail(&(found.lines.join("\n") + "\n"), budget / 2);
            if dropped > 0 {
                text.push_str(&format!("[{dropped} earlier lines left out]\n"));
            }
            text.push_str(&kept);
            if let Some(trouble) = found.trouble {
                text.push_str(&format!("[journalctl: {trouble}]\n"));
            }
        }
    }

    text.push_str(&format!(
        "\nCore dumps recorded by systemd-coredump, last {hours} h:\n"
    ));
    text.push_str(&dumps);

    text.push_str(&format!(
        "\nCrash reports in {} (apport), last {hours} h:\n",
        dir.display()
    ));
    match files {
        Err(error) => text.push_str(&unavailable(error)),
        Ok(None) => text.push_str(&format!(
            "there is no {} directory on this host\n",
            dir.display()
        )),
        Ok(Some((recent, older))) => {
            if recent.is_empty() {
                text.push_str("no crash reports in that time\n");
            } else {
                let rows: Vec<Vec<String>> = recent
                    .iter()
                    .take(MAX_CRASH_FILES)
                    .map(|file| {
                        vec![
                            rfc3339_utc(file.mtime),
                            human_bytes(file.size),
                            file.name.clone(),
                        ]
                    })
                    .collect();
                text.push_str(&format_table(
                    &["TIME", "SIZE", "NAME"],
                    &rows,
                    &[false, true, false],
                ));
                if recent.len() > rows.len() {
                    text.push_str(&format!(
                        "[{} more from that time not shown]\n",
                        recent.len().saturating_sub(rows.len())
                    ));
                }
            }
            if older > 0 {
                text.push_str(&format!("[{older} older files not shown]\n"));
            }
        }
    }
    auth.ok(fit(&text, budget))
}

/// The details systemd-coredump kept about one crashed process.
async fn coredump_info(ctx: &Ctx, auth: Authorized, pid: i64) -> ToolResult {
    let cmd = ctx.command("coredumpctl").map_err(|_| {
        ToolError::Failed(
            "coredumpctl is not installed: systemd does not record core dumps on this host \
             (package systemd-coredump)"
                .to_string(),
        )
    })?;
    // The pid is a number we formatted: it cannot be read as an option or another match.
    let argv = [
        "info".to_string(),
        "--no-pager".to_string(),
        pid.to_string(),
    ];
    let out = ctx.run(cmd.args(argv)).await?;
    // AIDEV-NOTE: the details include the crashed program's full command line. Mask
    // secrets in it as process_list does; without this, crash.view would show what
    // process.view takes care to hide.
    let text = redact_text(&command_text(&out));
    auth.done(fit(&text, ctx.output_budget()), command_ok(&out))
}

async fn crash_events(ctx: Ctx, args: Args) -> ToolResult {
    let hours = args.int("hours").unwrap_or(24);
    let pid = args.int("pid");
    let auth = ctx.authorize(None)?;
    match pid {
        Some(pid) => coredump_info(&ctx, auth, pid).await,
        None => crash_events_in(&ctx, auth, &Roots::default(), hours).await,
    }
}

// ---- incident_snapshot --------------------------------------------------------------

/// A filesystem at or above this share of its space or inodes is reported.
const FULL_PERCENT: u64 = 85;
/// Rows in each of the snapshot's small tables.
const SNAPSHOT_ROWS: usize = 5;
const SNAPSHOT_COMMAND_WIDTH: usize = 100;
/// Longest any one command of the snapshot may take, in seconds.
const SECTION_SECS: u64 = 10;
const SNAPSHOT_JOURNAL_MINUTES: i64 = 15;
const SNAPSHOT_JOURNAL_ENTRIES: usize = 2000;
const SNAPSHOT_CRASH_HOURS: i64 = 24;
const MAX_INTERFACES: usize = 500;
const MAX_NET_ALERTS: usize = 20;

/// The line for a filesystem that is nearly out of space or inodes; `None` for one that
/// is not. `files` is 0 for a filesystem that does not count inodes.
pub fn fs_alert(
    point: &str,
    size: u64,
    used: u64,
    avail: u64,
    files: u64,
    files_free: u64,
) -> Option<String> {
    // as df does: used out of what an unprivileged user could use
    let space = percent_up(used, used.saturating_add(avail));
    let inodes = (files > 0).then(|| percent_up(files.saturating_sub(files_free), files));
    if space < FULL_PERCENT && inodes.is_none_or(|share| share < FULL_PERCENT) {
        return None;
    }
    let mut line = format!(
        "{point}: {space}% of {} used, {} free",
        human_bytes(size),
        human_bytes(avail)
    );
    if let Some(share) = inodes {
        line.push_str(&format!(", inodes {share}%"));
    }
    Some(line)
}

/// The nearly full filesystems among the mounts in `mountinfo`.
fn full_filesystems(mountinfo: &str) -> Vec<String> {
    let mut mounts = parse_mountinfo(mountinfo);
    mounts.sort_by(|a, b| a.point.cmp(&b.point));
    let mut seen = HashSet::new();
    let mut alerts = Vec::new();
    for mount in &mounts {
        // As disk_usage: network and user-space filesystems are not touched (statting one
        // whose server is gone never returns), and pseudo filesystems are of no interest.
        if listing(mount, false, false) != Listing::Shown {
            continue;
        }
        let Ok(vfs) = rustix::fs::statvfs(mount.point.as_str()) else {
            continue;
        };
        if vfs.f_blocks == 0 {
            continue;
        }
        let device = std::fs::metadata(&mount.point).map(|meta| meta.dev()).ok();
        if device.is_some_and(|device| !seen.insert(device)) {
            continue;
        }
        let size = vfs.f_blocks.saturating_mul(vfs.f_frsize);
        let used = vfs
            .f_blocks
            .saturating_sub(vfs.f_bfree)
            .saturating_mul(vfs.f_frsize);
        let avail = vfs.f_bavail.saturating_mul(vfs.f_frsize);
        if let Some(line) = fs_alert(&mount.point, size, used, avail, vfs.f_files, vfs.f_ffree) {
            alerts.push(line);
        }
    }
    alerts
}

/// Load, pressure, memory and nearly full filesystems.
fn system_part(roots: &Roots) -> String {
    let read = |name: &str| read_text(&roots.proc.join(name), 1 << 20).unwrap_or_default();
    let load = read("loadavg");
    let averages: Vec<&str> = load.split_whitespace().take(3).collect();
    let cpus = count_cpus(&read("stat"));
    let mut text = format!(
        "Load: {} (1, 5 and 15 minutes) on {cpus} CPUs\n",
        if averages.is_empty() {
            "unknown".to_string()
        } else {
            averages.join(" ")
        }
    );
    if let Some(pressure) = pressure_line(roots) {
        text.push_str(&format!(
            "Pressure: {pressure}  [% of the last 10 s in which tasks were stalled]\n"
        ));
    }
    let mem = parse_meminfo(&read("meminfo"));
    let get = |key: &str| mem.get(key).copied().unwrap_or(0);
    let total = get("MemTotal");
    // "Available" is the kernel's estimate of what can be used without swapping.
    let used = total.saturating_sub(get("MemAvailable"));
    text.push_str(&format!(
        "Memory: {} of {} used ({}%), {} available\n",
        human_bytes(used),
        human_bytes(total),
        percent_up(used, total),
        human_bytes(get("MemAvailable"))
    ));
    let swap = get("SwapTotal");
    if swap == 0 {
        text.push_str("Swap: none\n");
    } else {
        text.push_str(&format!(
            "Swap: {} of {} used\n",
            human_bytes(swap.saturating_sub(get("SwapFree"))),
            human_bytes(swap)
        ));
    }
    let full = full_filesystems(&read("self/mountinfo"));
    if full.is_empty() {
        text.push_str(&format!(
            "Filesystems at or above {FULL_PERCENT}% of space or inodes: none\n"
        ));
    } else {
        text.push_str(&format!(
            "Filesystems at or above {FULL_PERCENT}% of space or inodes:\n"
        ));
        for line in full.iter().take(MAX_NET_ALERTS) {
            text.push_str(&format!("  {line}\n"));
        }
        if full.len() > MAX_NET_ALERTS {
            text.push_str(&format!(
                "  [{} more]\n",
                full.len().saturating_sub(MAX_NET_ALERTS)
            ));
        }
    }
    text
}

/// The interfaces that report errors or drops, and the physical ones whose link is down.
/// `None` if the interfaces cannot be listed.
pub fn net_alerts(net: &Path) -> Option<Vec<String>> {
    const COUNTERS: [&str; 4] = ["rx_errors", "tx_errors", "rx_dropped", "tx_dropped"];
    let mut names: Vec<String> = std::fs::read_dir(net)
        .ok()?
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names.truncate(MAX_INTERFACES);
    let mut alerts = Vec::new();
    for name in names {
        let dir = net.join(&name);
        // The loopback interface has no link and drops nothing of interest; plain files
        // here (bonding_masters) are not interfaces.
        if name == "lo" || !dir.is_dir() {
            continue;
        }
        let counters: Vec<String> = COUNTERS
            .iter()
            .filter_map(|counter| {
                let text = read_text(&dir.join("statistics").join(counter), 64)?;
                let value: u64 = text.trim().parse().ok()?;
                (value > 0).then(|| format!("{counter} {value}"))
            })
            .collect();
        if !counters.is_empty() {
            alerts.push(format!("{name}: {}", counters.join(", ")));
        }
        // A virtual interface that is down is normal (an unused bridge, a stopped
        // tunnel); one backed by a device means a cable, a switch port or a driver.
        let down =
            read_text(&dir.join("operstate"), 64).is_some_and(|state| state.trim() == "down");
        if down && dir.join("device").exists() {
            alerts.push(format!("{name}: link is down"));
        }
    }
    Some(alerts)
}

fn network_part(roots: &Roots) -> String {
    match net_alerts(&roots.net) {
        None => format!("[not available: cannot list {}]\n", roots.net.display()),
        Some(alerts) if alerts.is_empty() => {
            "no interface reports errors or drops, and no physical interface is down\n".to_string()
        }
        Some(alerts) => {
            let mut text = String::new();
            for line in alerts.iter().take(MAX_NET_ALERTS) {
                text.push_str(&format!("{line}\n"));
            }
            if alerts.len() > MAX_NET_ALERTS {
                text.push_str(&format!(
                    "[{} more]\n",
                    alerts.len().saturating_sub(MAX_NET_ALERTS)
                ));
            }
            text.push_str("[error and drop counters are totals since boot]\n");
            text
        }
    }
}

/// The top processes by CPU over a short sample, and by memory.
async fn process_part(ctx: &Ctx, roots: &Roots, sample_for: Duration) -> String {
    let (before, after) = match sample(ctx, roots, sample_for).await {
        Ok(samples) => samples,
        Err(error) => return unavailable(error),
    };
    let roots = roots.clone();
    let rendered = blocking(ctx.clone(), move || {
        let secs = after.taken.duration_since(before.taken).as_secs_f64();
        let clock = Clock::system();
        let mut rows = top_rows(&before, &after, secs, clock.ticks);
        let mut text = String::new();
        for (title, sort) in [
            (format!("By CPU over {secs:.1} s:\n"), Sort::Cpu),
            ("By memory:\n".to_string(), Sort::Mem),
        ] {
            sort_rows(&mut rows, sort);
            let top: Vec<TopRow> = rows.iter().take(SNAPSHOT_ROWS).cloned().collect();
            text.push_str(&title);
            text.push_str(&process_table(
                &roots,
                &top,
                clock,
                false,
                SNAPSHOT_COMMAND_WIDTH,
            ));
        }
        Ok(text)
    })
    .await;
    rendered.unwrap_or_else(unavailable)
}

/// The units systemd reports as failed.
async fn failed_units_part(ctx: &Ctx, limit: Duration) -> String {
    let cmd = match ctx.command("systemctl") {
        Ok(cmd) => cmd.timeout(limit),
        Err(error) => return unavailable(error),
    };
    let argv = [
        "list-units",
        "--state=failed",
        "--no-legend",
        "--plain",
        "--no-pager",
    ];
    let out = match ctx.run(cmd.args(argv)).await {
        Ok(out) => out,
        Err(error) => return unavailable(error),
    };
    if command_ok(&out) && out.stdout.iter().all(u8::is_ascii_whitespace) {
        return "none\n".to_string();
    }
    fit(&command_text(&out), 4000)
}

/// How many errors the journal took in the last minutes, and the most repeated.
async fn journal_part(ctx: &Ctx, limit: Duration) -> String {
    let opts = LogOpts {
        minutes: SNAPSHOT_JOURNAL_MINUTES,
        unit: None,
        priority: Some("err".to_string()),
        entries: SNAPSHOT_JOURNAL_ENTRIES,
        top: SNAPSHOT_ROWS,
    };
    let out = match run_summary(ctx, &opts, Some(limit)).await {
        Ok(out) => out,
        Err(error) => return unavailable(error),
    };
    if no_entries(&out) {
        return "none\n".to_string();
    }
    if out.stdout.iter().all(u8::is_ascii_whitespace) {
        return format!("[not available: {}]\n", one_line(&command_text(&out)));
    }
    let summary = summarize(&out.stdout);
    let limit_reached = usize::try_from(summary.total).is_ok_and(|n| n >= opts.entries);
    let mut text = format!(
        "{}{} entries at err or worse\n",
        summary.total,
        if limit_reached || out.truncated {
            " or more"
        } else {
            ""
        }
    );
    text.push_str(&groups_table(&summary, SNAPSHOT_ROWS));
    text
}

/// How many kills and crashes the kernel reported in the last day, and the newest.
async fn crash_part(ctx: &Ctx, limit: Duration) -> String {
    match kernel_crash_lines(ctx, SNAPSHOT_CRASH_HOURS, Some(limit)).await {
        Err(why) => format!("[not available: {why}]\n"),
        Ok(found) if found.lines.is_empty() => "none\n".to_string(),
        Ok(found) => {
            let mut text = format!(
                "{} out-of-memory kills; {} kernel lines about kills and crashes in all (crash_events lists them)\n",
                count_oom_kills(&found.lines),
                found.lines.len()
            );
            if let Some(trouble) = &found.trouble {
                text.push_str(&format!(
                    "[the search was cut short, so there may be more: {trouble}]\n"
                ));
            }
            if let Some(newest) = found.lines.last() {
                text.push_str(&format!("newest: {}\n", cut(newest, 300)));
            }
            text
        }
    }
}

/// Produces a section only for a caller who holds the permission of the tool that the
/// section's content belongs to.
///
/// AIDEV-NOTE: this is what keeps the snapshot from being a way around the policy. A
/// caller who is denied journal.view (or holds it for some units only) could not run
/// journal_query for everything, so the snapshot must not show journal content either.
/// `part` is a future that has not been polled: when the permission is missing it is
/// dropped without ever running, so nothing is read and no command is started.
async fn gated<F>(ctx: &Ctx, permission: &str, part: F) -> String
where
    F: Future<Output = String>,
{
    if ctx.holds_read(permission) {
        part.await
    } else {
        format!("[section left out: needs {permission}]\n")
    }
}

const NOT_IN_TIME: &str = "[not available: it did not finish in time]\n";

/// A part of the snapshot, or a note in its place if it has not finished after
/// `patience`.
///
/// AIDEV-NOTE: the commands have time limits of their own; this is for the file reads. A
/// read that the kernel never completes (a dying disk, a hung mount) cannot be
/// cancelled: its blocking job stays stuck (see `tools::blocking`). The snapshot is
/// returned without that part, because a machine in that state is exactly where a
/// snapshot is wanted.
async fn within<F>(patience: Duration, part: F) -> String
where
    F: Future<Output = String>,
{
    tokio::time::timeout(patience, part)
        .await
        .unwrap_or_else(|_| NOT_IN_TIME.to_string())
}

/// The snapshot, for a caller already authorized for system.view.
pub async fn incident_snapshot_in(
    ctx: &Ctx,
    auth: Authorized,
    roots: &Roots,
    sample_for: Duration,
) -> ToolResult {
    // Every command gets a short time limit of its own, and the parts run side by side,
    // so one slow command cannot use up the call.
    let limit = Duration::from_secs(ctx.cfg().limits.command_timeout_secs.clamp(1, SECTION_SECS));
    // How long any one part is waited for: longer than a command's limit, so that a
    // command that reaches it is reported as such.
    let patience = limit + sample_for + Duration::from_secs(3);
    let system = async {
        let roots = roots.clone();
        let read = blocking(ctx.clone(), move || {
            let hostname = read_text(&roots.proc.join("sys/kernel/hostname"), 256);
            let uptime = read_text(&roots.proc.join("uptime"), 256);
            Ok((hostname, uptime, system_part(&roots)))
        });
        match tokio::time::timeout(patience, read).await {
            Ok(Ok(parts)) => parts,
            Ok(Err(error)) => (None, None, unavailable(error)),
            Err(_) => (None, None, NOT_IN_TIME.to_string()),
        }
    };
    let network = async {
        let roots = roots.clone();
        blocking(ctx.clone(), move || Ok(network_part(&roots)))
            .await
            .unwrap_or_else(unavailable)
    };
    // AIDEV-NOTE: each part is boxed. A running command's future carries its read buffers
    // (about 18 KiB), and every wrapper around a future (the time limit, the gate, the
    // join) holds it by value at least once. Unboxed, the state of this function was
    // over 200 KiB and overflowed a 2 MiB thread stack in debug builds. Boxed, the
    // wrappers hold pointers.
    let processes = Box::pin(process_part(ctx, roots, sample_for));
    let failed = Box::pin(failed_units_part(ctx, limit));
    let journal = Box::pin(journal_part(ctx, limit));
    let crashes = Box::pin(crash_part(ctx, limit));
    let network = Box::pin(network);
    let ((hostname, uptime, system), processes, failed, journal, crashes, network) = tokio::join!(
        Box::pin(system),
        gated(ctx, "process.view", within(patience, processes)),
        gated(ctx, "service.view", within(patience, failed)),
        gated(ctx, "journal.view", within(patience, journal)),
        gated(ctx, "crash.view", within(patience, crashes)),
        gated(ctx, "net.view", within(patience, network)),
    );
    let hostname = hostname.map(|name| one_line(&name)).unwrap_or_default();
    let uptime = uptime
        .and_then(|text| text.split_whitespace().next()?.parse::<f64>().ok())
        .map(|secs| format!(" (up {})", human_duration(secs as u64)))
        .unwrap_or_default();
    let mut text = format!(
        "Incident snapshot of {} at {}{uptime}\n",
        if hostname.is_empty() {
            "this host"
        } else {
            &hostname
        },
        rfc3339_utc(now_secs())
    );
    let sections = [
        ("System".to_string(), system),
        ("Processes".to_string(), processes),
        ("Failed units".to_string(), failed),
        (
            format!("Journal errors, last {SNAPSHOT_JOURNAL_MINUTES} min"),
            journal,
        ),
        (
            format!("Kernel kills and crashes, last {SNAPSHOT_CRASH_HOURS} h"),
            crashes,
        ),
        ("Network".to_string(), network),
    ];
    for (title, body) in sections {
        text.push_str(&format!("\n== {title} ==\n{body}"));
        if !body.ends_with('\n') {
            text.push('\n');
        }
    }
    auth.ok(fit(&text, ctx.output_budget()))
}

async fn incident_snapshot(ctx: Ctx, _args: Args) -> ToolResult {
    let auth = ctx.authorize(None)?;
    incident_snapshot_in(&ctx, auth, &Roots::default(), Duration::from_secs(1)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::Host;
    use crate::tools::testing::{self, FakeBins, call, find, host, ok_text};
    use serde_json::json;
    use std::sync::Arc;

    // ---- stand-ins for /proc, cgroups, /sys/class/net and /var/crash ----------------

    struct FakeSystem {
        dir: tempfile::TempDir,
    }

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    impl FakeSystem {
        fn new() -> FakeSystem {
            let fake = FakeSystem {
                dir: tempfile::tempdir().unwrap(),
            };
            std::fs::create_dir_all(fake.roots().proc).unwrap();
            fake
        }

        fn roots(&self) -> Roots {
            let at = |name: &str| self.dir.path().join(name);
            Roots {
                proc: at("proc"),
                cgroup: at("cgroup"),
                net: at("net"),
                crash: at("crash"),
            }
        }

        fn proc_file(&self, name: &str, text: &str) {
            write(&self.roots().proc.join(name), text);
        }

        /// A process with this much CPU time (in ticks) and resident memory (in pages).
        fn process(&self, pid: i32, comm: &str, ticks: u64, starttime: u64, rss: i64) {
            let (utime, stime) = (ticks / 2, ticks - ticks / 2);
            self.proc_file(
                &format!("{pid}/stat"),
                &format!(
                    "{pid} ({comm}) S 1 {pid} {pid} 0 -1 4194304 0 0 0 0 {utime} {stime} 0 0 20 0 1 0 {starttime} 1000000 {rss} 0 0 0\n"
                ),
            );
            let uid = rustix::process::getuid().as_raw();
            self.proc_file(
                &format!("{pid}/status"),
                &format!("Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"),
            );
        }

        fn io(&self, pid: i32, read: u64, written: u64) {
            self.proc_file(
                &format!("{pid}/io"),
                &format!(
                    "rchar: 1\nwchar: 2\nread_bytes: {read}\nwrite_bytes: {written}\ncancelled_write_bytes: 7\n"
                ),
            );
        }

        fn cmdline(&self, pid: i32, args: &[&str]) {
            let joined: String = args.iter().map(|a| format!("{a}\0")).collect();
            self.proc_file(&format!("{pid}/cmdline"), &joined);
        }

        fn unit(&self, path: &str, usage_usec: u64, memory: u64) {
            let dir = self.roots().cgroup.join(path);
            write(
                &dir.join("cpu.stat"),
                &format!("usage_usec {usage_usec}\nuser_usec 1\nsystem_usec 2\n"),
            );
            write(&dir.join("memory.current"), &format!("{memory}\n"));
        }

        fn unified(&self) {
            write(
                &self.roots().cgroup.join("cgroup.controllers"),
                "cpu memory io\n",
            );
        }

        fn interface(&self, name: &str, state: &str, physical: bool, counters: &[(&str, u64)]) {
            let dir = self.roots().net.join(name);
            write(&dir.join("operstate"), &format!("{state}\n"));
            for counter in ["rx_errors", "tx_errors", "rx_dropped", "tx_dropped"] {
                let value = counters
                    .iter()
                    .find(|(n, _)| *n == counter)
                    .map_or(0, |(_, v)| *v);
                write(&dir.join("statistics").join(counter), &format!("{value}\n"));
            }
            if physical {
                std::fs::create_dir_all(dir.join("device")).unwrap();
            }
        }
    }

    const CLOCK: Clock = Clock {
        ticks: 100.0,
        page_size: 4096,
    };

    // ---- resource_top: parsing ---------------------------------------------------

    #[test]
    fn parse_cpu_times_groups_the_kernels_counters() {
        let stat = "cpu  100 20 50 800 30 4 6 10 0 0\ncpu0 50 10 25 400 15 2 3 5 0 0\nintr 1 2 3\n";
        assert_eq!(
            parse_cpu_times(stat),
            Some(CpuTimes {
                user: 120,
                system: 60,
                iowait: 30,
                steal: 10,
                idle: 800,
            })
        );
        assert_eq!(count_cpus(stat), 1);
        assert_eq!(
            count_cpus("cpu  1 2 3 4\ncpu0 1\ncpu1 1\ncpu10 1\ncpufreq x\n"),
            3
        );
        assert_eq!(parse_cpu_times("intr 1 2 3\n"), None);
        assert_eq!(parse_cpu_times("cpu  1 2\n"), None);
        assert_eq!(parse_cpu_times(""), None);
    }

    #[test]
    fn cpu_split_is_each_kind_of_time_as_a_share_of_the_interval() {
        let before = CpuTimes {
            user: 100,
            system: 50,
            iowait: 10,
            steal: 0,
            idle: 1000,
        };
        let after = CpuTimes {
            user: 150,
            system: 60,
            iowait: 20,
            steal: 5,
            idle: 1125,
        };
        let split = cpu_split(before, after).unwrap();
        assert_eq!(split, [25.0, 5.0, 5.0, 2.5, 62.5]);
        // no time passed, or counters went backwards: no answer rather than nonsense
        assert_eq!(cpu_split(after, after), None);
        assert_eq!(cpu_split(after, before), None);
    }

    #[test]
    fn parse_io_reads_storage_bytes_not_the_cancelled_ones() {
        let text = "rchar: 1\nwchar: 2\nsyscr: 3\nread_bytes: 4096\nwrite_bytes: 8192\ncancelled_write_bytes: 7\n";
        assert_eq!(parse_io(text), Some((4096, 8192)));
        assert_eq!(parse_io("read_bytes: 1\n"), None);
        assert_eq!(parse_io(""), None);
    }

    #[test]
    fn parse_pressure_takes_the_ten_second_averages() {
        let text = "some avg10=1.50 avg60=0.20 avg300=0.05 total=123\nfull avg10=0.75 avg60=0.10 avg300=0.01 total=45\n";
        assert_eq!(
            parse_pressure(text),
            (Some("1.50".to_string()), Some("0.75".to_string()))
        );
        // the cpu file has no "full" line on older kernels
        assert_eq!(
            parse_pressure("some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"),
            (Some("0.00".to_string()), None)
        );
        assert_eq!(parse_pressure(""), (None, None));
        // only numbers are passed on
        assert_eq!(parse_pressure("some avg10=[x] avg60=0\n"), (None, None));
    }

    #[test]
    fn parse_usage_usec_reads_cpu_stat() {
        assert_eq!(
            parse_usage_usec("usage_usec 123456\nuser_usec 1\nsystem_usec 2\n"),
            Some(123_456)
        );
        assert_eq!(parse_usage_usec("user_usec 1\n"), None);
    }

    // ---- resource_top: sampling ----------------------------------------------------

    /// Two samples of a made-up machine, three seconds apart.
    fn two_samples() -> (FakeSystem, Snapshot, Snapshot) {
        let fake = FakeSystem::new();
        fake.unified();
        fake.proc_file(
            "stat",
            "cpu  1000 0 500 8000 100 0 0 0 0 0\ncpu0 1 1 1 1\ncpu1 1 1 1 1\n",
        );
        fake.process(10, "web server", 1000, 500, 25_600);
        fake.io(10, 4096, 0);
        fake.cmdline(10, &["/usr/sbin/web", "--password=hunter2", "--port", "80"]);
        fake.process(20, "idle", 50, 600, 100);
        fake.process(40, "old", 5000, 100, 10);
        fake.unit("system.slice/nginx.service", 1_000_000, 64 << 20);
        fake.unit(
            "system.slice/system-postgresql.slice/postgresql@14-main.service",
            2_000_000,
            512 << 20,
        );
        fake.unit("machine.slice/libpod-abc.scope", 0, 1 << 20);
        fake.unit(
            "user.slice/user-1000.slice/session-1.scope",
            9_000_000,
            1 << 30,
        );
        let before = snapshot(&fake.roots());

        fake.proc_file(
            "stat",
            "cpu  1150 0 530 8405 115 0 0 0 0 0\ncpu0 1 1 1 1\ncpu1 1 1 1 1\n",
        );
        fake.process(10, "web server", 1300, 500, 25_600);
        fake.io(10, 4096 + 3 * 1_048_576, 6 * 1_048_576);
        // pid 30 started during the interval
        fake.process(30, "new", 30, 9000, 5);
        fake.io(30, 0, 300);
        // pid 40 is now a different process: the old one exited and the pid was reused
        fake.process(40, "reused", 10, 9500, 20);
        fake.unit("system.slice/nginx.service", 1_600_000, 80 << 20);
        fake.unit(
            "system.slice/system-postgresql.slice/postgresql@14-main.service",
            5_000_000,
            512 << 20,
        );
        let after = snapshot(&fake.roots());
        (fake, before, after)
    }

    fn row(rows: &[TopRow], pid: i32) -> &TopRow {
        rows.iter().find(|r| r.pid == pid).unwrap()
    }

    #[test]
    fn a_snapshot_reads_processes_cpu_counters_and_units() {
        let (_fake, before, after) = two_samples();
        assert_eq!(before.procs.len(), 3);
        assert_eq!(after.procs.len(), 4);
        assert_eq!(before.cpus, 2);
        assert_eq!(before.procs[&10].comm, "web server");
        assert_eq!(before.procs[&10].cpu_ticks, 1000);
        assert_eq!(before.procs[&10].io, Some((4096, 0)));
        assert_eq!(before.procs[&20].io, None);
        let units = before.units.as_ref().unwrap();
        // services and scopes of the system and machine slices, however deeply nested;
        // not the users' sessions
        let names: Vec<&str> = units.keys().map(String::as_str).collect();
        assert_eq!(
            names,
            [
                "libpod-abc.scope",
                "nginx.service",
                "postgresql@14-main.service"
            ]
        );
        assert_eq!(units["nginx.service"].cpu_usec, Some(1_000_000));
        assert_eq!(units["nginx.service"].memory, Some(64 << 20));
    }

    #[test]
    fn a_host_without_the_unified_cgroup_hierarchy_has_no_unit_figures() {
        let fake = FakeSystem::new();
        fake.unit("system.slice/nginx.service", 1, 1);
        assert!(snapshot(&fake.roots()).units.is_none());
    }

    #[test]
    fn top_rows_measure_what_each_process_used_during_the_interval() {
        let (_fake, before, after) = two_samples();
        let rows = top_rows(&before, &after, 3.0, 100.0);
        assert_eq!(rows.len(), 4);
        // 300 ticks at 100 per second is 3 s of CPU in 3 s: all of one CPU
        let web = row(&rows, 10);
        assert_eq!(web.cpu_percent, 100.0);
        assert_eq!(web.read_rate, Some(1_048_576.0));
        assert_eq!(web.write_rate, Some(2_097_152.0));
        // a process whose I/O cannot be read has no rate, not a rate of zero
        let idle = row(&rows, 20);
        assert_eq!(idle.cpu_percent, 0.0);
        assert_eq!((idle.read_rate, idle.write_rate), (None, None));
        // a process that started in the interval: everything it used counts
        let new = row(&rows, 30);
        assert_eq!(new.cpu_percent, 10.0);
        assert_eq!(new.write_rate, Some(100.0));
        // a reused pid is measured as the new process, never against the old one's total
        let reused = row(&rows, 40);
        assert!((reused.cpu_percent - 10.0 / 3.0).abs() < 1e-9, "{reused:?}");
        assert_eq!(reused.comm, "reused");
    }

    #[test]
    fn rows_can_be_ranked_by_cpu_memory_or_io() {
        let (_fake, before, after) = two_samples();
        let order = |sort: Sort| -> Vec<i32> {
            let mut rows = top_rows(&before, &after, 3.0, 100.0);
            sort_rows(&mut rows, sort);
            rows.iter().map(|r| r.pid).collect()
        };
        assert_eq!(order(Sort::Cpu), [10, 30, 40, 20]);
        assert_eq!(order(Sort::Mem), [10, 20, 40, 30]);
        // processes whose I/O is unknown come last
        assert_eq!(order(Sort::Io)[..2], [10, 30]);
        assert_eq!(Sort::parse("mem"), Sort::Mem);
        assert_eq!(Sort::parse("io"), Sort::Io);
        assert_eq!(Sort::parse("cpu"), Sort::Cpu);
    }

    #[test]
    fn unit_rows_measure_each_units_cpu_over_the_interval() {
        let (_fake, before, after) = two_samples();
        let rows = unit_rows(&before, &after, 3.0).unwrap();
        let unit = |name: &str| rows.iter().find(|r| r.name == name).unwrap();
        // 3,000,000 us of CPU in 3 s
        assert_eq!(unit("postgresql@14-main.service").cpu_percent, Some(100.0));
        assert_eq!(unit("nginx.service").cpu_percent, Some(20.0));
        assert_eq!(unit("nginx.service").memory, Some(80 << 20));
        assert_eq!(unit("libpod-abc.scope").cpu_percent, Some(0.0));
    }

    #[test]
    fn the_units_are_left_out_for_a_caller_who_may_not_see_units() {
        // AIDEV-NOTE: unit names (and container scopes) are service.view information.
        // process.view alone does not show them, as nowhere else does.
        let (fake, before, after) = two_samples();
        let text = render_top(
            &fake.roots(),
            &before,
            &after,
            3.0,
            CLOCK,
            Sort::Cpu,
            2,
            false,
        );
        assert!(text.contains("COMMAND"), "{text}");
        assert!(!text.contains("nginx.service"), "{text}");
        assert!(!text.contains("libpod-abc.scope"), "{text}");
        assert!(text.contains("service.view"), "{text}");
    }

    #[test]
    fn the_top_report_shows_the_split_the_processes_and_the_units() {
        let (fake, before, after) = two_samples();
        let text = render_top(
            &fake.roots(),
            &before,
            &after,
            3.0,
            CLOCK,
            Sort::Cpu,
            2,
            true,
        );
        // of the 600 ticks both CPUs had: 150 user, 30 system, 15 iowait, 405 idle
        assert!(text.starts_with("Sampled for 3.0 s on 2 CPUs"), "{text}");
        assert!(
            text.contains("25.0% user, 5.0% system, 2.5% iowait, 0.0% steal, 67.5% idle"),
            "{text}"
        );
        let lines: Vec<&str> = text.lines().collect();
        let header = lines.iter().position(|l| l.contains("COMMAND")).unwrap();
        assert!(lines[header].contains("%CPU") && lines[header].contains("WRITE/s"));
        let first: Vec<&str> = lines[header + 1].split_whitespace().collect();
        assert_eq!(first[0], "10");
        assert_eq!(first[2], "100.0");
        // resident memory: 25,600 pages of 4 KiB
        assert!(lines[header + 1].contains("100.0 MiB"), "{text}");
        assert!(lines[header + 1].contains("1.0 MiB"), "{text}");
        // secrets on the command line are masked, as process_list masks them
        assert!(
            lines[header + 1].ends_with("/usr/sbin/web --password=<redacted> --port 80"),
            "{text}"
        );
        assert!(!text.contains("hunter2"), "{text}");
        // a process without a command line is shown by name
        assert!(lines[header + 2].ends_with("[new]"), "{text}");
        // only `limit` rows, and the note says of how many
        assert!(!text.contains("[idle]"), "{text}");
        assert!(text.contains("top 2 of 4 processes by cpu"), "{text}");
        // units, busiest first
        let units = lines.iter().position(|l| l.starts_with("UNIT")).unwrap();
        assert!(
            lines[units + 1].starts_with("postgresql@14-main.service"),
            "{text}"
        );
        assert!(lines[units + 1].contains("100.0") && lines[units + 1].contains("512.0 MiB"));
        assert!(lines[units + 2].starts_with("nginx.service"), "{text}");
        assert!(text.contains("top 2 of 3 units"), "{text}");
    }

    #[test]
    fn the_top_report_says_so_when_units_cannot_be_measured() {
        let fake = FakeSystem::new();
        fake.process(10, "web", 100, 500, 10);
        let before = snapshot(&fake.roots());
        let after = snapshot(&fake.roots());
        let text = render_top(
            &fake.roots(),
            &before,
            &after,
            1.0,
            CLOCK,
            Sort::Mem,
            5,
            true,
        );
        assert!(text.contains("unified (v2) cgroup hierarchy"), "{text}");
        assert!(!text.contains("UNIT"), "{text}");
        // no /proc/stat and no pressure files: those lines are simply absent
        assert!(!text.contains("CPU:"), "{text}");
        assert!(!text.contains("Pressure"), "{text}");
        assert!(text.contains("top 1 of 1 processes by mem"), "{text}");
    }

    #[test]
    fn a_process_that_exited_after_the_sample_is_not_described_from_a_reused_pid() {
        let (fake, before, after) = two_samples();
        // after the second sample, pid 10 is taken by something else
        fake.process(10, "impostor", 1, 99_999, 1);
        fake.cmdline(10, &["/bin/impostor", "--flag"]);
        let text = render_top(
            &fake.roots(),
            &before,
            &after,
            3.0,
            CLOCK,
            Sort::Cpu,
            1,
            true,
        );
        assert!(text.contains("[web server] (exited)"), "{text}");
        assert!(!text.contains("impostor"), "{text}");
    }

    #[test]
    fn pressure_is_reported_when_the_kernel_provides_it() {
        let fake = FakeSystem::new();
        fake.proc_file("pressure/cpu", "some avg10=1.50 avg60=0 avg300=0 total=0\n");
        fake.proc_file(
            "pressure/memory",
            "some avg10=0.00 avg60=0 avg300=0 total=0\nfull avg10=0.25 avg60=0 avg300=0 total=0\n",
        );
        assert_eq!(
            pressure_line(&fake.roots()).as_deref(),
            Some("cpu 1.50, memory 0.00 (full 0.25)")
        );
        assert_eq!(pressure_line(&FakeSystem::new().roots()), None);
    }

    // ---- fixtures for the tools ------------------------------------------------------

    fn fixture(fake: &FakeBins) -> (Arc<Host>, MemorySink) {
        fixture_with(fake, "")
    }

    /// The fixture with more configuration added (limits, for example).
    fn fixture_with(fake: &FakeBins, extra: &str) -> (Arc<Host>, MemorySink) {
        host(&format!(
            r#"
[roles.admin]
allow = ["@all"]
[roles.reader]
allow = ["@read"]
[roles.sysonly]
allow = ["system.view"]
[roles.nojournal]
allow = ["@read"]
deny = ["journal.view"]
[roles.partjournal]
allow = ["@read"]
deny = ["journal.view:secret.service"]
[roles.nginxlogs]
allow = ["journal.view:nginx.service"]
[unix_users.adam]
roles = ["admin"]
[unix_users.rita]
roles = ["reader"]
[unix_users.sam]
roles = ["sysonly"]
[unix_users.nora]
roles = ["nojournal"]
[unix_users.pat]
roles = ["partjournal"]
[unix_users.nina]
roles = ["nginxlogs"]
{extra}
{}"#,
            fake.config_only()
        ))
    }

    fn denied(result: ToolResult) -> String {
        match result {
            Err(ToolError::Denied(message)) => message,
            other => panic!("expected a denial, got {other:?}"),
        }
    }

    fn failed_text(result: ToolResult) -> String {
        match result {
            Ok(output) if output.is_error() => output.into_parts().0,
            other => panic!("expected a reported failure, got {other:?}"),
        }
    }

    // ---- resource_top: the tool -------------------------------------------------------

    #[tokio::test]
    async fn resource_top_samples_the_real_machine() {
        let (host, sink) = fixture(&FakeBins::new());
        let tool = find(tools(), "resource_top");
        let text = ok_text(call(&host, "rita", &tool, json!({"seconds": 1, "limit": 3})).await);
        assert!(text.starts_with("Sampled for "), "{text}");
        assert!(text.contains("COMMAND"), "{text}");
        assert!(text.contains("processes by cpu"), "{text}");
        let records = sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["decision"], "allow");
        assert_eq!(records[0]["permission"], "process.view");
    }

    #[tokio::test]
    async fn resource_top_needs_process_view() {
        let (host, _sink) = fixture(&FakeBins::new());
        let tool = find(tools(), "resource_top");
        let message = denied(call(&host, "sam", &tool, json!({})).await);
        assert!(message.contains("process.view"), "{message}");
    }

    // ---- log_summary --------------------------------------------------------------------

    #[test]
    fn the_message_normaliser_is_usable() {
        assert!(NORMALISER.is_some());
    }

    #[test]
    fn messages_are_grouped_by_their_shape_not_their_numbers() {
        let cases = [
            (
                "Failed password for root from 10.0.0.5 port 4242 ssh2",
                "Failed password for root from IP port N sshN",
            ),
            (
                "Failed password for root from 192.168.17.200 port 51234 ssh2",
                "Failed password for root from IP port N sshN",
            ),
            ("pid=1234 took 15ms", "pid=N took Nms"),
            (
                "request 550e8400-e29b-41d4-a716-446655440000 done",
                "request UUID done",
            ),
            (
                "commit 9fceb02d0ae598e95dc970b74767f19372d61af8 ok",
                "commit H ok",
            ),
            ("at 0x7ffd1234abcd in main", "at H in main"),
            // a long number is a number whether or not it could be read as hex
            ("sent 123456789 bytes", "sent N bytes"),
            ("sent 1234567 bytes", "sent N bytes"),
            // a word that happens to consist of hex letters stays a word
            ("the facade was defaced", "the facade was defaced"),
            ("deadbeef", "deadbeef"),
            ("  spread   over\n  lines\t", "spread over lines"),
            ("", ""),
        ];
        for (message, want) in cases {
            assert_eq!(normalize_message(message), want, "{message:?}");
        }
        let long = "word ".repeat(100);
        assert_eq!(normalize_message(&long).chars().count(), 200);
    }

    #[test]
    fn the_journal_is_asked_for_the_newest_entries_of_the_window() {
        let opts = LogOpts {
            minutes: 90,
            unit: Some("nginx.service".to_string()),
            priority: Some("warning".to_string()),
            entries: 500,
            top: 15,
        };
        assert_eq!(
            summary_argv(&opts),
            [
                "--no-pager",
                "--quiet",
                "--reverse",
                "--all",
                "--output=json",
                "--output-fields=MESSAGE,PRIORITY,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER",
                "--since=-90min",
                "--lines=500",
                "--unit=nginx.service",
                "--priority=warning",
            ]
        );
        let all = LogOpts {
            minutes: 60,
            unit: None,
            priority: None,
            entries: 10_000,
            top: 15,
        };
        assert_eq!(summary_argv(&all).len(), 8);
    }

    fn entry(unit: Option<&str>, identifier: &str, priority: &str, message: &str) -> String {
        let mut value = json!({
            "__CURSOR": "s=1",
            "__REALTIME_TIMESTAMP": "1763632800000000",
            "SYSLOG_IDENTIFIER": identifier,
            "PRIORITY": priority,
            "MESSAGE": message,
        });
        if let Some(unit) = unit {
            value["_SYSTEMD_UNIT"] = json!(unit);
        }
        format!("{value}\n")
    }

    fn sample_journal() -> String {
        let mut text = String::new();
        for (address, port) in [(5, 4242), (6, 4243), (7, 4244)] {
            text.push_str(&entry(
                Some("ssh.service"),
                "sshd",
                "3",
                &format!("Failed password for root from 10.0.0.{address} port {port} ssh2"),
            ));
        }
        text.push_str(&entry(
            Some("nginx.service"),
            "nginx",
            "4",
            "upstream timed out",
        ));
        text.push_str(&entry(
            Some("nginx.service"),
            "nginx",
            "6",
            "GET /health 200",
        ));
        text.push_str(&entry(
            Some("nginx.service"),
            "nginx",
            "6",
            "GET /health 200",
        ));
        text.push_str(&entry(
            None,
            "backup",
            "6",
            "starting with --password=hunter2 --target /srv",
        ));
        text
    }

    #[test]
    fn summarize_counts_by_source_and_severity_and_groups_messages() {
        let summary = summarize(sample_journal().as_bytes());
        assert_eq!((summary.total, summary.errors, summary.warnings), (7, 3, 1));
        assert_eq!(summary.unreadable, 0);
        assert_eq!(
            summary.sources["ssh.service"],
            SourceCount {
                errors: 3,
                warnings: 0,
                total: 3
            }
        );
        assert_eq!(
            summary.sources["nginx.service"],
            SourceCount {
                errors: 0,
                warnings: 1,
                total: 3
            }
        );
        // an entry of no unit goes by its syslog identifier
        // AIDEV-NOTE: an entry with no unit is filed under the name its sender chose for
        // itself, and any local user can choose any name. It is marked, so that it cannot
        // pass for the unit of that name.
        assert_eq!(summary.sources["backup (syslog id)"].total, 1);
        let groups = summary.ranked_groups();
        // errors first, then by how often
        assert_eq!(groups[0].source, "ssh.service");
        assert_eq!((groups[0].count, groups[0].worst), (3, 3));
        // the example is the first seen (the newest, as the journal is read newest first)
        assert_eq!(
            groups[0].example,
            "Failed password for root from 10.0.0.5 port 4242 ssh2"
        );
        assert_eq!(
            (groups[1].source.as_str(), groups[1].worst),
            ("nginx.service", 4)
        );
        assert_eq!((groups[2].count, groups[2].worst), (2, 6));
        assert_eq!(groups.len(), 4);
        // a secret in a logged command line never reaches the summary
        let all: String = groups.iter().map(|g| g.example.clone()).collect();
        assert!(all.contains("--password=<redacted>"), "{all}");
        assert!(!all.contains("hunter2"), "{all}");
        assert_eq!(summary.oldest_usec, Some(1_763_632_800_000_000));
    }

    #[test]
    fn summarize_copes_with_every_form_the_journal_gives_a_field_in() {
        let lines = [
            // a message that is not valid UTF-8 comes as an array of bytes
            r#"{"PRIORITY":"3","SYSLOG_IDENTIFIER":"app","MESSAGE":[111,111,112,115]}"#,
            // a field given twice comes as an array of strings
            r#"{"PRIORITY":"4","SYSLOG_IDENTIFIER":["app","other"],"MESSAGE":["first","second"]}"#,
            // no message, no priority, no source
            r#"{"MESSAGE":null}"#,
            // a priority that is not a level
            r#"{"PRIORITY":"99","SYSLOG_IDENTIFIER":"app","MESSAGE":"odd"}"#,
            // not an entry at all, and a line cut off by the size limit
            r#"[1,2,3]"#,
            r#"{"PRIORITY":"3","MESSAGE":"cut of"#,
            "",
        ]
        .join("\n");
        let summary = summarize(lines.as_bytes());
        assert_eq!(summary.total, 4);
        assert_eq!(summary.unreadable, 2);
        assert_eq!((summary.errors, summary.warnings), (1, 1));
        assert_eq!(summary.sources["app (syslog id)"].total, 3);
        assert_eq!(summary.sources["(unknown)"].total, 1);
        let groups = summary.ranked_groups();
        assert_eq!(groups[0].example, "oops");
        assert_eq!(groups[1].example, "first");
        // an entry without a message says so, rather than showing an empty example
        assert!(
            groups.iter().any(|g| g.example == "(no message)"),
            "{groups:?}"
        );
    }

    #[test]
    fn an_enormous_entry_is_counted_but_not_parsed() {
        // AIDEV-NOTE: a message of binary data comes as a JSON array of numbers, which
        // takes many times its size to parse. An entry longer than the limit is counted
        // and left alone.
        let bytes = vec!["120"; MAX_ENTRY_BYTES / 4 + 1].join(",");
        let huge = format!(r#"{{"PRIORITY":"3","SYSLOG_IDENTIFIER":"app","MESSAGE":[{bytes}]}}"#);
        assert!(huge.len() > MAX_ENTRY_BYTES);
        let text = format!(
            "{}{huge}\n{}",
            entry(None, "app", "6", "one"),
            entry(None, "app", "6", "two")
        );
        let summary = summarize(text.as_bytes());
        assert_eq!(
            (summary.total, summary.oversized, summary.unreadable),
            (2, 1, 0)
        );
        assert_eq!(summary.errors, 0);
        let opts = LogOpts {
            minutes: 60,
            unit: None,
            priority: None,
            entries: 100,
            top: 5,
        };
        let report = render_summary(&summary, &opts, false);
        assert!(report.contains("1 very large"), "{report}");
    }

    #[test]
    fn a_summary_of_output_that_was_cut_says_what_it_covers() {
        let summary = summarize(sample_journal().as_bytes());
        let opts = LogOpts {
            minutes: 60,
            unit: None,
            priority: None,
            entries: 10_000,
            top: 5,
        };
        let whole = render_summary(&summary, &opts, false);
        assert!(!whole.contains("only the newest"), "{whole}");
        let cut = render_summary(&summary, &opts, true);
        assert!(cut.contains("printed more than is kept"), "{cut}");
        assert!(cut.contains("only the newest 7 entries"), "{cut}");
        assert!(cut.contains("2025-11-20T10:00:00Z"), "{cut}");
        // raising `entries` would not help here, so it is not suggested
        assert!(!cut.contains("raise entries"), "{cut}");
    }

    #[test]
    fn a_huge_message_is_cut_before_it_is_examined() {
        // long, but not so long that the whole entry is set aside
        let big = "x".repeat(100_000);
        let summary = summarize(entry(None, "app", "6", &big).as_bytes());
        let groups = summary.ranked_groups();
        assert!(
            groups[0].example.chars().count() <= 203,
            "{}",
            groups[0].example.len()
        );
    }

    #[tokio::test]
    async fn log_summary_turns_the_journal_into_counts_and_groups() {
        let fake = FakeBins::new().add("journalctl", &sample_journal(), 0);
        let (host, sink) = fixture(&fake);
        let tool = find(tools(), "log_summary");
        let text = ok_text(call(&host, "rita", &tool, json!({})).await);
        assert!(
            text.starts_with("Journal, last 60 minutes: 7 entries (3 at err or worse, 1 at warning) from 3 sources."),
            "{text}"
        );
        let lines: Vec<&str> = text.lines().collect();
        let sources = lines.iter().position(|l| l.starts_with("SOURCE")).unwrap();
        // busiest first; a tie is broken by name
        let cells: Vec<&str> = lines[sources + 1].split_whitespace().collect();
        assert_eq!(cells, ["nginx.service", "0", "1", "3"]);
        let cells: Vec<&str> = lines[sources + 2].split_whitespace().collect();
        assert_eq!(cells, ["ssh.service", "3", "0", "3"]);
        let groups = lines.iter().position(|l| l.contains("EXAMPLE")).unwrap();
        let cells: Vec<&str> = lines[groups + 1].split_whitespace().collect();
        assert_eq!(cells[..3], ["3", "err", "ssh.service"]);
        assert!(
            lines[groups + 1].contains("Failed password for root"),
            "{text}"
        );
        assert!(lines[groups + 2].contains("warning"), "{text}");
        assert!(!text.contains("hunter2"), "{text}");
        assert!(!text.contains("only the newest"), "{text}");
        // what was asked of journalctl
        assert_eq!(
            fake.calls("journalctl"),
            [[
                "--no-pager",
                "--quiet",
                "--reverse",
                "--all",
                "--output=json",
                "--output-fields=MESSAGE,PRIORITY,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER",
                "--since=-60min",
                "--lines=10000",
            ]]
        );
        let records = sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["permission"], "journal.view");
        assert!(records[0].get("resource").is_none());
    }

    #[tokio::test]
    async fn log_summary_for_one_unit_is_judged_by_that_unit() {
        let fake = FakeBins::new().add("journalctl", &sample_journal(), 0);
        let (host, sink) = fixture(&fake);
        let tool = find(tools(), "log_summary");
        // nina may see nginx's journal only
        let args =
            json!({"unit": "nginx", "minutes": 5, "priority": "err", "entries": 100, "top": 3});
        let text = ok_text(call(&host, "nina", &tool, args).await);
        assert!(
            text.starts_with("Journal, last 5 minutes, unit nginx.service, err or worse:"),
            "{text}"
        );
        assert_eq!(sink.records()[0]["resource"], "nginx.service");
        let calls = fake.calls("journalctl");
        assert_eq!(calls.len(), 1);
        assert!(
            calls[0].contains(&"--unit=nginx.service".to_string()),
            "{calls:?}"
        );
        assert!(
            calls[0].contains(&"--priority=err".to_string()),
            "{calls:?}"
        );
        assert!(calls[0].contains(&"--since=-5min".to_string()), "{calls:?}");
        assert!(calls[0].contains(&"--lines=100".to_string()), "{calls:?}");
        // everything, or another unit: refused, and journalctl is not run
        denied(call(&host, "nina", &tool, json!({})).await);
        denied(call(&host, "nina", &tool, json!({"unit": "ssh.service"})).await);
        assert_eq!(fake.calls("journalctl").len(), 1);
        // a deny for one unit takes away the summary of everything
        denied(call(&host, "pat", &tool, json!({})).await);
        denied(call(&host, "pat", &tool, json!({"unit": "secret.service"})).await);
        assert_eq!(fake.calls("journalctl").len(), 1);
        // and a unit name is held to the same rules as everywhere else
        let bad = call(&host, "adam", &tool, json!({"unit": "--file=/etc/shadow"})).await;
        assert!(matches!(bad, Err(ToolError::Invalid(_))), "{bad:?}");
        assert_eq!(fake.calls("journalctl").len(), 1);
    }

    #[tokio::test]
    async fn log_summary_says_when_the_entries_examined_do_not_cover_the_window() {
        let line = entry(Some("app.service"), "app", "6", "tick 1");
        let fake = FakeBins::new().add("journalctl", &line.repeat(100), 0);
        let (host, _sink) = fixture(&fake);
        let tool = find(tools(), "log_summary");
        let text = ok_text(call(&host, "rita", &tool, json!({"entries": 100})).await);
        assert!(
            text.starts_with("Journal, last 60 minutes: 100 entries (0 at err or worse, 0 at warning) from 1 source."),
            "{text}"
        );
        assert!(text.contains("only the newest 100 entries"), "{text}");
        assert!(text.contains("2025-11-20T10:00:00Z"), "{text}");
        // with room to spare there is no such note
        let text = ok_text(call(&host, "rita", &tool, json!({"entries": 101})).await);
        assert!(!text.contains("only the newest"), "{text}");
    }

    #[tokio::test]
    async fn log_summary_of_an_empty_window_is_an_answer() {
        // journalctl --quiet prints nothing and exits 1 when nothing matched
        let fake = FakeBins::new().add("journalctl", "", 1);
        let (host, _sink) = fixture(&fake);
        let tool = find(tools(), "log_summary");
        let text = ok_text(call(&host, "rita", &tool, json!({})).await);
        assert_eq!(text, "(no journal entries in the last 60 minutes)\n");
    }

    #[tokio::test]
    async fn log_summary_reports_a_journalctl_failure() {
        let fake =
            FakeBins::new().add_script("journalctl", "echo 'Failed to open journal' >&2; exit 1");
        let (host, _sink) = fixture(&fake);
        let tool = find(tools(), "log_summary");
        let text = failed_text(call(&host, "rita", &tool, json!({})).await);
        assert!(text.contains("Failed to open journal"), "{text}");
        // no journalctl at all is a plain failure too
        let (host, _sink) = fixture(&FakeBins::new());
        let result = call(&host, "rita", &tool, json!({})).await;
        assert!(matches!(result, Err(ToolError::Failed(_))), "{result:?}");
    }

    // ---- crash_events -------------------------------------------------------------------

    /// As `journalctl --reverse` prints them: the newest first.
    const KERNEL_LINES: &str = "\
2026-11-20T04:00:00+0000 web3 kernel: Memory cgroup out of memory: Killed process 5151 (php-fpm) total-vm:1000kB
2026-11-20T03:00:00+0000 web3 kernel: app[777]: segfault at 0 ip 00007f1 sp 00007ff error 4 in libc.so
2026-11-19T22:10:01+0000 web3 kernel: Out of memory: Killed process 4242 (java) total-vm:8000000kB, anon-rss:6000000kB
2026-11-19T22:10:01+0000 web3 kernel: oom-kill:constraint=CONSTRAINT_NONE,task_memcg=/system.slice/app.service,task=java,pid=4242,uid=33
";

    /// As `coredumpctl --reverse` prints them: the newest first, columns padded.
    const COREDUMPS: &str = "\
Fri 2026-11-20 03:00:01 UTC 888 33 33 SIGABRT present /usr/bin/other 2.0M      \n\
Thu 2026-11-19 22:11:00 UTC 777 33 33 SIGSEGV present /usr/bin/app 1.2M        \n";

    #[test]
    fn kernel_crash_lines_are_asked_for_across_boots() {
        let argv = crash_argv(36);
        assert_eq!(
            argv[..5],
            [
                "--no-pager",
                "--quiet",
                "--reverse",
                "--output=short-iso",
                "--since=-36h"
            ]
        );
        let grep = argv.iter().find(|a| a.starts_with("--grep=")).unwrap();
        // not every line that mentions the OOM killer: one kill would be three lines
        assert!(!grep.contains("oom-kill|"), "{grep}");
        for needle in [
            "Out of memory",
            "oom-kill:",
            "Killed process",
            "segfault at",
            "general protection fault",
        ] {
            assert!(grep.contains(needle), "{grep}");
        }
        // a match on the kernel transport rather than --dmesg, which means this boot only
        assert_eq!(argv.last().map(String::as_str), Some("_TRANSPORT=kernel"));
        assert!(!argv.iter().any(|a| a == "--dmesg" || a == "-k"));
    }

    #[test]
    fn oom_kills_are_counted_once_each() {
        let lines: Vec<String> = KERNEL_LINES.lines().map(str::to_string).collect();
        assert_eq!(count_oom_kills(&lines), 2);
        assert_eq!(count_oom_kills(&[]), 0);
    }

    #[test]
    fn the_crash_directory_is_listed_newest_first_within_the_window() {
        let dir = tempfile::tempdir().unwrap();
        let now = now_secs();
        let touch = |name: &str, age_secs: i64, size: usize| {
            let path = dir.path().join(name);
            std::fs::write(&path, vec![b'x'; size]).unwrap();
            let when =
                std::time::UNIX_EPOCH + Duration::from_secs(u64::try_from(now - age_secs).unwrap());
            std::fs::File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_modified(when)
                .unwrap();
        };
        touch("_usr_bin_old.0.crash", 10 * 3600, 5);
        touch("_usr_bin_app.33.crash", 3600, 2048);
        touch("_usr_bin_new.0.crash", 60, 10);
        touch("ancient.crash", 40 * 86_400, 1);
        std::fs::create_dir(dir.path().join("subdir")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", dir.path().join("link.crash")).unwrap();

        let (recent, older) = list_crash_dir(dir.path(), now - 24 * 3600).unwrap();
        let names: Vec<&str> = recent.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "_usr_bin_new.0.crash",
                "_usr_bin_app.33.crash",
                "_usr_bin_old.0.crash"
            ]
        );
        assert_eq!(recent[1].size, 2048);
        // older files are counted; directories and links are not files
        assert_eq!(older, 1);
        assert!(list_crash_dir(&dir.path().join("missing"), 0).is_none());
    }

    fn crash_fakes() -> FakeBins {
        FakeBins::new()
            .add("journalctl", KERNEL_LINES, 0)
            .add_script(
                "coredumpctl",
                &format!(
                    r#"
case "$1" in
  list) printf '%s' '{COREDUMPS}' ;;
  info)
    echo "           PID: $3 (app)"
    echo "  Command Line: /usr/bin/app --password=hunter2 --serve"
    echo "       Message: Process $3 (app) of user 33 dumped core." ;;
esac
"#
                ),
            )
    }

    async fn crash_report(host: &Arc<Host>, user: &str, roots: &Roots, hours: i64) -> ToolResult {
        let ctx = testing::ctx(host, user, "crash.view", Access::Read);
        let auth = ctx.authorize(None)?;
        crash_events_in(&ctx, auth, roots, hours).await
    }

    #[tokio::test]
    async fn crash_events_reports_kernel_kills_core_dumps_and_crash_files() {
        let fake = crash_fakes();
        let (host, _sink) = fixture(&fake);
        let system = FakeSystem::new();
        write(
            &system.roots().crash.join("_usr_bin_app.33.crash"),
            "report",
        );
        let text = ok_text(crash_report(&host, "rita", &system.roots(), 48).await);
        assert!(text.contains("last 48 h"), "{text}");
        assert!(text.contains("2 out-of-memory kills"), "{text}");
        assert!(text.contains("Killed process 4242 (java)"), "{text}");
        assert!(text.contains("segfault at 0"), "{text}");
        // the padding coredumpctl adds to its last column is not kept
        assert!(
            text.contains("SIGSEGV present /usr/bin/app 1.2M\n"),
            "{text}"
        );
        assert!(text.contains("_usr_bin_app.33.crash"), "{text}");
        // both lists read in time order, the newest last, whatever order they came in
        let at = |needle: &str| {
            text.find(needle)
                .unwrap_or_else(|| panic!("{needle}: {text}"))
        };
        assert!(at("Killed process 4242") < at("segfault at 0"), "{text}");
        assert!(at("segfault at 0") < at("Killed process 5151"), "{text}");
        assert!(
            at("/usr/bin/app 1.2M") < at("/usr/bin/other 2.0M"),
            "{text}"
        );
        // the sections come in a fixed order
        let kernel = text.find("Kernel").unwrap();
        let dumps = text.find("Core dumps").unwrap();
        let files = text.find("Crash reports").unwrap();
        assert!(kernel < dumps && dumps < files, "{text}");
        let journal = fake.calls("journalctl");
        assert_eq!(journal.len(), 1);
        assert!(
            journal[0].contains(&"--since=-48h".to_string()),
            "{journal:?}"
        );
        assert!(
            journal[0].contains(&"_TRANSPORT=kernel".to_string()),
            "{journal:?}"
        );
        assert_eq!(
            fake.calls("coredumpctl"),
            [[
                "list",
                "--no-pager",
                "--no-legend",
                "--reverse",
                "--since=-48h"
            ]]
        );
    }

    #[tokio::test]
    async fn crash_events_says_so_plainly_when_there_is_nothing() {
        let fake = FakeBins::new()
            .add("journalctl", "", 1)
            .add_script("coredumpctl", "echo 'No coredumps found.' >&2; exit 1");
        let (host, _sink) = fixture(&fake);
        let system = FakeSystem::new();
        let text = ok_text(crash_report(&host, "rita", &system.roots(), 24).await);
        assert!(text.contains("none found"), "{text}");
        assert!(text.contains("Core dumps"), "{text}");
        assert!(text.contains("none recorded"), "{text}");
        assert!(text.contains("there is no"), "{text}");
        assert!(!text.contains("No coredumps found"), "{text}");
    }

    #[tokio::test]
    async fn crash_events_skips_what_is_not_installed_and_reports_what_fails() {
        // neither journalctl nor coredumpctl
        let (host, _sink) = fixture(&FakeBins::new());
        let system = FakeSystem::new();
        std::fs::create_dir_all(system.roots().crash).unwrap();
        let text = ok_text(crash_report(&host, "rita", &system.roots(), 24).await);
        assert!(text.contains("journalctl"), "{text}");
        assert!(text.contains("coredumpctl is not installed"), "{text}");
        assert!(text.contains("no crash reports"), "{text}");
        // a journalctl that fails is reported in its section, not as a failed call
        let fake =
            FakeBins::new().add_script("journalctl", "echo 'Failed to open journal' >&2; exit 1");
        let (host, _sink) = fixture(&fake);
        let text = ok_text(crash_report(&host, "rita", &system.roots(), 24).await);
        assert!(text.contains("Failed to open journal"), "{text}");
    }

    #[tokio::test]
    async fn crash_events_keeps_the_newest_lines_within_the_output_limit() {
        // 300 kills, printed newest first as journalctl --reverse does
        let fake = FakeBins::new().add_script(
            "journalctl",
            r#"i=300; while [ $i -gt 0 ]; do echo "2026-11-20T00:00:00+0000 web3 kernel: Out of memory: Killed process $i (job)"; i=$((i-1)); done"#,
        );
        let (host, _sink) = fixture_with(&fake, "[limits]\nmax_output_bytes = 4096\n");
        let system = FakeSystem::new();
        // and more crash report files than there is room to list
        for n in 0..40 {
            let name = format!("_usr_lib_some_long_program_name_{n:02}.1000.crash");
            write(&system.roots().crash.join(name), "report");
        }
        let text = ok_text(crash_report(&host, "rita", &system.roots(), 24).await);
        assert!(text.len() <= 4096 - 512, "{} bytes", text.len());
        assert!(text.contains("left out to fit the output limit"), "{text}");
        assert!(
            text.contains("300 lines, 300 out-of-memory kills"),
            "{text}"
        );
        assert!(text.contains("Killed process 300 (job)"), "{text}");
        assert!(!text.contains("Killed process 1 (job)"), "{text}");
        assert!(text.contains("earlier lines left out"), "{text}");
        // the sections after the long one are still there
        assert!(text.contains("Core dumps"), "{text}");
        assert!(text.contains("Crash reports"), "{text}");
    }

    #[tokio::test]
    async fn a_kernel_search_that_was_cut_short_says_so() {
        // some lines, then journalctl gives up
        let fake = FakeBins::new().add_script(
            "journalctl",
            "echo '2026-11-20T04:00:00+0000 web3 kernel: Out of memory: Killed process 5151 (php-fpm)'\n\
             echo 'Failed to iterate through journal: Bad message' >&2; exit 1",
        );
        let (host, _sink) = fixture(&fake);
        let system = FakeSystem::new();
        let text = ok_text(crash_report(&host, "rita", &system.roots(), 24).await);
        assert!(text.contains("Killed process 5151"), "{text}");
        assert!(
            text.contains("[journalctl: Failed to iterate through journal: Bad message"),
            "{text}"
        );
        let text = ok_text(snapshot_for(&host, "rita", &snapshot_roots(&system)).await);
        assert!(text.contains("1 out-of-memory kills"), "{text}");
        assert!(text.contains("there may be more"), "{text}");
    }

    #[tokio::test]
    async fn crash_events_shows_one_core_dump_with_secrets_masked() {
        let fake = crash_fakes();
        let (host, _sink) = fixture(&fake);
        let tool = find(tools(), "crash_events");
        let text = ok_text(call(&host, "rita", &tool, json!({"pid": 777})).await);
        assert!(
            text.contains("Process 777 (app) of user 33 dumped core"),
            "{text}"
        );
        assert!(text.contains("--password=<redacted>"), "{text}");
        assert!(!text.contains("hunter2"), "{text}");
        assert_eq!(fake.calls("coredumpctl"), [["info", "--no-pager", "777"]]);
        assert!(fake.calls("journalctl").is_empty());
        // without coredumpctl there are no details to show
        let (host, _sink) = fixture(&FakeBins::new());
        let result = call(&host, "rita", &tool, json!({"pid": 777})).await;
        match result {
            Err(ToolError::Failed(message)) => {
                assert!(message.contains("systemd-coredump"), "{message}")
            }
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn crash_events_runs_nothing_without_the_permission() {
        let fake = crash_fakes();
        let (host, sink) = fixture(&fake);
        let tool = find(tools(), "crash_events");
        let message = denied(call(&host, "sam", &tool, json!({})).await);
        assert!(message.contains("crash.view"), "{message}");
        denied(call(&host, "sam", &tool, json!({"pid": 777})).await);
        assert!(fake.calls("journalctl").is_empty());
        assert!(fake.calls("coredumpctl").is_empty());
        assert_eq!(sink.records()[0]["decision"], "deny");
    }

    // ---- incident_snapshot --------------------------------------------------------------

    #[test]
    fn a_filesystem_is_flagged_when_space_or_inodes_run_low() {
        let gib = 1u64 << 30;
        // 92% of the space used
        let line = fs_alert("/var", 100 * gib, 92 * gib, 8 * gib, 1000, 900).unwrap();
        assert!(line.starts_with("/var: 92% of 100.0 GiB used"), "{line}");
        assert!(line.contains("8.0 GiB free"), "{line}");
        // plenty of space but nearly out of inodes
        let line = fs_alert("/srv", 100 * gib, 10 * gib, 90 * gib, 1000, 50).unwrap();
        assert!(line.contains("inodes 95%"), "{line}");
        // exactly at the threshold counts
        assert!(fs_alert("/a", 100, 85, 15, 0, 0).is_some());
        // comfortable, or a filesystem that does not count inodes
        assert_eq!(
            fs_alert("/", 100 * gib, 50 * gib, 50 * gib, 1000, 500),
            None
        );
        assert_eq!(fs_alert("/", 100 * gib, 84 * gib, 16 * gib, 0, 0), None);
    }

    #[test]
    fn interfaces_with_errors_or_a_dead_link_are_flagged() {
        let fake = FakeSystem::new();
        fake.interface("eth0", "up", true, &[("rx_errors", 12), ("tx_dropped", 3)]);
        fake.interface("eth1", "down", true, &[]);
        fake.interface("eth2", "up", true, &[]);
        // a virtual interface that is down is normal (an unused bridge, a stopped tunnel)
        fake.interface("docker0", "down", false, &[]);
        fake.interface("lo", "unknown", false, &[("rx_dropped", 5)]);
        // not an interface: the bonding driver's control file
        write(&fake.roots().net.join("bonding_masters"), "bond0\n");
        assert_eq!(
            net_alerts(&fake.roots().net),
            Some(vec![
                "eth0: rx_errors 12, tx_dropped 3".to_string(),
                "eth1: link is down".to_string(),
            ])
        );
        assert_eq!(net_alerts(&fake.roots().net.join("missing")), None);
    }

    /// Stand-ins for the commands the snapshot runs. journalctl answers as the kernel
    /// log or as the journal depending on what it is asked.
    fn snapshot_fakes() -> FakeBins {
        let mut journal = String::new();
        for line in sample_journal().lines().take(3) {
            journal.push_str(&format!("    printf '%s\\n' '{line}'\n"));
        }
        let mut kernel = String::new();
        for line in KERNEL_LINES.lines() {
            kernel.push_str(&format!("    printf '%s\\n' '{line}'\n"));
        }
        FakeBins::new()
            .add_script(
                "journalctl",
                &format!("case \"$*\" in\n  *_TRANSPORT=kernel*)\n{kernel}    ;;\n  *)\n{journal}    ;;\nesac"),
            )
            .add(
                "systemctl",
                "backup.service loaded failed failed Nightly backup\n",
                0,
            )
    }

    async fn snapshot_for(host: &Arc<Host>, user: &str, roots: &Roots) -> ToolResult {
        let ctx = testing::ctx(host, user, "system.view", Access::Read);
        let auth = ctx.authorize(None)?;
        incident_snapshot_in(&ctx, auth, roots, Duration::from_millis(30)).await
    }

    /// The real /proc (the system and process sections read it), made-up interfaces.
    fn snapshot_roots(fake: &FakeSystem) -> Roots {
        Roots {
            net: fake.roots().net,
            ..Roots::default()
        }
    }

    #[tokio::test]
    async fn the_snapshot_has_every_section_for_a_caller_who_may_see_them_all() {
        let fake = snapshot_fakes();
        let (host, sink) = fixture(&fake);
        let system = FakeSystem::new();
        system.interface("eth0", "up", true, &[("rx_errors", 12)]);
        let text = ok_text(snapshot_for(&host, "rita", &snapshot_roots(&system)).await);
        assert!(text.starts_with("Incident snapshot of "), "{text}");
        let order: Vec<usize> = [
            "== System ==",
            "== Processes ==",
            "== Failed units ==",
            "== Journal errors, last 15 min ==",
            "== Kernel kills and crashes, last 24 h ==",
            "== Network ==",
        ]
        .iter()
        .map(|title| {
            text.find(title)
                .unwrap_or_else(|| panic!("no {title} in {text}"))
        })
        .collect();
        assert!(order.windows(2).all(|pair| pair[0] < pair[1]), "{text}");
        assert!(text.contains("Load: "), "{text}");
        assert!(text.contains("Memory: "), "{text}");
        assert!(text.contains("By CPU over"), "{text}");
        assert!(text.contains("By memory:"), "{text}");
        assert!(text.contains("backup.service loaded failed"), "{text}");
        assert!(text.contains("3 entries at err or worse"), "{text}");
        assert!(text.contains("Failed password for root"), "{text}");
        assert!(text.contains("2 out-of-memory kills"), "{text}");
        assert!(text.contains("newest: 2026-11-20T04:00:00+0000"), "{text}");
        assert!(text.contains("eth0: rx_errors 12"), "{text}");
        assert!(!text.contains("left out"), "{text}");
        // what was asked of the commands
        assert_eq!(
            fake.calls("systemctl"),
            [[
                "list-units",
                "--state=failed",
                "--no-legend",
                "--plain",
                "--no-pager"
            ]]
        );
        let journal = fake.calls("journalctl");
        assert_eq!(journal.len(), 2, "{journal:?}");
        let errors = journal
            .iter()
            .find(|c| c.contains(&"--output=json".to_string()))
            .unwrap();
        assert!(errors.contains(&"--priority=err".to_string()), "{errors:?}");
        assert!(errors.contains(&"--since=-15min".to_string()), "{errors:?}");
        // one audit record: the snapshot itself
        assert_eq!(sink.records().len(), 1);
    }

    #[tokio::test]
    async fn the_snapshot_leaves_out_what_the_caller_may_not_see() {
        let fake = snapshot_fakes();
        let (host, _sink) = fixture(&fake);
        let system = FakeSystem::new();
        system.interface("eth0", "up", true, &[("rx_errors", 12)]);
        // sam holds system.view and nothing else
        let text = ok_text(snapshot_for(&host, "sam", &snapshot_roots(&system)).await);
        assert!(text.contains("Load: "), "{text}");
        for permission in [
            "process.view",
            "service.view",
            "journal.view",
            "crash.view",
            "net.view",
        ] {
            assert!(
                text.contains(&format!("[section left out: needs {permission}]")),
                "{permission}: {text}"
            );
        }
        assert!(!text.contains("By CPU"), "{text}");
        assert!(!text.contains("backup.service"), "{text}");
        assert!(!text.contains("Failed password"), "{text}");
        assert!(!text.contains("Killed process"), "{text}");
        assert!(!text.contains("eth0"), "{text}");
        // and nothing was run to find out what would have been in them
        assert!(fake.calls("systemctl").is_empty());
        assert!(fake.calls("journalctl").is_empty());
    }

    #[tokio::test]
    async fn the_snapshot_does_not_go_around_a_deny() {
        // AIDEV-NOTE: the property that matters most here. nora and pat hold @read, but
        // journal.view is denied to nora outright and to pat for one unit. Neither could
        // run journal_query for everything, so neither gets the journal section.
        for user in ["nora", "pat"] {
            let fake = snapshot_fakes();
            let (host, _sink) = fixture(&fake);
            let system = FakeSystem::new();
            let text = ok_text(snapshot_for(&host, user, &snapshot_roots(&system)).await);
            assert!(
                text.contains(
                    "== Journal errors, last 15 min ==\n[section left out: needs journal.view]"
                ),
                "{user}: {text}"
            );
            assert!(!text.contains("Failed password"), "{user}: {text}");
            // the other sections are unaffected
            assert!(
                text.contains("backup.service loaded failed"),
                "{user}: {text}"
            );
            assert!(text.contains("2 out-of-memory kills"), "{user}: {text}");
            let journal = fake.calls("journalctl");
            assert_eq!(journal.len(), 1, "{user}: {journal:?}");
            assert!(journal[0].contains(&"_TRANSPORT=kernel".to_string()));
        }
    }

    #[tokio::test]
    async fn the_snapshot_survives_missing_commands_and_quiet_systems() {
        // no systemctl, no journalctl
        let (host, _sink) = fixture(&FakeBins::new());
        let system = FakeSystem::new();
        system.interface("eth0", "up", true, &[]);
        let text = ok_text(snapshot_for(&host, "rita", &snapshot_roots(&system)).await);
        assert!(
            text.contains("== Failed units ==\n[not available: "),
            "{text}"
        );
        assert!(
            text.contains("== Journal errors, last 15 min ==\n[not available: "),
            "{text}"
        );
        assert!(
            text.contains("no interface reports errors or drops"),
            "{text}"
        );
        // commands that find nothing
        let fake = FakeBins::new()
            .add("journalctl", "", 1)
            .add("systemctl", "", 0);
        let (host, _sink) = fixture(&fake);
        let text = ok_text(snapshot_for(&host, "rita", &snapshot_roots(&system)).await);
        assert!(text.contains("== Failed units ==\nnone\n"), "{text}");
        assert!(
            text.contains("== Journal errors, last 15 min ==\nnone\n"),
            "{text}"
        );
        assert!(
            text.contains("== Kernel kills and crashes, last 24 h ==\nnone\n"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn the_state_of_a_call_that_runs_commands_side_by_side_stays_small() {
        // AIDEV-NOTE: every running command's future carries its read buffers (about
        // 18 KiB). Wrapped in a time limit and a permission gate and then joined, six of
        // them once made the snapshot's state over 200 KiB, and a test thread's 2 MiB
        // stack overflowed in a debug build. The parts are boxed; this keeps them so.
        let (host, _sink) = fixture(&FakeBins::new());
        let roots = Roots::default();
        let ctx = testing::ctx(&host, "rita", "system.view", Access::Read);
        let auth = ctx.authorize(None).unwrap();
        let snapshot = incident_snapshot_in(&ctx, auth, &roots, Duration::from_millis(1));
        let size = std::mem::size_of_val(&snapshot);
        assert!(size < 16 * 1024, "incident_snapshot_in is {size} bytes");
        let auth = ctx.authorize(None).unwrap();
        let crash = crash_events_in(&ctx, auth, &roots, 1);
        let size = std::mem::size_of_val(&crash);
        assert!(size < 16 * 1024, "crash_events_in is {size} bytes");
    }

    #[tokio::test]
    async fn a_part_that_does_not_finish_is_given_up_on() {
        let started = Instant::now();
        let stuck = async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            "never".to_string()
        };
        let text = within(Duration::from_millis(30), stuck).await;
        assert_eq!(text, "[not available: it did not finish in time]\n");
        assert!(started.elapsed() < Duration::from_secs(5));
        let quick = async { "done\n".to_string() };
        assert_eq!(within(Duration::from_secs(5), quick).await, "done\n");
    }

    #[tokio::test]
    async fn one_slow_command_does_not_hold_up_the_snapshot() {
        // a systemctl that never answers; every command gets one second
        let fake = FakeBins::new()
            .add_script("systemctl", "while :; do :; done")
            .add("journalctl", "", 1);
        let (host, _sink) = fixture_with(
            &fake,
            "[limits]\ncommand_timeout_secs = 1\ncall_timeout_secs = 60\n",
        );
        let system = FakeSystem::new();
        let started = Instant::now();
        let text = ok_text(snapshot_for(&host, "rita", &snapshot_roots(&system)).await);
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
        assert!(
            text.contains(
                "== Failed units ==\n[the command was stopped when it reached its time limit]"
            ),
            "{text}"
        );
        // everything else is there
        assert!(text.contains("Load: "), "{text}");
        assert!(text.contains("By memory:"), "{text}");
        assert!(
            text.contains("== Journal errors, last 15 min ==\nnone\n"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn incident_snapshot_is_a_system_view_tool_that_takes_no_arguments() {
        let (host, sink) = fixture(&snapshot_fakes());
        let tool = find(tools(), "incident_snapshot");
        assert_eq!(tool.permission, "system.view");
        assert!(tool.params.is_empty());
        let text = ok_text(call(&host, "sam", &tool, json!({})).await);
        assert!(text.contains("== System =="), "{text}");
        assert_eq!(sink.records()[0]["permission"], "system.view");
        // nina holds no system.view at all
        let message = denied(call(&host, "nina", &tool, json!({})).await);
        assert!(message.contains("system.view"), "{message}");
    }

    #[test]
    fn the_tools_are_read_tools_with_the_intended_permissions() {
        let listed: Vec<(String, String, Access)> = tools()
            .into_iter()
            .map(|t| (t.name, t.permission, t.access))
            .collect();
        let want = [
            ("resource_top", "process.view"),
            ("crash_events", "crash.view"),
            ("log_summary", "journal.view"),
            ("incident_snapshot", "system.view"),
        ];
        assert_eq!(listed.len(), want.len());
        for ((name, permission, access), (want_name, want_permission)) in listed.iter().zip(want) {
            assert_eq!(
                (name.as_str(), permission.as_str()),
                (want_name, want_permission)
            );
            assert_eq!(*access, Access::Read);
        }
    }
}
