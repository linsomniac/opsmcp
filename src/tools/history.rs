//! What changed, and what the machine looked like earlier.

use std::collections::BTreeMap;
use std::ffi::CStr;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, fstat, openat, statat};
use serde_json::{Map, Value};

use super::args::{Args, Param};
use super::fs::{denied_by, inside};
use super::{
    CallClock, Ctx, Tool, ToolError, ToolResult, blocking, command_ok, command_text, format_table,
};
use crate::exec::{Cmd, CmdOutput};
use crate::policy::Access;
use crate::sanitize::{keep_head, keep_tail, redact_text};
use crate::timefmt::{now_secs, parse_date, utc_parts};

/// Where the history tools look. Parameters, so that tests can point them elsewhere.
#[derive(Clone, Debug)]
pub struct Places {
    /// The directory holding `dpkg.log` and its rotated copies.
    pub dpkg_log_dir: PathBuf,
    /// The configuration tree searched for changed files.
    pub etc: PathBuf,
    /// `/proc/stat`, for the boot time when there is no journal.
    pub proc_stat: PathBuf,
    /// The directories sysstat keeps its daily files in.
    pub sar_dirs: Vec<PathBuf>,
    /// The directory atop keeps its daily files in.
    pub atop_dir: PathBuf,
}

impl Places {
    pub fn system() -> Places {
        Places {
            dpkg_log_dir: PathBuf::from("/var/log"),
            etc: PathBuf::from("/etc"),
            proc_stat: PathBuf::from("/proc/stat"),
            sar_dirs: vec![
                PathBuf::from("/var/log/sysstat"),
                PathBuf::from("/var/log/sa"),
            ],
            atop_dir: PathBuf::from("/var/log/atop"),
        }
    }
}

const KINDS: [&str; 6] = ["all", "packages", "boots", "units", "config", "sudo"];
const METRICS: [&str; 7] = [
    "overview", "cpu", "memory", "swap", "load", "disk", "network",
];

pub fn tools() -> Vec<Tool> {
    tools_with(Places::system())
}

pub fn tools_with(places: Places) -> Vec<Tool> {
    let places = Arc::new(places);
    let changes = places.clone();
    let performance = places;
    vec![
        Tool::new(
            "change_history",
            "Show what changed on this host recently, as one timeline, oldest first: packages \
             installed, upgraded or removed, boots, services that were started, stopped, \
             restarted or that failed, files changed under /etc, and commands run through \
             sudo. Use it first when something broke and the question is \"what changed?\". \
             Events that repeat (a timer's service, a monitoring check using sudo) are \
             folded into one line with a count. A part whose data belongs to another \
             permission is left out and says which permission it needs.",
            Access::Read,
            "history.view",
            vec![
                Param::int("hours", "How far back to look (default 24)", 1, 720),
                Param::choice("kind", "Only this kind of change (default all)", &KINDS),
                Param::int(
                    "limit",
                    "Most events to show; the newest are kept (default 150)",
                    10,
                    500,
                ),
            ],
            move |ctx, args| change_history(changes.clone(), ctx, args),
        ),
        Tool::new(
            "perf_history",
            "Show what the machine looked like at a past time: CPU, memory, swap, load, disk \
             or network figures recorded by sysstat (sar) or, failing that, atop. Use it to \
             answer \"what was happening at 03:00?\"; resource_top and incident_snapshot \
             only show the present. Times are this host's local time. Needs sysstat's or \
             atop's collector to have been running at the time.",
            Access::Read,
            "history.view",
            vec![
                Param::str("date", "The day, as YYYY-MM-DD (default today)").max_len(10),
                Param::str(
                    "start",
                    "Start of the period, HH:MM local time (default: an hour before the end \
                     today, 00:00 on another day)",
                )
                .max_len(5),
                Param::str(
                    "end",
                    "End of the period, HH:MM local time (default: now today, 23:59 on \
                     another day)",
                )
                .max_len(5),
                Param::choice(
                    "metric",
                    "What to show (default overview: CPU, memory, load and I/O)",
                    &METRICS,
                ),
            ],
            move |ctx, args| perf_history(performance.clone(), ctx, args),
        ),
    ]
}

// ---- time -----------------------------------------------------------------------------
//
// AIDEV-NOTE: there is no time-zone database here. Every event is kept as Unix seconds;
// local times are read and shown with ONE offset from UTC, the one `date +%z` reports
// now. If the period spans a change between summer and winter time, times before the
// change are an hour off, and the report says so. That is accepted for the sake of not
// carrying a time-zone library.

/// The offset from UTC in seconds, from `date +%z` output such as `-0700`.
pub fn parse_offset(text: &str) -> Option<i64> {
    let bytes = text.trim().as_bytes();
    let [sign, digits @ ..] = bytes else {
        return None;
    };
    if digits.len() != 4 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let number = |pair: &[u8]| -> i64 {
        pair.iter()
            .fold(0, |total, digit| total * 10 + i64::from(digit - b'0'))
    };
    let (hours, minutes) = (number(digits.get(..2)?), number(digits.get(2..)?));
    if hours > 15 || minutes > 59 {
        return None;
    }
    let seconds = hours * 3600 + minutes * 60;
    match sign {
        b'+' => Some(seconds),
        b'-' => Some(-seconds),
        _ => None,
    }
}

/// An offset as it is usually written: `UTC-07:00`.
pub fn offset_label(offset: i64) -> String {
    let sign = if offset < 0 { '-' } else { '+' };
    let minutes = offset.abs() / 60;
    format!("UTC{sign}{:02}:{:02}", minutes / 60, minutes % 60)
}

/// Unix seconds as local date and time: `2026-11-20 10:00:00`.
pub fn local_stamp(unix: i64, offset: i64) -> String {
    let t = utc_parts(unix.saturating_add(offset));
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        t.year, t.month, t.day, t.hour, t.minute, t.second
    )
}

/// Two digits at `at`, if that is what is there.
fn two_digits(bytes: &[u8], at: usize) -> Option<i64> {
    match bytes.get(at..at + 2)? {
        [a, b] if a.is_ascii_digit() && b.is_ascii_digit() => {
            Some(i64::from(a - b'0') * 10 + i64::from(b - b'0'))
        }
        _ => None,
    }
}

/// A local `YYYY-MM-DD` and `HH:MM:SS` as Unix seconds.
pub fn parse_local(date: &str, time: &str, offset: i64) -> Option<i64> {
    let day = parse_date(date)?;
    let bytes = time.as_bytes();
    if bytes.len() != 8 || bytes.get(2) != Some(&b':') || bytes.get(5) != Some(&b':') {
        return None;
    }
    let (hour, minute, second) = (
        two_digits(bytes, 0)?,
        two_digits(bytes, 3)?,
        two_digits(bytes, 6)?,
    );
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    Some(day + hour * 3600 + minute * 60 + second - offset)
}

/// `HH:MM` as minutes since midnight.
pub fn parse_hhmm(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() != 5 || bytes.get(2) != Some(&b':') {
        return None;
    }
    let (hour, minute) = (two_digits(bytes, 0)?, two_digits(bytes, 3)?);
    (hour <= 23 && minute <= 59).then_some(hour * 60 + minute)
}

fn hhmm(minute: i64) -> String {
    format!("{:02}:{:02}", minute / 60, minute % 60)
}

/// Why a part could not be produced, in a few words.
fn reason(error: ToolError) -> String {
    match error {
        ToolError::Denied(text) | ToolError::Invalid(text) | ToolError::Failed(text) => text,
        ToolError::Internal(_) => "an internal error".to_string(),
    }
}

/// Runs a command with what is left of the call's time. `None` when there is no time
/// left or it could not be started.
async fn run_limited(ctx: &Ctx, clock: &CallClock, cmd: Cmd) -> Option<CmdOutput> {
    let limit = clock.next()?;
    ctx.run(cmd.timeout(limit)).await.ok()
}

/// This host's offset from UTC now, and notes about how far it can be trusted. With
/// `earlier`, the offset at that time is asked for too, to notice a clock change.
async fn utc_offset(ctx: &Ctx, clock: &CallClock, earlier: Option<i64>) -> (i64, Vec<String>) {
    let unavailable = (
        0,
        vec!["[the date command is not available here: times are UTC]".to_string()],
    );
    let Ok(Some(date)) = ctx.optional_command("date") else {
        return unavailable;
    };
    let now = run_limited(ctx, clock, date.args(["+%z"]))
        .await
        .filter(command_ok)
        .and_then(|out| parse_offset(&String::from_utf8_lossy(&out.stdout)));
    let Some(now) = now else {
        return unavailable;
    };
    let mut notes = Vec::new();
    if let Some(earlier) = earlier
        && let Ok(Some(date)) = ctx.optional_command("date")
    {
        let then = run_limited(
            ctx,
            clock,
            date.args(["-d".to_string(), format!("@{earlier}"), "+%z".to_string()]),
        )
        .await
        .filter(command_ok)
        .and_then(|out| parse_offset(&String::from_utf8_lossy(&out.stdout)));
        if then.is_some_and(|then| then != now) {
            notes.push(
                "[the clock changed between summer and winter time in this period: times \
                 before the change may be shown an hour off]"
                    .to_string(),
            );
        }
    }
    (now, notes)
}

// ---- change_history: events -----------------------------------------------------------

/// What kind of change an event is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Package,
    Boot,
    Unit,
    Config,
    Sudo,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Package => "package",
            Kind::Boot => "boot",
            Kind::Unit => "unit",
            Kind::Config => "config",
            Kind::Sudo => "sudo",
        }
    }

    /// "3 package changes", "1 boot".
    fn counted(self, count: usize) -> String {
        let (one, many) = match self {
            Kind::Package => ("package change", "package changes"),
            Kind::Boot => ("boot", "boots"),
            Kind::Unit => ("unit event", "unit events"),
            Kind::Config => ("changed config file", "changed config files"),
            Kind::Sudo => ("use of sudo", "uses of sudo"),
        };
        format!("{count} {}", if count == 1 { one } else { many })
    }
}

/// One thing that happened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// Unix seconds.
    pub time: i64,
    pub kind: Kind,
    pub what: String,
}

/// `text` on one line: every run of whitespace and control characters is one space.
fn one_line(text: &str) -> String {
    text.split(|c: char| c.is_whitespace() || c.is_control())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
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

// ---- packages

const DPKG_ACTIONS: [&str; 4] = ["install", "upgrade", "remove", "purge"];
/// How many dpkg logs are read at most, and how much of each.
const MAX_DPKG_FILES: usize = 6;
const MAX_DPKG_BYTES: u64 = 8 << 20;

/// An action line of dpkg.log: `DATE TIME upgrade PACKAGE OLD NEW`, in local time.
pub fn parse_dpkg_line(line: &str, offset: i64) -> Option<Event> {
    let mut fields = line.split_whitespace();
    let (date, time, action) = (fields.next()?, fields.next()?, fields.next()?);
    if !DPKG_ACTIONS.contains(&action) {
        return None;
    }
    let (package, old, new) = (fields.next()?, fields.next()?, fields.next()?);
    let time = parse_local(date, time, offset)?;
    let (package, old, new) = (cut(package, 100), cut(old, 60), cut(new, 60));
    let what = match action {
        "remove" | "purge" => format!("{action} {package} {old}"),
        _ if old == "<none>" => format!("{action} {package} {new}"),
        _ => format!("{action} {package} {old} -> {new}"),
    };
    Some(Event {
        time,
        kind: Kind::Package,
        what,
    })
}

/// A line of `rpm -qa --qf '%{INSTALLTIME}\t%{NAME}-...\n'`.
pub fn parse_rpm_line(line: &str) -> Option<Event> {
    let (time, name) = line.split_once('\t')?;
    let time: u32 = time.trim().parse().ok()?;
    let name = one_line(name);
    if name.is_empty() {
        return None;
    }
    Some(Event {
        time: i64::from(time),
        kind: Kind::Package,
        what: format!("install or upgrade {}", cut(&name, 120)),
    })
}

/// Events that come in a burst (more than 30, each within a minute of the one before)
/// become one line that counts them and names the first few. An upgrade of two hundred
/// packages is one change, not two hundred.
pub fn collapse_runs(mut events: Vec<Event>, noun: &str) -> Vec<Event> {
    const BURST: usize = 30;
    const GAP_SECS: i64 = 60;
    const EXAMPLES: usize = 3;
    events.sort_by_key(|event| event.time);
    let mut out = Vec::with_capacity(events.len());
    let mut run: Vec<Event> = Vec::new();
    let flush = |run: &mut Vec<Event>, out: &mut Vec<Event>| {
        let (Some(first), Some(last)) = (run.first(), run.last()) else {
            return;
        };
        if run.len() <= BURST {
            out.append(run);
            return;
        }
        let minutes = ((last.time - first.time + 59) / 60).max(1);
        let examples: Vec<&str> = run
            .iter()
            .take(EXAMPLES)
            .map(|event| event.what.as_str())
            .collect();
        out.push(Event {
            time: first.time,
            kind: first.kind,
            what: format!(
                "{} {noun} within {minutes} minute{}, e.g. {}",
                run.len(),
                if minutes == 1 { "" } else { "s" },
                examples.join("; ")
            ),
        });
        run.clear();
    };
    for event in events {
        if run
            .last()
            .is_some_and(|previous| event.time - previous.time > GAP_SECS)
        {
            flush(&mut run, &mut out);
        }
        run.push(event);
    }
    flush(&mut run, &mut out);
    out
}

/// The names dpkg's log goes by, newest first; each rotated copy may be compressed.
pub fn dpkg_log_names() -> Vec<Vec<String>> {
    let mut names = vec![vec!["dpkg.log".to_string()]];
    for n in 1..=12 {
        names.push(vec![format!("dpkg.log.{n}"), format!("dpkg.log.{n}.gz")]);
    }
    names
}

/// Opens a regular file for reading without following a link or blocking on a FIFO.
fn open_plain(path: &Path) -> Option<std::fs::File> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY;
    let file =
        std::fs::File::from(rustix::fs::open(path, flags | OFlags::CLOEXEC, Mode::empty()).ok()?);
    file.metadata().ok()?.is_file().then_some(file)
}

/// The most that is decompressed of one rotated log, however little of it is kept.
const MAX_UNPACKED_BYTES: u64 = 16 * MAX_DPKG_BYTES;

/// The LAST `max` bytes of a file's text (decompressed first when `gzip`), from the start
/// of a line, and whether anything before them was left out.
///
/// AIDEV-NOTE: the end, not the start: a log is appended to, so when there is more than
/// is read the part to give up is the oldest. A plain file is read from `size - max`. A
/// compressed one cannot be entered in the middle: it is decompressed from the start and
/// only the last `max` bytes are kept as they go by, up to MAX_UNPACKED_BYTES in all (an
/// archive that unpacks to more than that is given up on there, so what is kept is then
/// not its end; no real rotated log comes near it).
fn read_tail(mut file: std::fs::File, gzip: bool, max: u64) -> (String, bool) {
    let keep = usize::try_from(max).unwrap_or(usize::MAX);
    let mut bytes = Vec::new();
    let mut cut = false;
    // An error part of the way through (a damaged archive) keeps what was read.
    if gzip {
        let mut unpacked = flate2::read::MultiGzDecoder::new(file).take(MAX_UNPACKED_BYTES);
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            match unpacked.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    bytes.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
                    // Let it grow to twice what is kept before shifting, so that the
                    // copying stays in proportion to what is read.
                    if bytes.len() > keep.saturating_mul(2) {
                        let surplus = bytes.len().saturating_sub(keep);
                        bytes.drain(..surplus);
                        cut = true;
                    }
                }
            }
        }
        if bytes.len() > keep {
            let surplus = bytes.len().saturating_sub(keep);
            bytes.drain(..surplus);
            cut = true;
        }
    } else {
        let size = file.metadata().map(|meta| meta.len()).unwrap_or(0);
        let skip = size.saturating_sub(max);
        if skip > 0 && file.seek(SeekFrom::Start(skip)).is_ok() {
            cut = true;
        }
        let _ = file.take(max).read_to_end(&mut bytes);
    }
    if cut {
        // what is kept begins in the middle of a line: drop that line's remainder
        let line_end = bytes.iter().position(|byte| *byte == b'\n');
        match line_end {
            Some(at) => {
                bytes.drain(..=at);
            }
            None => bytes.clear(),
        }
    }
    (String::from_utf8_lossy(&bytes).into_owned(), cut)
}

/// The package events since `start` in dpkg's logs, and notes about what could not be
/// read. `None` when this host has no dpkg log at all.
fn read_dpkg_logs(dir: &Path, start: i64, offset: i64) -> Option<(Vec<Event>, Vec<String>)> {
    let mut events = Vec::new();
    let mut notes = Vec::new();
    let mut found_any = false;
    let mut read = 0;
    for (position, names) in dpkg_log_names().iter().enumerate() {
        let opened = names
            .iter()
            .find_map(|name| open_plain(&dir.join(name)).map(|file| (name, file)));
        let Some((name, file)) = opened else {
            if position == 0 {
                continue; // just rotated: the first copy may still be there
            }
            break;
        };
        found_any = true;
        // Rotated logs only get older: one last written before the period ends the search.
        if file.metadata().is_ok_and(|meta| meta.mtime() < start) {
            break;
        }
        if read == MAX_DPKG_FILES {
            notes.push(format!(
                "[only the {MAX_DPKG_FILES} newest dpkg logs were read: earlier package \
                 changes in this period are missing]"
            ));
            break;
        }
        read += 1;
        let (text, cut) = read_tail(file, name.ends_with(".gz"), MAX_DPKG_BYTES);
        if cut {
            notes.push(format!(
                "[{name} is larger than {} MiB: only its last part, with the newest events, \
                 was read]",
                MAX_DPKG_BYTES >> 20
            ));
        }
        events.extend(
            text.lines()
                .filter_map(|line| parse_dpkg_line(line, offset))
                .filter(|event| event.time >= start),
        );
    }
    found_any.then_some((events, notes))
}

// ---- boots

/// One boot of the machine, as the journal records it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Boot {
    /// 0 is the current boot, -1 the one before.
    pub index: i64,
    /// Unix seconds of its first and last journal entries.
    pub first: i64,
    pub last: i64,
}

/// `journalctl --list-boots`: JSON from systemd 251 on, a table before that. Times in
/// the table are local unless marked UTC.
pub fn parse_boots(text: &str, offset: i64) -> Vec<Boot> {
    let mut boots = Vec::new();
    if text.trim_start().starts_with('[') {
        let Ok(Value::Array(items)) = serde_json::from_str::<Value>(text) else {
            return boots;
        };
        let seconds = |value: Option<&Value>| -> Option<i64> {
            let usec = match value? {
                Value::Number(number) => number.as_u64()?,
                Value::String(digits) => digits.parse().ok()?,
                _ => return None,
            };
            i64::try_from(usec / 1_000_000).ok()
        };
        for item in &items {
            let found = (|| {
                Some(Boot {
                    index: item.get("index")?.as_i64()?,
                    first: seconds(item.get("first_entry"))?,
                    last: seconds(item.get("last_entry"))?,
                })
            })();
            boots.extend(found);
        }
    } else {
        for line in text.lines() {
            // Older versions put a dash between the two times.
            let line = line.replace('\u{2014}', " ");
            let tokens: Vec<&str> = line.split_whitespace().collect();
            let Some(index) = tokens.first().and_then(|token| token.parse::<i64>().ok()) else {
                continue;
            };
            let mut times = Vec::new();
            for (at, pair) in tokens.windows(2).enumerate() {
                let [date, time] = pair else { continue };
                let zone = tokens.get(at + 2).copied().unwrap_or("");
                let offset = if zone == "UTC" || zone == "GMT" {
                    0
                } else {
                    offset
                };
                times.extend(parse_local(date, time, offset));
            }
            if let [first, last] = times[..] {
                boots.push(Boot { index, first, last });
            }
        }
    }
    boots.sort_by_key(|boot| boot.index);
    boots
}

/// The boots that began in the period, and the stops before them.
pub fn boot_events(boots: &[Boot], start: i64) -> Vec<Event> {
    let mut events = Vec::new();
    for (at, boot) in boots.iter().enumerate() {
        if boot.first >= start {
            events.push(Event {
                time: boot.first,
                kind: Kind::Boot,
                what: "the system booted".to_string(),
            });
        }
        // The last entry of a boot that another one followed: when the machine went down
        // (cleanly or not; the journal cannot tell which).
        if at + 1 < boots.len() && boot.last >= start {
            events.push(Event {
                time: boot.last,
                kind: Kind::Boot,
                what: "the system went down (last journal entry before the next boot)".to_string(),
            });
        }
    }
    events.sort_by_key(|event| event.time);
    events
}

/// The boot time from `/proc/stat` (`btime N`), for a host without a journal.
fn boot_from_stat(text: &str, now: i64) -> Option<Boot> {
    let first = text
        .lines()
        .find_map(|line| line.strip_prefix("btime "))?
        .trim()
        .parse()
        .ok()?;
    Some(Boot {
        index: 0,
        first,
        last: now,
    })
}

// ---- the journal

/// The longest journal line that is looked at.
const MAX_ENTRY_BYTES: usize = 64 * 1024;

/// A journal field as text. journalctl prints a value that is not valid UTF-8 as an
/// array of bytes.
fn field(entry: &Map<String, Value>, name: &str) -> Option<String> {
    match entry.get(name)? {
        Value::String(text) => Some(text.clone()),
        Value::Array(items) => {
            let bytes: Option<Vec<u8>> = items
                .iter()
                .map(|item| item.as_u64().and_then(|byte| u8::try_from(byte).ok()))
                .collect();
            bytes
                .filter(|bytes| !bytes.is_empty())
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        }
        _ => None,
    }
}

/// When an entry was written, in Unix seconds.
fn entry_time(entry: &Map<String, Value>) -> Option<i64> {
    let usec: u64 = field(entry, "__REALTIME_TIMESTAMP")?.trim().parse().ok()?;
    i64::try_from(usec / 1_000_000).ok()
}

/// Calls `each` for every entry of `journalctl --output=json` output; returns how many
/// lines were not entries.
fn for_each_entry(stdout: &[u8], mut each: impl FnMut(&Map<String, Value>)) -> usize {
    let mut unreadable = 0;
    for line in stdout.split(|byte| *byte == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if line.len() > MAX_ENTRY_BYTES {
            unreadable += 1;
            continue;
        }
        match serde_json::from_slice::<Value>(line) {
            Ok(Value::Object(entry)) => each(&entry),
            _ => unreadable += 1,
        }
    }
    unreadable
}

/// The events found in one source, and how many there were before repeats were folded.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Found {
    pub events: Vec<Event>,
    pub total: usize,
    /// Lines that could not be read as journal entries.
    pub unreadable: usize,
}

/// One occurrence, before repeats are folded.
struct Raw {
    time: i64,
    /// Occurrences with the same key are the same event happening again.
    key: String,
    what: String,
    /// Never folded: every occurrence is shown.
    single: bool,
}

/// The same thing happening more than three times is shown once, at the time it last
/// happened, with a count and when it first did.
fn fold_repeats(kind: Kind, mut raws: Vec<Raw>, offset: i64) -> Vec<Event> {
    const REPEATS: usize = 3;
    raws.sort_by_key(|raw| raw.time);
    let mut seen: BTreeMap<&str, (usize, i64)> = BTreeMap::new();
    for raw in raws.iter().filter(|raw| !raw.single) {
        let (count, first) = seen.entry(raw.key.as_str()).or_insert((0, raw.time));
        *count += 1;
        *first = (*first).min(raw.time);
    }
    let mut left: BTreeMap<&str, usize> = BTreeMap::new();
    let mut events = Vec::new();
    for raw in &raws {
        let folded = seen
            .get(raw.key.as_str())
            .filter(|(count, _)| !raw.single && *count > REPEATS);
        match folded {
            None => events.push(Event {
                time: raw.time,
                kind,
                what: raw.what.clone(),
            }),
            Some((count, first)) => {
                // Only the last occurrence produces the line.
                let met = left.entry(raw.key.as_str()).or_insert(0);
                *met += 1;
                if met == count {
                    events.push(Event {
                        time: raw.time,
                        kind,
                        what: format!(
                            "{} [{count} times; first {}]",
                            raw.what,
                            local_stamp(*first, offset)
                        ),
                    });
                }
            }
        }
    }
    events
}

// ---- units

/// A unit name as systemd writes one (the characters `service::normalize_unit` accepts).
fn is_unit_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ":_.@\\-".contains(c))
}

/// A job type or result as systemd writes one.
fn is_word(text: &str) -> bool {
    !text.is_empty() && text.len() <= 32 && text.chars().all(|c| c.is_ascii_lowercase() || c == '-')
}

/// What an entry from the service manager says happened to a service: the unit, what
/// happened, and whether it is a failure. `None` for everything else it logs.
fn unit_change(entry: &Map<String, Value>) -> Option<(String, String, bool)> {
    let unit = field(entry, "UNIT")?;
    if !unit.ends_with(".service") || !is_unit_name(&unit) {
        return None;
    }
    let message = field(entry, "MESSAGE").unwrap_or_default();
    if let Some(job) = field(entry, "JOB_TYPE") {
        // An entry with a job but no result is the job beginning ("Starting ...").
        let result = field(entry, "JOB_RESULT")?;
        if !is_word(&job) || !is_word(&result) {
            return None;
        }
        if result != "done" {
            return Some((unit, format!("{job} FAILED ({result})"), true));
        }
        let label = match job.as_str() {
            // A service that runs to completion logs "Finished" for its start job.
            "start" if message.starts_with("Finished ") => "finished".to_string(),
            "start" => "started".to_string(),
            "stop" => "stopped".to_string(),
            "restart" | "try-restart" => "restarted".to_string(),
            "reload" | "try-reload" | "reload-or-start" => "reloaded".to_string(),
            other => format!("{other} done"),
        };
        return Some((unit, label, false));
    }
    if message.contains("Failed with result") || message.contains("Failed to start") {
        let said = message
            .strip_prefix(&format!("{unit}: "))
            .unwrap_or(&message);
        let said = cut(&one_line(&redact_text(said)), 160);
        return Some((unit, format!("FAILED: {said}"), true));
    }
    if message.contains("Scheduled restart job") {
        let label = "restart scheduled by systemd after it stopped".to_string();
        return Some((unit, label, false));
    }
    None
}

/// Service events since `start`, from `journalctl --output=json _PID=1`.
///
/// AIDEV-NOTE: `_PID=1` is set by journald, not by the sender, so these entries are the
/// service manager's own and their UNIT field can be trusted.
pub fn unit_events(stdout: &[u8], start: i64, offset: i64) -> Found {
    let mut raws = Vec::new();
    let unreadable = for_each_entry(stdout, |entry| {
        let Some(time) = entry_time(entry).filter(|time| *time >= start) else {
            return;
        };
        if let Some((unit, label, failure)) = unit_change(entry) {
            raws.push(Raw {
                time,
                key: format!("{unit}\u{1f}{label}"),
                what: format!("{unit} {label}"),
                single: failure,
            });
        }
    });
    Found {
        total: raws.len(),
        events: fold_repeats(Kind::Unit, raws, offset),
        unreadable,
    }
}

// ---- sudo

/// One use of sudo, from its log line.
#[derive(Debug, PartialEq, Eq)]
pub struct SudoUse {
    pub user: String,
    pub target: String,
    pub command: String,
    /// What sudo said went wrong ("command not allowed"), if anything.
    pub problem: Option<String>,
}

/// sudo's log line: `USER : [PROBLEM ;] TTY=... ; PWD=... ; USER=... ; COMMAND=...`.
///
/// AIDEV-NOTE: sudo does not escape the working directory or the command, so a user can
/// put ` ; USER=x ; COMMAND=y` in either and make the line ambiguous. The FIRST `USER=`
/// and everything after the FIRST `COMMAND=` are taken: whatever was forged, the text
/// shown still contains the real command.
pub fn parse_sudo(message: &str) -> Option<SudoUse> {
    let (user, rest) = message.split_once(" : ")?;
    let user = user.trim();
    if user.is_empty() || user.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    let (before, command) = rest.split_once("COMMAND=")?;
    let mut target = None;
    let mut problem = None;
    for part in before.split(" ; ") {
        let part = part.trim().trim_end_matches(';').trim();
        let key = part.split_once('=').map(|(key, _)| key);
        match key {
            Some("USER") => {
                if target.is_none() {
                    target = part.strip_prefix("USER=").map(str::to_string);
                }
            }
            Some(key) if !key.is_empty() && key.chars().all(|c| c.is_ascii_uppercase()) => {}
            _ if !part.is_empty() && problem.is_none() => problem = Some(part.to_string()),
            _ => {}
        }
    }
    Some(SudoUse {
        user: user.to_string(),
        target: target.unwrap_or_else(|| "?".to_string()),
        command: command.to_string(),
        problem,
    })
}

/// Uses of sudo since `start`, from the journal entries sudo wrote.
///
/// AIDEV-NOTE: commands carry passwords and tokens, so each goes through `redact_text`
/// before it is kept. These entries are what a program calling itself sudo logged: a
/// local user can forge one, so they are a lead, not proof.
pub fn sudo_events(stdout: &[u8], start: i64, offset: i64) -> Found {
    let mut raws = Vec::new();
    let unreadable = for_each_entry(stdout, |entry| {
        let Some(time) = entry_time(entry).filter(|time| *time >= start) else {
            return;
        };
        let Some(used) = field(entry, "MESSAGE").and_then(|message| parse_sudo(&message)) else {
            return;
        };
        let user = cut(&one_line(&used.user), 64);
        let target = cut(&one_line(&used.target), 64);
        let command = cut(&one_line(&redact_text(&used.command)), 160);
        let problem = used
            .problem
            .map(|problem| format!(" ({})", cut(&one_line(&problem), 60)))
            .unwrap_or_default();
        let what = format!("{user} as {target}{problem}: {command}");
        raws.push(Raw {
            time,
            key: what.clone(),
            what,
            single: false,
        });
    });
    Found {
        total: raws.len(),
        events: fold_repeats(Kind::Sudo, raws, offset),
        unreadable,
    }
}

// ---- changed files

/// The files found changed, and whether the search had to stop early.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Changed {
    /// Modification time and path.
    pub files: Vec<(i64, String)>,
    pub incomplete: bool,
}

/// How deep the search goes.
const MAX_LEVELS: usize = 16;

fn child_path(parent: &str, name: &CStr) -> String {
    let name = name.to_string_lossy();
    if parent.ends_with('/') {
        format!("{parent}{name}")
    } else {
        format!("{parent}/{name}")
    }
}

/// The regular files under `root` modified at or after `start`.
///
/// AIDEV-NOTE: the walk never follows a symbolic link and stays on one filesystem: every
/// directory entered was looked up in the directory above it, relative to that
/// directory's descriptor. It runs in a blocking job, which cannot be cancelled, so it
/// stops by itself at `deadline` or after `max_entries` entries. A directory that
/// `denied` matches is not entered, and a file it matches is not named.
// The fields of `Stat` have different integer types on different architectures.
#[allow(clippy::unnecessary_cast)]
pub fn changed_files(
    root: &Path,
    start: i64,
    denied: &dyn Fn(&str) -> bool,
    deadline: Instant,
    max_entries: usize,
) -> Changed {
    let mut found = Changed::default();
    let flags =
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let Ok(top) = rustix::fs::open(root, flags, Mode::empty()) else {
        return found;
    };
    let Ok(dev) = fstat(&top).map(|stat| stat.st_dev as u64) else {
        return found;
    };
    let Ok(top) = Dir::new(top) else {
        return found;
    };
    // An explicit stack rather than recursion: a deep tree cannot overflow ours.
    let mut stack = vec![(top, root.display().to_string())];
    let mut entries = 0usize;
    loop {
        let depth = stack.len();
        let Some((dir, path)) = stack.last_mut() else {
            break;
        };
        if entries >= max_entries || (entries.is_multiple_of(64) && Instant::now() >= deadline) {
            found.incomplete = true;
            break;
        }
        let Some(Ok(entry)) = dir.read() else {
            stack.pop(); // the end of this directory, or an error reading it
            continue;
        };
        let name = entry.file_name();
        if name == c"." || name == c".." {
            continue;
        }
        entries += 1;
        let Ok(here) = dir.fd() else { continue };
        let Ok(stat) = statat(here, name, AtFlags::SYMLINK_NOFOLLOW) else {
            continue; // gone since it was listed
        };
        if stat.st_dev as u64 != dev {
            continue; // a mount point: another filesystem
        }
        let full = child_path(path, name);
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => {
                if denied(&full) || denied(&format!("{full}/")) {
                    continue; // not to be looked into: that is no gap in the search
                }
                if depth >= MAX_LEVELS {
                    // deeper than the search goes: what changed in there is not known
                    found.incomplete = true;
                    continue;
                }
                // It was a directory on this filesystem a moment ago; make sure that is
                // still what was opened.
                let entered = openat(here, name, flags, Mode::empty())
                    .ok()
                    .filter(|fd| {
                        fstat(fd).is_ok_and(|now| {
                            FileType::from_raw_mode(now.st_mode) == FileType::Directory
                                && now.st_dev as u64 == dev
                        })
                    })
                    .and_then(|fd| Dir::new(fd).ok());
                if let Some(entered) = entered {
                    stack.push((entered, full));
                }
            }
            FileType::RegularFile => {
                let modified = stat.st_mtime as i64;
                if modified >= start && !denied(&full) {
                    found.files.push((modified, full));
                }
            }
            _ => {}
        }
    }
    found.files.sort();
    found
}

// ---- the report

/// What `render` shows besides the events.
#[derive(Debug, Default)]
pub struct Report {
    pub hours: i64,
    pub offset: i64,
    pub limit: usize,
    /// Events per kind before repeats were folded, in the order they are reported.
    pub counts: Vec<(Kind, usize)>,
    pub notes: Vec<String>,
    /// A part was left out, could not be read, or was read only in part (the notes say
    /// which): an empty timeline then does not mean that nothing happened.
    pub gaps: bool,
}

/// The timeline as text: a header, notes, then the events oldest first. With more than
/// `report.limit` events, or more than fit in `budget` bytes, the newest are kept.
pub fn render(report: &Report, mut events: Vec<Event>, budget: usize) -> String {
    events.sort_by_key(|event| (event.time, event.kind));
    let mut head = format!(
        "Changes in the last {} hour{}, oldest first. Times are local ({}).\n",
        report.hours,
        if report.hours == 1 { "" } else { "s" },
        offset_label(report.offset)
    );
    let counts: Vec<String> = report
        .counts
        .iter()
        .map(|(kind, count)| kind.counted(*count))
        .collect();
    if !counts.is_empty() {
        head.push_str(&format!("Found: {}.\n", counts.join(", ")));
    }
    for note in &report.notes {
        head.push_str(note);
        head.push('\n');
    }
    if events.is_empty() {
        // AIDEV-NOTE: "nothing was recorded" is a statement about the host. It is only
        // made when every part asked for was read, and read whole.
        head.push_str(if report.gaps {
            "\nNothing was found in what could be read; the notes above say what could not be.\n"
        } else {
            "\nNothing was recorded in this period.\n"
        });
        return head;
    }
    let over = events.len().saturating_sub(report.limit);
    if over > 0 {
        events.drain(..over);
        head.push_str(&format!(
            "[{over} earlier events left out: only the newest {} are shown; ask for one kind \
             or fewer hours to see them]\n",
            report.limit
        ));
    }
    let rows: Vec<Vec<String>> = events
        .iter()
        .map(|event| {
            vec![
                local_stamp(event.time, report.offset),
                event.kind.label().to_string(),
                event.what.clone(),
            ]
        })
        .collect();
    let table = format_table(&["TIME", "KIND", "WHAT"], &rows, &[false, false, false]);
    let (titles, body) = table.split_once('\n').unwrap_or((table.as_str(), ""));
    // The oldest lines go first when the whole does not fit.
    let room = budget.saturating_sub(head.len() + titles.len() + 100);
    let (body, dropped) = keep_tail(body, room);
    if dropped > 0 {
        head.push_str(&format!(
            "[{dropped} more of the oldest events left out to fit the output limit]\n"
        ));
    }
    format!("{head}\n{titles}\n{body}")
}

// ---- change_history: gathering ----------------------------------------------------------

/// What one source contributed.
#[derive(Default)]
struct Part {
    events: Vec<Event>,
    total: usize,
    notes: Vec<String>,
    /// The source could not be read, or not all of it (the notes say what).
    gap: bool,
}

impl Part {
    /// A part that could not be read at all, and why.
    fn note(text: String) -> Part {
        Part {
            notes: vec![text],
            gap: true,
            ..Part::default()
        }
    }
}

async fn package_part(
    ctx: &Ctx,
    clock: &CallClock,
    places: &Places,
    start: i64,
    offset: i64,
) -> Part {
    let dir = places.dpkg_log_dir.clone();
    let logs = blocking(ctx.clone(), move || Ok(read_dpkg_logs(&dir, start, offset))).await;
    match logs {
        Err(error) => return Part::note(format!("[packages not available: {}]", reason(error))),
        Ok(Some((events, notes))) => {
            return Part {
                total: events.len(),
                events: collapse_runs(events, "package changes"),
                // every note here is about a log that was not read, or not whole
                gap: !notes.is_empty(),
                notes,
            };
        }
        Ok(None) => {}
    }
    let rpm = match ctx.optional_command("rpm") {
        Ok(Some(rpm)) => rpm,
        Ok(None) => {
            return Part::note(
                "[packages: this host has neither a dpkg log nor rpm; nothing to report]"
                    .to_string(),
            );
        }
        Err(error) => return Part::note(format!("[packages not available: {}]", reason(error))),
    };
    let mut rpm = rpm.args([
        "-qa",
        "--qf",
        "%{INSTALLTIME}\\t%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n",
    ]);
    rpm.max_output = 8 << 20;
    let Some(out) = run_limited(ctx, clock, rpm).await else {
        return Part::note("[packages not available: no time left to ask rpm]".to_string());
    };
    if !command_ok(&out) {
        return Part::note(format!(
            "[packages not available: {}]",
            one_line(&command_text(&out))
        ));
    }
    let events: Vec<Event> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(parse_rpm_line)
        .filter(|event| event.time >= start)
        .collect();
    Part {
        total: events.len(),
        events: collapse_runs(events, "package changes"),
        notes: vec![
            "[rpm records when each installed package was put in place: removals, and \
             versions since replaced, are not shown]"
                .to_string(),
        ],
        gap: false,
    }
}

async fn boot_part(ctx: &Ctx, clock: &CallClock, places: &Places, start: i64, offset: i64) -> Part {
    let mut boots = Vec::new();
    if let Ok(Some(journalctl)) = ctx.optional_command("journalctl") {
        let listing = journalctl.args(["--list-boots", "--no-pager", "--utc", "--output=json"]);
        if let Some(out) = run_limited(ctx, clock, listing).await {
            boots = parse_boots(&String::from_utf8_lossy(&out.stdout), offset);
        }
    }
    if boots.is_empty() {
        // No journal (or it would not say): the running boot's start is still known.
        let stat = places.proc_stat.clone();
        let read = blocking(ctx.clone(), move || {
            let mut text = String::new();
            let opened =
                std::fs::File::open(stat).map(|file| file.take(4 << 20).read_to_string(&mut text));
            Ok(opened.is_ok().then_some(text))
        })
        .await;
        if let Ok(Some(text)) = read {
            boots.extend(boot_from_stat(&text, now_secs()));
        }
    }
    let events = boot_events(&boots, start);
    Part {
        total: boots.iter().filter(|boot| boot.first >= start).count(),
        events,
        notes: Vec::new(),
        gap: false,
    }
}

/// Runs journalctl for one part of the report. Entries come newest first, so that when
/// there is more than can be read it is the oldest that is missing.
async fn journal(
    ctx: &Ctx,
    clock: &CallClock,
    hours: i64,
    fields: &str,
    matches: &[&str],
    what: &str,
) -> Result<(Vec<u8>, Vec<String>), String> {
    let journalctl = match ctx.optional_command("journalctl") {
        Ok(Some(journalctl)) => journalctl,
        Ok(None) => return Err(format!("[{what} not available: journalctl was not found]")),
        Err(error) => return Err(format!("[{what} not available: {}]", reason(error))),
    };
    let mut argv = vec![
        "--no-pager".to_string(),
        "--quiet".to_string(),
        "--output=json".to_string(),
        format!("--output-fields={fields}"),
        format!("--since=-{hours}h"),
        "--reverse".to_string(),
    ];
    argv.extend(matches.iter().map(|m| m.to_string()));
    let mut journalctl = journalctl.args(argv);
    journalctl.max_output = 16 << 20;
    let Some(mut out) = run_limited(ctx, clock, journalctl).await else {
        return Err(format!(
            "[{what} not available: no time was left to read the journal]"
        ));
    };
    let mut notes = Vec::new();
    if out.truncated {
        notes.push(format!(
            "[the journal holds more {what} than could be read: the oldest part of the \
             period is missing]"
        ));
    }
    if out.timed_out {
        notes.push(format!(
            "[reading {what} from the journal reached its time limit: the oldest part of the \
             period may be missing]"
        ));
    }
    let stdout = std::mem::take(&mut out.stdout);
    if stdout.is_empty() && !out.timed_out && !matches!(out.code, Some(0) | Some(1)) {
        // journalctl --quiet exits 1 with no output when nothing matched; anything else
        // with no output is a failure worth showing.
        return Err(format!(
            "[{what} not available: {}]",
            cut(&one_line(&command_text(&out)), 200)
        ));
    }
    Ok((stdout, notes))
}

/// The note for journal lines that could not be read as entries, if there were any: an
/// event may have been among them.
fn unreadable_note(lines: usize, what: &str) -> Option<String> {
    match lines {
        0 => None,
        1 => Some(format!(
            "[1 journal line about {what} could not be read and was skipped]"
        )),
        n => Some(format!(
            "[{n} journal lines about {what} could not be read and were skipped]"
        )),
    }
}

async fn unit_part(ctx: &Ctx, clock: &CallClock, hours: i64, start: i64, offset: i64) -> Part {
    let fields = "UNIT,JOB_TYPE,JOB_RESULT,MESSAGE";
    match journal(ctx, clock, hours, fields, &["_PID=1"], "unit events").await {
        Err(note) => Part::note(note),
        Ok((stdout, mut notes)) => {
            let found = unit_events(&stdout, start, offset);
            notes.extend(unreadable_note(found.unreadable, "unit events"));
            Part {
                events: found.events,
                total: found.total,
                gap: !notes.is_empty(),
                notes,
            }
        }
    }
}

async fn sudo_part(ctx: &Ctx, clock: &CallClock, hours: i64, start: i64, offset: i64) -> Part {
    // AIDEV-NOTE: both matches must hold. SYSLOG_IDENTIFIER is what the sender called
    // itself; _COMM is the name of the program that really sent the entry, as journald
    // saw it. Together they keep out `logger -t sudo`. (The entries carry the uid of the
    // user who ran sudo, not 0, so the uid cannot be used to tell.)
    let matches = ["SYSLOG_IDENTIFIER=sudo", "_COMM=sudo"];
    match journal(ctx, clock, hours, "MESSAGE", &matches, "uses of sudo").await {
        Err(note) => Part::note(note),
        Ok((stdout, mut notes)) => {
            let found = sudo_events(&stdout, start, offset);
            notes.extend(unreadable_note(found.unreadable, "uses of sudo"));
            Part {
                events: found.events,
                total: found.total,
                gap: !notes.is_empty(),
                notes,
            }
        }
    }
}

async fn config_part(ctx: &Ctx, clock: &CallClock, places: &Places, start: i64) -> Part {
    const MAX_ENTRIES: usize = 50_000;
    let Some(left) = clock.next() else {
        return Part::note("[config files not looked at: no time was left]".to_string());
    };
    let deadline = Instant::now() + left.min(Duration::from_secs(5));
    let root = places.etc.clone();
    let shown = root.display().to_string();
    let walker = ctx.clone();
    let found = blocking(ctx.clone(), move || {
        // AIDEV-NOTE: names only, never contents; and never the name of a path that the
        // filesystem tools would refuse to show (fs.deny and the built-in list).
        let denied = |path: &str| denied_by(&walker.cfg().fs, path).is_some();
        Ok(changed_files(&root, start, &denied, deadline, MAX_ENTRIES))
    })
    .await;
    let found = match found {
        Ok(found) => found,
        Err(error) => {
            return Part::note(format!("[config files not available: {}]", reason(error)));
        }
    };
    let mut notes = Vec::new();
    if found.incomplete {
        notes.push(format!(
            "[the search of {shown} was not complete (it reached its limit on time, entries \
             or depth): more files may have changed]"
        ));
    }
    let events: Vec<Event> = found
        .files
        .into_iter()
        .map(|(time, path)| Event {
            time,
            kind: Kind::Config,
            what: format!("changed {path}"),
        })
        .collect();
    Part {
        total: events.len(),
        events: collapse_runs(events, "config file changes"),
        gap: !notes.is_empty(),
        notes,
    }
}

/// Whether the configuration tree lies in a directory that may be listed on this host.
///
/// AIDEV-NOTE: `fs.list_roots` is a host-wide limit: fs_list refuses a directory outside
/// it whatever the caller is granted. The names of the files that changed under /etc are
/// a listing of /etc, so the same limit, by the same rule (`fs::inside`, on the
/// directory's real path), decides whether that part is shown at all.
async fn etc_may_be_listed(ctx: &Ctx, places: &Places) -> Result<bool, ToolError> {
    let etc = places.etc.clone();
    let asker = ctx.clone();
    blocking(ctx.clone(), move || {
        let real = std::fs::canonicalize(&etc).unwrap_or(etc);
        Ok(inside(&real.to_string_lossy(), &asker.cfg().fs.list_roots))
    })
    .await
}

async fn change_history(places: Arc<Places>, ctx: Ctx, args: Args) -> ToolResult {
    let hours = args.int("hours").unwrap_or(24);
    let kind = args.str("kind").unwrap_or("all").to_string();
    let limit = usize::try_from(args.int("limit").unwrap_or(150)).unwrap_or(150);
    let auth = ctx.authorize(None)?;

    let clock = CallClock::start(&ctx);
    let start = now_secs().saturating_sub(hours.saturating_mul(3600));
    let (offset, mut notes) = utc_offset(&ctx, &clock, Some(start)).await;

    // AIDEV-NOTE: this tool gathers what other tools show (package_query, service_status,
    // fs_list, journal_query). Each part is included only if the caller holds that
    // tool's permission in full, so the timeline can never show what a missing grant or
    // a deny keeps from the caller elsewhere.
    let mut events = Vec::new();
    let mut counts = Vec::new();
    let mut gaps = false;
    let sections = [
        ("packages", Kind::Package, Some("package.view")),
        ("boots", Kind::Boot, None),
        ("units", Kind::Unit, Some("service.view")),
        ("config", Kind::Config, Some("fs.view")),
        ("sudo", Kind::Sudo, Some("journal.view")),
    ];
    for (name, section, permission) in sections {
        if kind != "all" && kind != name {
            continue;
        }
        if let Some(permission) = permission
            && !ctx.holds_read(permission)
        {
            notes.push(format!("[{name} left out: needs {permission}]"));
            gaps = true;
            continue;
        }
        if section == Kind::Config {
            match etc_may_be_listed(&ctx, &places).await {
                Ok(true) => {}
                Ok(false) => {
                    notes.push(format!(
                        "[config left out: {} is outside the directories that fs.list_roots \
                         allows on this host]",
                        places.etc.display()
                    ));
                    gaps = true;
                    continue;
                }
                Err(error) => {
                    notes.push(format!("[config files not available: {}]", reason(error)));
                    gaps = true;
                    continue;
                }
            }
        }
        let part = match section {
            Kind::Package => package_part(&ctx, &clock, &places, start, offset).await,
            Kind::Boot => boot_part(&ctx, &clock, &places, start, offset).await,
            Kind::Unit => unit_part(&ctx, &clock, hours, start, offset).await,
            Kind::Config => config_part(&ctx, &clock, &places, start).await,
            Kind::Sudo => sudo_part(&ctx, &clock, hours, start, offset).await,
        };
        counts.push((section, part.total));
        events.extend(part.events);
        notes.extend(part.notes);
        gaps |= part.gap;
    }
    let report = Report {
        hours,
        offset,
        limit,
        counts,
        notes,
        gaps,
    };
    auth.ok(render(&report, events, ctx.output_budget()))
}

// ---- perf_history -----------------------------------------------------------------------

/// The files sysstat may have written for a day (`YYYY-MM-DD`), in order of preference.
pub fn sar_candidates(dirs: &[PathBuf], date: &str) -> Vec<PathBuf> {
    let day = date.get(8..10).unwrap_or("");
    let compact = date.replace('-', "");
    dirs.iter()
        .flat_map(|dir| {
            [
                dir.join(format!("sa{day}")),
                dir.join(format!("sa{compact}")),
            ]
        })
        .collect()
}

/// The period to show, as minutes since midnight. `now_minute` is the present time of
/// day when the day asked for is today.
pub fn period(
    today: bool,
    now_minute: i64,
    start: Option<i64>,
    end: Option<i64>,
) -> Result<(i64, i64), String> {
    let end = end.unwrap_or(if today { now_minute.max(1) } else { 1439 });
    let start = start.unwrap_or(if today { (end - 60).max(0) } else { 0 });
    if today && start > now_minute {
        return Err(format!(
            "start is in the future: it is {} here now",
            hhmm(now_minute)
        ));
    }
    if start >= end {
        return Err(format!(
            "start ({}) must be before end ({})",
            hhmm(start),
            hhmm(end)
        ));
    }
    Ok((start, end))
}

fn sar_flags(metric: &str) -> &'static [&'static str] {
    match metric {
        "cpu" => &["-u"],
        "memory" => &["-r"],
        "swap" => &["-S", "-W"],
        "load" => &["-q"],
        "disk" => &["-b", "-d", "-p"],
        "network" => &["-n", "DEV", "-n", "EDEV"],
        _ => &["-u", "-r", "-q", "-b"],
    }
}

fn atop_flags(metric: &str) -> &'static [&'static str] {
    match metric {
        "cpu" => &["-c"],
        "memory" => &["-m"],
        "swap" => &["-s"],
        "load" => &["-p"],
        "disk" => &["-d"],
        "network" => &["-i"],
        _ => &["-c", "-m", "-p"],
    }
}

/// Whether sar's or atopsar's output holds any record: a line that begins with a time
/// of day. The banner line and "Average:" lines are not records.
fn has_records(output: &str) -> bool {
    output.lines().any(|line| {
        let stamp = line.as_bytes();
        stamp.len() >= 5
            && stamp[..2].iter().all(u8::is_ascii_digit)
            && stamp[2] == b':'
            && stamp[3..5].iter().all(u8::is_ascii_digit)
    })
}

fn metric_title(metric: &str) -> &'static str {
    match metric {
        "cpu" => "CPU use",
        "memory" => "Memory use",
        "swap" => "Swap use and swapping",
        "load" => "Load and run queue",
        "disk" => "Disk I/O",
        "network" => "Network traffic and errors",
        _ => "CPU, memory, load and I/O",
    }
}

/// The first of `candidates` that is a file, and when it was last written (Unix seconds).
async fn first_file(
    ctx: &Ctx,
    candidates: Vec<PathBuf>,
) -> Result<Option<(PathBuf, i64)>, ToolError> {
    blocking(ctx.clone(), move || {
        Ok(candidates.into_iter().find_map(|path| {
            let meta = std::fs::metadata(&path).ok()?;
            meta.is_file().then(|| (path, meta.mtime()))
        }))
    })
    .await
}

/// The date in the first line sar prints, its banner: `Linux 6.8.0 (web1)  2026-11-20
/// _x86_64_  (12 CPU)`. With `S_TIME_FORMAT=ISO` it is written `YYYY-MM-DD`; a date in
/// any other form is not guessed at.
pub fn banner_date(output: &str) -> Option<String> {
    let banner = output.lines().find(|line| !line.trim().is_empty())?;
    banner
        .split_whitespace()
        .find(|word| word.len() == 10 && parse_date(word).is_some())
        .map(str::to_string)
}

async fn perf_history(places: Arc<Places>, ctx: Ctx, args: Args) -> ToolResult {
    // What can be checked without looking at anything is checked first.
    let day = args
        .str("date")
        .map(|date| {
            parse_date(date).ok_or_else(|| {
                ToolError::Invalid(format!("date {date:?} is not a day written as YYYY-MM-DD"))
            })
        })
        .transpose()?
        .map(|seconds| seconds.div_euclid(86_400));
    let time_of_day = |name: &str| -> Result<Option<i64>, ToolError> {
        args.str(name)
            .map(|text| {
                parse_hhmm(text).ok_or_else(|| {
                    ToolError::Invalid(format!("{name} {text:?} is not a time written as HH:MM"))
                })
            })
            .transpose()
    };
    let (start, end) = (time_of_day("start")?, time_of_day("end")?);
    let metric = args.str("metric").unwrap_or("overview").to_string();
    let auth = ctx.authorize(None)?;

    let clock = CallClock::start(&ctx);
    let (offset, notes) = utc_offset(&ctx, &clock, None).await;
    let local_now = now_secs().saturating_add(offset);
    let today = local_now.div_euclid(86_400);
    let day = day.unwrap_or(today);
    if day > today {
        return Err(ToolError::Invalid(
            "date is in the future: there is no history for it yet".to_string(),
        ));
    }
    if day < today - 366 {
        return Err(ToolError::Invalid(
            "date is more than a year back: no history is kept that long".to_string(),
        ));
    }
    let parts = utc_parts(day * 86_400);
    let date = format!("{:04}-{:02}-{:02}", parts.year, parts.month, parts.day);
    let now_minute = local_now.rem_euclid(86_400) / 60;
    let (start, end) = period(day == today, now_minute, start, end).map_err(ToolError::Invalid)?;

    // sysstat first; atop when sysstat has nothing for that day.
    let sar = ctx.optional_command("sar")?;
    let sar_file = first_file(&ctx, sar_candidates(&places.sar_dirs, &date)).await?;
    let atopsar = ctx.optional_command("atopsar")?;
    let atop_name = format!("atop_{}", date.replace('-', ""));
    let atop_file = first_file(&ctx, vec![places.atop_dir.join(atop_name)]).await?;

    let (source, mut cmd, sar_written) = match (sar, sar_file, atopsar, atop_file) {
        (Some(sar), Some((file, written)), _, _) => {
            let mut argv = vec![
                "-f".to_string(),
                file.display().to_string(),
                "-s".to_string(),
                format!("{}:00", hhmm(start)),
                // AIDEV-NOTE: the end is a minute and the whole of it is wanted. With
                // `-e 05:33:00` sar leaves out a sample taken at 05:33:18, so a period
                // ending "now" would never show the newest records.
                "-e".to_string(),
                format!("{}:59", hhmm(end)),
            ];
            argv.extend(sar_flags(&metric).iter().map(|flag| flag.to_string()));
            let mut sar = sar.args(argv);
            // 24-hour times whatever the locale.
            sar.env
                .push(("S_TIME_FORMAT".to_string(), "ISO".to_string()));
            ("sysstat (sar)", sar, Some(written))
        }
        (_, _, Some(atopsar), Some((file, _))) => {
            let mut argv = vec![
                "-r".to_string(),
                file.display().to_string(),
                "-b".to_string(),
                hhmm(start),
                "-e".to_string(),
                hhmm(end),
            ];
            argv.extend(atop_flags(&metric).iter().map(|flag| flag.to_string()));
            ("atop (atopsar)", atopsar.args(argv), None)
        }
        (sar, sar_file, atopsar, _) => {
            let sysstat = match (sar.is_some(), sar_file.is_some()) {
                (false, _) => "sar is not installed",
                (true, false) => "sar is installed but has no file for that day",
                (true, true) => "sar could not be used",
            };
            let atop = if atopsar.is_some() {
                "atopsar is installed but has no file for that day"
            } else {
                "atopsar is not installed"
            };
            return Err(ToolError::Failed(format!(
                "No performance history for {date} on this host: {sysstat}, and {atop}. \
                 sysstat (package sysstat) records it once its collector is enabled, and \
                 atop (package atop) once atop.service runs; both keep only some days."
            )));
        }
    };
    let Some(limit) = clock.next() else {
        return Err(ToolError::Failed(
            "no time was left in this call to read the history".to_string(),
        ));
    };
    cmd = cmd.timeout(limit);
    let out = ctx.run(cmd).await?;

    // AIDEV-NOTE: sysstat names its daily files by day of the month (`sa20`) and reuses
    // them month after month. Asked for the 20th of an earlier month, the file found is
    // this month's, and its figures would be shown under the date that was asked for.
    // sar's first line says which day the file holds; where it does not, the file must
    // at least have been last written on that day or the next (the day is closed just
    // after midnight).
    if let Some(written) = sar_written {
        let no_records = |holds: String| {
            ToolError::Failed(format!(
                "sysstat has no records for {date} on this host (its file for that day of the \
                 month {holds})"
            ))
        };
        match banner_date(&String::from_utf8_lossy(&out.stdout)) {
            Some(held) if held != date => return Err(no_records(format!("now holds {held}"))),
            Some(_) => {}
            None => {
                let written_day = written.saturating_add(offset).div_euclid(86_400);
                if written_day != day && written_day != day + 1 {
                    let parts = utc_parts(written_day.saturating_mul(86_400));
                    return Err(no_records(format!(
                        "was last written on {:04}-{:02}-{:02}",
                        parts.year, parts.month, parts.day
                    )));
                }
            }
        }
    }

    let mut text = format!(
        "{} on {date} from {} to {} (local time, {}), from {source}.\n",
        metric_title(&metric),
        hhmm(start),
        hhmm(end),
        offset_label(offset)
    );
    for note in notes {
        text.push_str(&note);
        text.push('\n');
    }
    text.push('\n');
    let room = ctx.output_budget().saturating_sub(text.len() + 120);
    let said = command_text(&out);
    let (body, dropped) = keep_head(&said, room);
    text.push_str(&body);
    if command_ok(&out) && !has_records(&said) {
        // sar and atopsar print their banner and nothing else when no sample falls in
        // the period: that must not read as an answer.
        if !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(
            "[no records for this period: the collector was not running then, or it \
             samples less often than this period is long; try a longer period]\n",
        );
    }
    if dropped > 0 {
        if !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&format!(
            "[{dropped} more lines left out to fit the output limit: ask for a shorter \
             period or one metric]\n"
        ));
    }
    auth.done(text, command_ok(&out))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: i64 = 3600;
    /// 2026-11-20 17:00:00 UTC.
    const NOON_ISH: i64 = 1_795_194_000;

    fn event(time: i64, kind: Kind, what: &str) -> Event {
        Event {
            time,
            kind,
            what: what.to_string(),
        }
    }

    // ---- time -------------------------------------------------------------------------

    #[test]
    fn an_offset_is_read_as_date_prints_it() {
        assert_eq!(parse_offset("+0000"), Some(0));
        assert_eq!(parse_offset("-0700\n"), Some(-7 * HOUR));
        assert_eq!(parse_offset("+0530"), Some(5 * HOUR + 1800));
        assert_eq!(parse_offset("+1400"), Some(14 * HOUR));
        for bad in [
            "", "0700", "+07", "+07:00", "+07000", "-0760", "+2400", "UTC", "+0a00", "++700",
        ] {
            assert_eq!(parse_offset(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn an_offset_is_shown_the_usual_way() {
        assert_eq!(offset_label(0), "UTC+00:00");
        assert_eq!(offset_label(-7 * HOUR), "UTC-07:00");
        assert_eq!(offset_label(5 * HOUR + 1800), "UTC+05:30");
    }

    #[test]
    fn local_time_is_the_utc_time_moved_by_the_offset() {
        assert_eq!(local_stamp(NOON_ISH, 0), "2026-11-20 17:00:00");
        assert_eq!(local_stamp(NOON_ISH, -7 * HOUR), "2026-11-20 10:00:00");
        // across midnight
        assert_eq!(local_stamp(NOON_ISH, 8 * HOUR), "2026-11-21 01:00:00");
    }

    #[test]
    fn a_local_date_and_time_convert_back_to_unix_time() {
        assert_eq!(
            parse_local("2026-11-20", "10:00:00", -7 * HOUR),
            Some(NOON_ISH)
        );
        assert_eq!(parse_local("2026-11-20", "17:00:00", 0), Some(NOON_ISH));
        for (date, time) in [
            ("2026-13-20", "10:00:00"),
            ("2026-11-20", "24:00:00"),
            ("2026-11-20", "10:60:00"),
            ("2026-11-20", "10:00:61"),
            ("2026-11-20", "10:00"),
            ("2026-11-20", "1o:00:00"),
            ("20261120", "10:00:00"),
            ("2026-11-20", "+1:00:00"),
        ] {
            assert_eq!(parse_local(date, time, 0), None, "{date} {time}");
        }
    }

    #[test]
    fn a_time_of_day_is_hours_and_minutes_only() {
        assert_eq!(parse_hhmm("00:00"), Some(0));
        assert_eq!(parse_hhmm("09:30"), Some(570));
        assert_eq!(parse_hhmm("23:59"), Some(1439));
        for bad in [
            "", "9:30", "24:00", "12:60", "12:3", "12-30", "12:30:00", " 12:30", "ab:cd", "+1:30",
        ] {
            assert_eq!(parse_hhmm(bad), None, "{bad:?}");
        }
    }

    // ---- packages ---------------------------------------------------------------------

    #[test]
    fn dpkg_action_lines_become_events() {
        let at = |line: &str| parse_dpkg_line(line, -7 * HOUR);
        assert_eq!(
            at("2026-11-20 10:00:00 upgrade nginx:amd64 1.24.0-1 1.24.0-2"),
            Some(event(
                NOON_ISH,
                Kind::Package,
                "upgrade nginx:amd64 1.24.0-1 -> 1.24.0-2"
            ))
        );
        assert_eq!(
            at("2026-11-20 10:00:00 install jq:amd64 <none> 1.7.1-3"),
            Some(event(NOON_ISH, Kind::Package, "install jq:amd64 1.7.1-3"))
        );
        assert_eq!(
            at("2026-11-20 10:00:00 remove jq:amd64 1.7.1-3 <none>"),
            Some(event(NOON_ISH, Kind::Package, "remove jq:amd64 1.7.1-3"))
        );
        assert_eq!(
            at("2026-11-20 10:00:00 purge jq:amd64 1.7.1-3 <none>"),
            Some(event(NOON_ISH, Kind::Package, "purge jq:amd64 1.7.1-3"))
        );
    }

    #[test]
    fn dpkg_lines_that_are_not_actions_are_ignored() {
        for line in [
            "2026-11-20 10:00:00 status installed nginx:amd64 1.24.0-2",
            "2026-11-20 10:00:00 configure nginx:amd64 1.24.0-2 <none>",
            "2026-11-20 10:00:00 trigproc man-db:amd64 2.12.0-4 <none>",
            "2026-11-20 10:00:00 startup archives unpack",
            "2026-11-20 10:00:00 upgrade nginx:amd64",
            "2026-11-20 xx:00:00 upgrade nginx:amd64 1 2",
            "",
            "garbage",
        ] {
            assert_eq!(parse_dpkg_line(line, 0), None, "{line:?}");
        }
    }

    #[test]
    fn rpm_install_times_become_events() {
        assert_eq!(
            parse_rpm_line("1795194000\tnginx-1.24.0-2.el9.x86_64"),
            Some(event(
                NOON_ISH,
                Kind::Package,
                "install or upgrade nginx-1.24.0-2.el9.x86_64"
            ))
        );
        for bad in ["", "nginx", "soon\tnginx", "1795194000\t", "-5\tnginx"] {
            assert_eq!(parse_rpm_line(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_long_burst_of_package_changes_becomes_one_line() {
        // 40 upgrades and one install, a few seconds apart: one run
        let mut events: Vec<Event> = (0..40)
            .map(|n| {
                event(
                    NOON_ISH + n * 5,
                    Kind::Package,
                    &format!("upgrade lib{n}:amd64 1 -> 2"),
                )
            })
            .collect();
        events.push(event(NOON_ISH + 205, Kind::Package, "install jq:amd64 1.7"));
        // and, an hour later, a change of its own
        events.push(event(NOON_ISH + HOUR, Kind::Package, "remove jq:amd64 1.7"));
        let folded = collapse_runs(events, "package changes");
        assert_eq!(folded.len(), 2, "{folded:?}");
        assert_eq!(folded[0].time, NOON_ISH);
        assert_eq!(folded[0].kind, Kind::Package);
        let what = &folded[0].what;
        assert!(
            what.starts_with("41 package changes within 4 minutes"),
            "{what}"
        );
        assert!(what.contains("upgrade lib0:amd64 1 -> 2"), "{what}");
        assert!(what.contains("upgrade lib2:amd64 1 -> 2"), "{what}");
        assert!(!what.contains("lib3:"), "only a few examples: {what}");
        assert_eq!(folded[1].what, "remove jq:amd64 1.7");
    }

    #[test]
    fn a_short_burst_is_left_as_it_is() {
        let events: Vec<Event> = (0..30)
            .map(|n| {
                event(
                    NOON_ISH + n,
                    Kind::Package,
                    &format!("upgrade lib{n} 1 -> 2"),
                )
            })
            .collect();
        assert_eq!(collapse_runs(events.clone(), "package changes"), events);
        // more than 30, but more than a minute apart each time: not a burst
        let spread: Vec<Event> = (0..40)
            .map(|n| {
                event(
                    NOON_ISH + n * 61,
                    Kind::Package,
                    &format!("upgrade lib{n} 1 -> 2"),
                )
            })
            .collect();
        assert_eq!(collapse_runs(spread.clone(), "package changes"), spread);
    }

    #[test]
    fn dpkg_logs_are_read_newest_first_compressed_or_not() {
        let names = dpkg_log_names();
        assert_eq!(names[0], ["dpkg.log"]);
        assert_eq!(names[1], ["dpkg.log.1", "dpkg.log.1.gz"]);
        assert_eq!(names[2], ["dpkg.log.2", "dpkg.log.2.gz"]);
        assert!(names.len() >= 6);
    }

    // ---- boots ------------------------------------------------------------------------

    #[test]
    fn boots_are_read_from_the_json_listing() {
        let text = r#"[{"index":-1,"boot_id":"4d98662ba98a456693552ed8d165b810","first_entry":1795000000097168,"last_entry":1795100000938570},{"index":0,"boot_id":"99b65a1f9bc04dc39d4f09a1e72d73ec","first_entry":1795100060053070,"last_entry":1795107600133136}]"#;
        assert_eq!(
            parse_boots(text, 0),
            [
                Boot {
                    index: -1,
                    first: 1_795_000_000,
                    last: 1_795_100_000
                },
                Boot {
                    index: 0,
                    first: 1_795_100_060,
                    last: 1_795_107_600
                },
            ]
        );
    }

    #[test]
    fn boots_are_read_from_the_older_text_listing() {
        // systemd before 251: no header, an em dash between the two times
        let old = "-1 4d98662ba98a456693552ed8d165b810 Fri 2026-11-20 09:00:00 UTC\u{2014}Fri 2026-11-20 16:00:00 UTC\n \
                    0 99b65a1f9bc04dc39d4f09a1e72d73ec Fri 2026-11-20 16:01:00 UTC\u{2014}Fri 2026-11-20 17:00:00 UTC\n";
        let boots = parse_boots(old, -7 * HOUR);
        assert_eq!(boots.len(), 2, "{boots:?}");
        assert_eq!(boots[0].index, -1);
        // marked UTC: the offset is not applied
        assert_eq!(boots[1].last, NOON_ISH);
        assert_eq!(boots[1].first, NOON_ISH - 59 * 60);

        // a table with a header, in local time
        let table = "IDX BOOT ID                          FIRST ENTRY                 LAST ENTRY\n \
                     -1 29872a81ed074ddfa26da6c562e3aac5 Fri 2026-11-20 02:00:00 MST Fri 2026-11-20 09:00:00 MST\n  \
                     0 a67734fbe623437f87319ca8d62930f9 Fri 2026-11-20 09:01:00 MST Fri 2026-11-20 10:00:00 MST\n";
        let boots = parse_boots(table, -7 * HOUR);
        assert_eq!(boots.len(), 2, "{boots:?}");
        assert_eq!(boots[1].index, 0);
        assert_eq!(boots[1].last, NOON_ISH);
        assert_eq!(boots[0].last, NOON_ISH - HOUR);
    }

    #[test]
    fn unreadable_boot_listings_give_no_boots() {
        assert_eq!(parse_boots("", 0), []);
        assert_eq!(
            parse_boots("Failed to determine boots: No data available\n", 0),
            []
        );
        assert_eq!(parse_boots("[{\"index\":\"x\"}]", 0), []);
        assert_eq!(parse_boots("[not json", 0), []);
    }

    #[test]
    fn a_boot_in_the_period_is_an_event_and_so_is_the_stop_before_it() {
        let boots = [
            Boot {
                index: -2,
                first: NOON_ISH - 100 * HOUR,
                last: NOON_ISH - 50 * HOUR,
            },
            Boot {
                index: -1,
                first: NOON_ISH - 49 * HOUR,
                last: NOON_ISH - 3 * HOUR,
            },
            Boot {
                index: 0,
                first: NOON_ISH - 3 * HOUR + 40,
                last: NOON_ISH,
            },
        ];
        let events = boot_events(&boots, NOON_ISH - 24 * HOUR);
        assert_eq!(
            events,
            [
                event(
                    NOON_ISH - 3 * HOUR,
                    Kind::Boot,
                    "the system went down (last journal entry before the next boot)"
                ),
                event(NOON_ISH - 3 * HOUR + 40, Kind::Boot, "the system booted"),
            ]
        );
        // nothing in the period: nothing reported, not even the running boot's last entry
        assert_eq!(boot_events(&boots[2..], NOON_ISH - HOUR), []);
    }

    // ---- units ------------------------------------------------------------------------

    fn entry(usec_secs: i64, fields: &[(&str, &str)]) -> String {
        let mut object = serde_json::Map::new();
        object.insert(
            "__REALTIME_TIMESTAMP".to_string(),
            serde_json::Value::String(format!("{}", usec_secs * 1_000_000)),
        );
        for (key, value) in fields {
            object.insert(
                key.to_string(),
                serde_json::Value::String(value.to_string()),
            );
        }
        format!("{}\n", serde_json::Value::Object(object))
    }

    fn job(at: i64, unit: &str, kind: &str, result: &str, message: &str) -> String {
        entry(
            at,
            &[
                ("UNIT", unit),
                ("JOB_TYPE", kind),
                ("JOB_RESULT", result),
                ("MESSAGE", message),
            ],
        )
    }

    fn whats(found: &Found) -> Vec<&str> {
        found.events.iter().map(|e| e.what.as_str()).collect()
    }

    #[test]
    fn unit_jobs_become_events() {
        let mut text = String::new();
        text.push_str(&job(
            NOON_ISH - 50,
            "nginx.service",
            "start",
            "done",
            "Started nginx.",
        ));
        text.push_str(&job(
            NOON_ISH - 40,
            "nginx.service",
            "reload",
            "done",
            "Reloaded nginx.",
        ));
        text.push_str(&job(
            NOON_ISH - 30,
            "nginx.service",
            "stop",
            "done",
            "Stopped nginx.",
        ));
        text.push_str(&job(
            NOON_ISH - 20,
            "nginx.service",
            "restart",
            "done",
            "Stopped nginx.",
        ));
        text.push_str(&job(
            NOON_ISH - 10,
            "logrotate.service",
            "start",
            "done",
            "Finished Logrotate Service.",
        ));
        let found = unit_events(text.as_bytes(), NOON_ISH - HOUR, 0);
        assert_eq!(
            whats(&found),
            [
                "nginx.service started",
                "nginx.service reloaded",
                "nginx.service stopped",
                "nginx.service restarted",
                "logrotate.service finished",
            ]
        );
        assert_eq!(found.total, 5);
        assert_eq!(found.unreadable, 0);
        assert!(found.events.iter().all(|e| e.kind == Kind::Unit));
        assert_eq!(found.events[0].time, NOON_ISH - 50);
    }

    #[test]
    fn a_failed_job_and_a_failed_unit_are_reported_as_failures() {
        let mut text = String::new();
        text.push_str(&job(
            NOON_ISH - 50,
            "app.service",
            "start",
            "failed",
            "Failed to start app.",
        ));
        text.push_str(&job(
            NOON_ISH - 45,
            "db.service",
            "start",
            "dependency",
            "Dependency failed for db.",
        ));
        text.push_str(&entry(
            NOON_ISH - 40,
            &[
                ("UNIT", "app.service"),
                ("MESSAGE", "app.service: Failed with result 'exit-code'."),
            ],
        ));
        text.push_str(&entry(
            NOON_ISH - 30,
            &[
                ("UNIT", "app.service"),
                (
                    "MESSAGE",
                    "app.service: Scheduled restart job, restart counter is at 5.",
                ),
            ],
        ));
        let found = unit_events(text.as_bytes(), NOON_ISH - HOUR, 0);
        assert_eq!(
            whats(&found),
            [
                "app.service start FAILED (failed)",
                "db.service start FAILED (dependency)",
                "app.service FAILED: Failed with result 'exit-code'.",
                "app.service restart scheduled by systemd after it stopped",
            ]
        );
    }

    #[test]
    fn entries_that_are_not_about_a_service_changing_state_are_ignored() {
        let mut text = String::new();
        // a job that has only begun
        text.push_str(&entry(
            NOON_ISH - 50,
            &[
                ("UNIT", "nginx.service"),
                ("JOB_TYPE", "start"),
                ("MESSAGE", "Starting nginx..."),
            ],
        ));
        // not services
        text.push_str(&job(
            NOON_ISH - 40,
            "session-12.scope",
            "start",
            "done",
            "Started Session 12.",
        ));
        text.push_str(&job(
            NOON_ISH - 39,
            "apt-daily.timer",
            "start",
            "done",
            "Started timer.",
        ));
        text.push_str(&entry(
            NOON_ISH - 38,
            &[
                ("UNIT", "run-x.mount"),
                ("MESSAGE", "run-x.mount: Deactivated successfully."),
            ],
        ));
        // chatter
        text.push_str(&entry(
            NOON_ISH - 37,
            &[
                ("UNIT", "nginx.service"),
                ("MESSAGE", "nginx.service: Consumed 1.2s CPU time."),
            ],
        ));
        // no unit at all
        text.push_str(&entry(NOON_ISH - 36, &[("MESSAGE", "Reloading.")]));
        // before the period
        text.push_str(&job(
            NOON_ISH - 2 * HOUR,
            "nginx.service",
            "start",
            "done",
            "Started nginx.",
        ));
        let found = unit_events(text.as_bytes(), NOON_ISH - HOUR, 0);
        assert_eq!(whats(&found), Vec::<&str>::new());
        assert_eq!(found.total, 0);
    }

    #[test]
    fn a_unit_event_that_keeps_repeating_is_one_line_but_failures_never_are() {
        let mut text = String::new();
        for n in 0..5 {
            text.push_str(&job(
                NOON_ISH - 500 + n * 60,
                "sysstat-collect.service",
                "start",
                "done",
                "Finished system activity accounting tool.",
            ));
            text.push_str(&job(
                NOON_ISH - 490 + n * 60,
                "app.service",
                "start",
                "failed",
                "Failed to start app.",
            ));
        }
        // three times is not yet "keeps repeating"
        for n in 0..3 {
            text.push_str(&job(
                NOON_ISH - 100 + n,
                "nginx.service",
                "reload",
                "done",
                "Reloaded.",
            ));
        }
        let found = unit_events(text.as_bytes(), NOON_ISH - HOUR, 0);
        assert_eq!(found.total, 13);
        let lines = whats(&found);
        assert_eq!(lines.len(), 1 + 5 + 3, "{lines:?}");
        let folded: Vec<&&str> = lines
            .iter()
            .filter(|line| line.starts_with("sysstat-collect.service"))
            .collect();
        assert_eq!(
            folded,
            [&"sysstat-collect.service finished [5 times; first 2026-11-20 16:51:40]"]
        );
        // the folded line stands at the time of the last occurrence
        let at = found
            .events
            .iter()
            .find(|e| e.what.starts_with("sysstat"))
            .map(|e| e.time);
        assert_eq!(at, Some(NOON_ISH - 500 + 4 * 60));
        assert_eq!(
            lines
                .iter()
                .filter(|line| **line == "app.service start FAILED (failed)")
                .count(),
            5
        );
        // events come out oldest first
        let times: Vec<i64> = found.events.iter().map(|e| e.time).collect();
        let mut sorted = times.clone();
        sorted.sort();
        assert_eq!(times, sorted);
    }

    #[test]
    fn journal_lines_that_are_not_entries_are_counted_not_fatal() {
        let mut text = String::from("not json\n\n{\"MESSAGE\":\"cut off");
        text.push('\n');
        text.push_str(&job(
            NOON_ISH - 5,
            "nginx.service",
            "start",
            "done",
            "Started.",
        ));
        let found = unit_events(text.as_bytes(), NOON_ISH - HOUR, 0);
        assert_eq!(whats(&found), ["nginx.service started"]);
        assert_eq!(found.unreadable, 2);
    }

    #[test]
    fn a_field_that_is_not_utf8_arrives_as_bytes_and_is_still_read() {
        let message: Vec<u8> =
            b"    sean : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls \xff".to_vec();
        let line = format!(
            "{}\n",
            serde_json::json!({"__REALTIME_TIMESTAMP": format!("{}", (NOON_ISH - 5) * 1_000_000), "MESSAGE": message})
        );
        let found = sudo_events(line.as_bytes(), NOON_ISH - HOUR, 0);
        assert_eq!(found.total, 1);
        assert!(
            found.events[0].what.starts_with("sean as root: /bin/ls"),
            "{:?}",
            found.events
        );
        // an entry with no time, or a field of another shape, is passed over
        let odd = "{\"MESSAGE\":\"x : USER=root ; COMMAND=/bin/ls\"}\n{\"__REALTIME_TIMESTAMP\":\"soon\",\"MESSAGE\":{\"a\":1}}\n";
        assert_eq!(sudo_events(odd.as_bytes(), 0, 0).total, 0);
    }

    #[test]
    fn a_unit_name_cannot_carry_a_line_of_its_own() {
        let text = job(
            NOON_ISH - 5,
            "evil\n2026-11-20 fake.service",
            "start",
            "done",
            "Started.",
        );
        let found = unit_events(text.as_bytes(), NOON_ISH - HOUR, 0);
        assert!(whats(&found).iter().all(|line| !line.contains('\n')));
    }

    // ---- sudo -------------------------------------------------------------------------

    #[test]
    fn a_sudo_log_line_says_who_ran_what_as_whom() {
        assert_eq!(
            parse_sudo(
                "    sean : TTY=pts/0 ; PWD=/home/sean ; USER=root ; COMMAND=/usr/bin/apt upgrade"
            ),
            Some(SudoUse {
                user: "sean".to_string(),
                target: "root".to_string(),
                command: "/usr/bin/apt upgrade".to_string(),
                problem: None,
            })
        );
        // the command is everything after COMMAND=, separators and all
        assert_eq!(
            parse_sudo(
                "nagios : PWD=/ ; USER=postgres ; COMMAND=/usr/local/sbin/check --a ; USER=x"
            )
            .map(|u| (u.target, u.command)),
            Some((
                "postgres".to_string(),
                "/usr/local/sbin/check --a ; USER=x".to_string()
            ))
        );
        assert_eq!(
            parse_sudo(
                "   mallory : command not allowed ; TTY=pts/3 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh"
            )
            .and_then(|u| u.problem),
            Some("command not allowed".to_string())
        );
        assert_eq!(
            parse_sudo(
                "bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/ls"
            )
            .and_then(|u| u.problem),
            Some("3 incorrect password attempts".to_string())
        );
    }

    #[test]
    fn other_lines_from_sudo_are_not_uses() {
        for line in [
            "pam_unix(sudo:session): session opened for user root(uid=0) by sean(uid=1000)",
            "pam_unix(sudo:session): session closed for user root",
            "sean : TTY=pts/0 ; PWD=/home/sean ; USER=root",
            " : TTY=pts/0 ; USER=root ; COMMAND=/bin/ls",
            "",
        ] {
            assert_eq!(parse_sudo(line), None, "{line:?}");
        }
    }

    #[test]
    fn sudo_uses_become_events_with_secrets_masked_and_repeats_folded() {
        let line = |user: &str, command: &str| {
            format!("    {user} : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND={command}")
        };
        let mut text = String::new();
        for n in 0..6 {
            text.push_str(&entry(
                NOON_ISH - 600 + n * 60,
                &[("MESSAGE", &line("nagios", "/usr/local/sbin/check --all"))],
            ));
        }
        text.push_str(&entry(
            NOON_ISH - 50,
            &[(
                "MESSAGE",
                &line("sean", "/usr/bin/mysql --password=hunter2 -e status"),
            )],
        ));
        text.push_str(&entry(
            NOON_ISH - 40,
            &[(
                "MESSAGE",
                "pam_unix(sudo:session): session opened for user root",
            )],
        ));
        text.push_str(&entry(
            NOON_ISH - 30,
            &[(
                "MESSAGE",
                "mallory : command not allowed ; TTY=pts/3 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh",
            )],
        ));
        text.push_str(&entry(
            NOON_ISH - 20,
            &[(
                "MESSAGE",
                &line("sean", &format!("/bin/echo {}", "x".repeat(400))),
            )],
        ));
        let found = sudo_events(text.as_bytes(), NOON_ISH - HOUR, 0);
        assert_eq!(found.total, 9);
        let lines = whats(&found);
        assert_eq!(lines.len(), 4, "{lines:?}");
        assert_eq!(
            lines[0],
            "nagios as root: /usr/local/sbin/check --all [6 times; first 2026-11-20 16:50:00]"
        );
        assert!(
            lines[1].starts_with("sean as root: /usr/bin/mysql"),
            "{}",
            lines[1]
        );
        assert!(!lines[1].contains("hunter2"), "{}", lines[1]);
        assert_eq!(lines[2], "mallory as root (command not allowed): /bin/sh");
        // a long command is cut
        assert!(lines[3].chars().count() < 200, "{}", lines[3]);
        assert!(lines[3].ends_with("..."), "{}", lines[3]);
        assert!(found.events.iter().all(|e| e.kind == Kind::Sudo));
    }

    // ---- config files -----------------------------------------------------------------

    fn set_mtime(path: &Path, unix: i64) {
        let file = std::fs::File::options().write(true).open(path).unwrap();
        let when = std::time::UNIX_EPOCH + std::time::Duration::from_secs(unix as u64);
        file.set_modified(when).unwrap();
    }

    fn far() -> Instant {
        Instant::now() + std::time::Duration::from_secs(60)
    }

    #[test]
    fn files_changed_in_the_period_are_found_and_older_ones_are_not() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("nginx/conf.d")).unwrap();
        std::fs::write(root.join("nginx/nginx.conf"), "new").unwrap();
        std::fs::write(root.join("nginx/conf.d/site.conf"), "new").unwrap();
        std::fs::write(root.join("hosts"), "old").unwrap();
        set_mtime(&root.join("nginx/nginx.conf"), NOON_ISH - 100);
        set_mtime(&root.join("nginx/conf.d/site.conf"), NOON_ISH - 50);
        set_mtime(&root.join("hosts"), NOON_ISH - 2 * HOUR);

        let found = changed_files(root, NOON_ISH - HOUR, &|_| false, far(), 50_000);
        assert!(!found.incomplete);
        let shown = root.display();
        let mut files = found.files.clone();
        files.sort();
        assert_eq!(
            files,
            [
                (NOON_ISH - 100, format!("{shown}/nginx/nginx.conf")),
                (NOON_ISH - 50, format!("{shown}/nginx/conf.d/site.conf")),
            ]
        );
    }

    #[test]
    fn the_search_follows_no_link_and_names_nothing_that_is_denied() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(outside.path().join("elsewhere.conf"), "x").unwrap();
        std::fs::create_dir_all(root.join("ssl/private")).unwrap();
        std::fs::write(root.join("ssl/private/server.key"), "x").unwrap();
        std::fs::write(root.join("ssl/cert.pem"), "x").unwrap();
        std::fs::write(root.join("shadow"), "x").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.join("linked-dir")).unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("elsewhere.conf"),
            root.join("linked-file"),
        )
        .unwrap();

        let shown = root.display().to_string();
        let private = format!("{shown}/ssl/private");
        let shadow = format!("{shown}/shadow");
        let denied = move |path: &str| path.starts_with(&private) || path == shadow;
        let found = changed_files(root, 0, &denied, far(), 50_000);
        let names: Vec<&str> = found.files.iter().map(|(_, path)| path.as_str()).collect();
        assert_eq!(names, [format!("{shown}/ssl/cert.pem")]);
    }

    #[test]
    fn a_search_that_runs_out_of_entries_or_time_says_it_is_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        for n in 0..20 {
            std::fs::write(dir.path().join(format!("f{n}")), "x").unwrap();
        }
        let found = changed_files(dir.path(), 0, &|_| false, far(), 5);
        assert!(found.incomplete);
        assert!(found.files.len() <= 5);

        let past = Instant::now();
        let found = changed_files(dir.path(), 0, &|_| false, past, 50_000);
        assert!(found.incomplete);
    }

    /// AIDEV-NOTE: a tree deeper than the search goes used to end the search there in
    /// silence: "no file changed" below that depth was never looked for.
    #[test]
    fn a_tree_deeper_than_the_search_goes_says_it_is_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        let mut deep = dir.path().to_path_buf();
        for level in 0..MAX_LEVELS + 2 {
            deep.push(format!("d{level}"));
        }
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("bottom.conf"), "x").unwrap();
        let found = changed_files(dir.path(), 0, &|_| false, far(), 50_000);
        assert!(found.incomplete);
        assert!(found.files.is_empty(), "{:?}", found.files);
        // a shallow tree is searched whole
        let shallow = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(shallow.path().join("a/b")).unwrap();
        std::fs::write(shallow.path().join("a/b/c.conf"), "x").unwrap();
        let found = changed_files(shallow.path(), 0, &|_| false, far(), 50_000);
        assert!(!found.incomplete);
        assert_eq!(found.files.len(), 1);
        // a directory that is not entered because it is denied is no gap in the search
        let found = changed_files(dir.path(), 0, &|path| path.ends_with("/d0"), far(), 50_000);
        assert!(!found.incomplete);
    }

    #[test]
    fn a_missing_directory_has_no_changed_files() {
        let found = changed_files(Path::new("/nonexistent/etc"), 0, &|_| false, far(), 100);
        assert_eq!(found, Changed::default());
    }

    // ---- the report -------------------------------------------------------------------

    fn report(limit: usize) -> Report {
        Report {
            hours: 24,
            offset: -7 * HOUR,
            limit,
            counts: vec![(Kind::Package, 2), (Kind::Boot, 1), (Kind::Unit, 0)],
            notes: vec!["[sudo left out: needs journal.view]".to_string()],
            gaps: true,
        }
    }

    #[test]
    fn the_report_is_one_timeline_oldest_first() {
        let events = vec![
            event(NOON_ISH - 10, Kind::Unit, "nginx.service restarted"),
            event(NOON_ISH - 600, Kind::Package, "upgrade nginx 1 -> 2"),
            event(NOON_ISH - 3000, Kind::Boot, "the system booted"),
        ];
        let text = render(&report(150), events, 60_000);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[0],
            "Changes in the last 24 hours, oldest first. Times are local (UTC-07:00)."
        );
        assert_eq!(lines[1], "Found: 2 package changes, 1 boot, 0 unit events.");
        assert_eq!(lines[2], "[sudo left out: needs journal.view]");
        assert_eq!(lines[3], "");
        assert_eq!(lines[4], "TIME                 KIND     WHAT");
        assert_eq!(lines[5], "2026-11-20 09:10:00  boot     the system booted");
        assert_eq!(
            lines[6],
            "2026-11-20 09:50:00  package  upgrade nginx 1 -> 2"
        );
        assert_eq!(
            lines[7],
            "2026-11-20 09:59:50  unit     nginx.service restarted"
        );
        assert_eq!(lines.len(), 8);
    }

    #[test]
    fn with_too_many_events_the_newest_are_kept_and_the_rest_counted() {
        let events: Vec<Event> = (0..20)
            .map(|n| {
                event(
                    NOON_ISH - 1000 + n,
                    Kind::Config,
                    &format!("changed /etc/f{n}"),
                )
            })
            .collect();
        let text = render(&report(5), events, 60_000);
        assert!(text.contains("[15 earlier events left out"), "{text}");
        assert!(text.contains("/etc/f19"), "{text}");
        assert!(text.contains("/etc/f15"), "{text}");
        assert!(!text.contains("/etc/f14\n"), "{text}");
    }

    #[test]
    fn a_report_that_is_too_long_drops_its_oldest_lines_and_says_so() {
        let events: Vec<Event> = (0..200)
            .map(|n| {
                event(
                    NOON_ISH - 1000 + n,
                    Kind::Config,
                    &format!("changed /etc/file-number-{n}"),
                )
            })
            .collect();
        let text = render(&report(500), events, 2000);
        assert!(text.len() <= 2000, "{}", text.len());
        assert!(text.starts_with("Changes in the last 24 hours"), "{text}");
        assert!(text.contains("file-number-199"), "{text}");
        assert!(!text.contains("file-number-0\n"), "{text}");
        assert!(text.contains("left out to fit the output limit"), "{text}");
    }

    #[test]
    fn a_period_with_nothing_in_it_says_so() {
        let mut empty = report(150);
        empty.counts = vec![(Kind::Boot, 0)];
        empty.notes.clear();
        empty.gaps = false;
        let text = render(&empty, Vec::new(), 60_000);
        assert!(
            text.contains("Nothing was recorded in this period."),
            "{text}"
        );
        assert!(!text.contains("TIME"), "{text}");
    }

    /// AIDEV-NOTE: "nothing was recorded" is a statement about the host. When a part was
    /// left out or could not be read it is not known to be true.
    #[test]
    fn nothing_found_is_not_nothing_recorded_when_a_part_could_not_be_read() {
        let mut gaps = report(150);
        gaps.counts = vec![(Kind::Boot, 0)];
        let text = render(&gaps, Vec::new(), 60_000);
        assert!(!text.contains("Nothing was recorded"), "{text}");
        assert!(
            text.ends_with(
                "\nNothing was found in what could be read; the notes above say what could \
                 not be.\n"
            ),
            "{text}"
        );
    }

    #[test]
    fn host_data_in_an_event_cannot_start_a_line_of_its_own() {
        let events = vec![event(
            NOON_ISH,
            Kind::Config,
            "changed /etc/a\n2026-11-20 fake",
        )];
        let text = render(&report(150), events, 60_000);
        assert!(text.contains("changed /etc/a\\n2026-11-20 fake"), "{text}");
    }

    // ---- performance history ----------------------------------------------------------

    #[test]
    fn the_sysstat_file_for_a_day_is_looked_for_under_both_names_in_every_directory() {
        let dirs = [
            PathBuf::from("/var/log/sysstat"),
            PathBuf::from("/var/log/sa"),
        ];
        assert_eq!(
            sar_candidates(&dirs, "2026-11-05"),
            [
                PathBuf::from("/var/log/sysstat/sa05"),
                PathBuf::from("/var/log/sysstat/sa20261105"),
                PathBuf::from("/var/log/sa/sa05"),
                PathBuf::from("/var/log/sa/sa20261105"),
            ]
        );
    }

    #[test]
    fn the_period_defaults_to_the_last_hour_today_and_the_whole_of_another_day() {
        // today at 10:30
        assert_eq!(period(true, 630, None, None), Ok((570, 630)));
        // shortly after midnight there is less than an hour to show
        assert_eq!(period(true, 20, None, None), Ok((0, 20)));
        assert_eq!(period(true, 0, None, None), Ok((0, 1)));
        // another day
        assert_eq!(period(false, 630, None, None), Ok((0, 1439)));
        // one end given
        assert_eq!(period(true, 630, Some(60), None), Ok((60, 630)));
        assert_eq!(period(true, 630, None, Some(300)), Ok((240, 300)));
        assert_eq!(period(false, 630, Some(600), None), Ok((600, 1439)));
        assert_eq!(period(false, 630, None, Some(300)), Ok((0, 300)));
        // both given
        assert_eq!(period(false, 0, Some(180), Some(240)), Ok((180, 240)));
    }

    #[test]
    fn a_period_must_run_forwards_and_not_start_in_the_future() {
        assert!(period(false, 0, Some(240), Some(240)).is_err());
        assert!(period(false, 0, Some(300), Some(240)).is_err());
        let late = period(true, 630, Some(700), None).unwrap_err();
        assert!(late.contains("future") && late.contains("10:30"), "{late}");
        // an end later than now is fine: the history simply stops at the present
        assert_eq!(period(true, 630, Some(600), Some(1439)), Ok((600, 1439)));
    }

    #[test]
    fn the_boot_time_is_read_from_proc_stat() {
        let stat = "cpu  1 2 3 4\nctxt 99\nbtime 1795190000\nprocesses 5\n";
        assert_eq!(
            boot_from_stat(stat, NOON_ISH),
            Some(Boot {
                index: 0,
                first: 1_795_190_000,
                last: NOON_ISH
            })
        );
        assert_eq!(boot_from_stat("cpu 1 2 3\n", NOON_ISH), None);
        assert_eq!(boot_from_stat("btime soon\n", NOON_ISH), None);
    }

    // ---- reading dpkg's logs ----------------------------------------------------------

    fn gzip(path: &Path, text: &str) {
        use std::io::Write;
        let file = std::fs::File::create(path).unwrap();
        let mut encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        encoder.write_all(text.as_bytes()).unwrap();
        encoder.finish().unwrap();
    }

    /// A dpkg log line for a time, written in local time as dpkg writes it.
    fn dpkg_line(unix: i64, offset: i64, rest: &str) -> String {
        format!("{} {rest}\n", local_stamp(unix, offset))
    }

    #[test]
    fn package_events_come_from_the_current_and_the_rotated_logs() {
        let dir = tempfile::tempdir().unwrap();
        let offset = -7 * HOUR;
        let start = NOON_ISH - 48 * HOUR;
        std::fs::write(
            dir.path().join("dpkg.log"),
            dpkg_line(NOON_ISH - 60, offset, "upgrade nginx:amd64 1 2")
                + &dpkg_line(NOON_ISH - 59, offset, "status installed nginx:amd64 2"),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("dpkg.log.1"),
            dpkg_line(NOON_ISH - 30 * HOUR, offset, "install jq:amd64 <none> 1.7"),
        )
        .unwrap();
        gzip(
            &dir.path().join("dpkg.log.2.gz"),
            &(dpkg_line(NOON_ISH - 40 * HOUR, offset, "remove vim:amd64 9.1 <none>")
                + &dpkg_line(NOON_ISH - 60 * HOUR, offset, "install old:amd64 <none> 1")),
        );
        let (events, notes) = read_dpkg_logs(dir.path(), start, offset).unwrap();
        assert_eq!(notes, Vec::<String>::new());
        let mut found: Vec<(i64, &str)> =
            events.iter().map(|e| (e.time, e.what.as_str())).collect();
        found.sort();
        assert_eq!(
            found,
            [
                (NOON_ISH - 40 * HOUR, "remove vim:amd64 9.1"),
                (NOON_ISH - 30 * HOUR, "install jq:amd64 1.7"),
                (NOON_ISH - 60, "upgrade nginx:amd64 1 -> 2"),
            ]
        );
    }

    #[test]
    fn a_log_last_written_before_the_period_ends_the_search() {
        let dir = tempfile::tempdir().unwrap();
        let start = NOON_ISH - HOUR;
        std::fs::write(
            dir.path().join("dpkg.log"),
            dpkg_line(NOON_ISH - 60, 0, "upgrade nginx:amd64 1 2"),
        )
        .unwrap();
        // Its content claims a time inside the period, but the file was last written
        // long before: it is not opened, and neither is anything older.
        let stale = dir.path().join("dpkg.log.1");
        std::fs::write(
            &stale,
            dpkg_line(NOON_ISH - 30, 0, "install ghost:amd64 <none> 1"),
        )
        .unwrap();
        set_mtime(&stale, start - 10);
        std::fs::write(
            dir.path().join("dpkg.log.2"),
            dpkg_line(NOON_ISH - 20, 0, "install older:amd64 <none> 1"),
        )
        .unwrap();
        let (events, _) = read_dpkg_logs(dir.path(), start, 0).unwrap();
        let found: Vec<&str> = events.iter().map(|e| e.what.as_str()).collect();
        assert_eq!(found, ["upgrade nginx:amd64 1 -> 2"]);
    }

    #[test]
    fn a_host_without_dpkg_logs_has_none_and_a_linked_log_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_dpkg_logs(dir.path(), 0, 0).is_none());
        let elsewhere = tempfile::tempdir().unwrap();
        let real = elsewhere.path().join("secret");
        std::fs::write(&real, dpkg_line(NOON_ISH, 0, "install x:amd64 <none> 1")).unwrap();
        std::os::unix::fs::symlink(&real, dir.path().join("dpkg.log")).unwrap();
        assert!(read_dpkg_logs(dir.path(), 0, 0).is_none());
    }

    #[test]
    fn only_so_many_logs_are_read_and_the_report_says_when_that_cut_the_period_short() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("dpkg.log"), "").unwrap();
        for n in 1..=8 {
            std::fs::write(
                dir.path().join(format!("dpkg.log.{n}")),
                dpkg_line(
                    NOON_ISH - n * HOUR,
                    0,
                    &format!("install p{n}:amd64 <none> 1"),
                ),
            )
            .unwrap();
        }
        let (events, notes) = read_dpkg_logs(dir.path(), 0, 0).unwrap();
        // dpkg.log and five rotated copies
        assert_eq!(events.len(), 5, "{events:?}");
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(
            notes[0].contains("only the 6 newest dpkg logs"),
            "{}",
            notes[0]
        );
    }

    /// AIDEV-NOTE: a log larger than is read used to be read from its START, so the
    /// events that were lost were the newest ones: the ones the period asks about.
    #[test]
    fn a_file_larger_than_its_limit_is_read_from_its_end() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("plain");
        std::fs::write(&plain, "aaaa\nbbbb\ncccc\ndddd\n").unwrap();
        // the last 12 bytes begin inside "bbbb": that broken line is dropped
        assert_eq!(
            read_tail(open_plain(&plain).unwrap(), false, 12),
            ("cccc\ndddd\n".to_string(), true)
        );
        assert_eq!(
            read_tail(open_plain(&plain).unwrap(), false, 20),
            ("aaaa\nbbbb\ncccc\ndddd\n".to_string(), false)
        );
        let packed = dir.path().join("packed.gz");
        let lines: String = (0..1000).map(|n| format!("line {n}\n")).collect();
        gzip(&packed, &lines);
        let (text, cut) = read_tail(open_plain(&packed).unwrap(), true, 50);
        assert!(cut);
        assert!(text.ends_with("line 998\nline 999\n"), "{text:?}");
        assert!(text.starts_with("line 99"), "{text:?}");
        assert!(text.len() <= 50, "{}", text.len());
        let (text, cut) = read_tail(open_plain(&packed).unwrap(), true, 1 << 20);
        assert_eq!((text, cut), (lines, false));
        // a damaged archive gives what could be read, not an error
        std::fs::write(&packed, b"\x1f\x8b\x08\x00garbage").unwrap();
        let (text, cut) = read_tail(open_plain(&packed).unwrap(), true, 50);
        assert_eq!((text.as_str(), cut), ("", false));
    }

    #[test]
    fn a_huge_dpkg_log_gives_its_newest_events_and_a_note() {
        let dir = tempfile::tempdir().unwrap();
        // more than the limit of status lines from long ago, then one new event
        let old = dpkg_line(NOON_ISH - 300 * HOUR, 0, "install ancient:amd64 <none> 1");
        let filler = dpkg_line(NOON_ISH - 200 * HOUR, 0, "status installed filler:amd64 1");
        let mut text = old;
        while (text.len() as u64) <= MAX_DPKG_BYTES {
            text.push_str(&filler);
        }
        text.push_str(&dpkg_line(NOON_ISH - 60, 0, "upgrade nginx:amd64 1 2"));
        std::fs::write(dir.path().join("dpkg.log"), text).unwrap();
        let (events, notes) = read_dpkg_logs(dir.path(), 0, 0).unwrap();
        let found: Vec<&str> = events.iter().map(|e| e.what.as_str()).collect();
        assert_eq!(found, ["upgrade nginx:amd64 1 -> 2"]);
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(
            notes[0].contains("dpkg.log is larger than 8 MiB: only its last part, with the newest events, was read"),
            "{}",
            notes[0]
        );
    }

    // ---- the tools, against stand-in commands -----------------------------------------

    use crate::audit::testing::MemorySink;
    use crate::tools::Host;
    use crate::tools::testing::{FakeBins, call, find, host, ok_text};
    use serde_json::json;
    use std::sync::Arc;

    /// A machine in a temporary directory: logs, a configuration tree, history files.
    struct Machine {
        dir: tempfile::TempDir,
    }

    impl Machine {
        fn new() -> Machine {
            let dir = tempfile::tempdir().unwrap();
            for sub in ["log", "etc", "sysstat", "sa", "atop", "data"] {
                std::fs::create_dir(dir.path().join(sub)).unwrap();
            }
            std::fs::write(dir.path().join("stat"), "cpu 1 2 3\nbtime 1000\n").unwrap();
            Machine { dir }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.dir.path().join(name)
        }

        fn places(&self) -> Places {
            Places {
                dpkg_log_dir: self.path("log"),
                etc: self.path("etc"),
                proc_stat: self.path("stat"),
                sar_dirs: vec![self.path("sysstat"), self.path("sa")],
                atop_dir: self.path("atop"),
            }
        }

        /// A journalctl stand-in that answers each kind of query from a file.
        fn journalctl(&self, fake: FakeBins) -> FakeBins {
            let data = self.path("data").display().to_string();
            let cat = |file: &str| {
                format!(
                    "if [ -f '{data}/{file}' ]; then while IFS= read -r line; do printf '%s\\n' \"$line\"; done < '{data}/{file}'; fi"
                )
            };
            fake.add_script(
                "journalctl",
                &format!(
                    "case \"$*\" in\n*--list-boots*) {} ;;\n*_PID=1*) {} ;;\n*SYSLOG_IDENTIFIER=sudo*) {} ;;\nesac\n",
                    cat("boots"),
                    cat("units"),
                    cat("sudo")
                ),
            )
        }

        fn data(&self, file: &str, text: &str) {
            std::fs::write(self.path("data").join(file), text).unwrap();
        }
    }

    const OFFSET: i64 = -7 * HOUR;

    fn date(fake: FakeBins) -> FakeBins {
        fake.add("date", "-0700\n", 0)
    }

    fn fixture(fake: &FakeBins, extra: &str) -> (Arc<Host>, MemorySink) {
        host(&format!(
            r#"
[roles.reader]
allow = ["@read"]
[roles.narrow]
allow = ["history.view", "service.view:nginx.service", "fs.view:/var/log/**"]
[roles.other]
allow = ["system.view"]
[unix_users.rita]
roles = ["reader"]
[unix_users.nell]
roles = ["narrow"]
[unix_users.sam]
roles = ["other"]
{extra}
{}"#,
            fake.config_only()
        ))
    }

    async fn changes(
        host: &Arc<Host>,
        machine: &Machine,
        user: &str,
        arguments: serde_json::Value,
    ) -> ToolResult {
        let tool = find(tools_with(machine.places()), "change_history");
        call(host, user, &tool, arguments).await
    }

    async fn performance(
        host: &Arc<Host>,
        machine: &Machine,
        user: &str,
        arguments: serde_json::Value,
    ) -> ToolResult {
        let tool = find(tools_with(machine.places()), "perf_history");
        call(host, user, &tool, arguments).await
    }

    /// Fills a machine with one event of every kind, a few minutes apart.
    fn busy(machine: &Machine, now: i64) {
        std::fs::write(
            machine.path("log").join("dpkg.log"),
            dpkg_line(
                now - 50 * 60,
                OFFSET,
                "upgrade nginx:amd64 1.24.0-1 1.24.0-2",
            ),
        )
        .unwrap();
        machine.data(
            "boots",
            &format!(
                "[{{\"index\":-1,\"boot_id\":\"a\",\"first_entry\":{},\"last_entry\":{}}},{{\"index\":0,\"boot_id\":\"b\",\"first_entry\":{},\"last_entry\":{}}}]\n",
                (now - 90 * HOUR) * 1_000_000,
                (now - 41 * 60) * 1_000_000,
                (now - 40 * 60) * 1_000_000,
                now * 1_000_000
            ),
        );
        machine.data(
            "units",
            &(job(
                now - 20 * 60,
                "nginx.service",
                "restart",
                "done",
                "Stopped nginx.",
            ) + &job(
                now - 30 * 60,
                "app.service",
                "start",
                "failed",
                "Failed to start app.",
            )),
        );
        machine.data(
            "sudo",
            &entry(
                now - 10 * 60,
                &[(
                    "MESSAGE",
                    "    sean : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx",
                )],
            ),
        );
        std::fs::create_dir(machine.path("etc").join("nginx")).unwrap();
        let conf = machine.path("etc").join("nginx/nginx.conf");
        std::fs::write(&conf, "x").unwrap();
        set_mtime(&conf, now - 25 * 60);
        let old = machine.path("etc").join("hosts");
        std::fs::write(&old, "x").unwrap();
        set_mtime(&old, now - 90 * HOUR);
    }

    #[tokio::test]
    async fn the_timeline_merges_every_source_oldest_first() {
        let machine = Machine::new();
        let now = now_secs();
        busy(&machine, now);
        let fake = machine.journalctl(date(FakeBins::new()));
        let (host, sink) = fixture(&fake, "");
        let text = ok_text(changes(&host, &machine, "rita", json!({})).await);

        assert!(
            text.starts_with(
                "Changes in the last 24 hours, oldest first. Times are local (UTC-07:00).\n"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "Found: 1 package change, 1 boot, 2 unit events, 1 changed config file, 1 use of sudo."
            ),
            "{text}"
        );
        let etc = machine.path("etc").display().to_string();
        let expected = [
            "upgrade nginx:amd64 1.24.0-1 -> 1.24.0-2".to_string(),
            "the system went down".to_string(),
            "the system booted".to_string(),
            "app.service start FAILED (failed)".to_string(),
            format!("changed {etc}/nginx/nginx.conf"),
            "nginx.service restarted".to_string(),
            "sean as root: /usr/bin/systemctl restart nginx".to_string(),
        ];
        let mut last = 0;
        for what in &expected {
            let at = text
                .find(what.as_str())
                .unwrap_or_else(|| panic!("{what} missing: {text}"));
            assert!(at > last, "{what} is out of order: {text}");
            last = at;
        }
        // local times, as the offset says
        assert!(text.contains(&local_stamp(now - 50 * 60, OFFSET)), "{text}");
        // what did not change is not there
        assert!(!text.contains(&format!("{etc}/hosts")), "{text}");

        let calls = fake.calls("journalctl");
        assert_eq!(calls.len(), 3, "{calls:?}");
        assert_eq!(
            calls[1],
            [
                "--no-pager",
                "--quiet",
                "--output=json",
                "--output-fields=UNIT,JOB_TYPE,JOB_RESULT,MESSAGE",
                "--since=-24h",
                "--reverse",
                "_PID=1"
            ]
        );
        assert_eq!(
            calls[2][3..],
            [
                "--output-fields=MESSAGE",
                "--since=-24h",
                "--reverse",
                "SYSLOG_IDENTIFIER=sudo",
                "_COMM=sudo"
            ]
        );
        // one decision, written before anything was looked at
        let records = sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["decision"], "allow");
        assert_eq!(records[0]["permission"], "history.view");
    }

    #[tokio::test]
    async fn a_part_is_left_out_without_the_permission_that_owns_its_data() {
        let machine = Machine::new();
        let now = now_secs();
        busy(&machine, now);
        let fake = machine.journalctl(date(FakeBins::new()));
        let (host, _sink) = fixture(&fake, "");
        // nell holds history.view, and the other permissions only for some resources
        let text = ok_text(changes(&host, &machine, "nell", json!({})).await);
        for note in [
            "[packages left out: needs package.view]",
            "[units left out: needs service.view]",
            "[config left out: needs fs.view]",
            "[sudo left out: needs journal.view]",
        ] {
            assert!(text.contains(note), "{note} missing: {text}");
        }
        assert!(text.contains("the system booted"), "{text}");
        for hidden in ["nginx", "app.service", "sean", "FAILED"] {
            assert!(!text.contains(hidden), "{hidden} shown: {text}");
        }
        assert!(text.contains("Found: 1 boot."), "{text}");
        // and nothing was even asked for
        let calls = fake.calls("journalctl");
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert!(calls[0].contains(&"--list-boots".to_string()), "{calls:?}");
    }

    /// AIDEV-NOTE: fs_list refuses a directory outside fs.list_roots whatever the caller
    /// is granted. The names of the files that changed under /etc are a listing too.
    #[tokio::test]
    async fn the_config_part_is_left_out_when_etc_may_not_be_listed_on_this_host() {
        let machine = Machine::new();
        let now = now_secs();
        busy(&machine, now);
        let fake = machine.journalctl(date(FakeBins::new()));
        let (host, _sink) = fixture(&fake, "[fs]\nlist_roots = [\"/var/www\"]\n");
        let text = ok_text(changes(&host, &machine, "rita", json!({})).await);
        let etc = machine.path("etc").display().to_string();
        assert!(
            text.contains(&format!(
                "[config left out: {etc} is outside the directories that fs.list_roots allows on this host]"
            )),
            "{text}"
        );
        assert!(!text.contains("changed "), "{text}");
        assert!(!text.contains("nginx.conf"), "{text}");
        assert!(
            text.contains("Found: 1 package change, 1 boot, 2 unit events, 1 use of sudo."),
            "{text}"
        );

        // listed under a directory that may be: shown as before
        let (host, _sink) = fixture(
            &fake,
            &format!(
                "[fs]\nlist_roots = [\"/var/www\", \"{}\"]\n",
                machine.dir.path().display()
            ),
        );
        let text = ok_text(changes(&host, &machine, "rita", json!({"kind": "config"})).await);
        assert!(
            text.contains(&format!("changed {etc}/nginx/nginx.conf")),
            "{text}"
        );
    }

    #[tokio::test]
    async fn journal_lines_that_cannot_be_read_are_mentioned_in_the_report() {
        let machine = Machine::new();
        let now = now_secs();
        machine.data(
            "units",
            &(job(now - 60, "nginx.service", "start", "done", "Started nginx.")
                + "this line is not an entry\n{also not\n"),
        );
        machine.data("sudo", "not json either\n");
        let fake = machine.journalctl(date(FakeBins::new()));
        let (host, _sink) = fixture(&fake, "");
        let text = ok_text(changes(&host, &machine, "rita", json!({})).await);
        assert!(text.contains("nginx.service started"), "{text}");
        assert!(
            text.contains("[2 journal lines about unit events could not be read and were skipped]"),
            "{text}"
        );
        assert!(
            text.contains("[1 journal line about uses of sudo could not be read and was skipped]"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn a_part_that_failed_is_not_reported_as_a_quiet_period() {
        let machine = Machine::new();
        let fake = date(FakeBins::new()).add_script(
            "journalctl",
            "printf '%s\\n' 'Failed to open journal: Permission denied' >&2; exit 2",
        );
        let (host, _sink) = fixture(&fake, "");
        let text = ok_text(changes(&host, &machine, "rita", json!({"kind": "units"})).await);
        assert!(text.contains("[unit events not available:"), "{text}");
        assert!(!text.contains("Nothing was recorded"), "{text}");
        assert!(
            text.contains("Nothing was found in what could be read"),
            "{text}"
        );
        // a part that was read and is empty IS a quiet period
        let quiet = machine.journalctl(date(FakeBins::new()));
        let (host, _sink) = fixture(&quiet, "");
        let text = ok_text(changes(&host, &machine, "rita", json!({"kind": "units"})).await);
        assert!(
            text.contains("Nothing was recorded in this period."),
            "{text}"
        );
    }

    #[tokio::test]
    async fn one_kind_can_be_asked_for_and_the_hours_are_passed_on() {
        let machine = Machine::new();
        let now = now_secs();
        busy(&machine, now);
        let fake = machine.journalctl(date(FakeBins::new()));
        let (host, _sink) = fixture(&fake, "");
        let text = ok_text(
            changes(
                &host,
                &machine,
                "rita",
                json!({"kind": "units", "hours": 48}),
            )
            .await,
        );
        assert!(text.contains("Changes in the last 48 hours"), "{text}");
        assert!(text.contains("Found: 2 unit events."), "{text}");
        assert!(text.contains("nginx.service restarted"), "{text}");
        for other in ["upgrade nginx", "booted", "sean as root", "changed "] {
            assert!(!text.contains(other), "{other} shown: {text}");
        }
        let calls = fake.calls("journalctl");
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert!(calls[0].contains(&"--since=-48h".to_string()), "{calls:?}");

        // a kind the caller may not see is still left out, not shown
        let text = ok_text(changes(&host, &machine, "nell", json!({"kind": "sudo"})).await);
        assert!(
            text.contains("[sudo left out: needs journal.view]"),
            "{text}"
        );
        // nothing was looked at, so nothing is claimed about the period
        assert!(!text.contains("Nothing was recorded"), "{text}");
        assert!(
            text.contains("Nothing was found in what could be read"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn without_the_permission_nothing_is_looked_at() {
        let machine = Machine::new();
        busy(&machine, now_secs());
        let fake = machine.journalctl(date(FakeBins::new()));
        let (host, sink) = fixture(&fake, "");
        for tool in ["change", "perf"] {
            let result = if tool == "change" {
                changes(&host, &machine, "sam", json!({})).await
            } else {
                performance(&host, &machine, "sam", json!({})).await
            };
            assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        }
        assert_eq!(fake.calls("journalctl").len(), 0);
        assert_eq!(fake.calls("date").len(), 0);
        let records = sink.records();
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|record| record["decision"] == "deny"));
    }

    #[tokio::test]
    async fn without_the_date_command_times_are_utc_and_the_report_says_so() {
        let machine = Machine::new();
        let now = now_secs();
        machine.data(
            "units",
            &job(now - 60, "nginx.service", "start", "done", "Started nginx."),
        );
        let fake = machine.journalctl(FakeBins::new());
        let (host, _sink) = fixture(&fake, "");
        let text = ok_text(changes(&host, &machine, "rita", json!({"kind": "units"})).await);
        assert!(text.contains("Times are local (UTC+00:00)."), "{text}");
        assert!(
            text.contains("[the date command is not available here: times are UTC]"),
            "{text}"
        );
        assert!(text.contains(&local_stamp(now - 60, 0)), "{text}");
    }

    #[tokio::test]
    async fn a_clock_change_inside_the_period_is_pointed_out() {
        let machine = Machine::new();
        let fake = machine.journalctl(FakeBins::new().add_script(
            "date",
            "case \"$*\" in *-d*) printf '%s\\n' '-0600' ;; *) printf '%s\\n' '-0700' ;; esac",
        ));
        let (host, _sink) = fixture(&fake, "");
        let text = ok_text(changes(&host, &machine, "rita", json!({"kind": "boots"})).await);
        assert!(text.contains("UTC-07:00"), "{text}");
        assert!(text.contains("summer and winter time"), "{text}");
        // the second question names the start of the period
        let calls = fake.calls("date");
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert_eq!(calls[0], ["+%z"]);
        assert_eq!(calls[1][0], "-d");
        assert!(calls[1][1].starts_with('@'), "{calls:?}");
        assert_eq!(calls[1][2], "+%z");
    }

    #[tokio::test]
    async fn without_a_journal_the_running_boot_still_comes_from_the_kernel() {
        let machine = Machine::new();
        let now = now_secs();
        std::fs::write(
            machine.path("stat"),
            format!("cpu 1 2\nbtime {}\n", now - 600),
        )
        .unwrap();
        let fake = date(FakeBins::new());
        let (host, _sink) = fixture(&fake, "");
        let text = ok_text(changes(&host, &machine, "rita", json!({})).await);
        assert!(text.contains("the system booted"), "{text}");
        assert!(text.contains(&local_stamp(now - 600, OFFSET)), "{text}");
        assert!(
            text.contains("[unit events not available: journalctl was not found]"),
            "{text}"
        );
        assert!(
            text.contains("[uses of sudo not available: journalctl was not found]"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn on_an_rpm_host_install_times_come_from_rpm() {
        let machine = Machine::new();
        let now = now_secs();
        let listing = format!(
            "{}\tnginx-1.24.0-2.el9.x86_64\n{}\told-1.0-1.el9.noarch\n",
            now - 600,
            now - 90 * HOUR
        );
        let fake = date(FakeBins::new()).add("rpm", &listing, 0);
        let (host, _sink) = fixture(&fake, "");
        let text = ok_text(changes(&host, &machine, "rita", json!({"kind": "packages"})).await);
        assert!(
            text.contains("install or upgrade nginx-1.24.0-2.el9.x86_64"),
            "{text}"
        );
        assert!(!text.contains("old-1.0"), "{text}");
        assert!(text.contains("removals"), "{text}");
        assert_eq!(
            fake.calls("rpm"),
            [[
                "-qa",
                "--qf",
                "%{INSTALLTIME}\\t%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n"
            ]]
        );
    }

    #[tokio::test]
    async fn a_host_with_neither_package_manager_says_so() {
        let machine = Machine::new();
        let fake = date(FakeBins::new());
        let (host, _sink) = fixture(&fake, "");
        let text = ok_text(changes(&host, &machine, "rita", json!({"kind": "packages"})).await);
        assert!(text.contains("neither a dpkg log nor rpm"), "{text}");
    }

    #[tokio::test]
    async fn a_journal_that_fails_is_reported_in_its_part_only() {
        let machine = Machine::new();
        let now = now_secs();
        std::fs::write(
            machine.path("log").join("dpkg.log"),
            dpkg_line(now - 60, OFFSET, "install jq:amd64 <none> 1.7"),
        )
        .unwrap();
        let fake = date(FakeBins::new()).add_script(
            "journalctl",
            "printf '%s\\n' 'Failed to open journal: password=hunter2 Permission denied' >&2; exit 2",
        );
        let (host, _sink) = fixture(&fake, "");
        let text = ok_text(changes(&host, &machine, "rita", json!({})).await);
        assert!(text.contains("install jq:amd64 1.7"), "{text}");
        assert!(
            text.contains("[unit events not available: Failed to open journal"),
            "{text}"
        );
        assert!(text.contains("[uses of sudo not available:"), "{text}");
    }

    #[tokio::test]
    async fn a_small_output_limit_keeps_the_header_and_the_newest_events() {
        let machine = Machine::new();
        let now = now_secs();
        let mut units = String::new();
        for n in 0..300 {
            units.push_str(&job(
                now - 3000 + n,
                &format!("worker-{n}.service"),
                "start",
                "failed",
                "Failed to start worker.",
            ));
        }
        machine.data("units", &units);
        let fake = machine.journalctl(date(FakeBins::new()));
        let (host, _sink) = fixture(&fake, "[limits]\nmax_output_bytes = 4096\n");
        let text = ok_text(
            changes(
                &host,
                &machine,
                "rita",
                json!({"kind": "units", "limit": 500}),
            )
            .await,
        );
        assert!(text.len() <= 4096 - 512, "{}", text.len());
        assert!(text.starts_with("Changes in the last 24 hours"), "{text}");
        assert!(text.contains("worker-299.service"), "{text}");
        assert!(!text.contains("worker-0.service"), "{text}");
        assert!(text.contains("left out to fit the output limit"), "{text}");
    }

    // ---- perf_history

    /// Today's date where the stand-in `date` says the host is.
    fn local_day(now: i64) -> String {
        local_stamp(now, OFFSET)[..10].to_string()
    }

    fn sar(fake: FakeBins) -> FakeBins {
        fake.add_script(
            "sar",
            "printf '%s\\n' \"time format: $S_TIME_FORMAT\" '10:00:01 CPU %user' '10:10:01 all 3.20'",
        )
    }

    #[tokio::test]
    async fn the_history_of_today_comes_from_sysstat() {
        let machine = Machine::new();
        let today = local_day(now_secs());
        let file = machine.path("sysstat").join(format!("sa{}", &today[8..]));
        std::fs::write(&file, "x").unwrap();
        let fake = sar(date(FakeBins::new()));
        let (host, sink) = fixture(&fake, "");
        let text = ok_text(
            performance(
                &host,
                &machine,
                "rita",
                json!({"start": "00:00", "end": "23:59"}),
            )
            .await,
        );
        assert!(
            text.starts_with(&format!(
                "CPU, memory, load and I/O on {today} from 00:00 to 23:59 (local time, UTC-07:00), from sysstat (sar).\n"
            )),
            "{text}"
        );
        assert!(text.contains("10:10:01 all 3.20"), "{text}");
        // 24-hour times, whatever the locale
        assert!(text.contains("time format: ISO"), "{text}");
        assert_eq!(
            fake.calls("sar"),
            [[
                "-f",
                file.to_str().unwrap(),
                "-s",
                "00:00:00",
                "-e",
                "23:59:59",
                "-u",
                "-r",
                "-q",
                "-b"
            ]]
        );
        assert_eq!(sink.records().len(), 1);
    }

    /// AIDEV-NOTE: found against real sysstat: `sar -e 05:33:00` leaves out the samples
    /// taken at 05:33:18, so "the last hour" never showed the newest records.
    #[tokio::test]
    async fn the_end_minute_is_included_whole() {
        let machine = Machine::new();
        let today = local_day(now_secs());
        let file = machine.path("sysstat").join(format!("sa{}", &today[8..]));
        std::fs::write(&file, "x").unwrap();
        let fake = sar(date(FakeBins::new()));
        let (host, _sink) = fixture(&fake, "");
        ok_text(
            performance(
                &host,
                &machine,
                "rita",
                json!({"start": "00:00", "end": "10:30", "metric": "cpu"}),
            )
            .await,
        );
        let calls = fake.calls("sar");
        assert_eq!(
            calls[0][2..6],
            ["-s", "00:00:00", "-e", "10:30:59"].map(String::from)
        );
    }

    #[tokio::test]
    async fn a_period_without_records_says_so_instead_of_showing_only_the_banner() {
        let machine = Machine::new();
        let today = local_day(now_secs());
        let file = machine.path("sysstat").join(format!("sa{}", &today[8..]));
        std::fs::write(&file, "x").unwrap();
        // what sar prints when no sample falls in the period: its banner and nothing else
        let fake = date(FakeBins::new()).add(
            "sar",
            &format!("Linux 6.8.0 (web1) \t{today} \t_x86_64_\t(12 CPU)\n"),
            0,
        );
        let (host, _sink) = fixture(&fake, "");
        let text = ok_text(
            performance(
                &host,
                &machine,
                "rita",
                json!({"start": "00:00", "end": "00:05", "metric": "cpu"}),
            )
            .await,
        );
        assert!(text.contains("[no records for this period:"), "{text}");
    }

    #[test]
    fn the_date_in_sars_first_line_is_found() {
        assert_eq!(
            banner_date("Linux 6.8.0 (web1) \t2026-11-20 \t_x86_64_\t(12 CPU)\n\n10:00:01 CPU\n"),
            Some("2026-11-20".to_string())
        );
        // blank lines before it do not matter; later lines are not the banner
        assert_eq!(
            banner_date("\nLinux 5.14.0 (db1)  2026-01-05  _x86_64_  (4 CPU)\n"),
            Some("2026-01-05".to_string())
        );
        for none in [
            "",
            "time format: ISO\n10:00:01 CPU %user\n",
            // a date in another form is not guessed at
            "Linux 6.8.0 (web1) \t11/20/2026 \t_x86_64_\t(12 CPU)\n",
            "Linux 6.8.0 (web1) \t2026-13-40 \t_x86_64_\n",
            "10:00:01 CPU\nLinux 6.8.0 (web1) \t2026-11-20\n",
        ] {
            assert_eq!(banner_date(none), None, "{none:?}");
        }
    }

    /// AIDEV-NOTE: sysstat names its files by day of the month (`sa20`) and reuses them
    /// every month. Asked for the 20th of LAST month it would read this month's file and
    /// the report would put last month's date over this month's figures.
    #[tokio::test]
    async fn a_sysstat_file_that_holds_another_day_is_not_passed_off_as_the_day_asked_for() {
        let machine = Machine::new();
        let now = now_secs();
        let (today, yesterday) = (local_day(now), local_day(now - 24 * HOUR));
        let file = machine
            .path("sysstat")
            .join(format!("sa{}", &yesterday[8..]));
        std::fs::write(&file, "x").unwrap();
        // the file under yesterday's day of the month says, in its banner, another date
        let fake = date(FakeBins::new()).add(
            "sar",
            &format!("Linux 6.8.0 (web1) \t{today} \t_x86_64_\t(12 CPU)\n\n10:00:01 all 3.20\n"),
            0,
        );
        let (host, _sink) = fixture(&fake, "");
        let result = performance(&host, &machine, "rita", json!({"date": yesterday})).await;
        let Err(ToolError::Failed(message)) = result else {
            panic!("expected a failure, got {result:?}");
        };
        assert_eq!(
            message,
            format!(
                "sysstat has no records for {yesterday} on this host (its file for that day of \
                 the month now holds {today})"
            )
        );

        // the banner names the day asked for: shown
        let fake = date(FakeBins::new()).add(
            "sar",
            &format!(
                "Linux 6.8.0 (web1) \t{yesterday} \t_x86_64_\t(12 CPU)\n\n10:00:01 all 3.20\n"
            ),
            0,
        );
        let (host, _sink) = fixture(&fake, "");
        let text = ok_text(performance(&host, &machine, "rita", json!({"date": yesterday})).await);
        assert!(text.contains("10:00:01 all 3.20"), "{text}");
    }

    #[tokio::test]
    async fn without_a_date_in_the_banner_the_age_of_the_file_decides() {
        let machine = Machine::new();
        let now = now_secs();
        let yesterday = local_day(now - 24 * HOUR);
        let file = machine
            .path("sysstat")
            .join(format!("sa{}", &yesterday[8..]));
        std::fs::write(&file, "x").unwrap();
        // last written forty days ago: it holds that day of an earlier month
        set_mtime(&file, now - 40 * 24 * HOUR);
        let fake = sar(date(FakeBins::new()));
        let (host, _sink) = fixture(&fake, "");
        let result = performance(&host, &machine, "rita", json!({"date": yesterday})).await;
        let Err(ToolError::Failed(message)) = result else {
            panic!("expected a failure, got {result:?}");
        };
        assert!(
            message.starts_with(&format!(
                "sysstat has no records for {yesterday} on this host (its file for that day of \
                 the month was last written on "
            )),
            "{message}"
        );
        // written on the day itself (or just after midnight, when the day is closed): shown
        set_mtime(&file, now - 20 * HOUR);
        let text = ok_text(performance(&host, &machine, "rita", json!({"date": yesterday})).await);
        assert!(text.contains("10:10:01 all 3.20"), "{text}");
    }

    #[tokio::test]
    async fn another_day_is_shown_whole_from_whichever_file_holds_it() {
        let machine = Machine::new();
        let yesterday = local_day(now_secs() - 24 * HOUR);
        // the long file name, in the second directory
        let file = machine
            .path("sa")
            .join(format!("sa{}", yesterday.replace('-', "")));
        std::fs::write(&file, "x").unwrap();
        let fake = sar(date(FakeBins::new()));
        let (host, _sink) = fixture(&fake, "");
        let text = ok_text(
            performance(
                &host,
                &machine,
                "rita",
                json!({"date": yesterday, "metric": "network"}),
            )
            .await,
        );
        assert!(
            text.starts_with(&format!(
                "Network traffic and errors on {yesterday} from 00:00 to 23:59"
            )),
            "{text}"
        );
        assert_eq!(
            fake.calls("sar"),
            [[
                "-f",
                file.to_str().unwrap(),
                "-s",
                "00:00:00",
                "-e",
                "23:59:59",
                "-n",
                "DEV",
                "-n",
                "EDEV"
            ]]
        );
    }

    #[tokio::test]
    async fn each_metric_asks_sar_for_its_own_tables() {
        assert_eq!(sar_flags("overview"), ["-u", "-r", "-q", "-b"]);
        assert_eq!(sar_flags("cpu"), ["-u"]);
        assert_eq!(sar_flags("memory"), ["-r"]);
        assert_eq!(sar_flags("swap"), ["-S", "-W"]);
        assert_eq!(sar_flags("load"), ["-q"]);
        assert_eq!(sar_flags("disk"), ["-b", "-d", "-p"]);
        assert_eq!(atop_flags("overview"), ["-c", "-m", "-p"]);
        assert_eq!(atop_flags("network"), ["-i"]);
        // every metric on offer has a title of its own
        let mut titles: Vec<&str> = METRICS.iter().map(|metric| metric_title(metric)).collect();
        titles.sort();
        titles.dedup();
        assert_eq!(titles.len(), METRICS.len());
    }

    #[tokio::test]
    async fn atop_is_used_when_sysstat_has_nothing_for_the_day() {
        let machine = Machine::new();
        let today = local_day(now_secs());
        let file = machine
            .path("atop")
            .join(format!("atop_{}", today.replace('-', "")));
        std::fs::write(&file, "x").unwrap();
        // sar is installed, but has no file for today
        let fake = sar(date(FakeBins::new())).add("atopsar", "10:10:01  cpu  %usr\n", 0);
        let (host, _sink) = fixture(&fake, "");
        let text = ok_text(
            performance(
                &host,
                &machine,
                "rita",
                json!({"start": "00:00", "end": "23:59", "metric": "cpu"}),
            )
            .await,
        );
        assert!(text.contains("from atop (atopsar)."), "{text}");
        assert!(text.contains("10:10:01  cpu  %usr"), "{text}");
        assert_eq!(fake.calls("sar").len(), 0);
        assert_eq!(
            fake.calls("atopsar"),
            [[
                "-r",
                file.to_str().unwrap(),
                "-b",
                "00:00",
                "-e",
                "23:59",
                "-c"
            ]]
        );
    }

    #[tokio::test]
    async fn a_host_that_keeps_no_history_says_what_to_install() {
        let machine = Machine::new();
        let fake = date(FakeBins::new());
        let (host, _sink) = fixture(&fake, "");
        let result = performance(&host, &machine, "rita", json!({"start": "00:00"})).await;
        let Err(ToolError::Failed(message)) = result else {
            panic!("expected a failure, got {result:?}");
        };
        assert!(message.contains("sar is not installed"), "{message}");
        assert!(message.contains("atopsar is not installed"), "{message}");
        assert!(message.contains("package sysstat"), "{message}");

        // installed, but nothing recorded for that day
        let fake = sar(date(FakeBins::new()));
        let (host, _sink) = fixture(&fake, "");
        let result = performance(&host, &machine, "rita", json!({"start": "00:00"})).await;
        let Err(ToolError::Failed(message)) = result else {
            panic!("expected a failure, got {result:?}");
        };
        assert!(
            message.contains("sar is installed but has no file for that day"),
            "{message}"
        );
        assert_eq!(fake.calls("sar").len(), 0);
    }

    #[tokio::test]
    async fn dates_and_times_must_be_real_and_not_in_the_future() {
        let machine = Machine::new();
        let fake = sar(date(FakeBins::new()));
        let (host, sink) = fixture(&fake, "");
        // refused on sight: nothing is authorized or run for these
        for arguments in [
            json!({"date": "2026-13-01"}),
            json!({"date": "yesterday"}),
            json!({"date": "2026-1-1"}),
            json!({"date": "../../etc"}),
            json!({"start": "25:00"}),
            json!({"end": "9:30"}),
            json!({"start": "-f/x"}),
        ] {
            let result = performance(&host, &machine, "rita", arguments.clone()).await;
            assert!(
                matches!(result, Err(ToolError::Invalid(_))),
                "{arguments}: {result:?}"
            );
        }
        assert_eq!(sink.records().len(), 0);
        assert_eq!(fake.calls("date").len(), 0);

        let now = now_secs();
        let tomorrow = local_day(now + 26 * HOUR);
        let long_ago = local_day(now - 400 * 24 * HOUR);
        for arguments in [
            json!({"date": tomorrow}),
            json!({"date": long_ago}),
            json!({"date": local_day(now - 24 * HOUR), "start": "10:00", "end": "09:00"}),
            json!({"date": local_day(now - 24 * HOUR), "start": "10:00", "end": "10:00"}),
        ] {
            let result = performance(&host, &machine, "rita", arguments.clone()).await;
            assert!(
                matches!(result, Err(ToolError::Invalid(_))),
                "{arguments}: {result:?}"
            );
        }
        assert_eq!(fake.calls("sar").len(), 0);
    }

    #[tokio::test]
    async fn a_long_history_is_cut_to_the_output_limit_with_a_note() {
        let machine = Machine::new();
        let today = local_day(now_secs());
        std::fs::write(
            machine.path("sysstat").join(format!("sa{}", &today[8..])),
            "x",
        )
        .unwrap();
        let fake = date(FakeBins::new()).add_script(
            "sar",
            "n=0; while [ $n -lt 400 ]; do printf '%s\\n' \"10:00:01 all $n 0.00 0.00 0.00\"; n=$((n+1)); done",
        );
        let (host, _sink) = fixture(&fake, "[limits]\nmax_output_bytes = 4096\n");
        let text = ok_text(
            performance(
                &host,
                &machine,
                "rita",
                json!({"start": "00:00", "end": "23:59"}),
            )
            .await,
        );
        assert!(text.len() <= 4096 - 512, "{}", text.len());
        assert!(text.contains("10:00:01 all 0 "), "{text}");
        assert!(!text.contains("all 399 "), "{text}");
        assert!(
            text.contains("more lines left out to fit the output limit"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn a_failing_sar_is_a_failed_result_with_what_it_said() {
        let machine = Machine::new();
        let today = local_day(now_secs());
        std::fs::write(
            machine.path("sysstat").join(format!("sa{}", &today[8..])),
            "x",
        )
        .unwrap();
        let fake = date(FakeBins::new()).add_script(
            "sar",
            "printf '%s\\n' 'Requested activities not available in file' >&2; exit 1",
        );
        let (host, _sink) = fixture(&fake, "");
        let result = performance(
            &host,
            &machine,
            "rita",
            json!({"start": "00:00", "end": "23:59"}),
        )
        .await;
        let output = result.unwrap();
        assert!(output.is_error());
        assert!(
            output.text().contains("Requested activities not available"),
            "{}",
            output.text()
        );
    }
}
