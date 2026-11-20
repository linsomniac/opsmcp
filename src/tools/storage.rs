//! Storage: block devices, drive health, and what is using the space.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::ffi::CStr;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, Stat, fstat, openat, statat};
use serde_json::Value;

use super::args::{Args, Param};
use super::fs::{check_limits, denied_by, dir_resource, pin};
use super::{
    Authorized, CallClock, Ctx, Tool, ToolError, ToolResult, blocking, command_ok, command_text,
    format_table, required,
};
use crate::exec::{Cmd, CmdOutput};
use crate::policy::Access;
use crate::sanitize::{keep_head, redact_args, redact_text};
use crate::timefmt::human_bytes;

const MDSTAT: &str = "/proc/mdstat";

pub fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "block_devices",
            "Show this host's storage layout: disks and partitions with size, type, filesystem \
         and mount point (lsblk), mounted filesystems with their mount options (findmnt), \
         software RAID state (/proc/mdstat) and LVM physical volumes, volume groups and \
         logical volumes. Use it to see what is mounted where and how, or to check a RAID \
         array or a volume group. For free space use disk_usage; for drive health use \
         disk_health.",
            Access::Read,
            "storage.view",
            vec![],
            block_devices,
        ),
        Tool::new(
            "disk_health",
            "Drive health from SMART (smartctl), for SATA, SAS and NVMe drives: the overall \
             verdict, temperature, power-on hours and the main wear or error figure of every \
             drive, or one drive's identity, verdict and attribute table. Use it when a disk \
             is suspected of failing (I/O errors in kernel_log, a degraded RAID array). Needs \
             the smartmontools package; the disks of a virtual machine usually report \
             nothing. Asking a drive that has spun down wakes it.",
            Access::Read,
            "storage.view",
            vec![
                Param::str(
                    "device",
                    "Show the report for this drive, e.g. /dev/sda or /dev/nvme0 \
                     (default: a summary of every drive)",
                )
                .max_len(64),
            ],
            disk_health,
        ),
        Tool::new(
            "disk_hogs",
            "Find what is using the space under a directory: the largest directories (down \
             to a chosen depth), the largest files, and deleted files that a process still \
             holds open (space that disk_usage counts but no file shows). Stays on one \
             filesystem and never follows links. Use it after disk_usage shows a filesystem \
             filling up; start at its mount point and move down. A very large tree is \
             walked for a limited time, and the sizes are then marked as incomplete.",
            Access::Read,
            "fs.view",
            vec![
                Param::str("path", "Absolute path of the directory to examine")
                    .max_len(4096)
                    .required(),
                Param::int(
                    "depth",
                    "Report directories this many levels below it (default 2)",
                    1,
                    5,
                ),
                Param::int("limit", "Most entries in each list (default 20)", 1, 100),
                Param::int(
                    "min_file_mb",
                    "Only list files of at least this many MiB (default 50)",
                    1,
                    1024 * 1024,
                ),
            ],
            disk_hogs,
        ),
    ]
}

/// True when /proc/mdstat describes at least one array (a line such as
/// `md0 : active raid1 sdb1[1] sda1[0]`).
pub fn mdstat_has_arrays(text: &str) -> bool {
    text.lines().any(|line| {
        let mut words = line.split_whitespace();
        words.next().is_some_and(|name| name.starts_with("md")) && words.next() == Some(":")
    })
}

/// Masks credentials in a list of mounts: a password in a source written as a URL, and
/// the value of any mount option whose name suggests a secret.
///
/// AIDEV-NOTE: the kernel hides the passwords of its own network filesystems, but a
/// FUSE filesystem decides for itself what its source and options show. Best effort,
/// like every redaction here.
fn redact_mounts(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in redact_text(text).split_inclusive('\n') {
        let (body, ending) = match line.strip_suffix('\n') {
            Some(body) => (body, "\n"),
            None => (line, ""),
        };
        // Split on single spaces so that the column spacing survives.
        let words: Vec<String> = body
            .split(' ')
            .map(|word| {
                if word.contains('=') {
                    let options: Vec<String> = word.split(',').map(str::to_string).collect();
                    redact_args(&options).join(",")
                } else {
                    word.to_string()
                }
            })
            .collect();
        out.push_str(&words.join(" "));
        out.push_str(ending);
    }
    out
}

/// `text` cut to `room` bytes at a line end, with a note saying how much was left out.
fn fit_section(text: &str, room: usize) -> String {
    let (mut kept, dropped) = keep_head(text, room);
    if dropped > 0 {
        if !kept.is_empty() && !kept.ends_with('\n') {
            kept.push('\n');
        }
        kept.push_str(&format!(
            "[{dropped} more lines left out to fit the output limit]\n"
        ));
    }
    kept
}

/// One section of a report: a heading, then what the command printed (at most `room`
/// bytes of it), or a bracketed line saying why there is nothing. Also returns whether
/// the command gave an answer.
async fn command_section(
    ctx: &Ctx,
    clock: &CallClock,
    title: &str,
    program: &str,
    args: &[&str],
    room: usize,
) -> Result<(String, bool), ToolError> {
    let mut text = format!("== {title} ==\n");
    let cmd = match ctx.command(program) {
        Ok(cmd) => cmd,
        Err(ToolError::Failed(problem)) => {
            text.push_str(&format!("[{problem}]\n"));
            return Ok((text, false));
        }
        Err(other) => return Err(other),
    };
    let Some(limit) = clock.next() else {
        text.push_str("[not run: this call is out of time]\n");
        return Ok((text, false));
    };
    let out = ctx
        .run(cmd.timeout(limit).args(args.iter().copied()))
        .await?;
    let answered = command_ok(&out);
    let body = command_text(&out);
    if body.trim().is_empty() {
        text.push_str("(none)\n");
    } else {
        text.push_str(&fit_section(&body, room));
    }
    Ok((text, answered))
}

async fn block_devices(ctx: Ctx, _args: Args) -> ToolResult {
    let auth = ctx.authorize(None)?;
    block_devices_report(&ctx, auth, Path::new(MDSTAT)).await
}

/// The report behind block_devices. `mdstat` is /proc/mdstat (a parameter for tests).
async fn block_devices_report(ctx: &Ctx, auth: Authorized, mdstat: &Path) -> ToolResult {
    // The two main sections may use a quarter of the output each, the rest an eighth:
    // one host with thousands of container mounts must not crowd out everything else.
    let budget = ctx.output_budget();
    let (large, small) = (budget / 4, budget / 8);
    // The commands share the call's time: a hung one (LVM with an unreachable device)
    // must not cost the whole answer.
    let clock = CallClock::start(ctx);

    let (mut text, devices_ok) = command_section(
        ctx,
        &clock,
        "Block devices (lsblk)",
        "lsblk",
        &["-o", "NAME,TYPE,SIZE,RO,ROTA,FSTYPE,LABEL,MOUNTPOINT,MODEL"],
        large,
    )
    .await?;

    let (mounts, mounts_ok) = command_section(
        ctx,
        &clock,
        "Mounted filesystems (findmnt)",
        "findmnt",
        &["--real", "--list", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"],
        large,
    )
    .await?;
    text.push('\n');
    text.push_str(&redact_mounts(&mounts));

    let mdstat = mdstat.to_path_buf();
    let raid = blocking(ctx.clone(), move || {
        Ok(std::fs::read_to_string(mdstat).unwrap_or_default())
    })
    .await?;
    if mdstat_has_arrays(&raid) {
        text.push_str("\n== Software RAID (/proc/mdstat) ==\n");
        text.push_str(&fit_section(&raid, small));
    }

    let lvm = [
        ("LVM physical volumes (pvs)", "pvs"),
        ("LVM volume groups (vgs)", "vgs"),
        ("LVM logical volumes (lvs)", "lvs"),
    ];
    if lvm
        .iter()
        .all(|(_, program)| ctx.bins().find(program).is_err())
    {
        text.push_str("\n[LVM: the pvs, vgs and lvs commands are not installed]\n");
    } else {
        for (title, program) in lvm {
            let (section, _) = command_section(ctx, &clock, title, program, &[], small).await?;
            text.push('\n');
            text.push_str(&section);
        }
    }
    auth.done(text, devices_ok || mounts_ok)
}

// ---- disk_health ---------------------------------------------------------------------

/// Most drives examined in one call.
const MAX_DRIVES: usize = 32;

/// smartctl's exit status is a bit mask, not a success flag.
const EXIT_NOT_READ: i32 = 0b11; // bits 0-1: bad command line, or the device could not be opened
const EXIT_FAILING: i32 = 1 << 3; // bit 3: the drive itself reports that it is failing
const EXIT_NOTES: [(i32, &str); 5] = [
    (1 << 2, "a SMART command to the drive failed"),
    (1 << 4, "an attribute is at or below its failure threshold"),
    (
        1 << 5,
        "an attribute was at or below its threshold in the past",
    ),
    (1 << 6, "the drive's error log has entries"),
    (1 << 7, "the self-test log has errors"),
];

/// One line of `smartctl --scan`: a device and, usually, the `-d TYPE` needed to reach it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scanned {
    pub device: String,
    pub kind: Option<String>,
}

/// A device node as smartctl names it: under /dev, plain characters only.
fn is_device_path(device: &str) -> bool {
    let plain = |c: char| c.is_ascii_alphanumeric() || "/_-.".contains(c);
    device.len() <= 64
        && device.len() > "/dev/".len()
        && device.starts_with("/dev/")
        && !device.contains("..")
        && device.chars().all(plain)
}

/// A smartctl device type, such as `sat`, `nvme` or `megaraid,3`.
fn is_device_type(kind: &str) -> bool {
    let plain = |c: char| c.is_ascii_alphanumeric() || ",/+_:-".contains(c);
    !kind.is_empty() && kind.len() <= 64 && !kind.starts_with('-') && kind.chars().all(plain)
}

/// The drives listed by `smartctl --scan` (`DEVICE -d TYPE # comment`).
///
/// AIDEV-NOTE: what is parsed here becomes arguments of the next smartctl commands, so a
/// line is only accepted if it has exactly the expected shape; anything else is skipped.
pub fn parse_scan(text: &str) -> Vec<Scanned> {
    let mut found = Vec::new();
    for line in text.lines() {
        let mut words = line.split('#').next().unwrap_or("").split_whitespace();
        let Some(device) = words.next().filter(|device| is_device_path(device)) else {
            continue;
        };
        let kind = match (words.next(), words.next(), words.next()) {
            (None, _, _) => None,
            (Some("-d"), Some(kind), None) if is_device_type(kind) => Some(kind.to_string()),
            _ => continue,
        };
        found.push(Scanned {
            device: device.to_string(),
            kind,
        });
    }
    found
}

/// What the summary table shows for one drive.
#[derive(Debug, PartialEq, Eq)]
pub struct Health {
    pub model: String,
    /// `PASSED`, `FAILED`, `unreadable` or `unknown`.
    pub verdict: &'static str,
    pub temperature: String,
    pub power_on: String,
    /// The one figure that best shows wear or damage, by kind of drive.
    pub wear: String,
    pub notes: Vec<String>,
}

/// The main wear or error figure in a smartctl JSON report.
fn wear_figure(report: &Value) -> String {
    let attributes = report
        .pointer("/ata_smart_attributes/table")
        .and_then(Value::as_array);
    if let Some(table) = attributes {
        let raw = |id: u64| {
            table
                .iter()
                .find(|attribute| attribute.get("id").and_then(Value::as_u64) == Some(id))
                .and_then(|attribute| attribute.pointer("/raw/value"))
                .and_then(Value::as_u64)
        };
        // 5: sectors already replaced by spares; 197: sectors waiting to be.
        if let Some(reallocated) = raw(5) {
            let mut text = format!("{reallocated} reallocated sectors");
            if let Some(pending) = raw(197).filter(|pending| *pending > 0) {
                text.push_str(&format!(", {pending} pending"));
            }
            return text;
        }
    }
    if let Some(log) = report.get("nvme_smart_health_information_log") {
        let number = |key: &str| log.get(key).and_then(Value::as_u64);
        let mut parts = Vec::new();
        if let Some(used) = number("percentage_used") {
            parts.push(format!("{used}% of rated life used"));
        }
        if let Some(errors) = number("media_errors") {
            parts.push(format!("{errors} media errors"));
        }
        if !parts.is_empty() {
            return parts.join(", ");
        }
    }
    match report.get("scsi_grown_defect_list").and_then(Value::as_u64) {
        Some(defects) => format!("{defects} grown defects"),
        None => "-".to_string(),
    }
}

/// Reduces one `smartctl -j -H -i -A` report, and the exit status that came with it, to
/// a table row.
pub fn summarize(report: &Value, code: Option<i32>) -> Health {
    let code = code.unwrap_or(0);
    let model = ["model_name", "scsi_model_name", "product", "scsi_product"]
        .iter()
        .find_map(|key| report.get(key).and_then(Value::as_str))
        .unwrap_or("-")
        .to_string();
    let passed = report
        .pointer("/smart_status/passed")
        .and_then(Value::as_bool);
    let verdict = if code & EXIT_FAILING != 0 || passed == Some(false) {
        "FAILED"
    } else if passed == Some(true) {
        "PASSED"
    } else if code & EXIT_NOT_READ != 0 {
        "unreadable"
    } else {
        "unknown"
    };
    let number = |pointer: &str| report.pointer(pointer).and_then(Value::as_i64);
    let or_dash = |value: Option<String>| value.unwrap_or_else(|| "-".to_string());

    // What smartctl itself said went wrong, then what its exit status adds.
    let mut notes: Vec<String> = report
        .pointer("/smartctl/messages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|message| message.get("string").and_then(Value::as_str))
        .take(2)
        .map(|message| message.chars().take(200).collect())
        .collect();
    if verdict == "unreadable" && notes.is_empty() {
        notes.push("smartctl could not read this drive".to_string());
    }
    for (bit, note) in EXIT_NOTES {
        if code & bit != 0 {
            notes.push(note.to_string());
        }
    }
    Health {
        model,
        verdict,
        temperature: or_dash(number("/temperature/current").map(|t| format!("{t} C"))),
        power_on: or_dash(number("/power_on_time/hours").map(|h| format!("{h} h"))),
        wear: wear_figure(report),
        notes,
    }
}

/// The smartctl command, or a failure that says which package provides it.
fn smartctl(ctx: &Ctx) -> Result<Cmd, ToolError> {
    ctx.optional_command("smartctl")?.ok_or_else(|| {
        ToolError::Failed(
            "the `smartctl` command is not installed on this host; it is part of the \
             smartmontools package"
                .to_string(),
        )
    })
}

/// The arguments that select one scanned drive.
fn drive_args(drive: &Scanned) -> Vec<String> {
    let mut argv = Vec::new();
    if let Some(kind) = &drive.kind {
        argv.push("-d".to_string());
        argv.push(kind.clone());
    }
    argv.push("--".to_string());
    argv.push(drive.device.clone());
    argv
}

/// How a drive is named in the output: its device, plus its type when several drives
/// share one device node (drives behind a RAID controller).
fn drive_label(drive: &Scanned, all: &[Scanned]) -> String {
    let shared = all.iter().filter(|d| d.device == drive.device).count() > 1;
    match &drive.kind {
        Some(kind) if shared => format!("{} [{kind}]", drive.device),
        _ => drive.device.clone(),
    }
}

/// smartctl's plain-text report for one drive, with its exit status put into words.
/// Returns the text, whether the drive could be read, and whether it says it is failing.
fn drive_text(out: &CmdOutput) -> (String, bool, bool) {
    let mut text = String::new();
    for stream in [&out.stdout, &out.stderr] {
        text.push_str(&String::from_utf8_lossy(stream));
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
    }
    let code = out.code.unwrap_or(0);
    let read = out.code.is_some() && !out.timed_out && code & EXIT_NOT_READ == 0;
    if out.timed_out {
        text.push_str("[smartctl did not finish within the time limit]\n");
    } else if out.code.is_none() {
        text.push_str("[smartctl was killed before it finished]\n");
    } else if code & EXIT_NOT_READ != 0 {
        text.push_str(&format!(
            "[smartctl could not read this drive (exit status {code})]\n"
        ));
    }
    for (bit, note) in EXIT_NOTES {
        if code & bit != 0 {
            text.push_str(&format!("[{note}]\n"));
        }
    }
    (text, read, code & EXIT_FAILING != 0)
}

fn failing_line(label: &str) -> String {
    format!(
        "FAILING: {label} reports that it is failing. Back up its data and plan to replace it.\n"
    )
}

async fn disk_health(ctx: Ctx, args: Args) -> ToolResult {
    let wanted = args.str("device").map(str::to_string);
    if let Some(device) = &wanted
        && !is_device_path(device)
    {
        return Err(ToolError::Invalid(format!(
            "{device:?} is not a device such as /dev/sda or /dev/nvme0"
        )));
    }
    let auth = ctx.authorize(None)?;
    // One clock for the scan and every drive: a drive that hangs must not use up the call.
    let clock = CallClock::start(&ctx);
    let scan = ctx.run(smartctl(&ctx)?.args(["--scan"])).await?;
    if !command_ok(&scan) {
        return auth.failed(format!(
            "smartctl could not list the drives:\n{}",
            command_text(&scan)
        ));
    }
    let found = parse_scan(&String::from_utf8_lossy(&scan.stdout));
    if found.is_empty() {
        return auth.ok(
            "No drives with SMART support were found on this host (usual for a virtual \
             machine, whose disks are not real drives).\n",
        );
    }
    match wanted {
        Some(device) => one_drive(&ctx, &clock, auth, &found, &device).await,
        None => every_drive(&ctx, &clock, auth, &found).await,
    }
}

/// The full report for the drive (or the drives behind the controller) at `device`.
async fn one_drive(
    ctx: &Ctx,
    clock: &CallClock,
    auth: Authorized,
    found: &[Scanned],
    device: &str,
) -> ToolResult {
    // AIDEV-NOTE: only a device that smartctl itself listed is ever examined; the
    // caller's text is compared with that list and never reaches the command line.
    let drives: Vec<&Scanned> = found.iter().filter(|d| d.device == device).collect();
    if drives.is_empty() {
        let mut known: Vec<&str> = Vec::new();
        for drive in found {
            if !known.contains(&drive.device.as_str()) {
                known.push(&drive.device);
            }
        }
        return Err(ToolError::Invalid(format!(
            "{device} is not one of the drives smartctl found on this host: {}",
            known.join(", ")
        )));
    }
    let room = ctx.output_budget() / drives.len().clamp(1, MAX_DRIVES);
    let mut failing = String::new();
    let mut text = String::new();
    let mut answered = false;
    for drive in drives.iter().take(MAX_DRIVES) {
        let label = drive_label(drive, found);
        let Some(limit) = clock.next() else {
            text.push_str(&format!(
                "== {label} ==\n[not examined: this call is out of time]\n"
            ));
            continue;
        };
        let cmd = smartctl(ctx)?
            .timeout(limit)
            .args(["-H", "-i", "-A"])
            .args(drive_args(drive));
        let (report, read, is_failing) = drive_text(&ctx.run(cmd).await?);
        answered |= read;
        if is_failing {
            failing.push_str(&failing_line(&label));
        }
        text.push_str(&format!(
            "== {label} ==\n{}",
            fit_section(&report, room.saturating_sub(200))
        ));
    }
    if drives.len() > MAX_DRIVES {
        text.push_str(&format!(
            "[{} more drives at {device} were not examined]\n",
            drives.len() - MAX_DRIVES
        ));
    }
    if !failing.is_empty() {
        failing.push('\n');
    }
    auth.done(format!("{failing}{text}"), answered)
}

/// One table row per drive.
async fn every_drive(
    ctx: &Ctx,
    clock: &CallClock,
    auth: Authorized,
    found: &[Scanned],
) -> ToolResult {
    let mut failing = String::new();
    let mut rows = Vec::new();
    let mut notes = String::new();
    let mut reports = String::new();
    // Until a drive's answer turns out not to be JSON (smartmontools before 7.0).
    let mut json = true;
    let mut examined = 0;
    let mut out_of_time = false;
    for drive in found.iter().take(MAX_DRIVES) {
        let Some(limit) = clock.next() else {
            out_of_time = true;
            break;
        };
        examined += 1;
        let label = drive_label(drive, found);
        if json {
            let cmd = smartctl(ctx)?
                .timeout(limit)
                .args(["-j", "-H", "-i", "-A"])
                .args(drive_args(drive));
            let out = ctx.run(cmd).await?;
            let report = serde_json::from_slice::<Value>(&out.stdout)
                .ok()
                .filter(Value::is_object);
            let health = match report {
                Some(report) => Some(summarize(&report, out.code)),
                None if out.timed_out => Some(Health {
                    model: "-".to_string(),
                    verdict: "unknown",
                    temperature: "-".to_string(),
                    power_on: "-".to_string(),
                    wear: "-".to_string(),
                    notes: vec!["smartctl did not finish within the time limit".to_string()],
                }),
                None => None,
            };
            if let Some(health) = health {
                if health.verdict == "FAILED" {
                    failing.push_str(&failing_line(&label));
                }
                for note in &health.notes {
                    notes.push_str(&format!("[{label}: {note}]\n"));
                }
                rows.push(vec![
                    label,
                    health.model,
                    health.verdict.to_string(),
                    health.temperature,
                    health.power_on,
                    health.wear,
                ]);
                continue;
            }
            json = false;
        }
        let Some(limit) = clock.next() else {
            out_of_time = true;
            break;
        };
        let cmd = smartctl(ctx)?
            .timeout(limit)
            .args(["-H", "-A"])
            .args(drive_args(drive));
        let (report, _, is_failing) = drive_text(&ctx.run(cmd).await?);
        if is_failing {
            failing.push_str(&failing_line(&label));
        }
        reports.push_str(&format!("== {label} ==\n{report}"));
    }

    let mut text = String::new();
    if !failing.is_empty() {
        text.push_str(&failing);
        text.push('\n');
    }
    if !rows.is_empty() {
        let headers = [
            "DEVICE",
            "MODEL",
            "HEALTH",
            "TEMP",
            "POWER-ON",
            "WEAR / ERRORS",
        ];
        let right = [false, false, false, true, true, false];
        text.push_str(&format_table(&headers, &rows, &right));
        text.push_str(&notes);
    }
    if !reports.is_empty() {
        let room = ctx.output_budget().saturating_sub(text.len() + 300);
        text.push_str(&fit_section(&reports, room));
    }
    let left = found.len() - examined;
    if out_of_time {
        text.push_str(&format!(
            "[{left} more drives were not examined: out of time; ask for one with `device`]\n"
        ));
    } else if left > 0 {
        text.push_str(&format!(
            "[{left} more drives were not examined: only the first {MAX_DRIVES} are; ask for one with `device`]\n"
        ));
    }
    auth.ok(text)
}

// ---- disk_hogs -----------------------------------------------------------------------

/// Directories nested deeper than this are not entered: the walk keeps one descriptor
/// open per level.
const MAX_LEVELS: usize = 200;
/// How many files with several names are remembered so that each is counted once.
const MAX_LINKED: usize = 1_000_000;
/// The search for deleted files stops after this many descriptors, or this long.
const MAX_FD_LINKS: usize = 200_000;
const DELETED_SCAN_TIME: Duration = Duration::from_secs(5);
/// What the kernel appends to the path of an open file that has been unlinked.
const DELETED_MARK: &str = " (deleted)";

/// What disk_hogs was asked for.
struct HogOpts {
    /// Directories this many levels below the one asked about are reported.
    depth: usize,
    /// Most entries per section.
    limit: usize,
    /// Files using less than this are not listed.
    min_file_bytes: u64,
    /// How long the walk may take.
    walk_time: Duration,
}

/// The limits of one walk.
pub struct WalkOpts {
    pub depth: usize,
    pub limit: usize,
    pub min_file_bytes: u64,
    /// When the walk gives up and reports what it has.
    pub deadline: Instant,
}

/// One directory or file and the disk space it uses.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Item {
    pub bytes: u64,
    pub path: String,
    /// The walk ran out of time inside this directory: it uses at least `bytes`.
    pub partial: bool,
}

/// What a walk found.
#[derive(Debug)]
pub struct Usage {
    /// Space used by everything under the directory (on its filesystem).
    pub total: u64,
    /// The walk ran out of time: `total` is a lower bound.
    pub partial: bool,
    /// The largest directories within `depth` levels, largest first.
    pub dirs: Vec<Item>,
    /// The largest files, largest first.
    pub files: Vec<Item>,
    /// Entries that would have been listed but that the caller may not see.
    pub hidden: u64,
    /// Directories that could not be entered.
    pub unreadable: u64,
}

/// The `limit` largest visible items offered so far.
struct Top {
    limit: usize,
    items: BinaryHeap<Reverse<Item>>,
    hidden: u64,
}

impl Top {
    fn new(limit: usize) -> Top {
        Top {
            limit: limit.max(1),
            items: BinaryHeap::new(),
            hidden: 0,
        }
    }

    /// Whether something of this size would make the list. Asked first, so that the
    /// (comparatively costly) path and policy check is only done for candidates.
    fn ranks(&self, bytes: u64) -> bool {
        self.items.len() < self.limit
            || self
                .items
                .peek()
                .is_some_and(|Reverse(least)| bytes > least.bytes)
    }

    fn offer(&mut self, item: Item, visible: bool) {
        if !visible {
            self.hidden += 1;
            return;
        }
        self.items.push(Reverse(item));
        if self.items.len() > self.limit {
            self.items.pop();
        }
    }

    fn sorted(self) -> Vec<Item> {
        let mut items: Vec<Item> = self.items.into_iter().map(|Reverse(item)| item).collect();
        items.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.path.cmp(&b.path)));
        items
    }
}

/// The few facts the walk needs about a file.
struct Meta {
    dev: u64,
    ino: u64,
    links: u64,
    kind: FileType,
    /// Disk space allocated to it (what `du` reports), not its apparent length.
    bytes: u64,
}

// The fields of `Stat` have different integer types on different architectures.
#[allow(clippy::unnecessary_cast)]
fn meta_of(stat: &Stat) -> Meta {
    Meta {
        dev: stat.st_dev as u64,
        ino: stat.st_ino as u64,
        links: stat.st_nlink as u64,
        kind: FileType::from_raw_mode(stat.st_mode),
        bytes: (stat.st_blocks as u64).saturating_mul(512),
    }
}

fn child_path(parent: &str, name: &CStr) -> String {
    let name = name.to_string_lossy();
    if parent.ends_with('/') {
        format!("{parent}{name}")
    } else {
        format!("{parent}/{name}")
    }
}

/// A directory being walked.
struct Frame {
    /// The open directory and how far it has been read.
    dir: Dir,
    path: String,
    /// 0 for the directory the walk started at.
    level: usize,
    /// Space used by what has been counted in and under this directory so far.
    bytes: u64,
    /// Something in or under it was not counted: it uses at least `bytes`.
    partial: bool,
}

/// Adds up the disk space used under the directory open at `root`, staying on its
/// filesystem and never following a link, and picks out the largest directories and
/// files. `visible(path, is_directory)` says whether the caller may be shown a path.
///
/// AIDEV-NOTE: this walks through directory DESCRIPTORS (openat with O_NOFOLLOW from the
/// pinned directory down), in-process, rather than handing the path to `du` and `find`.
/// A path given to another program is resolved again by name, after our checks: whoever
/// can rename a directory on the way could point it somewhere else, and the names it
/// printed would then be checked against the policy under the wrong path. Here every
/// directory entered is one that was looked up in the directory above it, so the paths
/// that are built, filtered and shown are the paths that were walked.
///
/// AIDEV-NOTE: the walk runs in a blocking job, which cannot be cancelled, so it stops
/// by itself at `opts.deadline`; directories it was still inside are marked partial.
/// It keeps one open directory per level and nothing per entry, so neither a deep tree
/// nor a directory with millions of entries can use up memory.
pub fn walk(
    root: OwnedFd,
    root_path: &str,
    opts: &WalkOpts,
    visible: &dyn Fn(&str, bool) -> bool,
) -> std::io::Result<Usage> {
    let own = meta_of(&fstat(&root)?);
    // The filesystem the walk stays on.
    let dev = own.dev;
    // Inodes of files with more than one name that have been counted.
    let mut linked: HashSet<u64> = HashSet::new();
    // Inodes of such files that are in the list of largest files already.
    let mut listed: HashSet<u64> = HashSet::new();
    let (mut dirs, mut files) = (Top::new(opts.limit), Top::new(opts.limit));
    let mut unreadable = 0;
    let (mut total, mut partial) = (0, false);
    let mut expired = false;
    let mut entries = 0u32;
    let flags =
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    // An explicit stack rather than recursion: a deep tree cannot overflow ours.
    let mut stack = vec![Frame {
        dir: Dir::new(root)?,
        path: root_path.to_string(),
        level: 0,
        bytes: own.bytes,
        partial: false,
    }];

    while let Some(top) = stack.last_mut() {
        entries = entries.wrapping_add(1);
        if entries.is_multiple_of(256) && Instant::now() >= opts.deadline {
            expired = true;
        }
        let entry = match top.dir.read() {
            Some(Ok(entry)) if !expired => Some(entry),
            // Out of time with entries still unread: what is here was not all counted.
            Some(Ok(_)) => {
                top.partial = true;
                None
            }
            // The end of the directory, or an error reading it.
            Some(Err(_)) | None => None,
        };
        let Some(entry) = entry else {
            // Done with this directory: offer it for the list and add it to its parent.
            let Some(done) = stack.pop() else { break };
            let (bytes, was_partial) = (done.bytes, done.partial);
            if (1..=opts.depth).contains(&done.level) && dirs.ranks(bytes) {
                let shown = visible(&done.path, true);
                let item = Item {
                    bytes,
                    path: done.path,
                    partial: was_partial,
                };
                dirs.offer(item, shown);
            }
            match stack.last_mut() {
                Some(parent) => {
                    parent.bytes = parent.bytes.saturating_add(bytes);
                    parent.partial |= was_partial;
                }
                None => (total, partial) = (bytes, was_partial),
            }
            continue;
        };

        let name = entry.file_name();
        if name == c"." || name == c".." {
            continue;
        }
        let Ok(here) = top.dir.fd() else { continue };
        // Never follows a link: a link is counted as the link itself.
        let Ok(stat) = statat(here, name, AtFlags::SYMLINK_NOFOLLOW) else {
            continue; // gone since it was listed
        };
        let meta = meta_of(&stat);
        if meta.dev != dev {
            continue; // a mount point: another filesystem's space
        }

        if meta.kind == FileType::Directory {
            if expired || Instant::now() >= opts.deadline {
                expired = true;
                top.partial = true;
                continue;
            }
            let level = top.level + 1;
            let entered = if level < MAX_LEVELS {
                openat(here, name, flags, Mode::empty()).ok()
            } else {
                None
            };
            // It was a directory on this filesystem a moment ago; make sure that is
            // still what was opened.
            let entered = entered
                .filter(|fd| {
                    fstat(fd).is_ok_and(|stat| {
                        let now = meta_of(&stat);
                        now.kind == FileType::Directory && now.dev == dev
                    })
                })
                .and_then(|fd| Dir::new(fd).ok());
            let Some(dir) = entered else {
                unreadable += 1;
                top.bytes = top.bytes.saturating_add(meta.bytes);
                continue;
            };
            let child = Frame {
                dir,
                path: child_path(&top.path, name),
                level,
                bytes: meta.bytes,
                partial: false,
            };
            stack.push(child);
            continue;
        }

        // A file with several names takes its space once: only the first name met
        // adds to the totals.
        let another_name = meta.links > 1 && linked.len() < MAX_LINKED && !linked.insert(meta.ino);
        if !another_name {
            top.bytes = top.bytes.saturating_add(meta.bytes);
        }
        if meta.kind == FileType::RegularFile
            && meta.bytes >= opts.min_file_bytes
            && files.ranks(meta.bytes)
        {
            let path = child_path(&top.path, name);
            let shown = visible(&path, false);
            // AIDEV-NOTE: every name is put to the caller's policy, not just the first
            // one met: otherwise a hidden name that happens to come first would keep a
            // file out of the list that the caller may see under another name. It is
            // listed once, under the first name the caller may see.
            if shown && meta.links > 1 && !listed.insert(meta.ino) {
                continue;
            }
            if !shown && another_name {
                continue; // a further hidden name: nothing new to count as hidden
            }
            let item = Item {
                bytes: meta.bytes,
                path,
                partial: false,
            };
            files.offer(item, shown);
        }
    }

    Ok(Usage {
        total,
        partial,
        hidden: dirs.hidden + files.hidden,
        dirs: dirs.sorted(),
        files: files.sorted(),
        unreadable,
    })
}

/// A deleted file that is still open somewhere.
struct Held {
    bytes: u64,
    path: String,
    /// The processes that have it open.
    pids: Vec<i32>,
}

/// How a process sees the filesystem: its mount namespace and its root directory.
///
/// AIDEV-NOTE: the kernel reports the path of an open file as the process that holds it
/// sees it. That path means the same thing here only if the process shares BOTH our
/// mount namespace (it is not in a container) and our root directory (it is not in a
/// chroot, as postfix and bind often are). Anything else is "elsewhere": counted, never
/// named, and never put to the policy under a path that is not really its path.
#[derive(Debug)]
pub struct View {
    mount_ns: Option<PathBuf>,
    root: Option<PathBuf>,
}

impl View {
    /// The server's own view.
    pub fn own() -> View {
        View::of(Path::new("/proc/self"))
    }

    /// The view of the process whose /proc directory is `process`.
    fn of(process: &Path) -> View {
        View {
            mount_ns: std::fs::read_link(process.join("ns/mnt")).ok(),
            root: std::fs::read_link(process.join("root")).ok(),
        }
    }

    /// Whether the process whose /proc directory is `process` certainly sees the same
    /// filesystem as this view. Anything that could not be read counts as "no".
    fn shared_by(&self, process: &Path) -> bool {
        let theirs = View::of(process);
        self.mount_ns.is_some()
            && self.root.is_some()
            && theirs.mount_ns == self.mount_ns
            && theirs.root == self.root
    }
}

/// What the search for deleted files found.
struct DeletedFiles {
    /// The largest, largest first.
    held: Vec<Held>,
    hidden: u64,
    /// The search hit its limits before it had seen every process.
    cut_short: bool,
    /// Deleted files on the same filesystem that are only held by processes in another
    /// mount namespace: how many, and the space they take. See `deleted_open_files`.
    elsewhere_files: u64,
    elsewhere_bytes: u64,
}

/// Finds files under `root` (on filesystem `dev`) that have been deleted but still take
/// up space because a process has them open: the space `df` counts and no file shows.
/// `mount_ns` is the server's own mount namespace (the target of /proc/self/ns/mnt).
///
/// AIDEV-NOTE: the path of an open file is reported by the kernel as the process that
/// holds it sees it. For a process in another mount namespace (a container) that path
/// says nothing about where the file is on this host: a container's /var/log/app.log
/// may be the host's /srv/volumes/app/app.log. Such a path must be neither matched
/// against `root` nor put to the policy (it would be checked under the wrong name), and
/// a deleted file cannot be looked up again to find its real one. So files held only by
/// processes in another namespace, or in one we cannot identify, are counted, and
/// their names are never used.
fn deleted_open_files(
    root: &str,
    dev: u64,
    limit: usize,
    view: &View,
    visible: &dyn Fn(&str, bool) -> bool,
) -> DeletedFiles {
    let deadline = Instant::now() + DELETED_SCAN_TIME;
    let prefix = if root.ends_with('/') {
        root.to_string()
    } else {
        format!("{root}/")
    };
    let mut found: HashMap<u64, Held> = HashMap::new();
    let mut elsewhere: HashMap<u64, u64> = HashMap::new();
    let mut links = 0;
    let mut cut_short = false;
    let processes = std::fs::read_dir("/proc")
        .map(|entries| entries.flatten().collect::<Vec<_>>())
        .unwrap_or_default();
    'processes: for process in processes {
        let pid = process
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<i32>().ok());
        let Some(pid) = pid else { continue };
        // Another user's process (when not root), or one that has just exited.
        let Ok(descriptors) = std::fs::read_dir(process.path().join("fd")) else {
            continue;
        };
        let same_namespace = view.shared_by(&process.path());
        for descriptor in descriptors.flatten() {
            links += 1;
            if links > MAX_FD_LINKS || Instant::now() >= deadline {
                cut_short = true;
                break 'processes;
            }
            let link = descriptor.path();
            let Ok(target) = std::fs::read_link(&link) else {
                continue;
            };
            let target = target.to_string_lossy();
            let Some(path) = target.strip_suffix(DELETED_MARK) else {
                continue;
            };
            if same_namespace && !path.starts_with(&prefix) {
                continue;
            }
            // Through the descriptor, to the file itself. A link count of zero is what
            // makes it a deleted file (a name can also just END in " (deleted)").
            let Ok(meta) = std::fs::metadata(&link) else {
                continue;
            };
            if !meta.is_file() || meta.nlink() != 0 || meta.dev() != dev {
                continue;
            }
            let bytes = meta.blocks().saturating_mul(512);
            if !same_namespace {
                elsewhere.insert(meta.ino(), bytes);
                continue;
            }
            let held = found.entry(meta.ino()).or_insert_with(|| Held {
                bytes,
                path: path.to_string(),
                pids: Vec::new(),
            });
            if !held.pids.contains(&pid) {
                held.pids.push(pid);
            }
        }
    }
    // A file that a process in our own namespace also holds is already accounted for.
    elsewhere.retain(|inode, _| !found.contains_key(inode));
    let mut all: Vec<Held> = found.into_values().collect();
    all.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.path.cmp(&b.path)));
    let mut held = Vec::new();
    let mut hidden = 0;
    for file in all {
        if held.len() >= limit {
            break;
        }
        if visible(&file.path, false) {
            held.push(file);
        } else {
            hidden += 1;
        }
    }
    DeletedFiles {
        held,
        hidden,
        cut_short,
        elsewhere_files: elsewhere.len() as u64,
        elsewhere_bytes: elsewhere
            .values()
            .fold(0, |sum, bytes| sum.saturating_add(*bytes)),
    }
}

fn size_text(bytes: u64, partial: bool) -> String {
    if partial {
        format!(">= {}", human_bytes(bytes))
    } else {
        human_bytes(bytes)
    }
}

fn size_rows(items: &[Item]) -> Vec<Vec<String>> {
    items
        .iter()
        .map(|item| vec![size_text(item.bytes, item.partial), item.path.clone()])
        .collect()
}

/// The report: a total, then the three lists.
/// The report. `show_processes`: the caller may see process information (holds
/// process.view), so the processes holding deleted files open may be named.
fn hogs_text(
    real: &str,
    opts: &HogOpts,
    usage: &Usage,
    deleted: &DeletedFiles,
    show_processes: bool,
) -> String {
    let mut text = format!(
        "Space used under {real}: {} (on this filesystem; links are not followed)\n",
        size_text(usage.total, usage.partial)
    );
    if usage.partial {
        text.push_str(&format!(
            "[the walk stopped at its time limit of {} s: sizes marked >= are incomplete, \
             and larger entries may be missing; ask about a directory further down]\n",
            opts.walk_time.as_secs()
        ));
    }

    let levels = if opts.depth == 1 { "level" } else { "levels" };
    text.push_str(&format!(
        "\n== Largest directories ({} {levels} down) ==\n",
        opts.depth
    ));
    if usage.dirs.is_empty() {
        text.push_str("(none)\n");
    } else {
        let rows = size_rows(&usage.dirs);
        text.push_str(&format_table(&["SIZE", "DIRECTORY"], &rows, &[true, false]));
    }

    text.push_str(&format!(
        "\n== Largest files ({} or more) ==\n",
        human_bytes(opts.min_file_bytes)
    ));
    if usage.files.is_empty() {
        text.push_str("(none)\n");
    } else {
        let rows = size_rows(&usage.files);
        text.push_str(&format_table(&["SIZE", "FILE"], &rows, &[true, false]));
    }

    text.push_str("\n== Deleted files still held open by a process ==\n");
    if deleted.held.is_empty() {
        text.push_str("(none)\n");
    } else if show_processes {
        let rows: Vec<Vec<String>> = deleted
            .held
            .iter()
            .map(|file| {
                let pid = file.pids.first().copied().unwrap_or(0);
                let mut process = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                    .map(|name| name.trim().to_string())
                    .unwrap_or_else(|_| "?".to_string());
                if file.pids.len() > 1 {
                    process.push_str(&format!(" +{} more", file.pids.len() - 1));
                }
                vec![
                    human_bytes(file.bytes),
                    pid.to_string(),
                    process,
                    file.path.clone(),
                ]
            })
            .collect();
        let headers = ["SIZE", "PID", "PROCESS", "FILE"];
        text.push_str(&format_table(&headers, &rows, &[true, true, false, false]));
        text.push_str(
            "[this space is freed when those processes close the file or are restarted]\n",
        );
    } else {
        // AIDEV-NOTE: which process holds a file is process information. fs.view alone
        // does not show it, so that this tool cannot be a way around process.view.
        let rows: Vec<Vec<String>> = deleted
            .held
            .iter()
            .map(|file| vec![human_bytes(file.bytes), file.path.clone()])
            .collect();
        text.push_str(&format_table(&["SIZE", "FILE"], &rows, &[true, false]));
        text.push_str(
            "[this space is freed when the processes holding them close the file or are \
             restarted; which processes those are is shown to callers with process.view]\n",
        );
    }
    if deleted.elsewhere_files > 0 {
        let (files, are) = match deleted.elsewhere_files {
            1 => ("file", "is"),
            _ => ("files", "are"),
        };
        text.push_str(&format!(
            "[{} more deleted {files} on this filesystem, {} in all, {are} held open by \
             processes in another mount namespace (containers); where they were cannot be \
             told from here]\n",
            deleted.elsewhere_files,
            human_bytes(deleted.elsewhere_bytes)
        ));
    }
    if deleted.cut_short {
        text.push_str("[not every process was examined: the search reached its limit]\n");
    }
    if !rustix::process::geteuid().is_root() {
        text.push_str(
            "[only processes of the server's own user could be examined: it is not running as root]\n",
        );
    }

    let mut notes = String::new();
    // AIDEV-NOTE: said without a count. The caller chooses depth, limit and the file
    // size threshold, so a count would let repeated calls map out how many directories
    // and large files there are in a tree the caller may not list.
    if usage.hidden + deleted.hidden > 0 {
        notes.push_str("[some entries are not shown: this caller may not list them]\n");
    }
    match usage.unreadable {
        0 => {}
        1 => notes.push_str(
            "[1 directory could not be entered (no permission, or nested too deeply): its \
             content is not counted]\n",
        ),
        n => notes.push_str(&format!(
            "[{n} directories could not be entered (no permission, or nested too deeply): \
             their content is not counted]\n"
        )),
    }
    if !notes.is_empty() {
        text.push('\n');
        text.push_str(&notes);
    }
    text
}

/// disk_hogs itself. Runs in a blocking job.
fn disk_hogs_report(ctx: &Ctx, path: &str, opts: &HogOpts) -> ToolResult {
    // Exactly the path handling of fs_list: pin, host-wide limits, then the caller's grant.
    let roots = &ctx.cfg().fs.list_roots;
    let opened = pin(ctx, path, true, roots, "fs.list_roots")?;
    let resource = if opened.meta.is_dir() {
        dir_resource(&opened.real)
    } else {
        opened.real.clone()
    };
    check_limits(ctx, &opened.real, &resource, roots, "fs.list_roots")?;
    // The grant first, then what kind of thing the path is (see fs_list).
    let auth = ctx.authorize(Some(&resource))?;
    if !opened.meta.is_dir() {
        return Err(ToolError::Invalid(format!(
            "{} is not a directory",
            opened.real
        )));
    }

    // AIDEV-NOTE: the walk crosses directories that the caller may not list. Their size
    // counts in the totals above them, but their names must not be shown: every path is
    // put to the same two tests as a path the caller asks for by name (the never-readable
    // patterns, then the caller's grants) before it is listed.
    let visible = |path: &str, is_dir: bool| {
        let resource = if is_dir {
            dir_resource(path)
        } else {
            path.to_string()
        };
        denied_by(&ctx.cfg().fs, &resource).is_none() && ctx.permits(&resource)
    };
    let root = opened
        .reopen_read()
        .map_err(|e| ToolError::Failed(format!("{}: {e}", opened.real)))?;
    let walk_opts = WalkOpts {
        depth: opts.depth,
        limit: opts.limit,
        min_file_bytes: opts.min_file_bytes,
        deadline: Instant::now() + opts.walk_time,
    };
    let usage = walk(root.into(), &opened.real, &walk_opts, &visible)
        .map_err(|e| ToolError::Failed(format!("{}: {e}", opened.real)))?;
    let deleted = deleted_open_files(
        &opened.real,
        opened.meta.dev(),
        opts.limit,
        &View::own(),
        &visible,
    );
    let show_processes = ctx.holds_read("process.view");
    let text = hogs_text(&opened.real, opts, &usage, &deleted, show_processes);
    auth.ok(fit_section(&text, ctx.output_budget()))
}

async fn disk_hogs(ctx: Ctx, args: Args) -> ToolResult {
    let path = required(&args, "path")?.to_string();
    let number = |name: &str, default: u64| {
        args.int(name)
            .and_then(|value| u64::try_from(value).ok())
            .unwrap_or(default)
    };
    // The walk, and the look through /proc that follows it, together get the time one
    // command may take.
    let walk_secs = ctx
        .cfg()
        .limits
        .command_timeout_secs
        .saturating_sub(DELETED_SCAN_TIME.as_secs())
        .max(1);
    let opts = HogOpts {
        depth: usize::try_from(number("depth", 2)).unwrap_or(2),
        limit: usize::try_from(number("limit", 20)).unwrap_or(20),
        min_file_bytes: number("min_file_mb", 50).saturating_mul(1024 * 1024),
        walk_time: Duration::from_secs(walk_secs),
    };
    blocking(ctx.clone(), move || disk_hogs_report(&ctx, &path, &opts)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::policy::Access;
    use crate::tools::Host;
    use crate::tools::testing::{FakeBins, call, ctx, find, host, ok_text};
    use serde_json::json;
    use std::sync::Arc;

    /// vera may view storage; otto may not.
    fn fixture(fake: &FakeBins) -> (Arc<Host>, MemorySink) {
        host(&format!(
            r#"
[roles.viewer]
allow = ["storage.view"]
[roles.other]
allow = ["system.view"]
[unix_users.vera]
roles = ["viewer"]
[unix_users.otto]
roles = ["other"]
{}"#,
            fake.config_only()
        ))
    }

    const LSBLK: &str = "NAME   TYPE  SIZE RO ROTA FSTYPE LABEL MOUNTPOINT MODEL\n\
                         sda    disk  100G  0    0                         QEMU HARDDISK\n\
                         `-sda1 part  100G  0    0 ext4         /\n";
    const FINDMNT: &str = "TARGET SOURCE    FSTYPE OPTIONS\n/      /dev/sda1 ext4   rw,relatime\n";

    fn storage_bins() -> FakeBins {
        FakeBins::new()
            .add("lsblk", LSBLK, 0)
            .add("findmnt", FINDMNT, 0)
            .add("pvs", "  PV         VG   Fmt  Attr PSize   PFree\n  /dev/sdb1  data lvm2 a--  <50.00g 10.00g\n", 0)
            .add("vgs", "  VG   #PV #LV #SN Attr   VSize   VFree\n  data   1   2   0 wz--n- <50.00g 10.00g\n", 0)
            .add("lvs", "  LV   VG   Attr       LSize\n  www  data -wi-ao---- 30.00g\n", 0)
    }

    /// Runs the report with a stand-in for /proc/mdstat.
    async fn report(host: &Arc<Host>, user: &str, mdstat: &Path) -> ToolResult {
        let ctx = ctx(host, user, "storage.view", Access::Read);
        let auth = ctx.authorize(None)?;
        block_devices_report(&ctx, auth, mdstat).await
    }

    #[test]
    fn mdstat_lists_an_array_only_when_one_is_defined() {
        let idle = "Personalities : \nunused devices: <none>\n";
        let raid = "Personalities : [raid1]\nmd0 : active raid1 sdb1[1] sda1[0]\n      \
                    1046528 blocks super 1.2 [2/2] [UU]\n\nunused devices: <none>\n";
        assert!(!mdstat_has_arrays(idle));
        assert!(!mdstat_has_arrays(""));
        assert!(mdstat_has_arrays(raid));
    }

    #[tokio::test]
    async fn a_hung_command_does_not_cost_block_devices_its_whole_answer() {
        // AIDEV-NOTE: LVM commands hang when a device is unreachable. Each command gets
        // only what is left of the call, so the answer still arrives, with what was learnt.
        let fake = FakeBins::new()
            .add("lsblk", LSBLK, 0)
            .add("findmnt", FINDMNT, 0)
            // commands that hang (a busy loop: stand-ins have only shell built-ins)
            .add_script("pvs", "while :; do :; done")
            .add_script("vgs", "while :; do :; done")
            .add_script("lvs", "while :; do :; done");
        let config = format!(
            "[roles.viewer]\nallow = [\"storage.view\"]\n[unix_users.vera]\nroles = [\"viewer\"]\n\
             [limits]\ncall_timeout_secs = 4\ncommand_timeout_secs = 4\n{}",
            fake.config_only()
        );
        let (host, _audit) = host(&config);
        let started = std::time::Instant::now();
        let text = ok_text(report(&host, "vera", Path::new("/nonexistent/mdstat")).await);
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "took {:?}: longer than the call may",
            started.elapsed()
        );
        assert!(text.contains("QEMU HARDDISK"), "{text}");
        assert!(text.contains("/dev/sda1"), "{text}");
        assert!(text.contains("time limit"), "{text}");
        assert!(text.contains("not run: this call is out of time"), "{text}");
        // the commands that could not be given any time were never started
        assert_eq!(fake.calls("lvs"), Vec::<Vec<String>>::new());
    }

    #[tokio::test]
    async fn block_devices_runs_each_command_and_shows_each_section() {
        let fake = storage_bins();
        let (host, _audit) = fixture(&fake);
        let dir = tempfile::tempdir().unwrap();
        let mdstat = dir.path().join("mdstat");
        std::fs::write(
            &mdstat,
            "Personalities : [raid1]\nmd0 : active raid1 sdb1[1] sda1[0]\n      1046528 blocks [2/2] [UU]\n",
        )
        .unwrap();

        let text = ok_text(report(&host, "vera", &mdstat).await);
        for expected in [
            "== Block devices (lsblk) ==",
            "`-sda1 part  100G",
            "== Mounted filesystems (findmnt) ==",
            "/dev/sda1 ext4   rw,relatime",
            "== Software RAID (/proc/mdstat) ==",
            "md0 : active raid1",
            "== LVM physical volumes (pvs) ==",
            "/dev/sdb1  data lvm2",
            "== LVM volume groups (vgs) ==",
            "== LVM logical volumes (lvs) ==",
            "www  data -wi-ao----",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
        assert_eq!(
            fake.calls("lsblk"),
            [["-o", "NAME,TYPE,SIZE,RO,ROTA,FSTYPE,LABEL,MOUNTPOINT,MODEL"]]
        );
        assert_eq!(
            fake.calls("findmnt"),
            [["--real", "--list", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"]]
        );
        for lvm in ["pvs", "vgs", "lvs"] {
            assert_eq!(fake.calls(lvm), [Vec::<String>::new()], "{lvm}");
        }
    }

    #[tokio::test]
    async fn block_devices_leaves_out_what_this_host_does_not_have() {
        // no LVM tools, and no RAID arrays in mdstat (or no mdstat at all)
        let fake = FakeBins::new()
            .add("lsblk", LSBLK, 0)
            .add("findmnt", FINDMNT, 0);
        let (host, _audit) = fixture(&fake);
        let dir = tempfile::tempdir().unwrap();
        let mdstat = dir.path().join("mdstat");
        std::fs::write(&mdstat, "Personalities : \nunused devices: <none>\n").unwrap();

        for mdstat in [mdstat.as_path(), &dir.path().join("missing")] {
            let text = ok_text(report(&host, "vera", mdstat).await);
            assert!(text.contains("== Block devices (lsblk) =="), "{text}");
            assert!(!text.contains("Software RAID"), "{text}");
            assert!(!text.contains("== LVM"), "{text}");
            assert!(
                text.contains("[LVM: the pvs, vgs and lvs commands are not installed]"),
                "{text}"
            );
        }
    }

    #[tokio::test]
    async fn block_devices_notes_a_missing_program_and_an_empty_answer() {
        // findmnt is missing; LVM is installed but has nothing to show
        let fake = FakeBins::new()
            .add("lsblk", LSBLK, 0)
            .add("pvs", "", 0)
            .add("vgs", "", 0)
            .add("lvs", "", 0);
        let (host, _audit) = fixture(&fake);
        let text = ok_text(report(&host, "vera", Path::new("/nonexistent/mdstat")).await);
        assert!(
            text.contains(
                "== Mounted filesystems (findmnt) ==\n[the `findmnt` command is not installed"
            ),
            "{text}"
        );
        assert!(
            text.contains("== LVM physical volumes (pvs) ==\n(none)\n"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn block_devices_is_an_error_when_nothing_could_be_shown() {
        let fake = FakeBins::new()
            .add_script("lsblk", "echo 'lsblk: failed to access sysfs' >&2; exit 1")
            .add_script("findmnt", "exit 1");
        let (host, _audit) = fixture(&fake);
        let output = report(&host, "vera", Path::new("/nonexistent/mdstat"))
            .await
            .unwrap();
        assert!(output.is_error());
        assert!(
            output.text().contains("failed to access sysfs"),
            "{}",
            output.text()
        );
        assert!(
            output.text().contains("[exit status 1]"),
            "{}",
            output.text()
        );
    }

    #[tokio::test]
    async fn block_devices_masks_credentials_in_mount_sources_and_options() {
        let mounts = "TARGET   SOURCE                          FSTYPE OPTIONS\n\
                      /mnt/dav https://bob:hunter2@dav.example/ davfs  rw,password=sesame,uid=0\n\
                      /        /dev/sda1                       ext4   rw,errors=remount-ro\n";
        let fake = FakeBins::new()
            .add("lsblk", LSBLK, 0)
            .add("findmnt", mounts, 0);
        let (host, _audit) = fixture(&fake);
        let text = ok_text(report(&host, "vera", Path::new("/nonexistent/mdstat")).await);
        assert!(!text.contains("hunter2"), "{text}");
        assert!(!text.contains("sesame"), "{text}");
        assert!(
            text.contains("https://bob:<redacted>@dav.example/"),
            "{text}"
        );
        assert!(text.contains("rw,password=<redacted>,uid=0"), "{text}");
        // ordinary options and the column spacing are untouched
        assert!(
            text.contains("/        /dev/sda1                       ext4   rw,errors=remount-ro"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn block_devices_cuts_a_very_long_section_and_says_so() {
        let many: String = (0..5000)
            .map(|i| format!("/var/lib/docker/overlay2/{i:04}/merged overlay overlay rw\n"))
            .collect();
        let fake = FakeBins::new()
            .add("lsblk", LSBLK, 0)
            .add("findmnt", &many, 0);
        let (host, _audit) = fixture(&fake);
        let text = ok_text(report(&host, "vera", Path::new("/nonexistent/mdstat")).await);
        assert!(text.len() <= 64 * 1024, "{} bytes", text.len());
        assert!(text.contains("overlay2/0000/merged"), "{text}");
        assert!(!text.contains("overlay2/4999/merged"));
        assert!(text.contains("more lines left out"), "{text}");
        // the sections after the long one are still there
        assert!(text.contains("[LVM: the pvs, vgs and lvs commands are not installed]"));
    }

    #[tokio::test]
    async fn block_devices_needs_the_storage_view_permission() {
        let fake = storage_bins();
        let (host, audit) = fixture(&fake);
        let tool = find(tools(), "block_devices");
        match call(&host, "otto", &tool, json!({})).await {
            Err(ToolError::Denied(message)) => {
                assert!(message.contains("storage.view"), "{message}")
            }
            other => panic!("expected a denial, got {other:?}"),
        }
        assert_eq!(audit.records().last().unwrap()["decision"], "deny");
        assert_eq!(fake.calls("lsblk"), Vec::<Vec<String>>::new());

        let text = ok_text(call(&host, "vera", &tool, json!({})).await);
        assert!(text.contains("== Block devices (lsblk) =="), "{text}");
        assert_eq!(audit.records().last().unwrap()["decision"], "allow");
        assert_eq!(tool.access, Access::Read);
        assert_eq!(tool.permission, "storage.view");
    }

    // ---- disk_health -------------------------------------------------------------------

    fn scanned(device: &str, kind: Option<&str>) -> Scanned {
        Scanned {
            device: device.to_string(),
            kind: kind.map(str::to_string),
        }
    }

    #[test]
    fn parse_scan_keeps_the_device_and_its_type_and_skips_anything_odd() {
        let text = "/dev/sda -d scsi # /dev/sda, SCSI device\n\
                    /dev/nvme0 -d nvme # /dev/nvme0, NVMe device\n\
                    /dev/bus/0 -d megaraid,0 # /dev/bus/0 [megaraid_disk_00], SCSI device\n\
                    /dev/bus/0 -d megaraid,1 # /dev/bus/0 [megaraid_disk_01], SCSI device\n\
                    /dev/sdc # no type given\n\
                    # a comment\n\
                    \n\
                    sdz -d ata # not under /dev\n\
                    /dev/../etc/passwd -d ata\n\
                    /dev/sdd -d --all\n\
                    /dev/sde -x scsi\n\
                    /dev/sd;f -d ata\n";
        assert_eq!(
            parse_scan(text),
            [
                scanned("/dev/sda", Some("scsi")),
                scanned("/dev/nvme0", Some("nvme")),
                scanned("/dev/bus/0", Some("megaraid,0")),
                scanned("/dev/bus/0", Some("megaraid,1")),
                scanned("/dev/sdc", None),
            ]
        );
        assert_eq!(parse_scan(""), []);
    }

    const ATA_JSON: &str = r#"{
  "smartctl": {"version": [7, 2], "exit_status": 0},
  "device": {"name": "/dev/sda", "type": "sat", "protocol": "ATA"},
  "model_name": "Samsung SSD 860 EVO 500GB",
  "smart_status": {"passed": true},
  "ata_smart_attributes": {"table": [
    {"id": 5, "name": "Reallocated_Sector_Ct", "value": 100, "raw": {"value": 0, "string": "0"}},
    {"id": 9, "name": "Power_On_Hours", "value": 97, "raw": {"value": 12345, "string": "12345"}},
    {"id": 197, "name": "Current_Pending_Sector", "value": 100, "raw": {"value": 8, "string": "8"}}
  ]},
  "power_on_time": {"hours": 12345},
  "temperature": {"current": 31}
}"#;

    const NVME_JSON: &str = r#"{
  "device": {"name": "/dev/nvme0", "type": "nvme", "protocol": "NVMe"},
  "model_name": "WDC PC SN730",
  "smart_status": {"passed": false, "nvme": {"value": 4}},
  "nvme_smart_health_information_log": {
    "critical_warning": 4, "temperature": 45, "available_spare": 3,
    "percentage_used": 104, "power_on_hours": 20000, "media_errors": 12
  },
  "temperature": {"current": 45},
  "power_on_time": {"hours": 20000}
}"#;

    fn summary(text: &str, code: i32) -> Health {
        summarize(&serde_json::from_str(text).unwrap(), Some(code))
    }

    #[test]
    fn summarize_reads_an_ata_drive() {
        let health = summary(ATA_JSON, 0);
        assert_eq!(
            health,
            Health {
                model: "Samsung SSD 860 EVO 500GB".to_string(),
                verdict: "PASSED",
                temperature: "31 C".to_string(),
                power_on: "12345 h".to_string(),
                wear: "0 reallocated sectors, 8 pending".to_string(),
                notes: vec![],
            }
        );
    }

    #[test]
    fn summarize_reads_a_failing_nvme_drive() {
        let health = summary(NVME_JSON, 8);
        assert_eq!(health.model, "WDC PC SN730");
        assert_eq!(health.verdict, "FAILED");
        assert_eq!(health.temperature, "45 C");
        assert_eq!(health.power_on, "20000 h");
        assert_eq!(health.wear, "104% of rated life used, 12 media errors");
    }

    #[test]
    fn summarize_reads_a_sas_drive_under_either_naming() {
        let old = r#"{"vendor": "SEAGATE", "product": "ST1200MM0009", "model_name": "SEAGATE ST1200MM0009",
                      "smart_status": {"passed": true}, "temperature": {"current": 28},
                      "power_on_time": {"hours": 41000, "minutes": 3}, "scsi_grown_defect_list": 2}"#;
        let health = summary(old, 0);
        assert_eq!(health.model, "SEAGATE ST1200MM0009");
        assert_eq!(health.wear, "2 grown defects");
        let new = r#"{"scsi_vendor": "SEAGATE", "scsi_product": "ST1200MM0009",
                      "scsi_model_name": "SEAGATE ST1200MM0009", "smart_status": {"passed": true}}"#;
        let health = summary(new, 0);
        assert_eq!(health.model, "SEAGATE ST1200MM0009");
        assert_eq!(
            (
                health.temperature.as_str(),
                health.power_on.as_str(),
                health.wear.as_str()
            ),
            ("-", "-", "-")
        );
    }

    #[test]
    fn summarize_trusts_the_exit_status_over_a_missing_or_passing_verdict() {
        // bit 3: the drive says it is failing, whatever else the report holds
        assert_eq!(summary(r#"{"model_name": "X"}"#, 8).verdict, "FAILED");
        assert_eq!(summary(ATA_JSON, 8).verdict, "FAILED");
        // bits 0 and 1: smartctl could not talk to the device at all
        let unreadable = r#"{"smartctl": {"messages": [
            {"string": "Smartctl open device: /dev/sda failed: Permission denied", "severity": "error"}
        ], "exit_status": 2}}"#;
        let health = summary(unreadable, 2);
        assert_eq!(health.verdict, "unreadable");
        assert_eq!(health.model, "-");
        assert_eq!(
            health.notes,
            ["Smartctl open device: /dev/sda failed: Permission denied"]
        );
        // nothing to go on
        assert_eq!(summary("{}", 0).verdict, "unknown");
        // the other bits are worth a note but are not a failure
        let health = summary(ATA_JSON, 64 | 128);
        assert_eq!(health.verdict, "PASSED");
        assert_eq!(
            health.notes,
            [
                "the drive's error log has entries",
                "the self-test log has errors"
            ]
        );
    }

    /// A stand-in smartctl: `--scan` lists an ATA disk (healthy) and an NVMe disk (failing,
    /// exit status 8); `-j` output is JSON, anything else is text.
    fn fake_smartctl() -> FakeBins {
        // On one line each, for `echo`: the stand-ins have no PATH, so no `cat`.
        let (ata, nvme) = (ATA_JSON.replace('\n', " "), NVME_JSON.replace('\n', " "));
        let script = format!(
            r#"
for last; do :; done
json=no
for a in "$@"; do [ "$a" = "-j" ] && json=yes; done
if [ "$1" = "--scan" ]; then
  echo '/dev/sda -d sat # /dev/sda [SAT], ATA device'
  echo '/dev/nvme0 -d nvme # /dev/nvme0, NVMe device'
  exit 0
fi
case "$last:$json" in
  /dev/sda:yes) echo '{ata}'; exit 0 ;;
  /dev/nvme0:yes) echo '{nvme}'; exit 8 ;;
  /dev/sda:no) echo 'SMART overall-health self-assessment test result: PASSED'; exit 0 ;;
  /dev/nvme0:no) echo 'SMART overall-health self-assessment test result: FAILED!'; exit 8 ;;
esac
exit 1
"#
        );
        FakeBins::new().add_script("smartctl", &script)
    }

    async fn health(host: &Arc<Host>, user: &str, arguments: serde_json::Value) -> ToolResult {
        call(host, user, &find(tools(), "disk_health"), arguments).await
    }

    #[tokio::test]
    async fn disk_health_summarizes_every_drive_and_leads_with_a_failing_one() {
        let fake = fake_smartctl();
        let (host, _audit) = fixture(&fake);
        let text = ok_text(health(&host, "vera", json!({})).await);
        assert!(
            text.starts_with("FAILING: /dev/nvme0 reports that it is failing"),
            "{text}"
        );
        let want = "\
DEVICE      MODEL                      HEALTH  TEMP  POWER-ON  WEAR / ERRORS
/dev/sda    Samsung SSD 860 EVO 500GB  PASSED  31 C   12345 h  0 reallocated sectors, 8 pending
/dev/nvme0  WDC PC SN730               FAILED  45 C   20000 h  104% of rated life used, 12 media errors
";
        assert!(text.contains(want), "{text}");
        assert_eq!(
            fake.calls("smartctl"),
            [
                vec!["--scan"],
                vec!["-j", "-H", "-i", "-A", "-d", "sat", "--", "/dev/sda"],
                vec!["-j", "-H", "-i", "-A", "-d", "nvme", "--", "/dev/nvme0"],
            ]
        );
    }

    #[tokio::test]
    async fn disk_health_shows_the_full_report_for_one_drive() {
        let fake = fake_smartctl();
        let (host, _audit) = fixture(&fake);
        let text = ok_text(health(&host, "vera", json!({"device": "/dev/sda"})).await);
        assert!(text.contains("== /dev/sda =="), "{text}");
        assert!(text.contains("test result: PASSED"), "{text}");
        assert!(!text.contains("FAILING"), "{text}");
        assert_eq!(
            fake.calls("smartctl"),
            [
                vec!["--scan"],
                vec!["-H", "-i", "-A", "-d", "sat", "--", "/dev/sda"],
            ]
        );

        // a failing drive is still an answer, not a tool failure
        let text = ok_text(health(&host, "vera", json!({"device": "/dev/nvme0"})).await);
        assert!(text.starts_with("FAILING: /dev/nvme0"), "{text}");
        assert!(text.contains("test result: FAILED!"), "{text}");
    }

    #[tokio::test]
    async fn disk_health_only_examines_devices_that_smartctl_found() {
        let fake = fake_smartctl();
        let (host, _audit) = fixture(&fake);
        match health(&host, "vera", json!({"device": "/dev/sdq"})).await {
            Err(ToolError::Invalid(message)) => {
                assert!(message.contains("/dev/sdq"), "{message}");
                assert!(message.contains("/dev/sda, /dev/nvme0"), "{message}");
            }
            other => panic!("expected the device to be refused, got {other:?}"),
        }
        assert_eq!(fake.calls("smartctl"), [vec!["--scan"]]);

        // not a device path at all: refused before anything runs
        for bad in [
            "sda",
            "/etc/passwd",
            "/dev/../etc/passwd",
            "/dev/sda -x",
            "--scan",
        ] {
            assert!(
                matches!(
                    health(&host, "vera", json!({"device": bad})).await,
                    Err(ToolError::Invalid(_))
                ),
                "{bad}"
            );
        }
        assert_eq!(fake.calls("smartctl").len(), 1);
    }

    #[tokio::test]
    async fn disk_health_reports_a_drive_that_cannot_be_read_without_failing() {
        let fake = FakeBins::new().add_script(
            "smartctl",
            r#"
if [ "$1" = "--scan" ]; then echo '/dev/sda -d scsi # /dev/sda, SCSI device'; exit 0; fi
for a in "$@"; do
  if [ "$a" = "-j" ]; then
    echo '{"smartctl": {"messages": [{"string": "Smartctl open device: /dev/sda failed: Permission denied", "severity": "error"}], "exit_status": 2}}'
    exit 2
  fi
done
echo 'Smartctl open device: /dev/sda failed: Permission denied'
exit 2
"#,
        );
        let (host, _audit) = fixture(&fake);
        let text = ok_text(health(&host, "vera", json!({})).await);
        assert!(text.contains("unreadable"), "{text}");
        assert!(
            text.contains("[/dev/sda: Smartctl open device: /dev/sda failed: Permission denied]"),
            "{text}"
        );
        assert!(!text.contains("FAILING"), "{text}");

        // asked about that one drive, the same problem IS a failure to answer
        let output = health(&host, "vera", json!({"device": "/dev/sda"}))
            .await
            .unwrap();
        assert!(output.is_error(), "{}", output.text());
        assert!(
            output.text().contains("Permission denied"),
            "{}",
            output.text()
        );
    }

    #[tokio::test]
    async fn disk_health_falls_back_to_text_when_smartctl_is_too_old_for_json() {
        let fake = FakeBins::new().add_script(
            "smartctl",
            r#"
if [ "$1" = "--scan" ]; then
  echo '/dev/sda -d scsi # /dev/sda, SCSI device'
  echo '/dev/sdb -d scsi # /dev/sdb, SCSI device'
  exit 0
fi
for last; do :; done
if [ "$1" = "-j" ]; then echo "smartctl: invalid option -- 'j'"; echo 'Use smartctl -h to get a usage summary'; exit 1; fi
echo "SMART Health Status: OK ($last)"
"#,
        );
        let (host, _audit) = fixture(&fake);
        let text = ok_text(health(&host, "vera", json!({})).await);
        assert!(
            text.contains("== /dev/sda ==\nSMART Health Status: OK (/dev/sda)"),
            "{text}"
        );
        assert!(
            text.contains("== /dev/sdb ==\nSMART Health Status: OK (/dev/sdb)"),
            "{text}"
        );
        assert!(!text.contains("invalid option"), "{text}");
        // JSON is tried once, not once per drive
        assert_eq!(
            fake.calls("smartctl"),
            [
                vec!["--scan"],
                vec!["-j", "-H", "-i", "-A", "-d", "scsi", "--", "/dev/sda"],
                vec!["-H", "-A", "-d", "scsi", "--", "/dev/sda"],
                vec!["-H", "-A", "-d", "scsi", "--", "/dev/sdb"],
            ]
        );
    }

    #[tokio::test]
    async fn disk_health_tells_apart_drives_behind_one_controller_device() {
        let fake = FakeBins::new().add_script(
            "smartctl",
            r#"
if [ "$1" = "--scan" ]; then
  echo '/dev/bus/0 -d megaraid,0 # /dev/bus/0 [megaraid_disk_00], SCSI device'
  echo '/dev/bus/0 -d megaraid,1 # /dev/bus/0 [megaraid_disk_01], SCSI device'
  exit 0
fi
case "$*" in
  *-j*megaraid,0*) echo '{"model_name": "DISK ZERO", "smart_status": {"passed": true}}' ;;
  *-j*megaraid,1*) echo '{"model_name": "DISK ONE", "smart_status": {"passed": true}}' ;;
  *) echo "report for $*" ;;
esac
"#,
        );
        let (host, _audit) = fixture(&fake);
        let text = ok_text(health(&host, "vera", json!({})).await);
        assert!(
            text.contains("/dev/bus/0 [megaraid,0]  DISK ZERO"),
            "{text}"
        );
        assert!(text.contains("/dev/bus/0 [megaraid,1]  DISK ONE"), "{text}");

        let text = ok_text(health(&host, "vera", json!({"device": "/dev/bus/0"})).await);
        assert!(text.contains("== /dev/bus/0 [megaraid,0] =="), "{text}");
        assert!(text.contains("== /dev/bus/0 [megaraid,1] =="), "{text}");
        assert!(
            text.contains("report for -H -i -A -d megaraid,1 -- /dev/bus/0"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn disk_health_says_so_when_there_is_nothing_to_examine() {
        // a virtual machine: smartctl is there but finds no devices
        let fake = FakeBins::new().add("smartctl", "", 0);
        let (host, _audit) = fixture(&fake);
        let text = ok_text(health(&host, "vera", json!({})).await);
        assert!(text.contains("No drives with SMART support"), "{text}");

        // no smartctl at all: a failure that says what to install
        let none = FakeBins::new();
        let (host, _audit) = fixture(&none);
        match health(&host, "vera", json!({})).await {
            Err(ToolError::Failed(message)) => {
                assert!(message.contains("smartctl"), "{message}");
                assert!(message.contains("smartmontools"), "{message}");
            }
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn disk_health_needs_the_storage_view_permission() {
        let fake = fake_smartctl();
        let (host, audit) = fixture(&fake);
        assert!(matches!(
            health(&host, "otto", json!({})).await,
            Err(ToolError::Denied(_))
        ));
        assert_eq!(audit.records().last().unwrap()["decision"], "deny");
        assert_eq!(fake.calls("smartctl"), Vec::<Vec<String>>::new());
    }

    // ---- disk_hogs ---------------------------------------------------------------------

    const KIB: u64 = 1024;

    /// Writes a file of `kib` KiB of real data (not sparse, and not compressible, so that
    /// a compressing filesystem stores all of it) and makes sure it is on disk, so that
    /// its block count is final.
    fn fill(path: &Path, kib: u64) {
        use std::io::Write;
        let mut file = std::fs::File::create(path).unwrap();
        let mut state = 0x9E37_79B9_7F4A_7C15u64 ^ kib;
        let mut chunk = [0u8; 1024];
        for _ in 0..kib {
            for byte in chunk.iter_mut() {
                // xorshift: cheap pseudo-random bytes
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = (state >> 32) as u8;
            }
            file.write_all(&chunk).unwrap();
        }
        file.sync_all().unwrap();
    }

    /// A temporary tree, and a host whose configuration opens it up:
    ///
    ///   root/pub/big.bin 300K, root/pub/small.txt 1K, root/pub/deep/a/b/huge.bin 600K,
    ///   root/secret/keys.bin 400K, root/logs/app.log 200K, root/server.key 250K,
    ///   root/link -> ../outside, outside/large.bin 900K
    ///
    /// rita may list anything; dana anything but root/secret; nora only root itself and
    /// root/pub; otto nothing.
    struct Tree {
        _dir: tempfile::TempDir,
        root: String,
        host: Arc<Host>,
        audit: MemorySink,
    }

    fn tree() -> Tree {
        let dir = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(dir.path()).unwrap();
        let root = base.join("root");
        for sub in ["pub/deep/a/b", "secret", "logs"] {
            std::fs::create_dir_all(root.join(sub)).unwrap();
        }
        std::fs::create_dir_all(base.join("outside")).unwrap();
        fill(&root.join("pub/big.bin"), 300);
        fill(&root.join("pub/small.txt"), 1);
        fill(&root.join("pub/deep/a/b/huge.bin"), 600);
        fill(&root.join("secret/keys.bin"), 400);
        fill(&root.join("logs/app.log"), 200);
        fill(&root.join("server.key"), 250);
        fill(&base.join("outside/large.bin"), 900);
        std::os::unix::fs::symlink("../outside", root.join("link")).unwrap();

        let root = root.to_string_lossy().into_owned();
        let config = format!(
            r#"
[roles.reader]
allow = ["@read"]
[roles.guarded]
allow = ["fs.view"]
deny = ["fs.view:{root}/secret/**"]
[roles.narrow]
allow = ["fs.view:{root}/", "fs.view:{root}/pub/**"]
[roles.other]
allow = ["system.view"]
[unix_users.rita]
roles = ["reader"]
[unix_users.dana]
roles = ["guarded"]
[unix_users.nora]
roles = ["narrow"]
[unix_users.otto]
roles = ["other"]
[fs]
list_roots = ["{root}"]
"#
        );
        let (host, audit) = host(&config);
        Tree {
            _dir: dir,
            root,
            host,
            audit,
        }
    }

    impl Tree {
        fn path(&self, rest: &str) -> String {
            format!("{}/{rest}", self.root)
        }

        /// The walk on its own, with every path visible unless `hide` says otherwise.
        fn walk(&self, depth: usize, limit: usize, hide: &str) -> Usage {
            let opts = WalkOpts {
                depth,
                limit,
                min_file_bytes: 100 * KIB,
                deadline: Instant::now() + Duration::from_secs(60),
            };
            let root = std::fs::File::open(&self.root).unwrap();
            let visible = |path: &str, _is_dir: bool| hide.is_empty() || !path.contains(hide);
            walk(root.into(), &self.root, &opts, &visible).unwrap()
        }

        /// The whole report as `user`, with small thresholds.
        fn report(&self, user: &str, path: &str) -> ToolResult {
            let ctx = ctx(&self.host, user, "fs.view", Access::Read);
            let opts = HogOpts {
                depth: 2,
                limit: 20,
                min_file_bytes: 100 * KIB,
                walk_time: Duration::from_secs(60),
            };
            disk_hogs_report(&ctx, path, &opts)
        }
    }

    fn paths(items: &[Item]) -> Vec<&str> {
        items.iter().map(|item| item.path.as_str()).collect()
    }

    /// The paths listed under one heading of the report, in order.
    fn listed(text: &str, heading: &str) -> Vec<String> {
        let start = text
            .find(heading)
            .unwrap_or_else(|| panic!("no {heading:?} in:\n{text}"));
        text[start..]
            .lines()
            .skip(2) // the heading and the column titles
            .take_while(|line| !line.is_empty() && !line.starts_with("=="))
            .filter(|line| !line.starts_with('[') && !line.starts_with('('))
            .filter_map(|line| line.split_whitespace().last().map(str::to_string))
            .collect()
    }

    fn denied(result: ToolResult) -> String {
        match result {
            Err(ToolError::Denied(message)) => message,
            other => panic!("expected a denial, got {other:?}"),
        }
    }

    #[test]
    fn walk_totals_every_directory_including_what_lies_deeper() {
        let t = tree();
        let usage = t.walk(2, 20, "");
        // two levels down: pub/deep is listed, pub/deep/a is not
        assert_eq!(
            paths(&usage.dirs),
            [
                t.path("pub"),
                t.path("pub/deep"),
                t.path("secret"),
                t.path("logs")
            ]
        );
        let size = |rest: &str| {
            let path = t.path(rest);
            usage.dirs.iter().find(|d| d.path == path).unwrap().bytes
        };
        // each directory holds everything beneath it (plus a little for the directories)
        let within = |bytes: u64, kib: u64| bytes >= kib * KIB && bytes < (kib + 100) * KIB;
        assert!(within(size("pub"), 901), "{}", size("pub"));
        assert!(within(size("pub/deep"), 600), "{}", size("pub/deep"));
        assert!(within(size("secret"), 400), "{}", size("secret"));
        assert!(within(size("logs"), 200), "{}", size("logs"));
        // the total leaves out what the link points to (900K more)
        assert!(within(usage.total, 1751), "{}", usage.total);
        assert!(!usage.partial);
        assert_eq!((usage.hidden, usage.unreadable), (0, 0));

        assert_eq!(
            paths(&t.walk(1, 20, "").dirs),
            [t.path("pub"), t.path("secret"), t.path("logs")]
        );
        assert_eq!(
            paths(&t.walk(3, 2, "").dirs),
            [t.path("pub"), t.path("pub/deep")],
            "the limit keeps the largest"
        );
        assert!(paths(&t.walk(3, 20, "").dirs).contains(&t.path("pub/deep/a").as_str()));
    }

    #[test]
    fn walk_lists_the_largest_files_at_or_over_the_threshold() {
        let t = tree();
        let usage = t.walk(2, 20, "");
        assert_eq!(
            paths(&usage.files),
            [
                t.path("pub/deep/a/b/huge.bin"),
                t.path("secret/keys.bin"),
                t.path("pub/big.bin"),
                t.path("server.key"),
                t.path("logs/app.log"),
            ]
        );
        assert!(usage.files[0].bytes >= 600 * KIB);
        assert_eq!(
            paths(&t.walk(2, 2, "").files),
            [t.path("pub/deep/a/b/huge.bin"), t.path("secret/keys.bin")]
        );
    }

    #[test]
    fn walk_counts_a_file_with_several_names_once() {
        let t = tree();
        let before = t.walk(2, 20, "").total;
        std::fs::hard_link(t.path("pub/big.bin"), t.path("logs/big-again.bin")).unwrap();
        let after = t.walk(2, 20, "");
        assert!(
            after.total < before + 50 * KIB,
            "{} then {}",
            before,
            after.total
        );
        // it is listed once, under whichever name was met first
        let names: Vec<&str> = paths(&after.files)
            .into_iter()
            .filter(|path| path.contains("big"))
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
    }

    #[test]
    fn a_name_the_caller_may_see_is_listed_even_if_a_hidden_name_of_the_file_came_first() {
        // AIDEV-NOTE: which of a file's names the walk meets first is an accident of the
        // directory order. It must not decide whether a caller sees a file it may see,
        // nor let the caller tell that a hidden name of it exists.
        let t = tree();
        std::fs::hard_link(t.path("pub/big.bin"), t.path("secret/big-copy.bin")).unwrap();
        std::fs::hard_link(t.path("pub/big.bin"), t.path("logs/big-third.bin")).unwrap();
        let some = t.walk(2, 20, "/secret");
        let names = paths(&some.files);
        assert!(!names.iter().any(|p| p.contains("secret")), "{names:?}");
        // one of the two visible names is listed, and only one
        let visible: Vec<&&str> = names.iter().filter(|p| p.contains("big")).collect();
        assert_eq!(visible.len(), 1, "{names:?}");
        // and the totals are those of a tree without the extra names
        assert_eq!(some.total, t.walk(2, 20, "").total);
    }

    #[test]
    fn walk_hides_what_the_caller_may_not_see_but_still_counts_its_size() {
        let t = tree();
        let all = t.walk(2, 20, "");
        let some = t.walk(2, 20, "/secret");
        assert_eq!(some.total, all.total);
        assert_eq!(
            paths(&some.dirs),
            [t.path("pub"), t.path("pub/deep"), t.path("logs")]
        );
        assert!(!paths(&some.files).iter().any(|p| p.contains("secret")));
        // the directory and the file in it
        assert_eq!(some.hidden, 2);
    }

    #[test]
    fn walk_fills_the_list_with_visible_entries_when_larger_ones_are_hidden() {
        let t = tree();
        // the two largest files are hidden: the next two take their places
        let usage = t.walk(2, 2, ".bin");
        assert_eq!(
            paths(&usage.files),
            [t.path("server.key"), t.path("logs/app.log")]
        );
    }

    #[test]
    fn walk_stops_at_its_time_limit_and_says_what_is_incomplete() {
        let t = tree();
        let opts = WalkOpts {
            depth: 2,
            limit: 20,
            min_file_bytes: 100 * KIB,
            deadline: Instant::now(),
        };
        let root = std::fs::File::open(&t.root).unwrap();
        let usage = walk(root.into(), &t.root, &opts, &|_: &str, _: bool| true).unwrap();
        assert!(usage.partial);
        // nothing below the top was walked, so the total is far too small
        assert!(usage.total < 400 * KIB, "{}", usage.total);
        assert_eq!(paths(&usage.dirs), Vec::<&str>::new());
    }

    #[test]
    fn walk_counts_directories_it_cannot_read() {
        use std::os::unix::fs::PermissionsExt;
        if rustix::process::geteuid().is_root() {
            return; // root can read everything; nothing to test
        }
        let t = tree();
        let secret = t.path("secret");
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o000)).unwrap();
        let usage = t.walk(2, 20, "");
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(usage.unreadable, 1);
        assert!(!paths(&usage.dirs).contains(&secret.as_str()));
        assert!(usage.total < 1751 * KIB, "{}", usage.total);
    }

    #[test]
    fn disk_hogs_reports_directories_files_and_the_total() {
        let t = tree();
        let text = ok_text(t.report("rita", &t.root));
        let total = crate::timefmt::human_bytes(t.walk(2, 20, "").total);
        assert!(
            text.starts_with(&format!("Space used under {}: {total} (", t.root)),
            "{text}"
        );
        assert_eq!(
            listed(&text, "== Largest directories"),
            [
                t.path("pub"),
                t.path("pub/deep"),
                t.path("secret"),
                t.path("logs")
            ]
        );
        // server.key is on the built-in list of paths that are never shown
        assert_eq!(
            listed(&text, "== Largest files"),
            [
                t.path("pub/deep/a/b/huge.bin"),
                t.path("secret/keys.bin"),
                t.path("pub/big.bin"),
                t.path("logs/app.log"),
            ]
        );
        assert!(!text.contains("server.key"), "{text}");
        assert!(text.contains("[some entries are not shown"), "{text}");
        assert!(text.contains("== Deleted files still held open"), "{text}");
        assert!(!text.contains("large.bin"), "{text}");
        assert!(!text.contains(">="), "{text}");

        let record = t.audit.records().last().unwrap().clone();
        assert_eq!(record["decision"], "allow");
        assert_eq!(record["resource"], format!("{}/", t.root));
    }

    #[test]
    fn disk_hogs_leaves_out_what_a_deny_covers() {
        let t = tree();
        let text = ok_text(t.report("dana", &t.root));
        assert!(!text.contains("secret"), "{text}");
        assert_eq!(
            listed(&text, "== Largest directories"),
            [t.path("pub"), t.path("pub/deep"), t.path("logs")]
        );
        // secret/, secret/keys.bin and server.key are left out. How MANY were left out is
        // not said: with the caller choosing depth and limit, a count would map out the
        // shape of a tree it may not see.
        assert!(text.contains("[some entries are not shown"), "{text}");
        assert!(!text.contains("3 entries"), "{text}");
        // and the denied directory cannot be asked for directly
        let message = denied(t.report("dana", &t.path("secret")));
        assert!(message.contains("fs.view"), "{message}");
    }

    #[test]
    fn disk_hogs_does_not_say_what_a_path_outside_the_callers_grant_is() {
        let t = tree();
        // nora's grant covers the root and pub/. A file elsewhere is refused outright...
        let message = denied(t.report("nora", &t.path("secret/keys.bin")));
        assert!(message.contains("fs.view"), "{message}");
        // ...and only inside the grant is she told that a file is not a directory.
        match t.report("nora", &t.path("pub/big.bin")) {
            Err(ToolError::Invalid(message)) => {
                assert!(message.contains("not a directory"), "{message}")
            }
            other => panic!("expected an invalid-argument error, got {other:?}"),
        }
    }

    #[test]
    fn disk_hogs_shows_a_narrowly_granted_caller_only_what_the_grant_covers() {
        let t = tree();
        let text = ok_text(t.report("nora", &t.root));
        assert_eq!(
            listed(&text, "== Largest directories"),
            [t.path("pub"), t.path("pub/deep")]
        );
        assert_eq!(
            listed(&text, "== Largest files"),
            [t.path("pub/deep/a/b/huge.bin"), t.path("pub/big.bin")]
        );
        for hidden in ["secret", "logs", "server.key"] {
            assert!(!text.contains(hidden), "{hidden} in:\n{text}");
        }
    }

    #[test]
    fn disk_hogs_refuses_what_fs_list_would_refuse() {
        let t = tree();
        // no grant at all
        let message = denied(t.report("otto", &t.root));
        assert!(message.contains("fs.view"), "{message}");
        assert_eq!(t.audit.records().last().unwrap()["decision"], "deny");
        // outside the directories the host opens up, whether or not it exists
        let outside = format!("{}/../outside", t.root);
        for path in [outside.as_str(), "/nonexistent-dir-for-opsmcp-test"] {
            let message = denied(t.report("rita", path));
            assert!(message.contains("fs.list_roots"), "{message}");
        }
        // through a link that leads outside
        let message = denied(t.report("rita", &t.path("link")));
        assert!(message.contains("fs.list_roots"), "{message}");
        // a never-shown path
        std::fs::create_dir(t.path(".ssh")).unwrap();
        let message = denied(t.report("rita", &t.path(".ssh")));
        assert!(message.contains("never-readable"), "{message}");
        // not a directory, and not there
        assert!(matches!(
            t.report("rita", &t.path("pub/big.bin")),
            Err(ToolError::Invalid(_))
        ));
        assert!(matches!(
            t.report("rita", &t.path("missing")),
            Err(ToolError::Failed(_))
        ));
    }

    #[test]
    fn disk_hogs_marks_sizes_as_incomplete_when_time_runs_out() {
        let t = tree();
        let ctx = ctx(&t.host, "rita", "fs.view", Access::Read);
        let opts = HogOpts {
            depth: 2,
            limit: 20,
            min_file_bytes: 100 * KIB,
            walk_time: Duration::ZERO,
        };
        let text = ok_text(disk_hogs_report(&ctx, &t.root, &opts));
        assert!(text.contains(": >= "), "{text}");
        assert!(text.contains("time limit"), "{text}");
    }

    #[test]
    fn disk_hogs_finds_deleted_files_that_a_process_still_holds_open() {
        let t = tree();
        let gone = t.path("logs/rotated.log");
        fill(Path::new(&gone), 500);
        let hidden = t.path("secret/gone.bin");
        fill(Path::new(&hidden), 700);
        // this test process is the one holding them open
        let _held = std::fs::File::open(&gone).unwrap();
        let _held_too = std::fs::File::open(&hidden).unwrap();
        std::fs::remove_file(&gone).unwrap();
        std::fs::remove_file(&hidden).unwrap();

        let text = ok_text(t.report("rita", &t.root));
        let section = &text[text.find("== Deleted files still held open").unwrap()..];
        let line = section
            .lines()
            .find(|line| line.ends_with("logs/rotated.log"))
            .unwrap_or_else(|| panic!("the deleted file is missing from:\n{section}"));
        assert!(line.contains(&std::process::id().to_string()), "{line}");
        assert!(section.contains("secret/gone.bin"), "{section}");
        // they are no longer part of the walk
        assert!(!listed(&text, "== Largest files").contains(&gone));

        // a caller who may not see the directory does not see its deleted files either
        let text = ok_text(t.report("dana", &t.root));
        assert!(text.contains("logs/rotated.log"), "{text}");
        assert!(!text.contains("gone.bin"), "{text}");
        // only what lies under the directory asked about is reported
        let text = ok_text(t.report("rita", &t.path("pub")));
        assert!(!text.contains("rotated.log"), "{text}");
    }

    #[tokio::test]
    async fn disk_hogs_takes_its_limits_from_the_arguments() {
        let t = tree();
        fill(Path::new(&t.path("pub/two-megabytes.bin")), 2048);
        let tool = find(tools(), "disk_hogs");
        assert_eq!(
            (tool.access, tool.permission.as_str()),
            (Access::Read, "fs.view")
        );
        let arguments = json!({"path": t.root, "depth": 1, "limit": 2, "min_file_mb": 1});
        let text = ok_text(call(&t.host, "rita", &tool, arguments).await);
        assert_eq!(
            listed(&text, "== Largest directories"),
            [t.path("pub"), t.path("secret")]
        );
        assert_eq!(
            listed(&text, "== Largest files"),
            [t.path("pub/two-megabytes.bin")]
        );
        // out of range values are refused by the declared bounds
        for bad in [
            json!({"path": t.root, "depth": 6}),
            json!({"path": t.root, "limit": 0}),
            json!({"path": t.root, "min_file_mb": 0}),
            json!({"depth": 1}),
        ] {
            assert!(
                matches!(
                    call(&t.host, "rita", &tool, bad.clone()).await,
                    Err(ToolError::Invalid(_))
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn deleted_files_held_in_another_mount_namespace_are_counted_but_not_named() {
        let t = tree();
        let gone = t.path("logs/held-elsewhere.log");
        fill(Path::new(&gone), 300);
        let _held = std::fs::File::open(&gone).unwrap();
        std::fs::remove_file(&gone).unwrap();
        let dev = std::fs::metadata(&t.root).unwrap().dev();
        let all = |_: &str, _: bool| true;

        // seen from the mount namespace of the process that holds it: named
        let own = View::own();
        let same = deleted_open_files(&t.root, dev, 20, &own, &all);
        assert!(same.held.iter().any(|file| file.path == gone));

        // seen from any other namespace, the path it reports means nothing: the file
        // is counted, and its name is not shown
        let other_namespace = View {
            mount_ns: Some("mnt:[1]".into()),
            root: own.root.clone(),
        };
        let unknown_namespace = View {
            mount_ns: None,
            root: own.root.clone(),
        };
        // A process in a chroot shares our mount namespace, but its paths are relative
        // to its own root directory: they mean something else here too.
        let other_root = View {
            mount_ns: own.mount_ns.clone(),
            root: Some("/srv/jail".into()),
        };
        for elsewhere in [other_namespace, unknown_namespace, other_root] {
            let other = deleted_open_files(&t.root, dev, 20, &elsewhere, &all);
            assert!(other.held.is_empty(), "{elsewhere:?}");
            assert!(other.elsewhere_files >= 1, "{elsewhere:?}");
            assert!(other.elsewhere_bytes >= 300 * KIB, "{elsewhere:?}");
        }
    }

    #[test]
    fn the_report_mentions_deleted_files_it_cannot_name() {
        let opts = HogOpts {
            depth: 2,
            limit: 20,
            min_file_bytes: 100 * KIB,
            walk_time: Duration::from_secs(25),
        };
        let usage = Usage {
            total: 4096,
            partial: false,
            dirs: vec![],
            files: vec![],
            hidden: 0,
            unreadable: 0,
        };
        let mut deleted = DeletedFiles {
            held: vec![],
            hidden: 0,
            cut_short: false,
            elsewhere_files: 2,
            elsewhere_bytes: 5 * 1024 * KIB,
        };
        let text = hogs_text("/srv", &opts, &usage, &deleted, true);
        assert!(
            text.contains(
                "[2 more deleted files on this filesystem, 5.0 MiB in all, are held open by \
                 processes in another mount namespace (containers)"
            ),
            "{text}"
        );
        deleted.elsewhere_files = 0;
        let text = hogs_text("/srv", &opts, &usage, &deleted, true);
        assert!(!text.contains("mount namespace"), "{text}");
    }

    #[test]
    fn who_holds_a_deleted_file_is_shown_only_to_a_caller_who_may_see_processes() {
        // AIDEV-NOTE: fs.view lets a caller see file names and sizes. Which process has a
        // file open is process information, and needs process.view like everywhere else.
        let opts = HogOpts {
            depth: 2,
            limit: 20,
            min_file_bytes: 100 * KIB,
            walk_time: Duration::from_secs(25),
        };
        let usage = Usage {
            total: 4096,
            partial: false,
            dirs: vec![],
            files: vec![],
            hidden: 0,
            unreadable: 0,
        };
        let deleted = DeletedFiles {
            held: vec![Held {
                bytes: 300 * KIB,
                path: "/srv/old.log".to_string(),
                pids: vec![std::process::id() as i32],
            }],
            hidden: 0,
            cut_short: false,
            elsewhere_files: 0,
            elsewhere_bytes: 0,
        };
        let with = hogs_text("/srv", &opts, &usage, &deleted, true);
        assert!(with.contains("PID") && with.contains("PROCESS"), "{with}");
        assert!(with.contains(&std::process::id().to_string()), "{with}");

        let without = hogs_text("/srv", &opts, &usage, &deleted, false);
        assert!(without.contains("/srv/old.log"), "{without}");
        assert!(
            !without.contains("PID") && !without.contains("PROCESS"),
            "{without}"
        );
        assert!(
            !without.contains(&std::process::id().to_string()),
            "{without}"
        );
        assert!(without.contains("process.view"), "{without}");
    }
}
