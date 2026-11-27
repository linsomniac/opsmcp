//! MegaRAID controllers (LSI, Avago and Broadcom MegaRAID, Dell PERC), read through
//! MegaCli: controllers, virtual drives, physical drives and the battery.
//!
//! AIDEV-NOTE: read-only by construction. Only `-AdpAllInfo`, `-LDInfo`, `-PDList` and
//! `-AdpBbuCmd -GetBbuStatus` are ever run, with fixed arguments; the one thing a caller
//! supplies is a controller number. `-NoLog` is always given: without it MegaCli appends
//! to a MegaSAS.log file in whatever directory it is started in.
//!
//! AIDEV-NOTE: MegaCli has no output meant for programs. What is read here are its
//! `Key : Value` lines, by key, wherever they stand, so that a firmware that prints more
//! or in another order still parses.
//!
//! AIDEV-NOTE: what this has been checked against. On 2026-11-27 the four reports of a
//! real controller (Dell PERC H730P, firmware 25.5.9, MegaCli 8.07.14: one healthy
//! RAID 60 of 24 SSDs with a battery) were run through the tool and read correctly; the
//! test `a_real_controllers_reports_are_read_as_megacli_printed_them` keeps their exact
//! form, with made-up serial numbers. Everything that is NOT healthy (a degraded or
//! offline array, failed and rebuilding drives, a missing or failed battery, a second
//! controller, older firmware's wording) is still tested only against samples written
//! from memory of MegaCli's output. When one of those is met for real, compare the
//! summary with view=virtual_drives and view=drives, which pass MegaCli's own text on.

use super::args::{Args, Param};
use std::path::PathBuf;

use super::{CallClock, Ctx, Tool, ToolError, ToolResult, command_ok, command_text, format_table};
use crate::exec::CmdOutput;
use crate::policy::Access;
use crate::sanitize::keep_head;

const VIEWS: [&str; 5] = [
    "summary",
    "controller",
    "virtual_drives",
    "drives",
    "battery",
];
/// The names MegaCli is installed under: the Debian package's, and the vendor's own for
/// 64-bit and 32-bit systems.
const PROGRAM_NAMES: [&str; 3] = ["megacli", "MegaCli64", "MegaCli"];
const MAX_CONTROLLER: i64 = 31;

const CONTROLLER_INFO: [&str; 1] = ["-AdpAllInfo"];
const VIRTUAL_DRIVES: [&str; 2] = ["-LDInfo", "-Lall"];
const PHYSICAL_DRIVES: [&str; 1] = ["-PDList"];
const BATTERY: [&str; 2] = ["-AdpBbuCmd", "-GetBbuStatus"];

pub fn tools() -> Vec<Tool> {
    vec![Tool::new(
        "megaraid_status",
        "Show the hardware RAID of this machine from MegaCli, for LSI, Avago and Broadcom \
         MegaRAID controllers and Dell PERC: by default each controller with its firmware \
         and battery, every virtual drive (RAID level, size, state, cache policy, any \
         rebuild or consistency check in progress) and every physical drive (slot, state, \
         size, model, media errors, predicted failures, SMART alert, temperature); the \
         first line is the verdict. Use it when a disk or array is suspected (I/O errors \
         in kernel_log, slow writes after a battery failure). view=controller, \
         virtual_drives, drives or battery gives MegaCli's own full report for that \
         part. Changes nothing. Needs MegaCli; for software RAID (md) use block_devices, \
         for a drive's SMART data disk_health.",
        Access::Read,
        "storage.view",
        vec![
            Param::choice(
                "view",
                "What to show: summary (default), or MegaCli's full report on the \
                 controller, the virtual_drives, the drives or the battery",
                &VIEWS,
            ),
            Param::int(
                "controller",
                "Only this controller, by number (default: all)",
                0,
                MAX_CONTROLLER,
            ),
        ],
        megaraid_status,
    )]
}

/// The arguments for one MegaCli report: what to show, on which controller, and never
/// with a log file.
pub fn megacli_argv(report: &[&str], controller: Option<i64>) -> Vec<String> {
    let mut argv: Vec<String> = report.iter().map(|word| word.to_string()).collect();
    argv.push(match controller {
        Some(number) => format!("-a{number}"),
        None => "-aALL".to_string(),
    });
    argv.push("-NoLog".to_string());
    argv
}

/// A `Key : Value` line: the key in lower case and the value, split at the first colon.
/// MegaCli pads either side of the colon differently from line to line and from version
/// to version, and has changed the capitals in some keys.
fn key_value(line: &str) -> Option<(String, &str)> {
    let (key, value) = line.split_once(':')?;
    Some((key.trim().to_ascii_lowercase(), value.trim()))
}

/// The controller a heading opens a section for: `Adapter #0`, `Adapter 0 -- Virtual
/// Drive Information:` or `BBU status for Adapter: 0`. A line that only mentions a
/// controller (`Adapter 0: Get BBU Status Failed.`) is not a heading.
fn controller_heading(line: &str) -> Option<u32> {
    let line = line.trim();
    if let Some(number) = line.strip_prefix("BBU status for Adapter:") {
        return number.trim().parse().ok();
    }
    let rest = line
        .strip_prefix("Adapter")?
        .trim_start()
        .trim_start_matches('#');
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    let after = rest[digits.len()..].trim_start();
    if after.is_empty() || after.starts_with("--") {
        digits.parse().ok()
    } else {
        None
    }
}

fn number(value: &str) -> u64 {
    value.trim().parse().unwrap_or(0)
}

/// What is known of one controller from `-AdpAllInfo`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Controller {
    pub number: u32,
    pub product: String,
    pub serial: String,
    pub firmware: String,
    pub memory_correctable: u64,
    pub memory_uncorrectable: u64,
}

pub fn parse_controllers(text: &str) -> Vec<Controller> {
    let mut controllers: Vec<Controller> = Vec::new();
    for line in text.lines() {
        if let Some(number) = controller_heading(line) {
            controllers.push(Controller {
                number,
                ..Controller::default()
            });
            continue;
        }
        let (Some(controller), Some((key, value))) = (controllers.last_mut(), key_value(line))
        else {
            continue;
        };
        match key.as_str() {
            "product name" => controller.product = value.to_string(),
            "serial no" => controller.serial = value.to_string(),
            "fw package build" => controller.firmware = value.to_string(),
            "memory correctable errors" => controller.memory_correctable = number(value),
            "memory uncorrectable errors" => controller.memory_uncorrectable = number(value),
            _ => {}
        }
    }
    controllers
}

/// One virtual drive from `-LDInfo -Lall`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VirtualDrive {
    pub controller: u32,
    pub number: String,
    pub name: String,
    /// `RAID 1`, `RAID 10`... worked out from the level and the span depth.
    pub raid: String,
    pub size: String,
    pub state: String,
    /// How many physical drives it is made of.
    pub drives: String,
    pub cache: String,
    pub configured_cache: String,
    /// Checks, initialisations and reconstructions under way, as MegaCli words them.
    pub in_progress: Vec<String>,
}

/// The name of a RAID level, from MegaCli's `Primary-1, Secondary-0, RAID Level
/// Qualifier-0` and the number of spans. A level in any other form is returned as it is.
///
/// AIDEV-NOTE: MegaCli does not print "RAID 10". An array of several spans is the
/// primary level with a 0 after it (10, 50, 60); older firmware instead marks a RAID 10
/// with Secondary-3 and reports a single span. Both are handled.
fn raid_name(level: &str, span_depth: u64) -> String {
    let part = |name: &str| -> Option<u64> {
        level
            .split(',')
            .find_map(|piece| piece.trim().strip_prefix(name)?.trim().parse().ok())
    };
    let Some(primary) = part("Primary-") else {
        return level.to_string();
    };
    if span_depth > 1 || (primary == 1 && part("Secondary-") == Some(3)) {
        format!("RAID {primary}0")
    } else {
        format!("RAID {primary}")
    }
}

/// A virtual drive while its lines are being read.
#[derive(Default)]
struct VirtualDriveLines {
    drive: VirtualDrive,
    level: String,
    drives: Option<u64>,
    drives_per_span: Option<u64>,
    span_depth: u64,
}

impl VirtualDriveLines {
    fn finish(self) -> VirtualDrive {
        let mut drive = self.drive;
        drive.raid = raid_name(&self.level, self.span_depth);
        drive.drives = match (self.drives_per_span, self.drives) {
            (Some(per_span), _) => per_span.saturating_mul(self.span_depth.max(1)).to_string(),
            (None, Some(count)) => count.to_string(),
            (None, None) => String::new(),
        };
        drive
    }
}

pub fn parse_virtual_drives(text: &str) -> Vec<VirtualDrive> {
    let mut drives = Vec::new();
    let mut controller = 0;
    let mut current: Option<VirtualDriveLines> = None;
    for line in text.lines() {
        if let Some(number) = controller_heading(line) {
            drives.extend(current.take().map(VirtualDriveLines::finish));
            controller = number;
            continue;
        }
        let Some((key, value)) = key_value(line) else {
            continue;
        };
        // older versions say "Virtual Disk"
        if key == "virtual drive" || key == "virtual disk" {
            drives.extend(current.take().map(VirtualDriveLines::finish));
            let mut lines = VirtualDriveLines::default();
            lines.drive.controller = controller;
            lines.drive.number = value.split_whitespace().next().unwrap_or("").to_string();
            current = Some(lines);
            continue;
        }
        let Some(lines) = current.as_mut() else {
            continue;
        };
        match key.as_str() {
            "name" => lines.drive.name = value.to_string(),
            "raid level" => lines.level = value.to_string(),
            "size" => lines.drive.size = value.to_string(),
            "state" => lines.drive.state = value.to_string(),
            "number of drives" => lines.drives = value.parse().ok(),
            "number of drives per span" => lines.drives_per_span = value.parse().ok(),
            "span depth" => lines.span_depth = number(value),
            "default cache policy" => lines.drive.configured_cache = value.to_string(),
            "current cache policy" => lines.drive.cache = value.to_string(),
            // Under "Ongoing Progresses:", e.g. "Check Consistency : Completed 37%, ..."
            _ if value.starts_with("Completed") => {
                let what = line.split_once(':').map_or("", |(what, _)| what.trim());
                lines.drive.in_progress.push(format!("{what}: {value}"));
            }
            _ => {}
        }
    }
    drives.extend(current.take().map(VirtualDriveLines::finish));
    drives
}

/// One physical drive from `-PDList`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PhysicalDrive {
    pub controller: u32,
    pub enclosure: String,
    pub slot: String,
    pub state: String,
    pub size: String,
    /// Interface and medium, e.g. `SAS HDD`.
    pub kind: String,
    pub model: String,
    pub media_errors: u64,
    pub other_errors: u64,
    pub predictive_failures: u64,
    pub smart_alert: bool,
    pub temperature: String,
    /// It carries the configuration of another controller.
    pub foreign: bool,
}

/// `278.875 GB [0x22dc0000 Sectors]` without the sector count.
fn size_only(value: &str) -> String {
    value.split('[').next().unwrap_or("").trim().to_string()
}

pub fn parse_physical_drives(text: &str) -> Vec<PhysicalDrive> {
    let mut drives: Vec<PhysicalDrive> = Vec::new();
    let mut controller = 0;
    // Interface and medium come on separate lines.
    let (mut interface, mut medium) = (String::new(), String::new());
    let close = |drives: &mut Vec<PhysicalDrive>, interface: &mut String, medium: &mut String| {
        if let Some(drive) = drives.last_mut() {
            drive.kind = format!("{interface} {medium}").trim().to_string();
        }
        interface.clear();
        medium.clear();
    };
    for line in text.lines() {
        if let Some(number) = controller_heading(line) {
            close(&mut drives, &mut interface, &mut medium);
            controller = number;
            continue;
        }
        let Some((key, value)) = key_value(line) else {
            continue;
        };
        // every drive's lines begin with its enclosure
        if key == "enclosure device id" {
            close(&mut drives, &mut interface, &mut medium);
            drives.push(PhysicalDrive {
                controller,
                enclosure: value.to_string(),
                ..PhysicalDrive::default()
            });
            continue;
        }
        let Some(drive) = drives
            .last_mut()
            .filter(|drive| drive.controller == controller)
        else {
            continue;
        };
        match key.as_str() {
            "slot number" => drive.slot = value.to_string(),
            "media error count" => drive.media_errors = number(value),
            "other error count" => drive.other_errors = number(value),
            "predictive failure count" => drive.predictive_failures = number(value),
            "pd type" => interface = value.to_string(),
            "coerced size" => drive.size = size_only(value),
            "raw size" if drive.size.is_empty() => drive.size = size_only(value),
            "firmware state" => drive.state = value.to_string(),
            "inquiry data" => {
                drive.model = value.split_whitespace().collect::<Vec<&str>>().join(" ");
            }
            "media type" => {
                medium = match value {
                    "Hard Disk Device" => "HDD".to_string(),
                    "Solid State Device" => "SSD".to_string(),
                    other => other.to_string(),
                };
            }
            "drive temperature" => {
                drive.temperature = value.split_whitespace().next().unwrap_or("").to_string();
            }
            "drive has flagged a s.m.a.r.t alert" => {
                drive.smart_alert = value.eq_ignore_ascii_case("yes");
            }
            "foreign state" => drive.foreign = value.eq_ignore_ascii_case("foreign"),
            _ => {}
        }
    }
    close(&mut drives, &mut interface, &mut medium);
    drives
}

/// One controller's battery (or capacitor) from `-AdpBbuCmd -GetBbuStatus`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Battery {
    pub controller: u32,
    pub state: String,
    pub charge: String,
    pub replace: bool,
}

pub fn parse_batteries(text: &str) -> Vec<Battery> {
    let mut batteries: Vec<Battery> = Vec::new();
    for line in text.lines() {
        if let Some(controller) = controller_heading(line) {
            batteries.push(Battery {
                controller,
                ..Battery::default()
            });
            continue;
        }
        let (Some(battery), Some((key, value))) = (batteries.last_mut(), key_value(line)) else {
            continue;
        };
        match key.as_str() {
            "battery state" => battery.state = value.to_string(),
            "relative state of charge" => battery.charge = value.to_string(),
            "battery replacement required" | "pack is about to fail & should be replaced" => {
                battery.replace |= value.eq_ignore_ascii_case("yes");
            }
            // older firmware: the battery's state of health, as a yes or no
            "issohgood" => battery.replace |= value.eq_ignore_ascii_case("no"),
            _ => {}
        }
    }
    batteries
}

/// Everything the summary is made from.
#[derive(Clone, Debug, Default)]
pub struct Readings {
    pub controllers: Vec<Controller>,
    pub virtual_drives: Vec<VirtualDrive>,
    pub physical_drives: Vec<PhysicalDrive>,
    pub batteries: Vec<Battery>,
    /// The reports MegaCli failed to give, or gave only part of: `controller`, `virtual
    /// drives`, `drives`, `battery`.
    pub unread: Vec<&'static str>,
}

fn counted(n: u64, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

/// What a drive's firmware state says about it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DriveState {
    /// In an array, a spare, unused, or passed through to the system.
    Good,
    /// Being rebuilt, or having a spare's contents copied back to it. Both end by
    /// themselves, and an array that is degraded meanwhile says so itself.
    Working,
    /// Failed, offline, marked bad, or anything not known here.
    Bad,
}

fn drive_state(state: &str) -> DriveState {
    let state = state.to_ascii_lowercase();
    let is = |names: &[&str]| names.iter().any(|name| state.starts_with(name));
    if is(&["online", "hotspare", "unconfigured(good)", "jbod"]) {
        DriveState::Good
    } else if is(&["rebuild", "copyback"]) {
        DriveState::Working
    } else {
        DriveState::Bad
    }
}

fn battery_state_ok(state: &str) -> bool {
    state.eq_ignore_ascii_case("optimal") || state.eq_ignore_ascii_case("operational")
}

fn or_dash(text: &str) -> String {
    if text.is_empty() {
        "-".to_string()
    } else {
        text.to_string()
    }
}

/// The write policy of a cache policy: its first word (`WriteBack`, `WriteThrough`).
fn write_policy(cache: &str) -> &str {
    cache.split(',').next().unwrap_or("").trim()
}

/// The summary: the verdict, the controllers with their batteries, and a table each of
/// the virtual and the physical drives.
pub fn summary_text(read: &Readings) -> String {
    // The controllers anything was read about, in order.
    let mut numbers: Vec<u32> = read
        .controllers
        .iter()
        .map(|c| c.number)
        .chain(read.virtual_drives.iter().map(|d| d.controller))
        .chain(read.physical_drives.iter().map(|d| d.controller))
        .chain(read.batteries.iter().map(|b| b.controller))
        .collect();
    numbers.sort_unstable();
    numbers.dedup();
    // With one controller, saying which one a finding is about is noise.
    let several = numbers.len() > 1;
    let on = |controller: u32| {
        if several {
            format!(" on controller {controller}")
        } else {
            String::new()
        }
    };

    let (mut problems, mut warnings) = (Vec::new(), Vec::new());
    for drive in &read.virtual_drives {
        let mut what = format!("virtual drive {}", drive.number);
        if !drive.name.is_empty() {
            what.push_str(&format!(" ({})", drive.name));
        }
        what.push_str(&on(drive.controller));
        if !drive.state.eq_ignore_ascii_case("optimal") {
            problems.push(format!("{what} is {}", or_dash(&drive.state)));
        }
        let (now, configured) = (
            write_policy(&drive.cache),
            write_policy(&drive.configured_cache),
        );
        // AIDEV-NOTE: a controller whose battery has failed drops from WriteBack to
        // WriteThrough by itself, and writes become several times slower. Nothing else
        // shows it: the array stays Optimal.
        if !now.is_empty() && !configured.is_empty() && now != configured {
            warnings.push(format!(
                "{what} is running {now} where {configured} is configured (usually the battery)"
            ));
        }
    }
    for drive in &read.physical_drives {
        let what = format!(
            "drive {}:{}{}",
            drive.enclosure,
            drive.slot,
            on(drive.controller)
        );
        let state = drive.state.split(',').next().unwrap_or("").trim();
        let kind = drive_state(&drive.state);
        if kind == DriveState::Bad {
            problems.push(format!("{what} is {}", or_dash(state)));
        } else if kind == DriveState::Working {
            warnings.push(format!("{what} is {state}"));
        }
        if kind != DriveState::Bad && (drive.predictive_failures > 0 || drive.smart_alert) {
            let mut signs = Vec::new();
            if drive.predictive_failures > 0 {
                signs.push(counted(
                    drive.predictive_failures,
                    "predictive failure",
                    "predictive failures",
                ));
            }
            if drive.smart_alert {
                signs.push("SMART alert".to_string());
            }
            problems.push(format!(
                "{what} predicts its own failure ({})",
                signs.join(", ")
            ));
        }
        if drive.media_errors > 0 {
            warnings.push(format!(
                "{what} has {}",
                counted(drive.media_errors, "media error", "media errors")
            ));
        }
        if drive.foreign {
            warnings.push(format!("{what} has a foreign configuration"));
        }
    }
    for controller in &read.controllers {
        if controller.memory_uncorrectable > 0 {
            problems.push(format!(
                "controller {} has {}",
                controller.number,
                counted(
                    controller.memory_uncorrectable,
                    "uncorrectable memory error",
                    "uncorrectable memory errors"
                )
            ));
        }
        if controller.memory_correctable > 0 {
            warnings.push(format!(
                "controller {} has {}",
                controller.number,
                counted(
                    controller.memory_correctable,
                    "corrected memory error",
                    "corrected memory errors"
                )
            ));
        }
    }
    for battery in &read.batteries {
        let what = if several {
            format!("the battery of controller {}", battery.controller)
        } else {
            "the battery".to_string()
        };
        let bad_state = !battery.state.is_empty() && !battery_state_ok(&battery.state);
        match (bad_state, battery.replace) {
            (true, true) => {
                problems.push(format!("{what} is {} and needs replacing", battery.state))
            }
            (true, false) => problems.push(format!("{what} is {}", battery.state)),
            (false, true) => problems.push(format!("{what} needs replacing")),
            (false, false) => {}
        }
    }

    // AIDEV-NOTE: the first line is what a caller acts on. When a report failed or was
    // cut short, what was read can look healthy and be half the picture, so that is said
    // first and the "no problems" sentence is never given.
    let mut sentences = Vec::new();
    if !read.unread.is_empty() {
        let views: Vec<String> = read
            .unread
            .iter()
            .map(|what| format!("view={}", what.replace(' ', "_")))
            .collect();
        sentences.push(format!(
            "INCOMPLETE: MegaCli's report on the {} failed or was cut short, so parts may \
             be missing here ({} {} what it said).",
            read.unread.join(" and the "),
            views.join(" and "),
            if views.len() == 1 { "shows" } else { "show" },
        ));
    }
    if !problems.is_empty() {
        sentences.push(format!("PROBLEM: {}.", problems.join("; ")));
    }
    if !warnings.is_empty() {
        sentences.push(format!("Warnings: {}.", warnings.join("; ")));
    }
    if problems.is_empty() && warnings.is_empty() && !read.unread.is_empty() {
        sentences.push("Nothing that was read reports a problem.".to_string());
    }
    let mut text = sentences.join(" ");
    if text.is_empty() {
        text = format!(
            "No MegaRAID problems are visible ({}, {}, {}).",
            counted(numbers.len() as u64, "controller", "controllers"),
            counted(
                read.virtual_drives.len() as u64,
                "virtual drive",
                "virtual drives"
            ),
            counted(read.physical_drives.len() as u64, "drive", "drives"),
        );
    }
    text.push_str("\n\n");

    for number in &numbers {
        let mut line = format!("Controller {number}");
        if let Some(controller) = read.controllers.iter().find(|c| c.number == *number) {
            let mut parts = Vec::new();
            if !controller.product.is_empty() {
                parts.push(controller.product.clone());
            }
            if !controller.firmware.is_empty() {
                parts.push(format!("firmware {}", controller.firmware));
            }
            if !controller.serial.is_empty() {
                parts.push(format!("serial {}", controller.serial));
            }
            if !parts.is_empty() {
                line.push_str(&format!(": {}", parts.join(", ")));
            }
        }
        text.push_str(&line);
        text.push('\n');
        match read.batteries.iter().find(|b| b.controller == *number) {
            Some(battery) => {
                let mut parts = vec![or_dash(&battery.state)];
                if !battery.charge.is_empty() {
                    parts.push(format!("{} charged", battery.charge));
                }
                if battery.replace {
                    parts.push("replacement required".to_string());
                }
                text.push_str(&format!("  Battery: {}\n", parts.join(", ")));
            }
            None if read.unread.contains(&"battery") => {
                text.push_str("  Battery: could not be read\n");
            }
            None => text.push_str("  Battery: none reported\n"),
        }
    }

    text.push_str("\n== Virtual drives ==\n");
    if read.virtual_drives.is_empty() {
        text.push_str("(none)\n");
    } else {
        let rows: Vec<Vec<String>> = read
            .virtual_drives
            .iter()
            .map(|drive| {
                vec![
                    drive.controller.to_string(),
                    or_dash(&drive.number),
                    or_dash(&drive.name),
                    or_dash(&drive.raid),
                    or_dash(&drive.size),
                    or_dash(&drive.state),
                    or_dash(&drive.drives),
                    or_dash(&drive.cache),
                    or_dash(&drive.in_progress.join("; ")),
                ]
            })
            .collect();
        text.push_str(&format_table(
            &[
                "CTRL",
                "VD",
                "NAME",
                "RAID",
                "SIZE",
                "STATE",
                "DRIVES",
                "CACHE",
                "IN PROGRESS",
            ],
            &rows,
            &[false; 9],
        ));
    }

    text.push_str("\n== Physical drives ==\n");
    if read.physical_drives.is_empty() {
        text.push_str("(none)\n");
    } else {
        let rows: Vec<Vec<String>> = read
            .physical_drives
            .iter()
            .map(|drive| {
                vec![
                    drive.controller.to_string(),
                    format!("{}:{}", drive.enclosure, drive.slot),
                    or_dash(&drive.state),
                    or_dash(&drive.size),
                    or_dash(&drive.kind),
                    or_dash(&drive.model),
                    drive.media_errors.to_string(),
                    drive.other_errors.to_string(),
                    drive.predictive_failures.to_string(),
                    if drive.smart_alert { "ALERT" } else { "no" }.to_string(),
                    or_dash(&drive.temperature),
                ]
            })
            .collect();
        text.push_str(&format_table(
            &[
                "CTRL",
                "ENCL:SLOT",
                "STATE",
                "SIZE",
                "TYPE",
                "MODEL",
                "MEDIA-ERR",
                "OTHER-ERR",
                "PRED-FAIL",
                "SMART",
                "TEMP",
            ],
            &rows,
            &[
                false, false, false, false, false, false, true, true, true, false, false,
            ],
        ));
    }
    text
}

/// `text`, cut at the end if it is longer than a call may return.
fn bounded(text: &str, budget: usize) -> String {
    let (mut kept, dropped) = keep_head(text, budget.saturating_sub(100));
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

/// Where MegaCli is, under any of its names. `None` when it is not installed.
fn find_megacli(ctx: &Ctx) -> Result<Option<PathBuf>, ToolError> {
    for name in PROGRAM_NAMES {
        if let Some(path) = ctx.bins().lookup(name).map_err(ToolError::Failed)? {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

async fn megaraid_status(ctx: Ctx, args: Args) -> ToolResult {
    let view = args.str("view").unwrap_or("summary").to_string();
    let controller = args.int("controller");
    let auth = ctx.authorize(None)?;
    let Some(program) = find_megacli(&ctx)? else {
        // AIDEV-NOTE: the vendor's package installs into /opt/MegaRAID/MegaCli, which is
        // not among the directories commands are looked for in, and is deliberately not
        // searched here either: where a program may be run from is the operator's
        // decision ([paths] in the configuration), not a tool's.
        return auth.failed(
            "MegaCli is not installed on this host (looked for megacli, MegaCli64 and \
             MegaCli). If it is installed somewhere commands are not looked for, as the \
             vendor's package is, say where in the configuration:\n\
             [paths.bin]\nmegacli = \"/opt/MegaRAID/MegaCli/MegaCli64\"\n",
        );
    };
    let budget = ctx.output_budget();
    let report: &[&str] = match view.as_str() {
        "controller" => &CONTROLLER_INFO,
        "virtual_drives" => &VIRTUAL_DRIVES,
        "drives" => &PHYSICAL_DRIVES,
        "battery" => &BATTERY,
        _ => &[],
    };
    if !report.is_empty() {
        let cmd = ctx
            .command_at(program)
            .args(megacli_argv(report, controller));
        let out = ctx.run(cmd).await?;
        return auth.done(bounded(&command_text(&out), budget), command_ok(&out));
    }

    let clock = CallClock::start(&ctx);
    let mut read = Readings::default();
    let mut answered = false;
    let mut failure: Option<String> = None;
    let reports: [(&'static str, &[&str]); 4] = [
        ("controller", &CONTROLLER_INFO),
        ("virtual drives", &VIRTUAL_DRIVES),
        ("drives", &PHYSICAL_DRIVES),
        ("battery", &BATTERY),
    ];
    for (what, report) in reports {
        let Some(time_left) = clock.next() else {
            read.unread.push(what);
            continue;
        };
        let cmd = ctx
            .command_at(program.clone())
            .args(megacli_argv(report, controller))
            .timeout(time_left);
        let out = ctx.run(cmd).await?;
        let said = stdout(&out);
        match what {
            "controller" => read.controllers = parse_controllers(&said),
            "virtual drives" => read.virtual_drives = parse_virtual_drives(&said),
            "drives" => read.physical_drives = parse_physical_drives(&said),
            _ => read.batteries = parse_batteries(&said),
        }
        answered |= command_ok(&out);
        // AIDEV-NOTE: MegaCli's exit status is the "Exit Code" it prints, and it is not
        // 0 for two answers that are complete: a controller with no battery (0x22, "The
        // required hardware component is not present") and, on some versions, one with
        // no virtual drive. Those are recognised by what they say. Any other failure, a
        // time limit, or output longer than is kept means the report was not all read.
        let nothing_there = match what {
            "battery" => said.contains("hardware component is not present"),
            "virtual drives" => said.contains("No Virtual Drive Configured"),
            _ => false,
        };
        let complete = !out.truncated && !out.timed_out && (command_ok(&out) || nothing_there);
        if !complete {
            read.unread.push(what);
            failure.get_or_insert_with(|| command_text(&out));
        }
    }
    if read.controllers.is_empty()
        && read.virtual_drives.is_empty()
        && read.physical_drives.is_empty()
    {
        return match failure {
            Some(said) if !answered => auth.failed(bounded(&said, budget)),
            _ => auth.ok("MegaCli found no MegaRAID controller on this host.\n"),
        };
    }
    auth.ok(bounded(&summary_text(&read), budget))
}

fn stdout(out: &CmdOutput) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::Host;
    use crate::tools::testing::{FakeBins, call, find, host, ok_text};
    use serde_json::{Value, json};
    use std::sync::Arc;

    const ADAPTER_INFO: &str = "\nAdapter #0\n\n==============================================================================\n                    Versions\n                ================\nProduct Name    : PERC H710 Mini\nSerial No       : 3A1234\nFW Package Build: 21.3.0-0009\n\n                    Mfg. Data\n                ================\nMfg. Date       : 06/24/13\nRework Date     : 06/24/13\n\n                    Device Present\n                ================\nVirtual Drives    : 2 \n  Degraded        : 1 \n  Offline         : 0 \nPhysical Devices  : 7 \n  Disks           : 6 \n  Critical Disks  : 1 \n  Failed Disks    : 1 \n\n                    Error Counters\n                ================\nMemory Correctable Errors   : 0 \nMemory Uncorrectable Errors : 0 \n\nExit Code: 0x00\n";

    /// One virtual drive as `-LDInfo` prints it.
    fn virtual_drive(
        number: u32,
        name: &str,
        level: &str,
        drives: &str,
        state: &str,
        cache: &str,
        extra: &str,
    ) -> String {
        format!(
            "Virtual Drive: {number} (Target Id: {number})\nName                :{name}\nRAID Level          : {level}\nSize                : 278.875 GB\nSector Size         : 512\nMirror Data         : 278.875 GB\nState               : {state}\nStrip Size          : 64 KB\n{drives}\nDefault Cache Policy: WriteBack, ReadAheadNone, Direct, No Write Cache if Bad BBU\nCurrent Cache Policy: {cache}, ReadAheadNone, Direct, No Write Cache if Bad BBU\nDefault Access Policy: Read/Write\nCurrent Access Policy: Read/Write\nDisk Cache Policy   : Disk's Default\n{extra}Encryption Type     : None\nBad Blocks Exist: No\nIs VD Cached: No\n\n\n"
        )
    }

    const MIRROR: &str = "Primary-1, Secondary-0, RAID Level Qualifier-0";
    const TWO_DRIVES: &str = "Number Of Drives    : 2\nSpan Depth          : 1";
    const TWO_SPANS: &str = "Number Of Drives per span:2\nSpan Depth          : 2";
    const CHECKING: &str =
        "Ongoing Progresses:\n  Check Consistency        : Completed 37%, Taken 12 min.\n";

    fn ld_info(drives: &[String]) -> String {
        format!(
            "\n\nAdapter 0 -- Virtual Drive Information:\n{}\nExit Code: 0x00\n",
            drives.concat()
        )
    }

    fn troubled_virtual_drives() -> String {
        ld_info(&[
            virtual_drive(
                0,
                "system",
                MIRROR,
                TWO_DRIVES,
                "Optimal",
                "WriteBack",
                CHECKING,
            ),
            virtual_drive(1, "data", MIRROR, TWO_SPANS, "Degraded", "WriteThrough", ""),
        ])
    }

    fn healthy_virtual_drives() -> String {
        ld_info(&[
            virtual_drive(0, "system", MIRROR, TWO_DRIVES, "Optimal", "WriteBack", ""),
            virtual_drive(1, "", MIRROR, TWO_SPANS, "Optimal", "WriteBack", ""),
        ])
    }

    /// One physical drive as `-PDList` prints it.
    fn physical_drive(
        slot: u32,
        state: &str,
        media_errors: u32,
        predictive: u32,
        alert: &str,
    ) -> String {
        format!(
            "Enclosure Device ID: 32\nSlot Number: {slot}\nDrive's position: DiskGroup: 0, Span: 0, Arm: {slot}\nEnclosure position: N/A\nDevice Id: {slot}\nWWN: 5000C5007F1B0A3C\nSequence Number: 2\nMedia Error Count: {media_errors}\nOther Error Count: 3\nPredictive Failure Count: {predictive}\nLast Predictive Failure Event Seq Number: 0\nPD Type: SAS\n\nRaw Size: 279.396 GB [0x22ecb25c Sectors]\nNon Coerced Size: 278.896 GB [0x22dcb25c Sectors]\nCoerced Size: 278.875 GB [0x22dc0000 Sectors]\nSector Size:  0\nFirmware state: {state}\nDevice Firmware Level: LS08\nShield Counter: 0\nSuccessful diagnostics completion on :  N/A\nSAS Address(0): 0x5000c5007f1b0a3d\nSAS Address(1): 0x0\nConnected Port Number: 0(path0) \nInquiry Data: SEAGATE ST300MM0006     LS08S0K2B5NV            \nFDE Capable: Not Capable\nFDE Enable: Disable\nSecured: Unsecured\nLocked: Unlocked\nNeeds EKM Attention: No\nForeign State: None \nDevice Speed: 6.0Gb/s \nLink Speed: 6.0Gb/s \nMedia Type: Hard Disk Device\nDrive Temperature :30C (86.00 F)\nPI Eligibility:  No \nDrive is formatted for PI information:  No\nPI: No PI\nPort-0 :\nPort status: Active\nPort's Linkspeed: 6.0Gb/s \nPort-1 :\nPort status: Active\nPort's Linkspeed: Unknown \nDrive has flagged a S.M.A.R.T alert : {alert}\n\n\n\n"
        )
    }

    fn pd_list(drives: &[String]) -> String {
        format!("\nAdapter #0\n\n{}\nExit Code: 0x00\n", drives.concat())
    }

    fn troubled_physical_drives() -> String {
        pd_list(&[
            physical_drive(0, "Online, Spun Up", 0, 0, "No"),
            physical_drive(1, "Online, Spun Up", 0, 0, "No"),
            physical_drive(2, "Rebuild", 0, 0, "No"),
            physical_drive(3, "Online, Spun Up", 14, 2, "Yes"),
            physical_drive(4, "Failed", 0, 0, "No"),
            physical_drive(5, "Hotspare, Spun down", 0, 0, "No"),
        ])
    }

    fn healthy_physical_drives() -> String {
        pd_list(&[
            physical_drive(0, "Online, Spun Up", 0, 0, "No"),
            physical_drive(1, "Online, Spun Up", 0, 0, "No"),
            physical_drive(2, "Unconfigured(good), Spun Up", 0, 0, "No"),
            physical_drive(3, "Hotspare, Spun down", 0, 0, "No"),
            physical_drive(4, "JBOD", 0, 0, "No"),
        ])
    }

    fn battery(state: &str, charge: u32, replace: &str) -> String {
        format!(
            "\nBBU status for Adapter: 0\n\nBatteryType: BBU\nVoltage: 4073 mV\nCurrent: 0 mA\nTemperature: 28 C\nBattery State: {state}\nBBU Firmware Status:\n\n  Charging Status              : None\n  Voltage                                 : OK\n  Temperature                             : OK\n  Learn Cycle Requested                   : No\n  Learn Cycle Active                      : No\n  Learn Cycle Status                      : OK\n  Learn Cycle Timeout                     : No\n  I2c Errors Detected                     : No\n  Battery Pack Missing                    : No\n  Battery Replacement required            : {replace}\n  Remaining Capacity Low                  : No\n  Periodic Learn Required                 : No\n  Transparent Learn                       : No\n  No space to cache offload               : No\n  Pack is about to fail & should be replaced : No\n  Cache Offload premium feature required  : No\n  Module microcode update required        : No\n\nBBU GasGauge Status: 0x0128 \n  Fully Charged        : Yes\nRelative State of Charge: {charge} %\nCharger System State: 49168\nCharger System Ctrl: 0\nCharging current: 0 mA\nAbsolute state of charge: {charge} %\nMax Error: 2 %\n\nExit Code: 0x00\n"
        )
    }

    const NO_BATTERY: &str = "\nAdapter 0: Get BBU Status Failed.\n\nFW error description: \n  The required hardware component is not present.  \n\nExit Code: 0x22\n";

    /// Shell (builtins only) that prints `text`.
    fn say(text: &str) -> String {
        text.lines()
            .map(|line| format!("printf '%s\\n' '{}'\n", line.replace('\'', "'\\''")))
            .collect()
    }

    /// A stand-in for MegaCli, under the name `program`, that prints these reports. The
    /// battery report ends with `battery_exit`, as MegaCli's does when there is none.
    fn fake_megacli(
        program: &str,
        virtual_drives: &str,
        physical_drives: &str,
        battery: &str,
        battery_exit: i32,
    ) -> FakeBins {
        let script = format!(
            "case \"$1\" in\n\
             -AdpAllInfo)\n{}\n;;\n\
             -LDInfo)\n{}\n;;\n\
             -PDList)\n{}\n;;\n\
             -AdpBbuCmd)\n{}\nexit {battery_exit} ;;\n\
             esac\n",
            say(ADAPTER_INFO),
            say(virtual_drives),
            say(physical_drives),
            say(battery),
        );
        FakeBins::new().add_script(program, &script)
    }

    fn troubled() -> FakeBins {
        fake_megacli(
            "megacli",
            &troubled_virtual_drives(),
            &troubled_physical_drives(),
            &battery("Failed", 12, "Yes"),
            0,
        )
    }

    fn healthy() -> FakeBins {
        fake_megacli(
            "megacli",
            &healthy_virtual_drives(),
            &healthy_physical_drives(),
            &battery("Optimal", 99, "No"),
            0,
        )
    }

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

    async fn status(host: &Arc<Host>, user: &str, arguments: Value) -> ToolResult {
        call(host, user, &find(tools(), "megaraid_status"), arguments).await
    }

    /// `text` with every run of spaces made one, so that a table row can be compared
    /// without counting its padding.
    fn squash(text: &str) -> String {
        text.lines()
            .map(|line| {
                line.split(' ')
                    .filter(|w| !w.is_empty())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[tokio::test]
    async fn the_summary_leads_with_what_is_wrong() {
        let fake = troubled();
        let (host, _audit) = fixture(&fake);
        let text = ok_text(status(&host, "vera", json!({})).await);
        assert_eq!(
            squash(&text),
            "PROBLEM: virtual drive 1 (data) is Degraded; drive 32:3 predicts its own failure \
             (2 predictive failures, SMART alert); drive 32:4 is Failed; the battery is \
             Failed and needs replacing. Warnings: virtual drive 1 (data) is running \
             WriteThrough where WriteBack is configured (usually the battery); drive 32:2 \
             is Rebuild; drive 32:3 has 14 media errors.\n\
             \n\
             Controller 0: PERC H710 Mini, firmware 21.3.0-0009, serial 3A1234\n\
             Battery: Failed, 12 % charged, replacement required\n\
             \n\
             == Virtual drives ==\n\
             CTRL VD NAME RAID SIZE STATE DRIVES CACHE IN PROGRESS\n\
             0 0 system RAID 1 278.875 GB Optimal 2 WriteBack, ReadAheadNone, Direct, No Write Cache if Bad BBU Check Consistency: Completed 37%, Taken 12 min.\n\
             0 1 data RAID 10 278.875 GB Degraded 4 WriteThrough, ReadAheadNone, Direct, No Write Cache if Bad BBU -\n\
             \n\
             == Physical drives ==\n\
             CTRL ENCL:SLOT STATE SIZE TYPE MODEL MEDIA-ERR OTHER-ERR PRED-FAIL SMART TEMP\n\
             0 32:0 Online, Spun Up 278.875 GB SAS HDD SEAGATE ST300MM0006 LS08S0K2B5NV 0 3 0 no 30C\n\
             0 32:1 Online, Spun Up 278.875 GB SAS HDD SEAGATE ST300MM0006 LS08S0K2B5NV 0 3 0 no 30C\n\
             0 32:2 Rebuild 278.875 GB SAS HDD SEAGATE ST300MM0006 LS08S0K2B5NV 0 3 0 no 30C\n\
             0 32:3 Online, Spun Up 278.875 GB SAS HDD SEAGATE ST300MM0006 LS08S0K2B5NV 14 3 2 ALERT 30C\n\
             0 32:4 Failed 278.875 GB SAS HDD SEAGATE ST300MM0006 LS08S0K2B5NV 0 3 0 no 30C\n\
             0 32:5 Hotspare, Spun down 278.875 GB SAS HDD SEAGATE ST300MM0006 LS08S0K2B5NV 0 3 0 no 30C"
        );
        assert_eq!(
            fake.calls("megacli"),
            [
                strings(&["-AdpAllInfo", "-aALL", "-NoLog"]),
                strings(&["-LDInfo", "-Lall", "-aALL", "-NoLog"]),
                strings(&["-PDList", "-aALL", "-NoLog"]),
                strings(&["-AdpBbuCmd", "-GetBbuStatus", "-aALL", "-NoLog"]),
            ]
        );
    }

    #[tokio::test]
    async fn a_healthy_controller_gets_a_line_saying_what_was_looked_at() {
        let fake = healthy();
        let (host, _audit) = fixture(&fake);
        let text = ok_text(status(&host, "vera", json!({"view": "summary"})).await);
        assert_eq!(
            text.lines().next().unwrap(),
            "No MegaRAID problems are visible (1 controller, 2 virtual drives, 5 drives)."
        );
        assert!(text.contains("Battery: Optimal, 99 % charged\n"), "{text}");
        assert!(!text.contains("PROBLEM"), "{text}");
        assert!(!text.contains("Warnings"), "{text}");
        // a spare, an unused drive and a pass-through drive are not faults
    }

    #[tokio::test]
    async fn a_controller_without_a_battery_is_not_a_problem() {
        // MegaCli fails that one report with exit status 0x22
        let fake = fake_megacli(
            "megacli",
            &healthy_virtual_drives(),
            &healthy_physical_drives(),
            NO_BATTERY,
            34,
        );
        let (host, _audit) = fixture(&fake);
        let text = ok_text(status(&host, "vera", json!({})).await);
        assert!(
            text.starts_with("No MegaRAID problems are visible"),
            "{text}"
        );
        assert!(text.contains("Battery: none reported\n"), "{text}");
    }

    #[test]
    fn raid_levels_are_named_from_the_level_and_the_span_depth() {
        let level = |primary: u32, secondary: u32| {
            format!("Primary-{primary}, Secondary-{secondary}, RAID Level Qualifier-0")
        };
        let spans = |per_span: u32, depth: u32| {
            format!("Number Of Drives per span:{per_span}\nSpan Depth          : {depth}")
        };
        let drives = |count: u32| format!("Number Of Drives    : {count}\nSpan Depth          : 1");
        let cases = [
            (level(0, 0), drives(2), "RAID 0", "2"),
            (level(1, 0), drives(2), "RAID 1", "2"),
            (level(5, 0), drives(5), "RAID 5", "5"),
            (level(6, 0), drives(8), "RAID 6", "8"),
            (level(1, 0), spans(2, 3), "RAID 10", "6"),
            (level(5, 0), spans(4, 2), "RAID 50", "8"),
            (level(6, 0), spans(6, 2), "RAID 60", "12"),
            // older firmware marks a RAID 10 with Secondary-3 and one span
            (level(1, 3), drives(4), "RAID 10", "4"),
        ];
        for (level, drives, raid, count) in cases {
            let text = ld_info(&[virtual_drive(
                0,
                "",
                &level,
                &drives,
                "Optimal",
                "WriteBack",
                "",
            )]);
            let parsed = parse_virtual_drives(&text);
            assert_eq!(parsed.len(), 1, "{text}");
            assert_eq!(
                (parsed[0].raid.as_str(), parsed[0].drives.as_str()),
                (raid, count)
            );
        }
        // a level in a form not seen before is shown as MegaCli printed it
        let text = ld_info(&[virtual_drive(
            0,
            "",
            "RAID-1E",
            TWO_DRIVES,
            "Optimal",
            "WriteBack",
            "",
        )]);
        assert_eq!(parse_virtual_drives(&text)[0].raid, "RAID-1E");
    }

    #[test]
    fn parse_virtual_drives_reads_every_drive_of_every_controller() {
        let text = format!(
            "{}\n\nAdapter 1 -- Virtual Drive Information:\n{}\nExit Code: 0x00\n",
            troubled_virtual_drives(),
            virtual_drive(0, "scratch", MIRROR, TWO_DRIVES, "Offline", "WriteBack", "")
        );
        let drives = parse_virtual_drives(&text);
        assert_eq!(drives.len(), 3);
        assert_eq!(
            drives[0],
            VirtualDrive {
                controller: 0,
                number: "0".to_string(),
                name: "system".to_string(),
                raid: "RAID 1".to_string(),
                size: "278.875 GB".to_string(),
                state: "Optimal".to_string(),
                drives: "2".to_string(),
                cache: "WriteBack, ReadAheadNone, Direct, No Write Cache if Bad BBU".to_string(),
                configured_cache: "WriteBack, ReadAheadNone, Direct, No Write Cache if Bad BBU"
                    .to_string(),
                in_progress: vec!["Check Consistency: Completed 37%, Taken 12 min.".to_string()],
            }
        );
        assert_eq!(
            (drives[2].controller, drives[2].name.as_str()),
            (1, "scratch")
        );
        assert!(parse_virtual_drives("\nExit Code: 0x00\n").is_empty());
    }

    #[test]
    fn parse_physical_drives_reads_what_the_table_shows() {
        let drives = parse_physical_drives(&troubled_physical_drives());
        assert_eq!(drives.len(), 6);
        assert_eq!(
            drives[3],
            PhysicalDrive {
                controller: 0,
                enclosure: "32".to_string(),
                slot: "3".to_string(),
                state: "Online, Spun Up".to_string(),
                size: "278.875 GB".to_string(),
                kind: "SAS HDD".to_string(),
                model: "SEAGATE ST300MM0006 LS08S0K2B5NV".to_string(),
                media_errors: 14,
                other_errors: 3,
                predictive_failures: 2,
                smart_alert: true,
                temperature: "30C".to_string(),
                foreign: false,
            }
        );
        // a drive wired to the controller directly has no enclosure; an SSD says so
        let direct = physical_drive(7, "Online, Spun Up", 0, 0, "No")
            .replace("Enclosure Device ID: 32", "Enclosure Device ID: N/A")
            .replace("PD Type: SAS", "PD Type: SATA")
            .replace("Hard Disk Device", "Solid State Device");
        let drives = parse_physical_drives(&pd_list(&[direct]));
        assert_eq!(
            (drives[0].enclosure.as_str(), drives[0].kind.as_str()),
            ("N/A", "SATA SSD")
        );
    }

    #[test]
    fn findings_on_a_second_controller_say_which_one() {
        let read = Readings {
            controllers: vec![
                Controller {
                    number: 0,
                    product: "PERC H710".to_string(),
                    ..Controller::default()
                },
                Controller {
                    number: 1,
                    product: "PERC H810".to_string(),
                    memory_uncorrectable: 2,
                    memory_correctable: 5,
                    ..Controller::default()
                },
            ],
            virtual_drives: vec![VirtualDrive {
                controller: 1,
                number: "0".to_string(),
                state: "Offline".to_string(),
                raid: "RAID 5".to_string(),
                ..VirtualDrive::default()
            }],
            physical_drives: vec![PhysicalDrive {
                controller: 1,
                enclosure: "N/A".to_string(),
                slot: "4".to_string(),
                state: "Unconfigured(bad)".to_string(),
                ..PhysicalDrive::default()
            }],
            batteries: vec![],
            unread: vec![],
        };
        let text = summary_text(&read);
        assert_eq!(
            text.lines().next().unwrap(),
            "PROBLEM: virtual drive 0 on controller 1 is Offline; drive N/A:4 on controller 1 \
             is Unconfigured(bad); controller 1 has 2 uncorrectable memory errors. Warnings: \
             controller 1 has 5 corrected memory errors."
        );
        assert!(text.contains("Controller 1: PERC H810\n"), "{text}");
    }

    #[tokio::test]
    async fn the_other_views_pass_megaclis_own_report_on_for_all_controllers_or_one() {
        let fake = troubled();
        let (host, _audit) = fixture(&fake);
        let text = ok_text(status(&host, "vera", json!({"view": "virtual_drives"})).await);
        assert!(
            text.contains("Adapter 0 -- Virtual Drive Information:\n"),
            "{text}"
        );
        assert!(
            text.contains("Disk Cache Policy   : Disk's Default\n"),
            "{text}"
        );
        let text = ok_text(status(&host, "vera", json!({"view": "drives", "controller": 1})).await);
        assert!(
            text.contains("Inquiry Data: SEAGATE ST300MM0006     LS08S0K2B5NV"),
            "{text}"
        );
        ok_text(status(&host, "vera", json!({"view": "controller"})).await);
        ok_text(status(&host, "vera", json!({"view": "battery", "controller": 0})).await);
        assert_eq!(
            fake.calls("megacli"),
            [
                strings(&["-LDInfo", "-Lall", "-aALL", "-NoLog"]),
                strings(&["-PDList", "-a1", "-NoLog"]),
                strings(&["-AdpAllInfo", "-aALL", "-NoLog"]),
                strings(&["-AdpBbuCmd", "-GetBbuStatus", "-a0", "-NoLog"]),
            ]
        );
    }

    #[tokio::test]
    async fn a_report_megacli_fails_to_give_is_a_failure_with_what_it_said() {
        let fake = fake_megacli("megacli", "", "", NO_BATTERY, 34);
        let (host, _audit) = fixture(&fake);
        let output = status(&host, "vera", json!({"view": "battery"}))
            .await
            .unwrap();
        assert!(output.is_error());
        assert!(
            output.text().contains("Get BBU Status Failed"),
            "{output:?}"
        );
    }

    #[tokio::test]
    async fn megacli_is_found_under_the_vendors_names_too() {
        for program in ["MegaCli64", "MegaCli"] {
            let fake = fake_megacli(
                program,
                &healthy_virtual_drives(),
                &healthy_physical_drives(),
                &battery("Optimal", 99, "No"),
                0,
            );
            let (host, _audit) = fixture(&fake);
            let text = ok_text(status(&host, "vera", json!({})).await);
            assert!(
                text.starts_with("No MegaRAID problems are visible"),
                "{text}"
            );
            assert_eq!(fake.calls(program).len(), 4);
        }
    }

    #[tokio::test]
    async fn a_host_without_megacli_says_how_to_point_at_it() {
        let fake = FakeBins::new().add("lsblk", "", 0);
        let (host, _audit) = fixture(&fake);
        let output = status(&host, "vera", json!({})).await.unwrap();
        assert!(output.is_error());
        let text = output.text();
        assert!(text.contains("MegaCli is not installed"), "{text}");
        assert!(
            text.contains("[paths.bin]") && text.contains("/opt/MegaRAID/MegaCli/MegaCli64"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn a_host_with_megacli_and_no_controller_says_so() {
        let script = "printf '%s\\n' '' 'Exit Code: 0x00'\n";
        let fake = FakeBins::new().add_script("megacli", script);
        let (host, _audit) = fixture(&fake);
        let text = ok_text(status(&host, "vera", json!({})).await);
        assert_eq!(text, "MegaCli found no MegaRAID controller on this host.\n");
    }

    #[tokio::test]
    async fn a_caller_without_the_permission_is_refused_and_nothing_runs() {
        let fake = troubled();
        let (host, audit) = fixture(&fake);
        let result = status(&host, "otto", json!({})).await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        assert!(fake.calls("megacli").is_empty());
        assert_eq!(audit.records()[0]["decision"], "deny");
    }

    #[test]
    fn a_battery_is_read_in_the_older_and_the_newer_wording() {
        let batteries = parse_batteries(&battery("Optimal", 99, "No"));
        assert_eq!(
            batteries,
            [Battery {
                controller: 0,
                state: "Optimal".to_string(),
                charge: "99 %".to_string(),
                replace: false,
            }]
        );
        // older firmware: padded keys, "Operational", and its health as a yes or no
        let older = "BBU status for Adapter: 1\n\nBatteryType: iBBU\nBattery State     : Operational\n  isSOHGood: No\nRelative State of Charge: 41 %\n\nExit Code: 0x00\n";
        let batteries = parse_batteries(older);
        assert_eq!(
            batteries,
            [Battery {
                controller: 1,
                state: "Operational".to_string(),
                charge: "41 %".to_string(),
                replace: true,
            }]
        );
        // a controller that has none answers with a failure, not with a battery
        assert!(parse_batteries(NO_BATTERY).is_empty());
    }

    /// A stand-in for MegaCli that prints `text` and exits with `code` for each report.
    fn fake_reports(reports: [(&str, &str, i32); 4]) -> FakeBins {
        let mut script = "case \"$1\" in\n".to_string();
        for (flag, text, code) in reports {
            script.push_str(&format!("{flag})\n{}\nexit {code} ;;\n", say(text)));
        }
        script.push_str("esac\n");
        FakeBins::new().add_script("megacli", &script)
    }

    #[tokio::test]
    async fn a_summary_made_from_a_report_that_failed_says_so_first_and_never_says_healthy() {
        // MegaCli prints one drive and then fails: what was read looks fine, and is not all
        let half = pd_list(&[physical_drive(0, "Online, Spun Up", 0, 0, "No")]);
        let fake = fake_reports([
            ("-AdpAllInfo", ADAPTER_INFO, 0),
            ("-LDInfo", &healthy_virtual_drives(), 0),
            ("-PDList", &half, 1),
            ("-AdpBbuCmd", &battery("Optimal", 99, "No"), 0),
        ]);
        let (host, _audit) = fixture(&fake);
        let text = ok_text(status(&host, "vera", json!({})).await);
        assert_eq!(
            text.lines().next().unwrap(),
            "INCOMPLETE: MegaCli's report on the drives failed or was cut short, so parts \
             may be missing here (view=drives shows what it said). Nothing that was read \
             reports a problem."
        );
        assert!(!text.contains("No MegaRAID problems"), "{text}");
    }

    #[tokio::test]
    async fn a_battery_report_that_fails_for_another_reason_is_not_taken_for_no_battery() {
        let failed = "\nAdapter 0: Get BBU Status Failed.\n\nFW error description: \n  The requested command has invalid arguments.  \n\nExit Code: 0x03\n";
        let fake = fake_reports([
            ("-AdpAllInfo", ADAPTER_INFO, 0),
            ("-LDInfo", &healthy_virtual_drives(), 0),
            ("-PDList", &healthy_physical_drives(), 0),
            ("-AdpBbuCmd", failed, 3),
        ]);
        let (host, _audit) = fixture(&fake);
        let text = ok_text(status(&host, "vera", json!({})).await);
        assert!(
            text.starts_with("INCOMPLETE: MegaCli's report on the battery failed or was cut short"),
            "{text}"
        );
        assert!(text.contains("Battery: could not be read\n"), "{text}");
        assert!(!text.contains("none reported"), "{text}");
    }

    #[tokio::test]
    async fn a_controller_with_no_virtual_drive_is_a_full_answer_whatever_megacli_exits_with() {
        let none = "\n\nAdapter 0: No Virtual Drive Configured.\n\nExit Code: 0x01\n";
        let fake = fake_reports([
            ("-AdpAllInfo", ADAPTER_INFO, 0),
            ("-LDInfo", none, 1),
            ("-PDList", &healthy_physical_drives(), 0),
            ("-AdpBbuCmd", &battery("Optimal", 99, "No"), 0),
        ]);
        let (host, _audit) = fixture(&fake);
        let text = ok_text(status(&host, "vera", json!({})).await);
        assert_eq!(
            text.lines().next().unwrap(),
            "No MegaRAID problems are visible (1 controller, 0 virtual drives, 5 drives)."
        );
        assert!(text.contains("== Virtual drives ==\n(none)\n"), "{text}");
    }

    #[test]
    fn a_drive_being_rebuilt_or_copied_back_is_a_warning_and_so_is_a_foreign_one() {
        let drive = |slot: &str, state: &str, foreign: bool| PhysicalDrive {
            enclosure: "32".to_string(),
            slot: slot.to_string(),
            state: state.to_string(),
            foreign,
            ..PhysicalDrive::default()
        };
        let read = Readings {
            physical_drives: vec![
                drive("0", "Rebuild", false),
                drive("1", "Copyback", false),
                drive("2", "Unconfigured(good), Spun Up", true),
                drive("3", "Online, Spun Up", false),
            ],
            ..Readings::default()
        };
        assert_eq!(
            summary_text(&read).lines().next().unwrap(),
            "Warnings: drive 32:0 is Rebuild; drive 32:1 is Copyback; drive 32:2 has a \
             foreign configuration."
        );
        // which MegaCli says in the drive's own lines
        let foreign = physical_drive(2, "Unconfigured(good), Spun Up", 0, 0, "No")
            .replace("Foreign State: None", "Foreign State: Foreign");
        assert!(parse_physical_drives(&pd_list(&[foreign]))[0].foreign);
        assert!(!parse_physical_drives(&healthy_physical_drives())[0].foreign);
    }

    // The four reports below are what MegaCli 8.07.14 printed for a real PERC H730P, line
    // for line (each begins with a carriage return and a line of spaces), with the
    // serial numbers and addresses made up and all but two of its 24 drives left out.
    const REAL_CONTROLLER: &str = "\r                                     \nAdapter #0\n\n==============================================================================\n                    Versions\n                ================\nProduct Name    : PERC H730P Adapter\nSerial No       : 00TEST00\nFW Package Build: 25.5.9.0001\n\n                    Mfg. Data\n                ================\nMfg. Date       : 01/01/19\nRework Date     : 01/01/19\n\n                    Hardware\n                ================\nBBU              : Present\n\n                    Settings\n                ================\nAny Offline VD Cache Preserved   : No\nBIOS Error Handling          \t : Pause on Errors\n\n                    Device Present\n                ================\nVirtual Drives    : 1 \n  Degraded        : 0 \n  Offline         : 0 \nPhysical Devices  : 25 \n  Disks           : 24 \n  Critical Disks  : 0 \n  Failed Disks    : 0 \n\n                    Supported Adapter Operations\n                ================\nBBU                             : Yes\nForce Offline                           : Yes\nEnable Copyback to SSD on SMART Error   : No\n\n                    Error Counters\n                ================\nMemory Correctable Errors   : 0 \nMemory Uncorrectable Errors : 0 \n\nExit Code: 0x00\n";
    const REAL_VIRTUAL_DRIVES: &str = "\r                                     \n\nAdapter 0 -- Virtual Drive Information:\nVirtual Drive: 0 (Target Id: 0)\nName                :\nRAID Level          : Primary-6, Secondary-0, RAID Level Qualifier-3\nSize                : 34.918 TB\nSector Size         : 512\nIs VD emulated      : Yes\nParity Size         : 6.983 TB\nState               : Optimal\nStrip Size          : 64 KB\nNumber Of Drives per span:12\nSpan Depth          : 2\nDefault Cache Policy: WriteBack, ReadAhead, Direct, No Write Cache if Bad BBU\nCurrent Cache Policy: WriteBack, ReadAhead, Direct, No Write Cache if Bad BBU\nDefault Access Policy: Read/Write\nCurrent Access Policy: Read/Write\nDisk Cache Policy   : Disk's Default\nEncryption Type     : None\nDefault Power Savings Policy: Controller Defined\nCurrent Power Savings Policy: None\nCan spin up in 1 minute: No\nLD has drives that support T10 power conditions: No\nLD's IO profile supports MAX power savings with cached writes: No\nBad Blocks Exist: No\nIs VD Cached: No\n\n\n\nExit Code: 0x00\n";
    const REAL_DRIVE: &str = "Enclosure Device ID: 32\nSlot Number: SLOT\nDrive's position: DiskGroup: 0, Span: 0, Arm: SLOT\nEnclosure position: 1\nDevice Id: SLOT\nWWN: 58CE38EE00000000\nSequence Number: 2\nMedia Error Count: 0\nOther Error Count: 0\nPredictive Failure Count: 0\nLast Predictive Failure Event Seq Number: 0\nPD Type: SAS\n\nRaw Size: 1.746 TB [0xdf8fe2b0 Sectors]\nNon Coerced Size: 1.745 TB [0xdf7fe2b0 Sectors]\nCoerced Size: 1.745 TB [0xdf7c0000 Sectors]\nSector Size:  512\nLogical Sector Size:  512\nPhysical Sector Size:  4096\nFirmware state: Online, Spun Up\nDevice Firmware Level: B02A\nShield Counter: 0\nSuccessful diagnostics completion on :  N/A\nSAS Address(0): 0x58ce38ee00000001\nSAS Address(1): 0x58ce38ee00000002\nConnected Port Number: 0(path0) \nInquiry Data: TOSHIBA KPM5XRUG1T92    B02A0000A0XXTEST        \nFDE Capable: Not Capable\nFDE Enable: Disable\nSecured: Unsecured\nLocked: Unlocked\nNeeds EKM Attention: No\nForeign State: None \nDevice Speed: 12.0Gb/s \nLink Speed: 12.0Gb/s \nMedia Type: Solid State Device\nDrive Temperature :40C (104.00 F)\nPI Eligibility:  No \nDrive is formatted for PI information:  No\nPI: No PI\nPort-0 :\nPort status: Active\nPort's Linkspeed: 12.0Gb/s \nPort-1 :\nPort status: Active\nPort's Linkspeed: 12.0Gb/s \nDrive has flagged a S.M.A.R.T alert : No\n\n\n\n";
    const REAL_BATTERY: &str = "\r                                     \nBBU status for Adapter: 0\n\nBatteryType: BBU\nVoltage: 3916 mV\nCurrent: 0 mA\nTemperature: 47 C\nBattery State: Optimal\nBBU Firmware Status:\n\n  Charging Status              : None\n  Voltage                                 : OK\n  Temperature                             : OK\n  Learn Cycle Requested\t                  : No\n  Learn Cycle Active                      : No\n  Learn Cycle Status                      : OK\n  Learn Cycle Timeout                     : No\n  I2c Errors Detected                     : No\n  Battery Pack Missing                    : No\n  Battery Replacement required            : No\n  Remaining Capacity Low                  : No\n  Periodic Learn Required                 : No\n  Transparent Learn                       : No\n  No space to cache offload               : No\n  Pack is about to fail & should be replaced : No\n  Cache Offload premium feature required  : No\n  Module microcode update required        : No\n\nBBU GasGauge Status: 0x0038 \nRelative State of Charge: 96 %\nCharger Status: Complete\nRemaining Capacity: 354 mAh\nFull Charge Capacity: 370 mAh\nisSOHGood: Yes\n\nExit Code: 0x00\n";

    #[test]
    fn a_real_controllers_reports_are_read_as_megacli_printed_them() {
        let drives = format!(
            "\r                                     \nAdapter #0\n\n{}{}\nExit Code: 0x00\n",
            REAL_DRIVE.replace("SLOT", "0"),
            REAL_DRIVE.replace("SLOT", "1")
        );
        let read = Readings {
            controllers: parse_controllers(REAL_CONTROLLER),
            virtual_drives: parse_virtual_drives(REAL_VIRTUAL_DRIVES),
            physical_drives: parse_physical_drives(&drives),
            batteries: parse_batteries(REAL_BATTERY),
            unread: vec![],
        };
        assert_eq!(
            squash(&summary_text(&read)),
            "No MegaRAID problems are visible (1 controller, 1 virtual drive, 2 drives).\n\
             \n\
             Controller 0: PERC H730P Adapter, firmware 25.5.9.0001, serial 00TEST00\n\
             Battery: Optimal, 96 % charged\n\
             \n\
             == Virtual drives ==\n\
             CTRL VD NAME RAID SIZE STATE DRIVES CACHE IN PROGRESS\n\
             0 0 - RAID 60 34.918 TB Optimal 24 WriteBack, ReadAhead, Direct, No Write Cache if Bad BBU -\n\
             \n\
             == Physical drives ==\n\
             CTRL ENCL:SLOT STATE SIZE TYPE MODEL MEDIA-ERR OTHER-ERR PRED-FAIL SMART TEMP\n\
             0 32:0 Online, Spun Up 1.745 TB SAS SSD TOSHIBA KPM5XRUG1T92 B02A0000A0XXTEST 0 0 0 no 40C\n\
             0 32:1 Online, Spun Up 1.745 TB SAS SSD TOSHIBA KPM5XRUG1T92 B02A0000A0XXTEST 0 0 0 no 40C"
        );
    }

    #[test]
    fn megacli_is_never_given_a_log_file_to_write() {
        for report in [
            &CONTROLLER_INFO[..],
            &VIRTUAL_DRIVES[..],
            &PHYSICAL_DRIVES[..],
            &BATTERY[..],
        ] {
            for controller in [None, Some(0), Some(31)] {
                let argv = megacli_argv(report, controller);
                assert_eq!(argv.last().map(String::as_str), Some("-NoLog"), "{argv:?}");
            }
        }
        assert_eq!(
            megacli_argv(&PHYSICAL_DRIVES, Some(3)),
            strings(&["-PDList", "-a3", "-NoLog"])
        );
    }
}
