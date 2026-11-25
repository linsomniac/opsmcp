//! Hardware health and inventory: sensors, memory errors, power, IPMI, SMBIOS/DMI.

use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::args::{Args, Param};
use super::{
    CallClock, Ctx, Tool, ToolError, ToolResult, blocking, command_ok, command_text, format_table,
    one_line_cell,
};
use crate::exec::CmdOutput;
use crate::policy::Access;
use crate::sanitize::keep_head;

/// Where the kernel's files are. Tests point these at a temporary directory.
#[derive(Clone, Debug)]
pub struct Roots {
    /// `/sys`
    pub sys: PathBuf,
    /// `/dev`
    pub dev: PathBuf,
}

impl Default for Roots {
    fn default() -> Self {
        Roots {
            sys: PathBuf::from("/sys"),
            dev: PathBuf::from("/dev"),
        }
    }
}

const DMI_SECTIONS: [&str; 11] = [
    "summary",
    "bios",
    "system",
    "baseboard",
    "chassis",
    "processor",
    "memory",
    "cache",
    "connector",
    "slot",
    "all",
];

pub fn tools() -> Vec<Tool> {
    tools_with(Roots::default())
}

pub fn tools_with(roots: Roots) -> Vec<Tool> {
    let roots = Arc::new(roots);
    let info_roots = roots.clone();
    vec![
        Tool::new(
            "hardware_health",
            "Check this machine's hardware: temperatures and fans, corrected and uncorrected \
             memory errors (EDAC), power supplies and batteries, CPU thermal throttling, \
             hardware errors in the kernel log, and, where the machine has a management \
             controller, the IPMI sensors that are not ok and its recent event log. The first \
             line is the verdict. Use it when a host crashes or slows down for no visible \
             reason. A virtual machine usually has nothing to show. For hardware inventory \
             (BIOS, CPUs, memory slots) use hardware_info; for drives use disk_health.",
            Access::Read,
            "hardware.view",
            vec![],
            move |ctx, args| {
                let roots = roots.clone();
                async move { hardware_health(ctx, args, roots).await }
            },
        ),
        Tool::new(
            "hardware_info",
            "Show this machine's hardware inventory from SMBIOS/DMI (dmidecode): system \
             vendor, model, serial number and UUID, BIOS/UEFI firmware, baseboard, chassis, \
             processor sockets, and memory array and DIMM slots. By default returns a \
             concise summary; pass `section` to inspect one SMBIOS section in full (bios, \
             system, baseboard, chassis, processor, memory, cache, connector, slot) or all. \
             Falls back to /sys/class/dmi/id when dmidecode is not installed or cannot read \
             the SMBIOS tables. Virtual machines and containers may report minimal or no \
             SMBIOS data. For sensors, memory errors and IPMI use hardware_health; for \
             drives use block_devices or disk_health.",
            Access::Read,
            "hardware.view",
            vec![Param::choice(
                "section",
                "Which SMBIOS section to show: summary (default: structured overview of \
                 system, BIOS, baseboard, chassis, processors and memory), or one of bios, \
                 system, baseboard, chassis, processor, memory, cache, connector, slot, all",
                &DMI_SECTIONS,
            )],
            move |ctx, args| {
                let roots = info_roots.clone();
                async move { hardware_info(ctx, args, roots).await }
            },
        ),
    ]
}

/// The most that is read of any one of the kernel's small files.
const SMALL_FILE: u64 = 4096;
/// The most entries looked at in any one directory.
const MAX_ENTRIES: usize = 4096;
/// The most sensor chips, and sensors in all, that are reported.
const MAX_CHIPS: usize = 64;
const MAX_SENSORS: usize = 256;
/// The most kernel-log lines counted, and shown.
const LOG_LINES: usize = 100;
const LOG_SHOWN: usize = 5;
/// The most IPMI rows shown in each list.
const IPMI_ROWS: usize = 40;

/// At most `max` bytes of a file as text, without the white space around it. `None` if
/// it cannot be read.
fn read_trimmed(path: &Path, max: u64) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let mut data = Vec::new();
    file.take(max).read_to_end(&mut data).ok()?;
    Some(String::from_utf8_lossy(&data).trim().to_string())
}

fn read_number<T: std::str::FromStr>(path: &Path) -> Option<T> {
    read_trimmed(path, 64)?.parse().ok()
}

/// The names in a directory, sorted, at most `MAX_ENTRIES` of them. `None` if it cannot
/// be listed.
fn names_in(dir: &Path) -> Option<Vec<String>> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .take(MAX_ENTRIES)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    Some(names)
}

/// The number in a name such as `hwmon3`, `cpu12` or `mc0`, when the name is exactly
/// `prefix` followed by digits.
fn numbered(name: &str, prefix: &str) -> Option<u32> {
    let digits = name.strip_prefix(prefix)?;
    (!digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()))
        .then(|| digits.parse().ok())
        .flatten()
}

/// The entries of `dir` named `prefix` + a number, in numeric order.
fn numbered_in(dir: &Path, prefix: &str) -> Vec<String> {
    let mut found: Vec<(u32, String)> = names_in(dir)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|name| Some((numbered(&name, prefix)?, name)))
        .collect();
    found.sort();
    found.into_iter().map(|(_, name)| name).collect()
}

/// Host text on one line of ours, cut to `max` characters.
///
/// AIDEV-NOTE: sensor labels, DMI strings and IPMI rows come from firmware and devices.
/// Everything shown passes through here, so none of it can start a line that looks like
/// the tool's own (a made-up verdict, say).
fn shown(text: &str, max: usize) -> String {
    let line = one_line_cell(text.trim());
    if line.chars().count() <= max {
        return line;
    }
    let mut kept: String = line.chars().take(max).collect();
    kept.push_str("...");
    kept
}

/// `1 thing` or `3 things`.
fn count(n: u64, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

/// A temperature limit a sensor reports, if it is one that means something. Drivers
/// report 0 or less, or a placeholder far beyond anything real (an NVMe drive without a
/// per-sensor limit says 65261.85 C), where no limit is set.
fn real_limit(limit: Option<i64>) -> Option<i64> {
    limit.filter(|limit| *limit > 0 && *limit < 250_000)
}

/// How a temperature compares with the limits its sensor reports (all in thousandths of
/// a degree). Limits that are not set are ignored.
pub fn temperature_status(value: i64, max: Option<i64>, critical: Option<i64>) -> &'static str {
    if real_limit(critical).is_some_and(|critical| value >= critical) {
        "CRITICAL"
    } else if real_limit(max).is_some_and(|max| value >= max) {
        "HIGH"
    } else {
        "ok"
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SensorKind {
    Temperature,
    Fan,
}

/// One reading from `/sys/class/hwmon`.
struct Sensor {
    chip: String,
    label: String,
    kind: SensorKind,
    /// Thousandths of a degree Celsius, or revolutions per minute.
    value: i64,
    max: Option<i64>,
    critical: Option<i64>,
    /// The driver names this sensor: it is wired to something.
    labelled: bool,
}

impl Sensor {
    fn status(&self) -> &'static str {
        match self.kind {
            SensorKind::Temperature => temperature_status(self.value, self.max, self.critical),
            // AIDEV-NOTE: an unlabelled fan input at 0 is usually a header with nothing
            // plugged in, so only a fan the driver names is reported as stopped.
            SensorKind::Fan if self.value == 0 && self.labelled => "STOPPED",
            SensorKind::Fan => "ok",
        }
    }
}

fn degrees(thousandths: i64) -> String {
    format!("{:.1} C", thousandths as f64 / 1000.0)
}

/// The temperature and fan readings of every sensor chip, and whether some were left out.
fn sensors(sys: &Path) -> (Vec<Sensor>, bool) {
    let base = sys.join("class/hwmon");
    let chips = numbered_in(&base, "hwmon");
    let mut cut = chips.len() > MAX_CHIPS;
    // (directory name, the chip's own name)
    let named: Vec<(String, String)> = chips
        .into_iter()
        .take(MAX_CHIPS)
        .map(|dir| {
            let name = read_trimmed(&base.join(&dir).join("name"), SMALL_FILE)
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| dir.clone());
            (dir, name)
        })
        .collect();
    let mut found = Vec::new();
    for (dir, name) in &named {
        // Two chips of the same kind (two NVMe drives) are told apart by directory.
        let shared = named.iter().filter(|(_, other)| other == name).count() > 1;
        let chip = if shared {
            format!("{name}/{dir}")
        } else {
            name.clone()
        };
        let chip_dir = base.join(dir);
        let files = names_in(&chip_dir).unwrap_or_default();
        for (prefix, kind) in [("temp", SensorKind::Temperature), ("fan", SensorKind::Fan)] {
            let mut indexes: Vec<u32> = files
                .iter()
                .filter_map(|file| numbered(file.strip_suffix("_input")?, prefix))
                .collect();
            indexes.sort_unstable();
            for index in indexes {
                let file = |suffix: &str| chip_dir.join(format!("{prefix}{index}_{suffix}"));
                let Some(value) = read_number::<i64>(&file("input")) else {
                    continue;
                };
                if found.len() >= MAX_SENSORS {
                    cut = true;
                    continue;
                }
                let label = read_trimmed(&file("label"), SMALL_FILE).filter(|l| !l.is_empty());
                found.push(Sensor {
                    chip: chip.clone(),
                    labelled: label.is_some(),
                    label: label.unwrap_or_else(|| format!("{prefix}{index}")),
                    kind,
                    value,
                    max: read_number(&file("max")),
                    critical: read_number(&file("crit")),
                });
            }
        }
    }
    (found, cut)
}

/// The error counters of one memory module.
struct Dimm {
    label: String,
    corrected: u64,
    uncorrected: u64,
}

/// The error counters of one memory controller (EDAC).
struct MemoryController {
    name: String,
    corrected: u64,
    uncorrected: u64,
    dimms: Vec<Dimm>,
}

fn memory_errors(sys: &Path) -> Vec<MemoryController> {
    let base = sys.join("devices/system/edac/mc");
    numbered_in(&base, "mc")
        .into_iter()
        .filter_map(|name| {
            let dir = base.join(&name);
            let corrected = read_number(&dir.join("ce_count"))?;
            let uncorrected = read_number(&dir.join("ue_count"))?;
            let mut dimms = Vec::new();
            for prefix in ["dimm", "rank"] {
                for dimm in numbered_in(&dir, prefix) {
                    let at = dir.join(&dimm);
                    let (Some(corrected), Some(uncorrected)) = (
                        read_number(&at.join("dimm_ce_count")),
                        read_number(&at.join("dimm_ue_count")),
                    ) else {
                        continue;
                    };
                    let label = read_trimmed(&at.join("dimm_label"), SMALL_FILE)
                        .filter(|label| !label.is_empty())
                        .unwrap_or(dimm);
                    dimms.push(Dimm {
                        label,
                        corrected,
                        uncorrected,
                    });
                }
            }
            Some(MemoryController {
                name,
                corrected,
                uncorrected,
                dimms,
            })
        })
        .collect()
}

/// How often the CPUs slowed themselves down because of heat since boot. `None` when
/// the kernel does not count it.
fn thermal_throttling(sys: &Path) -> Option<u64> {
    let base = sys.join("devices/system/cpu");
    let mut total = None;
    for cpu in numbered_in(&base, "cpu") {
        let file = base.join(cpu).join("thermal_throttle/core_throttle_count");
        if let Some(events) = read_number::<u64>(&file) {
            total = Some(total.unwrap_or(0u64).saturating_add(events));
        }
    }
    total
}

/// The power supplies and batteries.
#[derive(Default)]
struct Power {
    /// One line for each.
    lines: Vec<String>,
    /// Mains supplies that are online.
    mains_online: u64,
    /// The names of the mains supplies that are offline.
    mains_offline: Vec<String>,
}

fn power_supplies(sys: &Path) -> Power {
    let base = sys.join("class/power_supply");
    let mut power = Power::default();
    for name in names_in(&base).unwrap_or_default().into_iter().take(64) {
        let line = {
            let field = |file: &str| {
                read_trimmed(&base.join(&name).join(file), SMALL_FILE).filter(|v| !v.is_empty())
            };
            let mains = field("type").as_deref() == Some("Mains");
            let mut state = Vec::new();
            match field("online").as_deref() {
                Some("0") => {
                    state.push("offline".to_string());
                    if mains {
                        power.mains_offline.push(shown(&name, 60));
                    }
                }
                Some(_) => {
                    state.push("online".to_string());
                    if mains {
                        power.mains_online = power.mains_online.saturating_add(1);
                    }
                }
                None => {}
            }
            if let Some(status) = field("status") {
                state.push(shown(&status, 40));
            }
            if let Some(capacity) = field("capacity") {
                state.push(format!("{}%", shown(&capacity, 8)));
            }
            if state.is_empty() {
                state.push("present".to_string());
            }
            let kind = field("type").unwrap_or_else(|| "unknown type".to_string());
            format!(
                "{} ({}): {}",
                shown(&name, 60),
                shown(&kind, 40),
                state.join(", ")
            )
        };
        power.lines.push(line);
    }
    power
}

/// The maker, model and firmware, from DMI.
fn machine(sys: &Path) -> Option<String> {
    let field = |file: &str| {
        read_trimmed(&sys.join("class/dmi/id").join(file), SMALL_FILE)
            .filter(|value| !value.is_empty())
            .map(|value| shown(&value, 80))
    };
    let model: Vec<String> = [field("sys_vendor"), field("product_name")]
        .into_iter()
        .flatten()
        .collect();
    let bios = match (field("bios_version"), field("bios_date")) {
        (Some(version), Some(date)) => Some(format!("BIOS {version} ({date})")),
        (Some(version), None) => Some(format!("BIOS {version}")),
        (None, _) => None,
    };
    let parts: Vec<String> = [(!model.is_empty()).then(|| model.join(" ")), bios]
        .into_iter()
        .flatten()
        .collect();
    (!parts.is_empty()).then(|| parts.join("; "))
}

/// Everything that is read from files.
struct Readings {
    machine: Option<String>,
    sensors: Vec<Sensor>,
    sensors_cut: bool,
    memory: Vec<MemoryController>,
    throttled: Option<u64>,
    power: Power,
    /// There is an IPMI device node.
    ipmi_device: bool,
}

/// Blocking: reads files.
fn read_all(roots: &Roots) -> Readings {
    let (sensors, sensors_cut) = sensors(&roots.sys);
    let ipmi_device = ["ipmi0", "ipmi/0", "ipmidev/0"]
        .iter()
        .any(|node| roots.dev.join(node).symlink_metadata().is_ok());
    Readings {
        machine: machine(&roots.sys),
        sensors,
        sensors_cut,
        memory: memory_errors(&roots.sys),
        throttled: thermal_throttling(&roots.sys),
        power: power_supplies(&roots.sys),
        ipmi_device,
    }
}

/// One row of `ipmitool sdr elist` whose status is neither `ok` nor `ns`.
#[derive(Debug, PartialEq, Eq)]
pub struct SdrRow {
    pub name: String,
    pub status: String,
    pub reading: String,
}

impl SdrRow {
    /// `cr` (critical) and `nr` (non-recoverable), with or without the `l`/`u` for the
    /// lower or upper threshold.
    fn is_critical(&self) -> bool {
        self.status.ends_with("cr") || self.status.ends_with("nr")
    }
}

/// The rows of `ipmitool sdr elist` that report something other than `ok` (fine) or `ns`
/// (no sensor, or no reading). A row is `NAME | ID | STATUS | ENTITY | READING`.
pub fn sdr_not_ok(text: &str) -> Vec<SdrRow> {
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split('|').map(str::trim).collect();
            let (name, status) = (*fields.first()?, *fields.get(2)?);
            if name.is_empty() || status.is_empty() || status == "ok" || status == "ns" {
                return None;
            }
            Some(SdrRow {
                name: name.to_string(),
                status: status.to_string(),
                reading: fields.get(4).copied().unwrap_or("").to_string(),
            })
        })
        .collect()
}

/// What a command said when it did not work, on one line.
fn complaint(out: &CmdOutput) -> String {
    let text = command_text(out);
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    shown(&lines.join(" "), 300)
}

/// What is said first, gathered while the parts are put together.
#[derive(Default)]
struct Findings {
    problems: Vec<String>,
    warnings: Vec<String>,
}

/// The sensors, memory, power and throttling parts.
fn readings_text(read: &Readings, findings: &mut Findings) -> String {
    let mut text = String::new();
    if let Some(machine) = &read.machine {
        text.push_str(&format!("Machine: {machine}\n"));
    }

    if read.sensors.is_empty() {
        text.push_str("[no temperature or fan sensors are visible]\n");
    } else {
        text.push_str("== temperatures and fans ==\n");
        let with = |status: &str| {
            read.sensors
                .iter()
                .filter(|sensor| sensor.status() == status)
                .count() as u64
        };
        // AIDEV-NOTE: a fan at 0 rpm is a fault only while something is hot. Fans that
        // stop when the machine is cool are normal (laptops, quiet modes), and counting
        // every one of them made the first line cry wolf. With no temperature at or
        // above its maximum a stopped fan is shown as `stopped`, with a note, and is not
        // a warning.
        let hot = with("CRITICAL") + with("HIGH") > 0;
        let rows: Vec<Vec<String>> = read
            .sensors
            .iter()
            .map(|sensor| {
                let limit = |value: Option<i64>| match (sensor.kind, real_limit(value)) {
                    (SensorKind::Temperature, Some(value)) => degrees(value),
                    _ => "-".to_string(),
                };
                vec![
                    shown(&sensor.chip, 40),
                    shown(&sensor.label, 40),
                    match sensor.kind {
                        SensorKind::Temperature => degrees(sensor.value),
                        SensorKind::Fan => format!("{} rpm", sensor.value),
                    },
                    limit(sensor.max),
                    limit(sensor.critical),
                    match sensor.status() {
                        "STOPPED" if !hot => "stopped".to_string(),
                        status => status.to_string(),
                    },
                ]
            })
            .collect();
        text.push_str(&format_table(
            &["CHIP", "SENSOR", "VALUE", "MAX", "CRITICAL", "STATUS"],
            &rows,
            &[false, false, true, true, true, false],
        ));
        if read.sensors_cut {
            text.push_str(&format!(
                "[more sensors than are shown: the first {MAX_SENSORS} of {MAX_CHIPS} chips at most]\n"
            ));
        }
        match with("CRITICAL") {
            0 => {}
            1 => findings
                .problems
                .push("1 temperature at or above its critical value".to_string()),
            n => findings
                .problems
                .push(format!("{n} temperatures at or above their critical value")),
        }
        match with("HIGH") {
            0 => {}
            1 => findings
                .warnings
                .push("1 temperature at or above its maximum".to_string()),
            n => findings
                .warnings
                .push(format!("{n} temperatures at or above their maximum")),
        }
        match with("STOPPED") {
            0 => {}
            n if hot => findings.warnings.push(format!(
                "{} stopped while a temperature is at or above its maximum",
                count(n, "fan", "fans")
            )),
            n => text.push_str(&format!(
                "[{} stopped; no temperature is at or above its maximum, so that is not \
                 counted as a fault]\n",
                if n == 1 {
                    "1 fan is".to_string()
                } else {
                    format!("{n} fans are")
                }
            )),
        }
    }

    if read.memory.is_empty() {
        text.push_str("[no memory error counters (EDAC) on this host]\n");
    } else {
        text.push_str("== memory errors (EDAC) ==\n");
        let (mut corrected, mut uncorrected) = (0u64, 0u64);
        let mut suspects = Vec::new();
        for controller in &read.memory {
            corrected = corrected.saturating_add(controller.corrected);
            uncorrected = uncorrected.saturating_add(controller.uncorrected);
            text.push_str(&format!(
                "{}: {} corrected, {} uncorrected\n",
                controller.name, controller.corrected, controller.uncorrected
            ));
            for dimm in &controller.dimms {
                if dimm.corrected == 0 && dimm.uncorrected == 0 {
                    continue;
                }
                let label = shown(&dimm.label, 60);
                text.push_str(&format!(
                    "  {label}: {} corrected, {} uncorrected\n",
                    dimm.corrected, dimm.uncorrected
                ));
                suspects.push(label);
            }
        }
        suspects.truncate(8);
        let named = if suspects.is_empty() {
            String::new()
        } else {
            format!(" ({})", suspects.join(", "))
        };
        if uncorrected > 0 {
            findings.problems.push(format!(
                "{}{named}",
                count(
                    uncorrected,
                    "uncorrected memory error",
                    "uncorrected memory errors"
                )
            ));
        }
        if corrected > 0 {
            findings.warnings.push(format!(
                "{}{named}",
                count(
                    corrected,
                    "corrected memory error",
                    "corrected memory errors"
                )
            ));
        }
    }

    if !read.power.lines.is_empty() {
        text.push_str("== power ==\n");
        for line in &read.power.lines {
            text.push_str(line);
            text.push('\n');
        }
        // AIDEV-NOTE: a machine with two power supplies runs on one, so a dead one shows
        // nowhere else until the second fails. A lone supply that is offline is a
        // machine running on its battery, which is not a fault.
        if read.power.mains_online > 0 && !read.power.mains_offline.is_empty() {
            let offline = &read.power.mains_offline;
            let named: Vec<&str> = offline.iter().take(8).map(String::as_str).collect();
            findings.warnings.push(format!(
                "{} offline while another is online ({})",
                count(offline.len() as u64, "power supply", "power supplies"),
                named.join(", ")
            ));
        }
    }
    match read.throttled {
        Some(0) => text.push_str("CPU thermal throttling: none since boot\n"),
        Some(events) => {
            text.push_str(&format!(
                "CPU thermal throttling: {events} events since boot\n"
            ));
            findings.warnings.push(format!(
                "{} since boot",
                count(
                    events,
                    "CPU thermal throttling event",
                    "CPU thermal throttling events"
                )
            ));
        }
        None => {}
    }
    text
}

/// Machine-check and hardware-error lines of the last week from the kernel log.
async fn kernel_log_text(ctx: &Ctx, clock: &CallClock, findings: &mut Findings) -> String {
    // AIDEV-NOTE: these are kernel log lines, which belong to kernel_log.view. They are
    // shown only to a caller who could have read them with kernel_log itself, so this
    // tool is no way around a missing grant or a deny there.
    if !ctx.holds_read("kernel_log.view") {
        return "[hardware errors in the kernel log left out: needs kernel_log.view]\n".to_string();
    }
    let cmd = match ctx.optional_command("journalctl") {
        Ok(Some(cmd)) => cmd,
        Ok(None) => {
            return "[hardware errors in the kernel log not checked: journalctl is not installed]\n"
                .to_string();
        }
        Err(ToolError::Failed(problem)) => {
            return format!(
                "[hardware errors in the kernel log not checked: {}]\n",
                shown(&problem, 300)
            );
        }
        Err(_) => return String::new(),
    };
    let Some(limit) = clock.next() else {
        return "[hardware errors in the kernel log not checked: the call's time ran out]\n"
            .to_string();
    };
    let lines_arg = format!("--lines={LOG_LINES}");
    // AIDEV-NOTE: the match `_TRANSPORT=kernel`, not `--dmesg`. `--dmesg` also means
    // `--boot`, the current boot only: after a machine check that crashed the host, the
    // evidence is in the PREVIOUS boot, and a search of this one would report "none".
    let cmd = cmd.timeout(limit).args([
        "--no-pager",
        "--quiet",
        "--output=short-iso",
        "--since=-7d",
        "--grep=mce:|Machine check|Hardware Error",
        lines_arg.as_str(),
        "_TRANSPORT=kernel",
    ]);
    let out = match ctx.run(cmd).await {
        Ok(out) => out,
        Err(ToolError::Failed(problem)) => {
            return format!(
                "[hardware errors in the kernel log not checked: {}]\n",
                shown(&problem, 300)
            );
        }
        Err(_) => return String::new(),
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    let title = "Hardware errors in the kernel log (last 7 days)";
    if lines.is_empty() {
        // journalctl exits 1 without a word when --grep matches nothing.
        let silent = out.stderr.iter().all(u8::is_ascii_whitespace);
        if !out.timed_out && silent && matches!(out.code, Some(0) | Some(1)) {
            return format!("{title}: none\n");
        }
        return format!("[{title} not checked: {}]\n", complaint(&out));
    }
    let number = if lines.len() >= LOG_LINES {
        format!("{LOG_LINES} or more hardware-error lines")
    } else {
        count(
            lines.len() as u64,
            "hardware-error line",
            "hardware-error lines",
        )
    };
    findings
        .warnings
        .push(format!("{number} in the kernel log in the last 7 days"));
    let mut text = format!("== {title}: {number}; the newest ==\n");
    let newest = lines.len().saturating_sub(LOG_SHOWN);
    for line in lines.iter().skip(newest) {
        text.push_str(&shown(line, 300));
        text.push('\n');
    }
    text
}

/// The management controller's view: sensors that are not ok, and its event log.
async fn ipmi_text(
    ctx: &Ctx,
    clock: &CallClock,
    device: bool,
    findings: &mut Findings,
) -> (String, bool) {
    if !device {
        return (
            "[IPMI: this machine has no IPMI device (/dev/ipmi0)]\n".to_string(),
            false,
        );
    }
    let tool = match ctx.optional_command("ipmitool") {
        Ok(Some(cmd)) => cmd,
        Ok(None) => {
            return (
                "[IPMI: this machine has an IPMI device, but ipmitool is not installed \
                 (package ipmitool)]\n"
                    .to_string(),
                false,
            );
        }
        Err(ToolError::Failed(problem)) => {
            return (format!("[IPMI: {}]\n", shown(&problem, 300)), false);
        }
        Err(_) => return (String::new(), false),
    };
    let mut text = String::new();
    let mut read_sensors = false;

    // The sensors. A management controller can take many seconds to answer; each
    // command gets what the call has left and no more.
    match clock.next() {
        None => text.push_str("[IPMI sensors not read: the call's time ran out]\n"),
        Some(limit) => {
            match ctx
                .run(tool.clone().timeout(limit).args(["sdr", "elist"]))
                .await
            {
                Ok(out) if command_ok(&out) => {
                    read_sensors = true;
                    let rows = sdr_not_ok(&String::from_utf8_lossy(&out.stdout));
                    let critical = rows.iter().filter(|row| row.is_critical()).count() as u64;
                    let other = rows.len() as u64 - critical;
                    if critical > 0 {
                        findings.problems.push(format!(
                            "{} critical",
                            count(critical, "IPMI sensor is", "IPMI sensors are")
                        ));
                    }
                    if other > 0 {
                        findings.warnings.push(format!(
                            "{} not ok",
                            count(other, "IPMI sensor is", "IPMI sensors are")
                        ));
                    }
                    if rows.is_empty() {
                        text.push_str("IPMI sensors: all ok\n");
                    } else {
                        text.push_str("== IPMI sensors that are not ok ==\n");
                        let table: Vec<Vec<String>> = rows
                            .iter()
                            .take(IPMI_ROWS)
                            .map(|row| {
                                vec![
                                    shown(&row.name, 40),
                                    shown(&row.status, 8),
                                    shown(&row.reading, 120),
                                ]
                            })
                            .collect();
                        text.push_str(&format_table(
                            &["SENSOR", "STATUS", "READING"],
                            &table,
                            &[false, false, false],
                        ));
                        if rows.len() > IPMI_ROWS {
                            text.push_str(&format!(
                                "[{} more not shown]\n",
                                rows.len() - IPMI_ROWS
                            ));
                        }
                    }
                }
                Ok(out) => {
                    text.push_str(&format!("[IPMI sensors not read: {}]\n", complaint(&out)))
                }
                Err(ToolError::Failed(problem)) => {
                    text.push_str(&format!(
                        "[IPMI sensors not read: {}]\n",
                        shown(&problem, 300)
                    ));
                }
                Err(_) => {}
            }
        }
    }

    // The event log.
    match clock.next() {
        None => text.push_str("[IPMI event log not read: the call's time ran out]\n"),
        Some(limit) => {
            match ctx
                .run(tool.timeout(limit).args(["sel", "elist", "last", "10"]))
                .await
            {
                Ok(out) if command_ok(&out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    let lines: Vec<&str> =
                        stdout.lines().filter(|l| !l.trim().is_empty()).collect();
                    if lines.is_empty() {
                        text.push_str("IPMI event log: empty\n");
                    } else {
                        text.push_str("== IPMI event log (the last 10 entries) ==\n");
                        for line in lines.iter().take(IPMI_ROWS) {
                            text.push_str(&shown(line, 300));
                            text.push('\n');
                        }
                    }
                }
                Ok(out) => {
                    text.push_str(&format!("[IPMI event log not read: {}]\n", complaint(&out)))
                }
                Err(ToolError::Failed(problem)) => {
                    text.push_str(&format!(
                        "[IPMI event log not read: {}]\n",
                        shown(&problem, 300)
                    ));
                }
                Err(_) => {}
            }
        }
    }
    (text, read_sensors)
}

/// The first line.
fn verdict(read: &Readings, ipmi_read: bool, findings: &Findings) -> String {
    let warnings = || format!("Warnings: {}.", findings.warnings.join("; "));
    if !findings.problems.is_empty() {
        let mut line = format!("PROBLEM: {}.", findings.problems.join("; "));
        if !findings.warnings.is_empty() {
            line.push(' ');
            line.push_str(&warnings());
        }
        return line;
    }
    if !findings.warnings.is_empty() {
        return warnings();
    }
    if read.sensors.is_empty() && read.memory.is_empty() && !ipmi_read {
        return "No hardware sensors are visible on this host (a virtual machine usually \
                has none), and nothing that can be read reports a problem."
            .to_string();
    }
    let of = |kind: SensorKind| read.sensors.iter().filter(|s| s.kind == kind).count() as u64;
    let mut looked_at = Vec::new();
    match of(SensorKind::Temperature) {
        0 => {}
        n => looked_at.push(count(n, "temperature", "temperatures")),
    }
    match of(SensorKind::Fan) {
        0 => {}
        n => looked_at.push(count(n, "fan", "fans")),
    }
    if !read.memory.is_empty() {
        looked_at.push("memory error counters clean".to_string());
    }
    if ipmi_read {
        looked_at.push("IPMI sensors ok".to_string());
    }
    format!(
        "No hardware problems are visible ({}).",
        looked_at.join(", ")
    )
}

async fn hardware_health(ctx: Ctx, _args: Args, roots: Arc<Roots>) -> ToolResult {
    let auth = ctx.authorize(None)?;
    let clock = CallClock::start(&ctx);
    let read = blocking(ctx.clone(), move || Ok(read_all(&roots))).await?;

    let mut findings = Findings::default();
    let mut body = readings_text(&read, &mut findings);
    body.push_str(&kernel_log_text(&ctx, &clock, &mut findings).await);
    let (ipmi, ipmi_read) = ipmi_text(&ctx, &clock, read.ipmi_device, &mut findings).await;
    body.push_str(&ipmi);

    // AIDEV-NOTE: a finding is the answer to the question asked, not a failed call, so
    // the result is a success whatever it says; the first line carries the verdict.
    let text = format!("{}\n{body}", verdict(&read, ipmi_read, &findings));
    const NOTE_ROOM: usize = 80;
    let (kept, dropped) = keep_head(&text, ctx.output_budget().saturating_sub(NOTE_ROOM));
    if dropped == 0 {
        return auth.ok(kept);
    }
    auth.ok(format!(
        "{kept}[{dropped} more lines left out to fit the output limit]\n"
    ))
}

// ---- hardware_info (SMBIOS / DMI) ----------------------------------------------------

/// Limits for parsing `dmidecode` output so pathological firmware tables stay bounded.
const MAX_DMI_LINES: usize = 20_000;
const MAX_DMI_BLOCKS: usize = 512;
const MAX_DMI_FIELDS: usize = 128;
const MAX_PROCESSORS: usize = 64;
const MAX_DIMMS: usize = 128;
const MAX_EMPTY_SLOTS_SHOWN: usize = 16;

/// One SMBIOS structure block from `dmidecode` (for example `BIOS Information` or
/// `Memory Device`).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DmiBlock {
    pub title: String,
    pub fields: Vec<(String, String)>,
    /// Multi-line list items (such as `Characteristics` under `BIOS Information`),
    /// stored as `(field_name, items)`.
    pub lists: Vec<(String, Vec<String>)>,
}

impl DmiBlock {
    pub fn field(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    pub fn meaningful(&self, key: &str) -> Option<&str> {
        self.field(key).filter(|v| !is_dmi_placeholder(v))
    }

    pub fn list(&self, key: &str) -> &[String] {
        self.lists
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, items)| items.as_slice())
            .unwrap_or(&[])
    }
}

/// True when a DMI string is a firmware placeholder rather than a real value.
pub fn is_dmi_placeholder(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "not specified"
            | "not provided"
            | "not present"
            | "not available"
            | "not installed"
            | "none"
            | "unknown"
            | "n/a"
            | "to be filled by o.e.m."
            | "default string"
            | "o.e.m."
            | "oem"
            | "tbd"
            | "system manufacturer"
            | "system product name"
            | "system version"
            | "system serial number"
            | "base board serial number"
            | "chassis serial number"
            | "no asset tag"
            | "no asset information"
            | "asset-1234567890"
            | "00000000"
            | "0000000000"
            | "0123456789"
            | "123456789"
    )
}

/// Parses `dmidecode` output (with or without `-q`) into structured blocks.
pub fn parse_dmidecode(text: &str) -> Vec<DmiBlock> {
    let mut blocks = Vec::new();
    let mut current: Option<DmiBlock> = None;
    let mut current_field: Option<String> = None;

    let flush = |blocks: &mut Vec<DmiBlock>, current: &mut Option<DmiBlock>| {
        if let Some(block) = current.take()
            && !block.title.is_empty()
            && blocks.len() < MAX_DMI_BLOCKS
        {
            blocks.push(block);
        }
    };

    for raw in text.lines().take(MAX_DMI_LINES) {
        let line = raw.trim_end_matches('\r');
        let trimmed = line.trim();
        if trimmed.is_empty() {
            flush(&mut blocks, &mut current);
            current_field = None;
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        if !line.starts_with(['\t', ' ']) {
            if line.starts_with("Handle 0x") {
                flush(&mut blocks, &mut current);
                current_field = None;
                continue;
            }
            flush(&mut blocks, &mut current);
            current_field = None;
            if trimmed == "End Of Table" {
                continue;
            }
            current = Some(DmiBlock {
                title: trimmed.to_string(),
                fields: Vec::new(),
                lists: Vec::new(),
            });
            continue;
        }
        let Some(block) = current.as_mut() else {
            continue;
        };
        let is_list_item = line.starts_with("\t\t") || line.starts_with("        ");
        if is_list_item {
            if let Some(field) = current_field.as_deref() {
                push_list_item(block, field, trimmed);
            }
            continue;
        }
        if let Some((key, val)) = trimmed.split_once(':') {
            let key = key.trim();
            let val = val.trim();
            current_field = Some(key.to_string());
            if !val.is_empty() && block.fields.len() < MAX_DMI_FIELDS {
                block.fields.push((key.to_string(), val.to_string()));
            }
        } else if let Some(field) = current_field.as_deref() {
            push_list_item(block, field, trimmed);
        }
    }
    flush(&mut blocks, &mut current);
    blocks
}

fn push_list_item(block: &mut DmiBlock, field: &str, item: &str) {
    if let Some((_, items)) = block.lists.last_mut().filter(|(k, _)| k == field) {
        if items.len() < MAX_DMI_FIELDS {
            items.push(item.to_string());
        }
    } else if block.lists.len() < MAX_DMI_FIELDS {
        block
            .lists
            .push((field.to_string(), vec![item.to_string()]));
    }
}

/// True when a Type 17 `Size` value means the memory slot is empty.
fn is_empty_dimm_size(size: &str) -> bool {
    let lower = size.trim().to_ascii_lowercase();
    lower.is_empty()
        || matches!(
            lower.as_str(),
            "no module installed" | "not installed" | "unknown" | "none" | "0"
        )
        || lower.starts_with("0 ")
}

/// Parses a `dmidecode` memory size such as `32 GB`, `16384 MB` or `1 TB` into KiB.
/// Returns `None` for empty slots, zero, or unrecognized strings.
pub fn parse_dmi_memory_kib(size: &str) -> Option<u64> {
    let mut parts = size.split_whitespace();
    let number: u64 = parts.next()?.parse().ok()?;
    let unit = parts.next()?;
    if parts.next().is_some() || number == 0 {
        return None;
    }
    match unit {
        "kB" | "KB" | "KiB" => Some(number),
        "MB" | "MiB" => number.checked_mul(1024),
        "GB" | "GiB" => number.checked_mul(1024 * 1024),
        "TB" | "TiB" => number.checked_mul(1024 * 1024 * 1024),
        _ => None,
    }
}

/// Formats a KiB memory total in SMBIOS/dmidecode units (`TB`, `GB`, `MB`, `kB`).
pub fn format_dmi_kib(kib: u64) -> String {
    const MIB: u64 = 1024;
    const GIB: u64 = 1024 * 1024;
    const TIB: u64 = 1024 * 1024 * 1024;
    let format_unit = |unit: u64, suffix: &str| {
        if kib.is_multiple_of(unit) {
            format!("{} {suffix}", kib / unit)
        } else {
            format!("{:.1} {suffix}", kib as f64 / unit as f64)
        }
    };
    if kib >= TIB {
        format_unit(TIB, "TB")
    } else if kib >= GIB {
        format_unit(GIB, "GB")
    } else if kib >= MIB {
        format_unit(MIB, "MB")
    } else {
        format!("{kib} kB")
    }
}

/// Formats aligned `Key: value` lines, sanitizing every value onto one line.
fn format_kv(rows: &[(&str, String)]) -> String {
    let width = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    let mut out = String::new();
    for (key, value) in rows {
        let pad = " ".repeat(width.saturating_sub(key.len()));
        out.push_str(&format!("{key}:{pad} {}\n", shown(value, 120)));
    }
    out
}

/// Formats the `Machine: ...` one-line headline from vendor/product and BIOS version/date.
fn machine_headline(
    vendor: Option<&str>,
    product: Option<&str>,
    bios_version: Option<&str>,
    bios_date: Option<&str>,
) -> Option<String> {
    let model: Vec<String> = [vendor, product]
        .into_iter()
        .flatten()
        .map(|v| shown(v, 80))
        .collect();
    let bios = match (bios_version, bios_date) {
        (Some(version), Some(date)) => {
            Some(format!("BIOS {} ({})", shown(version, 80), shown(date, 40)))
        }
        (Some(version), None) => Some(format!("BIOS {}", shown(version, 80))),
        (None, _) => None,
    };
    let parts: Vec<String> = [(!model.is_empty()).then(|| model.join(" ")), bios]
        .into_iter()
        .flatten()
        .collect();
    (!parts.is_empty()).then(|| parts.join("; "))
}

/// Builds a concise, structured summary from parsed `dmidecode` blocks.
pub fn format_dmi_summary(blocks: &[DmiBlock]) -> String {
    let first = |title: &str| blocks.iter().find(|b| b.title == title);
    let system = first("System Information");
    let bios = first("BIOS Information");
    let baseboard = first("Base Board Information");
    let chassis = first("Chassis Information");

    let mut out = String::new();
    if let Some(headline) = machine_headline(
        system.and_then(|b| b.meaningful("Manufacturer")),
        system.and_then(|b| b.meaningful("Product Name")),
        bios.and_then(|b| b.meaningful("Version")),
        bios.and_then(|b| b.meaningful("Release Date")),
    ) {
        out.push_str(&format!("Machine: {headline}\n"));
    }

    if let Some(b) = system {
        let mut rows = Vec::new();
        for (label, key) in [
            ("Manufacturer", "Manufacturer"),
            ("Product", "Product Name"),
            ("Version", "Version"),
            ("Serial", "Serial Number"),
            ("UUID", "UUID"),
            ("SKU", "SKU Number"),
            ("Family", "Family"),
        ] {
            if let Some(val) = b.meaningful(key) {
                rows.push((label, val.to_string()));
            }
        }
        if !rows.is_empty() {
            out.push_str("== system ==\n");
            out.push_str(&format_kv(&rows));
        }
    }

    if let Some(b) = bios {
        let mut rows = Vec::new();
        for (label, key) in [
            ("Vendor", "Vendor"),
            ("Version", "Version"),
            ("Release Date", "Release Date"),
            ("BIOS Revision", "BIOS Revision"),
            ("Firmware", "Firmware Revision"),
        ] {
            if let Some(val) = b.meaningful(key) {
                rows.push((label, val.to_string()));
            }
        }
        if b.list("Characteristics")
            .iter()
            .any(|c| c.eq_ignore_ascii_case("UEFI is supported"))
        {
            rows.push(("Boot Mode", "UEFI".to_string()));
        }
        if !rows.is_empty() {
            out.push_str("== BIOS ==\n");
            out.push_str(&format_kv(&rows));
        }
    }

    if let Some(b) = baseboard {
        let mut rows = Vec::new();
        for (label, key) in [
            ("Manufacturer", "Manufacturer"),
            ("Product", "Product Name"),
            ("Version", "Version"),
            ("Serial", "Serial Number"),
            ("Asset Tag", "Asset Tag"),
        ] {
            if let Some(val) = b.meaningful(key) {
                rows.push((label, val.to_string()));
            }
        }
        if !rows.is_empty() {
            out.push_str("== baseboard ==\n");
            out.push_str(&format_kv(&rows));
        }
    }

    if let Some(b) = chassis {
        let mut rows = Vec::new();
        for (label, key) in [
            ("Manufacturer", "Manufacturer"),
            ("Type", "Type"),
            ("Version", "Version"),
            ("Serial", "Serial Number"),
            ("Asset Tag", "Asset Tag"),
        ] {
            if let Some(val) = b.meaningful(key) {
                rows.push((label, val.to_string()));
            }
        }
        if !rows.is_empty() {
            out.push_str("== chassis ==\n");
            out.push_str(&format_kv(&rows));
        }
    }

    let processors: Vec<&DmiBlock> = blocks
        .iter()
        .filter(|b| b.title == "Processor Information")
        .collect();
    if !processors.is_empty() {
        out.push_str("== processors ==\n");
        let rows: Vec<Vec<String>> = processors
            .iter()
            .take(MAX_PROCESSORS)
            .map(|p| {
                let socket = p
                    .meaningful("Socket Designation")
                    .map(|v| shown(v, 32))
                    .unwrap_or_else(|| "-".to_string());
                let model = p
                    .meaningful("Version")
                    .or_else(|| p.meaningful("Family"))
                    .or_else(|| p.meaningful("Manufacturer"))
                    .map(|v| shown(v, 64))
                    .unwrap_or_else(|| "-".to_string());
                let cores = format_processor_cores(p);
                let speed =
                    format_speed_pair(p.meaningful("Current Speed"), p.meaningful("Max Speed"));
                let status = p
                    .meaningful("Status")
                    .map(|v| shown(v, 32))
                    .unwrap_or_else(|| "-".to_string());
                vec![socket, model, cores, speed, status]
            })
            .collect();
        out.push_str(&format_table(
            &["SOCKET", "MODEL", "CORES/THREADS", "SPEED", "STATUS"],
            &rows,
            &[false, false, false, false, false],
        ));
        if processors.len() > MAX_PROCESSORS {
            out.push_str(&format!(
                "[{} more processors not shown]\n",
                processors.len() - MAX_PROCESSORS
            ));
        }
    }

    let arrays: Vec<&DmiBlock> = blocks
        .iter()
        .filter(|b| b.title == "Physical Memory Array")
        .collect();
    let devices: Vec<&DmiBlock> = blocks
        .iter()
        .filter(|b| b.title == "Memory Device")
        .collect();
    if !arrays.is_empty() || !devices.is_empty() {
        out.push_str("== memory ==\n");
        format_memory_section(&arrays, &devices, &mut out);
    }

    out
}

fn format_processor_cores(p: &DmiBlock) -> String {
    let cores = p.meaningful("Core Count");
    let enabled = p.meaningful("Core Enabled");
    let threads = p.meaningful("Thread Count");
    let core_part = match (cores, enabled) {
        (Some(c), Some(e)) if e != c => Some(format!("{} of {}c", shown(e, 8), shown(c, 8))),
        (Some(c), _) => Some(format!("{}c", shown(c, 8))),
        (None, Some(e)) => Some(format!("{}c", shown(e, 8))),
        (None, None) => None,
    };
    match (core_part, threads) {
        (Some(c), Some(t)) => format!("{c}/{}t", shown(t, 8)),
        (Some(c), None) => c,
        (None, Some(t)) => format!("{}t", shown(t, 8)),
        (None, None) => "-".to_string(),
    }
}

fn format_speed_pair(current: Option<&str>, max: Option<&str>) -> String {
    match (current, max) {
        (Some(cur), Some(mx)) if cur != mx => {
            format!("{} (max {})", shown(cur, 20), shown(mx, 20))
        }
        (Some(cur), _) => shown(cur, 24),
        (None, Some(mx)) => shown(mx, 24),
        (None, None) => "-".to_string(),
    }
}

fn format_memory_section(arrays: &[&DmiBlock], devices: &[&DmiBlock], out: &mut String) {
    // Prefer System Memory arrays so BIOS flash arrays do not skew RAM totals.
    let system_arrays: Vec<&DmiBlock> = arrays
        .iter()
        .copied()
        .filter(|a| {
            a.field("Use")
                .is_some_and(|u| u.eq_ignore_ascii_case("System Memory"))
        })
        .collect();
    let relevant_arrays = if system_arrays.is_empty() {
        arrays
    } else {
        system_arrays.as_slice()
    };

    let mut populated = Vec::new();
    let mut empty_locators = Vec::new();
    let mut total_kib = 0u64;
    let mut parsed_any_size = false;
    for dev in devices {
        let size = dev.field("Size").unwrap_or("");
        if is_empty_dimm_size(size) {
            let loc = dev
                .meaningful("Locator")
                .or_else(|| dev.meaningful("Bank Locator"))
                .map(|v| shown(v, 32));
            empty_locators.push(loc);
            continue;
        }
        if let Some(kib) = parse_dmi_memory_kib(size) {
            total_kib = total_kib.saturating_add(kib);
            parsed_any_size = true;
        }
        populated.push(*dev);
    }

    let array_slots: u64 = relevant_arrays
        .iter()
        .filter_map(|a| a.field("Number Of Devices")?.parse::<u64>().ok())
        .fold(0u64, u64::saturating_add);
    let total_slots = if !devices.is_empty() {
        devices.len() as u64
    } else {
        array_slots
    };

    let mut details = Vec::new();
    let mut max_kib = 0u64;
    let mut max_parsed = !relevant_arrays.is_empty();
    let mut max_raw = Vec::new();
    let mut ecc_types = Vec::new();
    for arr in relevant_arrays {
        if let Some(cap) = arr.meaningful("Maximum Capacity") {
            if let Some(kib) = parse_dmi_memory_kib(cap) {
                max_kib = max_kib.saturating_add(kib);
            } else {
                max_parsed = false;
                let s = shown(cap, 24);
                if !max_raw.contains(&s) {
                    max_raw.push(s);
                }
            }
        } else {
            max_parsed = false;
        }
        if let Some(ecc) = arr.field("Error Correction Type") {
            let trimmed = ecc.trim();
            if !trimmed.is_empty()
                && !trimmed.eq_ignore_ascii_case("Unknown")
                && !trimmed.eq_ignore_ascii_case("Other")
                && !trimmed.eq_ignore_ascii_case("Not Specified")
            {
                let label = if trimmed.eq_ignore_ascii_case("None") {
                    "no ECC".to_string()
                } else {
                    shown(trimmed, 32)
                };
                if !ecc_types.contains(&label) {
                    ecc_types.push(label);
                }
            }
        }
    }
    if max_parsed && max_kib > 0 {
        details.push(format!("max {}", format_dmi_kib(max_kib)));
    } else if !max_raw.is_empty() {
        details.push(format!("max {}", max_raw.join(" + ")));
    }
    if !ecc_types.is_empty() {
        details.push(ecc_types.join(", "));
    }
    let detail_suffix = if details.is_empty() {
        String::new()
    } else {
        format!(" ({})", details.join(", "))
    };

    if parsed_any_size {
        out.push_str(&format!(
            "Total: {} installed across {} of {}{detail_suffix}\n",
            format_dmi_kib(total_kib),
            populated.len(),
            count(total_slots, "slot", "slots"),
        ));
    } else if total_slots > 0 {
        out.push_str(&format!(
            "Total: {} populated of {}{detail_suffix}\n",
            populated.len(),
            count(total_slots, "slot", "slots"),
        ));
    } else if !details.is_empty() {
        out.push_str(&format!("Array: {}\n", details.join(", ")));
    }

    if !populated.is_empty() {
        let rows: Vec<Vec<String>> = populated
            .iter()
            .take(MAX_DIMMS)
            .map(|d| {
                let slot = d
                    .meaningful("Locator")
                    .or_else(|| d.meaningful("Bank Locator"))
                    .map(|v| shown(v, 32))
                    .unwrap_or_else(|| "-".to_string());
                let size = d
                    .field("Size")
                    .map(|v| shown(v, 20))
                    .unwrap_or_else(|| "-".to_string());
                let kind = d
                    .meaningful("Type")
                    .map(|v| shown(v, 20))
                    .unwrap_or_else(|| "-".to_string());
                let configured = d
                    .meaningful("Configured Memory Speed")
                    .or_else(|| d.meaningful("Configured Clock Speed"));
                let rated = d.meaningful("Speed");
                let speed = format_speed_pair(configured, rated);
                let manufacturer = d
                    .meaningful("Manufacturer")
                    .map(|v| shown(v, 28))
                    .unwrap_or_else(|| "-".to_string());
                let part = d
                    .meaningful("Part Number")
                    .map(|v| shown(v, 36))
                    .unwrap_or_else(|| "-".to_string());
                let serial = d
                    .meaningful("Serial Number")
                    .map(|v| shown(v, 28))
                    .unwrap_or_else(|| "-".to_string());
                vec![slot, size, kind, speed, manufacturer, part, serial]
            })
            .collect();
        out.push_str(&format_table(
            &[
                "SLOT",
                "SIZE",
                "TYPE",
                "SPEED",
                "MANUFACTURER",
                "PART",
                "SERIAL",
            ],
            &rows,
            &[false, true, false, false, false, false, false],
        ));
        if populated.len() > MAX_DIMMS {
            out.push_str(&format!(
                "[{} more memory modules not shown]\n",
                populated.len() - MAX_DIMMS
            ));
        }
    }

    if !empty_locators.is_empty() {
        let named: Vec<&str> = empty_locators
            .iter()
            .flatten()
            .take(MAX_EMPTY_SLOTS_SHOWN)
            .map(String::as_str)
            .collect();
        if named.is_empty() {
            out.push_str(&format!("Empty slots: {}\n", empty_locators.len()));
        } else if empty_locators.len() > named.len() {
            out.push_str(&format!(
                "Empty slots: {} ({}, ...)\n",
                empty_locators.len(),
                named.join(", ")
            ));
        } else {
            out.push_str(&format!(
                "Empty slots: {} ({})\n",
                empty_locators.len(),
                named.join(", ")
            ));
        }
    }
}

/// Basic DMI identity files exposed by the kernel under `/sys/class/dmi/id`.
#[derive(Default)]
struct SysfsDmi {
    sys_vendor: Option<String>,
    product_name: Option<String>,
    product_version: Option<String>,
    product_serial: Option<String>,
    product_uuid: Option<String>,
    product_sku: Option<String>,
    product_family: Option<String>,
    bios_vendor: Option<String>,
    bios_version: Option<String>,
    bios_date: Option<String>,
    bios_release: Option<String>,
    board_vendor: Option<String>,
    board_name: Option<String>,
    board_version: Option<String>,
    board_serial: Option<String>,
    board_asset_tag: Option<String>,
    chassis_vendor: Option<String>,
    chassis_type: Option<String>,
    chassis_version: Option<String>,
    chassis_serial: Option<String>,
    chassis_asset_tag: Option<String>,
    restricted_fields: bool,
}

fn read_dmi_file(path: &Path, restricted: &mut bool) -> Option<String> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(err) => {
            if err.kind() == ErrorKind::PermissionDenied {
                *restricted = true;
            }
            return None;
        }
    };
    let mut data = Vec::new();
    file.take(SMALL_FILE).read_to_end(&mut data).ok()?;
    let value = String::from_utf8_lossy(&data).trim().to_string();
    (!is_dmi_placeholder(&value)).then_some(value)
}

/// Maps the numeric SMBIOS chassis type in `/sys/class/dmi/id/chassis_type` to its name.
fn chassis_type_name(code: &str) -> String {
    match code.trim() {
        "1" => "Other".to_string(),
        "2" => "Unknown".to_string(),
        "3" => "Desktop".to_string(),
        "4" => "Low Profile Desktop".to_string(),
        "5" => "Pizza Box".to_string(),
        "6" => "Mini Tower".to_string(),
        "7" => "Tower".to_string(),
        "8" => "Portable".to_string(),
        "9" => "Laptop".to_string(),
        "10" => "Notebook".to_string(),
        "11" => "Hand Held".to_string(),
        "13" => "All in One".to_string(),
        "14" => "Sub Notebook".to_string(),
        "15" => "Space-saving".to_string(),
        "16" => "Lunch Box".to_string(),
        "17" => "Main Server Chassis".to_string(),
        "23" => "Rack Mount Chassis".to_string(),
        "24" => "Sealed-case PC".to_string(),
        "25" => "Multi-system".to_string(),
        "28" => "Blade".to_string(),
        "29" => "Blade Enclosure".to_string(),
        "30" => "Tablet".to_string(),
        "31" => "Convertible".to_string(),
        "32" => "Detachable".to_string(),
        "35" => "Mini PC".to_string(),
        "36" => "Stick PC".to_string(),
        other => shown(other, 32),
    }
}

/// Blocking: reads `/sys/class/dmi/id/*`.
fn read_sysfs_dmi(sys: &Path) -> SysfsDmi {
    let base = sys.join("class/dmi/id");
    let mut restricted = false;
    let mut read = |file: &str| read_dmi_file(&base.join(file), &mut restricted);
    SysfsDmi {
        sys_vendor: read("sys_vendor"),
        product_name: read("product_name"),
        product_version: read("product_version"),
        product_serial: read("product_serial"),
        product_uuid: read("product_uuid"),
        product_sku: read("product_sku"),
        product_family: read("product_family"),
        bios_vendor: read("bios_vendor"),
        bios_version: read("bios_version"),
        bios_date: read("bios_date"),
        bios_release: read("bios_release"),
        board_vendor: read("board_vendor"),
        board_name: read("board_name"),
        board_version: read("board_version"),
        board_serial: read("board_serial"),
        board_asset_tag: read("board_asset_tag"),
        chassis_vendor: read("chassis_vendor"),
        chassis_type: read("chassis_type").map(|code| chassis_type_name(&code)),
        chassis_version: read("chassis_version"),
        chassis_serial: read("chassis_serial"),
        chassis_asset_tag: read("chassis_asset_tag"),
        restricted_fields: restricted,
    }
}

fn sysfs_supports_section(section: &str) -> bool {
    matches!(
        section,
        "summary" | "all" | "system" | "bios" | "baseboard" | "chassis"
    )
}

/// Formats the sections of `/sys/class/dmi/id` matching `section`. Returns the text and
/// whether any DMI data was found.
fn format_sysfs_dmi(dmi: &SysfsDmi, section: &str) -> (String, bool) {
    if !sysfs_supports_section(section) {
        return (
            format!(
                "[/sys/class/dmi/id does not expose {section} tables; dmidecode is required]\n"
            ),
            false,
        );
    }
    let show_all = matches!(section, "summary" | "all");
    let mut out = String::new();
    if show_all
        && let Some(headline) = machine_headline(
            dmi.sys_vendor.as_deref(),
            dmi.product_name.as_deref(),
            dmi.bios_version.as_deref(),
            dmi.bios_date.as_deref(),
        )
    {
        out.push_str(&format!("Machine: {headline}\n"));
    }

    let push_section = |out: &mut String, title: &str, pairs: &[(&str, &Option<String>)]| {
        let rows: Vec<(&str, String)> = pairs
            .iter()
            .filter_map(|(label, val)| Some((*label, val.as_ref()?.clone())))
            .collect();
        if !rows.is_empty() {
            out.push_str(&format!("== {title} ==\n"));
            out.push_str(&format_kv(&rows));
        }
    };

    if show_all || section == "system" {
        push_section(
            &mut out,
            "system",
            &[
                ("Manufacturer", &dmi.sys_vendor),
                ("Product", &dmi.product_name),
                ("Version", &dmi.product_version),
                ("Serial", &dmi.product_serial),
                ("UUID", &dmi.product_uuid),
                ("SKU", &dmi.product_sku),
                ("Family", &dmi.product_family),
            ],
        );
    }
    if show_all || section == "bios" {
        push_section(
            &mut out,
            "BIOS",
            &[
                ("Vendor", &dmi.bios_vendor),
                ("Version", &dmi.bios_version),
                ("Release Date", &dmi.bios_date),
                ("BIOS Revision", &dmi.bios_release),
            ],
        );
    }
    if show_all || section == "baseboard" {
        push_section(
            &mut out,
            "baseboard",
            &[
                ("Manufacturer", &dmi.board_vendor),
                ("Product", &dmi.board_name),
                ("Version", &dmi.board_version),
                ("Serial", &dmi.board_serial),
                ("Asset Tag", &dmi.board_asset_tag),
            ],
        );
    }
    if show_all || section == "chassis" {
        push_section(
            &mut out,
            "chassis",
            &[
                ("Manufacturer", &dmi.chassis_vendor),
                ("Type", &dmi.chassis_type),
                ("Version", &dmi.chassis_version),
                ("Serial", &dmi.chassis_serial),
                ("Asset Tag", &dmi.chassis_asset_tag),
            ],
        );
    }

    let has_data = !out.is_empty();
    if dmi.restricted_fields {
        out.push_str("[some DMI fields (serial numbers, UUID) require root privileges to read]\n");
    }
    (out, has_data)
}

/// Fixed `dmidecode` arguments for a validated `section` choice.
///
/// AIDEV-NOTE: `section` is constrained by `Param::choice`, and mapped here to static
/// argument slices so caller input never reaches `dmidecode`'s flags directly.
fn dmidecode_args(section: &str) -> &'static [&'static str] {
    match section {
        "summary" => &[
            "-q",
            "-t",
            "bios",
            "-t",
            "system",
            "-t",
            "baseboard",
            "-t",
            "chassis",
            "-t",
            "processor",
            "-t",
            "memory",
        ],
        "bios" => &["-q", "-t", "bios"],
        "system" => &["-q", "-t", "system"],
        "baseboard" => &["-q", "-t", "baseboard"],
        "chassis" => &["-q", "-t", "chassis"],
        "processor" => &["-q", "-t", "processor"],
        "memory" => &["-q", "-t", "memory"],
        "cache" => &["-q", "-t", "cache"],
        "connector" => &["-q", "-t", "connector"],
        "slot" => &["-q", "-t", "slot"],
        _ => &["-q"],
    }
}

fn bound_dmi_output(text: &str, budget: usize, section: &str) -> String {
    const NOTE_ROOM: usize = 120;
    let (mut kept, dropped) = keep_head(text, budget.saturating_sub(NOTE_ROOM));
    if dropped == 0 {
        return kept;
    }
    if !kept.is_empty() && !kept.ends_with('\n') {
        kept.push('\n');
    }
    if section == "all" {
        kept.push_str(&format!(
            "[{dropped} more lines left out to fit the output limit; pass section to narrow the output]\n"
        ));
    } else {
        kept.push_str(&format!(
            "[{dropped} more lines left out to fit the output limit]\n"
        ));
    }
    kept
}

async fn hardware_info(ctx: Ctx, args: Args, roots: Arc<Roots>) -> ToolResult {
    let section = args.str("section").unwrap_or("summary").to_string();
    let auth = ctx.authorize(None)?;
    let budget = ctx.output_budget();

    // Fail closed if `dmidecode` exists on disk but fails the root-ownership trust check.
    let dmi_cmd = ctx.optional_command("dmidecode")?;

    if let Some(cmd) = dmi_cmd {
        let argv = dmidecode_args(&section);
        match ctx.run(cmd.args(argv.iter().copied())).await {
            Ok(out) if command_ok(&out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                if section == "summary" {
                    let blocks = parse_dmidecode(&stdout);
                    let mut text = format_dmi_summary(&blocks);
                    if !text.is_empty() {
                        if out.truncated {
                            text.push_str(
                                "[output truncated: dmidecode produced more than is kept]\n",
                            );
                        }
                        return auth.ok(bound_dmi_output(&text, budget, &section));
                    }
                    // dmidecode exited cleanly but returned no summarized blocks; check sysfs.
                    let sys = roots.sys.clone();
                    let sysfs = blocking(ctx.clone(), move || Ok(read_sysfs_dmi(&sys))).await?;
                    let (body, has_data) = format_sysfs_dmi(&sysfs, &section);
                    if has_data {
                        let text = format!(
                            "[dmidecode returned no SMBIOS records; showing /sys/class/dmi/id]\n{body}"
                        );
                        return auth.ok(bound_dmi_output(&text, budget, &section));
                    }
                    return auth.ok(
                        "No SMBIOS/DMI hardware information is available on this host \
                         (common in containers and some virtual machines).\n",
                    );
                }

                let has_records = stdout.lines().any(|line| {
                    let t = line.trim();
                    !t.is_empty() && !t.starts_with('#')
                });
                if !has_records {
                    let msg = if section == "all" {
                        "No SMBIOS/DMI hardware information is available on this host \
                         (common in containers and some virtual machines).\n"
                            .to_string()
                    } else {
                        format!("No SMBIOS records for section {section:?} on this host.\n")
                    };
                    return auth.ok(msg);
                }
                let mut text = stdout.trim().to_string();
                text.push('\n');
                if out.truncated {
                    text.push_str("[output truncated: dmidecode produced more than is kept]\n");
                }
                return auth.ok(bound_dmi_output(&text, budget, &section));
            }
            Ok(out) => {
                let reason = complaint(&out);
                let sys = roots.sys.clone();
                let sysfs = blocking(ctx.clone(), move || Ok(read_sysfs_dmi(&sys))).await?;
                let (body, has_data) = format_sysfs_dmi(&sysfs, &section);
                let text = if has_data {
                    format!(
                        "[dmidecode failed ({reason}); falling back to /sys/class/dmi/id]\n{body}"
                    )
                } else if sysfs_supports_section(&section) {
                    format!(
                        "[dmidecode failed ({reason}); no DMI information is available under /sys/class/dmi/id]\n{body}"
                    )
                } else {
                    format!("[dmidecode failed ({reason})]\n{body}")
                };
                return auth.done(bound_dmi_output(&text, budget, &section), has_data);
            }
            Err(ToolError::Failed(problem)) => {
                let reason = shown(&problem, 300);
                let sys = roots.sys.clone();
                let sysfs = blocking(ctx.clone(), move || Ok(read_sysfs_dmi(&sys))).await?;
                let (body, has_data) = format_sysfs_dmi(&sysfs, &section);
                let text = if has_data {
                    format!(
                        "[dmidecode failed ({reason}); falling back to /sys/class/dmi/id]\n{body}"
                    )
                } else {
                    format!("[dmidecode failed ({reason})]\n{body}")
                };
                return auth.done(bound_dmi_output(&text, budget, &section), has_data);
            }
            Err(other) => return Err(other),
        }
    }

    // dmidecode is not installed: fall back to /sys/class/dmi/id.
    let sys = roots.sys.clone();
    let sysfs = blocking(ctx.clone(), move || Ok(read_sysfs_dmi(&sys))).await?;
    if !sysfs_supports_section(&section) {
        return auth.failed(format!(
            "the `dmidecode` command is not installed on this host (package dmidecode); \
             /sys/class/dmi/id does not provide {section} tables.\n"
        ));
    }
    let (body, has_data) = format_sysfs_dmi(&sysfs, &section);
    let note = if matches!(section.as_str(), "summary" | "all") {
        "[dmidecode is not installed (package dmidecode); showing basic information from \
         /sys/class/dmi/id — processors, memory slots and other SMBIOS tables require dmidecode]\n"
    } else {
        "[dmidecode is not installed (package dmidecode); showing basic information from \
         /sys/class/dmi/id]\n"
    };
    let text = if has_data {
        format!("{note}{body}")
    } else {
        format!(
            "{note}[no DMI information is available under /sys/class/dmi/id \
             (common in containers and some virtual machines)]\n{body}"
        )
    };
    auth.ok(bound_dmi_output(&text, budget, &section))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::testing::{FakeBins, call, find, host, ok_text};
    use crate::tools::{Host, ToolError, ToolResult};
    use serde_json::json;
    use std::fs;
    use std::path::Path;

    #[test]
    fn a_temperature_is_judged_against_the_limits_the_sensor_reports() {
        assert_eq!(
            temperature_status(45_000, Some(80_000), Some(100_000)),
            "ok"
        );
        assert_eq!(
            temperature_status(80_000, Some(80_000), Some(100_000)),
            "HIGH"
        );
        assert_eq!(
            temperature_status(100_000, Some(80_000), Some(100_000)),
            "CRITICAL"
        );
        assert_eq!(temperature_status(101_000, None, Some(100_000)), "CRITICAL");
        assert_eq!(temperature_status(90_000, Some(80_000), None), "HIGH");
        // no limits, or limits that are plainly not set
        assert_eq!(temperature_status(90_000, None, None), "ok");
        assert_eq!(temperature_status(40_000, Some(0), Some(0)), "ok");
        assert_eq!(temperature_status(40_000, Some(-273_150), Some(-1)), "ok");
        // a placeholder far beyond anything real (NVMe: 65261.85 C) is not a limit
        assert_eq!(
            temperature_status(62_000, Some(65_261_850), Some(65_261_850)),
            "ok"
        );
    }

    const SDR: &str = "\
Temp             | 01h | ok  |  3.1 | 38 degrees C
Fan1A            | 30h | ok  |  7.1 | 5040 RPM
PS2 Status       | 86h | cr  | 10.2 | Presence detected, Failure detected
Mem ECC Warning  | 1Bh | ns  | 34.1 | No Reading
Inlet Temp       | 04h | nc  |  7.1 | 44 degrees C
Intrusion        | 73h | ok  |  7.1 |
not a sensor line
";

    #[test]
    fn only_ipmi_sensors_that_are_not_ok_are_kept() {
        assert_eq!(
            sdr_not_ok(SDR),
            vec![
                SdrRow {
                    name: "PS2 Status".to_string(),
                    status: "cr".to_string(),
                    reading: "Presence detected, Failure detected".to_string(),
                },
                SdrRow {
                    name: "Inlet Temp".to_string(),
                    status: "nc".to_string(),
                    reading: "44 degrees C".to_string(),
                },
            ]
        );
        assert_eq!(sdr_not_ok(""), Vec::new());
    }

    fn put(root: &Path, path: &str, content: &str) {
        let full = root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, content).unwrap();
    }

    fn roots_of(dir: &tempfile::TempDir) -> Roots {
        fs::create_dir_all(dir.path().join("sys")).unwrap();
        fs::create_dir_all(dir.path().join("dev")).unwrap();
        Roots {
            sys: dir.path().join("sys"),
            dev: dir.path().join("dev"),
        }
    }

    /// A healthy server: two chips, clean memory counters, mains power.
    fn healthy() -> (tempfile::TempDir, Roots) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        put(root, "sys/class/dmi/id/sys_vendor", "Example Corp\n");
        put(root, "sys/class/dmi/id/product_name", "Server R1\n");
        put(root, "sys/class/dmi/id/bios_version", "2.4.1\n");
        put(root, "sys/class/dmi/id/bios_date", "03/14/2025\n");
        put(root, "sys/class/hwmon/hwmon0/name", "coretemp\n");
        put(root, "sys/class/hwmon/hwmon0/temp1_input", "45000\n");
        put(root, "sys/class/hwmon/hwmon0/temp1_label", "Package id 0\n");
        put(root, "sys/class/hwmon/hwmon0/temp1_max", "80000\n");
        put(root, "sys/class/hwmon/hwmon0/temp1_crit", "100000\n");
        put(root, "sys/class/hwmon/hwmon0/temp2_input", "41000\n");
        put(root, "sys/class/hwmon/hwmon0/temp2_label", "Core 0\n");
        put(root, "sys/class/hwmon/hwmon1/name", "nct6775\n");
        put(root, "sys/class/hwmon/hwmon1/fan1_input", "1200\n");
        put(root, "sys/class/hwmon/hwmon1/fan1_label", "CPU fan\n");
        // an unlabelled header with nothing plugged in: not a stopped fan
        put(root, "sys/class/hwmon/hwmon1/fan2_input", "0\n");
        put(root, "sys/devices/system/edac/mc/mc0/ce_count", "0\n");
        put(root, "sys/devices/system/edac/mc/mc0/ue_count", "0\n");
        put(
            root,
            "sys/devices/system/cpu/cpu0/thermal_throttle/core_throttle_count",
            "0\n",
        );
        put(
            root,
            "sys/devices/system/cpu/cpu1/thermal_throttle/core_throttle_count",
            "0\n",
        );
        put(root, "sys/class/power_supply/AC/type", "Mains\n");
        put(root, "sys/class/power_supply/AC/online", "1\n");
        let roots = roots_of(&dir);
        (dir, roots)
    }

    const ROLES: &str = r#"
[roles.reader]
allow = ["@read"]
[roles.hw]
allow = ["hardware.view"]
[roles.other]
allow = ["net.view"]
[unix_users.rita]
roles = ["reader"]
[unix_users.hank]
roles = ["hw"]
[unix_users.otto]
roles = ["other"]
"#;

    fn fixture(fake: &FakeBins) -> (std::sync::Arc<Host>, MemorySink) {
        host(&format!("{ROLES}{}", fake.config_only()))
    }

    async fn run(roots: &Roots, fake: &FakeBins, user: &str) -> (ToolResult, MemorySink) {
        let (host, sink) = fixture(fake);
        let tool = find(tools_with(roots.clone()), "hardware_health");
        (call(&host, user, &tool, json!({})).await, sink)
    }

    /// A shell fragment that prints `text`, using builtins only.
    fn emit(text: &str) -> String {
        format!(
            "while IFS= read -r line; do printf '%s\\n' \"$line\"; done <<'EOF'\n{}\nEOF\n",
            text.trim_end()
        )
    }

    #[tokio::test]
    async fn a_healthy_machine_says_so_and_shows_its_sensors() {
        let (_dir, roots) = healthy();
        let (result, _) = run(&roots, &FakeBins::new(), "rita").await;
        let text = ok_text(result);
        let first = text.lines().next().unwrap();
        assert!(
            first.starts_with("No hardware problems are visible"),
            "{first}"
        );
        assert!(first.contains("2 temperatures"), "{first}");
        assert!(first.contains("2 fans"), "{first}");
        assert!(
            text.contains("Machine: Example Corp Server R1; BIOS 2.4.1 (03/14/2025)"),
            "{text}"
        );
        assert!(text.contains("coretemp"), "{text}");
        assert!(text.contains("Package id 0"), "{text}");
        assert!(text.contains("45.0 C"), "{text}");
        assert!(text.contains("80.0 C"), "{text}");
        assert!(text.contains("100.0 C"), "{text}");
        assert!(text.contains("CPU fan"), "{text}");
        assert!(text.contains("1200 rpm"), "{text}");
        assert!(text.contains("mc0: 0 corrected, 0 uncorrected"), "{text}");
        assert!(text.contains("AC (Mains): online"), "{text}");
        assert!(
            text.contains("CPU thermal throttling: none since boot"),
            "{text}"
        );
        assert!(!text.contains("STOPPED"), "{text}");
    }

    #[tokio::test]
    async fn uncorrected_memory_errors_and_a_critical_temperature_are_problems() {
        let (dir, roots) = healthy();
        let root = dir.path();
        put(root, "sys/class/hwmon/hwmon0/temp1_input", "101000\n");
        put(root, "sys/class/hwmon/hwmon0/temp2_input", "85000\n");
        put(root, "sys/class/hwmon/hwmon0/temp2_max", "80000\n");
        put(root, "sys/class/hwmon/hwmon1/fan1_input", "0\n");
        put(root, "sys/devices/system/edac/mc/mc0/ce_count", "7\n");
        put(root, "sys/devices/system/edac/mc/mc0/ue_count", "2\n");
        put(
            root,
            "sys/devices/system/edac/mc/mc0/dimm0/dimm_label",
            "CPU1_DIMM_A1\n",
        );
        put(
            root,
            "sys/devices/system/edac/mc/mc0/dimm0/dimm_ce_count",
            "7\n",
        );
        put(
            root,
            "sys/devices/system/edac/mc/mc0/dimm0/dimm_ue_count",
            "2\n",
        );
        put(
            root,
            "sys/devices/system/edac/mc/mc0/dimm1/dimm_label",
            "CPU1_DIMM_A2\n",
        );
        put(
            root,
            "sys/devices/system/edac/mc/mc0/dimm1/dimm_ce_count",
            "0\n",
        );
        put(
            root,
            "sys/devices/system/edac/mc/mc0/dimm1/dimm_ue_count",
            "0\n",
        );
        put(
            root,
            "sys/devices/system/cpu/cpu1/thermal_throttle/core_throttle_count",
            "12\n",
        );
        let (result, _) = run(&roots, &FakeBins::new(), "rita").await;
        let text = ok_text(result);
        let first = text.lines().next().unwrap();
        assert!(first.starts_with("PROBLEM: "), "{first}");
        assert!(first.contains("2 uncorrected memory errors"), "{first}");
        assert!(
            first.contains("1 temperature at or above its critical value"),
            "{first}"
        );
        // lesser findings are warnings on the same line
        assert!(first.contains("Warnings: "), "{first}");
        assert!(first.contains("7 corrected memory errors"), "{first}");
        assert!(first.contains("CPU1_DIMM_A1"), "{first}");
        assert!(
            first.contains("1 temperature at or above its maximum"),
            "{first}"
        );
        assert!(first.contains("1 fan stopped"), "{first}");
        assert!(
            first.contains("12 CPU thermal throttling events"),
            "{first}"
        );
        assert!(text.contains("CRITICAL"), "{text}");
        assert!(text.contains("HIGH"), "{text}");
        assert!(text.contains("STOPPED"), "{text}");
        assert!(
            text.contains("CPU1_DIMM_A1: 7 corrected, 2 uncorrected"),
            "{text}"
        );
        // a DIMM without errors is not listed
        assert!(!text.contains("CPU1_DIMM_A2"), "{text}");
    }

    #[tokio::test]
    async fn a_machine_without_sensors_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let roots = roots_of(&dir);
        let (result, _) = run(&roots, &FakeBins::new(), "rita").await;
        let text = ok_text(result);
        let first = text.lines().next().unwrap();
        assert!(
            first.starts_with("No hardware sensors are visible on this host"),
            "{first}"
        );
        assert!(first.contains("virtual machine"), "{first}");
    }

    #[tokio::test]
    async fn chips_with_the_same_name_are_told_apart() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for n in [3, 4] {
            put(root, &format!("sys/class/hwmon/hwmon{n}/name"), "nvme\n");
            put(
                root,
                &format!("sys/class/hwmon/hwmon{n}/temp1_input"),
                "38000\n",
            );
        }
        let roots = roots_of(&dir);
        let (result, _) = run(&roots, &FakeBins::new(), "rita").await;
        let text = ok_text(result);
        assert!(text.contains("nvme/hwmon3"), "{text}");
        assert!(text.contains("nvme/hwmon4"), "{text}");
    }

    #[tokio::test]
    async fn a_limit_that_is_only_a_placeholder_is_not_shown() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        put(root, "sys/class/hwmon/hwmon0/name", "nvme\n");
        put(root, "sys/class/hwmon/hwmon0/temp2_input", "48850\n");
        put(root, "sys/class/hwmon/hwmon0/temp2_label", "Sensor 1\n");
        put(root, "sys/class/hwmon/hwmon0/temp2_max", "65261850\n");
        let roots = roots_of(&dir);
        let (result, _) = run(&roots, &FakeBins::new(), "rita").await;
        let text = ok_text(result);
        assert!(text.contains("48.9 C"), "{text}");
        assert!(!text.contains("65261"), "{text}");
        assert!(
            text.lines()
                .next()
                .unwrap()
                .starts_with("No hardware problems are visible"),
            "{text}"
        );
    }

    /// AIDEV-NOTE: a server with two power supplies keeps running on one, which is the
    /// point of having two, and exactly why a dead one goes unnoticed until the other
    /// fails. It was shown in the body and never reached the first line.
    #[tokio::test]
    async fn a_power_supply_that_is_offline_beside_one_that_is_online_is_a_warning() {
        let (dir, roots) = healthy();
        let root = dir.path();
        put(root, "sys/class/power_supply/PSU2/type", "Mains\n");
        put(root, "sys/class/power_supply/PSU2/online", "0\n");
        let (result, _) = run(&roots, &FakeBins::new(), "rita").await;
        let text = ok_text(result);
        assert_eq!(
            text.lines().next().unwrap(),
            "Warnings: 1 power supply offline while another is online (PSU2).",
            "{text}"
        );
        assert!(text.contains("PSU2 (Mains): offline"), "{text}");
    }

    #[tokio::test]
    async fn a_lone_mains_supply_that_is_offline_is_a_machine_on_battery_not_a_warning() {
        let (dir, roots) = healthy();
        let root = dir.path();
        put(root, "sys/class/power_supply/AC/online", "0\n");
        put(root, "sys/class/power_supply/BAT0/type", "Battery\n");
        put(root, "sys/class/power_supply/BAT0/status", "Discharging\n");
        put(root, "sys/class/power_supply/BAT0/capacity", "85\n");
        let (result, _) = run(&roots, &FakeBins::new(), "rita").await;
        let text = ok_text(result);
        assert!(
            text.lines()
                .next()
                .unwrap()
                .starts_with("No hardware problems are visible"),
            "{text}"
        );
        assert!(text.contains("AC (Mains): offline"), "{text}");
    }

    /// AIDEV-NOTE: fans that stop when the machine is cool are normal (laptops, quiet
    /// modes). A fan at 0 rpm is worth the first line only while something is hot.
    #[tokio::test]
    async fn a_stopped_fan_is_a_warning_only_while_a_temperature_is_high() {
        let (dir, roots) = healthy();
        let root = dir.path();
        put(root, "sys/class/hwmon/hwmon1/fan1_input", "0\n");
        let (result, _) = run(&roots, &FakeBins::new(), "rita").await;
        let text = ok_text(result);
        assert!(
            text.lines()
                .next()
                .unwrap()
                .starts_with("No hardware problems are visible"),
            "{text}"
        );
        let fan = text.lines().find(|line| line.contains("CPU fan")).unwrap();
        assert!(fan.ends_with("stopped"), "{fan}");
        assert!(!text.contains("STOPPED"), "{text}");
        assert!(
            text.contains("[1 fan is stopped; no temperature is at or above its maximum, so that is not counted as a fault]"),
            "{text}"
        );

        // the same fan with a temperature over its maximum: now it matters
        put(root, "sys/class/hwmon/hwmon0/temp1_input", "85000\n");
        let (result, _) = run(&roots, &FakeBins::new(), "rita").await;
        let text = ok_text(result);
        let first = text.lines().next().unwrap();
        assert!(first.starts_with("Warnings: "), "{first}");
        assert!(
            first.contains("1 fan stopped while a temperature is at or above its maximum"),
            "{first}"
        );
        let fan = text.lines().find(|line| line.contains("CPU fan")).unwrap();
        assert!(fan.ends_with("STOPPED"), "{fan}");
    }

    #[tokio::test]
    async fn a_battery_shows_its_state_and_charge() {
        let (dir, roots) = healthy();
        let root = dir.path();
        put(root, "sys/class/power_supply/BAT0/type", "Battery\n");
        put(root, "sys/class/power_supply/BAT0/status", "Discharging\n");
        put(root, "sys/class/power_supply/BAT0/capacity", "85\n");
        let (result, _) = run(&roots, &FakeBins::new(), "rita").await;
        let text = ok_text(result);
        assert!(text.contains("BAT0 (Battery): Discharging, 85%"), "{text}");
    }

    const MCE_LINES: &str = "\
2026-11-19T03:12:44+0000 web1 kernel: mce: [Hardware Error]: Machine check events logged
2026-11-19T03:12:44+0000 web1 kernel: mce: [Hardware Error]: CPU 3: Machine Check: 0 Bank 7
";

    #[tokio::test]
    async fn hardware_errors_in_the_kernel_log_are_a_warning() {
        let (_dir, roots) = healthy();
        let fake = FakeBins::new().add("journalctl", MCE_LINES, 0);
        let (result, _) = run(&roots, &fake, "rita").await;
        let text = ok_text(result);
        let first = text.lines().next().unwrap();
        assert!(first.starts_with("Warnings: "), "{first}");
        assert!(
            first.contains("2 hardware-error lines in the kernel log"),
            "{first}"
        );
        assert!(text.contains("CPU 3: Machine Check: 0 Bank 7"), "{text}");
        let calls = fake.calls("journalctl");
        assert_eq!(calls.len(), 1);
        let args = &calls[0];
        // not --dmesg: that would search the current boot only (see `kernel_log_text`)
        assert!(
            !args.iter().any(|a| a == "--dmesg" || a == "-k"),
            "{args:?}"
        );
        assert_eq!(args.last().map(String::as_str), Some("_TRANSPORT=kernel"));
        for want in ["--no-pager", "--quiet", "--output=short-iso", "--since=-7d"] {
            assert!(args.iter().any(|a| a == want), "{want}: {args:?}");
        }
        assert!(
            args.iter()
                .any(|a| a == "--grep=mce:|Machine check|Hardware Error"),
            "{args:?}"
        );
    }

    #[tokio::test]
    async fn an_empty_kernel_log_search_says_none() {
        let (_dir, roots) = healthy();
        // journalctl exits 1 when --grep matches nothing
        let fake = FakeBins::new().add("journalctl", "", 1);
        let (result, _) = run(&roots, &fake, "rita").await;
        let text = ok_text(result);
        assert!(
            text.lines()
                .next()
                .unwrap()
                .starts_with("No hardware problems are visible"),
            "{text}"
        );
        assert!(
            text.contains("Hardware errors in the kernel log (last 7 days): none"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn the_kernel_log_part_needs_its_own_permission() {
        let (_dir, roots) = healthy();
        let fake = FakeBins::new().add("journalctl", MCE_LINES, 0);
        let (result, _) = run(&roots, &fake, "hank").await;
        let text = ok_text(result);
        assert!(
            text.contains("[hardware errors in the kernel log left out: needs kernel_log.view]"),
            "{text}"
        );
        assert!(!text.contains("Machine Check"), "{text}");
        // the journal was never asked
        assert_eq!(fake.calls("journalctl").len(), 0);
    }

    const SEL: &str = "\
   1 | 11/19/2026 | 03:12:40 | Power Supply PS2 Status | Failure detected | Asserted
   2 | 11/19/2026 | 03:20:11 | Temperature Inlet Temp | Upper Non-critical going high | Asserted
";

    fn ipmitool() -> String {
        format!(
            "case \"$1\" in\nsdr) {};;\nsel) {};;\n*) exit 2;;\nesac\n",
            emit(SDR),
            emit(SEL)
        )
    }

    #[tokio::test]
    async fn ipmi_sensors_that_are_not_ok_and_the_event_log_are_shown() {
        let (dir, roots) = healthy();
        put(dir.path(), "dev/ipmi0", "");
        let fake = FakeBins::new().add_script("ipmitool", &ipmitool());
        let (result, _) = run(&roots, &fake, "hank").await;
        let text = ok_text(result);
        let first = text.lines().next().unwrap();
        // a critical IPMI sensor is a problem; a non-critical one a warning
        assert!(first.starts_with("PROBLEM: "), "{first}");
        assert!(first.contains("1 IPMI sensor is critical"), "{first}");
        assert!(first.contains("1 IPMI sensor is not ok"), "{first}");
        assert!(text.contains("PS2 Status"), "{text}");
        assert!(text.contains("Failure detected"), "{text}");
        assert!(text.contains("Inlet Temp"), "{text}");
        // sensors that are fine are not listed
        assert!(!text.contains("Fan1A"), "{text}");
        assert!(!text.contains("Mem ECC Warning"), "{text}");
        assert!(text.contains("Upper Non-critical going high"), "{text}");
        assert_eq!(
            fake.calls("ipmitool"),
            vec![
                vec!["sdr".to_string(), "elist".to_string()],
                vec![
                    "sel".to_string(),
                    "elist".to_string(),
                    "last".to_string(),
                    "10".to_string()
                ],
            ]
        );
    }

    #[tokio::test]
    async fn ipmitool_is_not_run_on_a_machine_without_an_ipmi_device() {
        let (_dir, roots) = healthy();
        let fake = FakeBins::new().add_script("ipmitool", &ipmitool());
        let (result, _) = run(&roots, &fake, "hank").await;
        let text = ok_text(result);
        assert_eq!(fake.calls("ipmitool").len(), 0);
        assert!(text.contains("no IPMI device"), "{text}");
    }

    #[tokio::test]
    async fn an_ipmitool_that_fails_is_a_note_not_a_failure() {
        let (dir, roots) = healthy();
        put(dir.path(), "dev/ipmi/0", "");
        let fake = FakeBins::new().add_script(
            "ipmitool",
            "echo 'Could not open device at /dev/ipmi0' >&2\nexit 1\n",
        );
        let (result, _) = run(&roots, &fake, "hank").await;
        let text = ok_text(result);
        assert!(text.contains("Could not open device"), "{text}");
        assert!(
            text.lines()
                .next()
                .unwrap()
                .starts_with("No hardware problems are visible"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn an_ipmitool_that_hangs_does_not_take_the_answer_with_it() {
        let (dir, roots) = healthy();
        put(dir.path(), "dev/ipmi0", "");
        let fake = FakeBins::new().add_script("ipmitool", "while :; do :; done\n");
        let (host, _sink) = host(&format!(
            "{ROLES}[limits]\ncommand_timeout_secs = 1\ncall_timeout_secs = 4\n{}",
            fake.config_only()
        ));
        let tool = find(tools_with(roots.clone()), "hardware_health");
        let text = ok_text(call(&host, "hank", &tool, json!({})).await);
        assert!(text.contains("Package id 0"), "{text}");
        assert!(text.contains("time limit"), "{text}");
    }

    #[tokio::test]
    async fn the_call_is_authorized_and_audited() {
        let (_dir, roots) = healthy();
        let (result, sink) = run(&roots, &FakeBins::new(), "otto").await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        let records = sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["decision"], "deny");

        let (result, sink) = run(&roots, &FakeBins::new(), "hank").await;
        ok_text(result);
        let records = sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["decision"], "allow");
        assert_eq!(records[0]["permission"], "hardware.view");
    }

    #[tokio::test]
    async fn host_text_cannot_add_lines_of_its_own() {
        let (dir, roots) = healthy();
        put(
            dir.path(),
            "sys/class/hwmon/hwmon0/temp1_label",
            "Package\nPROBLEM: made up\n",
        );
        put(
            dir.path(),
            "sys/class/dmi/id/product_name",
            "R1\nNo hardware problems\n",
        );
        let (result, _) = run(&roots, &FakeBins::new(), "rita").await;
        let text = ok_text(result);
        assert!(
            !text
                .lines()
                .any(|line| line.starts_with("PROBLEM: made up")),
            "{text}"
        );
        assert_eq!(
            text.lines()
                .filter(|line| line.starts_with("No hardware problems"))
                .count(),
            1,
            "{text}"
        );
    }

    // ---- hardware_info tests ---------------------------------------------------------

    const SAMPLE_DMI: &str = "\
# dmidecode 3.5
BIOS Information
\tVendor: Dell Inc.
\tVersion: 2.18.0
\tRelease Date: 03/15/2025
\tBIOS Revision: 2.18
\tFirmware Revision: 6.10
\tCharacteristics:
\t\tPCI is supported
\t\tUEFI is supported

System Information
\tManufacturer: Dell Inc.
\tProduct Name: PowerEdge R750
\tVersion: Not Specified
\tSerial Number: ABC1234
\tUUID: 4c4c4544-0042-3110-8032-c3c04f333431
\tSKU Number: SKU=NotProvided;ModelName=PowerEdge R750
\tFamily: PowerEdge

Base Board Information
\tManufacturer: Dell Inc.
\tProduct Name: 06V45N
\tVersion: A01
\tSerial Number: .ABC1234.CNIVC001.

Chassis Information
\tManufacturer: Dell Inc.
\tType: Rack Mount Chassis
\tVersion: To Be Filled By O.E.M.
\tSerial Number: ABC1234
\tAsset Tag: RACK-A4-U12

Processor Information
\tSocket Designation: CPU1
\tType: Central Processor
\tManufacturer: Intel(R) Corporation
\tVersion: Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz
\tMax Speed: 4000 MHz
\tCurrent Speed: 2000 MHz
\tStatus: Populated, Enabled
\tCore Count: 32
\tCore Enabled: 32
\tThread Count: 64

Processor Information
\tSocket Designation: CPU2
\tType: Central Processor
\tVersion: Not Specified
\tStatus: Unpopulated

Physical Memory Array
\tLocation: System Board Or Motherboard
\tUse: System Memory
\tError Correction Type: Multi-bit ECC
\tMaximum Capacity: 4 TB
\tNumber Of Devices: 4

Physical Memory Array
\tLocation: System Board Or Motherboard
\tUse: Flash Memory
\tError Correction Type: None
\tMaximum Capacity: 32 MB
\tNumber Of Devices: 1

Memory Device
\tSize: 32 GB
\tLocator: A1
\tBank Locator: Not Specified
\tType: DDR4
\tSpeed: 3200 MT/s
\tConfigured Memory Speed: 2933 MT/s
\tManufacturer: Samsung
\tSerial Number: 12345678
\tPart Number: M393A4K40DB3-CWE

Memory Device
\tSize: No Module Installed
\tLocator: A2
\tType: Unknown
\tSpeed: Unknown
\tManufacturer: Not Specified
\tSerial Number: Not Specified
\tPart Number: Not Specified

Memory Device
\tSize: 32768 MB
\tLocator: B1
\tType: DDR4
\tSpeed: 3200 MT/s
\tConfigured Memory Speed: 3200 MT/s
\tManufacturer: Samsung
\tSerial Number: 12345679
\tPart Number: M393A4K40DB3-CWE

Memory Device
\tSize: No Module Installed
\tLocator: B2
\tType: Unknown
";

    async fn run_info(
        roots: &Roots,
        fake: &FakeBins,
        user: &str,
        arguments: serde_json::Value,
    ) -> (ToolResult, MemorySink) {
        let (host, sink) = fixture(fake);
        let tool = find(tools_with(roots.clone()), "hardware_info");
        (call(&host, user, &tool, arguments).await, sink)
    }

    #[test]
    fn parse_dmidecode_handles_quiet_and_verbose_output_and_lists() {
        let verbose = "\
# dmidecode 3.5
Handle 0x0000, DMI type 0, 26 bytes
BIOS Information
\tVendor: Example BIOS
\tVersion: 1.0:beta
\tCharacteristics:
\t\tPCI is supported
\t\tUEFI is supported

Handle 0x0001, DMI type 127, 4 bytes
End Of Table
";
        let blocks = parse_dmidecode(verbose);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].title, "BIOS Information");
        assert_eq!(blocks[0].field("Vendor"), Some("Example BIOS"));
        assert_eq!(blocks[0].field("Version"), Some("1.0:beta"));
        assert_eq!(
            blocks[0].list("Characteristics"),
            ["PCI is supported", "UEFI is supported"]
        );
    }

    #[test]
    fn memory_size_parsing_and_formatting_handle_smbios_units() {
        assert_eq!(parse_dmi_memory_kib("32 GB"), Some(32 * 1024 * 1024));
        assert_eq!(parse_dmi_memory_kib("16384 MB"), Some(16 * 1024 * 1024));
        assert_eq!(parse_dmi_memory_kib("1 TB"), Some(1024 * 1024 * 1024));
        assert_eq!(parse_dmi_memory_kib("512 kB"), Some(512));
        assert_eq!(parse_dmi_memory_kib("No Module Installed"), None);
        assert_eq!(parse_dmi_memory_kib("0 MB"), None);
        assert_eq!(parse_dmi_memory_kib("999999999999 TB"), None);

        assert_eq!(format_dmi_kib(64 * 1024 * 1024), "64 GB");
        assert_eq!(format_dmi_kib(1536 * 1024), "1.5 GB");
        assert_eq!(format_dmi_kib(4 * 1024 * 1024 * 1024), "4 TB");
        assert_eq!(format_dmi_kib(512 * 1024), "512 MB");
        assert_eq!(format_dmi_kib(512), "512 kB");
    }

    #[tokio::test]
    async fn hardware_info_summarizes_dmidecode_sections_and_omits_placeholders() {
        let dir = tempfile::tempdir().unwrap();
        let roots = roots_of(&dir);
        let fake = FakeBins::new().add("dmidecode", SAMPLE_DMI, 0);
        let (result, _) = run_info(&roots, &fake, "hank", json!({})).await;
        let text = ok_text(result);

        assert!(
            text.starts_with("Machine: Dell Inc. PowerEdge R750; BIOS 2.18.0 (03/15/2025)\n"),
            "{text}"
        );
        assert!(text.contains("== system =="), "{text}");
        assert!(text.contains("ABC1234"), "{text}");
        assert!(
            text.contains("4c4c4544-0042-3110-8032-c3c04f333431"),
            "{text}"
        );
        assert!(text.contains("== BIOS =="), "{text}");
        assert!(text.contains("Boot Mode:     UEFI"), "{text}");
        assert!(text.contains("== baseboard =="), "{text}");
        assert!(text.contains("06V45N"), "{text}");
        assert!(text.contains("== chassis =="), "{text}");
        assert!(text.contains("Rack Mount Chassis"), "{text}");
        assert!(text.contains("RACK-A4-U12"), "{text}");
        // vendor placeholders are filtered out
        assert!(!text.contains("Not Specified"), "{text}");
        assert!(!text.contains("To Be Filled By O.E.M."), "{text}");
        // processors
        assert!(text.contains("== processors =="), "{text}");
        assert!(text.contains("32c/64t"), "{text}");
        assert!(text.contains("2000 MHz (max 4000 MHz)"), "{text}");
        assert!(text.contains("Unpopulated"), "{text}");
        // memory: 32 GB + 32768 MB = 64 GB across 2 of 4 slots, System Memory array (not Flash)
        assert!(
            text.contains("Total: 64 GB installed across 2 of 4 slots (max 4 TB, Multi-bit ECC)"),
            "{text}"
        );
        assert!(text.contains("2933 MT/s (max 3200 MT/s)"), "{text}");
        assert!(text.contains("M393A4K40DB3-CWE"), "{text}");
        assert!(text.contains("Empty slots: 2 (A2, B2)"), "{text}");

        assert_eq!(
            fake.calls("dmidecode"),
            vec![vec![
                "-q",
                "-t",
                "bios",
                "-t",
                "system",
                "-t",
                "baseboard",
                "-t",
                "chassis",
                "-t",
                "processor",
                "-t",
                "memory"
            ]]
        );
    }

    #[tokio::test]
    async fn hardware_info_returns_detailed_output_for_a_specific_section() {
        let dir = tempfile::tempdir().unwrap();
        let roots = roots_of(&dir);
        let mem_only = "Memory Device\n\tSize: 32 GB\n\tLocator: A1\n";
        let fake = FakeBins::new().add("dmidecode", mem_only, 0);

        let (result, _) = run_info(&roots, &fake, "hank", json!({"section": "memory"})).await;
        let text = ok_text(result);
        assert!(text.contains("Memory Device"), "{text}");
        assert!(text.contains("Size: 32 GB"), "{text}");
        assert_eq!(fake.calls("dmidecode"), vec![vec!["-q", "-t", "memory"]]);

        let (result, _) = run_info(&roots, &fake, "hank", json!({"section": "all"})).await;
        ok_text(result);
        assert_eq!(fake.calls("dmidecode")[1], vec!["-q"]);
    }

    #[tokio::test]
    async fn hardware_info_reports_empty_section_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let roots = roots_of(&dir);
        let fake = FakeBins::new().add("dmidecode", "# dmidecode 3.5\n", 0);
        let (result, _) = run_info(&roots, &fake, "hank", json!({"section": "slot"})).await;
        let text = ok_text(result);
        assert!(
            text.contains("No SMBIOS records for section \"slot\""),
            "{text}"
        );
        assert_eq!(fake.calls("dmidecode"), vec![vec!["-q", "-t", "slot"]]);
    }

    #[tokio::test]
    async fn hardware_info_falls_back_to_sysfs_when_dmidecode_is_missing() {
        let (dir, roots) = healthy();
        let root = dir.path();
        put(root, "sys/class/dmi/id/board_vendor", "Supermicro\n");
        put(root, "sys/class/dmi/id/board_name", "X12DPi-N6\n");
        put(root, "sys/class/dmi/id/chassis_type", "23\n");
        put(
            root,
            "sys/class/dmi/id/product_version",
            "To Be Filled By O.E.M.\n",
        );

        // summary falls back to /sys/class/dmi/id
        let (result, _) = run_info(&roots, &FakeBins::new(), "hank", json!({})).await;
        let text = ok_text(result);
        assert!(text.contains("dmidecode is not installed"), "{text}");
        assert!(
            text.contains("Machine: Example Corp Server R1; BIOS 2.4.1 (03/14/2025)"),
            "{text}"
        );
        assert!(text.contains("X12DPi-N6"), "{text}");
        assert!(text.contains("Rack Mount Chassis"), "{text}");
        assert!(!text.contains("To Be Filled By O.E.M."), "{text}");

        // bios section falls back to only BIOS fields
        let (result, _) =
            run_info(&roots, &FakeBins::new(), "hank", json!({"section": "bios"})).await;
        let text = ok_text(result);
        assert!(text.contains("== BIOS =="), "{text}");
        assert!(text.contains("2.4.1"), "{text}");
        assert!(!text.contains("== baseboard =="), "{text}");

        // memory section cannot be served from /sys/class/dmi/id
        let (result, _) = run_info(
            &roots,
            &FakeBins::new(),
            "hank",
            json!({"section": "memory"}),
        )
        .await;
        let output = result.unwrap();
        assert!(output.is_error(), "{output:?}");
        assert!(output.text().contains("dmidecode"), "{}", output.text());
        assert!(output.text().contains("memory"), "{}", output.text());
    }

    #[tokio::test]
    async fn hardware_info_falls_back_to_sysfs_when_dmidecode_fails() {
        let (_dir, roots) = healthy();
        let fake = FakeBins::new().add_script(
            "dmidecode",
            "echo '/sys/firmware/dmi/tables/smbios_entry_point: Permission denied' >&2\nexit 1\n",
        );

        let (result, _) = run_info(&roots, &fake, "hank", json!({})).await;
        let text = ok_text(result);
        assert!(text.contains("Permission denied"), "{text}");
        assert!(text.contains("falling back to /sys/class/dmi/id"), "{text}");
        assert!(text.contains("Example Corp"), "{text}");

        // memory section reports failure when dmidecode fails
        let (result, _) = run_info(&roots, &fake, "hank", json!({"section": "memory"})).await;
        let output = result.unwrap();
        assert!(output.is_error(), "{output:?}");
        assert!(
            output.text().contains("Permission denied"),
            "{}",
            output.text()
        );
    }

    #[tokio::test]
    async fn hardware_info_handles_a_container_without_dmi_gracefully() {
        let dir = tempfile::tempdir().unwrap();
        let roots = roots_of(&dir);
        let (result, _) = run_info(&roots, &FakeBins::new(), "hank", json!({})).await;
        let text = ok_text(result);
        assert!(text.contains("no DMI information is available"), "{text}");
    }

    #[tokio::test]
    async fn hardware_info_is_authorized_and_audited() {
        let dir = tempfile::tempdir().unwrap();
        let roots = roots_of(&dir);
        let fake = FakeBins::new().add("dmidecode", SAMPLE_DMI, 0);

        let (result, sink) = run_info(&roots, &fake, "otto", json!({})).await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        assert_eq!(fake.calls("dmidecode").len(), 0);
        let records = sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["decision"], "deny");

        let (result, sink) = run_info(&roots, &fake, "hank", json!({})).await;
        ok_text(result);
        let records = sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["decision"], "allow");
        assert_eq!(records[0]["permission"], "hardware.view");
    }

    #[tokio::test]
    async fn hardware_info_rejects_unknown_sections_and_sanitizes_firmware_text() {
        let dir = tempfile::tempdir().unwrap();
        let roots = roots_of(&dir);
        let evil =
            "System Information\n\tManufacturer: Evil\x1b[31mCorp\u{e0041}\n\tProduct Name: Box\n";
        let fake = FakeBins::new().add("dmidecode", evil, 0);

        let (result, _) = run_info(&roots, &fake, "hank", json!({"section": "--dump"})).await;
        assert!(matches!(result, Err(ToolError::Invalid(_))), "{result:?}");
        assert_eq!(fake.calls("dmidecode").len(), 0);

        // summary mode cleans escape sequences and invisible Unicode tag characters
        let (result, _) = run_info(&roots, &fake, "hank", json!({})).await;
        let text = ok_text(result);
        assert!(!text.contains('\x1b'), "{text:?}");
        assert!(!text.contains('\u{e0041}'), "{text:?}");
        assert!(text.contains("\\x1b"), "{text:?}");
        assert!(text.contains("\\u{e0041}"), "{text:?}");

        // raw section mode cleans them too
        let (result, _) = run_info(&roots, &fake, "hank", json!({"section": "system"})).await;
        let text = ok_text(result);
        assert!(!text.contains('\x1b'), "{text:?}");
        assert!(!text.contains('\u{e0041}'), "{text:?}");
    }

    #[tokio::test]
    async fn hardware_info_truncates_large_all_output_with_a_hint() {
        let dir = tempfile::tempdir().unwrap();
        let roots = roots_of(&dir);
        let big: String = (0..200)
            .map(|i| format!("OEM Strings\n\tString {i}: some firmware entry number {i}\n\n"))
            .collect();
        let fake = FakeBins::new().add("dmidecode", &big, 0);
        let (host, _sink) = host(&format!(
            "{ROLES}[limits]\nmax_output_bytes = 1024\n{}",
            fake.config_only()
        ));
        let tool = find(tools_with(roots.clone()), "hardware_info");
        let text = ok_text(call(&host, "hank", &tool, json!({"section": "all"})).await);
        assert!(text.contains("more lines left out"), "{text}");
        assert!(text.contains("pass section to narrow"), "{text}");
    }
}
