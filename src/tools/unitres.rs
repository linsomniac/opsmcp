//! Unit resource limits and dependencies: what a unit's control group allows and has run
//! into (cgroup_limits), changing those limits on a running unit (service_limits), and
//! what a unit needs and is needed by (service_dependencies).

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use super::args::{Args, Param};
use super::service::{self, normalize_unit};
use super::{
    CallClock, Ctx, Tool, ToolError, ToolResult, blocking, command_ok, command_text, format_table,
    one_line_cell, required,
};
use crate::exec::CmdOutput;
use crate::policy::Access;
use crate::sanitize::{keep_head, redact_text};
use crate::timefmt::{human_bytes, human_duration};

/// Where the unified cgroup hierarchy is mounted. A parameter so that tests can point it
/// at a temporary directory; the server always uses the default.
#[derive(Clone, Debug)]
pub struct Roots {
    /// `/sys/fs/cgroup`
    pub cgroup: PathBuf,
}

impl Default for Roots {
    fn default() -> Self {
        Roots {
            cgroup: PathBuf::from("/sys/fs/cgroup"),
        }
    }
}

const DIRECTIONS: [&str; 3] = ["needs", "needed_by", "both"];

pub fn tools() -> Vec<Tool> {
    tools_with(Roots::default())
}

/// The tools, reading control groups under `roots`.
pub fn tools_with(roots: Roots) -> Vec<Tool> {
    let roots = Arc::new(roots);
    let (view_roots, change_roots) = (roots.clone(), roots);
    vec![
        Tool::new(
            "cgroup_limits",
            "Show what a unit's control group allows and what it has run into: memory in use \
             against its limit, how often the limit was hit and how many processes the kernel \
             killed for it (OOM kills), the CPU quota and how much the unit was throttled, \
             tasks against the task limit, and pressure. Name a unit for the detail; without \
             one, lists every service, container and session that has a limit set or has hit \
             one, problems first. Use it to answer 'is this service being throttled, or \
             running out of memory?'. For what is using the machine right now use \
             resource_top.",
            Access::Read,
            "service.view",
            vec![
                Param::str(
                    "unit",
                    "Unit name, e.g. nginx or nginx.service. Leave out to list every unit \
                     that has a limit or has hit one",
                )
                .max_len(255),
                Param::int(
                    "limit",
                    "Most units to list when no unit is named (default 50)",
                    1,
                    200,
                ),
            ],
            move |ctx, args| cgroup_limits(view_roots.clone(), ctx, args),
        ),
        Tool::new(
            "service_limits",
            "Set a memory, CPU or task limit on a running systemd service or scope without \
             restarting it (systemctl set-property --runtime). The limit applies at once and \
             lasts until the next reboot: nothing is written to the unit's configuration. A \
             memory limit below what the unit is using makes the kernel kill its processes, \
             so that, a limit under 16M, a high mark below what the unit is using, a CPU \
             quota under 10% and a task limit below the unit's current tasks are refused \
             unless force is set. Units the host's configuration marks as protected cannot \
             be changed, and neither can slices (a slice's limit holds back everything in \
             it). Give at least one limit.",
            Access::Write,
            "service.limits",
            vec![
                Param::str(
                    "unit",
                    "Unit name: a service or a scope, e.g. nginx or nginx.service",
                )
                .max_len(255)
                .required(),
                Param::str(
                    "memory_max",
                    "Hard memory limit: a number of bytes, optionally with K, M, G or T \
                     (powers of 1024), e.g. 2G; or infinity to remove the limit",
                )
                .max_len(20),
                Param::str(
                    "memory_high",
                    "Memory level above which the kernel slows the unit down and reclaims \
                     from it, without killing anything; same form as memory_max",
                )
                .max_len(20),
                Param::int(
                    "cpu_quota_percent",
                    "CPU time allowed, as a percentage of one CPU (200 is two CPUs); 0 \
                     removes the quota",
                    0,
                    100_000,
                ),
                Param::int(
                    "tasks_max",
                    "Most tasks (processes and threads) the unit may have; 0 removes the limit",
                    0,
                    4_194_304,
                ),
                Param::bool(
                    "force",
                    "Set the limit even if it is below what the unit is using now, or would \
                     all but stop it",
                ),
            ],
            move |ctx, args| service_limits(change_roots.clone(), ctx, args),
        ),
        Tool::new(
            "service_dependencies",
            "Show what a systemd unit needs and what needs it: its state, requirements that \
             have failed or are not active, a start condition that was not met, the \
             Requires, Wants and After lists, the dependency trees, and the chain of units \
             it waited for at boot. Use it to find out why a unit did not start, or what \
             stopping it would affect.",
            Access::Read,
            "service.view",
            vec![
                Param::str("unit", "Unit name, e.g. nginx or nginx.service")
                    .max_len(255)
                    .required(),
                Param::choice(
                    "direction",
                    "needs: what the unit depends on; needed_by: what depends on it; both \
                     (the default)",
                    &DIRECTIONS,
                ),
            ],
            service_dependencies,
        ),
    ]
}

// ---- reading systemd -------------------------------------------------------------------

/// `systemctl show` output for one or more units as one map per unit. systemctl puts an
/// empty line between units; only the first `=` on a line separates name from value.
pub(super) fn property_blocks(text: &str) -> Vec<BTreeMap<String, String>> {
    let mut blocks = Vec::new();
    let mut current = BTreeMap::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            if !current.is_empty() {
                blocks.push(std::mem::take(&mut current));
            }
            continue;
        }
        if let Some((name, value)) = line.split_once('=') {
            current.insert(name.to_string(), value.to_string());
        }
    }
    if !current.is_empty() {
        blocks.push(current);
    }
    blocks
}

/// `systemctl show` for these properties of these units.
///
/// AIDEV-NOTE: every property is its own `--property=` argument. systemctl also takes a
/// comma-separated list, but loginctl (which shares this style) silently prints nothing
/// for one, so the one form that works everywhere is used. The units come after `--`.
async fn show(
    ctx: &Ctx,
    units: &[String],
    properties: &[&str],
    limit: Option<Duration>,
) -> Result<CmdOutput, ToolError> {
    let mut argv = vec!["show".to_string()];
    argv.extend(properties.iter().map(|p| format!("--property={p}")));
    argv.push("--".to_string());
    argv.extend(units.iter().cloned());
    let mut cmd = ctx.command("systemctl")?.args(argv);
    if let Some(limit) = limit {
        cmd = cmd.timeout(limit);
    }
    ctx.run(cmd).await
}

/// The properties of one unit, or a failure saying why they could not be had.
async fn show_one(
    ctx: &Ctx,
    unit: &str,
    properties: &[&str],
) -> Result<BTreeMap<String, String>, ToolError> {
    let out = show(ctx, &[unit.to_string()], properties, None).await?;
    if !command_ok(&out) {
        return Err(ToolError::Failed(format!(
            "cannot read the properties of {unit}: {}",
            command_text(&out).trim()
        )));
    }
    Ok(property_blocks(&String::from_utf8_lossy(&out.stdout))
        .into_iter()
        .next()
        .unwrap_or_default())
}

// ---- reading control groups ------------------------------------------------------------

/// A limit file's content: a number, or `max` for no limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limit {
    Unlimited,
    At(u64),
}

/// `cpu.max`: the CPU time allowed per period, both in microseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuMax {
    /// `None`: no quota.
    pub quota: Option<u64>,
    pub period: u64,
}

/// What one control group allows, uses and has run into. Anything that could not be read
/// (a controller that is not enabled for the group) is absent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Figures {
    pub memory_current: Option<u64>,
    pub memory_max: Option<Limit>,
    pub memory_high: Option<Limit>,
    pub swap_current: Option<u64>,
    /// `memory.events`: low, high, max, oom, oom_kill.
    pub memory_events: BTreeMap<String, u64>,
    /// The main lines of `memory.stat` (see `MEMORY_PARTS`).
    pub memory_stat: BTreeMap<String, u64>,
    pub cpu_max: Option<CpuMax>,
    /// `cpu.stat`: usage_usec, nr_periods, nr_throttled, throttled_usec...
    pub cpu_stat: BTreeMap<String, u64>,
    pub pids_current: Option<u64>,
    pub pids_max: Option<Limit>,
    /// `pids.events`: max.
    pub pids_events: BTreeMap<String, u64>,
    /// Per resource (cpu, memory, io): the share of time some task was stalled over the
    /// last 10 and 60 seconds, as the kernel prints them.
    pub pressure: Vec<(String, String, String)>,
}

/// The lines of memory.stat that say what the memory is used for.
const MEMORY_PARTS: [&str; 6] = ["anon", "file", "kernel", "slab", "shmem", "sock"];
/// A use of this share of a limit, or more, counts as being at the limit.
const NEAR_PERCENT: u128 = 90;
/// The share of CPU periods (in percent) from which being throttled counts as a problem.
const THROTTLED_PROBLEM_PERCENT: u128 = 1;
/// No control file read here is anywhere near this long.
const MAX_FILE_BYTES: u64 = 64 * 1024;

/// The directory of a control group, relative to the hierarchy's root, from the path
/// systemd reports (`/system.slice/nginx.service`).
///
/// AIDEV-NOTE: the path comes from systemd, not from the caller, but it is joined onto a
/// directory we then read from, so it is held to the shape a control group path has: it
/// starts at the root and no part of it is empty, `.` or `..`. Anything else is refused
/// rather than cleaned up.
pub fn cgroup_dir(control_group: &str) -> Option<PathBuf> {
    let rest = control_group.strip_prefix('/')?;
    if rest.is_empty() {
        return Some(PathBuf::new());
    }
    let mut dir = PathBuf::new();
    for part in rest.split('/') {
        if part.is_empty() || part == "." || part == ".." || part.contains('\0') {
            return None;
        }
        dir.push(part);
    }
    Some(dir)
}

/// Lines of `NAME NUMBER` (memory.events, cpu.stat, memory.stat, pids.events) as a map.
/// Lines of any other shape are skipped.
pub fn keyed(text: &str) -> BTreeMap<String, u64> {
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        if let (Some(name), Some(value), None) = (fields.next(), fields.next(), fields.next())
            && let Ok(value) = value.parse()
        {
            map.insert(name.to_string(), value);
        }
    }
    map
}

/// The content of a limit file (memory.max, pids.max...).
pub fn parse_limit(text: &str) -> Option<Limit> {
    match text.trim() {
        "max" => Some(Limit::Unlimited),
        number => number.parse().ok().map(Limit::At),
    }
}

/// The content of cpu.max: `QUOTA PERIOD`, where the quota may be `max`.
pub fn parse_cpu_max(text: &str) -> Option<CpuMax> {
    let mut fields = text.split_whitespace();
    let quota = match fields.next()? {
        "max" => None,
        number => Some(number.parse().ok()?),
    };
    let period: u64 = fields.next()?.parse().ok()?;
    (period > 0).then_some(CpuMax { quota, period })
}

/// The 10 and 60 second averages of a pressure file's `some` line.
pub fn parse_some_pressure(text: &str) -> Option<(String, String)> {
    let line = text
        .lines()
        .find(|line| line.split_whitespace().next() == Some("some"))?;
    let average = |name: &str| -> Option<String> {
        let value = line
            .split_whitespace()
            .find_map(|field| field.strip_prefix(name))?;
        let numeric = !value.is_empty() && value.chars().all(|c| c.is_ascii_digit() || c == '.');
        numeric.then(|| value.to_string())
    };
    Some((average("avg10=")?, average("avg60=")?))
}

/// At most `MAX_FILE_BYTES` of a file as text. `None` if it cannot be read.
fn read_text(path: &Path) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let mut data = Vec::new();
    file.take(MAX_FILE_BYTES).read_to_end(&mut data).ok()?;
    Some(String::from_utf8_lossy(&data).into_owned())
}

/// Reads a control group's figures. With `full` false the memory breakdown and the
/// pressure files are skipped, which is enough for one row of the list of all units.
/// File I/O: call it from a blocking job.
pub fn read_figures(dir: &Path, full: bool) -> Figures {
    let text = |name: &str| read_text(&dir.join(name));
    let number = |name: &str| text(name).and_then(|t| t.trim().parse::<u64>().ok());
    let limit = |name: &str| text(name).and_then(|t| parse_limit(&t));
    let counters = |name: &str| text(name).map(|t| keyed(&t)).unwrap_or_default();

    let mut figures = Figures {
        memory_current: number("memory.current"),
        memory_max: limit("memory.max"),
        memory_high: limit("memory.high"),
        swap_current: number("memory.swap.current"),
        memory_events: counters("memory.events"),
        cpu_max: text("cpu.max").and_then(|t| parse_cpu_max(&t)),
        cpu_stat: counters("cpu.stat"),
        pids_current: number("pids.current"),
        pids_max: limit("pids.max"),
        pids_events: counters("pids.events"),
        ..Figures::default()
    };
    if full {
        let mut stat = counters("memory.stat");
        stat.retain(|name, _| MEMORY_PARTS.contains(&name.as_str()));
        figures.memory_stat = stat;
        for resource in ["cpu", "memory", "io"] {
            if let Some((avg10, avg60)) =
                text(&format!("{resource}.pressure")).and_then(|t| parse_some_pressure(&t))
            {
                figures.pressure.push((resource.to_string(), avg10, avg60));
            }
        }
    }
    figures
}

fn counter(map: &BTreeMap<String, u64>, name: &str) -> u64 {
    map.get(name).copied().unwrap_or(0)
}

/// `part` as a percentage of `whole`, to the nearest whole number.
fn percent(part: u64, whole: u64) -> u64 {
    if whole == 0 {
        return 0;
    }
    let (part, whole) = (u128::from(part), u128::from(whole));
    u64::try_from((part * 100 + whole / 2) / whole).unwrap_or(u64::MAX)
}

/// True when `used` is at least `NEAR_PERCENT` of `limit`.
fn near(used: u64, limit: u64) -> bool {
    limit > 0 && u128::from(used) * 100 >= u128::from(limit) * NEAR_PERCENT
}

/// The share of CPU periods in which the group was throttled, with one decimal.
fn throttled_share(stat: &BTreeMap<String, u64>) -> Option<String> {
    let (periods, throttled) = (counter(stat, "nr_periods"), counter(stat, "nr_throttled"));
    (periods > 0).then(|| format!("{:.1}%", throttled as f64 * 100.0 / periods as f64))
}

/// `1 OOM kill`, `2 OOM kills`.
fn counted(number: u64, thing: &str) -> String {
    if number == 1 {
        format!("1 {thing}")
    } else {
        format!("{number} {thing}s")
    }
}

/// `once`, `3 times`.
fn times(number: u64) -> String {
    if number == 1 {
        "once".to_string()
    } else {
        format!("{number} times")
    }
}

/// A time in microseconds, readably.
fn usec_text(usec: u64) -> String {
    if usec < 1_000_000 {
        format!("{} ms", usec / 1000)
    } else {
        human_duration(usec / 1_000_000)
    }
}

/// True when the group has a hard memory limit of its own.
fn own_memory_limit(figures: &Figures) -> bool {
    matches!(figures.memory_max, Some(Limit::At(_)))
}

/// What has hit, or is about to hit, a limit: the worst first. Empty when all is well.
///
/// AIDEV-NOTE: the kernel's event counters are hierarchical: a group's memory.events and
/// pids.events include what happened in the groups inside it. So a unit with no limit of
/// its own can still show a limit being hit (user@1000.service does, for the scopes
/// inside it), and the wording must not claim it was this unit's own limit.
pub fn problems(figures: &Figures) -> Vec<String> {
    let mut found = Vec::new();
    let kills = counter(&figures.memory_events, "oom_kill");
    if kills > 0 {
        found.push(counted(kills, "OOM kill"));
    }
    let hits = counter(&figures.memory_events, "max");
    if hits > 0 {
        // memory.events also counts what happened in the groups inside this one
        let which = if own_memory_limit(figures) {
            "the memory limit"
        } else {
            "a memory limit inside it"
        };
        found.push(format!("{which} was hit {}", times(hits)));
    }
    if let (Some(used), Some(Limit::At(limit))) = (figures.memory_current, figures.memory_max)
        && near(used, limit)
    {
        found.push(format!(
            "memory is at {}% of its limit",
            percent(used, limit)
        ));
    }
    // AIDEV-NOTE: a quota that was met in a handful of periods since the unit started is
    // not a problem (it used to read "PROBLEM: CPU was throttled in 0.0% of periods").
    // Below one period in a hundred the figures are still shown, as plain information.
    let (periods, throttled) = (
        counter(&figures.cpu_stat, "nr_periods"),
        counter(&figures.cpu_stat, "nr_throttled"),
    );
    if throttled > 0
        && u128::from(throttled) * 100 >= u128::from(periods) * THROTTLED_PROBLEM_PERCENT
        && let Some(share) = throttled_share(&figures.cpu_stat)
    {
        found.push(format!("CPU was throttled in {share} of periods"));
    }
    let task_hits = counter(&figures.pids_events, "max");
    if task_hits > 0 {
        found.push(format!("the task limit was hit {}", times(task_hits)));
    }
    if let (Some(used), Some(Limit::At(limit))) = (figures.pids_current, figures.pids_max)
        && near(used, limit)
    {
        found.push(format!(
            "tasks are at {}% of their limit",
            percent(used, limit)
        ));
    }
    found
}

/// The figures as sentences an agent can act on.
pub fn render_figures(figures: &Figures) -> String {
    let mut text = String::new();

    if let Some(used) = figures.memory_current {
        let hits = counter(&figures.memory_events, "max");
        let kills = counter(&figures.memory_events, "oom_kill");
        let mut ran_into = Vec::new();
        if hits > 0 {
            let which = if own_memory_limit(figures) {
                "The limit"
            } else {
                "A limit set inside this unit"
            };
            ran_into.push(format!("{which} was hit {}", times(hits)));
        }
        if kills > 0 {
            ran_into.push(counted(kills, "OOM kill"));
        }
        match figures.memory_max {
            Some(Limit::At(limit)) => {
                text.push_str(&format!(
                    "Memory: {} in use of a {} limit ({}%).",
                    human_bytes(used),
                    human_bytes(limit),
                    percent(used, limit)
                ));
                if ran_into.is_empty() {
                    text.push_str(" The limit has not been hit.");
                }
            }
            _ => text.push_str(&format!("Memory: {} in use; no limit.", human_bytes(used))),
        }
        if !ran_into.is_empty() {
            text.push_str(&format!(" {}.", ran_into.join("; ")));
        }
        if let Some(Limit::At(high)) = figures.memory_high {
            let exceeded = match counter(&figures.memory_events, "high") {
                0 => "never exceeded".to_string(),
                n => format!("exceeded {}", times(n)),
            };
            text.push_str(&format!(
                " High mark {} (above it the kernel slows the unit down): {exceeded}.",
                human_bytes(high)
            ));
        }
        text.push('\n');
        let parts: Vec<String> = MEMORY_PARTS
            .iter()
            .filter_map(|name| {
                let bytes = counter(&figures.memory_stat, name);
                (bytes > 0).then(|| format!("{name} {}", human_bytes(bytes)))
            })
            .collect();
        if !parts.is_empty() {
            text.push_str(&format!("  of which: {}\n", parts.join(", ")));
        }
    }
    if let Some(swap) = figures.swap_current.filter(|swap| *swap > 0) {
        text.push_str(&format!("Swap: {} in use.\n", human_bytes(swap)));
    }

    let mut cpu = Vec::new();
    if let Some(max) = figures.cpu_max {
        match max.quota {
            None => cpu.push("no quota.".to_string()),
            Some(quota) => {
                let periods = counter(&figures.cpu_stat, "nr_periods");
                let throttled = counter(&figures.cpu_stat, "nr_throttled");
                let how = match throttled_share(&figures.cpu_stat) {
                    Some(share) if throttled > 0 => format!(
                        "throttled in {throttled} of {periods} periods ({share}), {} in all.",
                        usec_text(counter(&figures.cpu_stat, "throttled_usec"))
                    ),
                    Some(_) => format!("never throttled ({periods} periods)."),
                    None => "never throttled.".to_string(),
                };
                cpu.push(format!(
                    "quota {}% of one CPU; {how}",
                    percent(quota, max.period)
                ));
            }
        }
    }
    if let Some(used) = figures.cpu_stat.get("usage_usec") {
        cpu.push(format!("{} of CPU time used.", usec_text(*used)));
    }
    if !cpu.is_empty() {
        text.push_str(&format!("CPU: {}\n", cpu.join(" ")));
    }

    if let Some(tasks) = figures.pids_current {
        let hits = counter(&figures.pids_events, "max");
        match figures.pids_max {
            Some(Limit::At(limit)) => {
                text.push_str(&format!("Tasks: {tasks} of at most {limit}."));
                if hits > 0 {
                    text.push_str(&format!(" The limit was hit {}.", times(hits)));
                }
            }
            _ => {
                text.push_str(&format!("Tasks: {tasks}; no limit."));
                if hits > 0 {
                    text.push_str(&format!(" A task limit was hit {}.", times(hits)));
                }
            }
        }
        text.push('\n');
    }

    if !figures.pressure.is_empty() {
        let parts: Vec<String> = figures
            .pressure
            .iter()
            .map(|(resource, avg10, avg60)| format!("{resource} {avg10}% / {avg60}%"))
            .collect();
        text.push_str(&format!(
            "Stalled (share of time some task was waiting, last 10 s / 60 s): {}\n",
            parts.join(", ")
        ));
    }

    if text.is_empty() {
        text.push_str("No figures are available for this control group.\n");
    }
    text
}

// ---- cgroup_limits ---------------------------------------------------------------------

/// The properties that say what systemd has configured for a unit.
const LIMIT_PROPERTIES: [&str; 6] = [
    "ControlGroup",
    "MemoryMax",
    "MemoryHigh",
    "MemorySwapMax",
    "CPUQuotaPerSecUSec",
    "TasksMax",
];

/// The limits systemd has configured, on one line. Used where the control group itself
/// cannot be read.
fn configured_line(properties: &BTreeMap<String, String>) -> String {
    let mut parts = Vec::new();
    for name in LIMIT_PROPERTIES.iter().skip(1) {
        let Some(value) = properties.get(*name) else {
            continue;
        };
        let value = one_line_cell(value);
        // a memory limit in bytes is easier read with a unit as well
        match value.parse::<u64>() {
            Ok(bytes) if name.starts_with("Memory") => {
                parts.push(format!("{name}={value} ({})", human_bytes(bytes)));
            }
            _ => parts.push(format!("{name}={value}")),
        }
    }
    if parts.is_empty() {
        "Limits configured in systemd: none reported.\n".to_string()
    } else {
        format!("Limits configured in systemd: {}\n", parts.join(", "))
    }
}

/// What looking for a unit's control group came to.
enum Located {
    /// The unit has none: it is not running.
    NoGroup,
    /// This host does not use the unified hierarchy.
    NotUnified,
    /// systemd's path does not have the shape of a control group path.
    Unusable,
    /// The directory is not there (the unit stopped a moment ago).
    Gone,
    Found(Box<Figures>),
}

fn locate(root: &Path, control_group: &str) -> Located {
    if control_group.is_empty() {
        return Located::NoGroup;
    }
    if !root.join("cgroup.controllers").exists() {
        return Located::NotUnified;
    }
    let Some(relative) = cgroup_dir(control_group) else {
        return Located::Unusable;
    };
    let dir = root.join(relative);
    if !dir.is_dir() {
        return Located::Gone;
    }
    Located::Found(Box::new(read_figures(&dir, true)))
}

/// The report on one unit: the verdict first, then its figures. The caller has already
/// been authorized for `id`.
async fn unit_report(ctx: &Ctx, roots: &Roots, id: &str) -> Result<String, ToolError> {
    let properties = show_one(ctx, id, &LIMIT_PROPERTIES).await?;
    let control_group = properties.get("ControlGroup").cloned().unwrap_or_default();
    let root = roots.cgroup.clone();
    let asked = control_group.clone();
    let located = blocking(ctx.clone(), move || Ok(locate(&root, &asked))).await?;
    let configured = configured_line(&properties);
    Ok(match located {
        Located::Found(figures) => {
            let wrong = problems(&figures);
            let verdict = if wrong.is_empty() {
                "no limit is being hit.".to_string()
            } else {
                format!("PROBLEM: {}", wrong.join("; "))
            };
            format!(
                "{id}: {verdict}\nControl group: {}\n{}[the counts are since the unit was last started]\n",
                one_line_cell(&control_group),
                render_figures(&figures)
            )
        }
        Located::NoGroup => format!(
            "{id}: it has no control group (it is not running, or it is not a kind of unit \
             that holds processes), so there is nothing to measure.\n{configured}"
        ),
        Located::NotUnified => format!(
            "{id}: this host does not use the unified control group hierarchy (cgroup v2), \
             so what the unit uses and has run into cannot be read here.\n{configured}"
        ),
        Located::Unusable => format!(
            "{id}: systemd reported an unusable control group path; nothing was read.\n\
             {configured}"
        ),
        Located::Gone => format!(
            "{id}: its control group is no longer there (the unit has just stopped).\n\
             {configured}"
        ),
    })
}

/// One unit in the list of all units.
struct Row {
    unit: String,
    figures: Figures,
}

/// The slices whose services and scopes are listed: the system's own units, containers
/// and virtual machines, and login sessions.
const LISTED_SLICES: [&str; 3] = ["system.slice", "machine.slice", "user.slice"];
/// Slices nest (system.slice/system-postgresql.slice/postgresql@14-main.service): this
/// many levels below a listed slice are followed.
const MAX_SLICE_DEPTH: usize = 3;
/// The most control groups looked at in one call.
const MAX_GROUPS: usize = 5000;

/// True for a unit worth a row: it has a limit of its own, or has run into one.
fn notable(figures: &Figures) -> bool {
    matches!(figures.memory_max, Some(Limit::At(_)))
        || matches!(figures.memory_high, Some(Limit::At(_)))
        || figures.cpu_max.is_some_and(|max| max.quota.is_some())
        || counter(&figures.memory_events, "high") > 0
        || counter(&figures.memory_events, "oom") > 0
        || !problems(figures).is_empty()
}

/// Collects the notable services and scopes under `dir`. Returns false when it stopped
/// at `MAX_GROUPS`.
fn collect(dir: &Path, depth: usize, seen: &mut usize, rows: &mut Vec<Row>) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return true;
    };
    for entry in entries.flatten() {
        // `file_type` does not follow links, and a control group is always a directory.
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        if *seen >= MAX_GROUPS {
            return false;
        }
        *seen += 1;
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        if name.ends_with(".service") || name.ends_with(".scope") {
            let figures = read_figures(&path, false);
            if notable(&figures) {
                rows.push(Row {
                    unit: name,
                    figures,
                });
            }
        } else if name.ends_with(".slice")
            && depth < MAX_SLICE_DEPTH
            && !collect(&path, depth + 1, seen, rows)
        {
            return false;
        }
    }
    true
}

/// Every notable unit, and whether the whole hierarchy was looked at. `None` on a host
/// without the unified hierarchy.
fn scan(root: &Path) -> Option<(Vec<Row>, bool)> {
    if !root.join("cgroup.controllers").exists() {
        return None;
    }
    let mut rows = Vec::new();
    let mut seen = 0;
    let mut complete = true;
    for slice in LISTED_SLICES {
        if !collect(&root.join(slice), 0, &mut seen, &mut rows) {
            complete = false;
            break;
        }
    }
    Some((rows, complete))
}

/// How bad a row is: 3 for an OOM kill, 2 for any other problem, 1 for a limit that has
/// not been hit.
fn severity(figures: &Figures) -> u8 {
    if counter(&figures.memory_events, "oom_kill") > 0 {
        3
    } else if !problems(figures).is_empty() {
        2
    } else {
        1
    }
}

fn table_row(row: &Row) -> Vec<String> {
    let figures = &row.figures;
    let memory = figures.memory_current.map_or("-".to_string(), human_bytes);
    let limit = match (figures.memory_current, figures.memory_max) {
        (Some(used), Some(Limit::At(limit))) => {
            format!("{} ({}%)", human_bytes(limit), percent(used, limit))
        }
        (None, Some(Limit::At(limit))) => human_bytes(limit),
        _ => "-".to_string(),
    };
    let throttled = match figures.cpu_max {
        Some(max) if max.quota.is_some() => {
            throttled_share(&figures.cpu_stat).unwrap_or_else(|| "0.0%".to_string())
        }
        _ => "-".to_string(),
    };
    let tasks = match (figures.pids_current, figures.pids_max) {
        (Some(tasks), Some(Limit::At(limit))) => format!("{tasks}/{limit}"),
        (Some(tasks), _) => tasks.to_string(),
        _ => "-".to_string(),
    };
    vec![
        row.unit.clone(),
        memory,
        limit,
        throttled,
        counter(&figures.memory_events, "oom_kill").to_string(),
        tasks,
    ]
}

/// The list of all notable units as text. `hidden` says that some were left out because
/// the caller may not view them.
fn render_list(mut rows: Vec<Row>, hidden: bool, complete: bool, limit: usize) -> String {
    rows.sort_by(|a, b| {
        severity(&b.figures)
            .cmp(&severity(&a.figures))
            .then_with(|| a.unit.cmp(&b.unit))
    });
    let mut notes = String::new();
    if hidden {
        notes.push_str("[some units are not shown: this caller may not view them]\n");
    }
    if !complete {
        notes.push_str(&format!(
            "[the search stopped after {MAX_GROUPS} control groups: the list is incomplete]\n"
        ));
    }
    if rows.is_empty() {
        let none = if hidden {
            "No unit that this caller may view has a limit set or has hit one.\n"
        } else {
            "No service or scope has a limit set or has hit one.\n"
        };
        return format!("{none}{notes}");
    }

    const NAMED: usize = 8;
    let in_trouble: Vec<&str> = rows
        .iter()
        .filter(|row| severity(&row.figures) >= 2)
        .map(|row| row.unit.as_str())
        .collect();
    let verdict = match in_trouble.len() {
        0 => format!(
            "No unit is at or over a limit ({} with a limit set).",
            counted(rows.len() as u64, "unit")
        ),
        count => {
            let mut names = in_trouble
                .iter()
                .take(NAMED)
                .map(|name| one_line_cell(name))
                .collect::<Vec<_>>()
                .join(", ");
            if count > NAMED {
                names.push_str(&format!(", and {} more", count - NAMED));
            }
            let are = if count == 1 { "unit is" } else { "units are" };
            format!("{count} {are} at or over a limit: {names}")
        }
    };

    let left_out = rows.len().saturating_sub(limit);
    let shown: Vec<Vec<String>> = rows.iter().take(limit).map(table_row).collect();
    let mut text = format!("{verdict}\n");
    text.push_str(&format_table(
        &["UNIT", "MEMORY", "LIMIT", "THROTTLED", "OOM-KILLS", "TASKS"],
        &shown,
        &[false, true, false, true, true, true],
    ));
    if left_out > 0 {
        text.push_str(&format!(
            "[{} left out; raise limit to see them]\n",
            counted(left_out as u64, "more unit")
        ));
    }
    text.push_str(&notes);
    text.push_str(
        "[THROTTLED is the share of CPU periods in which the unit was held back; the counts \
         are since each unit was last started]\n",
    );
    text
}

/// `text`, or as many whole lines from its start as fit the output limit, with a note.
fn fit(ctx: &Ctx, text: String) -> String {
    let (kept, dropped) = keep_head(&text, ctx.output_budget().saturating_sub(80));
    if dropped == 0 {
        return kept;
    }
    format!("{kept}[{dropped} more lines left out to fit the output limit]\n")
}

async fn cgroup_limits(roots: Arc<Roots>, ctx: Ctx, args: Args) -> ToolResult {
    let Some(unit) = args.str("unit") else {
        return all_units(roots, ctx, args.int("limit").unwrap_or(50)).await;
    };
    let asked = normalize_unit(unit)?;
    // Judged by the unit's real name, exactly as service_status does: asking by an
    // alias must not get around a grant or a deny written for the unit itself.
    let (id, load_state) = service::lookup(&ctx, &asked).await?;
    let auth = ctx.authorize(Some(&id))?;
    if load_state == "not-found" {
        return Err(ToolError::Failed(format!(
            "{id}: there is no such unit on this host"
        )));
    }
    let report = unit_report(&ctx, &roots, &id).await?;
    auth.ok(fit(&ctx, report))
}

async fn all_units(roots: Arc<Roots>, ctx: Ctx, limit: i64) -> ToolResult {
    let auth = ctx.authorize(None)?;
    let root = roots.cgroup.clone();
    let Some((rows, complete)) = blocking(ctx.clone(), move || Ok(scan(&root))).await? else {
        return auth.ok(
            "This host does not use the unified control group hierarchy (cgroup v2), so the \
             figures of its units cannot be read. Name a unit to see the limits systemd has \
             configured for it.\n",
        );
    };
    // AIDEV-NOTE: the walk sees every unit; a caller with a deny for some of them must
    // not learn their names or figures here. Each row is shown only if the caller could
    // have asked for that unit by name, and the note about the rest gives no count.
    // As the policy stands today this filter hides nothing: `authorize(None)` above is
    // already refused for a caller with a deny on any one unit (such a caller asks by
    // name instead). It is kept so that a change to that rule cannot make this list
    // show what a deny is meant to hide.
    let found = rows.len();
    let rows: Vec<Row> = rows
        .into_iter()
        .filter(|row| ctx.permits(&row.unit))
        .collect();
    let hidden = rows.len() != found;
    let limit = usize::try_from(limit).unwrap_or(50);
    auth.ok(fit(&ctx, render_list(rows, hidden, complete, limit)))
}

// ---- service_limits --------------------------------------------------------------------

/// Below this a memory limit is taken to be a mistake (bytes meant as megabytes).
const MEMORY_FLOOR: u64 = 16 << 20;
/// Below this share of one CPU a quota all but stops a unit.
const CPU_QUOTA_FLOOR_PERCENT: i64 = 10;

/// A memory size as systemd reads it: a whole number of bytes, optionally followed by
/// K, M, G or T (powers of 1024), or `infinity` for no limit (`None`).
///
/// AIDEV-NOTE: the text that passes this check is put after `MemoryMax=` on systemctl's
/// command line, so it is held to digits and one unit letter: no spaces, no `=`, nothing
/// that could add a property or an option.
pub fn parse_size(text: &str) -> Result<Option<u64>, String> {
    if text == "infinity" {
        return Ok(None);
    }
    let wrong = || {
        format!(
            "{text:?} is not a memory size: use a whole number of bytes, optionally followed \
             by K, M, G or T (e.g. 512M, 2G), or infinity"
        )
    };
    let (digits, shift) = [('K', 10u32), ('M', 20), ('G', 30), ('T', 40)]
        .iter()
        .find_map(|(unit, shift)| text.strip_suffix(*unit).map(|digits| (digits, *shift)))
        .unwrap_or((text, 0));
    let well_formed = !digits.is_empty()
        && digits.len() <= 13
        && !digits.starts_with('0')
        && digits.bytes().all(|b| b.is_ascii_digit());
    if !well_formed {
        return Err(wrong());
    }
    let number: u64 = digits.parse().map_err(|_| wrong())?;
    number
        .checked_mul(1u64 << shift)
        .map(Some)
        .ok_or_else(|| format!("{text:?} is too large"))
}

/// What a service_limits call asks for.
struct LimitRequest {
    /// `Property=value` arguments for `systemctl set-property`, each built here from a
    /// checked value.
    assignments: Vec<String>,
    /// The hard memory limit asked for in bytes, when it is not `infinity`.
    memory_max: Option<u64>,
    /// The high mark asked for in bytes, when it is not `infinity`.
    memory_high: Option<u64>,
    /// The CPU quota asked for in percent of one CPU, when one is being set (not removed).
    cpu_quota: Option<i64>,
    /// The task limit asked for, when it is not "no limit".
    tasks_max: Option<u64>,
}

impl LimitRequest {
    fn parse(args: &Args) -> Result<LimitRequest, ToolError> {
        let mut request = LimitRequest {
            assignments: Vec::new(),
            memory_max: None,
            memory_high: None,
            cpu_quota: None,
            tasks_max: None,
        };
        if let Some(text) = args.str("memory_max") {
            request.memory_max = parse_size(text).map_err(ToolError::Invalid)?;
            request.assignments.push(format!("MemoryMax={text}"));
        }
        if let Some(text) = args.str("memory_high") {
            request.memory_high = parse_size(text).map_err(ToolError::Invalid)?;
            request.assignments.push(format!("MemoryHigh={text}"));
        }
        if let Some(percent) = args.int("cpu_quota_percent") {
            request.cpu_quota = (percent > 0).then_some(percent);
            // the dispatcher has checked the range; an empty value removes the quota
            request.assignments.push(match percent {
                0 => "CPUQuota=".to_string(),
                percent => format!("CPUQuota={percent}%"),
            });
        }
        if let Some(tasks) = args.int("tasks_max") {
            match u64::try_from(tasks) {
                Ok(0) => request.assignments.push("TasksMax=infinity".to_string()),
                Ok(tasks) => {
                    request.tasks_max = Some(tasks);
                    request.assignments.push(format!("TasksMax={tasks}"));
                }
                Err(_) => {
                    return Err(ToolError::Invalid(
                        "tasks_max must not be negative".to_string(),
                    ));
                }
            }
        }
        if request.assignments.is_empty() {
            return Err(ToolError::Invalid(
                "give at least one of memory_max, memory_high, cpu_quota_percent and tasks_max"
                    .to_string(),
            ));
        }
        Ok(request)
    }

    /// True when a guard needs to know what the unit uses now.
    fn needs_current_use(&self) -> bool {
        self.memory_max.is_some() || self.memory_high.is_some() || self.tasks_max.is_some()
    }

    /// Why this request should not be carried out without `force`, if there is a reason.
    /// `current` holds the unit's `MemoryCurrent` and `TasksCurrent`, where systemd has
    /// them (a unit that is not running has neither).
    fn objections(&self, unit: &str, current: &BTreeMap<String, String>) -> Vec<String> {
        let now = |name: &str| current.get(name).and_then(|v| v.parse::<u64>().ok());
        let mut objections = Vec::new();
        if let Some(limit) = self.memory_max {
            if limit < MEMORY_FLOOR {
                objections.push(format!(
                    "a memory limit of {} is below {}, less than a service can run in",
                    human_bytes(limit),
                    human_bytes(MEMORY_FLOOR)
                ));
            }
            if let Some(used) = now("MemoryCurrent").filter(|used| limit < *used) {
                objections.push(format!(
                    "{unit} is using {}: a limit of {} would make the kernel kill its \
                     processes at once",
                    human_bytes(used),
                    human_bytes(limit)
                ));
            }
        }
        if let Some(mark) = self.memory_high
            && let Some(used) = now("MemoryCurrent").filter(|used| mark < *used)
        {
            objections.push(format!(
                "{unit} is using {}: with a high mark of {} the kernel would hold it back \
                 and take memory from it at once",
                human_bytes(used),
                human_bytes(mark)
            ));
        }
        if let Some(percent) = self
            .cpu_quota
            .filter(|percent| *percent < CPU_QUOTA_FLOOR_PERCENT)
        {
            objections.push(format!(
                "a CPU quota of {percent}% of one CPU (under {CPU_QUOTA_FLOOR_PERCENT}%) \
                 would all but stop {unit}"
            ));
        }
        if let Some(limit) = self.tasks_max
            && let Some(tasks) = now("TasksCurrent").filter(|tasks| limit < *tasks)
        {
            objections.push(format!(
                "{unit} has {tasks} tasks now: with a limit of {limit} it could start no \
                 new process or thread"
            ));
        }
        objections
    }

    /// The assignments as shown in the result.
    fn described(&self) -> String {
        self.assignments
            .iter()
            .map(|assignment| match assignment.as_str() {
                "CPUQuota=" => "CPUQuota= (no quota)".to_string(),
                other => other.to_string(),
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Limits are set on the units that hold processes of their own.
fn limitable(unit: &str) -> bool {
    unit.ends_with(".service") || unit.ends_with(".scope")
}

/// Why a unit is never limited through opsmcp, if it is one of those.
///
/// AIDEV-NOTE: `services.protected` is matched against a unit's own name. A limit on a
/// SLICE holds back everything under it: `system.slice` contains journald, logind, dbus
/// and opsmcp itself, so a caller allowed to limit a slice could throttle or starve the
/// very units that list keeps out of reach. `init.scope` is systemd (pid 1). Neither is
/// offered, whatever the grant and whatever `force` says.
fn off_limits(unit: &str) -> Option<String> {
    if unit.ends_with(".slice") {
        Some(format!(
            "{unit} is a slice: a limit on a slice holds back everything under it, protected \
             units included, so limits are set on services and scopes only"
        ))
    } else if unit == "init.scope" {
        Some("init.scope is systemd itself (pid 1), which is never limited".to_string())
    } else {
        None
    }
}

async fn service_limits(roots: Arc<Roots>, ctx: Ctx, args: Args) -> ToolResult {
    let asked = required(&args, "unit")?;
    let not_limitable =
        |unit: &str| format!("{unit}: limits can only be set on a service or a scope");
    let unit = normalize_unit(asked)?;
    let request = LimitRequest::parse(&args)?;
    let force = args.bool("force") == Some(true);
    if let Some(reason) = off_limits(&unit) {
        return Err(ctx.deny(Some(&unit), &reason));
    }
    if !limitable(&unit) {
        return Err(ToolError::Invalid(not_limitable(asked)));
    }

    // Protected units, the unit's real name, and the caller's grant for it.
    let (id, auth) = service::authorize_change(&ctx, asked).await?;
    // (an alias could lead somewhere else than its name says)
    if let Some(reason) = off_limits(&id) {
        return Err(ctx.deny(Some(&id), &reason));
    }
    if !limitable(&id) {
        return Err(ToolError::Failed(not_limitable(&id)));
    }

    // AIDEV-NOTE: the guards. A hard memory limit below what the unit uses makes the
    // kernel kill its processes the moment it is set, a high mark below it makes the
    // kernel stall the unit while it takes memory back, a CPU quota of a few percent all
    // but stops it, and a task limit below the current count makes every fork fail: all
    // look like a typo far more often than an intention, so they need `force`. What the
    // unit uses is read just before the change; it can move in between, which is why
    // this is a guard and not a guarantee.
    if !force {
        let current = if request.needs_current_use() {
            show_one(&ctx, &id, &["MemoryCurrent", "TasksCurrent"]).await?
        } else {
            BTreeMap::new()
        };
        let objections = request.objections(&id, &current);
        if !objections.is_empty() {
            return auth.failed(format!(
                "Refused: {}. Nothing was changed. Pass force to set it anyway.\n",
                objections.join("; ")
            ));
        }
    }

    // AIDEV-NOTE: `--runtime` always. The setting goes to /run and is gone at the next
    // reboot; nothing is written under /etc, where a limit would outlive the incident
    // it was set for and surprise whoever manages the unit's configuration.
    let mut argv = vec![
        "--no-ask-password".to_string(),
        "--runtime".to_string(),
        "set-property".to_string(),
        "--".to_string(),
        id.clone(),
    ];
    argv.extend(request.assignments.iter().cloned());
    let out = ctx.run(ctx.command("systemctl")?.args(argv)).await?;
    if !command_ok(&out) {
        return auth.failed(format!(
            "{}Setting limits on {id}: FAILED.\n",
            command_text(&out)
        ));
    }

    let mut text = format!(
        "Set on {id}: {}.\n\
         Runtime only: nothing was written under /etc, and the limits last until the next \
         reboot. To undo one sooner, set it again: infinity for memory, 0 for the CPU quota \
         or the task limit.\n\n",
        request.described()
    );
    match unit_report(&ctx, &roots, &id).await {
        Ok(report) => text.push_str(&report),
        Err(_) => text.push_str("[the unit's figures could not be read afterwards]\n"),
    }
    auth.ok(fit(&ctx, text))
}

// ---- service_dependencies --------------------------------------------------------------

const DEPENDENCY_PROPERTIES: [&str; 20] = [
    "Id",
    "ActiveState",
    "SubState",
    "Result",
    "ConditionResult",
    "ConditionTimestamp",
    "AssertResult",
    "AssertTimestamp",
    "Requires",
    "Requisite",
    "BindsTo",
    "Wants",
    "PartOf",
    "After",
    "Before",
    "Conflicts",
    "RequiredBy",
    "WantedBy",
    "BoundBy",
    "TriggeredBy",
];
/// What the unit depends on, and what depends on it.
const NEEDS: [&str; 7] = [
    "Requires",
    "Requisite",
    "BindsTo",
    "Wants",
    "PartOf",
    "After",
    "Conflicts",
];
const NEEDED_BY: [&str; 5] = ["RequiredBy", "WantedBy", "BoundBy", "TriggeredBy", "Before"];
/// The dependencies without which the unit does not start or does not stay up.
const HARD: [&str; 3] = ["Requires", "Requisite", "BindsTo"];
/// The most requirements whose state is looked up.
const MAX_REQUIREMENTS: usize = 50;
/// The most names shown from one dependency list, and lines from one tree.
const MAX_LISTED: usize = 40;
const MAX_TREE_LINES: usize = 60;

/// The unit a line of `systemctl list-dependencies --plain` names: the last word (the
/// line is the unit's name, indented).
fn tree_unit(line: &str) -> Option<&str> {
    line.split_whitespace().next_back()
}

/// The unit a line of `systemd-analyze critical-chain` names, if it names one: after
/// the indentation and the tree mark (`└─`, or `` `- `` in the C locale) comes the unit,
/// then its times. The explanations above the chain name no unit.
fn chain_unit(line: &str) -> Option<&str> {
    let rest = line.trim_start();
    let rest = rest
        .strip_prefix("└─")
        .or_else(|| rest.strip_prefix("`-"))
        .unwrap_or(rest);
    let word = rest.split_whitespace().next()?;
    normalize_unit(word)
        .is_ok_and(|normal| normal == word)
        .then_some(word)
}

/// The lines of `text` whose unit the caller may see, and whether any was left out.
/// `unit_of` says which unit a line names; a line that names none is kept.
fn visible_lines(
    text: &str,
    unit_of: fn(&str) -> Option<&str>,
    may_see: &dyn Fn(&str) -> bool,
) -> (String, bool) {
    let mut kept = String::new();
    let mut hidden = false;
    for line in text.lines() {
        match unit_of(line) {
            Some(unit) if !may_see(unit) => hidden = true,
            _ => {
                kept.push_str(line);
                kept.push('\n');
            }
        }
    }
    (kept, hidden)
}

/// One line of a dependency list: `Requires: a b c`, cut at `MAX_LISTED` names, and
/// whether units were left out of it because the caller may not see them. A list with
/// nothing left gives no line.
fn list_line(name: &str, value: &str, may_see: &dyn Fn(&str) -> bool) -> (Option<String>, bool) {
    let all: Vec<&str> = value.split_whitespace().collect();
    let words: Vec<&str> = all.iter().copied().filter(|unit| may_see(unit)).collect();
    let hidden = words.len() != all.len();
    if words.is_empty() {
        return (None, hidden);
    }
    let mut line = format!(
        "  {name}: {}",
        words
            .iter()
            .take(MAX_LISTED)
            .copied()
            .collect::<Vec<_>>()
            .join(" ")
    );
    if words.len() > MAX_LISTED {
        line.push_str(&format!(" (+{} more)", words.len() - MAX_LISTED));
    }
    (Some(line), hidden)
}

/// The units a unit cannot do without, as names that may be passed to systemctl.
///
/// AIDEV-NOTE: these names come out of `systemctl show`, and go back in as arguments.
/// Only names that are already complete, valid unit names are used (`-.mount`, which
/// starts with a dash, is one that is left out): nothing here may turn into an option.
fn requirements(properties: &BTreeMap<String, String>) -> Vec<String> {
    let mut units: Vec<String> = Vec::new();
    for name in HARD {
        for word in properties
            .get(name)
            .map(String::as_str)
            .unwrap_or("")
            .split_whitespace()
        {
            let usable = normalize_unit(word).is_ok_and(|normal| normal == word);
            if usable && !units.iter().any(|unit| unit == word) && units.len() < MAX_REQUIREMENTS {
                units.push(word.to_string());
            }
        }
    }
    units
}

/// The requirements that are not up, as lines for the report, and a summary of the
/// failed and missing ones for the verdict.
fn unmet_requirements(blocks: &[BTreeMap<String, String>]) -> (Vec<String>, Vec<String>) {
    let mut lines = Vec::new();
    let mut failed = Vec::new();
    let mut missing = Vec::new();
    let mut idle = Vec::new();
    for block in blocks {
        let field = |name: &str| one_line_cell(block.get(name).map(String::as_str).unwrap_or("?"));
        let Some(id) = block.get("Id").map(|id| one_line_cell(id)) else {
            continue;
        };
        if block.get("LoadState").map(String::as_str) == Some("not-found") {
            lines.push(format!("Requirement missing: {id} (there is no such unit)"));
            missing.push(id);
            continue;
        }
        match block.get("ActiveState").map(String::as_str) {
            Some("active" | "activating" | "reloading") => {}
            Some("failed") => {
                lines.push(format!(
                    "Requirement FAILED: {id} ({}, {})",
                    field("ActiveState"),
                    field("Result")
                ));
                failed.push(id);
            }
            _ => idle.push(format!(
                "Requirement not active: {id} ({}, {})",
                field("ActiveState"),
                field("SubState")
            )),
        }
    }
    lines.extend(idle);
    let mut summary = Vec::new();
    match failed.len() {
        0 => {}
        1 => summary.push(format!("a requirement has failed: {}", failed.join(", "))),
        _ => summary.push(format!("requirements have failed: {}", failed.join(", "))),
    }
    match missing.len() {
        0 => {}
        1 => summary.push(format!(
            "a requirement does not exist: {}",
            missing.join(", ")
        )),
        _ => summary.push(format!("requirements do not exist: {}", missing.join(", "))),
    }
    (lines, summary)
}

/// The `Condition:` and `Assert:` lines of `systemctl status` output, with the lines
/// under them that say which condition it was. Those are drawn as a little tree: with
/// line-drawing characters in a UTF-8 locale, with `|-` and `` `- `` in the C locale
/// that commands are run in here.
fn condition_lines(status: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut inside = false;
    for line in status.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Condition:") || trimmed.starts_with("Assert:") {
            inside = true;
            lines.push(trimmed.to_string());
        } else if inside
            && ["└", "├", "`-", "|-"]
                .iter()
                .any(|b| trimmed.starts_with(b))
        {
            lines.push(format!("  {trimmed}"));
        } else {
            inside = false;
        }
    }
    lines
}

/// The first `max` lines of a command's output, with a note about the rest.
fn head_lines(text: &str, max: usize) -> String {
    let total = text.lines().count();
    let mut kept: String = text
        .lines()
        .take(max)
        .map(|line| format!("{line}\n"))
        .collect();
    if total > max {
        kept.push_str(&format!("[{} more lines left out]\n", total - max));
    }
    kept
}

const OUT_OF_TIME: &str = "the call ran out of time";

/// Runs one more systemctl command for the report, if the call has time left for it.
async fn extra(ctx: &Ctx, clock: &CallClock, argv: &[&str]) -> Result<CmdOutput, String> {
    let Some(limit) = clock.next() else {
        return Err(OUT_OF_TIME.to_string());
    };
    let cmd = ctx.command("systemctl").map_err(said)?;
    ctx.run(cmd.timeout(limit).args(argv.iter().copied()))
        .await
        .map_err(said)
}

/// What a `ToolError` says, on one line, for a note inside a larger result.
fn said(error: ToolError) -> String {
    match error {
        ToolError::Denied(message) | ToolError::Invalid(message) | ToolError::Failed(message) => {
            message.split_whitespace().collect::<Vec<_>>().join(" ")
        }
        ToolError::Internal(_) => "an internal error".to_string(),
    }
}

/// One dependency tree (`systemctl list-dependencies`) as systemctl printed it, or why
/// it is not available.
async fn tree(ctx: &Ctx, clock: &CallClock, id: &str, reverse: bool) -> Result<String, String> {
    let mut argv = vec!["list-dependencies", "--plain", "--no-pager"];
    if reverse {
        argv.push("--reverse");
    }
    argv.extend(["--", id]);
    match extra(ctx, clock, &argv).await {
        Ok(out) if command_ok(&out) => Ok(String::from_utf8_lossy(&out.stdout).into_owned()),
        Ok(out) => Err(first_line(&command_text(&out))),
        Err(why) => Err(why),
    }
}

/// A tree for the report: the lines the caller may see, cut to `MAX_TREE_LINES`.
/// `hidden` is set when lines were left out.
fn shown_tree(
    tree: Result<String, String>,
    may_see: &dyn Fn(&str) -> bool,
    hidden: &mut bool,
) -> String {
    match tree {
        Ok(text) => {
            let (kept, some_hidden) = visible_lines(&text, tree_unit, may_see);
            *hidden |= some_hidden;
            head_lines(&kept, MAX_TREE_LINES)
        }
        Err(why) => format!("[not available: {why}]\n"),
    }
}

fn first_line(text: &str) -> String {
    text.lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("no reason given")
        .trim()
        .to_string()
}

async fn service_dependencies(ctx: Ctx, args: Args) -> ToolResult {
    let asked = normalize_unit(required(&args, "unit")?)?;
    let direction = args.str("direction").unwrap_or("both");
    let (needs, needed_by) = (direction != "needed_by", direction != "needs");
    // Judged by the unit's real name, as service_status is.
    let (id, load_state) = service::lookup(&ctx, &asked).await?;
    let auth = ctx.authorize(Some(&id))?;
    if load_state == "not-found" {
        return Err(ToolError::Failed(format!(
            "{id}: there is no such unit on this host"
        )));
    }
    let clock = CallClock::start(&ctx);
    let properties = show_one(&ctx, &id, &DEPENDENCY_PROPERTIES).await?;
    let property = |name: &str| properties.get(name).map(String::as_str).unwrap_or("");

    let mut state = format!(
        "{id}: {} ({})",
        one_line_cell(property("ActiveState")),
        one_line_cell(property("SubState"))
    );
    if !property("Result").is_empty() {
        state.push_str(&format!(
            ", last result {}",
            one_line_cell(property("Result"))
        ));
    }
    let mut wrong: Vec<String> = Vec::new();
    let mut body = String::new();

    // AIDEV-NOTE: everything below names OTHER units and, for requirements, says what
    // state they are in. The call was authorized for `id` alone, so every other unit is
    // shown only if the caller could have asked service_status about it (`permits`): a
    // grant for one unit, or a deny for another, must not be got around through the
    // dependencies of a unit the caller may see. What is left out is not counted, only
    // mentioned, and a hidden requirement's state is never even asked for.
    let may_see = |unit: &str| unit == id || ctx.permits(unit);
    let mut hidden = false;

    // Requirements that are not up: the usual reason a unit did not start.
    let all_required = requirements(&properties);
    let required_units: Vec<String> = all_required
        .iter()
        .filter(|unit| may_see(unit))
        .cloned()
        .collect();
    hidden |= required_units.len() != all_required.len();
    if needs && !required_units.is_empty() {
        let looked_up = match clock.next() {
            None => Err(OUT_OF_TIME.to_string()),
            Some(limit) => show(
                &ctx,
                &required_units,
                &["Id", "LoadState", "ActiveState", "SubState", "Result"],
                Some(limit),
            )
            .await
            .map_err(said),
        };
        match looked_up {
            Ok(out) if command_ok(&out) => {
                let blocks = property_blocks(&String::from_utf8_lossy(&out.stdout));
                let (lines, summary) = unmet_requirements(&blocks);
                for line in lines {
                    body.push_str(&format!("{line}\n"));
                }
                wrong.extend(summary);
            }
            Ok(out) => body.push_str(&format!(
                "[the state of its requirements is not available: {}]\n",
                first_line(&command_text(&out))
            )),
            Err(why) => body.push_str(&format!(
                "[the state of its requirements is not available: {why}]\n"
            )),
        }
    }

    // A start condition that did not hold: systemd then skips the start without an error.
    // AIDEV-NOTE: systemd reports ConditionResult=no (and AssertResult=no) for a unit
    // whose conditions were never checked at all, because nothing ever tried to start
    // it. Only a result with a timestamp is the outcome of a real check.
    let unmet_condition =
        property("ConditionResult") == "no" && !property("ConditionTimestamp").is_empty();
    let failed_assert = property("AssertResult") == "no" && !property("AssertTimestamp").is_empty();
    // An unmet condition is not an error to systemd (the start is skipped, often by
    // design), so it is reported as the reason the unit is not running, not as a problem.
    let skipped = unmet_condition.then_some("a start condition was not met");
    if failed_assert {
        wrong.push("a start assertion failed".to_string());
    }
    if unmet_condition || failed_assert {
        match extra(
            &ctx,
            &clock,
            &["status", "--no-pager", "--lines=0", "--", &id],
        )
        .await
        {
            // status exits 1 to 3 for a unit that is not running: that is not a failure
            Ok(out) if !out.timed_out => {
                // AIDEV-NOTE: only the condition lines are taken. The rest of the status
                // output (processes with their command lines) is service_status's to
                // show; what is taken still goes through the secret masking.
                let lines = condition_lines(&String::from_utf8_lossy(&out.stdout));
                if lines.is_empty() {
                    body.push_str("[systemd did not say which condition it was]\n");
                }
                for line in lines {
                    body.push_str(&format!("{}\n", redact_text(&line)));
                }
            }
            Ok(_) => body.push_str(&format!(
                "[the condition is not available: {OUT_OF_TIME}]\n"
            )),
            Err(why) => body.push_str(&format!("[the condition is not available: {why}]\n")),
        }
    }

    for (wanted, title, names) in [
        (needs, "Needs", NEEDS.as_slice()),
        (needed_by, "Needed by", NEEDED_BY.as_slice()),
    ] {
        if !wanted {
            continue;
        }
        let mut lines: Vec<String> = Vec::new();
        let mut hidden_here = false;
        for name in names {
            let (line, some_hidden) = list_line(name, &one_line_cell(property(name)), &may_see);
            hidden_here |= some_hidden;
            lines.extend(line);
        }
        hidden |= hidden_here;
        if lines.is_empty() {
            // "nothing" would be untrue when there is something the caller may not see
            let nothing = if hidden_here {
                "nothing this caller may see"
            } else {
                "nothing"
            };
            body.push_str(&format!("\n{title}: {nothing}\n"));
        } else {
            body.push_str(&format!("\n{title}\n{}\n", lines.join("\n")));
        }
    }

    if needs {
        body.push_str("\nDependency tree (what it pulls in)\n");
        let found = tree(&ctx, &clock, &id, false).await;
        body.push_str(&shown_tree(found, &may_see, &mut hidden));
    }
    if needed_by {
        body.push_str("\nReverse tree (what pulls it in)\n");
        let found = tree(&ctx, &clock, &id, true).await;
        body.push_str(&shown_tree(found, &may_see, &mut hidden));
    }

    if needs {
        body.push('\n');
        match boot_chain(&ctx, &clock, &id).await {
            Ok(text) => {
                let (kept, some_hidden) = visible_lines(&text, chain_unit, &may_see);
                hidden |= some_hidden;
                body.push_str(&format!(
                    "Start-up chain at boot (systemd-analyze critical-chain)\n{}",
                    head_lines(&kept, MAX_LISTED)
                ));
            }
            Err(why) => body.push_str(&format!("[boot chain left out: {why}]\n")),
        }
    }

    let mut verdict = state;
    if !wrong.is_empty() {
        verdict.push_str(&format!("; PROBLEM: {}", wrong.join("; ")));
    }
    if let Some(why) = skipped {
        verdict.push_str(&format!("; its start was skipped: {why}"));
    }
    // Second, so that it survives whatever is cut from the end of a long report.
    let note = if hidden {
        "[some units are not shown: this caller may not see them]\n"
    } else {
        ""
    };
    auth.ok(fit(&ctx, format!("{verdict}\n{note}{body}")))
}

/// The chain of units this one waited for at boot, as systemd-analyze printed it, or
/// why it is left out.
async fn boot_chain(ctx: &Ctx, clock: &CallClock, id: &str) -> Result<String, String> {
    let cmd = match ctx.optional_command("systemd-analyze") {
        Ok(Some(cmd)) => cmd,
        Ok(None) => return Err("systemd-analyze is not installed".to_string()),
        Err(error) => return Err(said(error)),
    };
    let Some(limit) = clock.next() else {
        return Err(OUT_OF_TIME.to_string());
    };
    let run = ctx
        .run(
            cmd.timeout(limit)
                .args(["critical-chain", "--no-pager", "--", id]),
        )
        .await;
    match run {
        Ok(out) if command_ok(&out) => Ok(String::from_utf8_lossy(&out.stdout).into_owned()),
        // it fails where there was no ordinary boot to analyse, as in a container
        Ok(out) => Err(first_line(&command_text(&out))),
        Err(error) => Err(said(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::testing::{FakeBins, call, find, host, ok_text};
    use crate::tools::{Host, ToolError, ToolResult};
    use serde_json::{Value, json};
    use std::sync::Arc;

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    // ---- parsing -----------------------------------------------------------------------

    #[test]
    fn a_control_group_path_must_stay_inside_the_hierarchy() {
        assert_eq!(
            cgroup_dir("/system.slice/web.service"),
            Some(PathBuf::from("system.slice/web.service"))
        );
        assert_eq!(
            cgroup_dir("/system.slice/system-pg.slice/pg@14\\x2dmain.service"),
            Some(PathBuf::from(
                "system.slice/system-pg.slice/pg@14\\x2dmain.service"
            ))
        );
        // the root control group is the hierarchy itself
        assert_eq!(cgroup_dir("/"), Some(PathBuf::new()));
        for bad in [
            "",
            "system.slice/web.service",
            "/system.slice/../../etc",
            "/system.slice//web.service",
            "/system.slice/web.service/",
            "/./web.service",
            "/a/..",
            "/a\0b",
        ] {
            assert_eq!(cgroup_dir(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn keyed_counters_are_read_line_by_line() {
        let map = keyed("low 0\nhigh 2\nmax 3\noom 1\noom_kill 1\njunk\nbad x\n\n");
        assert_eq!(map.get("high"), Some(&2));
        assert_eq!(map.get("max"), Some(&3));
        assert_eq!(map.get("oom_kill"), Some(&1));
        assert_eq!(map.get("junk"), None);
        assert_eq!(map.get("bad"), None);
        assert_eq!(map.len(), 5);
    }

    #[test]
    fn a_limit_is_a_number_or_max() {
        assert_eq!(parse_limit("max\n"), Some(Limit::Unlimited));
        assert_eq!(parse_limit("2147483648\n"), Some(Limit::At(2_147_483_648)));
        assert_eq!(parse_limit("0"), Some(Limit::At(0)));
        assert_eq!(parse_limit(""), None);
        assert_eq!(parse_limit("lots"), None);
        assert_eq!(parse_limit("-1"), None);
    }

    #[test]
    fn cpu_max_is_a_quota_and_a_period() {
        assert_eq!(
            parse_cpu_max("max 100000\n"),
            Some(CpuMax {
                quota: None,
                period: 100_000
            })
        );
        assert_eq!(
            parse_cpu_max("200000 100000\n"),
            Some(CpuMax {
                quota: Some(200_000),
                period: 100_000
            })
        );
        // a period of nothing cannot be divided by
        assert_eq!(parse_cpu_max("200000 0"), None);
        assert_eq!(parse_cpu_max("200000"), None);
        assert_eq!(parse_cpu_max(""), None);
        assert_eq!(parse_cpu_max("x y"), None);
    }

    #[test]
    fn pressure_gives_the_ten_and_sixty_second_averages_of_the_some_line() {
        let text = "some avg10=1.50 avg60=0.75 avg300=0.10 total=5\n\
                    full avg10=0.20 avg60=0.10 avg300=0.00 total=1\n";
        assert_eq!(
            parse_some_pressure(text),
            Some(("1.50".to_string(), "0.75".to_string()))
        );
        assert_eq!(
            parse_some_pressure("full avg10=0.20 avg60=0.10 avg300=0.00 total=1\n"),
            None
        );
        // only plain numbers are passed on
        assert_eq!(parse_some_pressure("some avg10=x avg60=0.75\n"), None);
        assert_eq!(parse_some_pressure(""), None);
    }

    #[test]
    fn a_memory_size_is_digits_with_an_optional_unit_or_infinity() {
        let good: &[(&str, Option<u64>)] = &[
            ("1", Some(1)),
            ("16K", Some(16 << 10)),
            ("512M", Some(512 << 20)),
            ("2G", Some(2 << 30)),
            ("1T", Some(1 << 40)),
            ("1234567890123", Some(1_234_567_890_123)),
            ("infinity", None),
        ];
        for (text, want) in good {
            assert_eq!(parse_size(text), Ok(*want), "{text}");
        }
        for bad in [
            "",
            "0",
            "01",
            "2g",
            "2GB",
            "1.5G",
            "-1",
            "2 G",
            "G",
            "max",
            "Infinity",
            "MemoryMax=1",
            "1G --now",
            "12345678901234",
            "9999999999999T",
        ] {
            assert!(parse_size(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn property_blocks_split_at_blank_lines() {
        let blocks = property_blocks(
            "Id=a.service\nActiveState=active\n\nId=b.service\nActiveState=failed\nNote=x=y\n\n\n",
        );
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0]["Id"], "a.service");
        assert_eq!(blocks[1]["ActiveState"], "failed");
        // only the first '=' separates the name from the value
        assert_eq!(blocks[1]["Note"], "x=y");
        assert!(property_blocks("").is_empty());
    }

    // ---- figures -----------------------------------------------------------------------

    fn put(root: &Path, rel: &str, content: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    fn put_all(root: &Path, unit: &str, files: &[(&str, &str)]) {
        for (file, content) in files {
            put(root, &format!("{unit}/{file}"), content);
        }
    }

    /// A cgroup hierarchy with: a web service that has hit its limits, a quiet service
    /// with nothing set, a secret service with a limit, a template instance in a nested
    /// slice close to its memory limit, a throttled container and a session that ran out
    /// of tasks.
    fn cgroup_tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        put(root, "cgroup.controllers", "cpu memory pids\n");
        put_all(
            root,
            "system.slice/web.service",
            &[
                ("memory.current", "1288490188\n"),
                ("memory.max", "2147483648\n"),
                ("memory.high", "max\n"),
                ("memory.swap.current", "12582912\n"),
                ("memory.events", "low 0\nhigh 0\nmax 3\noom 1\noom_kill 1\n"),
                (
                    "memory.stat",
                    "anon 858993459\nfile 322122547\nkernel 53687091\nslab 20971520\n\
                     shmem 0\nsock 4096\nunevictable 0\n",
                ),
                ("cpu.max", "200000 100000\n"),
                (
                    "cpu.stat",
                    "usage_usec 3722000000\nuser_usec 3000000000\nsystem_usec 722000000\n\
                     nr_periods 9000\nnr_throttled 412\nthrottled_usec 38000000\n",
                ),
                ("pids.current", "12\n"),
                ("pids.max", "512\n"),
                ("pids.events", "max 0\n"),
                (
                    "cpu.pressure",
                    "some avg10=1.50 avg60=0.75 avg300=0.10 total=5\n\
                     full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
                ),
                (
                    "memory.pressure",
                    "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
                ),
                (
                    "io.pressure",
                    "some avg10=0.25 avg60=0.05 avg300=0.00 total=9\n",
                ),
            ],
        );
        put_all(
            root,
            "system.slice/quiet.service",
            &[
                ("memory.current", "1048576\n"),
                ("memory.max", "max\n"),
                ("memory.high", "max\n"),
                ("memory.events", "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n"),
                ("cpu.max", "max 100000\n"),
                (
                    "cpu.stat",
                    "usage_usec 811387\nnr_periods 0\nnr_throttled 0\nthrottled_usec 0\n",
                ),
                ("pids.current", "1\n"),
                ("pids.max", "38002\n"),
                ("pids.events", "max 0\n"),
            ],
        );
        put_all(
            root,
            "system.slice/secret.service",
            &[
                ("memory.current", "536870912\n"),
                ("memory.max", "1073741824\n"),
                ("memory.events", "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n"),
                ("pids.current", "3\n"),
                ("pids.max", "38002\n"),
            ],
        );
        put_all(
            root,
            "system.slice/system-pg.slice/pg@14-main.service",
            &[
                ("memory.current", "950000000\n"),
                ("memory.max", "1000000000\n"),
                ("memory.events", "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n"),
                ("pids.current", "20\n"),
                ("pids.max", "max\n"),
            ],
        );
        put_all(
            root,
            "machine.slice/docker-abc.scope",
            &[
                ("memory.current", "104857600\n"),
                ("memory.max", "max\n"),
                ("cpu.max", "50000 100000\n"),
                (
                    "cpu.stat",
                    "usage_usec 5000000\nnr_periods 100\nnr_throttled 50\nthrottled_usec 2500000\n",
                ),
                ("pids.current", "4\n"),
                ("pids.max", "max\n"),
            ],
        );
        put_all(
            root,
            "user.slice/user-1000.slice/session-3.scope",
            &[
                ("memory.current", "2097152\n"),
                ("memory.max", "max\n"),
                ("pids.current", "30\n"),
                ("pids.max", "100\n"),
                ("pids.events", "max 7\n"),
            ],
        );
        dir
    }

    #[test]
    fn the_figures_of_a_unit_are_read_from_its_control_group() {
        let tree = cgroup_tree();
        let figures = read_figures(&tree.path().join("system.slice/web.service"), true);
        assert_eq!(figures.memory_current, Some(1_288_490_188));
        assert_eq!(figures.memory_max, Some(Limit::At(2_147_483_648)));
        assert_eq!(figures.memory_high, Some(Limit::Unlimited));
        assert_eq!(figures.swap_current, Some(12_582_912));
        assert_eq!(figures.memory_events.get("oom_kill"), Some(&1));
        assert_eq!(figures.memory_stat.get("anon"), Some(&858_993_459));
        assert_eq!(
            figures.cpu_max,
            Some(CpuMax {
                quota: Some(200_000),
                period: 100_000
            })
        );
        assert_eq!(figures.cpu_stat.get("nr_throttled"), Some(&412));
        assert_eq!(figures.pids_current, Some(12));
        assert_eq!(figures.pids_max, Some(Limit::At(512)));
        assert_eq!(
            figures.pressure,
            [
                ("cpu".to_string(), "1.50".to_string(), "0.75".to_string()),
                ("memory".to_string(), "0.00".to_string(), "0.00".to_string()),
                ("io".to_string(), "0.25".to_string(), "0.05".to_string()),
            ]
        );
        // the short form, used for the list of all units, skips the breakdown and pressure
        let short = read_figures(&tree.path().join("system.slice/web.service"), false);
        assert!(short.memory_stat.is_empty());
        assert!(short.pressure.is_empty());
        assert_eq!(short.memory_current, Some(1_288_490_188));
        // a directory that is not there gives nothing, and does not fail
        assert_eq!(
            read_figures(&tree.path().join("nowhere"), true),
            Figures::default()
        );
    }

    #[test]
    fn problems_are_what_has_hit_or_nearly_hit_a_limit() {
        let tree = cgroup_tree();
        let web = read_figures(&tree.path().join("system.slice/web.service"), true);
        assert_eq!(
            problems(&web),
            [
                "1 OOM kill",
                "the memory limit was hit 3 times",
                "CPU was throttled in 4.6% of periods",
            ]
        );
        let quiet = read_figures(&tree.path().join("system.slice/quiet.service"), true);
        assert_eq!(problems(&quiet), Vec::<String>::new());
        let pg = read_figures(
            &tree
                .path()
                .join("system.slice/system-pg.slice/pg@14-main.service"),
            true,
        );
        assert_eq!(problems(&pg), ["memory is at 95% of its limit"]);
        let session = read_figures(
            &tree
                .path()
                .join("user.slice/user-1000.slice/session-3.scope"),
            true,
        );
        assert_eq!(problems(&session), ["the task limit was hit 7 times"]);
        let near = Figures {
            pids_current: Some(95),
            pids_max: Some(Limit::At(100)),
            ..Figures::default()
        };
        assert_eq!(problems(&near), ["tasks are at 95% of their limit"]);
    }

    /// AIDEV-NOTE: one throttled period in a hundred thousand used to read "PROBLEM: CPU
    /// was throttled in 0.0% of periods".
    #[test]
    fn a_trace_of_throttling_is_information_not_a_problem() {
        let throttled = |periods: u64, throttled: u64| Figures {
            cpu_max: Some(CpuMax {
                quota: Some(200_000),
                period: 100_000,
            }),
            cpu_stat: [
                ("nr_periods".to_string(), periods),
                ("nr_throttled".to_string(), throttled),
                ("throttled_usec".to_string(), 5_000),
            ]
            .into_iter()
            .collect(),
            ..Figures::default()
        };
        assert_eq!(problems(&throttled(100_000, 1)), Vec::<String>::new());
        assert_eq!(problems(&throttled(100_000, 999)), Vec::<String>::new());
        assert_eq!(
            problems(&throttled(100_000, 1000)),
            ["CPU was throttled in 1.0% of periods"]
        );
        assert_eq!(
            problems(&throttled(10, 10)),
            ["CPU was throttled in 100.0% of periods"]
        );
        // below the mark it is still told, as a fact about the unit
        let text = render_figures(&throttled(100_000, 1));
        assert!(
            text.contains("throttled in 1 of 100000 periods (0.0%)"),
            "{text}"
        );
    }

    #[test]
    fn figures_are_rendered_as_sentences() {
        let tree = cgroup_tree();
        let web = render_figures(&read_figures(
            &tree.path().join("system.slice/web.service"),
            true,
        ));
        for want in [
            "Memory: 1.2 GiB in use of a 2.0 GiB limit (60%). The limit was hit 3 times; 1 OOM kill.\n",
            "anon 819.2 MiB",
            "file 307.2 MiB",
            "Swap: 12.0 MiB in use.\n",
            "CPU: quota 200% of one CPU; throttled in 412 of 9000 periods (4.6%), 38s in all. \
             1h 2m of CPU time used.\n",
            "Tasks: 12 of at most 512.\n",
            "cpu 1.50% / 0.75%, memory 0.00% / 0.00%, io 0.25% / 0.05%",
        ] {
            assert!(web.contains(want), "missing {want:?} in:\n{web}");
        }
        // nothing that is zero is listed in the breakdown
        assert!(!web.contains("shmem"), "{web}");

        let quiet = render_figures(&read_figures(
            &tree.path().join("system.slice/quiet.service"),
            true,
        ));
        for want in [
            "Memory: 1.0 MiB in use; no limit.\n",
            "CPU: no quota. 811 ms of CPU time used.\n",
            "Tasks: 1 of at most 38002.\n",
        ] {
            assert!(quiet.contains(want), "missing {want:?} in:\n{quiet}");
        }
        assert!(!quiet.contains("Swap"), "{quiet}");

        // a high mark, a limit that was never hit, a quota that never throttled
        let calm = Figures {
            memory_current: Some(100 << 20),
            memory_max: Some(Limit::At(1 << 30)),
            memory_high: Some(Limit::At(512 << 20)),
            memory_events: keyed("high 4\nmax 0\noom_kill 0\n"),
            cpu_max: Some(CpuMax {
                quota: Some(50_000),
                period: 100_000,
            }),
            cpu_stat: keyed("usage_usec 2000000\nnr_periods 40\nnr_throttled 0\n"),
            pids_current: Some(3),
            pids_max: Some(Limit::Unlimited),
            pids_events: keyed("max 2\n"),
            ..Figures::default()
        };
        let calm = render_figures(&calm);
        for want in [
            "Memory: 100.0 MiB in use of a 1.0 GiB limit (10%). The limit has not been hit.",
            "High mark 512.0 MiB (above it the kernel slows the unit down): exceeded 4 times.",
            "CPU: quota 50% of one CPU; never throttled (40 periods). 2s of CPU time used.\n",
            "Tasks: 3; no limit. A task limit was hit 2 times.\n",
        ] {
            assert!(calm.contains(want), "missing {want:?} in:\n{calm}");
        }

        // a unit with no limit of its own whose counters come from the groups inside it
        let outer = Figures {
            memory_current: Some(300 << 20),
            memory_max: Some(Limit::Unlimited),
            memory_events: keyed("max 4939\noom_kill 121\n"),
            ..Figures::default()
        };
        assert_eq!(
            problems(&outer),
            [
                "121 OOM kills",
                "a memory limit inside it was hit 4939 times"
            ]
        );
        assert!(
            render_figures(&outer).contains(
                "Memory: 300.0 MiB in use; no limit. A limit set inside this unit was hit \
                 4939 times; 121 OOM kills.\n"
            ),
            "{}",
            render_figures(&outer)
        );

        // nothing readable at all
        assert_eq!(
            render_figures(&Figures::default()),
            "No figures are available for this control group.\n"
        );
    }

    // ---- the tools ---------------------------------------------------------------------

    const UNITS: &str = r#"
block() {
  echo "Id=$1"
  echo "LoadState=${2:-loaded}"
  echo "ActiveState=${3:-active}"
  echo "SubState=${4:-running}"
  echo "Result=${5:-success}"
}
unit() {
  case "$1" in
    web.service|alias.service)
      block web.service
      echo "ConditionResult=yes"; echo "ConditionTimestamp=Fri 2026-11-20 09:00:00 UTC"
      echo "AssertResult=yes"; echo "AssertTimestamp=Fri 2026-11-20 09:00:00 UTC"
      echo "ControlGroup=/system.slice/web.service"
      echo "MemoryCurrent=1288490188"; echo "TasksCurrent=12"
      echo "MemoryMax=2147483648"; echo "MemoryHigh=infinity"; echo "MemorySwapMax=infinity"
      echo "CPUQuotaPerSecUSec=2s"; echo "TasksMax=512"
      echo "Requires=system.slice sysinit.target db.service -.mount --now"
      echo "Requisite="; echo "BindsTo=cache.service"; echo "Wants=logger.service"
      echo "PartOf="; echo "After=basic.target db.service"
      echo "Before=shutdown.target multi-user.target"; echo "Conflicts=shutdown.target"
      echo "RequiredBy=site.target"; echo "WantedBy=multi-user.target"
      echo "BoundBy="; echo "TriggeredBy=web.socket" ;;
    db.service) block db.service loaded failed failed exit-code ;;
    secret.service) block secret.service loaded failed failed exit-code ;;
    front.service)
      block front.service
      echo "Requires=secret.service db.service"
      echo "Wants=secret.service logger.service"; echo "After=secret.service"
      echo "RequiredBy=secret.service site.target"; echo "WantedBy=secret.service" ;;
    cache.service) block cache.service loaded inactive dead success ;;
    idle.service)
      block idle.service loaded inactive dead success
      echo "ControlGroup="
      echo "MemoryCurrent=[not set]"; echo "TasksCurrent=[not set]"
      echo "MemoryMax=infinity"; echo "MemoryHigh=infinity"; echo "MemorySwapMax=infinity"
      echo "CPUQuotaPerSecUSec=infinity"; echo "TasksMax=4915" ;;
    waiting.service)
      block waiting.service loaded inactive dead success
      echo "ConditionResult=no"; echo "ConditionTimestamp=Fri 2026-11-20 10:00:00 UTC"
      echo "AssertResult=no"; echo "AssertTimestamp="
      echo "Requires=system.slice" ;;
    never.service)
      block never.service loaded inactive dead success
      echo "ConditionResult=no"; echo "ConditionTimestamp="
      echo "AssertResult=no"; echo "AssertTimestamp=" ;;
    evil.service)
      block evil.service
      echo "ControlGroup=/system.slice/../../outside" ;;
    ghost.service) block ghost.service not-found inactive dead success ;;
    odd.service) echo "Id=odd service;x" ; echo "LoadState=loaded" ;;
    *) block "$1" ;;
  esac
}
"#;

    /// A stand-in systemctl that knows a handful of units (see `UNITS`).
    fn fake_systemctl() -> FakeBins {
        let body = format!(
            r#"{UNITS}
verb=
for a; do
  case "$a" in
    show|set-property|list-dependencies|status) verb=$a; break ;;
  esac
done
for last; do :; done
case "$verb" in
  show)
    seen=0; first=1
    for a; do
      if [ "$seen" = 1 ]; then
        [ "$first" = 1 ] || echo
        first=0
        unit "$a"
      elif [ "$a" = "--" ]; then
        seen=1
      fi
    done ;;
  set-property)
    for a; do
      if [ "$a" = broken.service ]; then
        echo "Failed to set unit properties: Access denied" >&2
        exit 1
      fi
    done ;;
  list-dependencies)
    rev=0
    for a; do [ "$a" = "--reverse" ] && rev=1; done
    echo "$last"
    if [ "$last" = big.service ]; then
      i=0
      while [ "$i" -lt 100 ]; do echo "  dep$i.service"; i=$((i+1)); done
    elif [ "$last" = front.service ]; then
      echo "  secret.service"; echo "  db.service"
    elif [ "$rev" = 1 ]; then
      echo "  multi-user.target"; echo "  site.target"
    else
      echo "  db.service"; echo "  system.slice"
    fi ;;
  status)
    echo "o $last - a unit"
    echo "     Loaded: loaded (/etc/systemd/system/$last; enabled)"
    echo "     Active: inactive (dead)"
    echo "  Condition: start condition unmet at Fri 2026-11-20 10:00:00 UTC; 5min ago"
    echo "             \`- ConditionPathExists=/etc/app --password=hunter2 was not met"
    echo "       Docs: man:app(8)"
    exit 3 ;;
esac
"#
        );
        FakeBins::new().add_script("systemctl", &body)
    }

    fn fake_all() -> FakeBins {
        fake_systemctl().add(
            "systemd-analyze",
            "The time when unit became active or started is printed after the \"@\" character.\n\
             web.service +43ms\n└─db.service @4.616s +1.2s\n",
            0,
        )
    }

    fn fixture(fake: &FakeBins) -> (Arc<Host>, MemorySink) {
        host(&format!(
            r#"
[roles.admin]
allow = ["@all"]
[roles.reader]
allow = ["@read"]
[roles.web]
allow = ["service.view:web.service", "service.limits:web.service"]
[roles.hidden]
allow = ["service.view"]
deny = ["service.view:secret.service"]
[unix_users.adam]
roles = ["admin"]
[unix_users.rita]
roles = ["reader"]
[unix_users.wendy]
roles = ["web"]
[unix_users.hal]
roles = ["hidden"]
{}"#,
            fake.config_only()
        ))
    }

    fn roots(tree: &tempfile::TempDir) -> Roots {
        Roots {
            cgroup: tree.path().to_path_buf(),
        }
    }

    async fn run(
        host: &Arc<Host>,
        tree: &tempfile::TempDir,
        user: &str,
        tool: &str,
        arguments: Value,
    ) -> ToolResult {
        call(host, user, &find(tools_with(roots(tree)), tool), arguments).await
    }

    /// The runs of systemctl whose arguments include `word`.
    fn runs_with(fake: &FakeBins, word: &str) -> Vec<Vec<String>> {
        fake.calls("systemctl")
            .into_iter()
            .filter(|argv| argv.iter().any(|a| a == word))
            .collect()
    }

    // ---- cgroup_limits -----------------------------------------------------------------

    #[tokio::test]
    async fn one_unit_is_reported_in_sentences_with_the_verdict_first() {
        let fake = fake_systemctl();
        let (host, audit) = fixture(&fake);
        let tree = cgroup_tree();
        let text = ok_text(
            run(
                &host,
                &tree,
                "rita",
                "cgroup_limits",
                json!({"unit": "web"}),
            )
            .await,
        );
        assert!(
            text.starts_with(
                "web.service: PROBLEM: 1 OOM kill; the memory limit was hit 3 times; \
                 CPU was throttled in 4.6% of periods\n"
            ),
            "{text}"
        );
        assert!(
            text.contains("Memory: 1.2 GiB in use of a 2.0 GiB limit (60%)"),
            "{text}"
        );
        assert!(text.contains("Tasks: 12 of at most 512."), "{text}");
        assert!(text.contains("/system.slice/web.service"), "{text}");
        assert_eq!(audit.records().last().unwrap()["resource"], "web.service");
        // the unit was looked up first, then asked for its control group
        let calls = fake.calls("systemctl");
        assert_eq!(
            calls[0],
            strings(&[
                "show",
                "--property=Id",
                "--property=LoadState",
                "--",
                "web.service"
            ])
        );
        assert!(
            calls[1].contains(&"--property=ControlGroup".to_string()),
            "{calls:?}"
        );
        assert_eq!(calls[1].last().unwrap(), "web.service");
        assert_eq!(calls[1][calls[1].len() - 2], "--");
    }

    #[tokio::test]
    async fn a_unit_with_nothing_wrong_says_so_first() {
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake);
        let tree = cgroup_tree();
        // the same unit, had it never hit its limits
        put(
            tree.path(),
            "system.slice/web.service/memory.events",
            "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n",
        );
        put(
            tree.path(),
            "system.slice/web.service/cpu.stat",
            "usage_usec 1000\nnr_periods 10\nnr_throttled 0\nthrottled_usec 0\n",
        );
        let text = ok_text(
            run(
                &host,
                &tree,
                "rita",
                "cgroup_limits",
                json!({"unit": "web.service"}),
            )
            .await,
        );
        assert!(
            text.starts_with("web.service: no limit is being hit.\n"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn a_unit_is_judged_by_its_real_name_not_the_alias_asked_for() {
        let fake = fake_systemctl();
        let (host, audit) = fixture(&fake);
        let tree = cgroup_tree();
        // wendy may view web.service; alias.service is another name for it
        let text = ok_text(
            run(
                &host,
                &tree,
                "wendy",
                "cgroup_limits",
                json!({"unit": "alias.service"}),
            )
            .await,
        );
        assert!(text.starts_with("web.service:"), "{text}");
        assert_eq!(audit.records().last().unwrap()["resource"], "web.service");
        // and nothing else
        let result = run(
            &host,
            &tree,
            "wendy",
            "cgroup_limits",
            json!({"unit": "db.service"}),
        )
        .await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        assert_eq!(audit.records().last().unwrap()["decision"], "deny");
    }

    #[tokio::test]
    async fn a_unit_that_does_not_exist_is_a_failure_after_authorization() {
        let fake = fake_systemctl();
        let (host, audit) = fixture(&fake);
        let tree = cgroup_tree();
        for tool in ["cgroup_limits", "service_dependencies"] {
            match run(&host, &tree, "rita", tool, json!({"unit": "ghost"})).await {
                Err(ToolError::Failed(message)) => {
                    assert!(message.contains("no such unit"), "{message}");
                }
                other => panic!("{tool}: expected a failure, got {other:?}"),
            }
            assert_eq!(audit.records().last().unwrap()["decision"], "allow");
            // someone without the grant learns nothing about what exists
            let result = run(&host, &tree, "wendy", tool, json!({"unit": "ghost"})).await;
            assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        }
    }

    #[tokio::test]
    async fn unit_names_are_checked_before_anything_runs() {
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake);
        let tree = cgroup_tree();
        for tool in ["cgroup_limits", "service_dependencies", "service_limits"] {
            for bad in ["", "-x", "web*", "a b", "web.service;id", "../x", "--now"] {
                let arguments = if tool == "service_limits" {
                    json!({"unit": bad, "tasks_max": 10})
                } else {
                    json!({"unit": bad})
                };
                let result = run(&host, &tree, "adam", tool, arguments).await;
                assert!(
                    matches!(result, Err(ToolError::Invalid(_))),
                    "{tool} {bad:?}: {result:?}"
                );
            }
        }
        assert_eq!(fake.calls("systemctl"), Vec::<Vec<String>>::new());
    }

    #[tokio::test]
    async fn a_name_systemd_reports_that_is_not_a_unit_name_is_not_used() {
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake);
        let tree = cgroup_tree();
        let result = run(
            &host,
            &tree,
            "adam",
            "cgroup_limits",
            json!({"unit": "odd.service"}),
        )
        .await;
        assert!(matches!(result, Err(ToolError::Failed(_))), "{result:?}");
        assert_eq!(fake.calls("systemctl").len(), 1);
    }

    #[tokio::test]
    async fn a_unit_that_is_not_running_shows_what_systemd_has_configured() {
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake);
        let tree = cgroup_tree();
        let text = ok_text(
            run(
                &host,
                &tree,
                "rita",
                "cgroup_limits",
                json!({"unit": "idle.service"}),
            )
            .await,
        );
        assert!(
            text.starts_with("idle.service: it has no control group"),
            "{text}"
        );
        assert!(text.contains("Limits configured in systemd:"), "{text}");
        assert!(text.contains("TasksMax=4915"), "{text}");
        assert!(text.contains("MemoryMax=infinity"), "{text}");
    }

    #[tokio::test]
    async fn a_control_group_path_that_leaves_the_hierarchy_is_not_read() {
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake);
        let tree = tempfile::tempdir().unwrap();
        let inner = tree.path().join("cgroup");
        put(&inner, "cgroup.controllers", "cpu memory pids\n");
        // what "/system.slice/../../outside" would reach if it were followed
        put(tree.path(), "outside/memory.current", "424242\n");
        put(tree.path(), "outside/memory.max", "434343\n");
        let tool = find(
            tools_with(Roots {
                cgroup: inner.clone(),
            }),
            "cgroup_limits",
        );
        let text = ok_text(call(&host, "rita", &tool, json!({"unit": "evil.service"})).await);
        assert!(text.contains("unusable control group"), "{text}");
        assert!(!text.contains("414.3 KiB"), "{text}");
        assert!(!text.contains("424242"), "{text}");
    }

    #[tokio::test]
    async fn without_the_unified_hierarchy_only_the_systemd_settings_are_shown() {
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake);
        let tree = cgroup_tree();
        std::fs::remove_file(tree.path().join("cgroup.controllers")).unwrap();
        let text = ok_text(
            run(
                &host,
                &tree,
                "rita",
                "cgroup_limits",
                json!({"unit": "web.service"}),
            )
            .await,
        );
        assert!(text.contains("cgroup v2"), "{text}");
        assert!(text.contains("Limits configured in systemd:"), "{text}");
        assert!(text.contains("MemoryMax=2147483648 (2.0 GiB)"), "{text}");
        assert!(text.contains("TasksMax=512"), "{text}");
        assert!(!text.contains("in use of"), "{text}");

        let all = ok_text(run(&host, &tree, "rita", "cgroup_limits", json!({})).await);
        assert!(all.contains("cgroup v2"), "{all}");
        assert!(!all.contains("web.service"), "{all}");
    }

    #[tokio::test]
    async fn without_a_unit_the_units_with_limits_or_events_are_listed_problems_first() {
        let fake = fake_systemctl();
        let (host, audit) = fixture(&fake);
        let tree = cgroup_tree();
        let text = ok_text(run(&host, &tree, "adam", "cgroup_limits", json!({})).await);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[0],
            "4 units are at or over a limit: web.service, docker-abc.scope, \
             pg@14-main.service, session-3.scope",
            "{text}"
        );
        assert!(
            lines[1].starts_with("UNIT") && lines[1].contains("OOM-KILLS"),
            "{text}"
        );
        let units: Vec<&str> = lines[2..7]
            .iter()
            .map(|line| line.split_whitespace().next().unwrap())
            .collect();
        assert_eq!(
            units,
            [
                "web.service",
                "docker-abc.scope",
                "pg@14-main.service",
                "session-3.scope",
                "secret.service"
            ],
            "{text}"
        );
        // a unit with nothing set and nothing recorded is not listed
        assert!(!text.contains("quiet.service"), "{text}");
        let web = lines[2];
        for want in ["1.2 GiB", "2.0 GiB (60%)", "4.6%", "12/512"] {
            assert!(web.contains(want), "missing {want:?} in {web:?}");
        }
        let docker = lines[3];
        assert!(docker.contains("50.0%"), "{docker}");
        assert!(lines[4].contains("(95%)"), "{}", lines[4]);
        assert!(lines[5].contains("30/100"), "{}", lines[5]);
        assert!(!text.contains("are not shown"), "{text}");
        // the whole-host view is one operation without a resource; no command is run
        let record = audit.records().last().unwrap().clone();
        assert_eq!(record["decision"], "allow");
        assert!(record.get("resource").is_none(), "{record}");
        assert_eq!(fake.calls("systemctl"), Vec::<Vec<String>>::new());
    }

    #[tokio::test]
    async fn a_caller_with_a_deny_for_one_unit_cannot_list_them_all() {
        let fake = fake_systemctl();
        let (host, audit) = fixture(&fake);
        let tree = cgroup_tree();
        // hal may view every unit but secret.service. The list has no resource, so the
        // policy refuses it outright rather than trusting a filter; the unit can still
        // be asked for by name.
        let result = run(&host, &tree, "hal", "cgroup_limits", json!({})).await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        assert_eq!(audit.records().last().unwrap()["decision"], "deny");
        ok_text(
            run(
                &host,
                &tree,
                "hal",
                "cgroup_limits",
                json!({"unit": "web.service"}),
            )
            .await,
        );
    }

    #[test]
    fn the_list_says_when_units_were_left_out_or_the_search_was_cut_short() {
        let row = |unit: &str, figures: Figures| Row {
            unit: unit.to_string(),
            figures,
        };
        let limited = Figures {
            memory_current: Some(1 << 20),
            memory_max: Some(Limit::At(1 << 30)),
            ..Figures::default()
        };
        let text = render_list(vec![row("a.service", limited.clone())], true, false, 50);
        assert!(
            text.starts_with("No unit is at or over a limit (1 unit with a limit set).\n"),
            "{text}"
        );
        assert!(
            text.contains("[some units are not shown: this caller may not view them]"),
            "{text}"
        );
        assert!(
            text.contains("[the search stopped after 5000 control groups: the list is incomplete]"),
            "{text}"
        );
        // nothing the caller may see, but something was hidden: do not claim there is nothing
        let text = render_list(Vec::new(), true, true, 50);
        assert!(
            text.starts_with("No unit that this caller may view has a limit set"),
            "{text}"
        );
        assert!(text.contains("are not shown"), "{text}");
        // one unit in trouble is named in the singular
        let killed = Figures {
            memory_events: keyed("oom_kill 2\n"),
            ..limited
        };
        let text = render_list(vec![row("b.service", killed)], false, true, 50);
        assert!(
            text.starts_with("1 unit is at or over a limit: b.service\n"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn the_list_needs_a_grant_for_every_unit() {
        let fake = fake_systemctl();
        let (host, audit) = fixture(&fake);
        let tree = cgroup_tree();
        // wendy may view web.service only
        let result = run(&host, &tree, "wendy", "cgroup_limits", json!({})).await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        assert_eq!(audit.records().last().unwrap()["decision"], "deny");
    }

    #[tokio::test]
    async fn the_list_is_cut_at_the_limit_and_says_so() {
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake);
        let tree = cgroup_tree();
        let text = ok_text(run(&host, &tree, "adam", "cgroup_limits", json!({"limit": 2})).await);
        assert!(text.contains("web.service"), "{text}");
        assert!(text.contains("docker-abc.scope"), "{text}");
        assert!(!text.contains("secret.service"), "{text}");
        assert!(text.contains("[3 more units left out"), "{text}");
        let one = ok_text(run(&host, &tree, "adam", "cgroup_limits", json!({"limit": 4})).await);
        assert!(one.contains("[1 more unit left out"), "{one}");
    }

    #[tokio::test]
    async fn a_host_where_nothing_is_limited_says_so() {
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake);
        let tree = tempfile::tempdir().unwrap();
        put(tree.path(), "cgroup.controllers", "cpu memory pids\n");
        put(
            tree.path(),
            "system.slice/quiet.service/memory.current",
            "1048576\n",
        );
        put(
            tree.path(),
            "system.slice/quiet.service/memory.max",
            "max\n",
        );
        let text = ok_text(run(&host, &tree, "rita", "cgroup_limits", json!({})).await);
        assert_eq!(
            text,
            "No service or scope has a limit set or has hit one.\n"
        );
    }

    // ---- service_limits ----------------------------------------------------------------

    #[tokio::test]
    async fn limits_are_set_for_the_running_unit_only_and_the_result_says_so() {
        let fake = fake_systemctl();
        let (host, audit) = fixture(&fake);
        let tree = cgroup_tree();
        let output = run(
            &host,
            &tree,
            "wendy",
            "service_limits",
            json!({"unit": "web", "memory_max": "2G", "memory_high": "1536M",
                   "cpu_quota_percent": 150, "tasks_max": 512}),
        )
        .await
        .unwrap();
        assert!(!output.is_error(), "{}", output.text());
        assert_eq!(
            runs_with(&fake, "set-property"),
            [strings(&[
                "--no-ask-password",
                "--runtime",
                "set-property",
                "--",
                "web.service",
                "MemoryMax=2G",
                "MemoryHigh=1536M",
                "CPUQuota=150%",
                "TasksMax=512",
            ])]
        );
        let text = output.text();
        assert!(
            text.starts_with(
                "Set on web.service: MemoryMax=2G, MemoryHigh=1536M, CPUQuota=150%, TasksMax=512.\n"
            ),
            "{text}"
        );
        assert!(text.contains("until the next reboot"), "{text}");
        assert!(text.contains("nothing was written under /etc"), "{text}");
        // followed by the unit's figures, as cgroup_limits shows them
        assert!(text.contains("Memory: 1.2 GiB in use"), "{text}");
        let record = audit.records().last().unwrap().clone();
        assert_eq!(record["resource"], "web.service");
        assert_eq!(record["decision"], "allow");
    }

    #[tokio::test]
    async fn a_limit_is_removed_with_infinity_or_zero() {
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake);
        let tree = cgroup_tree();
        let text = ok_text(
            run(
                &host,
                &tree,
                "adam",
                "service_limits",
                json!({"unit": "web.service", "memory_max": "infinity",
                       "cpu_quota_percent": 0, "tasks_max": 0}),
            )
            .await,
        );
        let calls = runs_with(&fake, "set-property");
        assert_eq!(
            calls[0][4..],
            strings(&[
                "web.service",
                "MemoryMax=infinity",
                "CPUQuota=",
                "TasksMax=infinity"
            ])
        );
        assert!(text.contains("CPUQuota= (no quota)"), "{text}");
    }

    #[tokio::test]
    async fn at_least_one_limit_must_be_given_and_each_must_be_well_formed() {
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake);
        let tree = cgroup_tree();
        let cases = [
            json!({"unit": "web.service"}),
            json!({"unit": "web.service", "force": true}),
            json!({"unit": "web.service", "memory_max": "2g"}),
            json!({"unit": "web.service", "memory_max": "0"}),
            json!({"unit": "web.service", "memory_max": "1G MemoryMax=infinity"}),
            json!({"unit": "web.service", "memory_high": "-1"}),
            json!({"unit": "web.service", "memory_high": "1.5G"}),
            json!({"unit": "web.service", "cpu_quota_percent": -1}),
            json!({"unit": "web.service", "cpu_quota_percent": 100001}),
            json!({"unit": "web.service", "tasks_max": 4194305}),
            // limits belong to services and scopes
            json!({"unit": "web.timer", "tasks_max": 10}),
            json!({"unit": "tmp.mount", "memory_max": "1G"}),
            // (the root slice is not even a name that is accepted)
            json!({"unit": "-.slice", "tasks_max": 10}),
        ];
        for arguments in cases {
            let result = run(&host, &tree, "adam", "service_limits", arguments.clone()).await;
            assert!(
                matches!(result, Err(ToolError::Invalid(_))),
                "{arguments}: {result:?}"
            );
        }
        assert_eq!(fake.calls("systemctl"), Vec::<Vec<String>>::new());
    }

    #[tokio::test]
    async fn a_protected_unit_cannot_be_limited_whatever_the_grant() {
        let fake = fake_systemctl();
        let (host, audit) = fixture(&fake);
        let tree = cgroup_tree();
        for unit in ["dbus.service", "opsmcp.service", "systemd-journald.service"] {
            let result = run(
                &host,
                &tree,
                "adam",
                "service_limits",
                json!({"unit": unit, "memory_max": "1G"}),
            )
            .await;
            match result {
                Err(ToolError::Denied(message)) => {
                    assert!(message.contains("protected"), "{message}");
                }
                other => panic!("{unit}: expected a refusal, got {other:?}"),
            }
            let record = audit.records().last().unwrap().clone();
            assert_eq!(record["decision"], "deny");
            assert_eq!(record["resource"], unit);
        }
        assert_eq!(runs_with(&fake, "set-property"), Vec::<Vec<String>>::new());
    }

    /// AIDEV-NOTE: a limit on a slice holds back everything under it. system.slice
    /// holds journald, logind, dbus and opsmcp itself, the units `services.protected`
    /// keeps out of reach, and init.scope is systemd. So neither is offered at all.
    #[tokio::test]
    async fn a_slice_or_the_init_scope_cannot_be_limited_whatever_the_grant() {
        let fake = fake_systemctl();
        let (host, audit) = fixture(&fake);
        let tree = cgroup_tree();
        for (unit, why) in [
            ("system.slice", "everything under it"),
            ("user.slice", "everything under it"),
            ("user-1000.slice", "everything under it"),
            ("system-postgresql.slice", "everything under it"),
            ("init.scope", "systemd itself"),
        ] {
            for arguments in [
                json!({"unit": unit, "cpu_quota_percent": 50}),
                json!({"unit": unit, "memory_high": "1G", "force": true}),
            ] {
                match run(&host, &tree, "adam", "service_limits", arguments.clone()).await {
                    Err(ToolError::Denied(message)) => {
                        assert!(message.contains(why), "{unit}: {message}");
                    }
                    other => panic!("{arguments}: expected a refusal, got {other:?}"),
                }
                let record = audit.records().last().unwrap().clone();
                assert_eq!(record["decision"], "deny");
                assert_eq!(record["resource"], unit);
            }
        }
        // nothing at all was asked of systemd
        assert_eq!(fake.calls("systemctl"), Vec::<Vec<String>>::new());
        // a scope with processes of its own is still fine
        ok_text(
            run(
                &host,
                &tree,
                "adam",
                "service_limits",
                json!({"unit": "session-3.scope", "tasks_max": 100}),
            )
            .await,
        );
        assert_eq!(runs_with(&fake, "set-property").len(), 1);
    }

    #[tokio::test]
    async fn a_high_mark_below_what_is_used_or_almost_no_cpu_needs_force() {
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake);
        let tree = cgroup_tree();
        for (arguments, why) in [
            // web.service uses 1.2 GiB
            (
                json!({"unit": "web.service", "memory_high": "1G"}),
                "1.2 GiB",
            ),
            (json!({"unit": "web.service", "cpu_quota_percent": 1}), "1%"),
            (json!({"unit": "web.service", "cpu_quota_percent": 9}), "9%"),
        ] {
            let output = run(&host, &tree, "adam", "service_limits", arguments.clone())
                .await
                .unwrap();
            assert!(output.is_error(), "{arguments}");
            let text = output.text();
            assert!(
                text.contains(why)
                    && text.contains("force")
                    && text.contains("Nothing was changed"),
                "{arguments}: {text}"
            );
        }
        assert_eq!(runs_with(&fake, "set-property"), Vec::<Vec<String>>::new());

        for arguments in [
            // above what it uses; a tenth of a CPU; no quota at all; and with force
            json!({"unit": "web.service", "memory_high": "1536M"}),
            json!({"unit": "web.service", "cpu_quota_percent": 10}),
            json!({"unit": "web.service", "cpu_quota_percent": 0}),
            json!({"unit": "web.service", "cpu_quota_percent": 5, "force": true}),
            json!({"unit": "web.service", "memory_high": "1G", "force": true}),
            // a high mark of "infinity" is never below anything
            json!({"unit": "web.service", "memory_high": "infinity"}),
        ] {
            ok_text(run(&host, &tree, "adam", "service_limits", arguments).await);
        }
        assert_eq!(runs_with(&fake, "set-property").len(), 6);
    }

    #[tokio::test]
    async fn a_grant_for_one_unit_does_not_reach_another_or_a_reader() {
        let fake = fake_systemctl();
        let (host, audit) = fixture(&fake);
        let tree = cgroup_tree();
        let result = run(
            &host,
            &tree,
            "wendy",
            "service_limits",
            json!({"unit": "db.service", "tasks_max": 100}),
        )
        .await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        assert_eq!(audit.records().last().unwrap()["resource"], "db.service");
        // an alias is judged, and acted on, by the unit's real name
        ok_text(
            run(
                &host,
                &tree,
                "wendy",
                "service_limits",
                json!({"unit": "alias.service", "tasks_max": 100}),
            )
            .await,
        );
        let calls = runs_with(&fake, "set-property");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0][4..], strings(&["web.service", "TasksMax=100"]));
    }

    #[tokio::test]
    async fn a_unit_that_does_not_exist_cannot_be_limited() {
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake);
        let tree = cgroup_tree();
        let result = run(
            &host,
            &tree,
            "adam",
            "service_limits",
            json!({"unit": "ghost.service", "tasks_max": 100}),
        )
        .await;
        match result {
            Err(ToolError::Failed(message)) => {
                assert!(message.contains("no such unit"), "{message}")
            }
            other => panic!("expected a failure, got {other:?}"),
        }
        assert_eq!(runs_with(&fake, "set-property"), Vec::<Vec<String>>::new());
    }

    #[tokio::test]
    async fn a_memory_limit_below_what_the_unit_uses_needs_force() {
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake);
        let tree = cgroup_tree();
        // web.service uses 1.2 GiB
        let arguments = json!({"unit": "web.service", "memory_max": "1G"});
        let output = run(&host, &tree, "adam", "service_limits", arguments)
            .await
            .unwrap();
        assert!(output.is_error());
        assert!(
            output.text().contains("1.2 GiB") && output.text().contains("force"),
            "{}",
            output.text()
        );
        assert!(
            output.text().contains("Nothing was changed"),
            "{}",
            output.text()
        );
        assert_eq!(runs_with(&fake, "set-property"), Vec::<Vec<String>>::new());

        let forced = json!({"unit": "web.service", "memory_max": "1G", "force": true});
        ok_text(run(&host, &tree, "adam", "service_limits", forced).await);
        assert_eq!(runs_with(&fake, "set-property").len(), 1);
    }

    #[tokio::test]
    async fn a_tiny_memory_limit_or_too_few_tasks_needs_force() {
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake);
        let tree = cgroup_tree();
        // idle.service is not running, so there is no current use to compare with: the
        // floor still applies
        for arguments in [
            json!({"unit": "idle.service", "memory_max": "8M"}),
            json!({"unit": "web.service", "memory_max": "16777215"}),
            // web.service has 12 tasks
            json!({"unit": "web.service", "tasks_max": 11}),
        ] {
            let output = run(&host, &tree, "adam", "service_limits", arguments.clone())
                .await
                .unwrap();
            assert!(output.is_error(), "{arguments}");
            assert!(output.text().contains("force"), "{}", output.text());
        }
        assert_eq!(runs_with(&fake, "set-property"), Vec::<Vec<String>>::new());

        // exactly at the floor, and exactly at the current number of tasks, is allowed
        for arguments in [
            json!({"unit": "idle.service", "memory_max": "16M"}),
            json!({"unit": "web.service", "tasks_max": 12}),
            json!({"unit": "web.service", "tasks_max": 11, "force": true}),
            // a high mark only slows the unit down: no floor
            json!({"unit": "idle.service", "memory_high": "8M"}),
        ] {
            ok_text(run(&host, &tree, "adam", "service_limits", arguments).await);
        }
        assert_eq!(runs_with(&fake, "set-property").len(), 4);
    }

    #[tokio::test]
    async fn a_failed_change_is_an_error_result_with_systemds_message() {
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake);
        let tree = cgroup_tree();
        let output = run(
            &host,
            &tree,
            "adam",
            "service_limits",
            json!({"unit": "broken.service", "tasks_max": 100}),
        )
        .await
        .unwrap();
        assert!(output.is_error());
        assert!(output.text().contains("Access denied"), "{}", output.text());
        assert!(output.text().contains("FAILED"), "{}", output.text());
        assert!(!output.text().contains("Set on"), "{}", output.text());
    }

    // ---- service_dependencies ----------------------------------------------------------

    #[tokio::test]
    async fn dependencies_show_the_state_what_is_needed_and_what_failed() {
        let fake = fake_all();
        let (host, audit) = fixture(&fake);
        let tree = cgroup_tree();
        let text = ok_text(
            run(
                &host,
                &tree,
                "rita",
                "service_dependencies",
                json!({"unit": "web"}),
            )
            .await,
        );
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[0],
            "web.service: active (running), last result success; PROBLEM: a requirement \
             has failed: db.service",
            "{text}"
        );
        assert!(
            text.contains("Requirement FAILED: db.service (failed, exit-code)"),
            "{text}"
        );
        assert!(
            text.contains("Requirement not active: cache.service (inactive, dead)"),
            "{text}"
        );
        for want in [
            "Requires: system.slice sysinit.target db.service -.mount --now",
            "BindsTo: cache.service",
            "Wants: logger.service",
            "After: basic.target db.service",
            "RequiredBy: site.target",
            "WantedBy: multi-user.target",
            "TriggeredBy: web.socket",
            "  db.service\n",
            "  site.target\n",
            "web.service +43ms",
        ] {
            assert!(text.contains(want), "missing {want:?} in:\n{text}");
        }
        // empty lists are left out
        assert!(!text.contains("Requisite:"), "{text}");
        assert!(!text.contains("PartOf:"), "{text}");
        assert_eq!(audit.records().last().unwrap()["resource"], "web.service");

        // the requirements were asked about in one run, and only by real unit names:
        // "-.mount" and "--now" are never passed as arguments
        let states: Vec<Vec<String>> = fake
            .calls("systemctl")
            .into_iter()
            .filter(|argv| {
                argv.contains(&"--property=SubState".to_string())
                    && !argv.contains(&"--property=Requires".to_string())
            })
            .collect();
        let asked: Vec<&String> = states
            .iter()
            .flat_map(|argv| argv.iter().skip_while(|a| *a != "--").skip(1))
            .collect();
        assert_eq!(
            asked,
            [
                "system.slice",
                "sysinit.target",
                "db.service",
                "cache.service"
            ]
        );
        for argv in fake.calls("systemctl") {
            let after: Vec<&String> = argv.iter().skip_while(|a| *a != "--").skip(1).collect();
            assert!(
                !after.iter().any(|a| a.starts_with('-')),
                "an option-like name reached systemctl: {argv:?}"
            );
        }
        assert_eq!(
            fake.calls("systemd-analyze"),
            [strings(&[
                "critical-chain",
                "--no-pager",
                "--",
                "web.service"
            ])]
        );
    }

    #[tokio::test]
    async fn the_direction_chooses_which_half_is_shown() {
        let fake = fake_all();
        let (host, _audit) = fixture(&fake);
        let tree = cgroup_tree();
        let needs = ok_text(
            run(
                &host,
                &tree,
                "rita",
                "service_dependencies",
                json!({"unit": "web.service", "direction": "needs"}),
            )
            .await,
        );
        assert!(needs.contains("Requires:"), "{needs}");
        assert!(!needs.contains("WantedBy:"), "{needs}");
        assert_eq!(runs_with(&fake, "--reverse"), Vec::<Vec<String>>::new());
        assert_eq!(
            runs_with(&fake, "list-dependencies"),
            [strings(&[
                "list-dependencies",
                "--plain",
                "--no-pager",
                "--",
                "web.service"
            ])]
        );

        let fake = fake_all();
        let (host, _audit) = fixture(&fake);
        let needed_by = ok_text(
            run(
                &host,
                &tree,
                "rita",
                "service_dependencies",
                json!({"unit": "web.service", "direction": "needed_by"}),
            )
            .await,
        );
        assert!(
            needed_by.contains("WantedBy: multi-user.target"),
            "{needed_by}"
        );
        assert!(!needed_by.contains("Requires:"), "{needed_by}");
        assert!(needed_by.contains("  multi-user.target\n"), "{needed_by}");
        assert_eq!(
            runs_with(&fake, "list-dependencies"),
            [strings(&[
                "list-dependencies",
                "--plain",
                "--no-pager",
                "--reverse",
                "--",
                "web.service"
            ])]
        );
        // the boot chain is about what the unit waited for: not part of "needed by"
        assert_eq!(fake.calls("systemd-analyze"), Vec::<Vec<String>>::new());
    }

    #[tokio::test]
    async fn an_unmet_start_condition_is_quoted_with_secrets_masked() {
        let fake = fake_all();
        let (host, _audit) = fixture(&fake);
        let tree = cgroup_tree();
        let text = ok_text(
            run(
                &host,
                &tree,
                "rita",
                "service_dependencies",
                json!({"unit": "waiting.service"}),
            )
            .await,
        );
        assert!(
            text.lines()
                .next()
                .unwrap()
                .ends_with("; its start was skipped: a start condition was not met"),
            "{text}"
        );
        assert!(
            text.contains("Condition: start condition unmet at"),
            "{text}"
        );
        assert!(text.contains("ConditionPathExists=/etc/app"), "{text}");
        assert!(!text.contains("hunter2"), "{text}");
        // only the condition lines are taken from the status output
        assert!(!text.contains("Docs:"), "{text}");
        assert!(!text.contains("Loaded:"), "{text}");
        assert_eq!(
            runs_with(&fake, "status"),
            [strings(&[
                "status",
                "--no-pager",
                "--lines=0",
                "--",
                "waiting.service"
            ])]
        );
    }

    #[tokio::test]
    async fn a_unit_nothing_ever_tried_to_start_has_no_unmet_condition() {
        // systemd says ConditionResult=no for it all the same: without a timestamp that
        // is not the outcome of a check
        let fake = fake_all();
        let (host, _audit) = fixture(&fake);
        let tree = cgroup_tree();
        let text = ok_text(
            run(
                &host,
                &tree,
                "rita",
                "service_dependencies",
                json!({"unit": "never.service"}),
            )
            .await,
        );
        assert_eq!(
            text.lines().next().unwrap(),
            "never.service: inactive (dead), last result success",
            "{text}"
        );
        assert!(!text.contains("PROBLEM"), "{text}");
        assert_eq!(runs_with(&fake, "status"), Vec::<Vec<String>>::new());
    }

    #[test]
    fn condition_lines_are_found_in_either_way_of_drawing_the_tree() {
        let utf8 = "● app.service - App\n     Loaded: loaded (/etc/systemd/system/app.service)\n\
                    \x20 Condition: start condition unmet at Fri 2026-11-20 10:00:00 UTC; 5min ago\n\
                    \x20            ├─ ConditionPathExists=/etc/a was not met\n\
                    \x20            └─ ConditionPathExists=/etc/b was not met\n\
                    \x20      Docs: man:app(8)\n\
                    \x20            └─ not a condition\n";
        assert_eq!(
            condition_lines(utf8),
            [
                "Condition: start condition unmet at Fri 2026-11-20 10:00:00 UTC; 5min ago",
                "  ├─ ConditionPathExists=/etc/a was not met",
                "  └─ ConditionPathExists=/etc/b was not met",
            ]
        );
        let ascii = "* app.service - App\n     Active: inactive (dead)\n\
                     \x20    Assert: start assertion failed at Fri 2026-11-20 10:00:00 UTC; 5min ago\n\
                     \x20            |- AssertPathExists=/etc/a was not met\n\
                     \x20            `- AssertPathExists=/etc/b was not met\n\
                     \x20   Drop-In: /etc/systemd/system/app.service.d\n\
                     \x20            `-override.conf\n";
        assert_eq!(
            condition_lines(ascii),
            [
                "Assert: start assertion failed at Fri 2026-11-20 10:00:00 UTC; 5min ago",
                "  |- AssertPathExists=/etc/a was not met",
                "  `- AssertPathExists=/etc/b was not met",
            ]
        );
        assert_eq!(
            condition_lines("Active: active (running)\n"),
            Vec::<String>::new()
        );
    }

    #[tokio::test]
    async fn a_unit_whose_conditions_held_does_not_run_status() {
        let fake = fake_all();
        let (host, _audit) = fixture(&fake);
        let tree = cgroup_tree();
        ok_text(
            run(
                &host,
                &tree,
                "rita",
                "service_dependencies",
                json!({"unit": "web.service"}),
            )
            .await,
        );
        assert_eq!(runs_with(&fake, "status"), Vec::<Vec<String>>::new());
    }

    #[tokio::test]
    async fn a_long_dependency_tree_is_cut_with_a_note() {
        let fake = fake_all();
        let (host, _audit) = fixture(&fake);
        let tree = cgroup_tree();
        let text = ok_text(
            run(
                &host,
                &tree,
                "rita",
                "service_dependencies",
                json!({"unit": "big.service", "direction": "needs"}),
            )
            .await,
        );
        assert!(text.contains("  dep58.service\n"), "{text}");
        assert!(!text.contains("dep59.service"), "{text}");
        assert!(text.contains("[41 more lines left out]"), "{text}");
    }

    #[tokio::test]
    async fn the_boot_chain_is_skipped_with_a_note_when_it_cannot_be_had() {
        let tree = cgroup_tree();
        // not installed
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake);
        let text = ok_text(
            run(
                &host,
                &tree,
                "rita",
                "service_dependencies",
                json!({"unit": "web.service"}),
            )
            .await,
        );
        assert!(
            text.contains("[boot chain left out: systemd-analyze is not installed]"),
            "{text}"
        );
        // installed, but it fails (as it does in a container)
        let fake = fake_systemctl().add_script(
            "systemd-analyze",
            "echo 'Bootup is not yet finished.' >&2\nexit 1",
        );
        let (host, _audit) = fixture(&fake);
        let output = run(
            &host,
            &tree,
            "rita",
            "service_dependencies",
            json!({"unit": "web.service"}),
        )
        .await
        .unwrap();
        assert!(!output.is_error(), "{}", output.text());
        assert!(
            output.text().contains("[boot chain left out:")
                && output.text().contains("Bootup is not yet finished"),
            "{}",
            output.text()
        );
    }

    #[tokio::test]
    async fn dependencies_respect_a_scoped_grant_and_a_deny() {
        let fake = fake_all();
        let (host, audit) = fixture(&fake);
        let tree = cgroup_tree();
        ok_text(
            run(
                &host,
                &tree,
                "wendy",
                "service_dependencies",
                json!({"unit": "alias.service"}),
            )
            .await,
        );
        assert_eq!(audit.records().last().unwrap()["resource"], "web.service");
        let result = run(
            &host,
            &tree,
            "wendy",
            "service_dependencies",
            json!({"unit": "db.service"}),
        )
        .await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        let result = run(
            &host,
            &tree,
            "hal",
            "service_dependencies",
            json!({"unit": "secret.service"}),
        )
        .await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        // nothing beyond the lookup was run for the refused calls
        assert_eq!(runs_with(&fake, "list-dependencies").len(), 2);
    }

    /// AIDEV-NOTE: a unit's dependencies name other units and say what state they are
    /// in. A caller whose grant covers one unit, or who is denied one, must not learn
    /// through a unit they may see what service_status would refuse to tell them.
    #[tokio::test]
    async fn units_the_caller_may_not_see_are_left_out_of_a_units_dependencies() {
        let chain = "The time when unit became active or started is printed after the \"@\" character.\n\
                     \n\
                     front.service +43ms\n\
                     `-secret.service @4.616s +1.2s\n\
                     \x20\x20`-db.service @1.000s\n";
        let fake = fake_systemctl().add("systemd-analyze", chain, 0);
        let (host, _audit) = fixture(&fake);
        let tree = cgroup_tree();
        let note = "[some units are not shown: this caller may not see them]";

        // hal may see every unit but secret.service
        let text = ok_text(
            run(
                &host,
                &tree,
                "hal",
                "service_dependencies",
                json!({"unit": "front.service"}),
            )
            .await,
        );
        assert!(!text.contains("secret"), "{text}");
        assert!(text.contains(note), "{text}");
        assert_eq!(
            text.lines().next().unwrap(),
            "front.service: active (running), last result success; PROBLEM: a requirement \
             has failed: db.service",
            "{text}"
        );
        for want in [
            "Requirement FAILED: db.service (failed, exit-code)",
            "Requires: db.service",
            "Wants: logger.service",
            "RequiredBy: site.target",
            "  db.service\n",
            "front.service +43ms",
            "`-db.service @1.000s",
            "is printed after",
        ] {
            assert!(text.contains(want), "missing {want:?} in:\n{text}");
        }
        // lists that hold nothing the caller may see are not printed empty
        assert!(!text.contains("After:"), "{text}");
        assert!(!text.contains("WantedBy:"), "{text}");
        // and the hidden unit's state was never asked for
        for argv in fake.calls("systemctl") {
            let after: Vec<&String> = argv.iter().skip_while(|a| *a != "--").skip(1).collect();
            assert!(
                !after.iter().any(|a| *a == "secret.service"),
                "the state of a unit the caller may not see was looked up: {argv:?}"
            );
        }

        // rita may see everything: nothing is left out, and nothing says so
        let text = ok_text(
            run(
                &host,
                &tree,
                "rita",
                "service_dependencies",
                json!({"unit": "front.service"}),
            )
            .await,
        );
        assert!(!text.contains("not shown"), "{text}");
        assert!(
            text.lines()
                .next()
                .unwrap()
                .ends_with("PROBLEM: requirements have failed: secret.service, db.service"),
            "{text}"
        );
        assert!(text.contains("`-secret.service @4.616s"), "{text}");
        assert!(text.contains("After: secret.service"), "{text}");

        // wendy's grant covers web.service alone: she sees none of the others by name
        let text = ok_text(
            run(
                &host,
                &tree,
                "wendy",
                "service_dependencies",
                json!({"unit": "web.service"}),
            )
            .await,
        );
        assert_eq!(
            text.lines().next().unwrap(),
            "web.service: active (running), last result success",
            "{text}"
        );
        assert!(text.contains(note), "{text}");
        for hidden in [
            "db.service",
            "cache.service",
            "logger.service",
            "site.target",
            "multi-user.target",
            "sysinit.target",
            "system.slice",
            "web.socket",
            "secret",
        ] {
            assert!(!text.contains(hidden), "{hidden} is shown in:\n{text}");
        }
        assert!(
            text.contains("Needs: nothing this caller may see"),
            "{text}"
        );
    }

    #[test]
    fn dependency_lists_and_trees_keep_only_what_the_caller_may_see() {
        let may_see = |unit: &str| unit != "secret.service" && unit != "b.target";
        // a list
        assert_eq!(
            list_line("Requires", "a.service secret.service c.service", &may_see),
            (Some("  Requires: a.service c.service".to_string()), true)
        );
        assert_eq!(
            list_line("Wants", "a.service", &may_see),
            (Some("  Wants: a.service".to_string()), false)
        );
        assert_eq!(
            list_line("After", "secret.service b.target", &may_see),
            (None, true)
        );
        assert_eq!(list_line("After", "  ", &may_see), (None, false));
        // a tree, as `systemctl list-dependencies --plain` prints it
        assert_eq!(
            visible_lines(
                "web.service\n  secret.service\n  a.service\n",
                tree_unit,
                &may_see
            ),
            ("web.service\n  a.service\n".to_string(), true)
        );
        assert_eq!(
            visible_lines("web.service\n  a.service\n", tree_unit, &may_see),
            ("web.service\n  a.service\n".to_string(), false)
        );
        // the boot chain, in both ways of drawing it; its explanations are kept
        let chain = "The time when unit became active or started is printed after the \"@\" character.\n\
                     \n\
                     web.service +43ms\n\
                     `-secret.service @4.6s +1.2s\n\
                     \x20\x20└─b.target @1.0s\n\
                     \x20\x20\x20\x20`-a.service @0.5s\n";
        let (kept, hidden) = visible_lines(chain, chain_unit, &may_see);
        assert!(hidden);
        assert_eq!(
            kept,
            "The time when unit became active or started is printed after the \"@\" character.\n\
             \n\
             web.service +43ms\n\
             \x20\x20\x20\x20`-a.service @0.5s\n"
        );
        assert_eq!(
            chain_unit("`-network.target @4.616s"),
            Some("network.target")
        );
        assert_eq!(
            chain_unit("  └─sshd.service @4.5s +100ms"),
            Some("sshd.service")
        );
        assert_eq!(chain_unit("sshd.service +43ms"), Some("sshd.service"));
        assert_eq!(chain_unit("The time when unit became active"), None);
        assert_eq!(chain_unit(""), None);
    }

    #[test]
    fn the_tools_are_tagged_as_the_contract_expects() {
        use crate::policy::Access;
        let tools = tools();
        let tags: Vec<(&str, Access, &str)> = tools
            .iter()
            .map(|t| (t.name.as_str(), t.access, t.permission.as_str()))
            .collect();
        assert_eq!(
            tags,
            [
                ("cgroup_limits", Access::Read, "service.view"),
                ("service_limits", Access::Write, "service.limits"),
                ("service_dependencies", Access::Read, "service.view"),
            ]
        );
    }
}
