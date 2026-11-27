//! Ganeti: the virtual machines (instances) of a cluster, its nodes and its jobs, read
//! through `gnt-instance`, `gnt-node` and `gnt-job`.
//!
//! AIDEV-NOTE: nothing here changes an instance, a node or the cluster. What is run is
//! the `list` subcommand of each program, always with a fixed set of output fields, and
//! for one instance `gnt-instance info`. The one thing a caller supplies is an instance
//! or node name, which is checked (`check_host_name`) and so can never be read as an
//! option.
//!
//! AIDEV-NOTE: `gnt-instance info` is not a plain query the way `list` is. Ganeti runs
//! it as a job (INSTANCE_QUERY_DATA, visible in `gnt-job list`) that takes the
//! instance's lock, shared: it waits while another job works on the instance, and it
//! asks the instance's nodes about the disks. So it comes second, after a summary made
//! from `list`, which never waits; when it does not answer, the summary still stands.
//! Its report is passed on as Ganeti printed it, except for what could be a secret
//! (`mask_instance_info`).
//!
//! Ganeti answers only on the cluster's master node. On any other node the commands
//! fail and say which node the master is; that answer is passed on as it is.

use super::args::{Args, Param};
use super::{
    CallClock, Ctx, Tool, ToolError, ToolResult, command_ok, command_text, format_rows,
    format_table,
};
use crate::exec::CmdOutput;
use crate::policy::Access;
use crate::sanitize::{is_sensitive, keep_head, redact_text};
use crate::timefmt::{human_bytes, rfc3339_utc};

const VIEWS: [&str; 4] = ["instances", "instance", "nodes", "jobs"];
/// Between the fields of a line. No name, tag or address Ganeti accepts contains it.
const SEPARATOR: &str = "|";
const INSTANCE_FIELDS: &str =
    "name,status,pnode,snodes,os,be/vcpus,be/maxmem,disk_template,disk.sizes,nic.ips";
const DETAIL_FIELDS: &str = "name,status,pnode,snodes,os,hypervisor,be/vcpus,oper_vcpus,\
                             be/minmem,be/maxmem,oper_ram,disk_template,disk.count,disk.sizes,\
                             disk_usage,nic.ips,nic.macs,nic.modes,nic.links,network_port,tags,\
                             be/auto_balance,ctime,mtime,uuid";
const NODE_FIELDS: &str =
    "name,role,group,pinst_cnt,sinst_cnt,ctotal,mtotal,mnode,mfree,dtotal,dfree";
const JOB_FIELDS: &str = "id,status,summary,start_ts,end_ts";
/// The exit status of a `list` that was asked for a field this version does not have:
/// the rows are still printed, with `??` in that column.
const EXIT_UNKNOWN_FIELD: i32 = 14;
const DEFAULT_INSTANCES: i64 = 200;
const DEFAULT_JOBS: i64 = 20;
const MAX_ROWS: i64 = 1000;

pub fn tools() -> Vec<Tool> {
    vec![Tool::new(
        "ganeti_status",
        "Show the virtual machines of a Ganeti cluster (gnt-instance, gnt-node, gnt-job). \
         By default every instance with its state, the node it runs on, its secondary \
         node, OS, vCPUs, memory, disks and addresses; the first lines name any instance \
         that is in an error state (ERROR_down: it should be running and is not) and \
         count the instances by state. view=instance: one instance in full (name \
         required): a summary with what it uses now and its tags, then Ganeti's own \
         `gnt-instance info` report with every disk and its device and state, every NIC, \
         and the hypervisor and backend parameters. view=nodes: the nodes \
         with their role, memory and disk space, and how many instances each holds. \
         view=jobs: the newest jobs of the cluster and how each ended. Changes nothing. \
         Ganeti answers only on the cluster's master node: asked on another node, the \
         answer is an error that names the master.",
        Access::Read,
        "ganeti.view",
        vec![
            Param::choice(
                "view",
                "What to show: instances (default), instance, nodes or jobs",
                &VIEWS,
            ),
            Param::str(
                "name",
                "view=instance: the instance to show (required), by its full name",
            )
            .max_len(253),
            Param::str(
                "node",
                "view=instances: only the instances whose primary or secondary node this is",
            )
            .max_len(253),
            Param::int(
                "limit",
                "Most rows: instances (default 200), or the newest jobs (default 20)",
                1,
                MAX_ROWS,
            ),
        ],
        ganeti_status,
    )]
}

/// Checks an instance or node name: a host name, starting with a letter or digit so that
/// it can never be read as an option.
pub fn check_host_name(kind: &str, name: &str) -> Result<(), ToolError> {
    let allowed = |c: char| c.is_ascii_alphanumeric() || "._-".contains(c);
    let starts_well = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric());
    if name.len() > 253 || !starts_well || !name.chars().all(allowed) {
        return Err(ToolError::Invalid(format!(
            "{name:?} is not a valid {kind} name"
        )));
    }
    Ok(())
}

/// The arguments of a `list` that prints `fields` for a program to read. `units` asks
/// for sizes as plain numbers of mebibytes; `gnt-job list` has no such option.
pub fn list_argv(fields: &str, units: bool) -> Vec<String> {
    let mut argv = vec![
        "list".to_string(),
        "--no-headers".to_string(),
        format!("--separator={SEPARATOR}"),
    ];
    if units {
        argv.push("--units=m".to_string());
    }
    argv.extend(["-o".to_string(), fields.to_string()]);
    argv
}

/// The lines of a listing that have exactly `columns` fields.
fn rows(listing: &str, columns: usize) -> Vec<Vec<&str>> {
    listing
        .lines()
        .map(|line| line.split(SEPARATOR).collect::<Vec<&str>>())
        .filter(|cells| cells.len() == columns)
        .collect()
}

/// What is said of the lines of a listing that do not have `columns` fields; nothing
/// when all of them do. A list must never be called empty because its lines could not
/// be read.
fn not_rows_note(listing: &str, columns: usize) -> String {
    let not_rows = listing
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter(|line| line.split(SEPARATOR).count() != columns)
        .count();
    match not_rows {
        0 => String::new(),
        1 => "[1 line was not in the form that was asked for and is left out]\n".to_string(),
        n => format!("[{n} lines were not in the form that was asked for and are left out]\n"),
    }
}

/// A number of mebibytes in readable units. What is not a number (`-` for an instance
/// that is down, `?` for a node that does not answer) is shown as it is.
fn mib_cell(cell: &str) -> String {
    cell.parse::<u64>().map_or_else(
        |_| or_dash(cell),
        |mib| human_bytes(mib.saturating_mul(1024 * 1024)),
    )
}

fn or_dash(cell: &str) -> String {
    if cell.is_empty() {
        "-".to_string()
    } else {
        cell.to_string()
    }
}

/// A list Ganeti prints with commas and no spaces, made readable; `-` when empty.
fn spaced(list: &str) -> String {
    or_dash(&list.split(',').collect::<Vec<&str>>().join(", "))
}

/// A comma-separated list of sizes in mebibytes, in readable units.
fn sizes(list: &str) -> String {
    list.split(',')
        .filter(|size| !size.is_empty())
        .map(mib_cell)
        .collect::<Vec<String>>()
        .join(", ")
}

fn counted(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

/// `1 running, 2 ADMIN_down`: how many rows have each value, in the order the values
/// first appear.
fn tally<'a>(values: impl Iterator<Item = &'a str>) -> String {
    let mut counts: Vec<(&str, usize)> = Vec::new();
    for value in values {
        match counts.iter_mut().find(|(seen, _)| *seen == value) {
            Some((_, n)) => *n += 1,
            None => counts.push((value, 1)),
        }
    }
    counts
        .iter()
        .map(|(value, n)| format!("{n} {value}"))
        .collect::<Vec<String>>()
        .join(", ")
}

/// What an instance's error state means, for the states Ganeti has.
fn error_meaning(status: &str) -> Option<&'static str> {
    Some(match status {
        "ERROR_up" => "it is running and should be stopped",
        "ERROR_down" => "it should be running and is not",
        "ERROR_nodedown" => "its node does not answer",
        "ERROR_nodeoffline" => "its node is marked offline",
        "ERROR_wrongnode" => "it is running on a node that is not its primary",
        _ => return None,
    })
}

/// Whether `asked` names `node`: in full, or by the part before the first dot.
fn same_node(node: &str, asked: &str) -> bool {
    node == asked || (!asked.contains('.') && node.split('.').next() == Some(asked))
}

/// Most instances named on the PROBLEM line; the table has them all.
const MAX_PROBLEMS_NAMED: usize = 10;

/// The instances view, from the output of `gnt-instance list` with `INSTANCE_FIELDS`:
/// the verdict, the count by state and the table. `node` keeps only the instances on
/// that node.
pub fn instances_text(listing: &str, node: Option<&str>, limit: usize) -> String {
    let all = rows(listing, 10);
    let picked: Vec<&Vec<&str>> = all
        .iter()
        .filter(|cells| {
            node.is_none_or(|asked| {
                same_node(cells[2], asked) || cells[3].split(',').any(|n| same_node(n, asked))
            })
        })
        .collect();
    let odd = not_rows_note(listing, 10);
    if all.is_empty() && !odd.is_empty() {
        return odd;
    }
    if picked.is_empty() {
        return match node {
            Some(node) => format!("No instances on {node}.\n"),
            None => "No instances on this cluster.\n".to_string(),
        };
    }

    let mut text = String::new();
    let in_error: Vec<String> = picked
        .iter()
        .filter(|cells| cells[1].starts_with("ERROR_"))
        .map(|cells| match error_meaning(cells[1]) {
            Some(meaning) => format!("{} is {} ({meaning})", cells[0], cells[1]),
            None => format!("{} is {}", cells[0], cells[1]),
        })
        .collect();
    if !in_error.is_empty() {
        let named = in_error.len().min(MAX_PROBLEMS_NAMED);
        text.push_str(&format!("PROBLEM: {}", in_error[..named].join("; ")));
        if in_error.len() > named {
            text.push_str(&format!(
                "; and {} more in an error state",
                in_error.len() - named
            ));
        }
        text.push_str(".\n");
    }
    text.push_str(&counted(picked.len(), "instance", "instances"));
    if let Some(node) = node {
        text.push_str(&format!(" on {node}"));
    }
    text.push_str(&format!(
        ": {}.\n\n",
        tally(picked.iter().map(|cells| cells[1]))
    ));

    let table: Vec<Vec<String>> = picked
        .iter()
        .take(limit)
        .map(|cells| {
            let disks = match sizes(cells[8]) {
                sizes if sizes.is_empty() => cells[7].to_string(),
                sizes => format!("{}: {sizes}", cells[7]),
            };
            vec![
                cells[0].to_string(),
                cells[1].to_string(),
                cells[2].to_string(),
                spaced(cells[3]),
                cells[4].to_string(),
                cells[5].to_string(),
                mib_cell(cells[6]),
                disks,
                spaced(cells[9]),
            ]
        })
        .collect();
    text.push_str(&format_table(
        &[
            "INSTANCE",
            "STATUS",
            "NODE",
            "SECONDARY",
            "OS",
            "VCPUS",
            "MEMORY",
            "DISKS",
            "ADDRESSES",
        ],
        &table,
        &[false, false, false, false, false, true, true, false, false],
    ));
    let more = picked.len().saturating_sub(limit);
    if more > 0 {
        text.push_str(&format!(
            "[{more} more not shown; raise limit, or give node]\n"
        ));
    }
    text.push_str(&odd);
    text
}

/// One instance in full, from the one line `gnt-instance list` prints for it with
/// `DETAIL_FIELDS`. `None` when the line does not have those fields.
pub fn instance_text(listing: &str) -> Option<String> {
    let cells = rows(listing, 25).into_iter().next()?;
    let [
        name,
        status,
        pnode,
        snodes,
        os,
        hypervisor,
        vcpus,
        oper_vcpus,
        minmem,
        maxmem,
        oper_ram,
        disk_template,
        disk_count,
        disk_sizes,
        disk_usage,
        nic_ips,
        nic_macs,
        nic_modes,
        nic_links,
        network_port,
        tags,
        auto_balance,
        ctime,
        mtime,
        uuid,
    ] = cells[..]
    else {
        return None;
    };
    let is_number = |cell: &str| cell.parse::<u64>().is_ok();

    let mut cpus = format!("{vcpus} configured");
    if is_number(oper_vcpus) {
        cpus.push_str(&format!(", {oper_vcpus} in use"));
    }
    let mut memory = if minmem == maxmem {
        format!("{} configured", mib_cell(maxmem))
    } else {
        format!("{} to {} configured", mib_cell(minmem), mib_cell(maxmem))
    };
    if is_number(oper_ram) {
        memory.push_str(&format!(", {} in use", mib_cell(oper_ram)));
    }
    let mut disks = disk_template.to_string();
    let listed = sizes(disk_sizes);
    if !listed.is_empty() {
        let count = disk_count.parse::<usize>().unwrap_or(0);
        disks.push_str(&format!(", {}: {listed}", counted(count, "disk", "disks")));
        if disk_usage.parse::<u64>().is_ok_and(|used| used > 0) {
            disks.push_str(&format!(" ({} used on the nodes)", mib_cell(disk_usage)));
        }
    }

    let mut lines: Vec<(String, String)> = vec![
        ("Instance:".to_string(), name.to_string()),
        ("Status:".to_string(), status.to_string()),
        ("Primary node:".to_string(), pnode.to_string()),
        ("Secondary nodes:".to_string(), spaced(snodes)),
        ("OS:".to_string(), os.to_string()),
        ("Hypervisor:".to_string(), hypervisor.to_string()),
        ("vCPUs:".to_string(), cpus),
        ("Memory:".to_string(), memory),
        ("Disks:".to_string(), disks),
    ];
    // One entry per NIC in each of the four lists, in the same order.
    let part = |list: &'_ str, index: usize| -> String {
        or_dash(list.split(',').nth(index).unwrap_or(""))
    };
    let nics = if nic_macs.is_empty() {
        0
    } else {
        nic_macs.split(',').count()
    };
    for index in 0..nics {
        lines.push((
            format!("NIC {index}:"),
            format!(
                "{}, {}, {} on {}",
                part(nic_ips, index),
                part(nic_macs, index),
                part(nic_modes, index),
                part(nic_links, index)
            ),
        ));
    }
    if nics == 0 {
        lines.push(("NICs:".to_string(), "none".to_string()));
    }
    lines.extend([
        ("Console port:".to_string(), or_dash(network_port)),
        ("Tags:".to_string(), spaced(tags)),
        ("Auto-balance:".to_string(), or_dash(auto_balance)),
        ("Created:".to_string(), or_dash(ctime)),
        ("Modified:".to_string(), or_dash(mtime)),
        ("UUID:".to_string(), or_dash(uuid)),
    ]);
    let table: Vec<Vec<String>> = lines
        .into_iter()
        .map(|(label, value)| vec![label, value])
        .collect();
    Some(format_rows(&table, &[false, false]))
}

/// The nodes view, from the output of `gnt-node list` with `NODE_FIELDS`.
pub fn nodes_text(listing: &str) -> String {
    let all = rows(listing, 11);
    let odd = not_rows_note(listing, 11);
    if all.is_empty() {
        return if odd.is_empty() {
            "No nodes were listed.\n".to_string()
        } else {
            odd
        };
    }
    let warnings: Vec<String> = all
        .iter()
        .filter_map(|cells| match cells[1] {
            "O" => Some(format!("{} is offline", cells[0])),
            "D" => Some(format!(
                "{} is drained (no new instances are placed on it)",
                cells[0]
            )),
            // AIDEV-NOTE: found against Ganeti 3.0.2: a node whose daemon is dead keeps
            // its role in the list, and has `?` where it would have had to be asked (its
            // memory, CPUs and disk). Disk alone is `?` on any node without a volume
            // group, so it is the memory figures that tell.
            _ if cells[6] == "?" && cells[8] == "?" => Some(format!(
                "{} does not answer (Ganeti has no figures from it)",
                cells[0]
            )),
            _ => None,
        })
        .collect();
    let mut text = String::new();
    if !warnings.is_empty() {
        text.push_str(&format!("Warnings: {}.\n", warnings.join("; ")));
    }
    text.push_str(&counted(all.len(), "node", "nodes"));
    if let Some(master) = all.iter().find(|cells| cells[1] == "M") {
        text.push_str(&format!("; the master is {}", master[0]));
    }
    text.push_str(".\n\n");

    let table: Vec<Vec<String>> = all
        .iter()
        .map(|cells| {
            let role = match cells[1] {
                "M" => "master",
                "C" => "candidate",
                "R" => "regular",
                "D" => "drained",
                "O" => "offline",
                other => other,
            };
            vec![
                cells[0].to_string(),
                role.to_string(),
                or_dash(cells[2]),
                or_dash(cells[3]),
                or_dash(cells[4]),
                or_dash(cells[5]),
                mib_cell(cells[6]),
                mib_cell(cells[7]),
                mib_cell(cells[8]),
                mib_cell(cells[9]),
                mib_cell(cells[10]),
            ]
        })
        .collect();
    text.push_str(&format_table(
        &[
            "NODE",
            "ROLE",
            "GROUP",
            "PRIMARY",
            "SECONDARY",
            "CPUS",
            "MEM",
            "MEM-NODE",
            "MEM-FREE",
            "DISK",
            "DISK-FREE",
        ],
        &table,
        &[
            false, false, false, true, true, true, true, true, true, true, true,
        ],
    ));
    text.push_str(&odd);
    text
}

/// A job's time as `gnt-job list` prints it, `[seconds, microseconds]`, as a UTC time.
/// Anything else (`-` for a job that has not started or ended) is shown as it is.
fn job_time(cell: &str) -> String {
    cell.strip_prefix('[')
        .and_then(|rest| rest.split(',').next())
        .and_then(|seconds| seconds.trim().parse::<i64>().ok())
        .map_or_else(|| or_dash(cell), rfc3339_utc)
}

/// The jobs view, from the output of `gnt-job list` with `JOB_FIELDS`, which is in the
/// order the jobs were submitted: the newest `limit` are kept.
pub fn jobs_text(listing: &str, limit: usize, cut: bool) -> String {
    let all = rows(listing, 5);
    let odd = not_rows_note(listing, 5);
    if all.is_empty() {
        return if odd.is_empty() {
            "No jobs in the queue.\n".to_string()
        } else {
            odd
        };
    }
    let skipped = all.len().saturating_sub(limit);
    let kept = &all[skipped..];
    // AIDEV-NOTE: `gnt-job list` cannot be asked for the newest first. A list longer
    // than is kept is therefore cut at its newest end, and what is left must not be
    // passed off as the newest jobs. (Ganeti archives finished jobs after some hours,
    // so a queue that long is rare.)
    let mut text = if cut {
        format!(
            "The job list was too long to keep whole: the newest jobs are missing. The \
             last {} of the first {}, oldest first",
            kept.len(),
            all.len()
        )
    } else {
        let mut text = counted(all.len(), "job", "jobs");
        if skipped > 0 {
            text.push_str(&format!(
                "; the newest {} are shown, oldest first",
                kept.len()
            ));
        } else if all.len() > 1 {
            text.push_str(", oldest first");
        }
        text
    };
    text.push_str(&format!(
        ": {}.\n\n",
        tally(kept.iter().map(|cells| cells[1]))
    ));
    let table: Vec<Vec<String>> = kept
        .iter()
        .map(|cells| {
            vec![
                cells[0].to_string(),
                cells[1].to_string(),
                job_time(cells[3]),
                job_time(cells[4]),
                cells[2].to_string(),
            ]
        })
        .collect();
    text.push_str(&format_table(
        &["ID", "STATUS", "STARTED", "ENDED", "SUMMARY"],
        &table,
        &[true, false, false, false, false],
    ));
    text.push_str(&odd);
    text
}

/// `gnt-instance info`'s report with what could be a secret masked, and otherwise as
/// Ganeti printed it.
///
/// AIDEV-NOTE: two places in the report can hold a secret. The OS parameters are whatever
/// an OS definition asks for, and some take a password (Ganeti has private parameters for
/// that since 2.12, which are not printed, but nothing stops a plain one being used): a
/// parameter there whose name says it is a secret has its value masked. Hypervisor
/// parameters are left alone: their names only sound like secrets (`keymap`,
/// `vnc_password_file` is a path). And versions of Ganeti from before 2015 printed a
/// DRBD disk's shared secret as `auth key`; 3.0 does not print it at all. A URL with a
/// password in it (an image path) is masked wherever it stands.
pub fn mask_instance_info(report: &str) -> String {
    let mut masked = String::with_capacity(report.len());
    // The indentation of the "Operating system parameters:" line, while inside it.
    let mut os_parameters: Option<usize> = None;
    for line in report.split_inclusive('\n') {
        let body = line.trim_end_matches('\n');
        let indent = body.len() - body.trim_start().len();
        if os_parameters.is_some_and(|section| indent <= section) && !body.trim().is_empty() {
            os_parameters = None;
        }
        let secret = body.trim_start().split_once(':').filter(|(key, value)| {
            !value.trim().is_empty()
                && (key.eq_ignore_ascii_case("auth key")
                    || (os_parameters.is_some() && is_sensitive(key)))
        });
        match secret {
            Some((key, _)) => masked.push_str(&format!("{}{key}: <redacted>", &body[..indent])),
            None => masked.push_str(body),
        }
        masked.push_str(&line[body.len()..]);
        if body
            .trim_start()
            .starts_with("Operating system parameters:")
        {
            os_parameters = Some(indent);
        }
    }
    redact_text(&masked)
}

/// Ganeti's own report on one instance, for under the summary; or a line on why there
/// is none.
async fn full_report(ctx: &Ctx, clock: &CallClock, name: &str) -> Result<String, ToolError> {
    let Some(time_left) = clock.next() else {
        return Ok("[not asked for: this call's time ran out]\n".to_string());
    };
    let cmd = ctx
        .command("gnt-instance")?
        .args(["info", name])
        .timeout(time_left);
    let out = ctx.run(cmd).await?;
    if out.timed_out {
        return Ok(
            "[gnt-instance info did not answer in time. It waits while another job holds \
             the instance's lock (view=jobs shows the jobs); what it asked for stays in \
             Ganeti's queue and ends by itself.]\n"
                .to_string(),
        );
    }
    let mut text = mask_instance_info(&command_text(&out));
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    Ok(text)
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

/// How long Ganeti's own commands wait for its master daemons before they say that
/// these do not answer.
const GANETI_CONNECT_SECS: u64 = 30;

/// How long a gnt command may take, in seconds.
///
/// AIDEV-NOTE: found against Ganeti 3.0.2: with the master daemons stopped, `gnt-instance
/// list` waits exactly 30 s and then explains ("Timeout while talking to the master
/// daemon"). 30 s is also the default limit for a command here, which ended it a moment
/// before it spoke and left the caller with nothing but "stopped at its time limit".
/// So a gnt command gets a little longer than Ganeti's own wait, as far as the limit for
/// the whole call leaves room; an operator's longer limit for commands stands.
pub fn wait_secs(command_timeout_secs: u64, call_timeout_secs: u64) -> u64 {
    call_timeout_secs
        .saturating_sub(10)
        .min(GANETI_CONNECT_SECS + 15)
        .max(command_timeout_secs)
}

fn stdout(out: &CmdOutput) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

async fn ganeti_status(ctx: Ctx, args: Args) -> ToolResult {
    let view = args.str("view").unwrap_or("instances").to_string();
    let name = args.str("name").map(str::to_string);
    let node = args.str("node").map(str::to_string);
    if let Some(name) = &name {
        check_host_name("instance", name)?;
    }
    if let Some(node) = &node {
        check_host_name("node", node)?;
    }
    if view == "instance" && name.is_none() {
        return Err(ToolError::Invalid(
            "view=instance needs name: the instance to show".to_string(),
        ));
    }
    let default_rows = if view == "jobs" {
        DEFAULT_JOBS
    } else {
        DEFAULT_INSTANCES
    };
    let limit = args.int("limit").unwrap_or(default_rows).clamp(1, MAX_ROWS);
    let limit = usize::try_from(limit).unwrap_or(1);
    let auth = ctx.authorize(None)?;
    let clock = CallClock::start(&ctx);

    let (program, mut argv) = match view.as_str() {
        "instance" => ("gnt-instance", list_argv(DETAIL_FIELDS, true)),
        "nodes" => ("gnt-node", list_argv(NODE_FIELDS, true)),
        "jobs" => ("gnt-job", list_argv(JOB_FIELDS, false)),
        _ => ("gnt-instance", list_argv(INSTANCE_FIELDS, true)),
    };
    if view == "instance" {
        argv.extend(name);
    }
    let Some(cmd) = ctx.optional_command(program)? else {
        return auth.failed(format!(
            "Ganeti is not installed on this host: the {program} command was not found.\n"
        ));
    };
    let limits = &ctx.cfg().limits;
    let wait = wait_secs(limits.command_timeout_secs, limits.call_timeout_secs);
    let mut cmd = cmd.args(argv).timeout(std::time::Duration::from_secs(wait));
    cmd.max_output = 4 << 20;
    let out = ctx.run(cmd).await?;
    let budget = ctx.output_budget();
    if out.timed_out {
        let mut text = command_text(&out);
        text.push_str(&format!(
            "[{program} did not answer in time. It waits like this when Ganeti's master \
             daemons are not running on this node, or when a node it must ask does not \
             answer.]\n"
        ));
        return auth.failed(bounded(&text, budget));
    }
    // AIDEV-NOTE: found against Ganeti 3.0.2: a field this version does not have is not
    // fatal. The rows are printed with `??` in its column, a warning goes to stderr and
    // the exit status is 14. The fields asked for here have existed since 2.6, but a
    // list with one column unknown is still better than no answer.
    let unknown_field = out.code == Some(EXIT_UNKNOWN_FIELD) && !out.timed_out;
    if !command_ok(&out) && !unknown_field {
        return auth.failed(bounded(&command_text(&out), budget));
    }
    let mut listing = stdout(&out);
    if out.truncated {
        // the last line of a list that was cut may be half a line
        let whole = listing.trim_end_matches(|c| c != '\n').len();
        listing.truncate(whole);
    }
    let mut text = match view.as_str() {
        "instance" => instance_text(&listing).unwrap_or_else(|| {
            format!("[gnt-instance did not answer in the form that was asked for]\n{listing}")
        }),
        "nodes" => nodes_text(&listing),
        "jobs" => jobs_text(&listing, limit, out.truncated),
        _ => instances_text(&listing, node.as_deref(), limit),
    };
    if unknown_field {
        text.push_str(
            "[this version of Ganeti does not have every field that was asked for; it shows \
             ?? for those]\n",
        );
    }
    if out.truncated && view != "jobs" {
        text.push_str("[the list was longer than is kept: what is shown is not all of it]\n");
    }
    if view == "instance" {
        text.push_str("\n== gnt-instance info ==\n");
        let name = args.str("name").unwrap_or_default();
        text.push_str(&full_report(&ctx, &clock, name).await?);
    }
    auth.ok(bounded(&text, budget))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::Host;
    use crate::tools::testing::{FakeBins, call, find, host, ok_text};
    use serde_json::{Value, json};
    use std::sync::Arc;

    // The shape of these lines is what Ganeti 3.0.2 printed for a test cluster.
    const INSTANCES: &str = "db1.example.com|running|node1.example.com|node2.example.com|debootstrap+default|4|8192|drbd|20480,102400|192.0.2.12,198.51.100.12\n\
                             old1.example.com|ADMIN_down|node2.example.com||noop|1|256|diskless||192.0.2.14\n\
                             web1.example.com|ERROR_down|node1.example.com||debootstrap+default|2|512|plain|10240|192.0.2.11\n";
    const HEALTHY: &str = "db1.example.com|running|node1.example.com|node2.example.com|debootstrap+default|4|8192|drbd|20480,102400|192.0.2.12,198.51.100.12\n\
                           web1.example.com|running|node1.example.com||debootstrap+default|2|512|plain|10240|-\n";
    const DB1: &str = "db1.example.com|running|node1.example.com|node2.example.com|debootstrap+default|kvm|4|4|4096|8192|8192|drbd|2|20480,102400|122880|192.0.2.12,198.51.100.12|aa:00:00:3b:6f:0e,aa:00:00:f0:5e:66|bridged,bridged|br0,br1|11000|env:prod,role:db|Y|2026-11-27 17:01:32|2026-11-27 17:01:36|258fa88f-742f-455e-b86a-4691e2d4955d\n";
    const OLD1: &str = "old1.example.com|ADMIN_down|node2.example.com||noop|fake|1|-|256|256|-|diskless|0||0|192.0.2.14|aa:00:00:4f:30:f9|routed|100|-||Y|2026-11-27 17:01:34|2026-11-27 17:01:34|3035ad65-29c7-4090-9ba1-34c07a502049\n";
    const NODES: &str = "node1.example.com|M|default|12|9|32|128000|4096|61440|2048000|1024000\n\
                         node2.example.com|C|default|9|12|32|128000|4096|71680|2048000|1126400\n\
                         node3.example.com|O|default|0|0|?|?|?|?|?|?\n";
    const JOBS: &str = "11|success|INSTANCE_CREATE(old1.example.com)|[1795798894, 32204]|[1795798894, 413807]\n\
                        12|error|TAGS_SET|[1795798894, 845200]|[1795798894, 872568]\n\
                        13|success|INSTANCE_STARTUP(web1.example.com)|[1795798895, 356204]|[1795798895, 609630]\n\
                        14|running|INSTANCE_MIGRATE(db1.example.com)|[1795798896, 42102]|-\n";

    /// `gnt-instance info` as Ganeti 3.0.2 printed it for an instance with two LVM disks.
    const INFO: &str = "- Instance name: db1.example.com\n  UUID: a3c76a61-1d77-45fc-a4bf-8367db517a8e\n  Serial number: 5\n  Creation time: 2026-11-27 17:58:01\n  Modification time: 2026-11-27 17:58:04\n  State: configured to be up, actual state is up\n  Nodes: \n    - primary: node1.example.com\n      group: default (UUID ec3a4816-3cbf-4221-8944-b98b1bb2a590)\n    - secondaries: \n  Operating system: noop\n  Operating system parameters: \n  Allocated network port: None\n  Hypervisor: fake\n  Hypervisor parameters: \n  Back-end parameters: \n    always_failover: default (False)\n    auto_balance: default (True)\n    maxmem: 512\n    memory: default (512)\n    minmem: 256\n    spindle_use: default (1)\n    vcpus: 2\n  NICs: \n    - nic/0: \n      MAC: aa:00:00:be:b1:7b\n      IP: 192.0.2.11\n      mode: routed\n      link: 100\n      vlan: \n      network: None\n      UUID: b2f62e64-8fae-4da6-9cfb-6b52c5d6d531\n      name: None\n  Disk template: plain\n  Disks: \n    - disk/0: plain, size 2.0G\n      access mode: rw\n      logical_id: xenvg/4fd62346-5ee9-4f0e-ac17-261a3ddce165.disk0\n      on primary: /dev/xenvg/4fd62346-5ee9-4f0e-ac17-261a3ddce165.disk0 (253:0)\n      name: None\n      UUID: 113b4014-ae7b-48f1-9906-70b486d58b86\n    - disk/1: plain, size 1.0G\n      access mode: rw\n      logical_id: xenvg/90ba0d89-de4f-4e2d-b45e-f242b7b6d379.disk1\n      on primary: /dev/xenvg/90ba0d89-de4f-4e2d-b45e-f242b7b6d379.disk1 (253:1)\n      name: None\n      UUID: 55e4d8e0-378b-46ce-a3fc-9c81d451918b\n";

    /// Shell (builtins only) that prints `text`.
    fn say(text: &str) -> String {
        text.lines()
            .map(|line| format!("printf '%s\\n' '{}'\n", line.replace('\'', "'\\''")))
            .collect()
    }

    /// Stand-ins for the three programs. `gnt-instance` answers for the whole list, or
    /// for the one instance named last.
    fn fake_ganeti(instances: &str) -> FakeBins {
        let instance = format!(
            "for last; do :; done\n\
             if [ \"$1\" = info ]; then\n\
             case \"$last\" in\n\
             db1.example.com)\n{}\nexit 0 ;;\n\
             old1.example.com) while :; do :; done ;;\n\
             *) echo \"Failure: the instance is locked\" >&2; exit 1 ;;\n\
             esac\n\
             fi\n\
             case \"$last\" in\n\
             db1.example.com)\n{}\n;;\n\
             old1.example.com)\n{}\n;;\n\
             gone.example.com)\n\
             echo 'Failure: prerequisites not met for this operation:' >&2\n\
             echo 'error type: unknown_entity, error details:' >&2\n\
             echo 'Instance name gone.example.com not found' >&2\n\
             exit 1 ;;\n\
             *)\n{}\n;;\n\
             esac\n",
            say(INFO),
            say(DB1),
            say(OLD1),
            say(instances),
        );
        FakeBins::new()
            .add_script("gnt-instance", &instance)
            .add_script("gnt-node", &say(NODES))
            .add_script("gnt-job", &say(JOBS))
    }

    /// gina may look at Ganeti; otto may not.
    fn fixture(fake: &FakeBins) -> (Arc<Host>, MemorySink) {
        host(&format!(
            r#"
[roles.viewer]
allow = ["ganeti.view"]
[roles.other]
allow = ["system.view"]
[unix_users.gina]
roles = ["viewer"]
[unix_users.otto]
roles = ["other"]
{}"#,
            fake.config_only()
        ))
    }

    async fn status(host: &Arc<Host>, user: &str, arguments: Value) -> ToolResult {
        call(host, user, &find(tools(), "ganeti_status"), arguments).await
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
    async fn the_instances_view_leads_with_the_one_that_should_be_running_and_is_not() {
        let fake = fake_ganeti(INSTANCES);
        let (host, _audit) = fixture(&fake);
        let text = ok_text(status(&host, "gina", json!({})).await);
        assert_eq!(
            squash(&text),
            "PROBLEM: web1.example.com is ERROR_down (it should be running and is not).\n\
             3 instances: 1 running, 1 ADMIN_down, 1 ERROR_down.\n\
             \n\
             INSTANCE STATUS NODE SECONDARY OS VCPUS MEMORY DISKS ADDRESSES\n\
             db1.example.com running node1.example.com node2.example.com debootstrap+default 4 8.0 GiB drbd: 20.0 GiB, 100.0 GiB 192.0.2.12, 198.51.100.12\n\
             old1.example.com ADMIN_down node2.example.com - noop 1 256.0 MiB diskless 192.0.2.14\n\
             web1.example.com ERROR_down node1.example.com - debootstrap+default 2 512.0 MiB plain: 10.0 GiB 192.0.2.11"
        );
        assert_eq!(
            fake.calls("gnt-instance"),
            [strings(&[
                "list",
                "--no-headers",
                "--separator=|",
                "--units=m",
                "-o",
                "name,status,pnode,snodes,os,be/vcpus,be/maxmem,disk_template,disk.sizes,nic.ips"
            ])]
        );
    }

    #[tokio::test]
    async fn instances_that_are_all_as_they_should_be_get_no_problem_line() {
        let fake = fake_ganeti(HEALTHY);
        let (host, _audit) = fixture(&fake);
        let text = ok_text(status(&host, "gina", json!({"view": "instances"})).await);
        assert!(text.starts_with("2 instances: 2 running.\n"), "{text}");
        assert!(!text.contains("PROBLEM"), "{text}");
    }

    #[test]
    fn each_error_state_is_explained() {
        let line = |status: &str| format!("a.example.com|{status}|n1||noop|1|256|diskless||-\n");
        for (status, meaning) in [
            ("ERROR_up", "it is running and should be stopped"),
            ("ERROR_down", "it should be running and is not"),
            ("ERROR_nodedown", "its node does not answer"),
            ("ERROR_nodeoffline", "its node is marked offline"),
            (
                "ERROR_wrongnode",
                "it is running on a node that is not its primary",
            ),
        ] {
            let text = instances_text(&line(status), None, 10);
            assert_eq!(
                text.lines().next().unwrap(),
                format!("PROBLEM: a.example.com is {status} ({meaning}).")
            );
        }
        // a state this code has not heard of is still a problem when Ganeti calls it one
        let text = instances_text(&line("ERROR_new"), None, 10);
        assert_eq!(
            text.lines().next().unwrap(),
            "PROBLEM: a.example.com is ERROR_new."
        );
        // stopped on purpose, by the administrator or from inside, is not
        for status in ["ADMIN_down", "ADMIN_offline", "USER_down"] {
            assert!(!instances_text(&line(status), None, 10).contains("PROBLEM"));
        }
    }

    #[test]
    fn the_instances_of_one_node_can_be_picked_and_the_rows_limited() {
        // node2 is primary for old1 and secondary for db1; a short name is enough
        for node in ["node2.example.com", "node2"] {
            let text = instances_text(INSTANCES, Some(node), 10);
            assert!(text.starts_with("2 instances on node2"), "{text}");
            assert!(text.contains("db1.example.com"), "{text}");
            assert!(text.contains("old1.example.com"), "{text}");
            assert!(!text.contains("web1.example.com"), "{text}");
        }
        assert_eq!(
            instances_text(INSTANCES, Some("node9.example.com"), 10),
            "No instances on node9.example.com.\n"
        );
        assert_eq!(
            instances_text("", None, 10),
            "No instances on this cluster.\n"
        );
        let text = instances_text(INSTANCES, None, 2);
        assert!(
            text.ends_with("[1 more not shown; raise limit, or give node]\n"),
            "{text}"
        );
        // the verdict and the count are for all of them, shown or not
        assert!(
            text.starts_with("PROBLEM: web1.example.com is ERROR_down"),
            "{text}"
        );
        assert!(text.contains("3 instances: "), "{text}");
    }

    #[tokio::test]
    async fn one_instance_is_shown_in_full() {
        let fake = fake_ganeti(INSTANCES);
        let (host, _audit) = fixture(&fake);
        let arguments = json!({"view": "instance", "name": "db1.example.com"});
        let text = ok_text(status(&host, "gina", arguments).await);
        // Ganeti's own report follows the summary, untouched
        assert!(
            text.ends_with(&format!("\n== gnt-instance info ==\n{INFO}")),
            "{text}"
        );
        let summary: String = squash(&text)
            .lines()
            .take(20)
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            summary,
            "Instance: db1.example.com\n\
             Status: running\n\
             Primary node: node1.example.com\n\
             Secondary nodes: node2.example.com\n\
             OS: debootstrap+default\n\
             Hypervisor: kvm\n\
             vCPUs: 4 configured, 4 in use\n\
             Memory: 4.0 GiB to 8.0 GiB configured, 8.0 GiB in use\n\
             Disks: drbd, 2 disks: 20.0 GiB, 100.0 GiB (120.0 GiB used on the nodes)\n\
             NIC 0: 192.0.2.12, aa:00:00:3b:6f:0e, bridged on br0\n\
             NIC 1: 198.51.100.12, aa:00:00:f0:5e:66, bridged on br1\n\
             Console port: 11000\n\
             Tags: env:prod, role:db\n\
             Auto-balance: Y\n\
             Created: 2026-11-27 17:01:32\n\
             Modified: 2026-11-27 17:01:36\n\
             UUID: 258fa88f-742f-455e-b86a-4691e2d4955d\n\
             \n\
             == gnt-instance info ==\n\
             - Instance name: db1.example.com"
        );
        let calls = fake.calls("gnt-instance");
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1], strings(&["info", "db1.example.com"]));
        assert_eq!(
            calls[0][..4],
            strings(&["list", "--no-headers", "--separator=|", "--units=m"])
        );
        assert_eq!(calls[0][6], "db1.example.com");
    }

    #[test]
    fn an_instance_that_is_down_shows_what_it_has_and_not_what_it_uses() {
        let text = instance_text(OLD1).unwrap();
        let flat = squash(&text);
        assert!(flat.contains("Status: ADMIN_down\n"), "{text}");
        assert!(flat.contains("Secondary nodes: -\n"), "{text}");
        assert!(flat.contains("vCPUs: 1 configured\n"), "{text}");
        assert!(flat.contains("Memory: 256.0 MiB configured\n"), "{text}");
        assert!(flat.contains("Disks: diskless\n"), "{text}");
        assert!(
            flat.contains("NIC 0: 192.0.2.14, aa:00:00:4f:30:f9, routed on 100\n"),
            "{text}"
        );
        assert!(flat.contains("Console port: -\n"), "{text}");
        assert!(flat.contains("Tags: -\n"), "{text}");
        // a line that is not what was asked for is not guessed at
        assert_eq!(instance_text("db1.example.com|running\n"), None);
        assert_eq!(instance_text(""), None);
    }

    #[tokio::test]
    async fn the_instance_view_needs_a_name_and_passes_on_what_ganeti_says_of_a_stranger() {
        let fake = fake_ganeti(INSTANCES);
        let (host, _audit) = fixture(&fake);
        let result = status(&host, "gina", json!({"view": "instance"})).await;
        assert!(matches!(result, Err(ToolError::Invalid(_))), "{result:?}");
        assert!(fake.calls("gnt-instance").is_empty());
        let arguments = json!({"view": "instance", "name": "gone.example.com"});
        let output = status(&host, "gina", arguments).await.unwrap();
        assert!(output.is_error());
        assert!(
            output
                .text()
                .contains("Instance name gone.example.com not found"),
            "{output:?}"
        );
    }

    #[tokio::test]
    async fn a_name_that_could_be_an_option_is_refused_before_anything_runs() {
        let fake = fake_ganeti(INSTANCES);
        let (host, _audit) = fixture(&fake);
        for name in ["-f", "--submit", "a;id", "a b", "", "a/b", "a|b", ".a"] {
            let arguments = json!({"view": "instance", "name": name});
            let result = status(&host, "gina", arguments).await;
            assert!(
                matches!(result, Err(ToolError::Invalid(_))),
                "{name:?}: {result:?}"
            );
            let arguments = json!({"view": "instances", "node": name});
            let result = status(&host, "gina", arguments).await;
            assert!(
                matches!(result, Err(ToolError::Invalid(_))),
                "{name:?}: {result:?}"
            );
        }
        assert!(check_host_name("instance", "web-1.example.com").is_ok());
        assert!(check_host_name("instance", &"a".repeat(254)).is_err());
        assert!(fake.calls("gnt-instance").is_empty());
    }

    #[tokio::test]
    async fn the_nodes_view_names_the_master_and_warns_of_a_node_that_is_out() {
        let fake = fake_ganeti(INSTANCES);
        let (host, _audit) = fixture(&fake);
        let text = ok_text(status(&host, "gina", json!({"view": "nodes"})).await);
        assert_eq!(
            squash(&text),
            "Warnings: node3.example.com is offline.\n\
             3 nodes; the master is node1.example.com.\n\
             \n\
             NODE ROLE GROUP PRIMARY SECONDARY CPUS MEM MEM-NODE MEM-FREE DISK DISK-FREE\n\
             node1.example.com master default 12 9 32 125.0 GiB 4.0 GiB 60.0 GiB 2.0 TiB 1000.0 GiB\n\
             node2.example.com candidate default 9 12 32 125.0 GiB 4.0 GiB 70.0 GiB 2.0 TiB 1.1 TiB\n\
             node3.example.com offline default 0 0 ? ? ? ? ? ?"
        );
        assert_eq!(
            fake.calls("gnt-node"),
            [strings(&[
                "list",
                "--no-headers",
                "--separator=|",
                "--units=m",
                "-o",
                "name,role,group,pinst_cnt,sinst_cnt,ctotal,mtotal,mnode,mfree,dtotal,dfree"
            ])]
        );
    }

    #[test]
    fn a_drained_node_is_a_warning_and_a_regular_one_is_not() {
        let text = nodes_text(
            "n1|M|default|1|0|8|1024|100|900|?|?\nn2|D|default|0|0|8|1024|100|900|?|?\nn3|R|default|0|0|8|1024|100|900|?|?\n",
        );
        assert!(
            text.starts_with("Warnings: n2 is drained (no new instances are placed on it).\n3 nodes; the master is n1.\n"),
            "{text}"
        );
        assert!(squash(&text).contains("n3 regular default"), "{text}");
        assert_eq!(nodes_text(""), "No nodes were listed.\n");
    }

    #[tokio::test]
    async fn the_jobs_view_keeps_the_newest_and_says_how_they_ended() {
        let fake = fake_ganeti(INSTANCES);
        let (host, _audit) = fixture(&fake);
        let text = ok_text(status(&host, "gina", json!({"view": "jobs", "limit": 3})).await);
        assert_eq!(
            squash(&text),
            "4 jobs; the newest 3 are shown, oldest first: 1 error, 1 success, 1 running.\n\
             \n\
             ID STATUS STARTED ENDED SUMMARY\n\
             12 error 2026-11-27T17:01:34Z 2026-11-27T17:01:34Z TAGS_SET\n\
             13 success 2026-11-27T17:01:35Z 2026-11-27T17:01:35Z INSTANCE_STARTUP(web1.example.com)\n\
             14 running 2026-11-27T17:01:36Z - INSTANCE_MIGRATE(db1.example.com)"
        );
        assert_eq!(
            fake.calls("gnt-job"),
            [strings(&[
                "list",
                "--no-headers",
                "--separator=|",
                "-o",
                "id,status,summary,start_ts,end_ts"
            ])]
        );
        assert_eq!(jobs_text("", 20, false), "No jobs in the queue.\n");
        assert!(
            jobs_text(JOBS, 20, false)
                .starts_with("4 jobs, oldest first: 2 success, 1 error, 1 running.\n")
        );
    }

    #[tokio::test]
    async fn a_field_this_ganeti_does_not_know_is_noted_and_the_rest_is_shown() {
        // exit status 14, a warning, and ?? in the column
        let script = format!(
            "echo 'Warning: Queried for unknown fields nic.ips' >&2\n{}exit 14\n",
            say("web1.example.com|running|node1.example.com||noop|2|512|plain|10240|??\n")
        );
        let fake = FakeBins::new().add_script("gnt-instance", &script);
        let (host, _audit) = fixture(&fake);
        let text = ok_text(status(&host, "gina", json!({})).await);
        assert!(text.contains("web1.example.com"), "{text}");
        assert!(
            text.contains("[this version of Ganeti does not have every field that was asked for; it shows ?? for those]"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn on_a_node_that_is_not_the_master_the_answer_names_the_master() {
        // word for word what a node that is not the master answered on a real cluster
        let script = "echo 'Failure: prerequisites not met for this operation:' >&2\n\
                      echo 'error type: wrong_input, error details:' >&2\n\
                      echo 'This is not the master node, please connect to node '\"'\"'node1.example.com'\"'\"' and rerun the command' >&2\n\
                      exit 1\n";
        let fake = FakeBins::new()
            .add_script("gnt-instance", script)
            .add_script("gnt-node", script)
            .add_script("gnt-job", script);
        let (host, _audit) = fixture(&fake);
        for view in ["instances", "nodes", "jobs"] {
            let output = status(&host, "gina", json!({"view": view})).await.unwrap();
            assert!(output.is_error(), "{view}");
            assert!(
                output
                    .text()
                    .contains("please connect to node 'node1.example.com'"),
                "{output:?}"
            );
        }
    }

    #[test]
    fn ganeti_is_given_longer_than_it_takes_to_give_up_on_its_own_daemons() {
        // (the limit for a command, the limit for a call) -> what a gnt command gets
        for (command, call, wanted) in [(30, 120, 45), (60, 120, 60), (30, 40, 30), (10, 300, 45)] {
            assert_eq!(wait_secs(command, call), wanted, "{command} {call}");
        }
    }

    #[tokio::test]
    async fn a_command_that_never_answers_is_ended_with_a_word_on_why_that_happens() {
        // a stand-in that never returns, and a host that allows a command one second
        let fake = FakeBins::new().add_script("gnt-instance", "while :; do :; done\n");
        let (host, _audit) = host(&format!(
            "[roles.viewer]\nallow = [\"ganeti.view\"]\n[unix_users.gina]\nroles = [\"viewer\"]\n\
             [limits]\ncommand_timeout_secs = 1\ncall_timeout_secs = 5\n{}",
            fake.config_only()
        ));
        let output = status(&host, "gina", json!({})).await.unwrap();
        assert!(output.is_error());
        assert!(
            output.text().contains(
                "[gnt-instance did not answer in time. It waits like this when Ganeti's master \
                 daemons are not running on this node, or when a node it must ask does not answer.]"
            ),
            "{output:?}"
        );
    }

    #[test]
    fn a_node_that_does_not_answer_is_a_warning() {
        // as Ganeti 3.0.2 lists a node whose daemon is dead: its role as ever, and ? for
        // everything it would have had to be asked for
        let text = nodes_text(
            "node1.example.com|M|default|3|0|8|1024|100|900|?|?\nnode2.example.com|R|default|2|1|?|?|?|?|?|?\n",
        );
        assert!(
            text.starts_with(
                "Warnings: node2.example.com does not answer (Ganeti has no figures from it).\n"
            ),
            "{text}"
        );
        // a node without a volume group has no disk figures and answers all the same
        assert!(
            !text.contains("node1.example.com does not answer"),
            "{text}"
        );
    }

    #[test]
    fn lines_that_are_not_rows_are_counted_and_never_taken_for_an_empty_list() {
        let note = "[2 lines were not in the form that was asked for and are left out]";
        let odd = "what is this\nand this\n";
        for text in [
            instances_text(odd, None, 10),
            nodes_text(odd),
            jobs_text(odd, 10, false),
        ] {
            assert!(text.contains(note), "{text}");
            assert!(!text.starts_with("No "), "{text}");
        }
        // one odd line beside good ones: the good ones are shown and the odd one counted
        let text = instances_text(&format!("{INSTANCES}a|b\n"), None, 10);
        assert!(text.contains("3 instances: "), "{text}");
        assert!(
            text.ends_with("[1 line was not in the form that was asked for and is left out]\n"),
            "{text}"
        );
    }

    #[test]
    fn a_job_list_that_was_cut_short_does_not_claim_to_have_the_newest() {
        let text = jobs_text(JOBS, 2, true);
        assert!(
            text.starts_with(
                "The job list was too long to keep whole: the newest jobs are missing. The \
                 last 2 of the first 4, oldest first: 1 success, 1 running.\n"
            ),
            "{text}"
        );
    }

    #[tokio::test]
    async fn an_instance_whose_full_report_does_not_come_still_gets_its_summary() {
        // old1's `info` never returns, as when another job holds the instance's lock;
        // web1's fails. A host that allows a command one second.
        let fake = fake_ganeti(INSTANCES);
        let (host, _audit) = host(&format!(
            "[roles.viewer]\nallow = [\"ganeti.view\"]\n[unix_users.gina]\nroles = [\"viewer\"]\n\
             [limits]\ncommand_timeout_secs = 1\ncall_timeout_secs = 8\n{}",
            fake.config_only()
        ));
        let arguments = json!({"view": "instance", "name": "old1.example.com"});
        let text = ok_text(status(&host, "gina", arguments).await);
        assert!(
            squash(&text).starts_with("Instance: old1.example.com\nStatus: ADMIN_down\n"),
            "{text}"
        );
        assert!(
            text.contains(
                "== gnt-instance info ==\n[gnt-instance info did not answer in time. It waits \
                 while another job holds the instance's lock (view=jobs shows the jobs); what \
                 it asked for stays in Ganeti's queue and ends by itself.]\n"
            ),
            "{text}"
        );
    }

    #[tokio::test]
    async fn a_full_report_that_fails_is_shown_as_what_ganeti_said_under_the_summary() {
        let fake = fake_ganeti(INSTANCES);
        let (host, _audit) = fixture(&fake);
        // the stand-in knows no `info` for this name; its list falls through to the default
        let script_only = FakeBins::new().add_script(
            "gnt-instance",
            &format!(
                "if [ \"$1\" = info ]; then echo 'Failure: command execution error:' >&2; echo 'Node node2.example.com is down' >&2; exit 1; fi\n{}",
                say(DB1)
            ),
        );
        let (host2, _audit2) = fixture(&script_only);
        let arguments = json!({"view": "instance", "name": "db1.example.com"});
        let text = ok_text(status(&host2, "gina", arguments).await);
        assert!(
            squash(&text).starts_with("Instance: db1.example.com\n"),
            "{text}"
        );
        assert!(
            text.contains("== gnt-instance info ==\nFailure: command execution error:\nNode node2.example.com is down\n[exit status 1]\n"),
            "{text}"
        );
        // an instance Ganeti does not know fails at the summary, and its report is not asked for
        let arguments = json!({"view": "instance", "name": "gone.example.com"});
        let output = status(&host, "gina", arguments).await.unwrap();
        assert!(output.is_error());
        assert_eq!(fake.calls("gnt-instance").len(), 1);
    }

    #[test]
    fn the_full_report_is_passed_on_as_it_is_except_for_what_could_be_a_secret() {
        // the real report has nothing to hide: not a character changes
        assert_eq!(mask_instance_info(INFO), INFO);
        // OS parameters are whatever an OS definition asks for, a password included; older
        // Ganeti printed a DRBD disk's shared secret
        let with_secrets = "- Instance name: db1.example.com\n  Operating system: debootstrap+default\n  Operating system parameters: \n    dhcp: default (yes)\n    root_password: hunter2\n    api_token: default (abc123)\n  Allocated network port: 11000\n  Hypervisor: kvm\n  Hypervisor parameters: \n    keymap: default ()\n    vnc_password_file: default (/etc/ganeti/vnc-cluster-password)\n    cdrom_image_path: http://mirror:s3cret@images.example.com/boot.iso\n  Disks: \n    - disk/0: drbd, size 10.0G\n      nodeA: node1.example.com, minor=0\n      nodeB: node2.example.com, minor=0\n      port: 11000\n      auth key: 5e2f0c3d9a8b7c6d5e4f\n      on primary: /dev/drbd0 (147:0) in sync, status ok\n";
        let masked = mask_instance_info(with_secrets);
        for secret in ["hunter2", "abc123", "s3cret", "5e2f0c3d9a8b7c6d5e4f"] {
            assert!(!masked.contains(secret), "{secret}: {masked}");
        }
        assert!(
            masked.contains("    root_password: <redacted>\n"),
            "{masked}"
        );
        assert!(masked.contains("    api_token: <redacted>\n"), "{masked}");
        assert!(masked.contains("      auth key: <redacted>\n"), "{masked}");
        // the rest stands: an OS parameter that is no secret, and hypervisor parameters
        // whose names only sound like one (a key map, the path of a password file)
        assert!(masked.contains("    dhcp: default (yes)\n"), "{masked}");
        assert!(masked.contains("    keymap: default ()\n"), "{masked}");
        assert!(
            masked.contains("    vnc_password_file: default (/etc/ganeti/vnc-cluster-password)\n"),
            "{masked}"
        );
        assert!(masked.contains("images.example.com/boot.iso"), "{masked}");
        assert!(
            masked.contains("      on primary: /dev/drbd0 (147:0) in sync, status ok\n"),
            "{masked}"
        );
    }

    #[tokio::test]
    async fn a_host_without_ganeti_says_so() {
        let fake = FakeBins::new().add("lsblk", "", 0);
        let (host, _audit) = fixture(&fake);
        for view in VIEWS {
            let arguments = json!({"view": view, "name": "db1.example.com"});
            let output = status(&host, "gina", arguments).await.unwrap();
            assert!(output.is_error());
            assert!(
                output.text().contains("Ganeti is not installed"),
                "{output:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_caller_without_the_permission_is_refused_and_nothing_runs() {
        let fake = fake_ganeti(INSTANCES);
        let (host, audit) = fixture(&fake);
        let result = status(&host, "otto", json!({})).await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        assert!(fake.calls("gnt-instance").is_empty());
        assert_eq!(audit.records()[0]["decision"], "deny");
    }
}
