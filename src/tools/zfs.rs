//! ZFS: pools, datasets, snapshots and properties, read through `zpool` and `zfs`.
//!
//! AIDEV-NOTE: read-only by construction. The only subcommands ever run are `zpool list`,
//! `zpool status`, `zpool get`, `zfs list` and `zfs get`, each with a fixed argument
//! list. The one thing a caller supplies is a name, which is checked (`check_name`) and
//! so can never be read as an option. Nothing here imports, scrubs, snapshots or sets
//! anything, and nothing is run at all while the kernel module is not loaded (see
//! `zfs_status`).

use std::path::PathBuf;
use std::sync::Arc;

use super::args::{Args, Param};
use super::{
    Authorized, Ctx, Tool, ToolError, ToolResult, blocking, command_ok, command_text, format_table,
};
use crate::exec::CmdOutput;
use crate::policy::Access;
use crate::sanitize::{is_sensitive, keep_head, redact_text};
use crate::timefmt::{human_bytes, rfc3339_utc};

/// Where the kernel's files are. Tests point these at a temporary directory.
#[derive(Clone, Debug)]
pub struct Roots {
    /// `/sys`
    pub sys: PathBuf,
    /// `/proc`
    pub proc: PathBuf,
}

impl Default for Roots {
    fn default() -> Self {
        Roots {
            sys: PathBuf::from("/sys"),
            proc: PathBuf::from("/proc"),
        }
    }
}

const VIEWS: [&str; 5] = ["summary", "pools", "datasets", "snapshots", "properties"];
/// From this many percent full a pool gets a warning: ZFS has to work harder for every
/// write as free space runs out.
const FULL_PERCENT: u64 = 80;
const DEFAULT_ROWS: i64 = 50;
const MAX_ROWS: i64 = 500;
/// The longest name ZFS allows for a dataset or snapshot.
const MAX_NAME: usize = 256;
/// Most that is read of the kernel's ARC statistics file.
const ARCSTATS_BYTES: u64 = 64 * 1024;

const POOL_LIST: [&str; 5] = [
    "list",
    "-H",
    "-p",
    "-o",
    "name,size,allocated,free,fragmentation,capacity,dedupratio,health",
];
const DATASET_LIST: [&str; 7] = [
    "list",
    "-H",
    "-p",
    "-t",
    "filesystem,volume",
    "-o",
    "name,type,used,available,referenced,compressratio,mountpoint",
];
const SNAPSHOT_LIST: [&str; 9] = [
    "list",
    "-H",
    "-p",
    "-t",
    "snapshot",
    "-o",
    "name,used,referenced,creation",
    // AIDEV-NOTE: newest first (`-S`, not `-s`). A host can have more snapshots than a
    // call keeps the output of; cut at the end, a list in this order loses its oldest
    // and what is shown as "the newest" still is.
    "-S",
    "creation",
];
const GET_ALL: [&str; 5] = ["get", "-H", "-o", "property,value,source", "all"];

pub fn tools() -> Vec<Tool> {
    tools_with(Roots::default())
}

pub fn tools_with(roots: Roots) -> Vec<Tool> {
    let roots = Arc::new(roots);
    vec![Tool::new(
        "zfs_status",
        "Show ZFS on this host (zpool and zfs). By default: every pool with its size, how \
         full and fragmented it is and its health, what `zpool status` says about a pool \
         that has a problem, and how much memory the ARC cache holds; the first line is \
         the verdict. view=pools: the full `zpool status` of every pool or of one \
         (devices, read, write and checksum errors, scrub and resilver progress). \
         view=datasets: filesystems and volumes with the space they use and have left, \
         compression ratio and mount point. view=snapshots: the newest snapshots. \
         view=properties: every property of one pool, dataset or snapshot, with where \
         each value was set. Changes nothing. For the drives under a pool use \
         disk_health; for other filesystems use disk_usage and block_devices.",
        Access::Read,
        "storage.view",
        vec![
            Param::choice(
                "view",
                "What to show: summary (default), pools, datasets, snapshots or properties",
                &VIEWS,
            ),
            Param::str(
                "name",
                "pools: only this pool. datasets and snapshots: only what is at or below \
                 this pool or dataset. properties: the pool, dataset or snapshot to show \
                 (required)",
            )
            .max_len(MAX_NAME),
            Param::int(
                "limit",
                "For datasets and snapshots: most rows to show (default 50)",
                1,
                MAX_ROWS,
            ),
        ],
        move |ctx, args| {
            let roots = roots.clone();
            async move { zfs_status(ctx, args, roots).await }
        },
    )]
}

/// Checks the name of a pool, dataset, snapshot or bookmark: the characters ZFS itself
/// allows, starting with a letter or digit so that it can never be read as an option.
pub fn check_name(name: &str) -> Result<(), ToolError> {
    let allowed = |c: char| c.is_ascii_alphanumeric() || "_-.:/@# ".contains(c);
    let starts_well = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric());
    if name.len() > MAX_NAME || !starts_well || !name.chars().all(allowed) {
        return Err(ToolError::Invalid(format!(
            "{name:?} is not the name of a ZFS pool, dataset or snapshot"
        )));
    }
    Ok(())
}

/// One line of `zpool list -H -p`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pool {
    pub name: String,
    pub size: Option<u64>,
    pub allocated: Option<u64>,
    pub free: Option<u64>,
    /// Percent of free space that is fragmented; some pools do not report it.
    pub fragmentation: Option<u64>,
    /// Percent full.
    pub capacity: Option<u64>,
    pub dedup: String,
    pub health: String,
}

/// The pools in the output of `zpool list -H -p -o` with the columns of `POOL_LIST`.
/// Lines that are not such a row ("no pools available") are passed over.
pub fn parse_pools(text: &str) -> Vec<Pool> {
    text.lines()
        .filter_map(|line| {
            let cells: Vec<&str> = line.split('\t').collect();
            let [
                name,
                size,
                allocated,
                free,
                fragmentation,
                capacity,
                dedup,
                health,
            ] = cells[..]
            else {
                return None;
            };
            Some(Pool {
                name: name.to_string(),
                size: size.parse().ok(),
                allocated: allocated.parse().ok(),
                free: free.parse().ok(),
                fragmentation: fragmentation.parse().ok(),
                capacity: capacity.parse().ok(),
                dedup: dedup.to_string(),
                health: health.to_string(),
            })
        })
        .collect()
}

/// The figures of the ARC, the cache ZFS keeps in memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArcStats {
    pub size: u64,
    pub target: u64,
    pub max: u64,
    pub hits: u64,
    pub misses: u64,
}

/// Reads `/proc/spl/kstat/zfs/arcstats`. `None` when the size is not in it.
pub fn parse_arcstats(text: &str) -> Option<ArcStats> {
    // Each line is `name type value`.
    let value = |wanted: &str| {
        text.lines().find_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some(wanted))
                .then(|| words.nth(1)?.parse::<u64>().ok())
                .flatten()
        })
    };
    Some(ArcStats {
        size: value("size")?,
        target: value("c").unwrap_or(0),
        max: value("c_max").unwrap_or(0),
        hits: value("hits").unwrap_or(0),
        misses: value("misses").unwrap_or(0),
    })
}

/// One line about the ARC for the summary.
pub fn arc_line(arc: &ArcStats) -> String {
    let mut line = format!(
        "ARC: {} in use (target {}, limit {})",
        human_bytes(arc.size),
        human_bytes(arc.target),
        human_bytes(arc.max)
    );
    let lookups = arc.hits.saturating_add(arc.misses);
    if lookups > 0 {
        let percent = arc.hits as f64 * 100.0 / lookups as f64;
        line.push_str(&format!(
            "; {percent:.1}% of {lookups} lookups were hits since boot"
        ));
    }
    line.push_str(".\n");
    line
}

fn size_cell(bytes: Option<u64>) -> String {
    bytes.map_or_else(|| "-".to_string(), human_bytes)
}

fn percent_cell(percent: Option<u64>) -> String {
    percent.map_or_else(|| "-".to_string(), |p| format!("{p}%"))
}

/// The summary: the verdict, the pools, what `zpool status -x` complains about (if
/// anything) and the ARC.
pub fn summary_text(pools: &[Pool], complaint: Option<&str>, arc: Option<&ArcStats>) -> String {
    let mut problems: Vec<String> = pools
        .iter()
        .filter(|pool| pool.health != "ONLINE")
        .map(|pool| format!("pool {} is {}", pool.name, pool.health))
        .collect();
    // AIDEV-NOTE: a pool with data errors or a failing device that still has its
    // redundancy stays ONLINE; `zpool status -x` is what reports those. So a complaint
    // is a problem even when every pool in the list looks healthy.
    if problems.is_empty() && complaint.is_some() {
        problems.push("zpool status reports a problem (below)".to_string());
    }
    let warnings: Vec<String> = pools
        .iter()
        .filter(|pool| pool.capacity.is_some_and(|full| full >= FULL_PERCENT))
        .map(|pool| {
            format!(
                "pool {} is {}% full (ZFS slows down as a pool fills up)",
                pool.name,
                pool.capacity.unwrap_or(0)
            )
        })
        .collect();

    let mut text = String::new();
    if !problems.is_empty() {
        text.push_str(&format!("PROBLEM: {}.", problems.join("; ")));
        if !warnings.is_empty() {
            text.push(' ');
        }
    }
    if !warnings.is_empty() {
        text.push_str(&format!("Warnings: {}.", warnings.join("; ")));
    }
    if text.is_empty() {
        text = match pools.len() {
            1 => "No ZFS problems are visible (1 pool, ONLINE).".to_string(),
            n => format!("No ZFS problems are visible ({n} pools, all ONLINE)."),
        };
    }
    text.push_str("\n\n");

    let rows: Vec<Vec<String>> = pools
        .iter()
        .map(|pool| {
            vec![
                pool.name.clone(),
                size_cell(pool.size),
                size_cell(pool.allocated),
                size_cell(pool.free),
                percent_cell(pool.capacity),
                percent_cell(pool.fragmentation),
                format!("{}x", pool.dedup.trim_end_matches('x')),
                pool.health.clone(),
            ]
        })
        .collect();
    text.push_str(&format_table(
        &[
            "POOL", "SIZE", "USED", "FREE", "FULL", "FRAG", "DEDUP", "HEALTH",
        ],
        &rows,
        &[false, true, true, true, true, true, true, false],
    ));
    if let Some(complaint) = complaint {
        text.push_str("\n== zpool status -x ==\n");
        text.push_str(complaint);
        end_line(&mut text);
    }
    if let Some(arc) = arc {
        text.push('\n');
        text.push_str(&arc_line(arc));
    }
    text
}

fn end_line(text: &mut String) {
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
}

/// The rows of a listing printed with `-H`: one per line, cells separated by tabs. Also
/// how many lines were not such a row of `columns` cells.
fn listed(listing: &str, columns: usize) -> (Vec<Vec<&str>>, usize) {
    let mut rows = Vec::new();
    let mut not_rows = 0;
    for line in listing.lines().filter(|line| !line.trim().is_empty()) {
        let cells: Vec<&str> = line.split('\t').collect();
        if cells.len() == columns {
            rows.push(cells);
        } else {
            not_rows += 1;
        }
    }
    (rows, not_rows)
}

/// What is said of lines that were not rows. A list must never be called empty because
/// its lines could not be read.
fn not_rows_note(not_rows: usize) -> String {
    match not_rows {
        0 => String::new(),
        1 => "[1 line was not in the form that was asked for and is left out]\n".to_string(),
        n => format!("[{n} lines were not in the form that was asked for and are left out]\n"),
    }
}

/// A byte count as `zfs list -p` prints it, in readable units; anything else as it is.
fn bytes_cell(cell: &str) -> String {
    cell.parse::<u64>()
        .map_or_else(|_| cell.to_string(), human_bytes)
}

/// A table of the output of `zfs list -H -p` with the columns of `DATASET_LIST`.
pub fn datasets_text(listing: &str, limit: usize) -> String {
    let (all, not_rows) = listed(listing, 7);
    if all.is_empty() {
        return match not_rows {
            0 => "No datasets.\n".to_string(),
            _ => not_rows_note(not_rows),
        };
    }
    let rows: Vec<Vec<String>> = all
        .iter()
        .take(limit)
        .map(|cells| {
            vec![
                cells[0].to_string(),
                cells[1].to_string(),
                bytes_cell(cells[2]),
                bytes_cell(cells[3]),
                bytes_cell(cells[4]),
                // 1.85 with -p on current versions; allow for 1.85x
                format!("{}x", cells[5].trim_end_matches('x')),
                cells[6].to_string(),
            ]
        })
        .collect();
    let mut text = format_table(
        &[
            "NAME",
            "TYPE",
            "USED",
            "AVAIL",
            "REFER",
            "RATIO",
            "MOUNTPOINT",
        ],
        &rows,
        &[false, false, true, true, true, true, false],
    );
    let more = all.len().saturating_sub(limit);
    if more > 0 {
        text.push_str(&format!(
            "[{more} more not shown; raise limit, or give name to list below one dataset]\n"
        ));
    }
    text.push_str(&not_rows_note(not_rows));
    text
}

/// A table of the output of `zfs list -H -p` with the columns of `SNAPSHOT_LIST`, which
/// is sorted newest first: the newest `limit` are kept, and shown oldest first. `cut`
/// says that the listing is only the start of a longer one.
pub fn snapshots_text(listing: &str, limit: usize, cut: bool) -> String {
    let (all, not_rows) = listed(listing, 4);
    if all.is_empty() {
        return match not_rows {
            0 => "No snapshots.\n".to_string(),
            _ => not_rows_note(not_rows),
        };
    }
    let total = all.len();
    let rows: Vec<Vec<String>> = all
        .iter()
        .take(limit)
        .rev()
        .map(|cells| {
            let created = cells[3]
                .parse::<i64>()
                .map_or_else(|_| cells[3].to_string(), rfc3339_utc);
            vec![
                cells[0].to_string(),
                bytes_cell(cells[1]),
                bytes_cell(cells[2]),
                created,
            ]
        })
        .collect();
    let mut text = if cut {
        format!(
            "More than {total} snapshots (the list was too long to keep whole); the newest \
             {} are shown, oldest first.\n",
            rows.len()
        )
    } else if total > rows.len() {
        format!(
            "{total} snapshots; the newest {} are shown, oldest first.\n",
            rows.len()
        )
    } else if total == 1 {
        "1 snapshot.\n".to_string()
    } else {
        format!("{total} snapshots, oldest first.\n")
    };
    text.push_str(&format_table(
        &["SNAPSHOT", "USED", "REFER", "CREATED"],
        &rows,
        &[false, true, true, false],
    ));
    text.push_str(&not_rows_note(not_rows));
    text
}

/// A table of the output of `zpool get` or `zfs get` with the columns of `GET_ALL`.
///
/// AIDEV-NOTE: found against real ZFS: a user property (`zfs set com.example:password=...`)
/// is printed in full, and anyone may have put a secret in one. The value of a user
/// property (a name with a colon) whose name says it is a secret is masked. ZFS's own
/// properties are not: keyformat and keylocation say how a key is given, not what it is.
pub fn properties_text(listing: &str) -> String {
    let mut rows = Vec::new();
    let mut not_rows = 0;
    for line in listing.lines().filter(|line| !line.trim().is_empty()) {
        // The value is the one cell that can hold anything, a tab included: the name is
        // what comes before the first tab and the source what comes after the last.
        let cells = line
            .split_once('\t')
            .and_then(|(name, rest)| Some((name, rest.rsplit_once('\t')?)));
        let Some((name, (value, source))) = cells else {
            not_rows += 1;
            continue;
        };
        let value = if name.contains(':') && is_sensitive(name) {
            "<redacted>"
        } else {
            value
        };
        rows.push(vec![
            name.to_string(),
            value.to_string(),
            source.to_string(),
        ]);
    }
    let mut text = format_table(&["PROPERTY", "VALUE", "SOURCE"], &rows, &[false; 3]);
    text.push_str(&not_rows_note(not_rows));
    text
}

/// `text`, cut at the end if it is longer than a call may return.
fn bounded(text: &str, budget: usize) -> String {
    let (mut kept, dropped) = keep_head(text, budget.saturating_sub(100));
    if dropped > 0 {
        end_line(&mut kept);
        kept.push_str(&format!(
            "[{dropped} more lines left out to fit the output limit]\n"
        ));
    }
    kept
}

/// Whether a name is a pool's: a pool has properties of its own (`zpool get`) beside
/// those of the dataset of the same name.
fn is_pool_name(name: &str) -> bool {
    !name.contains(['/', '@', '#'])
}

fn stdout(out: &CmdOutput) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

async fn zfs_status(ctx: Ctx, args: Args, roots: Arc<Roots>) -> ToolResult {
    let view = args.str("view").unwrap_or("summary").to_string();
    let name = args.str("name").map(str::to_string);
    if let Some(name) = &name {
        check_name(name)?;
    }
    if view == "properties" && name.is_none() {
        return Err(ToolError::Invalid(
            "view=properties needs name: the pool, dataset or snapshot to show".to_string(),
        ));
    }
    let limit = args.int("limit").unwrap_or(DEFAULT_ROWS).clamp(1, MAX_ROWS);
    let limit = usize::try_from(limit).unwrap_or(50);
    let auth = ctx.authorize(None)?;

    if ctx.optional_command("zpool")?.is_none() {
        return auth.failed(
            "ZFS is not installed on this host: the zpool command was not found (package \
             zfsutils-linux on Debian and Ubuntu).\n",
        );
    }
    // AIDEV-NOTE: `zpool` and `zfs` may load the kernel module when it is not loaded
    // (depending on the version and on ZFS_MODULE_LOADING). A tool that only looks must
    // not change what the kernel has loaded, so nothing is run until the module is there.
    // Without it no pool can be imported, and that is all there is to say.
    let module = roots.sys.join("module/zfs");
    if !blocking(ctx.clone(), move || Ok(module.is_dir())).await? {
        return auth.ok(
            "ZFS is installed, but its kernel module is not loaded: no pool is in use on \
             this host.\n",
        );
    }

    let budget = ctx.output_budget();
    match view.as_str() {
        "pools" => {
            let mut argv = vec!["status".to_string(), "-v".to_string()];
            argv.extend(name);
            let out = ctx.run(ctx.command("zpool")?.args(argv)).await?;
            auth.done(bounded(&command_text(&out), budget), command_ok(&out))
        }
        "datasets" | "snapshots" => {
            let mut argv: Vec<String> = match view.as_str() {
                "datasets" => DATASET_LIST.map(String::from).to_vec(),
                _ => SNAPSHOT_LIST.map(String::from).to_vec(),
            };
            if let Some(name) = name {
                argv.extend(["-r".to_string(), name]);
            }
            let mut cmd = ctx.command("zfs")?.args(argv);
            // a host can have tens of thousands of snapshots
            cmd.max_output = 8 << 20;
            let out = ctx.run(cmd).await?;
            if !command_ok(&out) {
                return auth.failed(bounded(&command_text(&out), budget));
            }
            let mut listing = stdout(&out);
            if out.truncated {
                // the last line of a list that was cut may be half a line
                let whole = listing.trim_end_matches(|c| c != '\n').len();
                listing.truncate(whole);
            }
            let mut text = match view.as_str() {
                "datasets" => datasets_text(&listing, limit),
                _ => snapshots_text(&listing, limit, out.truncated),
            };
            if out.truncated && view == "datasets" {
                text.push_str(
                    "[the list was longer than is kept: give name to list below one dataset]\n",
                );
            }
            auth.ok(bounded(&text, budget))
        }
        "properties" => {
            let name = name.unwrap_or_default();
            let mut text = String::new();
            let mut ok = true;
            let mut sources = vec![("Dataset", "zfs")];
            if is_pool_name(&name) {
                sources.insert(0, ("Pool", "zpool"));
            }
            for (what, program) in sources {
                let argv = GET_ALL.iter().copied().chain([name.as_str()]);
                let out = ctx.run(ctx.command(program)?.args(argv)).await?;
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(&format!("== {what} {name} ({program} get all) ==\n"));
                if command_ok(&out) {
                    text.push_str(&properties_text(&stdout(&out)));
                } else {
                    ok = false;
                    text.push_str(&command_text(&out));
                    end_line(&mut text);
                }
            }
            // AIDEV-NOTE: a property can hold a location with a password in it
            // (keylocation=https://user:password@host/...), and user properties can hold
            // anything.
            auth.done(bounded(&redact_text(&text), budget), ok)
        }
        _ => summary(&ctx, auth, &roots, budget).await,
    }
}

async fn summary(ctx: &Ctx, auth: Authorized, roots: &Roots, budget: usize) -> ToolResult {
    let out = ctx.run(ctx.command("zpool")?.args(POOL_LIST)).await?;
    if !command_ok(&out) {
        return auth.failed(bounded(&command_text(&out), budget));
    }
    let pools = parse_pools(&stdout(&out));
    if pools.is_empty() {
        return auth.ok("No ZFS pool is imported on this host.\n");
    }
    // Prints one line when nothing is wrong, and otherwise the status of each pool that
    // has a problem.
    let status = ctx
        .run(ctx.command("zpool")?.args(["status", "-x"]))
        .await?;
    // What zpool says about itself on stderr is not a complaint about a pool.
    let healthy = command_ok(&status) && stdout(&status).trim() == "all pools are healthy";
    let complaint = (!healthy).then(|| command_text(&status));
    let arcstats = roots.proc.join("spl/kstat/zfs/arcstats");
    let arc = blocking(ctx.clone(), move || {
        use std::io::Read;
        let mut text = String::new();
        let read = std::fs::File::open(arcstats)
            .and_then(|file| file.take(ARCSTATS_BYTES).read_to_string(&mut text));
        Ok(read.ok().and_then(|_| parse_arcstats(&text)))
    })
    .await?;
    auth.ok(bounded(
        &summary_text(&pools, complaint.as_deref(), arc.as_ref()),
        budget,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::Host;
    use crate::tools::testing::{FakeBins, call, find, host, ok_text};
    use serde_json::{Value, json};
    use std::sync::Arc;

    const POOLS: &str = "backup\t1099511627776\t989560464998\t109951162778\t61\t90\t1.00\tDEGRADED\n\
                         tank\t2199023255552\t549755813888\t1649267441664\t12\t25\t1.00\tONLINE\n";
    const HEALTHY_POOLS: &str =
        "tank\t2199023255552\t549755813888\t1649267441664\t12\t25\t1.00\tONLINE\n";
    /// As ZFS 2.2 prints it, for a mirror with one side taken offline.
    const STATUS_X: &str = "  pool: backup\n state: DEGRADED\nstatus: One or more devices has been taken offline by the administrator.\n\tSufficient replicas exist for the pool to continue functioning in a\n\tdegraded state.\naction: Online the device using 'zpool online' or replace the device with\n\t'zpool replace'.\nconfig:\n\n\tNAME        STATE     READ WRITE CKSUM\n\tbackup      DEGRADED     0     0     0\n\t  mirror-0  DEGRADED     0     0     0\n\t    sdc     ONLINE       0     0     0\n\t    sdd     OFFLINE      0     0     0\n\nerrors: No known data errors\n";
    const ALL_HEALTHY: &str = "all pools are healthy\n";
    const DATASETS: &str = "tank\tfilesystem\t1073741824\t2147483648\t1048576\t1.00\t/tank\n\
                            tank/data\tfilesystem\t536870912\t2147483648\t536870912\t1.85\t/tank/data\n\
                            tank/vol1\tvolume\t104857600\t2252341248\t12288\t1.00\t-\n";
    /// Newest first, as `-S creation` gives them.
    const SNAPSHOTS: &str = "tank/data@nightly-2\t8192\t24576\t1795884913\n\
                             tank/data@nightly-1\t0\t24576\t1795798513\n\
                             tank/data/www@before\t14336\t21010432\t1795712113\n";
    const DATASET_PROPERTIES: &str = "type\tfilesystem\t-\n\
                                      compression\tlz4\tlocal\n\
                                      keylocation\thttps://backup:hunter2@keys.example.com/tank\tlocal\n\
                                      mountpoint\t/tank/data\tdefault\n";
    const POOL_PROPERTIES: &str = "size\t2T\t-\nhealth\tONLINE\t-\nautotrim\toff\tdefault\n";
    const ARCSTATS: &str = "9 1 0x01 147 39984 50132443103 200574778763\n\
                            name                            type data\n\
                            hits                            4    990\n\
                            misses                          4    10\n\
                            c                               4    2147483648\n\
                            c_min                           4    95284736\n\
                            c_max                           4    4294967296\n\
                            size                            4    1073741824\n";

    /// Shell (builtins only) that prints `text`.
    fn say(text: &str) -> String {
        text.lines()
            .map(|line| format!("printf '%s\\n' '{}'\n", line.replace('\'', "'\\''")))
            .collect()
    }

    /// Stand-ins for `zpool` and `zfs` that answer the commands the tool runs.
    fn fake_zfs(pools: &str, status_x: &str) -> FakeBins {
        let zpool = format!(
            "case \"$1 $2\" in\n\
             'list -H')\n{}\n;;\n\
             'status -x')\n{}\n;;\n\
             'status -v')\n\
             case \"$3\" in gone) echo \"cannot open 'gone': no such pool\" >&2; exit 1;; esac\n\
             {}\n;;\n\
             'get -H')\n{}\n;;\n\
             esac\n",
            say(pools),
            say(status_x),
            say(STATUS_X),
            say(POOL_PROPERTIES),
        );
        let zfs = format!(
            "case \"$1 $5\" in\n\
             'list filesystem,volume')\n{}\n;;\n\
             'list snapshot')\n{}\n;;\n\
             'get all')\n\
             case \"$6\" in tank/gone) echo \"cannot open 'tank/gone': dataset does not exist\" >&2; exit 1;; esac\n\
             {}\n;;\n\
             esac\n",
            say(DATASETS),
            say(SNAPSHOTS),
            say(DATASET_PROPERTIES),
        );
        FakeBins::new()
            .add_script("zpool", &zpool)
            .add_script("zfs", &zfs)
    }

    /// A stand-in for `/sys` and `/proc`: with or without the ZFS module, and with or
    /// without the ARC's statistics.
    fn roots(module_loaded: bool, arcstats: Option<&str>) -> (tempfile::TempDir, Roots) {
        let dir = tempfile::tempdir().unwrap();
        let (sys, proc) = (dir.path().join("sys"), dir.path().join("proc"));
        std::fs::create_dir_all(&sys).unwrap();
        if module_loaded {
            std::fs::create_dir_all(sys.join("module/zfs")).unwrap();
        }
        if let Some(text) = arcstats {
            let kstat = proc.join("spl/kstat/zfs");
            std::fs::create_dir_all(&kstat).unwrap();
            std::fs::write(kstat.join("arcstats"), text).unwrap();
        }
        (dir, Roots { sys, proc })
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

    async fn status(host: &Arc<Host>, user: &str, roots: &Roots, arguments: Value) -> ToolResult {
        call(
            host,
            user,
            &find(tools_with(roots.clone()), "zfs_status"),
            arguments,
        )
        .await
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

    #[test]
    fn parse_pools_reads_the_parsable_listing() {
        let pools = parse_pools(POOLS);
        assert_eq!(pools.len(), 2);
        assert_eq!(
            pools[0],
            Pool {
                name: "backup".to_string(),
                size: Some(1_099_511_627_776),
                allocated: Some(989_560_464_998),
                free: Some(109_951_162_778),
                fragmentation: Some(61),
                capacity: Some(90),
                dedup: "1.00".to_string(),
                health: "DEGRADED".to_string(),
            }
        );
        // a pool that does not report its fragmentation prints "-"
        let pools = parse_pools("old\t100\t50\t50\t-\t50\t1.00\tONLINE\n\nnot a pool line\n");
        assert_eq!(pools.len(), 1);
        assert_eq!(pools[0].fragmentation, None);
    }

    #[tokio::test]
    async fn the_summary_leads_with_the_pool_that_is_not_healthy() {
        let fake = fake_zfs(POOLS, STATUS_X);
        let (host, _audit) = fixture(&fake);
        let (_dir, roots) = roots(true, Some(ARCSTATS));
        let text = ok_text(status(&host, "vera", &roots, json!({})).await);
        assert_eq!(
            text.lines().next().unwrap(),
            "PROBLEM: pool backup is DEGRADED. Warnings: pool backup is 90% full (ZFS slows \
             down as a pool fills up)."
        );
        let flat = squash(&text);
        assert!(
            flat.contains(
                "POOL SIZE USED FREE FULL FRAG DEDUP HEALTH\n\
                 backup 1.0 TiB 921.6 GiB 102.4 GiB 90% 61% 1.00x DEGRADED\n\
                 tank 2.0 TiB 512.0 GiB 1.5 TiB 25% 12% 1.00x ONLINE\n"
            ),
            "{text}"
        );
        // what zpool says about the pool that is not healthy, as it printed it
        assert!(text.contains("== zpool status -x ==\n  pool: backup\n state: DEGRADED\n"));
        assert!(
            text.contains("\t    sdd     OFFLINE      0     0     0\n"),
            "{text}"
        );
        assert!(
            text.contains(
                "ARC: 1.0 GiB in use (target 2.0 GiB, limit 4.0 GiB); 99.0% of 1000 lookups \
                 were hits since boot.\n"
            ),
            "{text}"
        );
        assert_eq!(
            fake.calls("zpool"),
            [
                strings(&[
                    "list",
                    "-H",
                    "-p",
                    "-o",
                    "name,size,allocated,free,fragmentation,capacity,dedupratio,health"
                ]),
                strings(&["status", "-x"]),
            ]
        );
        assert!(fake.calls("zfs").is_empty());
    }

    #[tokio::test]
    async fn the_summary_of_healthy_pools_says_so_and_leaves_zpool_status_out() {
        let fake = fake_zfs(HEALTHY_POOLS, ALL_HEALTHY);
        let (host, _audit) = fixture(&fake);
        let (_dir, roots) = roots(true, None);
        let text = ok_text(status(&host, "vera", &roots, json!({"view": "summary"})).await);
        assert_eq!(
            text.lines().next().unwrap(),
            "No ZFS problems are visible (1 pool, ONLINE)."
        );
        assert!(!text.contains("zpool status"), "{text}");
        assert!(!text.contains("all pools are healthy"), "{text}");
        // the ARC's file could not be read: no line about it, and no failure
        assert!(!text.contains("ARC"), "{text}");
    }

    #[tokio::test]
    async fn a_complaint_from_zpool_status_about_an_online_pool_is_a_problem() {
        // data errors leave a pool ONLINE; `zpool status -x` is what reports them
        let complaint = "  pool: tank\n state: ONLINE\nstatus: One or more devices has experienced an error resulting in data\n\tcorruption.\nerrors: 2 data errors, use -v for a list\n";
        let fake = fake_zfs(HEALTHY_POOLS, complaint);
        let (host, _audit) = fixture(&fake);
        let (_dir, roots) = roots(true, None);
        let text = ok_text(status(&host, "vera", &roots, json!({})).await);
        assert_eq!(
            text.lines().next().unwrap(),
            "PROBLEM: zpool status reports a problem (below)."
        );
        assert!(text.contains("errors: 2 data errors"), "{text}");
    }

    #[test]
    fn a_pool_that_is_filling_up_is_a_warning_not_a_problem() {
        let pools = parse_pools("tank\t1000\t850\t150\t40\t85\t1.00\tONLINE\n");
        let text = summary_text(&pools, None, None);
        assert_eq!(
            text.lines().next().unwrap(),
            "Warnings: pool tank is 85% full (ZFS slows down as a pool fills up)."
        );
        // 79% is not worth a remark
        let pools = parse_pools(
            "tank\t1000\t790\t210\t40\t79\t1.00\tONLINE\nb\t1\t0\t1\t0\t0\t1.00\tONLINE\n",
        );
        let text = summary_text(&pools, None, None);
        assert_eq!(
            text.lines().next().unwrap(),
            "No ZFS problems are visible (2 pools, all ONLINE)."
        );
    }

    #[tokio::test]
    async fn a_host_with_no_pool_says_so() {
        // some versions print nothing with -H, others this line
        for listing in ["", "no pools available\n"] {
            let fake = fake_zfs(listing, ALL_HEALTHY);
            let (host, _audit) = fixture(&fake);
            let (_dir, roots) = roots(true, None);
            let text = ok_text(status(&host, "vera", &roots, json!({})).await);
            assert_eq!(text, "No ZFS pool is imported on this host.\n");
            assert_eq!(fake.calls("zpool").len(), 1);
        }
    }

    #[tokio::test]
    async fn nothing_is_run_while_the_kernel_module_is_not_loaded() {
        let fake = fake_zfs(POOLS, STATUS_X);
        let (host, _audit) = fixture(&fake);
        let (_dir, roots) = roots(false, None);
        for view in VIEWS {
            let arguments = json!({"view": view, "name": "tank"});
            let text = ok_text(status(&host, "vera", &roots, arguments).await);
            assert!(text.contains("kernel module is not loaded"), "{text}");
        }
        assert!(fake.calls("zpool").is_empty());
        assert!(fake.calls("zfs").is_empty());
    }

    #[tokio::test]
    async fn a_host_without_zfs_says_which_package_is_missing() {
        let fake = FakeBins::new().add("lsblk", "", 0);
        let (host, _audit) = fixture(&fake);
        let (_dir, roots) = roots(true, None);
        let output = status(&host, "vera", &roots, json!({})).await.unwrap();
        assert!(output.is_error());
        assert!(output.text().contains("ZFS is not installed"), "{output:?}");
        assert!(output.text().contains("zfsutils-linux"), "{output:?}");
    }

    #[tokio::test]
    async fn the_pools_view_is_zpool_status_for_all_pools_or_one() {
        let fake = fake_zfs(POOLS, STATUS_X);
        let (host, _audit) = fixture(&fake);
        let (_dir, roots) = roots(true, None);
        let text = ok_text(status(&host, "vera", &roots, json!({"view": "pools"})).await);
        assert!(
            text.starts_with("  pool: backup\n state: DEGRADED\n"),
            "{text}"
        );
        ok_text(
            status(
                &host,
                "vera",
                &roots,
                json!({"view": "pools", "name": "backup"}),
            )
            .await,
        );
        // what zpool says about a pool that does not exist comes back as a failure
        let output = status(
            &host,
            "vera",
            &roots,
            json!({"view": "pools", "name": "gone"}),
        )
        .await
        .unwrap();
        assert!(output.is_error());
        assert!(output.text().contains("no such pool"), "{output:?}");
        assert_eq!(
            fake.calls("zpool"),
            [
                strings(&["status", "-v"]),
                strings(&["status", "-v", "backup"]),
                strings(&["status", "-v", "gone"]),
            ]
        );
    }

    #[tokio::test]
    async fn a_name_that_could_be_an_option_is_refused_before_anything_runs() {
        let fake = fake_zfs(POOLS, STATUS_X);
        let (host, _audit) = fixture(&fake);
        let (_dir, roots) = roots(true, None);
        for name in [
            "-f",
            "--help",
            "tank;id",
            "tank$(id)",
            "",
            "/tank",
            "tank\ttank",
        ] {
            for view in ["pools", "datasets", "snapshots", "properties"] {
                let result =
                    status(&host, "vera", &roots, json!({"view": view, "name": name})).await;
                assert!(
                    matches!(result, Err(ToolError::Invalid(_))),
                    "{name:?}: {result:?}"
                );
            }
        }
        assert!(fake.calls("zpool").is_empty());
        assert!(fake.calls("zfs").is_empty());
    }

    #[test]
    fn check_name_takes_what_zfs_allows() {
        for name in [
            "tank",
            "tank/data/www",
            "tank/data@nightly-1",
            "rpool/ROOT/ubuntu_x1y2z3",
            "tank/time machine",
            "tank/data#mark",
            "pool.1:a",
        ] {
            assert!(check_name(name).is_ok(), "{name}");
        }
        assert!(check_name(&"a".repeat(257)).is_err());
    }

    #[tokio::test]
    async fn the_datasets_view_is_a_table_with_sizes_in_readable_units() {
        let fake = fake_zfs(POOLS, STATUS_X);
        let (host, _audit) = fixture(&fake);
        let (_dir, roots) = roots(true, None);
        let text = ok_text(status(&host, "vera", &roots, json!({"view": "datasets"})).await);
        assert_eq!(
            squash(&text),
            "NAME TYPE USED AVAIL REFER RATIO MOUNTPOINT\n\
             tank filesystem 1.0 GiB 2.0 GiB 1.0 MiB 1.00x /tank\n\
             tank/data filesystem 512.0 MiB 2.0 GiB 512.0 MiB 1.85x /tank/data\n\
             tank/vol1 volume 100.0 MiB 2.1 GiB 12.0 KiB 1.00x -"
        );
        let arguments = json!({"view": "datasets", "name": "tank/data", "limit": 2});
        let text = ok_text(status(&host, "vera", &roots, arguments).await);
        assert!(
            text.ends_with(
                "[1 more not shown; raise limit, or give name to list below one dataset]\n"
            ),
            "{text}"
        );
        assert!(!text.contains("tank/vol1"), "{text}");
        let listing = [
            "list",
            "-H",
            "-p",
            "-t",
            "filesystem,volume",
            "-o",
            "name,type,used,available,referenced,compressratio,mountpoint",
        ];
        let mut below = strings(&listing);
        below.extend(strings(&["-r", "tank/data"]));
        assert_eq!(fake.calls("zfs"), [strings(&listing), below]);
    }

    #[tokio::test]
    async fn the_snapshots_view_keeps_the_newest_and_says_when_each_was_taken() {
        let fake = fake_zfs(POOLS, STATUS_X);
        let (host, _audit) = fixture(&fake);
        let (_dir, roots) = roots(true, None);
        let text = ok_text(status(&host, "vera", &roots, json!({"view": "snapshots"})).await);
        assert_eq!(
            squash(&text),
            "3 snapshots, oldest first.\n\
             SNAPSHOT USED REFER CREATED\n\
             tank/data/www@before 14.0 KiB 20.0 MiB 2026-11-26T16:55:13Z\n\
             tank/data@nightly-1 0 B 24.0 KiB 2026-11-27T16:55:13Z\n\
             tank/data@nightly-2 8.0 KiB 24.0 KiB 2026-11-28T16:55:13Z"
        );
        let arguments = json!({"view": "snapshots", "name": "tank", "limit": 2});
        let text = ok_text(status(&host, "vera", &roots, arguments).await);
        assert!(
            text.starts_with("3 snapshots; the newest 2 are shown, oldest first.\n"),
            "{text}"
        );
        assert!(!text.contains("@before"), "{text}");
        assert!(text.contains("@nightly-2"), "{text}");
        let calls = fake.calls("zfs");
        assert_eq!(
            calls[1],
            strings(&[
                "list",
                "-H",
                "-p",
                "-t",
                "snapshot",
                "-o",
                "name,used,referenced,creation",
                "-S",
                "creation",
                "-r",
                "tank"
            ])
        );
    }

    #[test]
    fn no_snapshots_is_said_in_words() {
        assert_eq!(snapshots_text("", 50, false), "No snapshots.\n");
        assert_eq!(datasets_text("", 50), "No datasets.\n");
    }

    #[tokio::test]
    async fn the_properties_view_shows_a_pool_and_its_dataset_and_masks_a_password() {
        let fake = fake_zfs(POOLS, STATUS_X);
        let (host, _audit) = fixture(&fake);
        let (_dir, roots) = roots(true, None);
        // it needs to be told what to show
        let result = status(&host, "vera", &roots, json!({"view": "properties"})).await;
        assert!(matches!(result, Err(ToolError::Invalid(_))), "{result:?}");

        let arguments = json!({"view": "properties", "name": "tank"});
        let text = ok_text(status(&host, "vera", &roots, arguments).await);
        let flat = squash(&text);
        assert!(
            flat.starts_with(
                "== Pool tank (zpool get all) ==\n\
                 PROPERTY VALUE SOURCE\n\
                 size 2T -\n\
                 health ONLINE -\n\
                 autotrim off default\n"
            ),
            "{text}"
        );
        assert!(
            flat.contains(
                "== Dataset tank (zfs get all) ==\nPROPERTY VALUE SOURCE\ntype filesystem -\n"
            ),
            "{text}"
        );
        assert!(!text.contains("hunter2"), "{text}");
        assert!(text.contains("keys.example.com/tank"), "{text}");

        // a dataset or a snapshot has no pool properties of its own
        let arguments = json!({"view": "properties", "name": "tank/data@nightly-1"});
        let text = ok_text(status(&host, "vera", &roots, arguments).await);
        assert!(
            text.starts_with("== Dataset tank/data@nightly-1 (zfs get all) ==\n"),
            "{text}"
        );
        assert_eq!(
            fake.calls("zpool"),
            [strings(&[
                "get",
                "-H",
                "-o",
                "property,value,source",
                "all",
                "tank"
            ])]
        );
        assert_eq!(
            fake.calls("zfs")[1],
            strings(&[
                "get",
                "-H",
                "-o",
                "property,value,source",
                "all",
                "tank/data@nightly-1"
            ])
        );

        let arguments = json!({"view": "properties", "name": "tank/gone"});
        let output = status(&host, "vera", &roots, arguments).await.unwrap();
        assert!(output.is_error());
        assert!(
            output.text().contains("dataset does not exist"),
            "{output:?}"
        );
    }

    #[test]
    fn a_snapshot_list_that_was_cut_short_still_has_the_newest_and_says_it_is_not_all() {
        // zfs is asked for the newest first, so that what is lost of a list too long to
        // keep is the oldest; the count is then a lower bound
        let text = snapshots_text(SNAPSHOTS, 2, true);
        assert!(
            text.starts_with(
                "More than 3 snapshots (the list was too long to keep whole); the newest 2 \
                 are shown, oldest first.\n"
            ),
            "{text}"
        );
        let shown: Vec<&str> = text.lines().skip(2).collect();
        assert!(shown[0].starts_with("tank/data@nightly-1"), "{text}");
        assert!(shown[1].starts_with("tank/data@nightly-2"), "{text}");
    }

    #[test]
    fn lines_that_are_not_rows_are_counted_and_never_taken_for_an_empty_list() {
        // a tab inside a mount point gives a row one cell too many
        let odd = "tank\tfilesystem\t1\t2\t3\t1.00\t/tank\ntank/x\tfilesystem\t1\t2\t3\t1.00\t/odd\tpath\n";
        let text = datasets_text(odd, 50);
        assert!(text.contains("tank "), "{text}");
        assert!(
            text.ends_with("[1 line was not in the form that was asked for and is left out]\n"),
            "{text}"
        );
        let text = datasets_text("cannot understand this\nor this\n", 50);
        assert!(!text.contains("No datasets"), "{text}");
        assert!(
            text.contains("[2 lines were not in the form that was asked for and are left out]"),
            "{text}"
        );
        let text = snapshots_text("what\n", 50, false);
        assert!(!text.contains("No snapshots"), "{text}");
    }

    #[test]
    fn a_ratio_that_already_ends_in_x_is_not_given_another() {
        // `zfs list -p` prints 1.85 on current versions; allow for 1.85x
        let text = datasets_text("tank\tfilesystem\t1\t2\t3\t1.85x\t/tank\n", 50);
        assert!(text.contains("1.85x  /tank"), "{text}");
        let pools = parse_pools("tank\t1000\t100\t900\t1\t10\t2.50x\tONLINE\n");
        let text = summary_text(&pools, None, None);
        assert!(text.contains("2.50x  ONLINE"), "{text}");
    }

    #[test]
    fn a_user_property_that_says_it_is_a_secret_is_masked_and_odd_values_are_kept_whole() {
        // found against real ZFS: `zfs set com.example:password=...` is printed in full
        let listing = "com.example:password\thunter2\tlocal\n\
                       com.example:api-token\tabc123\tinherited from tank\n\
                       com.example:note\ta value\twith a tab\tlocal\n\
                       keyformat\tpassphrase\t-\n\
                       keylocation\tprompt\tlocal\n";
        let text = properties_text(listing);
        assert!(!text.contains("hunter2"), "{text}");
        assert!(!text.contains("abc123"), "{text}");
        let flat = squash(&text);
        assert!(
            flat.contains("com.example:password <redacted> local\n"),
            "{text}"
        );
        assert!(
            flat.contains("com.example:api-token <redacted> inherited from tank\n"),
            "{text}"
        );
        // a value with a tab in it stays one value, shown on one line
        assert!(
            flat.contains("com.example:note a value\\twith a tab local\n"),
            "{text}"
        );
        // ZFS's own key properties say how a key is given, not what it is
        assert!(flat.contains("keyformat passphrase -\n"), "{text}");
        assert!(flat.contains("keylocation prompt local"), "{text}");
    }

    #[tokio::test]
    async fn a_warning_beside_all_pools_are_healthy_is_not_a_problem() {
        // zpool says on stderr that something about itself is unusual, and on stdout
        // that nothing is wrong with any pool
        let zpool = format!(
            "case \"$1 $2\" in\n\
             'list -H')\n{}\n;;\n\
             'status -x')\necho 'WARNING: zfs: module version differs' >&2\necho 'all pools are healthy' ;;\n\
             esac\n",
            say(HEALTHY_POOLS)
        );
        let fake = FakeBins::new().add_script("zpool", &zpool);
        let (host, _audit) = fixture(&fake);
        let (_dir, roots) = roots(true, None);
        let text = ok_text(status(&host, "vera", &roots, json!({})).await);
        assert_eq!(
            text.lines().next().unwrap(),
            "No ZFS problems are visible (1 pool, ONLINE)."
        );
    }

    #[tokio::test]
    async fn a_caller_without_the_permission_is_refused_and_nothing_runs() {
        let fake = fake_zfs(POOLS, STATUS_X);
        let (host, audit) = fixture(&fake);
        let (_dir, roots) = roots(true, None);
        let result = status(&host, "otto", &roots, json!({})).await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        assert!(fake.calls("zpool").is_empty());
        assert_eq!(audit.records()[0]["decision"], "deny");
    }

    #[test]
    fn the_arc_line_gives_its_size_and_how_often_it_hit() {
        let arc = parse_arcstats(ARCSTATS).unwrap();
        assert_eq!(
            arc,
            ArcStats {
                size: 1 << 30,
                target: 2 << 30,
                max: 4 << 30,
                hits: 990,
                misses: 10,
            }
        );
        // nothing has been looked up yet: no ratio to give
        let idle = ArcStats {
            hits: 0,
            misses: 0,
            ..arc
        };
        assert_eq!(
            arc_line(&idle),
            "ARC: 1.0 GiB in use (target 2.0 GiB, limit 4.0 GiB).\n"
        );
        assert_eq!(parse_arcstats("name type data\nhits 4 1\n"), None);
    }
}
