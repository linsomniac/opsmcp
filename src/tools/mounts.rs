//! The health of mounted filesystems: network mounts that hang or have gone stale,
//! filesystems that turned read-only, and fstab entries that are not mounted.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use super::args::Args;
use super::package::read_small;
use super::system::{MountKind, mount_kind, unescape_octal};
use super::{CallClock, Ctx, Tool, ToolError, ToolResult, blocking, format_table, one_line_cell};
use crate::exec::CmdOutput;
use crate::policy::Access;
use crate::sanitize::{keep_head, redact_text};

/// How long one network mount gets to answer.
const PROBE_LIMIT: Duration = Duration::from_secs(3);
/// Probes that run at the same time.
const PROBES_AT_ONCE: usize = 8;
/// Network mounts probed in one call.
const MAX_PROBES: usize = 64;

/// Filesystems that live on this host's own disks. Only these are judged when they are
/// read-only: an image or a container layer is read-only by design.
const LOCAL_TYPES: [&str; 17] = [
    "ext2", "ext3", "ext4", "xfs", "btrfs", "vfat", "exfat", "f2fs", "jfs", "reiserfs", "ntfs",
    "ntfs3", "bcachefs", "zfs", "nilfs2", "ocfs2", "gfs2",
];

/// A mount that did not answer is not asked again for this long.
const HUNG_REST: Duration = Duration::from_secs(300);
/// A probe that has not reported back after this long never will: the call that started
/// it was cut off. (A probe is given a few seconds, and a few more to be cleaned up.)
const ASKING_GRACE: Duration = Duration::from_secs(30);

/// Whether a mount may be probed now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Claim {
    /// Yes: the caller starts a probe, and reports its outcome with `settle`.
    Probe,
    /// Another call's probe of this mount is out right now.
    BeingAsked,
    /// It did not answer this long ago, and is being left alone.
    StillHung(Duration),
}

/// What is remembered of one mount between calls.
#[derive(Clone, Copy, Debug)]
enum Remembered {
    /// A probe was started then and has not reported back.
    Asking(Instant),
    /// A probe got no answer then.
    Hung(Instant),
}

/// What the server remembers, between calls, about the probes of network mounts.
///
/// AIDEV-NOTE: a probe of a hard-mounted filesystem whose server is gone sits inside the
/// kernel where no signal reaches it: the time limit "kills" it, and it stays. Without
/// this memory every call would start another such process for the same dead mount, and
/// a caller asking in a loop could fill the process table. With it there is at most one
/// probe of a mount at any time, and a mount that did not answer gets no new probe for
/// `HUNG_REST`: it is reported as hung from memory. Mounts that answer are forgotten at
/// once, so the map only ever holds the troubled ones.
#[derive(Debug, Default)]
pub struct ProbeMemory {
    by_point: Mutex<HashMap<String, Remembered>>,
}

impl ProbeMemory {
    fn remembered(&self) -> std::sync::MutexGuard<'_, HashMap<String, Remembered>> {
        // Nothing is left half-done while the lock is held, so a lock that a panicking
        // thread left behind is still good.
        self.by_point
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Asks to probe the mount at `point`. On `Claim::Probe` the mount is marked as
    /// being asked, and the caller owes a `settle`.
    pub fn claim(&self, point: &str, now: Instant, rest: Duration) -> Claim {
        let mut remembered = self.remembered();
        let since = |then: Instant| now.saturating_duration_since(then);
        // What happened long enough ago is forgotten, whichever mount it was about.
        remembered.retain(|_, what| match what {
            Remembered::Asking(then) | Remembered::Hung(then) => since(*then) < rest,
        });
        match remembered.get(point).copied() {
            Some(Remembered::Hung(then)) => Claim::StillHung(since(then)),
            Some(Remembered::Asking(then)) if since(then) <= ASKING_GRACE => Claim::BeingAsked,
            // A probe that never reported back: its call was cut off, and the probe is
            // as good as hung.
            Some(Remembered::Asking(then)) => Claim::StillHung(since(then)),
            None => {
                remembered.insert(point.to_string(), Remembered::Asking(now));
                Claim::Probe
            }
        }
    }

    /// Records how the probe of `point` ended: a mount that hung is remembered, any
    /// other is forgotten.
    pub fn settle(&self, point: &str, outcome: &Probe, now: Instant) {
        let mut remembered = self.remembered();
        match outcome {
            Probe::Hung(_) => {
                remembered.insert(point.to_string(), Remembered::Hung(now));
            }
            _ => {
                remembered.remove(point);
            }
        }
    }
}

/// The memory of the running server. (Tests give each fixture one of its own.)
fn server_memory() -> Arc<ProbeMemory> {
    static MEMORY: OnceLock<Arc<ProbeMemory>> = OnceLock::new();
    MEMORY.get_or_init(Arc::default).clone()
}

/// Where this tool reads from. Tests point these at a temporary directory.
#[derive(Clone, Debug)]
pub struct Env {
    pub mountinfo: PathBuf,
    pub fstab: PathBuf,
    pub sys: PathBuf,
    /// How long one network mount gets to answer.
    pub probe_limit: Duration,
    /// What is remembered between calls about probes (see `ProbeMemory`).
    pub memory: Arc<ProbeMemory>,
    /// How long a mount that hung is left alone.
    pub rest: Duration,
}

impl Default for Env {
    fn default() -> Self {
        Env {
            mountinfo: PathBuf::from("/proc/self/mountinfo"),
            fstab: PathBuf::from("/etc/fstab"),
            sys: PathBuf::from("/sys"),
            probe_limit: PROBE_LIMIT,
            memory: server_memory(),
            rest: HUNG_REST,
        }
    }
}

pub fn tools() -> Vec<Tool> {
    vec![Tool::new(
        "mount_health",
        "Check the mounted filesystems for trouble: network filesystems (NFS, CIFS, Ceph, \
         FUSE and the like) that hang or have gone stale, local filesystems that are \
         read-only although /etc/fstab says read-write (the kernel does that after disk \
         errors), ext4 filesystems that have recorded errors, and /etc/fstab entries that \
         are not mounted. The first line is the verdict. Use it when file access hangs or \
         fails, after a reboot, or when a network storage server had trouble. For free \
         space use disk_usage; for the layout use block_devices.",
        Access::Read,
        "storage.view",
        vec![],
        |ctx, args| mount_health_at(ctx, args, Env::default()),
    )]
}

/// One line of /proc/self/mountinfo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mounted {
    /// The device number, `MAJOR:MINOR`.
    pub device: String,
    pub point: String,
    pub fstype: String,
    pub source: String,
    /// The filesystem itself is read-only (not just this one mount of it).
    pub fs_read_only: bool,
}

/// The mounts in /proc/self/mountinfo. Lines that do not parse are skipped.
///
/// AIDEV-NOTE: a mount has two sets of options. Those before the ` - ` belong to this
/// one mount (a bind mount can be made read-only on purpose while the filesystem stays
/// writable: /nix/store, a container's view of a directory). Those at the end of the
/// line belong to the filesystem. Only the latter says that the filesystem itself went
/// read-only, which is what the kernel does to it after an error.
pub fn parse_mounts(text: &str) -> Vec<Mounted> {
    let mut mounts = Vec::new();
    for line in text.lines() {
        // ID PARENT MAJ:MIN ROOT MOUNTPOINT OPTIONS [TAGS...] - FSTYPE SOURCE SUPEROPTIONS
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        let mut left = left.split(' ');
        let mut right = right.split(' ');
        let (Some(device), Some(point), Some(fstype), Some(source)) =
            (left.nth(2), left.nth(1), right.next(), right.next())
        else {
            continue;
        };
        let super_options = right.next().unwrap_or("");
        mounts.push(Mounted {
            device: device.to_string(),
            point: unescape_octal(point),
            fstype: fstype.to_string(),
            source: unescape_octal(source),
            fs_read_only: super_options.split(',').any(|option| option == "ro"),
        });
    }
    mounts
}

/// One line of /etc/fstab.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FstabEntry {
    pub source: String,
    pub point: String,
    pub fstype: String,
    pub options: Vec<String>,
}

impl FstabEntry {
    fn has(&self, option: &str) -> bool {
        self.options.iter().any(|o| o == option)
    }

    /// Whether the boot is meant to mount this entry at a place of its own: not swap,
    /// and not something that is only mounted when asked for.
    pub fn expected(&self) -> bool {
        self.point.starts_with('/') && self.fstype != "swap" && !self.has("noauto")
    }
}

/// A mount point without trailing slashes (`/` stays as it is).
fn plain_point(point: &str) -> String {
    let trimmed = point.trim_end_matches('/');
    if trimmed.is_empty() && point.starts_with('/') {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

/// The entries of /etc/fstab. Comments, blank lines and lines with fewer than three
/// fields are skipped.
pub fn parse_fstab(text: &str) -> Vec<FstabEntry> {
    let mut entries = Vec::new();
    for line in text.lines() {
        let line = line.trim_start();
        if line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let (Some(source), Some(point), Some(fstype)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let options = fields
            .next()
            .map(|list| {
                list.split(',')
                    .filter(|option| !option.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        entries.push(FstabEntry {
            // fstab writes a space as \040, as the kernel does
            source: unescape_octal(source),
            point: plain_point(&unescape_octal(point)),
            fstype: fstype.to_string(),
            options,
        });
    }
    entries
}

/// A local filesystem that is read-only.
#[derive(Debug, PartialEq, Eq)]
pub struct ReadOnly {
    pub mount: Mounted,
    /// /etc/fstab lists it as read-write: nobody asked for this.
    pub unexpected: bool,
}

/// The local filesystems that are read-only and are not meant to be, one line for each
/// filesystem however many places it is mounted at.
///
/// A filesystem that fstab mounts read-only is left out. One that fstab mounts
/// read-write is `unexpected`. One that fstab does not list was mounted by hand or by
/// something else (a snapshot mounted for a backup, a rescue mount): it is reported,
/// but nobody can say from here whether that was intended.
pub fn read_only_filesystems(mounts: &[Mounted], fstab: &[FstabEntry]) -> Vec<ReadOnly> {
    // The places each read-only filesystem is mounted at, in the order they were mounted.
    let mut by_device: BTreeMap<&str, Vec<&Mounted>> = BTreeMap::new();
    for mount in mounts {
        if mount.fs_read_only && LOCAL_TYPES.contains(&mount.fstype.as_str()) {
            by_device
                .entry(mount.device.as_str())
                .or_default()
                .push(mount);
        }
    }
    let mut found = Vec::new();
    for places in by_device.values() {
        let listed: Vec<(&Mounted, &FstabEntry)> = places
            .iter()
            .filter_map(|mount| {
                let entry = fstab.iter().find(|entry| entry.point == mount.point)?;
                Some((*mount, entry))
            })
            .collect();
        if listed.iter().any(|(_, entry)| entry.has("ro")) {
            continue;
        }
        let (mount, unexpected) = match (listed.first(), places.first()) {
            (Some((mount, _)), _) => (*mount, true),
            (None, Some(mount)) => (*mount, false),
            (None, None) => continue,
        };
        found.push(ReadOnly {
            mount: mount.clone(),
            unexpected,
        });
    }
    found.sort_by(|a, b| a.mount.point.cmp(&b.mount.point));
    found
}

/// What became of the fstab entries that should be mounted.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Unmounted {
    /// Nothing is mounted there.
    pub missing: Vec<FstabEntry>,
    /// An automount point is waiting there: it mounts when first used.
    pub waiting: Vec<FstabEntry>,
}

/// Compares fstab with what is mounted. Places are compared as written: an fstab entry
/// whose mount point is reached through a symbolic link shows up as not mounted.
pub fn unmounted(mounts: &[Mounted], fstab: &[FstabEntry]) -> Unmounted {
    let mut found = Unmounted::default();
    for entry in fstab.iter().filter(|entry| entry.expected()) {
        let mut there = mounts.iter().filter(|mount| mount.point == entry.point);
        match there.next() {
            None => found.missing.push(entry.clone()),
            Some(first) => {
                // systemd puts an autofs mount at the place and mounts the real
                // filesystem on top of it at the first access
                let only_automount =
                    first.fstype == "autofs" && there.all(|mount| mount.fstype == "autofs");
                if only_automount {
                    found.waiting.push(entry.clone());
                }
            }
        }
    }
    found
}

/// What probing one network mount found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Probe {
    Answered(Duration),
    /// No answer in this long.
    Hung(Duration),
    /// Not asked this time: it gave no answer this long ago (see `ProbeMemory`).
    StillHung(Duration),
    Stale,
    /// Only its owner may use it (a user's FUSE mount): nothing can be said.
    Private,
    Failed(String),
    NotProbed(String),
}

/// Reads the outcome of `stat -f` on a mount point.
pub fn classify(out: &CmdOutput, took: Duration) -> Probe {
    if out.timed_out {
        return Probe::Hung(took);
    }
    if out.code == Some(0) {
        return Probe::Answered(took);
    }
    let said = String::from_utf8_lossy(&out.stderr);
    if said.contains("Stale file handle") {
        return Probe::Stale;
    }
    // A FUSE mount without allow_other refuses everyone but the user who mounted it,
    // root included. That says nothing about its health.
    if said.contains("Permission denied") {
        return Probe::Private;
    }
    let reason = match said.lines().map(str::trim).find(|line| !line.is_empty()) {
        Some(line) => line.chars().take(200).collect(),
        None => match (out.signal, out.code) {
            (Some(signal), _) => format!("stat was killed by signal {signal}"),
            (None, Some(code)) => format!("stat failed with exit status {code}"),
            (None, None) => "stat failed".to_string(),
        },
    };
    Probe::Failed(reason)
}

/// The number of errors ext4 has recorded for the filesystem on `device`
/// (`MAJOR:MINOR`), if it says.
pub fn ext4_errors(sys: &Path, device: &str) -> Option<u64> {
    // Only a device number is ever made part of a path.
    let (major, minor) = device.split_once(':')?;
    let digits = |text: &str| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    if !digits(major) || !digits(minor) {
        return None;
    }
    // /sys/dev/block/8:17 is a link to the device's own directory, whose last part is
    // the name ext4 files it under (sdb1, dm-3).
    let link = std::fs::read_link(sys.join("dev/block").join(device)).ok()?;
    let name = link.file_name()?;
    let count = read_small(&sys.join("fs/ext4").join(name).join("errors_count"), 32)?;
    count.trim().parse().ok()
}

/// Everything the tool found.
#[derive(Debug, Default)]
pub struct Report {
    pub network: Vec<(Mounted, Probe)>,
    /// Network mounts beyond the number probed in one call.
    pub not_probed: usize,
    pub read_only: Vec<ReadOnly>,
    pub errors: Vec<(Mounted, u64)>,
    /// `None` when there is no readable /etc/fstab.
    pub fstab: Option<Unmounted>,
}

/// `count` with `one` or `many` after it.
fn counted(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

/// The first line: what is wrong, or that nothing is.
fn verdict(report: &Report) -> String {
    let count =
        |wanted: fn(&Probe) -> bool| report.network.iter().filter(|(_, p)| wanted(p)).count();
    let hung = count(|p| matches!(p, Probe::Hung(_) | Probe::StillHung(_)));
    let stale = count(|p| matches!(p, Probe::Stale));
    let failing = count(|p| matches!(p, Probe::Failed(_)));
    let unchecked =
        count(|p| matches!(p, Probe::Private | Probe::NotProbed(_))) + report.not_probed;
    let read_only = report.read_only.iter().filter(|r| r.unexpected).count();
    let unlisted = report.read_only.len().saturating_sub(read_only);
    let with_errors = report.errors.len();
    let missing = report.fstab.as_ref().map_or(0, |f| f.missing.len());

    let mut problems = Vec::new();
    let mut network = Vec::new();
    for (number, word) in [(hung, "hung"), (stale, "stale"), (failing, "failing")] {
        if number == 0 {
            continue;
        }
        network.push(if network.is_empty() {
            format!(
                "{} {word}",
                counted(number, "network mount", "network mounts")
            )
        } else {
            format!("{number} {word}")
        });
    }
    if !network.is_empty() {
        problems.push(network.join(", "));
    }
    if read_only > 0 {
        problems.push(format!(
            "{} read-only",
            counted(read_only, "filesystem", "filesystems")
        ));
    }
    if with_errors > 0 {
        problems.push(format!("{with_errors} with recorded errors"));
    }
    if missing > 0 {
        problems.push(format!(
            "{} not mounted",
            counted(missing, "fstab entry", "fstab entries")
        ));
    }
    let not_checked = format!(
        "{} not checked",
        counted(unchecked, "network mount was", "network mounts were")
    );
    if !problems.is_empty() {
        let mut line = format!("PROBLEMS: {}", problems.join("; "));
        if unchecked > 0 {
            line.push_str(&format!(" ({not_checked})"));
        }
        return line;
    }
    if unchecked > 0 {
        return format!("No problem found, but {not_checked}.");
    }
    let rest = match (report.fstab.is_some(), unlisted > 0) {
        (true, false) => "nothing is read-only or missing",
        (true, true) => "nothing listed in fstab is read-only or missing",
        (false, false) => "nothing is read-only",
        (false, true) => "some filesystems are read-only (see below)",
    };
    match report.network.len() {
        0 => format!("No network filesystem is mounted; {rest}."),
        1 => format!("The 1 network mount answers; {rest}."),
        many => format!("All {many} network mounts answer; {rest}."),
    }
}

/// The report as text, verdict first.
pub fn render(report: &Report) -> String {
    let cell = |text: &str| one_line_cell(text);
    // AIDEV-NOTE: what a filesystem is mounted FROM can be a URL with a user name and a
    // password in it (davfs, rclone and other user-space filesystems are mounted that
    // way), in the mount table and in fstab alike. Every source shown goes through here.
    let source = |text: &str| one_line_cell(&redact_text(text));
    let row = |mount: &Mounted, state: String| {
        vec![
            cell(&mount.point),
            cell(&mount.fstype),
            source(&mount.source),
            state,
        ]
    };
    let headers = ["MOUNT POINT", "TYPE", "SOURCE", "STATE"];
    let mut text = verdict(report);
    text.push('\n');

    if !report.network.is_empty() {
        let rows: Vec<Vec<String>> = report
            .network
            .iter()
            .map(|(mount, probe)| {
                let state = match probe {
                    Probe::Answered(took) => format!("ok ({} ms)", took.as_millis()),
                    Probe::Hung(waited) => {
                        format!("HUNG (no answer in {:.0} s)", waited.as_secs_f64().max(1.0))
                    }
                    Probe::StillHung(ago) => format!(
                        "HUNG (did not answer {} s ago; not asked again yet)",
                        ago.as_secs()
                    ),
                    Probe::Stale => {
                        "STALE (stale file handle: it must be unmounted and mounted again)"
                            .to_string()
                    }
                    Probe::Private => "not checked: only its owner may use it".to_string(),
                    Probe::Failed(reason) => format!("FAILING: {}", cell(reason)),
                    Probe::NotProbed(reason) => format!("not checked: {reason}"),
                };
                row(mount, state)
            })
            .collect();
        text.push_str("\nNetwork filesystems\n");
        text.push_str(&format_table(&headers, &rows, &[]));
    }
    if report.not_probed > 0 {
        text.push_str(&format!(
            "[{} not probed: at most {MAX_PROBES} are probed in one call]\n",
            counted(
                report.not_probed,
                "more network mount was",
                "more network mounts were"
            )
        ));
    }

    let mut rows = Vec::new();
    for found in &report.read_only {
        let state = if found.unexpected {
            "READ-ONLY (fstab says read-write: the kernel makes a filesystem read-only \
             after an error; see kernel_log)"
        } else {
            "read-only (not in fstab, so it cannot be told whether that is intended)"
        };
        rows.push(row(&found.mount, state.to_string()));
    }
    for (mount, errors) in &report.errors {
        rows.push(row(
            mount,
            format!(
                "{} recorded by ext4 (see kernel_log; it needs a check with fsck)",
                counted(
                    usize::try_from(*errors).unwrap_or(usize::MAX),
                    "error",
                    "errors"
                )
            ),
        ));
    }
    if !rows.is_empty() {
        text.push_str("\nLocal filesystems\n");
        text.push_str(&format_table(&headers, &rows, &[]));
    }

    match &report.fstab {
        None => text.push_str(
            "\n[/etc/fstab could not be read: what should be mounted, and whether a \
             read-only filesystem is meant to be, was not checked]\n",
        ),
        Some(fstab) => {
            let entry_row = |entry: &FstabEntry, state: &str| {
                let state = if entry.has("nofail") {
                    format!("{state} (nofail: the boot does not wait for it)")
                } else {
                    state.to_string()
                };
                vec![
                    cell(&entry.point),
                    cell(&entry.fstype),
                    source(&entry.source),
                    state,
                ]
            };
            let mut rows = Vec::new();
            for entry in &fstab.missing {
                rows.push(entry_row(entry, "NOT MOUNTED"));
            }
            for entry in &fstab.waiting {
                rows.push(entry_row(entry, "automount, not triggered yet"));
            }
            if !rows.is_empty() {
                text.push_str("\nEntries in /etc/fstab\n");
                text.push_str(&format_table(&headers, &rows, &[]));
            }
            if !fstab.missing.is_empty() {
                text.push_str(
                    "[mount points are compared as written: an entry whose path leads \
                     through a symbolic link shows as not mounted]\n",
                );
            }
        }
    }
    text
}

/// What is read from files, before anything is probed.
struct Facts {
    mounts: Vec<Mounted>,
    fstab: Option<Vec<FstabEntry>>,
    /// ext4 filesystems that have recorded errors.
    errors: Vec<(Mounted, u64)>,
}

fn read_facts(env: &Env) -> Result<Facts, ToolError> {
    // Without the mount table nothing can be said: that must not read as "all is well".
    let table = read_small(&env.mountinfo, 8 << 20).ok_or_else(|| {
        ToolError::Failed(format!(
            "cannot read the mount table ({})",
            env.mountinfo.display()
        ))
    })?;
    let mounts = parse_mounts(&table);
    let fstab = read_small(&env.fstab, 1 << 20).map(|text| parse_fstab(&text));
    let mut errors = Vec::new();
    let mut seen = BTreeSet::new();
    for mount in &mounts {
        let ext = matches!(mount.fstype.as_str(), "ext2" | "ext3" | "ext4");
        if !ext || !seen.insert(mount.device.as_str()) {
            continue;
        }
        if let Some(count) = ext4_errors(&env.sys, &mount.device).filter(|count| *count > 0) {
            errors.push((mount.clone(), count));
        }
    }
    Ok(Facts {
        mounts,
        fstab,
        errors,
    })
}

/// The network mounts, one for each place (what is mounted on top wins), by place.
fn network_mounts(mounts: &[Mounted]) -> Vec<Mounted> {
    let mut by_point: HashMap<&str, &Mounted> = HashMap::new();
    for mount in mounts {
        by_point.insert(mount.point.as_str(), mount);
    }
    let mut network: Vec<Mounted> = by_point
        .into_values()
        .filter(|mount| mount_kind(&mount.fstype) == MountKind::Remote)
        .cloned()
        .collect();
    network.sort_by(|a, b| a.point.cmp(&b.point));
    network
}

/// Asks one mount whether it still answers.
///
/// AIDEV-NOTE: an external command on purpose. A mount whose server is gone blocks the
/// caller inside the kernel. A child process that blocks is killed at its time limit and
/// cleaned up; a thread of this server that blocked there would stay stuck for as long
/// as the kernel cared to wait.
async fn probe(ctx: Ctx, stat: PathBuf, point: String, limit: Duration) -> Probe {
    let cmd = ctx
        .command_at(stat)
        .timeout(limit)
        .args(["-f".to_string(), "--".to_string(), point]);
    let started = Instant::now();
    match ctx.run(cmd).await {
        Ok(out) => classify(&out, started.elapsed()),
        Err(ToolError::Failed(problem)) => Probe::Failed(problem),
        Err(_) => Probe::Failed("stat could not be run".to_string()),
    }
}

pub async fn mount_health_at(ctx: Ctx, _args: Args, env: Env) -> ToolResult {
    let auth = ctx.authorize(None)?;
    let clock = CallClock::start(&ctx);
    let probe_limit = env.probe_limit;
    let (memory, rest) = (env.memory.clone(), env.rest);
    let facts = blocking(ctx.clone(), move || read_facts(&env)).await?;

    let mut network = network_mounts(&facts.mounts);
    let not_probed = network.len().saturating_sub(MAX_PROBES);
    network.truncate(MAX_PROBES);
    // Looked up only when there is something to probe.
    let stat = match network.is_empty() {
        true => None,
        false => ctx.bins().lookup("stat").map_err(ToolError::Failed)?,
    };
    let mut probed: Vec<(Mounted, Probe)> = Vec::with_capacity(network.len());
    for batch in network.chunks(PROBES_AT_ONCE) {
        let limit = match (&stat, clock.next()) {
            (None, _) => Err("stat is not installed"),
            (Some(_), None) => Err("this call ran out of time"),
            (Some(stat), Some(left)) => Ok((stat, probe_limit.min(left))),
        };
        let (stat, limit) = match limit {
            Ok(ready) => ready,
            Err(reason) => {
                for mount in batch {
                    probed.push((mount.clone(), Probe::NotProbed(reason.to_string())));
                }
                continue;
            }
        };
        // A mount is only probed if no probe of it is out and it has not just hung
        // (see `ProbeMemory`).
        let running: Vec<_> = batch
            .iter()
            .map(
                |mount| match memory.claim(&mount.point, Instant::now(), rest) {
                    Claim::StillHung(ago) => Err(Probe::StillHung(ago)),
                    Claim::BeingAsked => Err(Probe::NotProbed(
                        "another call is asking it right now".to_string(),
                    )),
                    Claim::Probe => {
                        let (ctx, stat, memory) = (ctx.clone(), stat.clone(), memory.clone());
                        let point = mount.point.clone();
                        // AIDEV-NOTE: the probe reports to the memory itself, inside its own
                        // task. A call that is cut off drops this function but not the
                        // task, so the outcome is still recorded.
                        Ok(tokio::spawn(async move {
                            let outcome = probe(ctx, stat, point.clone(), limit).await;
                            memory.settle(&point, &outcome, Instant::now());
                            outcome
                        }))
                    }
                },
            )
            .collect();
        for (mount, started) in batch.iter().zip(running) {
            let outcome = match started {
                Err(known) => known,
                Ok(handle) => match handle.await {
                    Ok(outcome) => outcome,
                    Err(_) => {
                        memory.settle(&mount.point, &Probe::Failed(String::new()), Instant::now());
                        Probe::Failed("the probe could not be run".to_string())
                    }
                },
            };
            probed.push((mount.clone(), outcome));
        }
    }

    let report = Report {
        network: probed,
        not_probed,
        read_only: read_only_filesystems(&facts.mounts, facts.fstab.as_deref().unwrap_or(&[])),
        errors: facts.errors,
        fstab: facts
            .fstab
            .as_deref()
            .map(|fstab| unmounted(&facts.mounts, fstab)),
    };
    let (text, dropped) = keep_head(&render(&report), ctx.output_budget().saturating_sub(120));
    if dropped == 0 {
        return auth.ok(text);
    }
    auth.ok(format!(
        "{text}[{dropped} more lines left out to fit the output limit]\n"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::Host;
    use crate::tools::testing::{self, FakeBins, find, host, ok_text};
    use serde_json::json;
    use std::sync::Arc;

    const MOUNTINFO: &str = "\
22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw,errors=remount-ro
23 22 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw
30 22 8:17 / /data rw,relatime shared:30 - ext4 /dev/sdb1 ro
31 22 8:17 /sub /srv/data\\040copy ro,relatime shared:30 - ext4 /dev/sdb1 ro
40 22 0:44 / /mnt/nfs rw,relatime shared:40 - nfs4 filer:/export/data rw,vers=4.2,hard
41 22 0:45 / /mnt/stale rw,relatime shared:41 - nfs filer:/old rw,vers=3
42 22 0:46 / /mnt/hung rw,relatime shared:42 - cifs //nas/share rw
43 22 0:47 / /mnt/private rw,nosuid,nodev - fuse.sshfs sam@host:/ rw,user_id=1000
50 22 253:3 / /nix/store ro,relatime shared:1 - ext4 /dev/sda2 rw,errors=remount-ro
60 22 0:50 / /srv/lazy rw,relatime shared:60 - autofs systemd-1 rw,fd=44
61 22 7:0 / /snap/core/1 ro,nodev,relatime - squashfs /dev/loop0 ro
this line is not a mount
";

    const FSTAB: &str = "\
# /etc/fstab: static file system information.
UUID=aaaa  /          ext4  errors=remount-ro  0 1
/dev/sdb1  /data      ext4  defaults           0 2
  # indented comment
filer:/export/data /mnt/nfs/ nfs4 rw,hard 0 0
filer:/backup /backup nfs defaults,nofail 0 0
/dev/sdc1 /srv/lazy xfs noauto,x-systemd.automount 0 0
/dev/sdd1 /srv/lazy2 xfs x-systemd.automount 0 0
/dev/sde1 /media/usb vfat noauto,user 0 0
/swapfile none swap sw 0 0
UUID=bbbb swap swap defaults 0 0
/dev/sdf1 /mnt/with\\040space ext4 ro 0 0
short line
";

    fn mount(device: &str, point: &str, fstype: &str, source: &str, fs_read_only: bool) -> Mounted {
        Mounted {
            device: device.to_string(),
            point: point.to_string(),
            fstype: fstype.to_string(),
            source: source.to_string(),
            fs_read_only,
        }
    }

    fn entry(source: &str, point: &str, fstype: &str, options: &[&str]) -> FstabEntry {
        FstabEntry {
            source: source.to_string(),
            point: point.to_string(),
            fstype: fstype.to_string(),
            options: options.iter().map(|o| o.to_string()).collect(),
        }
    }

    #[test]
    fn parse_mounts_reads_the_device_the_place_and_whether_the_filesystem_is_read_only() {
        let mounts = parse_mounts(MOUNTINFO);
        assert_eq!(mounts.len(), 11, "{mounts:?}");
        assert_eq!(mounts[0], mount("8:2", "/", "ext4", "/dev/sda2", false));
        assert_eq!(mounts[2], mount("8:17", "/data", "ext4", "/dev/sdb1", true));
        // an escaped space in the mount point
        assert_eq!(mounts[3].point, "/srv/data copy");
        assert_eq!(
            mounts[4],
            mount("0:44", "/mnt/nfs", "nfs4", "filer:/export/data", false)
        );
        // a read-only MOUNT of a filesystem that is itself read-write (a bind mount
        // made read-only on purpose) is not a read-only filesystem
        assert_eq!(
            mounts[8],
            mount("253:3", "/nix/store", "ext4", "/dev/sda2", false)
        );
        assert!(mounts[10].fs_read_only);
    }

    #[test]
    fn parse_mounts_copes_with_missing_fields() {
        assert_eq!(parse_mounts(""), Vec::new());
        assert_eq!(parse_mounts("1 2 8:1 / /x rw\n"), Vec::new());
        assert_eq!(parse_mounts("1 2 8:1 / /x rw - ext4\n"), Vec::new());
        // no super options at all: taken as read-write
        assert_eq!(
            parse_mounts("1 2 8:1 / /x rw - ext4 /dev/sda1\n"),
            vec![mount("8:1", "/x", "ext4", "/dev/sda1", false)]
        );
        // `ro` must be a whole option
        assert!(
            !parse_mounts("1 2 8:1 / /x rw - ext4 /dev/sda1 rw,errors=remount-ro\n")[0]
                .fs_read_only
        );
        assert!(parse_mounts("1 2 8:1 / /x rw - ext4 /dev/sda1 seclabel,ro\n")[0].fs_read_only);
    }

    #[test]
    fn parse_fstab_reads_entries_and_skips_comments() {
        let entries = parse_fstab(FSTAB);
        assert_eq!(entries.len(), 10, "{entries:?}");
        assert_eq!(
            entries[0],
            entry("UUID=aaaa", "/", "ext4", &["errors=remount-ro"])
        );
        // a trailing slash is not part of the place
        assert_eq!(entries[2].point, "/mnt/nfs");
        assert_eq!(entries[3].options, ["defaults", "nofail"]);
        assert_eq!(entries[9].point, "/mnt/with space");
        // three fields are enough; the options then count as none
        assert_eq!(
            parse_fstab("/dev/sda1 /x ext4\n"),
            vec![entry("/dev/sda1", "/x", "ext4", &[])]
        );
    }

    #[test]
    fn only_entries_the_boot_mounts_at_a_place_are_expected() {
        let expected: Vec<String> = parse_fstab(FSTAB)
            .into_iter()
            .filter(FstabEntry::expected)
            .map(|e| e.point)
            .collect();
        // noauto entries, swap and "none" are left out
        assert_eq!(
            expected,
            [
                "/",
                "/data",
                "/mnt/nfs",
                "/backup",
                "/srv/lazy2",
                "/mnt/with space"
            ]
        );
        assert!(!entry("/dev/x", "relative", "ext4", &[]).expected());
    }

    #[test]
    fn a_read_only_local_filesystem_is_reported_once_and_judged_by_fstab() {
        let mounts = parse_mounts(MOUNTINFO);
        let fstab = parse_fstab(FSTAB);
        // /data: fstab says read-write, so nobody asked for read-only. Its second
        // mount (/srv/data copy) is the same filesystem. The squashfs image is not a
        // local filesystem, and /nix/store is a read-only mount of a writable one.
        assert_eq!(
            read_only_filesystems(&mounts, &fstab),
            vec![ReadOnly {
                mount: mount("8:17", "/data", "ext4", "/dev/sdb1", true),
                unexpected: true,
            }]
        );
        // fstab asks for read-only: nothing to report
        let asked = [entry("/dev/sdb1", "/data", "ext4", &["ro", "noatime"])];
        assert_eq!(read_only_filesystems(&mounts, &asked), Vec::new());
        // not in fstab at all: reported, but not as unexpected
        assert_eq!(
            read_only_filesystems(&mounts, &[]),
            vec![ReadOnly {
                mount: mount("8:17", "/data", "ext4", "/dev/sdb1", true),
                unexpected: false,
            }]
        );
        // the entry may be for any of the places the filesystem is mounted at
        let other = [entry("/dev/sdb1", "/srv/data copy", "ext4", &["defaults"])];
        assert_eq!(
            read_only_filesystems(&mounts, &other),
            vec![ReadOnly {
                mount: mount("8:17", "/srv/data copy", "ext4", "/dev/sdb1", true),
                unexpected: true,
            }]
        );
    }

    #[test]
    fn fstab_entries_are_missing_waiting_or_mounted() {
        let mounts = parse_mounts(MOUNTINFO);
        let fstab = parse_fstab(FSTAB);
        let found = unmounted(&mounts, &fstab);
        let points = |entries: &[FstabEntry]| -> Vec<String> {
            entries.iter().map(|e| e.point.clone()).collect()
        };
        assert_eq!(
            points(&found.missing),
            ["/backup", "/srv/lazy2", "/mnt/with space"]
        );
        assert_eq!(found.waiting, Vec::new());
        // an automount point waiting at the place counts as present
        let lazy = [entry(
            "/dev/sdd1",
            "/srv/lazy",
            "xfs",
            &["x-systemd.automount"],
        )];
        let found = unmounted(&mounts, &lazy);
        assert_eq!(points(&found.waiting), ["/srv/lazy"]);
        assert_eq!(found.missing, Vec::new());
        // once it has been triggered, the real filesystem is mounted on top
        let mut triggered = mounts.clone();
        triggered.push(mount("8:49", "/srv/lazy", "xfs", "/dev/sdd1", false));
        assert_eq!(unmounted(&triggered, &lazy), Unmounted::default());
    }

    fn output(code: Option<i32>, stderr: &str, timed_out: bool) -> CmdOutput {
        CmdOutput {
            code,
            signal: None,
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
            truncated: false,
            timed_out,
        }
    }

    #[test]
    fn classify_tells_an_answer_from_a_hang_and_a_stale_handle() {
        let took = Duration::from_millis(12);
        assert_eq!(
            classify(&output(Some(0), "", false), took),
            Probe::Answered(took)
        );
        assert_eq!(classify(&output(None, "", true), took), Probe::Hung(took));
        assert_eq!(
            classify(
                &output(
                    Some(1),
                    "stat: cannot read file system information for '/mnt/x': Stale file handle\n",
                    false
                ),
                took
            ),
            Probe::Stale
        );
        assert_eq!(
            classify(
                &output(
                    Some(1),
                    "stat: cannot read file system information for '/mnt/x': Permission denied\n",
                    false
                ),
                took
            ),
            Probe::Private
        );
        assert_eq!(
            classify(
                &output(
                    Some(1),
                    "stat: cannot read file system information for '/mnt/x': Input/output error\nmore\n",
                    false
                ),
                took
            ),
            Probe::Failed(
                "stat: cannot read file system information for '/mnt/x': Input/output error"
                    .to_string()
            )
        );
        // nothing said at all
        assert_eq!(
            classify(&output(Some(2), "", false), took),
            Probe::Failed("stat failed with exit status 2".to_string())
        );
        let killed = CmdOutput {
            signal: Some(9),
            ..output(None, "", false)
        };
        assert_eq!(
            classify(&killed, took),
            Probe::Failed("stat was killed by signal 9".to_string())
        );
    }

    /// A stand-in /sys with one ext4 filesystem on device 8:17 (sdb1).
    fn sysfs(errors: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let sys = dir.path();
        std::fs::create_dir_all(sys.join("dev/block")).unwrap();
        std::fs::create_dir_all(sys.join("devices/pci0/sdb/sdb1")).unwrap();
        std::os::unix::fs::symlink("../../devices/pci0/sdb/sdb1", sys.join("dev/block/8:17"))
            .unwrap();
        std::fs::create_dir_all(sys.join("fs/ext4/sdb1")).unwrap();
        std::fs::write(sys.join("fs/ext4/sdb1/errors_count"), errors).unwrap();
        dir
    }

    #[test]
    fn ext4_errors_finds_the_count_through_the_device_number() {
        let sys = sysfs("12\n");
        assert_eq!(ext4_errors(sys.path(), "8:17"), Some(12));
        assert_eq!(ext4_errors(sysfs("0\n").path(), "8:17"), Some(0));
        // a device ext4 knows nothing about
        assert_eq!(ext4_errors(sys.path(), "8:2"), None);
        assert_eq!(ext4_errors(sysfs("many\n").path(), "8:17"), None);
        // only a device number is ever made part of a path
        for bad in ["", "8", "8:", ":17", "../8:17", "8:17/..", "a:b", "8:17:1"] {
            assert_eq!(ext4_errors(sys.path(), bad), None, "{bad:?}");
        }
    }

    #[test]
    fn render_gives_the_verdict_first() {
        let fine = Report {
            network: vec![
                (
                    mount("0:44", "/mnt/nfs", "nfs4", "filer:/export", false),
                    Probe::Answered(Duration::from_millis(12)),
                ),
                (
                    mount("0:45", "/mnt/b", "nfs4", "filer:/b", false),
                    Probe::Answered(Duration::from_millis(3)),
                ),
            ],
            fstab: Some(Unmounted::default()),
            ..Report::default()
        };
        let text = render(&fine);
        let first = text.lines().next().unwrap();
        assert_eq!(
            first,
            "All 2 network mounts answer; nothing is read-only or missing."
        );
        assert!(text.contains("ok (12 ms)"), "{text}");

        let none = Report {
            fstab: Some(Unmounted::default()),
            ..Report::default()
        };
        assert_eq!(
            render(&none).lines().next().unwrap(),
            "No network filesystem is mounted; nothing is read-only or missing."
        );

        let bad = Report {
            network: vec![
                (
                    mount("0:44", "/mnt/a", "nfs4", "filer:/a", false),
                    Probe::Hung(Duration::from_millis(3004)),
                ),
                (
                    mount("0:45", "/mnt/b", "nfs", "filer:/b", false),
                    Probe::Stale,
                ),
                (
                    mount("0:46", "/mnt/c", "cifs", "//nas/c", false),
                    Probe::Failed("stat: Input/output error".to_string()),
                ),
                (
                    mount("0:47", "/mnt/d", "nfs", "filer:/d", false),
                    Probe::Answered(Duration::from_millis(1)),
                ),
            ],
            not_probed: 0,
            read_only: vec![ReadOnly {
                mount: mount("8:17", "/data", "ext4", "/dev/sdb1", true),
                unexpected: true,
            }],
            errors: vec![(mount("8:2", "/", "ext4", "/dev/sda2", false), 7)],
            fstab: Some(Unmounted {
                missing: vec![entry("filer:/backup", "/backup", "nfs", &["nofail"])],
                waiting: vec![entry("/dev/sdd1", "/srv/lazy", "xfs", &[])],
            }),
        };
        let text = render(&bad);
        assert_eq!(
            text.lines().next().unwrap(),
            "PROBLEMS: 1 network mount hung, 1 stale, 1 failing; 1 filesystem read-only; \
             1 with recorded errors; 1 fstab entry not mounted"
        );
        for needle in [
            "HUNG (no answer in 3 s)",
            "STALE",
            "stat: Input/output error",
            "READ-ONLY",
            "7 errors recorded",
            "NOT MOUNTED",
            "automount, not triggered yet",
            "compared as written",
        ] {
            assert!(text.contains(needle), "{needle:?} missing from:\n{text}");
        }
    }

    #[test]
    fn render_says_what_could_not_be_judged() {
        let report = Report {
            network: vec![
                (
                    mount("0:47", "/run/user/1000/x", "fuse.sshfs", "sam@h:/", false),
                    Probe::Private,
                ),
                (
                    mount("0:48", "/mnt/late", "nfs", "filer:/l", false),
                    Probe::NotProbed("out of time".to_string()),
                ),
            ],
            not_probed: 3,
            read_only: vec![ReadOnly {
                mount: mount("8:33", "/mnt/snap", "ext4", "/dev/vg0/snap", true),
                unexpected: false,
            }],
            errors: Vec::new(),
            fstab: None,
        };
        let text = render(&report);
        let first = text.lines().next().unwrap();
        // nothing here is known to be wrong, but not everything was looked at
        assert!(first.starts_with("No problem found"), "{first}");
        assert!(
            first.contains("5 network mounts were not checked"),
            "{first}"
        );
        assert!(text.contains("only its owner may use it"), "{text}");
        assert!(text.contains("not checked: out of time"), "{text}");
        assert!(text.contains("3 more network mounts"), "{text}");
        // read-only, but not listed in fstab: shown, without calling it a problem
        assert!(text.contains("/mnt/snap"), "{text}");
        assert!(text.contains("read-only (not in fstab"), "{text}");
        assert!(text.contains("/etc/fstab could not be read"), "{text}");
    }

    #[test]
    fn render_keeps_a_mount_point_on_one_line() {
        let report = Report {
            network: vec![(
                mount("0:44", "/mnt/a\nPROBLEMS: fake", "nfs4", "filer:/a", false),
                Probe::Answered(Duration::from_millis(1)),
            )],
            fstab: Some(Unmounted::default()),
            ..Report::default()
        };
        let text = render(&report);
        assert!(text.contains("/mnt/a\\nPROBLEMS: fake"), "{text}");
        assert!(
            !text.lines().any(|line| line.starts_with("PROBLEMS")),
            "{text}"
        );
    }

    const CONFIG: &str = r#"
[roles.reader]
allow = ["@read"]
[roles.other]
allow = ["service.view"]
[unix_users.rita]
roles = ["reader"]
[unix_users.oscar]
roles = ["other"]
"#;

    /// A stand-in `stat`: how it answers depends on the mount point it is asked about.
    const STAT: &str = r#"
case "$3" in
  /mnt/hung) while :; do :; done ;;
  /mnt/stale) echo "stat: cannot read file system information for '$3': Stale file handle" >&2; exit 1 ;;
  /mnt/private) echo "stat: cannot read file system information for '$3': Permission denied" >&2; exit 1 ;;
  *) echo "  File: \"$3\"" ;;
esac
"#;

    /// `STAT`, which also checks how it was called and counts, in a file of its own for
    /// each mount point under `notes`, how often it was asked about that mount.
    ///
    /// AIDEV-NOTE: the probes of one call run at the same time, and `FakeBins::calls`
    /// cannot be trusted for commands that do: the stand-in appends its record a line at
    /// a time when /bin/sh is bash (which writes a line at a time, whatever it writes
    /// to), so the records of two runs interleave and a test comparing them fails at
    /// random. One byte appended to a file per mount cannot be torn.
    fn counting_stat(notes: &std::path::Path) -> String {
        format!(
            "[ \"$#\" = 3 ] && [ \"$1\" = -f ] && [ \"$2\" = -- ] || {{ echo \"stat: unexpected arguments: $*\" >&2; exit 9; }}\n\
             printf x >> '{}/asked-'\"${{3##*/}}\"\n{STAT}",
            notes.display()
        )
    }

    /// How often `counting_stat` was asked about the mount whose last path component is
    /// `name`.
    fn asked(notes: &std::path::Path, name: &str) -> u64 {
        std::fs::metadata(notes.join(format!("asked-{name}"))).map_or(0, |meta| meta.len())
    }

    struct Fixture {
        host: Arc<Host>,
        audit: MemorySink,
        env: Env,
        _dir: tempfile::TempDir,
        _sys: tempfile::TempDir,
    }

    fn fixture_with(fake: &FakeBins, mountinfo: &str, fstab: Option<&str>, extra: &str) -> Fixture {
        let (host, audit) = host(&format!("{CONFIG}{extra}{}", fake.config_only()));
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("mountinfo"), mountinfo).unwrap();
        if let Some(fstab) = fstab {
            std::fs::write(dir.path().join("fstab"), fstab).unwrap();
        }
        let sys = sysfs("3\n");
        let env = Env {
            mountinfo: dir.path().join("mountinfo"),
            fstab: dir.path().join("fstab"),
            sys: sys.path().to_path_buf(),
            // short, so that the hung mount does not hold the tests up; long enough
            // for a stand-in to answer on a busy machine
            probe_limit: Duration::from_millis(1500),
            // a memory of its own: tests must not see each other's hung mounts
            memory: Arc::default(),
            rest: HUNG_REST,
        };
        Fixture {
            host,
            audit,
            env,
            _dir: dir,
            _sys: sys,
        }
    }

    async fn run(fixture: &Fixture, user: &str) -> ToolResult {
        let tool = find(tools(), "mount_health");
        let args = Args::parse(&tool.params, Some(&json!({}))).map_err(ToolError::Invalid)?;
        let ctx = testing::ctx(&fixture.host, user, "storage.view", Access::Read);
        mount_health_at(ctx, args, fixture.env.clone()).await
    }

    #[tokio::test]
    async fn the_tool_probes_network_mounts_and_reports_every_kind_of_trouble() {
        let notes = tempfile::tempdir().unwrap();
        let fake = FakeBins::new().add_script("stat", &counting_stat(notes.path()));
        let fixture = fixture_with(&fake, MOUNTINFO, Some(FSTAB), "");
        let text = ok_text(run(&fixture, "rita").await);
        let first = text.lines().next().unwrap();
        assert_eq!(
            first,
            "PROBLEMS: 1 network mount hung, 1 stale; 1 filesystem read-only; \
             1 with recorded errors; 3 fstab entries not mounted \
             (1 network mount was not checked)"
        );
        // every network mount was asked about once, by its mount point, after `--`
        // (the stand-in refuses any other form, which would show as FAILING)
        for name in ["hung", "nfs", "private", "stale"] {
            assert_eq!(asked(notes.path(), name), 1, "{name}");
        }
        assert!(!text.contains("FAILING"), "{text}");
        for needle in [
            "/mnt/nfs",
            "ok (",
            "HUNG",
            "STALE",
            "only its owner may use it",
            "/data",
            "READ-ONLY",
            "3 errors recorded",
            "/backup",
            "NOT MOUNTED",
        ] {
            assert!(text.contains(needle), "{needle:?} missing from:\n{text}");
        }
        // local filesystems and kernel interfaces are never probed
        assert!(!text.contains("/proc"), "{text}");
        // one audit record: the call itself
        let records = fixture.audit.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["decision"], "allow");
        assert!(records[0].get("resource").is_none());
    }

    // -- a hung mount is not probed again and again (sec-read 7) --

    #[test]
    fn a_mount_is_asked_by_one_probe_at_a_time_and_rests_after_it_hung() {
        let memory = ProbeMemory::default();
        let rest = Duration::from_secs(300);
        let start = Instant::now();
        assert_eq!(memory.claim("/mnt/a", start, rest), Claim::Probe);
        // while that probe is out, nobody else starts one for the same mount
        assert_eq!(memory.claim("/mnt/a", start, rest), Claim::BeingAsked);
        // another mount is not affected
        assert_eq!(memory.claim("/mnt/b", start, rest), Claim::Probe);
        // it answered: forgotten, and asked again next time
        memory.settle("/mnt/b", &Probe::Answered(Duration::from_millis(3)), start);
        assert_eq!(memory.claim("/mnt/b", start, rest), Claim::Probe);
        // it hung: not asked again until the rest is over
        memory.settle("/mnt/a", &Probe::Hung(Duration::from_secs(3)), start);
        let later = start + Duration::from_secs(120);
        assert_eq!(
            memory.claim("/mnt/a", later, rest),
            Claim::StillHung(Duration::from_secs(120))
        );
        assert_eq!(
            memory.claim("/mnt/a", start + Duration::from_secs(301), rest),
            Claim::Probe
        );
    }

    #[test]
    fn a_probe_that_never_reported_back_counts_as_hung() {
        // the call that started it was cut off, and its probe with it
        let memory = ProbeMemory::default();
        let rest = Duration::from_secs(300);
        let start = Instant::now();
        assert_eq!(memory.claim("/mnt/a", start, rest), Claim::Probe);
        let later = start + ASKING_GRACE + Duration::from_secs(1);
        assert!(
            matches!(memory.claim("/mnt/a", later, rest), Claim::StillHung(_)),
            "{:?}",
            memory.claim("/mnt/a", later, rest)
        );
    }

    #[tokio::test]
    async fn a_mount_that_hung_is_not_probed_again_until_it_has_rested() {
        let notes = tempfile::tempdir().unwrap();
        let fake = FakeBins::new().add_script("stat", &counting_stat(notes.path()));
        let mountinfo = "\
22 1 8:2 / / rw,relatime - ext4 /dev/sda2 rw
40 22 0:44 / /mnt/hung rw,relatime - nfs4 filer:/dead rw
41 22 0:45 / /mnt/nfs rw,relatime - nfs4 filer:/export/data rw
";
        let mut fixture = fixture_with(&fake, mountinfo, Some(""), "");
        let counts = || (asked(notes.path(), "hung"), asked(notes.path(), "nfs"));
        let first = ok_text(run(&fixture, "rita").await);
        assert!(first.contains("HUNG (no answer in"), "{first}");
        assert_eq!(counts(), (1, 1), "{first}");

        // The second call reports the dead mount as hung and starts NO new probe for
        // it: a probe of a dead hard mount cannot be killed, and one per call would
        // pile up for as long as someone kept asking.
        let second = ok_text(run(&fixture, "rita").await);
        assert_eq!(
            second.lines().next().unwrap(),
            "PROBLEMS: 1 network mount hung"
        );
        assert!(
            second.contains("HUNG (did not answer") && second.contains("not asked again yet)"),
            "{second}"
        );
        // the mount that answers is asked every time
        assert_eq!(counts(), (1, 2), "{second}");

        // once it has rested it is asked again
        fixture.env.rest = Duration::ZERO;
        let third = ok_text(run(&fixture, "rita").await);
        assert!(third.contains("HUNG (no answer in"), "{third}");
        assert_eq!(counts(), (2, 3), "{third}");
    }

    #[tokio::test]
    async fn two_calls_at_once_start_one_probe_of_a_mount_between_them() {
        let notes = tempfile::tempdir().unwrap();
        let fake = FakeBins::new().add_script("stat", &counting_stat(notes.path()));
        let mountinfo = "40 22 0:44 / /mnt/hung rw,relatime - nfs4 filer:/dead rw\n";
        let fixture = fixture_with(&fake, mountinfo, Some(""), "");
        let (one, two) = tokio::join!(run(&fixture, "rita"), run(&fixture, "rita"));
        let (one, two) = (ok_text(one), ok_text(two));
        // one of them asked the mount; the other saw that it was being asked
        assert_eq!(asked(notes.path(), "hung"), 1, "{one}\n{two}");
        let both = format!("{one}\n{two}");
        assert!(both.contains("HUNG (no answer in"), "{both}");
        assert!(
            both.contains("not checked: another call is asking it right now"),
            "{both}"
        );
    }

    // -- a source can carry a password (sec-read 11) --

    #[test]
    fn a_password_in_a_source_is_masked_wherever_the_source_is_shown() {
        let source = "https://alice:hunter2@dav.example.com/files";
        let report = Report {
            network: vec![(
                mount("0:44", "/mnt/dav", "davfs", source, false),
                Probe::Answered(Duration::from_millis(4)),
            )],
            read_only: vec![ReadOnly {
                mount: mount("8:33", "/mnt/snap", "ext4", source, true),
                unexpected: false,
            }],
            errors: vec![(mount("8:17", "/data", "ext4", source, false), 2)],
            fstab: Some(Unmounted {
                missing: vec![FstabEntry {
                    source: source.to_string(),
                    point: "/mnt/other".to_string(),
                    fstype: "davfs".to_string(),
                    options: Vec::new(),
                }],
                waiting: vec![FstabEntry {
                    source: source.to_string(),
                    point: "/mnt/auto".to_string(),
                    fstype: "davfs".to_string(),
                    options: Vec::new(),
                }],
            }),
            ..Report::default()
        };
        let text = render(&report);
        assert!(!text.contains("hunter2"), "{text}");
        // the rest of the source is still there, five times over
        assert_eq!(
            text.matches("https://alice:<redacted>@dav.example.com/files")
                .count(),
            5,
            "{text}"
        );
    }

    #[tokio::test]
    async fn a_healthy_host_gets_a_one_line_all_clear() {
        let fake = FakeBins::new().add_script("stat", STAT);
        let mountinfo = "\
22 1 8:2 / / rw,relatime - ext4 /dev/sda2 rw
40 22 0:44 / /mnt/nfs rw,relatime - nfs4 filer:/export/data rw
";
        let fstab =
            "/dev/sda2 / ext4 defaults 0 1\nfiler:/export/data /mnt/nfs nfs4 defaults 0 0\n";
        let fixture = fixture_with(&fake, mountinfo, Some(fstab), "");
        let text = ok_text(run(&fixture, "rita").await);
        assert_eq!(
            text.lines().next().unwrap(),
            "The 1 network mount answers; nothing is read-only or missing."
        );
    }

    #[tokio::test]
    async fn without_network_mounts_nothing_is_run() {
        // no stat at all on this host: it is never needed
        let fake = FakeBins::new();
        let mountinfo = "22 1 8:2 / / rw,relatime - ext4 /dev/sda2 rw\n";
        let fixture = fixture_with(&fake, mountinfo, None, "");
        let text = ok_text(run(&fixture, "rita").await);
        assert_eq!(
            text.lines().next().unwrap(),
            "No network filesystem is mounted; nothing is read-only."
        );
        assert!(text.contains("/etc/fstab could not be read"), "{text}");
    }

    #[tokio::test]
    async fn a_missing_stat_program_is_a_note_not_a_failure() {
        let fake = FakeBins::new();
        let fixture = fixture_with(&fake, MOUNTINFO, Some(FSTAB), "");
        let text = ok_text(run(&fixture, "rita").await);
        let first = text.lines().next().unwrap();
        assert!(
            first.starts_with("PROBLEMS: 1 filesystem read-only"),
            "{first}"
        );
        assert!(
            first.contains("4 network mounts were not checked"),
            "{first}"
        );
        assert!(text.contains("not checked: stat"), "{text}");
    }

    #[tokio::test]
    async fn at_most_64_network_mounts_are_probed() {
        let fake = FakeBins::new().add_script("stat", STAT);
        let mut mountinfo = String::new();
        for n in 0..70 {
            mountinfo.push_str(&format!(
                "{} 22 0:{} / /mnt/n{n:02} rw - nfs4 filer:/n{n} rw\n",
                100 + n,
                100 + n
            ));
        }
        // the same place mounted over again is one mount, not two
        mountinfo.push_str("300 22 0:300 / /mnt/n00 rw - nfs4 filer:/again rw\n");
        let fixture = fixture_with(&fake, &mountinfo, Some(""), "");
        let text = ok_text(run(&fixture, "rita").await);
        assert_eq!(fake.calls("stat").len(), 64);
        assert!(text.contains("6 more network mounts"), "{text}");
        let first = text.lines().next().unwrap();
        assert!(
            first.contains("6 network mounts were not checked"),
            "{first}"
        );
        // the mount on top is the one reported
        assert!(text.contains("filer:/again"), "{text}");
        assert!(!text.contains("filer:/n0 "), "{text}");
    }

    #[tokio::test]
    async fn with_no_time_left_nothing_is_probed_and_the_report_says_so() {
        let fake = FakeBins::new().add_script("stat", STAT);
        // a call limit this short leaves nothing for a command (see CallClock)
        let limits = "[limits]\ncommand_timeout_secs = 1\ncall_timeout_secs = 1\n";
        let fixture = fixture_with(&fake, MOUNTINFO, Some(FSTAB), limits);
        let text = ok_text(run(&fixture, "rita").await);
        assert_eq!(fake.calls("stat"), Vec::<Vec<String>>::new());
        assert!(
            text.contains("not checked: this call ran out of time"),
            "{text}"
        );
        // what needs no command is still reported
        assert!(text.contains("READ-ONLY"), "{text}");
    }

    #[tokio::test]
    async fn an_unreadable_mount_table_is_a_failure_not_an_all_clear() {
        let fake = FakeBins::new().add_script("stat", STAT);
        let mut fixture = fixture_with(&fake, MOUNTINFO, Some(FSTAB), "");
        fixture.env.mountinfo = fixture.env.mountinfo.with_file_name("absent");
        let result = run(&fixture, "rita").await;
        match result {
            Err(ToolError::Failed(message)) => assert!(message.contains("absent"), "{message}"),
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_tool_needs_the_storage_permission() {
        let fake = FakeBins::new().add_script("stat", STAT);
        let fixture = fixture_with(&fake, MOUNTINFO, Some(FSTAB), "");
        let result = run(&fixture, "oscar").await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        assert_eq!(fake.calls("stat"), Vec::<Vec<String>>::new());
        assert_eq!(fixture.audit.records()[0]["decision"], "deny");
    }

    #[test]
    fn the_tool_is_a_read_tool_without_parameters() {
        let tool = find(tools(), "mount_health");
        assert_eq!(tool.access, Access::Read);
        assert_eq!(tool.permission, "storage.view");
        assert!(tool.params.is_empty());
    }
}
