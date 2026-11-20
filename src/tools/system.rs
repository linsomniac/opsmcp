//! Host overview: identity and load, memory, disk space, disk I/O.

use std::collections::{BTreeMap, HashSet};
use std::os::unix::fs::MetadataExt;

use super::args::{Args, Param};
use super::logs::uptime_secs;
use super::{Ctx, Tool, ToolResult, blocking, format_table};
use crate::policy::Access;
use crate::timefmt::{human_bytes, human_duration, now_secs, rfc3339_utc};

pub fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "system_info",
            "Overview of this host: hostname, operating system, kernel, uptime, load \
             averages, CPUs and the current time. A good first call.",
            Access::Read,
            "system.view",
            vec![],
            system_info,
        ),
        Tool::new(
            "memory_info",
            "Memory and swap usage (from /proc/meminfo), with memory pressure if the kernel \
             reports it.",
            Access::Read,
            "system.view",
            vec![],
            memory_info,
        ),
        Tool::new(
            "disk_usage",
            "Disk space and inode usage per mounted filesystem (like df). Network and \
             container-layer filesystems are left out unless asked for.",
            Access::Read,
            "system.view",
            vec![
                Param::bool(
                    "include_network",
                    "Include network filesystems (NFS, CIFS, FUSE...). A dead server can make this slow.",
                ),
                Param::bool(
                    "all",
                    "Include every mount: pseudo filesystems, container layers, images",
                ),
            ],
            disk_usage,
        ),
        Tool::new(
            "disk_io",
            "Cumulative I/O counters per block device since boot (from /proc/diskstats): \
             reads, writes, bytes, time spent and I/O in progress.",
            Access::Read,
            "system.view",
            vec![],
            disk_io,
        ),
    ]
}

/// `part` as a percentage of `whole`, rounded up: a filesystem with anything in it is
/// never shown as 0% used, and one that is not quite full is shown as 100%, as df does.
pub fn percent_up(part: u64, whole: u64) -> u64 {
    if whole == 0 {
        return 0;
    }
    let percent = (u128::from(part) * 100).div_ceil(u128::from(whole));
    u64::try_from(percent).unwrap_or(u64::MAX)
}

/// /proc/meminfo as a map. Sizes are converted to bytes; plain counts are kept as they are.
pub fn parse_meminfo(text: &str) -> BTreeMap<String, u64> {
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let mut parts = rest.split_whitespace();
        let Some(value) = parts.next().and_then(|v| v.parse::<u64>().ok()) else {
            continue;
        };
        let value = if parts.next() == Some("kB") {
            value.saturating_mul(1024)
        } else {
            value
        };
        map.insert(key.trim().to_string(), value);
    }
    map
}

/// `part` as a whole-number percentage of `whole`.
fn percent(part: u64, whole: u64) -> u64 {
    if whole == 0 {
        0
    } else {
        (part as f64 * 100.0 / whole as f64).round() as u64
    }
}

/// A short human summary of memory and swap.
pub fn format_memory(mem: &BTreeMap<String, u64>) -> String {
    let get = |key: &str| mem.get(key).copied().unwrap_or(0);
    let total = get("MemTotal");
    // "Available" is the kernel's estimate of what can be used without swapping; it is
    // the honest measure of free memory, so "used" is everything else.
    let available = get("MemAvailable");
    let used = total.saturating_sub(available);
    let mut text = format!(
        "Memory: total {}, used {} ({}%), available {}\n        free {}, buffers {}, cached {}, shared {}\n",
        human_bytes(total),
        human_bytes(used),
        percent(used, total),
        human_bytes(available),
        human_bytes(get("MemFree")),
        human_bytes(get("Buffers")),
        human_bytes(get("Cached")),
        human_bytes(get("Shmem")),
    );
    let swap_total = get("SwapTotal");
    if swap_total == 0 {
        text.push_str("Swap:   none\n");
    } else {
        let swap_used = swap_total.saturating_sub(get("SwapFree"));
        text.push_str(&format!(
            "Swap:   total {}, used {} ({}%), free {}\n",
            human_bytes(swap_total),
            human_bytes(swap_used),
            percent(swap_used, swap_total),
            human_bytes(get("SwapFree")),
        ));
    }
    text.push_str(&format!(
        "Kernel: slab {} (reclaimable {}), page tables {}, dirty {}, writeback {}\n",
        human_bytes(get("Slab")),
        human_bytes(get("SReclaimable")),
        human_bytes(get("PageTables")),
        human_bytes(get("Dirty")),
        human_bytes(get("Writeback")),
    ));
    if get("HugePages_Total") > 0 {
        text.push_str(&format!(
            "Huge pages: {} total, {} free, {} each\n",
            get("HugePages_Total"),
            get("HugePages_Free"),
            human_bytes(get("Hugepagesize")),
        ));
    }
    text
}

#[derive(Debug, PartialEq, Eq)]
pub struct Mount {
    pub source: String,
    pub point: String,
    pub fstype: String,
}

/// The mounts in /proc/self/mountinfo. Lines that do not parse are skipped.
pub fn parse_mountinfo(text: &str) -> Vec<Mount> {
    let mut mounts = Vec::new();
    for line in text.lines() {
        // ID PARENT MAJ:MIN ROOT MOUNTPOINT OPTIONS [TAGS...] - FSTYPE SOURCE SUPEROPTIONS
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        let mut right = right.split(' ');
        let (Some(point), Some(fstype), Some(source)) =
            (left.split(' ').nth(4), right.next(), right.next())
        else {
            continue;
        };
        mounts.push(Mount {
            source: unescape_octal(source),
            point: unescape_octal(point),
            fstype: fstype.to_string(),
        });
    }
    mounts
}

/// The kernel writes spaces and other awkward bytes in mount paths as `\NNN` (octal).
fn unescape_octal(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let octal = bytes
            .get(i + 1..i + 4)
            .filter(|d| bytes[i] == b'\\' && d.iter().all(|b| (b'0'..=b'7').contains(b)));
        match octal {
            Some(digits) => {
                let value = digits
                    .iter()
                    .fold(0u32, |acc, b| acc * 8 + u32::from(b - b'0'));
                out.push(u8::try_from(value).unwrap_or(b'?'));
                i += 4;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[derive(Debug, PartialEq, Eq)]
pub enum MountKind {
    /// Storage worth reporting: disks, tmpfs.
    Storage,
    /// Kernel interfaces and container/image layers: only shown with `all`.
    Other,
    /// Served over the network or from user space: statting it can hang.
    Remote,
}

pub fn mount_kind(fstype: &str) -> MountKind {
    const OTHER: [&str; 30] = [
        "proc",
        "sysfs",
        "devtmpfs",
        "devpts",
        "cgroup",
        "cgroup2",
        "securityfs",
        "debugfs",
        "tracefs",
        "configfs",
        "pstore",
        "bpf",
        "mqueue",
        "hugetlbfs",
        "autofs",
        "fusectl",
        "binfmt_misc",
        "rpc_pipefs",
        "nsfs",
        "efivarfs",
        "selinuxfs",
        "ramfs",
        "nfsd",
        "sunrpc",
        // container layers and read-only images: many, and none tells you about a disk
        "overlay",
        "squashfs",
        "erofs",
        "iso9660",
        "fuse.lxcfs",
        "fuse.portal",
    ];
    const REMOTE: [&str; 11] = [
        "nfs",
        "nfs4",
        "cifs",
        "smb3",
        "smbfs",
        "ceph",
        "9p",
        "afs",
        "lustre",
        "glusterfs",
        "davfs",
    ];
    if OTHER.contains(&fstype) {
        MountKind::Other
    } else if REMOTE.contains(&fstype) || fstype == "fuse" || fstype.starts_with("fuse.") {
        // Any user-space filesystem can stall a stat; "fuseblk" (a local disk) is not one.
        MountKind::Remote
    } else {
        MountKind::Storage
    }
}

/// Whether `disk_usage` reports a mount.
#[derive(Debug, PartialEq, Eq)]
pub enum Listing {
    Shown,
    Hidden,
    /// Left out because it is remote; counted, so the caller can be told.
    HiddenRemote,
}

/// Decides whether a mount gets a row. `all` shows everything; `include_network` adds
/// the remote filesystems.
pub fn listing(mount: &Mount, all: bool, include_network: bool) -> Listing {
    if all {
        return Listing::Shown;
    }
    match mount_kind(&mount.fstype) {
        // AIDEV-NOTE: statting a mount whose server is gone blocks for as long as the
        // kernel cares to wait, and cannot be interrupted. Remote and user-space
        // filesystems are therefore only touched when the caller asks.
        MountKind::Remote if include_network => Listing::Shown,
        MountKind::Remote => Listing::HiddenRemote,
        // The root filesystem is always worth a row, even when it is a container's overlay.
        _ if mount.point == "/" => Listing::Shown,
        MountKind::Other => Listing::Hidden,
        // systemd's per-service credential stores: a tiny tmpfs for every unit.
        MountKind::Storage if mount.point.starts_with("/run/credentials/") => Listing::Hidden,
        MountKind::Storage => Listing::Shown,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DiskStat {
    pub name: String,
    pub reads: u64,
    pub sectors_read: u64,
    pub writes: u64,
    pub sectors_written: u64,
    pub in_progress: u64,
    pub io_ms: u64,
}

/// The devices in /proc/diskstats. Lines that do not parse are skipped.
pub fn parse_diskstats(text: &str) -> Vec<DiskStat> {
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let number = |index: usize| fields.get(index)?.parse::<u64>().ok();
            Some(DiskStat {
                name: fields.get(2)?.to_string(),
                reads: number(3)?,
                sectors_read: number(5)?,
                writes: number(7)?,
                sectors_written: number(9)?,
                in_progress: number(11)?,
                io_ms: number(12)?,
            })
        })
        .collect()
}

/// PRETTY_NAME from /etc/os-release.
pub fn parse_os_release(text: &str) -> Option<String> {
    let value = text
        .lines()
        .find_map(|line| line.strip_prefix("PRETTY_NAME="))?;
    Some(value.trim().trim_matches(['"', '\'']).to_string())
}

/// Number of logical CPUs and the model name of the first, from /proc/cpuinfo.
pub fn cpu_summary(cpuinfo: &str) -> (usize, Option<String>) {
    let field = |line: &str, name: &str| -> Option<String> {
        let (key, value) = line.split_once(':')?;
        (key.trim() == name).then(|| value.trim().to_string())
    };
    let count = cpuinfo
        .lines()
        .filter(|l| field(l, "processor").is_some())
        .count();
    let model = cpuinfo.lines().find_map(|l| field(l, "model name"));
    (count, model)
}

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

async fn system_info(ctx: Ctx, _args: Args) -> ToolResult {
    let auth = ctx.authorize(None)?;
    blocking(ctx.clone(), move || {
        let now = now_secs();
        let uptime = uptime_secs().unwrap_or(0.0) as u64;
        let load = read("/proc/loadavg");
        let mut load = load.split_whitespace();
        let averages: Vec<&str> = load.by_ref().take(3).collect();
        let tasks = load.next().unwrap_or("?");
        let (cpus, model) = cpu_summary(&read("/proc/cpuinfo"));
        let mem = parse_meminfo(&read("/proc/meminfo"));
        let get = |key: &str| mem.get(key).copied().unwrap_or(0);
        let text = format!(
            "Host:    {}\n\
             OS:      {}\n\
             Kernel:  {} ({})\n\
             Uptime:  {} (booted {})\n\
             Load:    {} (1, 5 and 15 minutes); {tasks} tasks running/total\n\
             CPUs:    {cpus}{}\n\
             Memory:  total {}, available {} (memory_info has more)\n\
             Time:    {}\n",
            read("/proc/sys/kernel/hostname").trim(),
            parse_os_release(&read("/etc/os-release")).unwrap_or_else(|| "unknown".to_string()),
            read("/proc/sys/kernel/osrelease").trim(),
            std::env::consts::ARCH,
            human_duration(uptime),
            rfc3339_utc(now - i64::try_from(uptime).unwrap_or(0)),
            averages.join(" "),
            model.map(|m| format!(" x {m}")).unwrap_or_default(),
            human_bytes(get("MemTotal")),
            human_bytes(get("MemAvailable")),
            rfc3339_utc(now),
        );
        auth.ok(text)
    })
    .await
}

async fn memory_info(ctx: Ctx, _args: Args) -> ToolResult {
    let auth = ctx.authorize(None)?;
    blocking(ctx.clone(), move || {
        let mut text = format_memory(&parse_meminfo(&read("/proc/meminfo")));
        let pressure = read("/proc/pressure/memory");
        if !pressure.is_empty() {
            text.push_str("Pressure (share of time tasks stalled waiting for memory):\n");
            for line in pressure.lines() {
                text.push_str(&format!("  {line}\n"));
            }
        }
        auth.ok(text)
    })
    .await
}

async fn disk_usage(ctx: Ctx, args: Args) -> ToolResult {
    let all = args.bool("all") == Some(true);
    let include_network = all || args.bool("include_network") == Some(true);
    let auth = ctx.authorize(None)?;
    blocking(ctx.clone(), move || {
        let mut mounts = parse_mountinfo(&read("/proc/self/mountinfo"));
        // Shortest mount point first, so "/" leads and a filesystem mounted twice is
        // reported at its main mount point.
        mounts.sort_by(|a, b| a.point.cmp(&b.point));
        let mut seen = HashSet::new();
        let mut rows = Vec::new();
        let mut remote_skipped = 0;
        for mount in &mounts {
            match listing(mount, all, include_network) {
                Listing::Shown => {}
                Listing::Hidden => continue,
                Listing::HiddenRemote => {
                    remote_skipped += 1;
                    continue;
                }
            }
            let Ok(vfs) = rustix::fs::statvfs(mount.point.as_str()) else {
                continue;
            };
            if !all {
                if vfs.f_blocks == 0 {
                    continue;
                }
                let device = std::fs::metadata(&mount.point).map(|m| m.dev()).ok();
                if device.is_some_and(|d| !seen.insert(d)) {
                    continue;
                }
            }
            let size = vfs.f_blocks.saturating_mul(vfs.f_frsize);
            let used = vfs.f_blocks.saturating_sub(vfs.f_bfree).saturating_mul(vfs.f_frsize);
            let avail = vfs.f_bavail.saturating_mul(vfs.f_frsize);
            let inodes = if vfs.f_files == 0 {
                "-".to_string()
            } else {
format!(
                    "{}%",
                    percent_up(vfs.f_files.saturating_sub(vfs.f_ffree), vfs.f_files)
                )
            };
            rows.push(vec![
                mount.source.clone(),
                mount.fstype.clone(),
                human_bytes(size),
                human_bytes(used),
                human_bytes(avail),
                // as df does: used out of what an unprivileged user could use
                format!("{}%", percent_up(used, used.saturating_add(avail))),
                inodes,
                mount.point.clone(),
            ]);
        }
        let headers = ["FILESYSTEM", "TYPE", "SIZE", "USED", "AVAIL", "USE%", "IUSE%", "MOUNTED ON"];
        let right = [false, false, true, true, true, true, true, false];
        let mut text = format_table(&headers, &rows, &right);
        if remote_skipped > 0 {
            text.push_str(&format!(
                "[{remote_skipped} network or user-space filesystem(s) not shown; pass include_network to include them]\n"
            ));
        }
        auth.ok(text)
    })
    .await
}

async fn disk_io(ctx: Ctx, _args: Args) -> ToolResult {
    let auth = ctx.authorize(None)?;
    blocking(ctx.clone(), move || {
        let rows: Vec<Vec<String>> = parse_diskstats(&read("/proc/diskstats"))
            .into_iter()
            .filter(|d| d.reads + d.writes > 0)
            .map(|d| {
                vec![
                    d.name,
                    d.reads.to_string(),
                    human_bytes(d.sectors_read.saturating_mul(512)),
                    d.writes.to_string(),
                    human_bytes(d.sectors_written.saturating_mul(512)),
                    d.in_progress.to_string(),
                    human_duration(d.io_ms / 1000),
                ]
            })
            .collect();
        let headers = [
            "DEVICE",
            "READS",
            "READ",
            "WRITES",
            "WRITTEN",
            "IN-FLIGHT",
            "BUSY-TIME",
        ];
        let mut text = format_table(
            &headers,
            &rows,
            &[false, true, true, true, true, true, true],
        );
        text.push_str("[counters are totals since boot; devices with no I/O are left out]\n");
        auth.ok(text)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::ToolError;
    use crate::tools::testing::{call, find, host, ok_text};
    use serde_json::json;

    const GIB: u64 = 1024 * 1024 * 1024;

    #[test]
    fn parse_meminfo_converts_sizes_to_bytes_and_keeps_counts() {
        let mem = parse_meminfo(
            "MemTotal:       16314508 kB\nMemFree:  1000 kB\nHugePages_Total:       4\nbroken line\n",
        );
        assert_eq!(mem.get("MemTotal"), Some(&(16_314_508 * 1024)));
        assert_eq!(mem.get("MemFree"), Some(&1_024_000));
        assert_eq!(mem.get("HugePages_Total"), Some(&4));
        assert_eq!(mem.len(), 3);
    }

    #[test]
    fn format_memory_reports_used_as_total_minus_available() {
        let mem: BTreeMap<String, u64> = [
            ("MemTotal", 16 * GIB),
            ("MemAvailable", 4 * GIB),
            ("MemFree", GIB),
            ("Buffers", GIB),
            ("Cached", 2 * GIB),
            ("SwapTotal", 2 * GIB),
            ("SwapFree", GIB + GIB / 2),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        let text = format_memory(&mem);
        for want in [
            "total 16.0 GiB",
            "used 12.0 GiB (75%)",
            "available 4.0 GiB",
            "free 1.0 GiB",
            "cached 2.0 GiB",
            "Swap",
            "used 512.0 MiB (25%)",
        ] {
            assert!(text.contains(want), "expected {want:?} in:\n{text}");
        }
    }

    #[test]
    fn format_memory_copes_with_no_swap_and_missing_fields() {
        let mem: BTreeMap<String, u64> = [("MemTotal".to_string(), GIB)].into_iter().collect();
        let text = format_memory(&mem);
        assert!(text.contains("total 1.0 GiB"), "{text}");
        assert!(text.contains("Swap:   none"), "{text}");
    }

    #[test]
    fn parse_mountinfo_reads_source_mount_point_and_type() {
        let text = "\
36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
22 1 0:21 / /proc rw,nosuid shared:5 - proc proc rw
40 1 8:2 / /data/my\\040disk rw - xfs /dev/sdb1 rw
50 1 0:30 / /run rw - tmpfs tmpfs rw
this line is not a mount
";
        let mount = |source: &str, point: &str, fstype: &str| Mount {
            source: source.to_string(),
            point: point.to_string(),
            fstype: fstype.to_string(),
        };
        assert_eq!(
            parse_mountinfo(text),
            vec![
                mount("/dev/root", "/mnt2", "ext3"),
                mount("proc", "/proc", "proc"),
                mount("/dev/sdb1", "/data/my disk", "xfs"),
                mount("tmpfs", "/run", "tmpfs"),
            ]
        );
    }

    #[test]
    fn mount_kind_sorts_filesystems_by_whether_they_are_worth_statting() {
        for storage in ["ext4", "xfs", "btrfs", "zfs", "tmpfs", "vfat", "fuseblk"] {
            assert_eq!(mount_kind(storage), MountKind::Storage, "{storage}");
        }
        for other in [
            "proc", "sysfs", "cgroup2", "devtmpfs", "overlay", "squashfs", "debugfs", "nsfs",
        ] {
            assert_eq!(mount_kind(other), MountKind::Other, "{other}");
        }
        for remote in [
            "nfs",
            "nfs4",
            "cifs",
            "ceph",
            "9p",
            "fuse",
            "fuse.sshfs",
            "fuse.glusterfs",
        ] {
            assert_eq!(mount_kind(remote), MountKind::Remote, "{remote}");
        }
    }

    fn mount(point: &str, fstype: &str) -> Mount {
        Mount {
            source: "src".to_string(),
            point: point.to_string(),
            fstype: fstype.to_string(),
        }
    }

    #[test]
    fn listing_shows_real_storage_and_hides_the_noise_unless_asked() {
        use Listing::{Hidden, HiddenRemote, Shown};
        let cases: &[(&str, &str, bool, bool, Listing)] = &[
            // (mount point, type, all, include_network, expected)
            ("/", "ext4", false, false, Shown),
            ("/data", "xfs", false, false, Shown),
            ("/dev/shm", "tmpfs", false, false, Shown),
            // the root filesystem is always shown, whatever it is (a container's overlay)
            ("/", "overlay", false, false, Shown),
            (
                "/var/lib/docker/overlay2/abc/merged",
                "overlay",
                false,
                false,
                Hidden,
            ),
            (
                "/var/lib/docker/overlay2/abc/merged",
                "overlay",
                true,
                false,
                Shown,
            ),
            ("/proc", "proc", false, false, Hidden),
            // per-service credential stores: tiny tmpfs mounts, one per unit
            (
                "/run/credentials/systemd-journald.service",
                "tmpfs",
                false,
                false,
                Hidden,
            ),
            (
                "/run/credentials/systemd-journald.service",
                "tmpfs",
                true,
                false,
                Shown,
            ),
            // remote filesystems can hang: only when asked for
            ("/mnt/nfs", "nfs4", false, false, HiddenRemote),
            ("/mnt/nfs", "nfs4", false, true, Shown),
            ("/mnt/nfs", "nfs4", true, false, Shown),
            ("/home/u/remote", "fuse.sshfs", false, false, HiddenRemote),
        ];
        for (point, fstype, all, include_network, want) in cases {
            assert_eq!(
                listing(&mount(point, fstype), *all, *include_network),
                *want,
                "{point} ({fstype}) all={all} include_network={include_network}"
            );
        }
    }

    #[test]
    fn percent_up_rounds_up_as_df_does() {
        let cases: &[(u64, u64, u64)] = &[
            (0, 1000, 0),
            (1, 1000, 1),
            (500, 1000, 50),
            (501, 1000, 51),
            (999, 1000, 100),
            (1000, 1000, 100),
            (5, 0, 0),
            (u64::MAX, u64::MAX, 100),
        ];
        for (part, whole, want) in cases {
            assert_eq!(percent_up(*part, *whole), *want, "{part} of {whole}");
        }
    }

    #[test]
    fn parse_diskstats_picks_the_counters_by_position() {
        let text = "   8       0 sda 12345 100 987654 5000 54321 200 876543 9000 2 7000 14000 0 0 0 0\n 259 0 nvme0n1 1 2 3 4 5 6 7 8 9 10 11\nshort line\n";
        assert_eq!(
            parse_diskstats(text),
            vec![
                DiskStat {
                    name: "sda".into(),
                    reads: 12345,
                    sectors_read: 987_654,
                    writes: 54321,
                    sectors_written: 876_543,
                    in_progress: 2,
                    io_ms: 7000
                },
                DiskStat {
                    name: "nvme0n1".into(),
                    reads: 1,
                    sectors_read: 3,
                    writes: 5,
                    sectors_written: 7,
                    in_progress: 9,
                    io_ms: 10
                },
            ]
        );
    }

    #[test]
    fn parse_os_release_finds_the_pretty_name() {
        let text = "NAME=\"Debian GNU/Linux\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\n";
        assert_eq!(
            parse_os_release(text).as_deref(),
            Some("Debian GNU/Linux 12 (bookworm)")
        );
        assert_eq!(
            parse_os_release("PRETTY_NAME=NixOS\n").as_deref(),
            Some("NixOS")
        );
        assert_eq!(parse_os_release("ID=debian\n"), None);
    }

    #[test]
    fn cpu_summary_counts_processors_and_names_the_model() {
        let text = "processor\t: 0\nmodel name\t: Intel(R) Xeon(R) CPU\nflags\t: fpu\n\nprocessor\t: 1\nmodel name\t: Intel(R) Xeon(R) CPU\n";
        assert_eq!(
            cpu_summary(text),
            (2, Some("Intel(R) Xeon(R) CPU".to_string()))
        );
        assert_eq!(cpu_summary(""), (0, None));
    }

    const CONFIG: &str = r#"
[roles.reader]
allow = ["@read"]
[roles.other]
allow = ["logs.view"]
[unix_users.rita]
roles = ["reader"]
[unix_users.otto]
roles = ["other"]
"#;

    async fn run(user: &str, tool: &str, arguments: serde_json::Value) -> ToolResult {
        let (host, _audit) = host(CONFIG);
        call(&host, user, &find(tools(), tool), arguments).await
    }

    #[tokio::test]
    async fn system_info_describes_this_host() {
        let text = ok_text(run("rita", "system_info", json!({})).await);
        let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap();
        let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
        assert!(text.contains(hostname.trim()), "{text}");
        assert!(text.contains(release.trim()), "{text}");
        for label in ["Uptime:", "Load:", "CPUs:", "Time:"] {
            assert!(text.contains(label), "{label} missing in:\n{text}");
        }
    }

    #[tokio::test]
    async fn memory_info_reports_this_hosts_memory() {
        let text = ok_text(run("rita", "memory_info", json!({})).await);
        assert!(text.contains("Memory: total "), "{text}");
        assert!(text.contains("Swap:"), "{text}");
    }

    #[tokio::test]
    async fn disk_usage_always_includes_the_root_filesystem() {
        let text = ok_text(run("rita", "disk_usage", json!({})).await);
        assert!(
            text.lines().any(|line| line.ends_with(" /")),
            "no line for / in:\n{text}"
        );
        assert!(text.lines().next().unwrap().contains("USE%"), "{text}");
    }

    #[tokio::test]
    async fn disk_io_lists_devices_under_a_header() {
        let text = ok_text(run("rita", "disk_io", json!({})).await);
        assert!(text.lines().next().unwrap().contains("DEVICE"), "{text}");
    }

    #[tokio::test]
    async fn the_overview_tools_need_the_system_view_permission() {
        for tool in ["system_info", "memory_info", "disk_usage", "disk_io"] {
            let result = run("otto", tool, json!({})).await;
            assert!(
                matches!(result, Err(ToolError::Denied(_))),
                "{tool}: {result:?}"
            );
        }
    }
}
