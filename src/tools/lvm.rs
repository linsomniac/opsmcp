//! Growing a logical volume and its filesystem.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::args::{Args, Param};
use super::mounts::{Mounted, parse_mounts};
use super::package::{check_unit_command, plain_name, read_small, unit_output, unit_state};
use super::{
    Authorized, Ctx, Tool, ToolError, ToolResult, blocking, command_ok, command_text,
    command_text_tail, required,
};
use crate::glob::glob_match;
use crate::policy::Access;
use crate::timefmt::{human_bytes, now_secs};

const GIB: u64 = 1 << 30;

/// Where this tool reads from. Tests point it at a temporary file.
#[derive(Clone, Debug)]
pub struct Env {
    pub mountinfo: PathBuf,
}

impl Default for Env {
    fn default() -> Self {
        Env {
            mountinfo: PathBuf::from("/proc/self/mountinfo"),
        }
    }
}

pub fn tools() -> Vec<Tool> {
    vec![Tool::new(
        "lvm_extend",
        "Grow an LVM logical volume, and the filesystem on it, by a number of GiB taken \
         from the free space of its volume group (lvextend --resizefs). It only ever \
         grows: nothing can be shrunk. Only plain volumes are handled, not snapshots, \
         thin pools, mirrors or RAID. Which volumes may be grown, and by how much in one \
         call, is set in this host's configuration. Use dry_run first to see what would \
         happen; block_devices shows the volumes and the free space. A real run is \
         started as its own systemd unit, so that it is never cut off half way.",
        Access::Write,
        "storage.extend",
        vec![
            Param::str(
                "volume",
                "The logical volume, as VG/LV (for example vg0/data)",
            )
            .max_len(256)
            .required(),
            Param::int("add_gb", "How many GiB to add", 1, 10240).required(),
            Param::bool(
                "dry_run",
                "Only check and show what would be done; change nothing",
            ),
        ],
        |ctx, args| lvm_extend_at(ctx, args, Env::default()),
    )]
}

/// Checks one LVM name: letters, digits and `+ _ . -`, not starting with `-`.
///
/// AIDEV-NOTE: this is what keeps options (`--size`), paths, globs and the `$` and `%`
/// that systemd would expand out of the command lines built from these names. LVM's
/// own rules for names are the same set of characters.
fn check_lvm_name(kind: &str, name: &str) -> Result<(), ToolError> {
    let valid = !name.is_empty()
        && name.len() <= 127
        && !name.starts_with('-')
        && name != "."
        && name != ".."
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+_.-".contains(c));
    if valid {
        Ok(())
    } else {
        Err(ToolError::Invalid(format!(
            "{name:?} is not a {kind} name (letters, digits and + _ . - only, not starting with -)"
        )))
    }
}

/// Splits `VG/LV` and checks both names.
pub fn parse_volume(text: &str) -> Result<(String, String), ToolError> {
    let Some((vg, lv)) = text.split_once('/') else {
        return Err(ToolError::Invalid(format!(
            "{text:?} does not name a logical volume: write it as VG/LV, for example vg0/data"
        )));
    };
    check_lvm_name("volume group", vg)?;
    check_lvm_name("logical volume", lv)?;
    Ok((vg.to_string(), lv.to_string()))
}

/// One logical volume as `lvs` reports it.
#[derive(Debug, PartialEq, Eq)]
pub struct Volume {
    pub vg: String,
    pub lv: String,
    pub bytes: u64,
    /// The attribute string, e.g. `-wi-ao----`.
    pub attr: String,
}

/// Reads the one line of `lvs --noheadings --nosuffix --units b --separator '|' -o
/// vg_name,lv_name,lv_size,lv_attr`. Anything else LVM printed (warnings) is skipped.
pub fn parse_lvs(text: &str) -> Option<Volume> {
    text.lines().find_map(|line| {
        let fields: Vec<&str> = line.trim().split('|').collect();
        let [vg, lv, bytes, attr] = fields.as_slice() else {
            return None;
        };
        Some(Volume {
            vg: vg.to_string(),
            lv: lv.to_string(),
            bytes: bytes.parse().ok()?,
            attr: attr.to_string(),
        })
    })
}

/// What kind of volume an attribute string describes, when it is not a plain one.
///
/// AIDEV-NOTE: only a plain (linear or striped) volume is grown. Growing the others
/// takes decisions that belong to a person: a snapshot fills up and is dropped, a thin
/// pool has data and metadata to balance, a thin volume can be given more space than
/// exists, a mirror or RAID needs room on every leg. The first character of `lv_attr`
/// is the volume's type; `-` is the plain one. Anything unrecognised is refused.
pub fn special_kind(attr: &str) -> Option<&'static str> {
    Some(match attr.chars().next() {
        Some('-') => return None,
        Some('s' | 'S') => "a snapshot",
        Some('o' | 'O') => "the origin of a snapshot",
        Some('t') => "a thin pool",
        Some('V') => "a thin volume",
        Some('m' | 'M') => "a mirror",
        Some('r' | 'R') => "a RAID volume",
        Some('C') => "a cache volume",
        Some('d' | 'D') => "a VDO pool",
        Some('v') => "a virtual volume",
        Some('g') => "an integrity volume",
        Some('i' | 'I' | 'l' | 'e' | 'T') => "an internal part of a mirror, RAID or pool",
        Some('c' | 'p') => "being converted or moved, so not a plain volume right now",
        _ => "not a plain volume",
    })
}

/// Reads the free space, in bytes, from `vgs --noheadings --nosuffix --units b -o vg_free`.
pub fn parse_free(text: &str) -> Option<u64> {
    text.lines().find_map(|line| line.trim().parse().ok())
}

/// The arguments for lvextend.
///
/// AIDEV-NOTE: this is the whole of what makes the tool grow-only. The size always
/// carries a `+` (an amount to add; without it lvextend would read a new total), the
/// number comes from a checked integer, and no other LVM command that changes a volume
/// is ever built. `--resizefs` grows the filesystem with the volume.
pub fn extend_argv(volume: &str, add_gb: u64, test: bool) -> Vec<String> {
    let mut argv = Vec::new();
    if test {
        argv.push("--test".to_string());
    }
    argv.extend([
        "--resizefs".to_string(),
        "--size".to_string(),
        format!("+{add_gb}G"),
        "--".to_string(),
        volume.to_string(),
    ]);
    argv
}

/// The name of the systemd unit for one run.
pub fn unit_name(unix_secs: i64, random: [u8; 2]) -> String {
    format!("opsmcp-lvm-{unix_secs}-{:02x}{:02x}", random[0], random[1])
}

/// The device-mapper name of a volume: the two names joined by `-`, with every `-`
/// inside a name doubled.
pub fn dm_name(vg: &str, lv: &str) -> String {
    format!("{}-{}", vg.replace('-', "--"), lv.replace('-', "--"))
}

/// Where the volume is mounted, if it is.
pub fn mounted_at(mounts: &[Mounted], vg: &str, lv: &str) -> Option<String> {
    let names = [
        format!("/dev/{vg}/{lv}"),
        format!("/dev/mapper/{}", dm_name(vg, lv)),
    ];
    mounts
        .iter()
        .find(|mount| names.contains(&mount.source))
        .map(|mount| mount.point.clone())
}

/// An LVM command, or a failure that says where LVM's tools come from.
fn lvm_command(ctx: &Ctx, name: &str) -> Result<crate::exec::Cmd, ToolError> {
    ctx.command(name).map_err(|e| match e {
        ToolError::Failed(problem) => {
            ToolError::Failed(format!("{problem}; LVM's tools come with the package lvm2"))
        }
        other => other,
    })
}

/// Looks one volume up with `lvs`.
async fn look_up(ctx: &Ctx, volume: &str) -> Result<Volume, ToolError> {
    let argv = [
        "--noheadings",
        "--nosuffix",
        "--units",
        "b",
        "--separator",
        "|",
        "-o",
        "vg_name,lv_name,lv_size,lv_attr",
        "--",
        volume,
    ];
    let out = ctx.run(lvm_command(ctx, "lvs")?.args(argv)).await?;
    if !command_ok(&out) {
        return Err(ToolError::Failed(format!(
            "cannot look up {volume}: {}",
            command_text(&out).trim()
        )));
    }
    parse_lvs(&String::from_utf8_lossy(&out.stdout)).ok_or_else(|| {
        ToolError::Failed(format!(
            "cannot look up {volume}: lvs gave no answer that could be read"
        ))
    })
}

/// The free space of a volume group, in bytes.
async fn free_space(ctx: &Ctx, vg: &str) -> Result<u64, ToolError> {
    let argv = [
        "--noheadings",
        "--nosuffix",
        "--units",
        "b",
        "-o",
        "vg_free",
        "--",
        vg,
    ];
    let out = ctx.run(lvm_command(ctx, "vgs")?.args(argv)).await?;
    let free = parse_free(&String::from_utf8_lossy(&out.stdout)).filter(|_| command_ok(&out));
    free.ok_or_else(|| {
        ToolError::Failed(format!(
            "cannot find out how much space volume group {vg} has free: {}",
            command_text(&out).trim()
        ))
    })
}

/// The size of the filesystem on the volume, where it is mounted: one sentence.
async fn filesystem_line(ctx: &Ctx, env: &Env, vg: &str, lv: &str) -> String {
    let (mountinfo, vg, lv) = (env.mountinfo.clone(), vg.to_string(), lv.to_string());
    let looked = blocking(ctx.clone(), move || {
        let mounts = parse_mounts(&read_small(&mountinfo, 8 << 20).unwrap_or_default());
        let Some(point) = mounted_at(&mounts, &vg, &lv) else {
            return Ok(None);
        };
        let size = rustix::fs::statvfs(point.as_str())
            .ok()
            .map(|vfs| vfs.f_blocks.saturating_mul(vfs.f_frsize));
        Ok(Some((point, size)))
    })
    .await;
    match looked {
        Ok(Some((point, Some(size)))) => format!(
            "The filesystem mounted at {} is now {}.\n",
            super::one_line_cell(&point),
            human_bytes(size)
        ),
        Ok(Some((point, None))) => format!(
            "The volume is mounted at {}, but the size of its filesystem could not be read; \
             disk_usage shows it.\n",
            super::one_line_cell(&point)
        ),
        _ => "The volume is not mounted under its own name, so the size of the filesystem on \
              it was not checked (block_devices and disk_usage show it).\n"
            .to_string(),
    }
}

/// One run to be started as a systemd unit.
struct Job {
    systemd_run: PathBuf,
    lvextend: PathBuf,
    argv: Vec<String>,
    volume: String,
    add_gb: u64,
    /// The volume before the run.
    before: Volume,
    /// How long this call can wait for it.
    wait: Duration,
    /// What the call has to say already.
    text: String,
}

/// Starts lvextend as a transient systemd unit and waits for it as long as this call
/// may.
///
/// AIDEV-NOTE: growing a volume and its filesystem must never be killed half way. Run
/// as a child of this server it would be killed when the call's time limit passes or
/// the client goes away. Started through `systemd-run` (as package_upgrade does, see
/// `package.rs`) it belongs to systemd: when the wait below ends, only the waiting
/// client is stopped and the unit runs to its end. No `--pipe`, for the same reason;
/// the output is read back from the journal. The unit's name starts with `opsmcp`,
/// which `services.protected` covers by default.
async fn run_detached(ctx: &Ctx, env: &Env, auth: Authorized, job: Job) -> ToolResult {
    let mut random = [0u8; 2];
    getrandom::fill(&mut random)
        .map_err(|e| ToolError::Failed(format!("cannot get random bytes: {e}")))?;
    let unit = unit_name(now_secs(), random);
    let service = format!("{unit}.service");
    let program = job
        .lvextend
        .to_str()
        .ok_or_else(|| ToolError::Failed("lvextend's path is not valid UTF-8".to_string()))?;
    let (volume, add_gb) = (job.volume, job.add_gb);
    let mut argv = vec![
        format!("--unit={unit}"),
        format!(
            "--description=opsmcp lvm_extend of {volume} requested by {}",
            plain_name(&ctx.principal().name)
        ),
        "--collect".to_string(),
        "--wait".to_string(),
        "--quiet".to_string(),
        // without the right to start a unit, fail at once instead of asking for a password
        "--no-ask-password".to_string(),
    ];
    let mut command = vec![program.to_string()];
    command.extend(job.argv);
    check_unit_command(&command)?;
    argv.push("--".to_string());
    argv.extend(command);
    let out = ctx
        .run(ctx.command_at(job.systemd_run).timeout(job.wait).args(argv))
        .await?;

    let mut text = job.text;
    text.push_str(&format!(
        "== lvextend of {volume} by {add_gb} GiB, as systemd unit {service} ==\n"
    ));
    let room = ctx.output_budget().saturating_sub(text.len() + 1536);
    let (vg, lv) = (job.before.vg.as_str(), job.before.lv.as_str());
    let follow = format!(
        "Follow it with journal_query (unit={service}) or service_status; afterwards \
         block_devices and disk_usage show the sizes.\n"
    );
    if out.timed_out {
        // Only the wait ended. Whether the run is still going is systemd's to say.
        let state = unit_state(ctx, &service).await;
        match state.as_str() {
            "inactive" | "failed" => {
                // AIDEV-NOTE: the unit ended just as the wait did. `--collect` makes
                // systemd forget a unit as soon as it has ended, so "inactive" says
                // nothing about how it ended; only "failed" is a known result. The
                // volume's size is what can still be asked: a volume that grew by what
                // was asked for was grown, whatever became of this call's wait.
                let was = job.before.bytes;
                let now = look_up(ctx, &volume).await.ok();
                let grew_as_asked = now
                    .as_ref()
                    .is_some_and(|now| now.bytes >= was.saturating_add(add_gb.saturating_mul(GIB)));
                let said = unit_output(ctx, &service, room).await;
                if state == "inactive"
                    && grew_as_asked
                    && let Some(now) = &now
                {
                    // The verdict goes first: it is what the caller must not miss.
                    let mut answer = format!(
                        "{volume} was grown by {add_gb} GiB: it was {}, it is now {}. The run \
                         ended just as this call's time limit passed, so what it said about \
                         growing the filesystem was not seen: disk_usage shows whether the \
                         filesystem has the new size, and journal_query (unit={service}) \
                         what the run wrote.\n",
                        human_bytes(was),
                        human_bytes(now.bytes)
                    );
                    answer.push_str(&text);
                    answer.push_str(&said);
                    answer.push_str(&filesystem_line(ctx, env, vg, lv).await);
                    answer.push_str(
                        "This change is permanent: it is in LVM's metadata, and it survives a \
                         reboot. A volume cannot be made smaller through opsmcp.\n",
                    );
                    return auth.ok(answer);
                }
                text.push_str(&said);
                text.push_str(if state == "failed" {
                    "Extending FAILED: systemd reports the run as failed. The output above \
                     is what it wrote.\n"
                } else {
                    "The run ended just as this call's time limit passed, and its result \
                     was not seen. The output above is what it wrote.\n"
                });
                match &now {
                    Some(now) if now.bytes > was => text.push_str(&format!(
                        "The volume itself was grown all the same, from {} to {}: that is \
                         permanent. Whether the filesystem on it was grown too is what \
                         disk_usage shows; it can be grown by hand to use the space.\n",
                        human_bytes(was),
                        human_bytes(now.bytes)
                    )),
                    Some(now) => text.push_str(&format!(
                        "{volume} is still {}: it was not grown.\n",
                        human_bytes(now.bytes)
                    )),
                    None => text.push_str(
                        "Whether the volume was changed could not be found out; block_devices \
                         shows its size.\n",
                    ),
                }
                text.push_str(&filesystem_line(ctx, env, vg, lv).await);
                return auth.failed(text);
            }
            "active" | "activating" | "reloading" | "deactivating" => text.push_str(&format!(
                "The run is still running as {service}. It was not interrupted and will \
                 run to its end.\n"
            )),
            _ => text.push_str(&format!(
                "The run was started as {service} and had not finished when this call's \
                 time limit passed; it was not interrupted. Whether it is still running \
                 could not be found out.\n"
            )),
        }
        text.push_str(&follow);
        return auth.ok(text);
    }

    let succeeded = command_ok(&out);
    // journald takes what a unit wrote a moment after the unit has ended
    tokio::time::sleep(Duration::from_millis(200)).await;
    text.push_str(&unit_output(ctx, &service, room).await);
    // anything systemd-run itself had to say, and the exit status
    text.push_str(&command_text(&out));
    // Looked at again whatever the outcome: when the filesystem step fails, lvextend may
    // already have grown the volume.
    let now = look_up(ctx, &volume).await.ok();
    let was = job.before.bytes;
    if succeeded {
        text.push_str(&match &now {
            Some(now) => format!(
                "Extended {volume} by {add_gb} GiB: it was {}, it is now {}.\n",
                human_bytes(was),
                human_bytes(now.bytes)
            ),
            None => format!("Extended {volume} by {add_gb} GiB.\n"),
        });
        text.push_str(&filesystem_line(ctx, env, vg, lv).await);
        text.push_str(
            "This change is permanent: it is in LVM's metadata and in the filesystem, and \
             it survives a reboot. A volume cannot be made smaller through opsmcp.\n",
        );
    } else {
        text.push_str(&format!("Extending {volume}: FAILED.\n"));
        match &now {
            Some(now) if now.bytes > was => text.push_str(&format!(
                "The volume itself was grown all the same, from {} to {}: only the \
                 filesystem on it was not. That is permanent; the filesystem can be \
                 grown by hand to use the space.\n",
                human_bytes(was),
                human_bytes(now.bytes)
            )),
            Some(now) => text.push_str(&format!(
                "{volume} is still {}: nothing was changed.\n",
                human_bytes(now.bytes)
            )),
            None => text.push_str(
                "Whether the volume was changed could not be found out; block_devices \
                 shows its size.\n",
            ),
        }
    }
    auth.done(text, succeeded)
}

pub async fn lvm_extend_at(ctx: Ctx, args: Args, env: Env) -> ToolResult {
    let started = Instant::now();
    let (vg, lv) = parse_volume(required(&args, "volume")?)?;
    let add_gb = args
        .int("add_gb")
        .and_then(|gb| u64::try_from(gb).ok())
        .filter(|gb| *gb >= 1)
        .ok_or_else(|| ToolError::Invalid("add_gb must be at least 1".to_string()))?;
    let dry_run = args.bool("dry_run") == Some(true);
    let volume = format!("{vg}/{lv}");

    // Host-wide limits first, whatever the caller has been granted.
    let limits = &ctx.cfg().storage;
    if !limits
        .extendable
        .iter()
        .any(|pattern| glob_match(pattern, &volume))
    {
        let reason = format!(
            "{volume} is not among the volumes that storage.extendable lets lvm_extend \
             grow on this host"
        );
        return Err(ctx.deny(Some(&volume), &reason));
    }
    // AIDEV-NOTE: storage.max_extend_gb bounds ONE call, not what a caller can add over
    // several: the free space of the volume group is the only total. The description and
    // this refusal both say "in one call", so that nobody takes it for a quota.
    if add_gb > u64::from(limits.max_extend_gb) {
        let reason = format!(
            "adding {add_gb} GiB is more than storage.max_extend_gb allows in one call on \
             this host ({} GiB)",
            limits.max_extend_gb
        );
        return Err(ctx.deny(Some(&volume), &reason));
    }
    let auth = ctx.authorize(Some(&volume))?;

    let lvextend = lvm_command(&ctx, "lvextend")?;
    // Found out before anything is looked at, so that the answer does not depend on it.
    let systemd_run = if dry_run {
        None
    } else {
        Some(ctx.bins().find("systemd-run").map_err(|_| {
            ToolError::Failed(
                "lvm_extend starts a real run as a systemd unit (with systemd-run), so that \
                 it cannot be cut off half way, and systemd-run was not found on this host. \
                 Nothing was changed. A dry run is still possible."
                    .to_string(),
            )
        })?)
    };

    let before = look_up(&ctx, &volume).await?;
    if before.vg != vg || before.lv != lv {
        return Err(ToolError::Failed(format!(
            "asked LVM about {volume} and was told about {}/{}: nothing was changed",
            before.vg, before.lv
        )));
    }
    if let Some(kind) = special_kind(&before.attr) {
        return Err(ToolError::Failed(format!(
            "{volume} is {kind}. lvm_extend only grows plain logical volumes: extend this \
             one by hand. Nothing was changed."
        )));
    }
    let free = free_space(&ctx, &vg).await?;
    if free < add_gb.saturating_mul(GIB) {
        return Err(ToolError::Failed(format!(
            "volume group {vg} has {} free, less than the {add_gb} GiB asked for. Nothing \
             was changed.",
            human_bytes(free)
        )));
    }
    let mut text = format!(
        "{volume} is {}; volume group {vg} has {} free.\n",
        human_bytes(before.bytes),
        human_bytes(free)
    );

    let Some(systemd_run) = systemd_run else {
        // A dry run: LVM's own test mode, run directly like any other read.
        let out = ctx
            .run(lvextend.args(extend_argv(&volume, add_gb, true)))
            .await?;
        let succeeded = command_ok(&out);
        text.push_str(&format!(
            "== lvextend --test of {volume} by {add_gb} GiB ==\n"
        ));
        text.push_str(&command_text_tail(
            &out,
            ctx.output_budget().saturating_sub(text.len() + 512),
        ));
        text.push_str(&if succeeded {
            format!("Dry run: LVM accepts growing {volume} by {add_gb} GiB; nothing was changed.\n")
        } else {
            "The dry run FAILED; nothing was changed.\n".to_string()
        });
        return auth.done(text, succeeded);
    };

    // What is left of this call's time, keeping some back for reading the output.
    let wait = ctx
        .cfg()
        .limits
        .call_timeout_secs
        .saturating_sub(15)
        .saturating_sub(started.elapsed().as_secs())
        .max(2);
    let job = Job {
        systemd_run,
        lvextend: lvextend.program,
        argv: extend_argv(&volume, add_gb, false),
        volume,
        add_gb,
        before,
        wait: Duration::from_secs(wait),
        text,
    };
    run_detached(&ctx, &env, auth, job).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::Host;
    use crate::tools::testing::{self, FakeBins, find, host, ok_text};
    use serde_json::{Value, json};
    use std::sync::Arc;

    type Calls = Vec<Vec<String>>;

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_volume_wants_two_plain_names() {
        for (text, vg, lv) in [
            ("vg0/data", "vg0", "data"),
            ("vg-main/var_log", "vg-main", "var_log"),
            ("ubuntu-vg/ubuntu-lv", "ubuntu-vg", "ubuntu-lv"),
            ("a.b/c+d", "a.b", "c+d"),
        ] {
            assert_eq!(
                parse_volume(text).unwrap(),
                (vg.to_string(), lv.to_string()),
                "{text}"
            );
        }
        let long = format!("vg0/{}", "x".repeat(128));
        for bad in [
            "",
            "vg0",
            "vg0/",
            "/data",
            "vg0/data/extra",
            "/dev/vg0/data",
            "vg0/-data",
            "-vg0/data",
            "vg0/..",
            "./data",
            "vg0/da ta",
            "vg0/data;id",
            "vg0/$(id)",
            "vg0/da%ta",
            "vg0/data\n",
            "vg0/*",
            "vg 0/data",
            long.as_str(),
        ] {
            assert!(
                matches!(parse_volume(bad), Err(ToolError::Invalid(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn parse_lvs_reads_one_volume() {
        assert_eq!(
            parse_lvs("  vg0|data|107374182400|-wi-ao----\n"),
            Some(Volume {
                vg: "vg0".to_string(),
                lv: "data".to_string(),
                bytes: 107_374_182_400,
                attr: "-wi-ao----".to_string(),
            })
        );
        // warnings that LVM prints on the way are not volumes
        assert_eq!(
            parse_lvs("  WARNING: something\n  vg0|data|1024|-wi-a-----\n").map(|v| v.bytes),
            Some(1024)
        );
        for bad in [
            "",
            "\n",
            "vg0|data|big|-wi-a-----",
            "vg0|data|1024",
            "garbage",
        ] {
            assert_eq!(parse_lvs(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn only_a_plain_volume_is_not_special() {
        for plain in ["-wi-ao----", "-wi-a-----", "-wi-------"] {
            assert_eq!(special_kind(plain), None, "{plain}");
        }
        for (attr, word) in [
            ("swi-a-s---", "snapshot"),
            ("Swi-I-s---", "snapshot"),
            ("owi-aos---", "snapshot"),
            ("twi-aotz--", "thin pool"),
            ("Vwi-a-tz--", "thin volume"),
            ("mwi-a-m---", "mirror"),
            ("Mwi-a-m---", "mirror"),
            ("rwi-a-r---", "RAID"),
            ("Rwi-a-r---", "RAID"),
            ("Cwi-a-C---", "cache"),
            ("dwi-a-v---", "VDO"),
            ("ewi-ao----", "internal"),
            ("?wi-a-----", "plain"),
            ("", "plain"),
        ] {
            let kind = special_kind(attr).unwrap_or_else(|| panic!("{attr:?} passed as plain"));
            assert!(kind.contains(word), "{attr:?}: {kind}");
        }
    }

    #[test]
    fn parse_free_reads_a_byte_count() {
        assert_eq!(parse_free("  53687091200\n"), Some(53_687_091_200));
        assert_eq!(parse_free("  WARNING: x\n  0\n"), Some(0));
        assert_eq!(parse_free(""), None);
        assert_eq!(parse_free("  50.00g\n"), None);
    }

    #[test]
    fn extend_argv_only_ever_grows() {
        assert_eq!(
            extend_argv("vg0/data", 5, false),
            strings(&["--resizefs", "--size", "+5G", "--", "vg0/data"])
        );
        assert_eq!(
            extend_argv("vg0/data", 20, true),
            strings(&["--test", "--resizefs", "--size", "+20G", "--", "vg0/data"])
        );
        // AIDEV-NOTE: the `+` is what makes the size an amount to ADD. Without it
        // lvextend would take it as the new size.
        for gb in [1, 7, 10240] {
            let argv = extend_argv("vg0/data", gb, false);
            assert_eq!(argv[2], format!("+{gb}G"));
        }
    }

    #[test]
    fn unit_names_are_ours_and_distinct() {
        assert_eq!(
            unit_name(1_700_000_000, [0xab, 0x01]),
            "opsmcp-lvm-1700000000-ab01"
        );
    }

    #[test]
    fn dm_name_doubles_hyphens() {
        assert_eq!(dm_name("vg0", "data"), "vg0-data");
        assert_eq!(dm_name("ubuntu-vg", "ubuntu-lv"), "ubuntu--vg-ubuntu--lv");
    }

    #[test]
    fn mounted_at_finds_the_volume_under_either_of_its_names() {
        let mounts = parse_mounts(
            "\
22 1 253:0 / / rw - ext4 /dev/mapper/ubuntu--vg-ubuntu--lv rw
30 22 253:1 / /data rw - xfs /dev/vg0/data rw
31 22 253:2 / /srv rw - ext4 /dev/mapper/vg0-srv rw
",
        );
        assert_eq!(
            mounted_at(&mounts, "ubuntu-vg", "ubuntu-lv"),
            Some("/".to_string())
        );
        assert_eq!(
            mounted_at(&mounts, "vg0", "data"),
            Some("/data".to_string())
        );
        assert_eq!(mounted_at(&mounts, "vg0", "srv"), Some("/srv".to_string()));
        assert_eq!(mounted_at(&mounts, "vg0", "other"), None);
        // vg0-srv is not the volume srv in a group called "vg0-" or the like
        assert_eq!(mounted_at(&mounts, "vg0-srv", "x"), None);
    }

    const CONFIG: &str = r#"
[roles.admin]
allow = ["@all"]
[roles.data]
allow = ["storage.extend:vg0/data"]
[roles.reader]
allow = ["@read"]
[unix_users.adam]
roles = ["admin"]
[unix_users.dana]
roles = ["data"]
[unix_users.rita]
roles = ["reader"]
[storage]
extendable = ["vg0/*", "small/*"]
max_extend_gb = 20
"#;

    /// A stand-in systemd-run: runs the command after `--`, as systemd would.
    const SYSTEMD_RUN: &str = r#"
while [ $# -gt 0 ]; do
  case "$1" in
    --) shift; break ;;
  esac
  shift
done
"$@"
"#;

    struct Fixture {
        host: Arc<Host>,
        audit: MemorySink,
        env: Env,
        fake: FakeBins,
        dir: tempfile::TempDir,
    }

    /// LVM stand-ins. `lvs` answers by volume, and reports vg0/data as larger once the
    /// stand-in `lvextend` has run for real.
    fn lvm(dir: &std::path::Path) -> FakeBins {
        let grown = dir.join("grown").display().to_string();
        let lvs = format!(
            r#"
for last; do :; done
case "$last" in
  vg0/data)
    if [ -e '{grown}' ]; then echo '  vg0|data|112742891520|-wi-ao----'
    else echo '  vg0|data|107374182400|-wi-ao----'; fi ;;
  vg0/snap) echo '  vg0|snap|1073741824|swi-a-s---' ;;
  vg0/pool) echo '  vg0|pool|10737418240|twi-aotz--' ;;
  vg0/thin) echo '  vg0|thin|10737418240|Vwi-a-tz--' ;;
  vg0/mirror) echo '  vg0|mirror|10737418240|mwi-a-m---' ;;
  vg0/raid) echo '  vg0|raid|10737418240|rwi-a-r---' ;;
  small/data) echo '  small|data|10737418240|-wi-ao----' ;;
  vg0/broken) echo '  vg0|broken|10737418240|-wi-ao----' ;;
  vg0/other) echo '  vg0|data|107374182400|-wi-ao----' ;;
  *) echo "  Failed to find logical volume \"$last\"" >&2; exit 5 ;;
esac
"#
        );
        let vgs = r#"
for last; do :; done
case "$last" in
  vg0) echo '  53687091200' ;;
  small) echo '  1073741824' ;;
  *) echo "  Volume group \"$last\" not found" >&2; exit 5 ;;
esac
"#;
        let lvextend = format!(
            r#"
for last; do :; done
if [ "$1" = --test ]; then
  echo '  TEST MODE: Metadata will NOT be updated and volumes will not be (de)activated.'
  echo "  Logical volume $last successfully resized."
  exit 0
fi
if [ "$last" = vg0/broken ]; then
  echo '  fsadm: Cannot get FSTYPE of "/dev/mapper/vg0-broken".' >&2
  exit 5
fi
: > '{grown}'
echo "  Logical volume $last successfully resized."
"#
        );
        FakeBins::new()
            .add_script("lvs", &lvs)
            .add_script("vgs", vgs)
            .add_script("lvextend", &lvextend)
    }

    fn with_systemd(fake: FakeBins) -> FakeBins {
        fake.add_script("systemd-run", SYSTEMD_RUN)
            .add(
                "journalctl",
                "  Size of logical volume vg0/data changed from 100.00 GiB to 105.00 GiB.\n",
                0,
            )
            .add("systemctl", "active\n", 0)
    }

    fn fixture_from(
        build: impl FnOnce(&std::path::Path) -> FakeBins,
        config: &str,
        extra: &str,
    ) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let fake = build(dir.path());
        let (host, audit) = host(&format!("{config}{extra}{}", fake.config_only()));
        // vg0/data is mounted (here: at the temporary directory, which exists)
        let mountinfo = format!(
            "30 22 253:1 / {} rw - ext4 /dev/mapper/vg0-data rw\n",
            dir.path().display()
        );
        std::fs::write(dir.path().join("mountinfo"), mountinfo).unwrap();
        let env = Env {
            mountinfo: dir.path().join("mountinfo"),
        };
        Fixture {
            host,
            audit,
            env,
            fake,
            dir,
        }
    }

    fn fixture() -> Fixture {
        fixture_from(|dir| with_systemd(lvm(dir)), CONFIG, "")
    }

    async fn run(fixture: &Fixture, user: &str, arguments: Value) -> ToolResult {
        let tool = find(tools(), "lvm_extend");
        let args = Args::parse(&tool.params, Some(&arguments)).map_err(ToolError::Invalid)?;
        let ctx = testing::ctx(&fixture.host, user, "storage.extend", Access::Write);
        lvm_extend_at(ctx, args, fixture.env.clone()).await
    }

    fn nothing_ran(fixture: &Fixture) {
        for name in ["lvs", "vgs", "lvextend", "systemd-run"] {
            assert_eq!(fixture.fake.calls(name), Calls::new(), "{name}");
        }
    }

    /// Where a stand-in command lives: what the server passes to systemd-run.
    fn path_of(fake: &FakeBins, name: &str) -> String {
        let config = fake.config();
        let line = config
            .lines()
            .find(|line| line.starts_with(&format!("\"{name}\" = ")))
            .unwrap();
        line.split('"').nth(3).unwrap().to_string()
    }

    #[tokio::test]
    async fn unusable_arguments_are_refused_before_anything_is_decided() {
        let fixture = fixture();
        for arguments in [
            json!({}),
            json!({"volume": "vg0/data"}),
            json!({"add_gb": 5}),
            json!({"volume": "vg0/data", "add_gb": 0}),
            json!({"volume": "vg0/data", "add_gb": -5}),
            json!({"volume": "vg0/data", "add_gb": 10241}),
            json!({"volume": "vg0/data", "add_gb": "5"}),
            json!({"volume": "vg0", "add_gb": 5}),
            json!({"volume": "vg0/--size", "add_gb": 5}),
            json!({"volume": "/dev/vg0/data", "add_gb": 5}),
            json!({"volume": "vg0/data", "add_gb": 5, "shrink": true}),
        ] {
            let result = run(&fixture, "adam", arguments.clone()).await;
            assert!(
                matches!(result, Err(ToolError::Invalid(_))),
                "{arguments}: {result:?}"
            );
        }
        nothing_ran(&fixture);
        assert_eq!(fixture.audit.records().len(), 0);
    }

    #[tokio::test]
    async fn a_volume_the_host_does_not_list_is_refused_whatever_the_grant() {
        let fixture = fixture();
        // adam holds @all, but other/data matches nothing in storage.extendable
        let result = run(
            &fixture,
            "adam",
            json!({"volume": "other/data", "add_gb": 5}),
        )
        .await;
        match result {
            Err(ToolError::Denied(message)) => {
                assert!(message.contains("storage.extendable"), "{message}")
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        let records = fixture.audit.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["decision"], "deny");
        assert_eq!(records[0]["resource"], "other/data");
        assert!(
            records[0]["reason"]
                .as_str()
                .unwrap()
                .contains("storage.extendable")
        );
        nothing_ran(&fixture);
    }

    #[tokio::test]
    async fn by_default_no_volume_may_be_grown() {
        let config = CONFIG.split("[storage]").next().unwrap();
        let fixture = fixture_from(|dir| with_systemd(lvm(dir)), config, "");
        let result = run(&fixture, "adam", json!({"volume": "vg0/data", "add_gb": 1})).await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        nothing_ran(&fixture);
    }

    #[tokio::test]
    async fn more_than_the_host_allows_in_one_call_is_refused() {
        let fixture = fixture();
        let result = run(
            &fixture,
            "adam",
            json!({"volume": "vg0/data", "add_gb": 21}),
        )
        .await;
        match result {
            Err(ToolError::Denied(message)) => {
                assert!(message.contains("storage.max_extend_gb"), "{message}");
                // the limit is on one call, and the refusal says so
                assert!(message.contains("in one call"), "{message}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert_eq!(fixture.audit.records()[0]["decision"], "deny");
        nothing_ran(&fixture);
        // so does the description the agent reads
        let tool = find(tools(), "lvm_extend");
        assert!(
            tool.description.contains("in one call"),
            "{}",
            tool.description
        );
    }

    #[tokio::test]
    async fn the_caller_needs_a_grant_for_that_volume() {
        let fixture = fixture();
        // dana may grow vg0/data only
        let result = run(&fixture, "dana", json!({"volume": "vg0/srv", "add_gb": 5})).await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        let records = fixture.audit.records();
        assert_eq!(
            (&records[0]["resource"], &records[0]["decision"]),
            (&json!("vg0/srv"), &json!("deny"))
        );
        // a reader holds no write permission at all
        let result = run(&fixture, "rita", json!({"volume": "vg0/data", "add_gb": 5})).await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        nothing_ran(&fixture);
        // and what dana may grow, she can
        let arguments = json!({"volume": "vg0/data", "add_gb": 5, "dry_run": true});
        ok_text(run(&fixture, "dana", arguments).await);
    }

    #[tokio::test]
    async fn an_unknown_volume_is_only_reported_after_authorization() {
        let fixture = fixture();
        let result = run(
            &fixture,
            "adam",
            json!({"volume": "vg0/ghost", "add_gb": 5}),
        )
        .await;
        match result {
            Err(ToolError::Failed(message)) => {
                assert!(message.contains("vg0/ghost"), "{message}");
                assert!(message.contains("Failed to find"), "{message}");
            }
            other => panic!("expected a failure, got {other:?}"),
        }
        assert_eq!(fixture.audit.records()[0]["decision"], "allow");
        assert_eq!(fixture.fake.calls("lvextend"), Calls::new());
        assert_eq!(fixture.fake.calls("systemd-run"), Calls::new());
        // a caller without the grant learns nothing about what exists
        let result = run(
            &fixture,
            "dana",
            json!({"volume": "vg0/ghost", "add_gb": 5}),
        )
        .await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
    }

    #[tokio::test]
    async fn an_answer_about_another_volume_is_not_acted_on() {
        let fixture = fixture();
        // lvs answers with a volume that is not the one asked about
        let result = run(
            &fixture,
            "adam",
            json!({"volume": "vg0/other", "add_gb": 1}),
        )
        .await;
        match result {
            Err(ToolError::Failed(message)) => {
                assert!(message.contains("vg0/other"), "{message}");
                assert!(message.contains("vg0/data"), "{message}");
            }
            other => panic!("expected a failure, got {other:?}"),
        }
        assert_eq!(fixture.fake.calls("lvextend"), Calls::new());
        assert_eq!(fixture.fake.calls("systemd-run"), Calls::new());
    }

    #[tokio::test]
    async fn only_plain_volumes_are_grown() {
        let fixture = fixture();
        for (volume, word) in [
            ("vg0/snap", "snapshot"),
            ("vg0/pool", "thin pool"),
            ("vg0/thin", "thin volume"),
            ("vg0/mirror", "mirror"),
            ("vg0/raid", "RAID"),
        ] {
            let result = run(&fixture, "adam", json!({"volume": volume, "add_gb": 1})).await;
            match result {
                Err(ToolError::Failed(message)) => {
                    assert!(message.contains(word), "{volume}: {message}");
                    assert!(message.contains("by hand"), "{volume}: {message}");
                }
                other => panic!("{volume}: expected a failure, got {other:?}"),
            }
        }
        assert_eq!(fixture.fake.calls("lvextend"), Calls::new());
        assert_eq!(fixture.fake.calls("systemd-run"), Calls::new());
    }

    #[tokio::test]
    async fn too_little_free_space_is_said_before_anything_is_changed() {
        let fixture = fixture();
        // the group "small" has 1 GiB free
        let result = run(
            &fixture,
            "adam",
            json!({"volume": "small/data", "add_gb": 2}),
        )
        .await;
        match result {
            Err(ToolError::Failed(message)) => {
                assert!(message.contains("1.0 GiB"), "{message}");
                assert!(message.contains("small"), "{message}");
            }
            other => panic!("expected a failure, got {other:?}"),
        }
        assert_eq!(fixture.fake.calls("lvextend"), Calls::new());
        assert_eq!(fixture.fake.calls("systemd-run"), Calls::new());
        // exactly what is free can be taken
        let arguments = json!({"volume": "small/data", "add_gb": 1, "dry_run": true});
        ok_text(run(&fixture, "adam", arguments).await);
    }

    #[tokio::test]
    async fn a_dry_run_tests_directly_and_changes_nothing() {
        let fixture = fixture();
        let arguments = json!({"volume": "vg0/data", "add_gb": 5, "dry_run": true});
        let text = ok_text(run(&fixture, "adam", arguments).await);
        assert_eq!(
            fixture.fake.calls("lvextend"),
            vec![strings(&[
                "--test",
                "--resizefs",
                "--size",
                "+5G",
                "--",
                "vg0/data"
            ])]
        );
        assert_eq!(fixture.fake.calls("systemd-run"), Calls::new());
        // what the volume and the group look like now
        assert!(text.contains("100.0 GiB"), "{text}");
        assert!(text.contains("50.0 GiB"), "{text}");
        assert!(text.contains("TEST MODE"), "{text}");
        assert!(text.contains("Dry run"), "{text}");
        assert!(text.contains("nothing was changed"), "{text}");
        // how the volume and the group were looked up
        assert_eq!(
            fixture.fake.calls("lvs"),
            vec![strings(&[
                "--noheadings",
                "--nosuffix",
                "--units",
                "b",
                "--separator",
                "|",
                "-o",
                "vg_name,lv_name,lv_size,lv_attr",
                "--",
                "vg0/data"
            ])]
        );
        assert_eq!(
            fixture.fake.calls("vgs"),
            vec![strings(&[
                "--noheadings",
                "--nosuffix",
                "--units",
                "b",
                "-o",
                "vg_free",
                "--",
                "vg0"
            ])]
        );
    }

    #[tokio::test]
    async fn a_real_run_is_its_own_systemd_unit_and_reports_the_new_sizes() {
        let fixture = fixture();
        let text = ok_text(run(&fixture, "adam", json!({"volume": "vg0/data", "add_gb": 5})).await);

        let started = fixture.fake.calls("systemd-run");
        assert_eq!(started.len(), 1);
        let unit = started[0][0].strip_prefix("--unit=").unwrap().to_string();
        let (stamp, random) = unit
            .strip_prefix("opsmcp-lvm-")
            .unwrap()
            .split_once('-')
            .unwrap();
        assert!(stamp.parse::<u64>().unwrap() > 1_700_000_000, "{unit}");
        assert_eq!(random.len(), 4, "{unit}");
        assert!(
            started[0][1].starts_with("--description=opsmcp"),
            "{started:?}"
        );
        assert!(started[0][1].contains("adam"), "{started:?}");
        assert_eq!(
            started[0][2..],
            strings(&[
                "--collect",
                "--wait",
                "--quiet",
                "--no-ask-password",
                "--",
                &path_of(&fixture.fake, "lvextend"),
                "--resizefs",
                "--size",
                "+5G",
                "--",
                "vg0/data"
            ])
        );
        // no --pipe: the unit must not depend on this call staying around
        assert!(!started[0].iter().any(|arg| arg == "--pipe"), "{started:?}");
        // the run itself was not a test
        assert_eq!(
            fixture.fake.calls("lvextend"),
            vec![strings(&["--resizefs", "--size", "+5G", "--", "vg0/data"])]
        );
        // its output is read back from the journal, for that unit
        let journal = fixture.fake.calls("journalctl");
        assert!(
            journal[0].contains(&format!("--unit={unit}.service")),
            "{journal:?}"
        );
        assert!(
            text.contains("changed from 100.00 GiB to 105.00 GiB"),
            "{text}"
        );
        // before and after
        assert!(text.contains("100.0 GiB"), "{text}");
        assert!(text.contains("105.0 GiB"), "{text}");
        assert!(text.contains(&unit), "{text}");
        // the filesystem on it, where it is mounted
        let mounted = format!("mounted at {}", fixture.dir.path().display());
        assert!(text.contains(&mounted), "{text}");
        // what lasts
        assert!(text.contains("permanent"), "{text}");
    }

    #[tokio::test]
    async fn without_systemd_run_a_real_run_is_refused_and_a_dry_run_still_works() {
        let fixture = fixture_from(lvm, CONFIG, "");
        let result = run(&fixture, "adam", json!({"volume": "vg0/data", "add_gb": 5})).await;
        match result {
            Err(ToolError::Failed(message)) => {
                assert!(message.contains("systemd-run"), "{message}");
                assert!(message.contains("Nothing was changed"), "{message}");
            }
            other => panic!("expected a failure, got {other:?}"),
        }
        assert_eq!(fixture.fake.calls("lvextend"), Calls::new());
        let arguments = json!({"volume": "vg0/data", "add_gb": 5, "dry_run": true});
        let text = ok_text(run(&fixture, "adam", arguments).await);
        assert!(text.contains("Dry run"), "{text}");
    }

    #[tokio::test]
    async fn a_failed_run_is_reported_as_failed_with_what_lvm_said() {
        let fixture = fixture_from(
            |dir| {
                lvm(dir)
                    .add_script("systemd-run", SYSTEMD_RUN)
                    .add(
                        "journalctl",
                        "  fsadm: Cannot get FSTYPE of \"/dev/mapper/vg0-broken\".\n",
                        0,
                    )
                    .add("systemctl", "failed\n", 3)
            },
            CONFIG,
            "",
        );
        let output = run(
            &fixture,
            "adam",
            json!({"volume": "vg0/broken", "add_gb": 5}),
        )
        .await
        .unwrap();
        assert!(output.is_error(), "{output:?}");
        assert!(output.text().contains("Cannot get FSTYPE"), "{output:?}");
        assert!(output.text().contains("FAILED"), "{output:?}");
        // the size is looked at again all the same: lvextend may have grown the volume
        // before the filesystem step failed
        assert_eq!(fixture.fake.calls("lvs").len(), 2);
    }

    #[tokio::test]
    async fn a_run_that_outlasts_the_call_is_left_running_and_named() {
        let fixture = fixture_from(
            |dir| {
                lvm(dir)
                    // a systemd-run that never comes back (a busy loop: stand-ins have
                    // only shell built-ins)
                    .add_script("systemd-run", "while :; do :; done")
                    .add("journalctl", "", 0)
                    .add("systemctl", "active\n", 0)
            },
            CONFIG,
            "[limits]\ncommand_timeout_secs = 1\ncall_timeout_secs = 16\n",
        );
        let text = ok_text(run(&fixture, "adam", json!({"volume": "vg0/data", "add_gb": 5})).await);
        let unit = fixture.fake.calls("systemd-run")[0][0]
            .strip_prefix("--unit=")
            .unwrap()
            .to_string();
        assert!(text.contains(&format!("{unit}.service")), "{text}");
        assert!(text.contains("still running"), "{text}");
        assert!(text.contains("not interrupted"), "{text}");
        assert!(text.contains("journal_query"), "{text}");
    }

    /// A stand-in systemd-run that runs the command, as systemd would, and then does not
    /// come back: the wait for the unit outlasts the call.
    const SYSTEMD_RUN_THEN_HANG: &str = r#"
while [ $# -gt 0 ]; do
  case "$1" in
    --) shift; break ;;
  esac
  shift
done
"$@"
while :; do :; done
"#;

    const SHORT_CALL: &str = "[limits]\ncommand_timeout_secs = 1\ncall_timeout_secs = 16\n";

    /// AIDEV-NOTE: when the wait ends at the same moment as the unit, systemd has
    /// already forgotten the unit (`--collect`) and its result cannot be asked for. The
    /// volume's size can: a volume that grew by what was asked for was grown.
    #[tokio::test]
    async fn a_run_whose_end_was_not_seen_is_a_success_when_the_volume_grew() {
        let fixture = fixture_from(
            |dir| {
                lvm(dir)
                    .add_script("systemd-run", SYSTEMD_RUN_THEN_HANG)
                    .add(
                        "journalctl",
                        "  Size of logical volume vg0/data changed from 100.00 GiB to 105.00 GiB.\n",
                        0,
                    )
                    // the unit is gone: neither running nor known to have failed
                    .add("systemctl", "inactive\n", 3)
            },
            CONFIG,
            SHORT_CALL,
        );
        let text = ok_text(run(&fixture, "adam", json!({"volume": "vg0/data", "add_gb": 5})).await);
        let first = text.lines().next().unwrap();
        assert!(first.starts_with("vg0/data was grown by 5 GiB"), "{text}");
        assert!(
            first.contains("100.0 GiB") && first.contains("105.0 GiB"),
            "{text}"
        );
        // what is not known is said, with how to find out
        assert!(text.contains("was not seen"), "{text}");
        assert!(text.contains("disk_usage"), "{text}");
        assert!(text.contains("journal_query"), "{text}");
        // what the run wrote is still shown
        assert!(
            text.contains("changed from 100.00 GiB to 105.00 GiB"),
            "{text}"
        );
        assert!(text.contains("permanent"), "{text}");
    }

    #[tokio::test]
    async fn a_run_whose_end_was_not_seen_is_a_failure_when_the_volume_did_not_grow() {
        let fixture = fixture_from(
            |dir| {
                lvm(dir)
                    // never runs lvextend, never comes back
                    .add_script("systemd-run", "while :; do :; done")
                    .add("journalctl", "", 0)
                    .add("systemctl", "inactive\n", 3)
            },
            CONFIG,
            SHORT_CALL,
        );
        let output = run(&fixture, "adam", json!({"volume": "vg0/data", "add_gb": 5}))
            .await
            .unwrap();
        assert!(output.is_error(), "{output:?}");
        let text = output.text();
        assert!(!text.contains("was grown by"), "{text}");
        assert!(text.contains("was not seen"), "{text}");
        assert!(text.contains("vg0/data is still 100.0 GiB"), "{text}");
    }

    #[tokio::test]
    async fn a_unit_known_to_have_failed_is_a_failure_even_if_the_volume_grew() {
        let fixture = fixture_from(
            |dir| {
                lvm(dir)
                    .add_script("systemd-run", SYSTEMD_RUN_THEN_HANG)
                    .add("journalctl", "  resize2fs: Device or resource busy\n", 0)
                    .add("systemctl", "failed\n", 3)
            },
            CONFIG,
            SHORT_CALL,
        );
        let output = run(&fixture, "adam", json!({"volume": "vg0/data", "add_gb": 5}))
            .await
            .unwrap();
        assert!(output.is_error(), "{output:?}");
        let text = output.text();
        assert!(text.contains("FAILED"), "{text}");
        // the volume itself did grow, and that is said
        assert!(text.contains("grown all the same"), "{text}");
        assert!(text.contains("105.0 GiB"), "{text}");
    }

    #[tokio::test]
    async fn missing_lvm_tools_are_named_with_their_package() {
        let fixture = fixture_from(|_| FakeBins::new(), CONFIG, "");
        let arguments = json!({"volume": "vg0/data", "add_gb": 5, "dry_run": true});
        let result = run(&fixture, "adam", arguments).await;
        match result {
            Err(ToolError::Failed(message)) => {
                assert!(message.contains("lvm2"), "{message}");
            }
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[test]
    fn the_tool_is_a_write_tool() {
        let tool = find(tools(), "lvm_extend");
        assert_eq!(tool.access, Access::Write);
        assert_eq!(tool.permission, "storage.extend");
    }
}
