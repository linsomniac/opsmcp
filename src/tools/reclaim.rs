//! Freeing disk space with fixed, safe actions.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};

use super::args::{Args, Param};
use super::package::{Family, dnf_name, family};
use super::storage::{WalkOpts, walk};
use super::{
    Authorized, Ctx, Tool, ToolError, ToolResult, blocking, command_ok, command_text_tail,
    format_table, one_line_cell, required,
};
use crate::config::RECLAIM_ACTIONS;
use crate::policy::Access;
use crate::timefmt::{human_bytes, now_secs};

/// Where the things this tool frees live. Tests point these at temporary directories.
#[derive(Clone, Debug)]
pub struct Env {
    /// Where the journal is kept: the first that exists is the filesystem measured.
    pub journal_dirs: Vec<PathBuf>,
    /// The package files apt has downloaded.
    pub apt_cache: PathBuf,
    /// The same for dnf and yum.
    pub rpm_caches: Vec<PathBuf>,
    /// Where docker and podman keep images.
    pub container_dirs: Vec<PathBuf>,
    /// The directories core dumps and crash reports are written to.
    pub core_dirs: Vec<PathBuf>,
    /// The directories systemd-tmpfiles cleans by default.
    pub tmp_dirs: Vec<PathBuf>,
}

impl Default for Env {
    fn default() -> Self {
        let paths = |list: &[&str]| list.iter().map(PathBuf::from).collect();
        Env {
            journal_dirs: paths(&["/var/log/journal", "/run/log/journal"]),
            apt_cache: PathBuf::from("/var/cache/apt/archives"),
            rpm_caches: paths(&["/var/cache/dnf", "/var/cache/libdnf5", "/var/cache/yum"]),
            container_dirs: paths(&["/var/lib/docker", "/var/lib/containers"]),
            core_dirs: paths(&["/var/lib/systemd/coredump", "/var/crash"]),
            tmp_dirs: paths(&["/tmp", "/var/tmp"]),
        }
    }
}

pub fn tools() -> Vec<Tool> {
    vec![Tool::new(
        "space_reclaim",
        "Free disk space with one of a few fixed, safe actions: journal (cut the systemd \
         journal down to keep_mb), package_cache (delete downloaded package files: apt-get \
         clean, dnf clean packages), container_images (remove untagged images, and with \
         all_unused also images no container uses), core_dumps (delete core dumps and \
         crash reports older than min_age_days), tmpfiles (systemd-tmpfiles --clean: this \
         host's own rules for /tmp and the like). Which actions are allowed is set in \
         this host's configuration. Nothing else is ever deleted. Use dry_run to see \
         what an action would free; disk_usage and disk_hogs show where the space went.",
        Access::Write,
        "storage.reclaim",
        vec![
            Param::choice("action", "What to free", &RECLAIM_ACTIONS).required(),
            Param::bool(
                "dry_run",
                "Show what would be freed without removing anything (tmpfiles has no dry run)",
            ),
            Param::int(
                "keep_mb",
                "journal: how much of the journal to keep, in MiB (default 500)",
                50,
                100_000,
            ),
            Param::int(
                "min_age_days",
                "core_dumps, and container_images with all_unused: only what is at least \
                 this many days old (default 7)",
                1,
                365,
            ),
            Param::bool(
                "all_unused",
                "container_images: also remove images that no container uses, not only \
                 untagged ones",
            ),
        ],
        |ctx, args| space_reclaim_at(ctx, args, Env::default()),
    )]
}

/// What one action is asked to do.
#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    pub action: String,
    pub dry_run: bool,
    pub keep_mb: u64,
    pub min_age_days: u64,
    pub all_unused: bool,
}

/// Reads the arguments, refusing a parameter that does not belong to the action: an
/// agent that passes `keep_mb` to another action expects something that will not happen.
pub fn request(args: &Args) -> Result<Request, ToolError> {
    let action = required(args, "action")?.to_string();
    let belongs: &[&str] = match action.as_str() {
        "journal" => &["keep_mb"],
        "core_dumps" => &["min_age_days"],
        "container_images" => &["all_unused", "min_age_days"],
        _ => &[],
    };
    let given = [
        ("keep_mb", args.int("keep_mb").is_some()),
        ("min_age_days", args.int("min_age_days").is_some()),
        ("all_unused", args.bool("all_unused").is_some()),
    ];
    for (name, given) in given {
        if given && !belongs.contains(&name) {
            return Err(ToolError::Invalid(format!(
                "{name} does not apply to the {action} action"
            )));
        }
    }
    let all_unused = args.bool("all_unused") == Some(true);
    if action == "container_images" && args.int("min_age_days").is_some() && !all_unused {
        return Err(ToolError::Invalid(
            "min_age_days only narrows what all_unused adds: pass all_unused as well, or \
             leave min_age_days out"
                .to_string(),
        ));
    }
    let number = |name: &str, default: u64| {
        args.int(name)
            .and_then(|n| u64::try_from(n).ok())
            .unwrap_or(default)
    };
    Ok(Request {
        action,
        dry_run: args.bool("dry_run") == Some(true),
        keep_mb: number("keep_mb", 500),
        min_age_days: number("min_age_days", 7),
        all_unused,
    })
}

/// The arguments for `docker` or `podman` to remove unused images.
///
/// AIDEV-NOTE: without `--all` only untagged ("dangling") images go: layers nothing
/// refers to by name. `--all` adds every image no container uses, which is what frees
/// real space and also what removes the image someone meant to roll back to, so it is
/// only added when asked for and then only for images older than `min_age_days`.
pub fn prune_argv(all_unused: bool, min_age_days: u64) -> Vec<String> {
    let mut argv = vec![
        "image".to_string(),
        "prune".to_string(),
        "--force".to_string(),
    ];
    if all_unused {
        argv.extend([
            "--all".to_string(),
            "--filter".to_string(),
            format!("until={}h", min_age_days.saturating_mul(24)),
        ]);
    }
    argv
}

/// One file that is, or would be, removed.
#[derive(Debug, PartialEq, Eq)]
pub struct Swept {
    pub name: String,
    pub bytes: u64,
    pub age_days: u64,
}

/// What became of one crash directory.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Sweep {
    /// Why nothing was done there, if nothing was.
    pub skipped: Option<String>,
    /// The files old enough to go, largest first.
    pub old: Vec<Swept>,
    /// How many of them could not be removed.
    pub failed: usize,
    /// More entries than are looked at in one run.
    pub cut_short: bool,
    /// Sub-directories, which are left alone.
    pub directories: usize,
}

/// Entries of one crash directory looked at in one run.
const MAX_SWEPT_ENTRIES: usize = 100_000;

/// Removes (or with `dry_run` only lists) the regular files directly inside `dir`
/// whose last change is at least `min_age_days` old.
///
/// AIDEV-NOTE: the server is usually root, and /var/crash is a directory every user may
/// write to. So the directory is opened without following a link, and everything after
/// that goes through that one descriptor: each entry is examined with `statat` without
/// following links and removed with `unlinkat`, which removes a name in THIS directory
/// and nothing else. No path is ever built and resolved again, nothing below a
/// sub-directory is touched, and only regular files are removed. If a user swaps an
/// entry between the look and the removal, the worst that happens is that another
/// non-directory of the same name in the same crash directory is removed. Names
/// starting with a dot are left alone (apport keeps its lock file there).
pub fn sweep(dir: &Path, min_age_days: u64, now: i64, dry_run: bool) -> Sweep {
    let skipped = |why: String| Sweep {
        skipped: Some(why),
        ..Sweep::default()
    };
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let fd = match rustix::fs::open(dir, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(e) => {
            // Only to say why: nothing is done on the strength of this second look.
            return skipped(match std::fs::symlink_metadata(dir) {
                Err(_) => "does not exist".to_string(),
                Ok(meta) if meta.file_type().is_symlink() => {
                    "is a symbolic link, which is not followed: nothing was done there".to_string()
                }
                Ok(meta) if !meta.is_dir() => "is not a directory".to_string(),
                Ok(_) => format!("cannot be opened: {}", std::io::Error::from(e)),
            });
        }
    };
    let entries = match Dir::read_from(&fd) {
        Ok(entries) => entries,
        Err(e) => return skipped(format!("cannot be read: {}", std::io::Error::from(e))),
    };
    let min_age_secs = i64::try_from(min_age_days.saturating_mul(86_400)).unwrap_or(i64::MAX);
    let mut found = Sweep::default();
    for (seen, entry) in entries.flatten().enumerate() {
        if seen >= MAX_SWEPT_ENTRIES {
            found.cut_short = true;
            break;
        }
        let name = entry.file_name();
        if name.to_bytes().starts_with(b".") {
            continue;
        }
        let Ok(stat) = rustix::fs::statat(&fd, name, AtFlags::SYMLINK_NOFOLLOW) else {
            continue; // gone since it was listed
        };
        let kind = FileType::from_raw_mode(stat.st_mode);
        if kind == FileType::Directory {
            found.directories += 1;
        }
        if kind != FileType::RegularFile {
            continue;
        }
        // The fields of `Stat` have different integer types on different architectures.
        #[allow(clippy::unnecessary_cast)]
        let (changed, bytes) = (
            stat.st_mtime as i64,
            (stat.st_blocks as u64).saturating_mul(512),
        );
        let age = now.saturating_sub(changed);
        if age < min_age_secs {
            continue;
        }
        if !dry_run && rustix::fs::unlinkat(&fd, name, AtFlags::empty()).is_err() {
            found.failed += 1;
            continue;
        }
        found.old.push(Swept {
            name: name.to_string_lossy().into_owned(),
            bytes,
            age_days: u64::try_from(age / 86_400).unwrap_or(0),
        });
    }
    found
        .old
        .sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.name.cmp(&b.name)));
    found
}

/// The free space of the filesystems that hold `dirs`: one figure for each filesystem,
/// named by the first of the directories found on it. Directories that do not exist are
/// skipped; with `first_only` the first that exists is the only one looked at.
fn free_space(dirs: &[PathBuf], first_only: bool) -> Vec<(String, u64)> {
    use std::os::unix::fs::MetadataExt;
    let mut seen = Vec::new();
    let mut found = Vec::new();
    for dir in dirs {
        let Ok(meta) = std::fs::metadata(dir) else {
            continue;
        };
        if !meta.is_dir() {
            continue;
        }
        if !seen.contains(&meta.dev())
            && let Ok(vfs) = rustix::fs::statvfs(dir)
        {
            seen.push(meta.dev());
            found.push((
                dir.display().to_string(),
                vfs.f_bavail.saturating_mul(vfs.f_frsize),
            ));
        }
        if first_only {
            break;
        }
    }
    found
}

/// `free_space`, off the async threads. A server too busy to look says nothing.
async fn measure(ctx: &Ctx, dirs: &[PathBuf], first_only: bool) -> Vec<(String, u64)> {
    let dirs = dirs.to_vec();
    blocking(ctx.clone(), move || Ok(free_space(&dirs, first_only)))
        .await
        .unwrap_or_default()
}

/// One line for each filesystem measured before and after: how its free space changed.
///
/// AIDEV-NOTE: this is the change in free space over the run, not what the command
/// removed: logs are written meanwhile (the journal itself, for one), so a real
/// clean-up can leave less free than before. It is worded as a change, with that said,
/// and never as "nothing was freed". Where a command reports what it removed
/// (`vacuum_freed`), that figure is given as well, and is the one to go by.
fn freed_text(before: &[(String, u64)], after: &[(String, u64)]) -> String {
    let mut text = String::new();
    for (dir, was) in before {
        let Some((_, now)) = after.iter().find(|(other, _)| other == dir) else {
            continue;
        };
        let change = match now.cmp(was) {
            std::cmp::Ordering::Greater => format!(
                "{} more; other writes during the run are included",
                human_bytes(now.saturating_sub(*was))
            ),
            std::cmp::Ordering::Equal => "unchanged; other writes during the run are \
                                          included, so this does not show what was removed"
                .to_string(),
            std::cmp::Ordering::Less => format!(
                "{} less: other writes during the run outweighed what was removed",
                human_bytes(was.saturating_sub(*now))
            ),
        };
        text.push_str(&format!(
            "Free space on the filesystem holding {}: {} before, {} now ({change}).\n",
            one_line_cell(dir),
            human_bytes(*was),
            human_bytes(*now)
        ));
    }
    text
}

/// What `journalctl --vacuum-size` says it freed: the figure of each of its lines
/// `Vacuuming done, freed 1.2G of archived journals from DIR.` (one per journal
/// directory).
///
/// AIDEV-NOTE: the figure is repeated in a line of the tool's own, so only a plain size
/// (digits, a dot, a unit letter) is taken over.
pub fn vacuum_freed(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            let (_, rest) = line.split_once("Vacuuming done, freed ")?;
            let (figure, _) = rest.split_once(" of archived journals")?;
            let plain = !figure.is_empty()
                && figure.len() <= 12
                && figure.starts_with(|c: char| c.is_ascii_digit())
                && figure
                    .chars()
                    .all(|c| c.is_ascii_digit() || c == '.' || "BKMGTPE".contains(c));
            plain.then(|| figure.to_string())
        })
        .collect()
}

/// How long a command of this tool may run: what is left of the call, with some kept
/// back for the answer. Cutting one of these commands short does no harm (what it has
/// removed is removed, the rest is still there), so they may use the time the call has.
fn time_left(ctx: &Ctx, started: Instant) -> Duration {
    let left = ctx
        .cfg()
        .limits
        .call_timeout_secs
        .saturating_sub(10)
        .saturating_sub(started.elapsed().as_secs())
        .max(2);
    Duration::from_secs(left)
}

/// Runs one command and adds what it was and what it said to `text`. Returns whether
/// it succeeded.
async fn step(
    ctx: &Ctx,
    started: Instant,
    name: &str,
    argv: Vec<String>,
    text: &mut String,
) -> Result<bool, ToolError> {
    let cmd = ctx.command(name)?.timeout(time_left(ctx, started));
    text.push_str(&format!("== {name} {} ==\n", argv.join(" ")));
    let out = ctx.run(cmd.args(argv)).await?;
    let room = ctx.output_budget().saturating_sub(text.len() + 1024);
    text.push_str(&command_text_tail(&out, room));
    Ok(command_ok(&out))
}

const GONE: &str = "Done. What was removed is gone for good.\n";

/// The closing line of a real run.
fn closing(succeeded: bool) -> &'static str {
    if succeeded {
        GONE
    } else {
        "FAILED: see above. What was removed before the failure is gone for good.\n"
    }
}

async fn journal(ctx: &Ctx, auth: Authorized, env: &Env, asked: &Request) -> ToolResult {
    let started = Instant::now();
    // Asked for first: without journalctl there is nothing to do, dry run or not.
    ctx.command("journalctl")?;
    let mut text = String::new();
    if asked.dry_run {
        let argv = vec!["--disk-usage".to_string()];
        let succeeded = step(ctx, started, "journalctl", argv, &mut text).await?;
        text.push_str(&format!(
            "Dry run: nothing was removed. A real run cuts the archived journal files down \
             to about {} MiB; the files still being written are never removed. What is \
             cut is gone for good, including any opsmcp audit records stored only in the \
             journal.\n",
            asked.keep_mb
        ));
        return auth.done(text, succeeded);
    }
    let before = measure(ctx, &env.journal_dirs, true).await;
    let argv = vec![format!("--vacuum-size={}M", asked.keep_mb)];
    let said_from = text.len();
    let succeeded = step(ctx, started, "journalctl", argv, &mut text).await?;
    let after = measure(ctx, &env.journal_dirs, true).await;
    // journalctl's own count comes first: it is what was removed. The change in free
    // space below includes whatever else was written meanwhile.
    let figures = vacuum_freed(text.get(said_from..).unwrap_or(""));
    if !figures.is_empty() {
        text.push_str(&format!(
            "journalctl reports that it freed {} of archived journal files.\n",
            figures.join(" and ")
        ));
    }
    text.push_str(&freed_text(&before, &after));
    // AIDEV-NOTE: the journal is also where syslog messages end up on most hosts, and
    // opsmcp's audit records are sent to syslog (audit.syslog). A caller granted this
    // action can therefore shorten the audit trail's history if the journal is its
    // only store; `keep_mb` has a floor, and the result says so. Operators who grant
    // storage.reclaim:journal should keep the audit trail somewhere else as well
    // (audit.file, or a remote syslog).
    text.push_str(
        "Journal entries older than what was kept are gone, and with them any opsmcp \
         audit records that were stored only in the journal.\n",
    );
    text.push_str(closing(succeeded));
    auth.done(text, succeeded)
}

/// The disk space used under `dir`, and whether the count had to stop early. `None`
/// when it is not a directory that can be opened.
fn cache_size(dir: &Path) -> Option<(u64, bool)> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let fd = rustix::fs::open(dir, flags, Mode::empty()).ok()?;
    let opts = WalkOpts {
        depth: 0,
        limit: 1,
        min_file_bytes: u64::MAX,
        deadline: Instant::now() + Duration::from_secs(5),
    };
    let usage = walk(fd, &dir.display().to_string(), &opts, &|_, _| false).ok()?;
    Some((usage.total, usage.partial))
}

async fn package_cache(ctx: &Ctx, auth: Authorized, env: &Env, asked: &Request) -> ToolResult {
    let started = Instant::now();
    let family = family(ctx)?;
    let (program, argv, dirs): (&str, &[&str], Vec<PathBuf>) = match family {
        Family::Apt => ("apt-get", &["clean"], vec![env.apt_cache.clone()]),
        Family::Rpm => (
            dnf_name(ctx)?,
            &["clean", "packages"],
            env.rpm_caches.clone(),
        ),
    };
    let mut text = String::new();
    if asked.dry_run {
        let listed = dirs.clone();
        let sizes = blocking(ctx.clone(), move || {
            Ok(listed
                .iter()
                .map(|dir| (dir.display().to_string(), cache_size(dir)))
                .collect::<Vec<_>>())
        })
        .await?;
        for (dir, size) in sizes {
            let dir = one_line_cell(&dir);
            match size {
                Some((bytes, false)) => text.push_str(&format!(
                    "The package cache at {dir} holds {}.\n",
                    human_bytes(bytes)
                )),
                Some((bytes, true)) => text.push_str(&format!(
                    "The package cache at {dir} holds at least {} (counting it was cut short).\n",
                    human_bytes(bytes)
                )),
                None => text.push_str(&format!("There is no package cache at {dir}.\n")),
            }
        }
        text.push_str(&format!(
            "Dry run: nothing was removed. A real run deletes the downloaded package files \
             with `{program} {}`; installed packages are not touched.\n",
            argv.join(" ")
        ));
        if family == Family::Rpm {
            text.push_str(
                "The directory also holds repository metadata, which is kept: less than \
                 the whole of it is freed.\n",
            );
        }
        return auth.ok(text);
    }
    let before = measure(ctx, &dirs, false).await;
    let argv = argv.iter().map(|arg| arg.to_string()).collect();
    let succeeded = step(ctx, started, program, argv, &mut text).await?;
    let after = measure(ctx, &dirs, false).await;
    text.push_str(&freed_text(&before, &after));
    text.push_str(closing(succeeded));
    auth.done(text, succeeded)
}

const RUNTIMES: [&str; 2] = ["podman", "docker"];

async fn container_images(ctx: &Ctx, auth: Authorized, env: &Env, asked: &Request) -> ToolResult {
    let started = Instant::now();
    let mut runtimes = Vec::new();
    for name in RUNTIMES {
        if ctx.optional_command(name)?.is_some() {
            runtimes.push(name);
        }
    }
    if runtimes.is_empty() {
        return Err(ToolError::Failed(
            "neither podman nor docker is installed on this host".to_string(),
        ));
    }
    let mut text = String::new();
    let mut succeeded = true;
    if asked.dry_run {
        for name in runtimes {
            let argv = ["images", "--filter", "dangling=true"]
                .map(String::from)
                .to_vec();
            succeeded &= step(ctx, started, name, argv, &mut text).await?;
        }
        text.push_str(
            "Dry run: nothing was removed. This lists untagged images only, which is what a \
             run removes.",
        );
        text.push_str(if asked.all_unused {
            " What all_unused would remove as well (images that no container uses) cannot \
             be listed beforehand.\n"
        } else {
            "\n"
        });
        return auth.done(text, succeeded);
    }
    let before = measure(ctx, &env.container_dirs, false).await;
    for name in runtimes {
        let argv = prune_argv(asked.all_unused, asked.min_age_days);
        succeeded &= step(ctx, started, name, argv, &mut text).await?;
    }
    let after = measure(ctx, &env.container_dirs, false).await;
    text.push_str(&freed_text(&before, &after));
    text.push_str(closing(succeeded));
    auth.done(text, succeeded)
}

/// Files of one crash directory shown in the answer.
const SHOWN_PER_DIR: usize = 30;

async fn core_dumps(ctx: &Ctx, auth: Authorized, env: &Env, asked: &Request) -> ToolResult {
    let dry_run = asked.dry_run;
    let min_age_days = asked.min_age_days;
    let before = if dry_run {
        Vec::new()
    } else {
        measure(ctx, &env.core_dirs, false).await
    };
    let dirs = env.core_dirs.clone();
    let swept = blocking(ctx.clone(), move || {
        let now = now_secs();
        Ok(dirs
            .iter()
            .map(|dir| {
                (
                    dir.display().to_string(),
                    sweep(dir, min_age_days, now, dry_run),
                )
            })
            .collect::<Vec<_>>())
    })
    .await?;

    let mut text = format!("== core dumps and crash reports at least {min_age_days} days old ==\n");
    let (mut files, mut bytes, mut failed) = (0usize, 0u64, 0usize);
    for (dir, found) in &swept {
        let dir = one_line_cell(dir);
        if let Some(why) = &found.skipped {
            text.push_str(&format!("{dir}: {why}\n"));
            continue;
        }
        let total: u64 = found.old.iter().map(|file| file.bytes).sum();
        files += found.old.len();
        bytes = bytes.saturating_add(total);
        failed += found.failed;
        if found.old.is_empty() {
            text.push_str(&format!("{dir}: nothing that old\n"));
        } else {
            text.push_str(&format!(
                "{dir}: {} {}, {}\n",
                if dry_run { "would remove" } else { "removed" },
                counted_files(found.old.len()),
                human_bytes(total)
            ));
            let rows: Vec<Vec<String>> = found
                .old
                .iter()
                .take(SHOWN_PER_DIR)
                .map(|file| {
                    vec![
                        format!("  {}", human_bytes(file.bytes)),
                        format!("{}d", file.age_days),
                        file.name.clone(),
                    ]
                })
                .collect();
            text.push_str(&format_table(
                &["  SIZE", "AGE", "FILE"],
                &rows,
                &[true, true, false],
            ));
            if found.old.len() > SHOWN_PER_DIR {
                text.push_str(&format!(
                    "  [{} smaller files not listed]\n",
                    found.old.len() - SHOWN_PER_DIR
                ));
            }
        }
        if found.failed > 0 {
            text.push_str(&format!(
                "  [{} could not be removed]\n",
                counted_files(found.failed)
            ));
        }
        if found.cut_short {
            text.push_str(&format!(
                "  [only the first {MAX_SWEPT_ENTRIES} entries were looked at; run it again for the rest]\n"
            ));
        }
        // Kernel crash dumps (kdump) are kept in sub-directories of /var/crash.
        match found.directories {
            0 => {}
            1 => text.push_str(
                "  [1 sub-directory was left alone: only files directly inside are removed]\n",
            ),
            many => text.push_str(&format!(
                "  [{many} sub-directories were left alone: only files directly inside are removed]\n"
            )),
        }
    }
    if dry_run {
        text.push_str(&format!(
            "Dry run: {}, {} in all, would be removed; nothing was removed.\n",
            counted_files(files),
            human_bytes(bytes)
        ));
        return auth.ok(text);
    }
    let after = measure(ctx, &env.core_dirs, false).await;
    text.push_str(&format!(
        "Removed {}, {} in all.\n",
        counted_files(files),
        human_bytes(bytes)
    ));
    text.push_str(&freed_text(&before, &after));
    text.push_str(closing(failed == 0));
    auth.done(text, failed == 0)
}

fn counted_files(count: usize) -> String {
    format!("{count} {}", if count == 1 { "file" } else { "files" })
}

async fn tmpfiles(ctx: &Ctx, auth: Authorized, env: &Env, asked: &Request) -> ToolResult {
    let started = Instant::now();
    if asked.dry_run {
        return auth.ok(
            "systemd-tmpfiles has no dry run, so nothing was done. A real run removes what \
             this host's own tmpfiles.d rules call old enough, in /tmp, /var/tmp and the \
             other places those rules name.\n",
        );
    }
    ctx.command("systemd-tmpfiles")?;
    let before = measure(ctx, &env.tmp_dirs, false).await;
    let mut text = String::new();
    let argv = vec!["--clean".to_string()];
    let succeeded = step(ctx, started, "systemd-tmpfiles", argv, &mut text).await?;
    let after = measure(ctx, &env.tmp_dirs, false).await;
    text.push_str(&freed_text(&before, &after));
    text.push_str(closing(succeeded));
    auth.done(text, succeeded)
}

pub async fn space_reclaim_at(ctx: Ctx, args: Args, env: Env) -> ToolResult {
    let asked = request(&args)?;
    let action = asked.action.as_str();
    // Host-wide limit first, whatever the caller has been granted.
    if !ctx
        .cfg()
        .storage
        .reclaim
        .iter()
        .any(|allowed| allowed == action)
    {
        let reason = format!(
            "the {action} action is not among those that storage.reclaim allows on this host"
        );
        return Err(ctx.deny(Some(action), &reason));
    }
    let auth = ctx.authorize(Some(action))?;
    // AIDEV-NOTE: every action is a fixed command, or the sweep of two fixed
    // directories. Nothing from the caller reaches a command line except two checked
    // integers. Each is boxed so that this tool's future stays small.
    match action {
        "journal" => Box::pin(journal(&ctx, auth, &env, &asked)).await,
        "package_cache" => Box::pin(package_cache(&ctx, auth, &env, &asked)).await,
        "container_images" => Box::pin(container_images(&ctx, auth, &env, &asked)).await,
        "core_dumps" => Box::pin(core_dumps(&ctx, auth, &env, &asked)).await,
        "tmpfiles" => Box::pin(tmpfiles(&ctx, auth, &env, &asked)).await,
        other => Err(ToolError::Invalid(format!("{other:?} is not an action"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::Host;
    use crate::tools::testing::{self, FakeBins, find, host, ok_text};
    use serde_json::{Value, json};
    use std::sync::Arc;
    use std::time::SystemTime;

    type Calls = Vec<Vec<String>>;

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn parsed(arguments: Value) -> Result<Request, ToolError> {
        let tool = find(tools(), "space_reclaim");
        let args = Args::parse(&tool.params, Some(&arguments)).map_err(ToolError::Invalid)?;
        request(&args)
    }

    #[test]
    fn request_fills_in_the_defaults() {
        assert_eq!(
            parsed(json!({"action": "journal"})).unwrap(),
            Request {
                action: "journal".to_string(),
                dry_run: false,
                keep_mb: 500,
                min_age_days: 7,
                all_unused: false,
            }
        );
        let asked = parsed(json!({"action": "journal", "keep_mb": 200, "dry_run": true})).unwrap();
        assert_eq!((asked.keep_mb, asked.dry_run), (200, true));
        let asked = parsed(json!({"action": "core_dumps", "min_age_days": 30})).unwrap();
        assert_eq!(asked.min_age_days, 30);
        let asked =
            parsed(json!({"action": "container_images", "all_unused": true, "min_age_days": 3}))
                .unwrap();
        assert_eq!((asked.all_unused, asked.min_age_days), (true, 3));
    }

    #[test]
    fn request_refuses_a_parameter_that_does_not_belong_to_the_action() {
        for arguments in [
            json!({}),
            json!({"action": "everything"}),
            json!({"action": "journal", "keep_mb": 10}),
            json!({"action": "journal", "keep_mb": 100001}),
            json!({"action": "journal", "min_age_days": 3}),
            json!({"action": "journal", "all_unused": true}),
            json!({"action": "package_cache", "keep_mb": 100}),
            json!({"action": "package_cache", "min_age_days": 3}),
            json!({"action": "core_dumps", "keep_mb": 100}),
            json!({"action": "core_dumps", "all_unused": true}),
            json!({"action": "core_dumps", "min_age_days": 0}),
            json!({"action": "tmpfiles", "min_age_days": 3}),
            json!({"action": "tmpfiles", "keep_mb": 100}),
            json!({"action": "container_images", "keep_mb": 100}),
            // an age only narrows what all_unused adds
            json!({"action": "container_images", "min_age_days": 3}),
            json!({"action": "journal", "path": "/"}),
        ] {
            assert!(
                matches!(parsed(arguments.clone()), Err(ToolError::Invalid(_))),
                "{arguments}"
            );
        }
    }

    #[test]
    fn prune_argv_removes_untagged_images_and_more_only_when_asked() {
        assert_eq!(
            prune_argv(false, 7),
            strings(&["image", "prune", "--force"])
        );
        assert_eq!(
            prune_argv(true, 7),
            strings(&[
                "image",
                "prune",
                "--force",
                "--all",
                "--filter",
                "until=168h"
            ])
        );
        assert_eq!(prune_argv(true, 1)[5], "until=24h");
        assert_eq!(prune_argv(true, 365)[5], "until=8760h");
    }

    const DAY: u64 = 86_400;

    fn file(path: &Path, bytes: usize, age_days: u64) {
        std::fs::write(path, vec![b'x'; bytes]).unwrap();
        let then = SystemTime::now() - Duration::from_secs(age_days * DAY + 3600);
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(then)
            .unwrap();
    }

    /// A crash directory with old and new files and the things that must be left alone.
    fn crash_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let at = |name: &str| dir.path().join(name);
        file(&at("core.nginx.1000.zst"), 20_000, 30);
        file(&at("core.app.33.zst"), 8_000, 8);
        file(&at("core.fresh.0.zst"), 4_000, 1);
        file(&at(".lock"), 10, 400);
        std::fs::create_dir(at("old-directory")).unwrap();
        file(&at("old-directory/inside"), 10, 400);
        dir
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn sweep_lists_what_is_old_enough_without_removing_it_in_a_dry_run() {
        let dir = crash_dir();
        let before = names(dir.path());
        let found = sweep(dir.path(), 7, now_secs(), true);
        assert_eq!(found.skipped, None);
        assert_eq!(found.failed, 0);
        let listed: Vec<(&str, u64)> = found
            .old
            .iter()
            .map(|file| (file.name.as_str(), file.age_days))
            .collect();
        // largest first; the new file, the hidden file and the directory are not there
        assert_eq!(
            listed,
            [("core.nginx.1000.zst", 30), ("core.app.33.zst", 8)]
        );
        assert!(found.old[0].bytes >= 20_000, "{found:?}");
        // what is in a sub-directory is not this tool's to remove, but it is counted
        assert_eq!(found.directories, 1);
        assert_eq!(names(dir.path()), before);
    }

    #[test]
    fn sweep_removes_only_old_regular_files_directly_inside() {
        let dir = crash_dir();
        let found = sweep(dir.path(), 7, now_secs(), false);
        assert_eq!(found.old.len(), 2);
        assert_eq!(found.failed, 0);
        assert_eq!(
            names(dir.path()),
            [".lock", "core.fresh.0.zst", "old-directory"]
        );
        // nothing below a sub-directory is touched
        assert!(dir.path().join("old-directory/inside").exists());
        // a higher age keeps more
        let dir = crash_dir();
        let found = sweep(dir.path(), 10, now_secs(), false);
        assert_eq!(found.old.len(), 1);
        assert!(dir.path().join("core.app.33.zst").exists());
    }

    #[test]
    fn sweep_never_follows_a_link() {
        let outside = tempfile::tempdir().unwrap();
        file(&outside.path().join("precious"), 100, 400);
        // a link inside the directory, to a file and to a directory
        let dir = crash_dir();
        std::os::unix::fs::symlink(outside.path().join("precious"), dir.path().join("link"))
            .unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("dirlink")).unwrap();
        let found = sweep(dir.path(), 7, now_secs(), false);
        assert_eq!(found.old.len(), 2);
        assert!(outside.path().join("precious").exists());
        assert!(dir.path().join("link").symlink_metadata().is_ok());
        assert!(dir.path().join("dirlink").symlink_metadata().is_ok());

        // the directory itself being a link: nothing is done there
        let holder = tempfile::tempdir().unwrap();
        let target = crash_dir();
        let link = holder.path().join("crash");
        std::os::unix::fs::symlink(target.path(), &link).unwrap();
        let before = names(target.path());
        let found = sweep(&link, 7, now_secs(), false);
        assert!(found.old.is_empty(), "{found:?}");
        let why = found.skipped.unwrap();
        assert!(why.contains("link"), "{why}");
        assert_eq!(names(target.path()), before);
    }

    #[test]
    fn sweep_says_when_the_directory_is_not_there() {
        let dir = tempfile::tempdir().unwrap();
        let found = sweep(&dir.path().join("absent"), 7, now_secs(), false);
        assert!(found.old.is_empty());
        assert!(found.skipped.unwrap().contains("does not exist"));
        // a file where the directory should be
        file(&dir.path().join("file"), 10, 400);
        let found = sweep(&dir.path().join("file"), 7, now_secs(), false);
        assert!(found.skipped.is_some(), "{found:?}");
        assert!(dir.path().join("file").exists());
    }

    const CONFIG: &str = r#"
[roles.admin]
allow = ["@all"]
[roles.logs]
allow = ["storage.reclaim:journal"]
[roles.reader]
allow = ["@read"]
[unix_users.adam]
roles = ["admin"]
[unix_users.lars]
roles = ["logs"]
[unix_users.rita]
roles = ["reader"]
"#;

    const ALL_ACTIONS: &str = "[storage]\nreclaim = [\"journal\", \"package_cache\", \
                               \"container_images\", \"core_dumps\", \"tmpfiles\"]\n";

    struct Fixture {
        host: Arc<Host>,
        audit: MemorySink,
        env: Env,
        dir: tempfile::TempDir,
    }

    fn fixture_with(fake: &FakeBins, storage: &str) -> Fixture {
        let (host, audit) = host(&format!("{CONFIG}{storage}{}", fake.config_only()));
        let dir = tempfile::tempdir().unwrap();
        let at = |name: &str| dir.path().join(name);
        for name in [
            "journal", "apt", "dnf", "docker", "coredump", "crash", "tmp",
        ] {
            std::fs::create_dir(at(name)).unwrap();
        }
        file(&at("apt/nginx_1.24.0_amd64.deb"), 300_000, 3);
        file(&at("dnf/nginx-1.24.0.rpm"), 300_000, 3);
        file(&at("coredump/core.nginx.1000.zst"), 20_000, 30);
        file(&at("coredump/core.fresh.0.zst"), 4_000, 1);
        file(&at("crash/_usr_bin_app.1000.crash"), 9_000, 12);
        let env = Env {
            journal_dirs: vec![at("no-journal-here"), at("journal")],
            apt_cache: at("apt"),
            rpm_caches: vec![at("dnf"), at("no-yum-cache")],
            container_dirs: vec![at("docker"), at("no-podman")],
            core_dirs: vec![at("coredump"), at("crash"), at("no-such-dir")],
            tmp_dirs: vec![at("tmp")],
        };
        Fixture {
            host,
            audit,
            env,
            dir,
        }
    }

    fn fixture(fake: &FakeBins) -> Fixture {
        fixture_with(fake, ALL_ACTIONS)
    }

    async fn run(fixture: &Fixture, user: &str, arguments: Value) -> ToolResult {
        let tool = find(tools(), "space_reclaim");
        let args = Args::parse(&tool.params, Some(&arguments)).map_err(ToolError::Invalid)?;
        let ctx = testing::ctx(&fixture.host, user, "storage.reclaim", Access::Write);
        space_reclaim_at(ctx, args, fixture.env.clone()).await
    }

    fn everything() -> FakeBins {
        FakeBins::new()
            .add_script(
                "journalctl",
                "echo 'Vacuuming done, freed 1.2G of archived journals from /var/log/journal/abc.' >&2",
            )
            .add("dpkg-query", "", 0)
            .add("apt-get", "", 0)
            .add("docker", "Total reclaimed space: 1.5GB\n", 0)
            .add("systemd-tmpfiles", "", 0)
    }

    const PROGRAMS: [&str; 6] = [
        "journalctl",
        "apt-get",
        "dnf",
        "docker",
        "podman",
        "systemd-tmpfiles",
    ];

    fn nothing_ran(fake: &FakeBins) {
        for name in PROGRAMS {
            assert_eq!(fake.calls(name), Calls::new(), "{name}");
        }
    }

    #[tokio::test]
    async fn by_default_no_action_is_allowed_on_a_host() {
        let fake = everything();
        let fixture = fixture_with(&fake, "");
        for action in RECLAIM_ACTIONS {
            let result = run(&fixture, "adam", json!({"action": action})).await;
            match result {
                Err(ToolError::Denied(message)) => {
                    assert!(message.contains("storage.reclaim"), "{message}")
                }
                other => panic!("{action}: expected a refusal, got {other:?}"),
            }
        }
        nothing_ran(&fake);
        let records = fixture.audit.records();
        assert_eq!(records.len(), RECLAIM_ACTIONS.len());
        assert_eq!(records[0]["decision"], "deny");
        assert_eq!(records[0]["resource"], "journal");
        // the crash directories were not touched either
        assert_eq!(names(&fixture.dir.path().join("coredump")).len(), 2);
    }

    #[tokio::test]
    async fn only_the_actions_the_host_lists_are_allowed() {
        let fake = everything();
        let fixture = fixture_with(&fake, "[storage]\nreclaim = [\"journal\"]\n");
        let result = run(&fixture, "adam", json!({"action": "core_dumps"})).await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        assert_eq!(names(&fixture.dir.path().join("coredump")).len(), 2);
        ok_text(run(&fixture, "adam", json!({"action": "journal"})).await);
    }

    #[tokio::test]
    async fn the_caller_needs_a_grant_for_that_action() {
        let fake = everything();
        let fixture = fixture(&fake);
        // lars may vacuum the journal and nothing else
        let result = run(&fixture, "lars", json!({"action": "package_cache"})).await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        let records = fixture.audit.records();
        assert_eq!(
            (&records[0]["resource"], &records[0]["decision"]),
            (&json!("package_cache"), &json!("deny"))
        );
        // a reader holds no write permission at all
        let result = run(&fixture, "rita", json!({"action": "journal"})).await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        nothing_ran(&fake);
        ok_text(run(&fixture, "lars", json!({"action": "journal"})).await);
        let records = fixture.audit.records();
        let last = records.last().unwrap();
        assert_eq!(
            (&last["resource"], &last["decision"]),
            (&json!("journal"), &json!("allow"))
        );
    }

    #[tokio::test]
    async fn journal_vacuums_down_to_what_is_to_be_kept() {
        let fake = everything();
        let fixture = fixture(&fake);
        let text = ok_text(run(&fixture, "adam", json!({"action": "journal"})).await);
        assert_eq!(
            fake.calls("journalctl"),
            vec![strings(&["--vacuum-size=500M"])]
        );
        assert!(text.contains("journalctl --vacuum-size=500M"), "{text}");
        assert!(text.contains("freed 1.2G"), "{text}");
        // the free space of the filesystem the journal is on, before and after
        let journal = fixture.dir.path().join("journal");
        assert!(
            text.contains(&format!(
                "Free space on the filesystem holding {}",
                journal.display()
            )),
            "{text}"
        );
        assert!(text.contains("gone for good"), "{text}");

        ok_text(
            run(
                &fixture,
                "adam",
                json!({"action": "journal", "keep_mb": 200}),
            )
            .await,
        );
        assert_eq!(
            fake.calls("journalctl")[1],
            strings(&["--vacuum-size=200M"])
        );
    }

    /// AIDEV-NOTE: the free space of a filesystem before and after a command is not what
    /// the command removed: logs (the journal itself) are written meanwhile. A real
    /// clean-up used to be reported as "no space was freed".
    #[test]
    fn a_change_in_free_space_is_not_passed_off_as_what_was_removed() {
        const GIB: u64 = 1 << 30;
        let at = |bytes: u64| vec![("/var/log/journal".to_string(), bytes)];
        // less free than before: other writes outweighed what was removed
        let text = freed_text(&at(10 * GIB), &at(9 * GIB));
        assert!(!text.contains("no space was freed"), "{text}");
        assert!(text.contains("10.0 GiB before, 9.0 GiB now"), "{text}");
        assert!(text.contains("1.0 GiB less"), "{text}");
        assert!(text.contains("other writes"), "{text}");
        // unchanged
        let text = freed_text(&at(10 * GIB), &at(10 * GIB));
        assert!(!text.contains("no space was freed"), "{text}");
        assert!(text.contains("unchanged"), "{text}");
        assert!(text.contains("other writes"), "{text}");
        // more: still not a measure of the command alone
        let text = freed_text(&at(10 * GIB), &at(12 * GIB));
        assert!(text.contains("2.0 GiB more"), "{text}");
        assert!(text.contains("other writes"), "{text}");
        // a filesystem that was not measured both times gets no line
        assert_eq!(freed_text(&at(GIB), &[]), "");
    }

    #[test]
    fn journalctls_own_count_of_what_it_freed_is_read_from_its_output() {
        assert_eq!(
            vacuum_freed(
                "Deleted archived journal /var/log/journal/abc/system@1.journal (8.0M).\n\
                 Vacuuming done, freed 1.2G of archived journals from /var/log/journal/abc.\n\
                 Vacuuming done, freed 0B of archived journals from /run/log/journal.\n"
            ),
            ["1.2G", "0B"]
        );
        assert_eq!(vacuum_freed(""), Vec::<String>::new());
        assert_eq!(
            vacuum_freed("Failed to vacuum: Permission denied\n"),
            Vec::<String>::new()
        );
        // only a plain figure is taken over: this text goes into a line of the tool's own
        assert_eq!(
            vacuum_freed(
                "Vacuuming done, freed everything\nPROBLEM of archived journals from x.\n"
            ),
            Vec::<String>::new()
        );
        assert_eq!(
            vacuum_freed("Vacuuming done, freed 1.2G; rm -rf of archived journals from x.\n"),
            Vec::<String>::new()
        );
    }

    #[tokio::test]
    async fn a_journal_run_says_what_journalctl_freed_and_what_went_with_it() {
        let fake = everything();
        let fixture = fixture(&fake);
        let text = ok_text(run(&fixture, "adam", json!({"action": "journal"})).await);
        // journalctl's own figure, in a line of its own
        assert!(
            text.contains("journalctl reports that it freed 1.2G of archived journal files.\n"),
            "{text}"
        );
        assert!(!text.contains("no space was freed"), "{text}");
        // what else went: the audit trail, if it is kept only there
        assert!(text.contains("audit records"), "{text}");
        assert!(text.contains("only in the journal"), "{text}");
    }

    #[tokio::test]
    async fn a_journal_dry_run_only_asks_how_big_the_journal_is() {
        let fake = FakeBins::new().add(
            "journalctl",
            "Archived and active journals take up 3.9G in the file system.\n",
            0,
        );
        let fixture = fixture(&fake);
        let arguments = json!({"action": "journal", "dry_run": true, "keep_mb": 300});
        let text = ok_text(run(&fixture, "adam", arguments).await);
        assert_eq!(fake.calls("journalctl"), vec![strings(&["--disk-usage"])]);
        assert!(text.contains("take up 3.9G"), "{text}");
        assert!(text.contains("Dry run"), "{text}");
        assert!(text.contains("nothing was removed"), "{text}");
        assert!(text.contains("300 MiB"), "{text}");
    }

    #[tokio::test]
    async fn package_cache_cleans_with_the_hosts_package_manager() {
        let fake = everything();
        let fixture = fixture(&fake);
        let text = ok_text(run(&fixture, "adam", json!({"action": "package_cache"})).await);
        assert_eq!(fake.calls("apt-get"), vec![strings(&["clean"])]);
        assert!(text.contains("apt-get clean"), "{text}");
        assert!(
            text.contains("Free space on the filesystem holding"),
            "{text}"
        );

        // an rpm host with dnf
        let fake = FakeBins::new()
            .add("rpm", "", 0)
            .add("dnf", "12 files removed\n", 0);
        let fixture = fixture_with(&fake, ALL_ACTIONS);
        let text = ok_text(run(&fixture, "adam", json!({"action": "package_cache"})).await);
        assert_eq!(fake.calls("dnf"), vec![strings(&["clean", "packages"])]);
        assert!(text.contains("12 files removed"), "{text}");
        // its dry run says that not everything in that directory goes
        let arguments = json!({"action": "package_cache", "dry_run": true});
        let text = ok_text(run(&fixture, "adam", arguments).await);
        assert!(text.contains("repository metadata"), "{text}");
        assert_eq!(fake.calls("dnf").len(), 1);

        // an older one with yum only
        let fake = FakeBins::new().add("rpm", "", 0).add("yum", "", 0);
        let fixture = fixture_with(&fake, ALL_ACTIONS);
        ok_text(run(&fixture, "adam", json!({"action": "package_cache"})).await);
        assert_eq!(fake.calls("yum"), vec![strings(&["clean", "packages"])]);
    }

    #[tokio::test]
    async fn a_package_cache_dry_run_measures_the_cache_and_runs_nothing() {
        let fake = everything();
        let fixture = fixture(&fake);
        let arguments = json!({"action": "package_cache", "dry_run": true});
        let text = ok_text(run(&fixture, "adam", arguments).await);
        assert_eq!(fake.calls("apt-get"), Calls::new());
        let cache = fixture.dir.path().join("apt");
        assert!(text.contains(&cache.display().to_string()), "{text}");
        // a 300 kB package file is in it
        assert!(text.contains("KiB"), "{text}");
        assert!(text.contains("Dry run"), "{text}");
        assert!(cache.join("nginx_1.24.0_amd64.deb").exists());
    }

    #[tokio::test]
    async fn package_cache_needs_a_package_manager() {
        let fake = FakeBins::new();
        let fixture = fixture(&fake);
        let result = run(&fixture, "adam", json!({"action": "package_cache"})).await;
        assert!(matches!(result, Err(ToolError::Failed(_))), "{result:?}");
    }

    #[tokio::test]
    async fn container_images_prunes_with_every_runtime_there_is() {
        let fake = FakeBins::new()
            .add("docker", "Total reclaimed space: 1.5GB\n", 0)
            .add("podman", "", 0);
        let fixture = fixture(&fake);
        let text = ok_text(run(&fixture, "adam", json!({"action": "container_images"})).await);
        let untagged = vec![strings(&["image", "prune", "--force"])];
        assert_eq!(fake.calls("docker"), untagged);
        assert_eq!(fake.calls("podman"), untagged);
        assert!(text.contains("docker image prune --force"), "{text}");
        assert!(text.contains("podman image prune --force"), "{text}");
        assert!(text.contains("Total reclaimed space: 1.5GB"), "{text}");

        let arguments = json!({"action": "container_images", "all_unused": true});
        ok_text(run(&fixture, "adam", arguments).await);
        assert_eq!(
            fake.calls("docker")[1],
            strings(&[
                "image",
                "prune",
                "--force",
                "--all",
                "--filter",
                "until=168h"
            ])
        );
        let arguments =
            json!({"action": "container_images", "all_unused": true, "min_age_days": 2});
        ok_text(run(&fixture, "adam", arguments).await);
        assert_eq!(fake.calls("podman")[2][5], "until=48h");
    }

    #[tokio::test]
    async fn a_container_images_dry_run_lists_untagged_images_only() {
        let fake = FakeBins::new().add(
            "docker",
            "REPOSITORY   TAG       IMAGE ID       CREATED        SIZE\n<none>       <none>    0123456789ab   2 weeks ago    1.1GB\n",
            0,
        );
        let fixture = fixture(&fake);
        let arguments = json!({"action": "container_images", "dry_run": true, "all_unused": true});
        let text = ok_text(run(&fixture, "adam", arguments).await);
        assert_eq!(
            fake.calls("docker"),
            vec![strings(&["images", "--filter", "dangling=true"])]
        );
        assert!(text.contains("0123456789ab"), "{text}");
        assert!(text.contains("Dry run"), "{text}");
        // what all_unused would add cannot be listed beforehand: say so
        assert!(text.contains("untagged images only"), "{text}");
    }

    #[tokio::test]
    async fn container_images_needs_a_runtime() {
        let fake = FakeBins::new();
        let fixture = fixture(&fake);
        let result = run(&fixture, "adam", json!({"action": "container_images"})).await;
        match result {
            Err(ToolError::Failed(message)) => {
                assert!(message.contains("podman"), "{message}");
                assert!(message.contains("docker"), "{message}");
            }
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn core_dumps_removes_old_dumps_from_the_crash_directories() {
        let fake = FakeBins::new();
        let fixture = fixture(&fake);
        let at = |name: &str| fixture.dir.path().join(name);
        let arguments = json!({"action": "core_dumps", "dry_run": true});
        let text = ok_text(run(&fixture, "adam", arguments).await);
        assert!(text.contains("core.nginx.1000.zst"), "{text}");
        assert!(text.contains("_usr_bin_app.1000.crash"), "{text}");
        assert!(!text.contains("core.fresh.0.zst"), "{text}");
        assert!(text.contains("Dry run"), "{text}");
        assert!(text.contains("2 files"), "{text}");
        assert_eq!(names(&at("coredump")).len(), 2);
        assert_eq!(names(&at("crash")).len(), 1);

        let text = ok_text(run(&fixture, "adam", json!({"action": "core_dumps"})).await);
        assert_eq!(names(&at("coredump")), ["core.fresh.0.zst"]);
        assert_eq!(names(&at("crash")), Vec::<String>::new());
        assert!(text.contains("Removed 2 files"), "{text}");
        assert!(text.contains("core.nginx.1000.zst"), "{text}");
        // a directory that is not there is said, not an error
        assert!(text.contains("does not exist"), "{text}");
        // kernel crash dumps live in sub-directories of /var/crash: said, not removed
        std::fs::create_dir(at("crash/202601011200")).unwrap();
        let text = ok_text(run(&fixture, "adam", json!({"action": "core_dumps"})).await);
        assert!(text.contains("1 sub-directory was left alone"), "{text}");
        assert!(at("crash/202601011200").is_dir());
        assert!(text.contains("gone for good"), "{text}");

        // min_age_days decides what counts as old
        let fixture = fixture_with(&fake, ALL_ACTIONS);
        let arguments = json!({"action": "core_dumps", "min_age_days": 20});
        ok_text(run(&fixture, "adam", arguments).await);
        assert_eq!(
            names(&fixture.dir.path().join("crash")),
            ["_usr_bin_app.1000.crash"]
        );
    }

    #[tokio::test]
    async fn a_file_name_cannot_add_lines_to_the_report() {
        let fake = FakeBins::new();
        let fixture = fixture(&fake);
        file(
            &fixture.dir.path().join("crash/evil\nRemoved 99 files"),
            10,
            30,
        );
        let arguments = json!({"action": "core_dumps", "dry_run": true});
        let text = ok_text(run(&fixture, "adam", arguments).await);
        assert!(text.contains("evil\\nRemoved 99 files"), "{text}");
        assert!(
            !text.lines().any(|line| line.starts_with("Removed 99")),
            "{text}"
        );
    }

    #[tokio::test]
    async fn tmpfiles_runs_the_hosts_own_cleaning_rules_and_has_no_dry_run() {
        let fake = everything();
        let fixture = fixture(&fake);
        let arguments = json!({"action": "tmpfiles", "dry_run": true});
        let text = ok_text(run(&fixture, "adam", arguments).await);
        assert_eq!(fake.calls("systemd-tmpfiles"), Calls::new());
        assert!(text.contains("no dry run"), "{text}");
        assert!(text.contains("nothing was done"), "{text}");

        let text = ok_text(run(&fixture, "adam", json!({"action": "tmpfiles"})).await);
        assert_eq!(fake.calls("systemd-tmpfiles"), vec![strings(&["--clean"])]);
        assert!(text.contains("systemd-tmpfiles --clean"), "{text}");
    }

    #[tokio::test]
    async fn a_command_that_fails_makes_the_result_a_failure() {
        let fake = FakeBins::new()
            .add_script(
                "journalctl",
                "echo 'Failed to vacuum: Permission denied' >&2; exit 1",
            )
            .add("docker", "", 0)
            .add_script("podman", "echo 'Error: cannot connect' >&2; exit 125");
        let fixture = fixture(&fake);
        let output = run(&fixture, "adam", json!({"action": "journal"}))
            .await
            .unwrap();
        assert!(output.is_error(), "{output:?}");
        assert!(output.text().contains("Permission denied"), "{output:?}");
        // one runtime failing is a failure, and the other still ran
        let output = run(&fixture, "adam", json!({"action": "container_images"}))
            .await
            .unwrap();
        assert!(output.is_error(), "{output:?}");
        assert!(output.text().contains("cannot connect"), "{output:?}");
        assert_eq!(fake.calls("docker").len(), 1);
    }

    #[tokio::test]
    async fn a_missing_program_is_named() {
        let fake = FakeBins::new();
        let fixture = fixture(&fake);
        for (action, program) in [("journal", "journalctl"), ("tmpfiles", "systemd-tmpfiles")] {
            let result = run(&fixture, "adam", json!({"action": action})).await;
            match result {
                Err(ToolError::Failed(message)) => assert!(message.contains(program), "{message}"),
                other => panic!("{action}: expected a failure, got {other:?}"),
            }
        }
    }

    #[test]
    fn the_tool_offers_exactly_the_actions_the_configuration_knows() {
        let tool = find(tools(), "space_reclaim");
        assert_eq!(tool.access, Access::Write);
        assert_eq!(tool.permission, "storage.reclaim");
        match &tool.params[0].kind {
            crate::tools::args::Kind::Choice(values) => {
                assert_eq!(values.as_slice(), RECLAIM_ACTIONS.map(String::from))
            }
            other => panic!("action should be a choice, got {other:?}"),
        }
    }
}
