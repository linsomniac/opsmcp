//! Whether this host is affected by a given CVE.
//!
//! AIDEV-NOTE: what can be known differs by distribution, and the tool says which it is:
//!   - dpkg hosts, offline: a package that was changed because of a CVE names it in its
//!     changelog, and the changelogs of installed packages are on disk. A hit means the
//!     fix is installed. No hit means "not affected OR not fixed yet": there is no local
//!     list of what is still vulnerable, so that is reported as UNKNOWN, never as safe.
//!   - dpkg hosts, online (Ubuntu): `pro fix --dry-run` asks Ubuntu's security service.
//!   - rpm hosts: the repositories carry advisories that list CVEs, so dnf can say
//!     whether a fixing update is pending or installed.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::args::{Args, Param};
use super::{
    CallClock, Ctx, Tool, ToolError, ToolResult, blocking, command_ok, command_text, required,
};
use crate::exec::{Cmd, CmdOutput};
use crate::policy::Access;
use crate::sanitize::keep_head;
use crate::timefmt::human_bytes;

/// Where the changelogs of installed packages are. A parameter so that tests can use a
/// temporary directory.
#[derive(Clone, Debug)]
pub struct Paths {
    pub doc_root: PathBuf,
    /// The files whose presence says that this host is waiting for a reboot.
    pub reboot_flags: Vec<PathBuf>,
}

impl Default for Paths {
    fn default() -> Self {
        Paths {
            doc_root: PathBuf::from("/usr/share/doc"),
            reboot_flags: vec![
                PathBuf::from("/run/reboot-required"),
                PathBuf::from("/var/run/reboot-required"),
            ],
        }
    }
}

pub fn tools() -> Vec<Tool> {
    tools_with(Paths::default())
}

pub fn tools_with(paths: Paths) -> Vec<Tool> {
    let paths = Arc::new(paths);
    vec![Tool::new(
        "cve_status",
        "Tell whether this host is affected by one CVE and whether the fix is installed. \
         The first line is the verdict (FIXED, AFFECTED, NOT AFFECTED or UNKNOWN) and the \
         rest says what it is based on. On Debian and Ubuntu it searches the changelogs of \
         the installed packages, which can show that a fix is in but cannot tell 'not \
         affected' from 'not fixed yet'; with online it also asks Ubuntu's security \
         service (pro). On rpm hosts it reads the advisories dnf has cached. FIXED is \
         about what is installed: programs that were already running need a restart. Use \
         it to answer 'are we exposed to CVE-...?' for one host; package_updates lists \
         what is pending in general.",
        Access::Read,
        "package.view",
        vec![
            Param::str("cve", "The CVE id, e.g. CVE-2024-6119")
                .max_len(32)
                .required(),
            Param::bool(
                "online",
                "Also ask the distribution's security service or repositories. This sends \
                 the CVE id out from the host and needs outbound network access; it works \
                 only where the host's configuration allows it (package.cve_online)",
            ),
        ],
        move |ctx, args| cve_status(ctx, args, paths.clone()),
    )]
}

/// Most characters of a changelog or advisory line that are repeated.
const MAX_LINE: usize = 200;
/// Most lines of one changelog that are repeated.
const MAX_LINES: usize = 3;
/// Most entry versions of one changelog that are listed.
const MAX_VERSIONS: usize = 5;
/// How long `pro` is given to ask the security service.
const PRO_SECS: u64 = 20;

fn cut(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        let mut kept: String = text.chars().take(max).collect();
        kept.push_str("...");
        kept
    }
}

/// Checks a CVE id and gives it in its usual upper-case form.
///
/// AIDEV-NOTE: the id is passed to `pro` and `dnf` as an argument and is searched for in
/// files, so nothing but `CVE-`, four digits, `-` and four to seven digits gets through.
pub fn check_cve(text: &str) -> Result<String, ToolError> {
    let id = text.trim().to_ascii_uppercase();
    let digits = |part: &str| part.bytes().all(|b| b.is_ascii_digit());
    let well_formed = id
        .strip_prefix("CVE-")
        .and_then(|rest| rest.split_once('-'))
        .is_some_and(|(year, number)| {
            year.len() == 4 && digits(year) && (4..=7).contains(&number.len()) && digits(number)
        });
    if well_formed {
        Ok(id)
    } else {
        Err(ToolError::Invalid(
            "a CVE id looks like CVE-2024-6119: CVE, the year, and a number of four to seven digits"
                .to_string(),
        ))
    }
}

/// True when `line` names `cve` (upper case) as a whole id, in either case:
/// `CVE-2024-6119` is not found in `CVE-2024-61190`.
pub fn mentions_id(line: &str, cve: &str) -> bool {
    let (line, id) = (line.as_bytes(), cve.as_bytes());
    if id.is_empty() || line.len() < id.len() {
        return false;
    }
    line.windows(id.len()).enumerate().any(|(at, window)| {
        if !window.eq_ignore_ascii_case(id) {
            return false;
        }
        let before = at.checked_sub(1).and_then(|i| line.get(i));
        let after = line.get(at.saturating_add(id.len()));
        !before.is_some_and(u8::is_ascii_alphanumeric) && !after.is_some_and(u8::is_ascii_digit)
    })
}

/// What one package's changelog says about a CVE.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mention {
    /// The source package the changelog belongs to; empty if the changelog is not in
    /// Debian's format.
    pub source: String,
    /// The version of the newest entry: what is installed.
    pub installed: String,
    /// The versions of the entries that name the CVE, newest first.
    pub versions: Vec<String>,
    /// The lines that name it (a few).
    pub lines: Vec<String>,
}

/// The package and version of a Debian changelog entry's first line:
/// `openssl (3.0.13-0ubuntu3.4) noble-security; urgency=medium`.
fn entry_header(line: &str) -> Option<(&str, &str)> {
    let (name, rest) = line.split_once(" (")?;
    let (version, rest) = rest.split_once(')')?;
    let name_ok = !name.is_empty()
        && name.len() <= 128
        && name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c));
    let version_ok = !version.is_empty()
        && version.len() <= 100
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".+~:-".contains(c));
    (name_ok && version_ok && rest.starts_with(' ')).then_some((name, version))
}

/// Searches one changelog. `None` when it does not name the CVE.
///
/// AIDEV-NOTE: a changelog is a file from a package, so what is repeated from it is kept
/// small and plain: a name and versions only if they look like a package name and
/// versions, and at most a few lines, each cut short.
pub fn scan_changelog(text: &str, cve: &str) -> Option<Mention> {
    let mut found = Mention {
        source: String::new(),
        installed: String::new(),
        versions: Vec::new(),
        lines: Vec::new(),
    };
    let mut named = false;
    let mut first_entry_seen = false;
    let mut current: Option<&str> = None;
    for line in text.lines() {
        if let Some((name, version)) = entry_header(line) {
            if !first_entry_seen {
                first_entry_seen = true;
                found.source = name.to_string();
                found.installed = version.to_string();
            }
            current = Some(version);
            continue;
        }
        if !mentions_id(line, cve) {
            continue;
        }
        named = true;
        if let Some(version) = current
            && found.versions.len() < MAX_VERSIONS
            && !found.versions.iter().any(|seen| seen == version)
        {
            found.versions.push(version.to_string());
        }
        if found.lines.len() < MAX_LINES {
            found.lines.push(cut(line.trim(), MAX_LINE));
        }
    }
    named.then_some(found)
}

/// The packages (by the name of their directory) that share one changelog finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    pub packages: Vec<String>,
    pub mention: Mention,
}

/// The result of searching every installed package's changelog.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scan {
    pub hits: Vec<Hit>,
    /// Changelogs read.
    pub files: usize,
    /// Why the search did not cover everything, if it did not.
    pub incomplete: Vec<String>,
}

/// The bounds on a search.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_files: usize,
    pub max_bytes: u64,
    pub time: Duration,
}

impl Limits {
    pub fn usual(time: Duration) -> Limits {
        Limits {
            max_files: 20_000,
            max_bytes: 2 * 1024 * 1024,
            time,
        }
    }
}

/// The names a package's Debian changelog goes by, in order of preference. The plain
/// `changelog.gz` is the upstream project's when there is a Debian one beside it, and
/// the package's own when there is not (a package that has no upstream).
const CHANGELOG_NAMES: [&str; 3] = ["changelog.Debian.gz", "changelog.Debian", "changelog.gz"];

/// A directory under the documentation root that could be a package's.
fn is_package_dir_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+._:-".contains(c))
}

/// Opens a package's changelog, if it has one that is a regular file.
fn open_changelog(dir: &Path) -> Option<(std::fs::File, bool)> {
    use rustix::fs::{Mode, OFlags};
    let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    for name in CHANGELOG_NAMES {
        let Ok(fd) = rustix::fs::open(dir.join(name), flags, Mode::empty()) else {
            continue;
        };
        let file = std::fs::File::from(fd);
        if file.metadata().is_ok_and(|meta| meta.is_file()) {
            return Some((file, name.ends_with(".gz")));
        }
    }
    None
}

/// The text of a changelog, up to `max` bytes of it, and whether there was more.
fn read_changelog(file: std::fs::File, compressed: bool, max: u64) -> Option<(String, bool)> {
    let mut data = Vec::new();
    // One byte more than is kept shows whether the changelog goes on. The limit is on
    // what comes OUT of the decompressor, so a small file cannot expand without bound.
    let wanted = max.saturating_add(1);
    let read = if compressed {
        flate2::read::MultiGzDecoder::new(file)
            .take(wanted)
            .read_to_end(&mut data)
    } else {
        file.take(wanted).read_to_end(&mut data)
    };
    read.ok()?;
    let more = u64::try_from(data.len()).is_ok_and(|len| len > max);
    if more {
        data.truncate(usize::try_from(max).unwrap_or(usize::MAX));
    }
    Some((String::from_utf8_lossy(&data).into_owned(), more))
}

/// Searches the changelog of every package that has a directory under `root`.
pub fn scan_docs(root: &Path, cve: &str, limits: Limits) -> Scan {
    let started = Instant::now();
    let mut scan = Scan::default();
    let Ok(entries) = std::fs::read_dir(root) else {
        scan.incomplete
            .push(format!("{} cannot be read", root.display()));
        return scan;
    };
    // In name order, so that the same host gives the same answer each time.
    let mut names: Vec<String> = entries
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter(|name| is_package_dir_name(name))
        .take(200_000)
        .collect();
    names.sort();
    let mut longer = 0usize;
    for name in names {
        let Some((file, compressed)) = open_changelog(&root.join(&name)) else {
            continue;
        };
        if scan.files >= limits.max_files {
            scan.incomplete.push(format!(
                "only the first {} changelogs were searched",
                scan.files
            ));
            break;
        }
        if started.elapsed() >= limits.time {
            scan.incomplete.push(format!(
                "the search ran out of time after {} changelogs",
                scan.files
            ));
            break;
        }
        let Some((text, more)) = read_changelog(file, compressed, limits.max_bytes) else {
            continue;
        };
        scan.files = scan.files.saturating_add(1);
        if more {
            longer = longer.saturating_add(1);
        }
        let Some(mention) = scan_changelog(&text, cve) else {
            continue;
        };
        // Several packages built from one source carry the same changelog.
        match scan
            .hits
            .iter_mut()
            .find(|hit| !mention.source.is_empty() && hit.mention == mention)
        {
            Some(hit) => hit.packages.push(name),
            None => scan.hits.push(Hit {
                packages: vec![name],
                mention,
            }),
        }
    }
    if longer > 0 {
        scan.incomplete.push(format!(
            "{longer} changelogs are longer than is read ({}) and were searched only that far",
            human_bytes(limits.max_bytes)
        ));
    }
    scan
}

/// What `pro fix --dry-run` concluded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProVerdict {
    NotAffected,
    Fixed,
    FixAvailable,
    NoFix,
    Unclear,
}

/// Reads the verdict out of what `pro fix --dry-run` printed.
///
/// AIDEV-NOTE: with --dry-run, pro ends with "is resolved" even when the fix is only
/// AVAILABLE, because it reports what a real run would achieve. So the closing line is
/// not the verdict: a command it would run (`{ apt ... }`) means the fix is not
/// installed, and that is looked for first.
pub fn pro_verdict(output: &str) -> ProVerdict {
    let has = |needle: &str| output.contains(needle);
    let would_install = output.lines().any(|line| {
        let line = line.trim();
        line.starts_with('{') && line.contains("apt")
    });
    if has("does not affect your system") || has("No affected source packages are installed") {
        ProVerdict::NotAffected
    } else if would_install {
        ProVerdict::FixAvailable
    } else if has("no fix is available") || has("is not resolved") || has("still affected") {
        ProVerdict::NoFix
    } else if has("already installed") || has("is resolved") {
        ProVerdict::Fixed
    } else {
        ProVerdict::Unclear
    }
}

fn plural(count: usize, one: &str, many: &str) -> String {
    if count == 1 {
        format!("1 {one}")
    } else {
        format!("{count} {many}")
    }
}

/// How many packages that were merely rebuilt are listed by name.
const MAX_REBUILT_NAMED: usize = 20;

/// Whether a changelog names the CVE only as the reason for rebuilding the package
/// ("No-change rebuild for CVE-..."), in every line that names it.
fn only_rebuilt(mention: &Mention) -> bool {
    !mention.lines.is_empty()
        && mention.lines.iter().all(|line| {
            let line = line.to_ascii_lowercase();
            line.contains("no-change rebuild") || line.contains("no change rebuild")
        })
}

/// What is added to every FIXED verdict.
///
/// AIDEV-NOTE: FIXED says what is INSTALLED. A process that was started before the
/// update still runs the old code, and so does the kernel until the host reboots; the
/// first line must not read as "nothing left to do" on a host that upgraded openssl an
/// hour ago and restarted nothing.
fn running_caveat(reboot_pending: bool) -> &'static str {
    if reboot_pending {
        " Programs that were already running use it only after a restart, and a kernel only \
         after a reboot. A reboot is pending on this host (reboot-required)."
    } else {
        " Programs that were already running use it only after a restart, and a kernel only \
         after a reboot."
    }
}

/// The verdict line and the per-package details for what the changelogs showed, and
/// whether the verdict is FIXED.
fn changelog_report(cve: &str, scan: &Scan) -> (String, String, bool) {
    if scan.files == 0 && scan.hits.is_empty() {
        // AIDEV-NOTE: with nothing to search, "no changelog names it" would be true of
        // every CVE there is. Minimal and container images often ship no changelogs.
        let verdict = format!(
            "{cve}: UNKNOWN: not one package changelog could be read on this host, so the \
             changelogs can say nothing about it (minimal images do not ship them)."
        );
        return (verdict, String::new(), false);
    }
    if scan.hits.is_empty() {
        let verdict = if scan.incomplete.is_empty() {
            format!(
                "{cve}: UNKNOWN: no installed package's changelog names it. This host is \
                 either not affected or not yet fixed, and that cannot be told apart offline."
            )
        } else {
            format!(
                "{cve}: UNKNOWN: none of the changelogs that were searched names it, and not \
                 all of them could be searched."
            )
        };
        return (verdict, String::new(), false);
    }
    let subject = |hit: &Hit| {
        if hit.mention.source.is_empty() {
            hit.packages.join(", ")
        } else {
            format!("{} {}", hit.mention.source, hit.mention.installed)
        }
    };
    // AIDEV-NOTE: a changelog names a CVE for more than one reason. "No-change rebuild for
    // CVE-2024-3094" is in dozens of Ubuntu packages, none of which fixed anything: they
    // were rebuilt because the build machines might have been affected. Those are set
    // apart, and never make the verdict FIXED by themselves.
    let (rebuilt, fixes): (Vec<&Hit>, Vec<&Hit>) =
        scan.hits.iter().partition(|hit| only_rebuilt(&hit.mention));
    let rebuilt_names = || {
        let mut names: Vec<&str> = rebuilt
            .iter()
            .map(|hit| {
                if hit.mention.source.is_empty() {
                    hit.packages.first().map_or("?", String::as_str)
                } else {
                    hit.mention.source.as_str()
                }
            })
            .collect();
        let more = names.len().saturating_sub(MAX_REBUILT_NAMED);
        names.truncate(MAX_REBUILT_NAMED);
        let mut text = names.join(", ");
        if more > 0 {
            text.push_str(&format!(" and {more} more"));
        }
        text
    };
    let Some(first_fix) = fixes.first() else {
        let verdict = format!(
            "{cve}: UNKNOWN: {} only as the reason for a rebuild, which fixed nothing in \
             them. Whether this host is affected cannot be told from the changelogs.",
            plural(
                rebuilt.len(),
                "installed package names it",
                "installed packages name it"
            )
        );
        let details = format!("Rebuilt because of it: {}\n", rebuilt_names());
        return (verdict, details, false);
    };
    let others = fixes.len().saturating_sub(1);
    // "names it", not "includes the fix": a changelog can also name a CVE to say the
    // package is not affected. The quoted lines below let the reader tell.
    let verdict = match others {
        0 => format!(
            "{cve}: FIXED: {} (installed) names it in its changelog, which normally means \
             the fix is in.",
            subject(first_fix)
        ),
        _ => format!(
            "{cve}: FIXED: {} and {} (installed) name it in their changelogs, which \
             normally means the fix is in.",
            subject(first_fix),
            plural(others, "other source package", "other source packages")
        ),
    };
    let mut details = String::new();
    for hit in &fixes {
        let where_named = match hit.mention.versions.as_slice() {
            [] => "named in its changelog, which is not in Debian's format, so the version \
                   that brought the fix is not known"
                .to_string(),
            [version] => format!("named in the changelog entry for {version}"),
            versions => format!("named in the changelog entries for {}", versions.join(", ")),
        };
        details.push_str(&format!("{}: {where_named}\n", subject(hit)));
        if !hit.mention.source.is_empty() {
            details.push_str(&format!("  packages: {}\n", hit.packages.join(", ")));
        }
        for line in &hit.mention.lines {
            details.push_str(&format!("    {line}\n"));
        }
    }
    if !rebuilt.is_empty() {
        details.push_str(&format!(
            "{} only as the reason for a rebuild, which fixed nothing in them: {}\n",
            plural(
                rebuilt.len(),
                "other package names it",
                "other packages name it"
            ),
            rebuilt_names()
        ));
    }
    (verdict, details, true)
}

async fn run_within(ctx: &Ctx, cmd: Cmd, limit: Option<Duration>) -> Result<CmdOutput, String> {
    let Some(limit) = limit else {
        return Err("the call ran out of time".to_string());
    };
    // Boxed: a running command's future is large, and this is awaited more than once.
    match Box::pin(ctx.run(cmd.timeout(limit))).await {
        Ok(out) => Ok(out),
        Err(ToolError::Failed(why)) => Err(why),
        Err(_) => Err("the command could not be run".to_string()),
    }
}

/// Asks Ubuntu's security service through `pro`. Returns its verdict and the text to show.
async fn ask_pro(ctx: &Ctx, clock: &CallClock, cve: &str) -> (ProVerdict, String) {
    let cmd = match ctx.optional_command("pro") {
        Ok(Some(cmd)) => cmd,
        Ok(None) => {
            return (
                ProVerdict::Unclear,
                "[online was asked for, but pro is not installed (package ubuntu-pro-client, \
                 Ubuntu only): only the offline answer is given]\n"
                    .to_string(),
            );
        }
        Err(ToolError::Failed(why)) => {
            return (
                ProVerdict::Unclear,
                format!(
                    "[the security service was not asked: {}]\n",
                    cut(&why, MAX_LINE)
                ),
            );
        }
        Err(_) => {
            return (
                ProVerdict::Unclear,
                "[the security service was not asked]\n".to_string(),
            );
        }
    };
    // AIDEV-NOTE: `--dry-run` is what makes this a question. Without it `pro fix`
    // installs the fixing packages. The arguments are fixed here and nowhere else; an
    // old pro that does not know the flag refuses the command line and does nothing.
    let limit = clock
        .next()
        .map(|left| left.min(Duration::from_secs(PRO_SECS)));
    let out = match run_within(ctx, cmd.args(["fix", "--dry-run", cve]), limit).await {
        Ok(out) => out,
        Err(why) => {
            return (
                ProVerdict::Unclear,
                format!(
                    "[the security service was not asked: {}]\n",
                    cut(&why, MAX_LINE)
                ),
            );
        }
    };
    let verdict = if command_ok(&out) {
        pro_verdict(&String::from_utf8_lossy(&out.stdout))
    } else if out.timed_out {
        ProVerdict::Unclear
    } else {
        // pro exits non-zero when the CVE is not resolved; its words still decide
        match pro_verdict(&String::from_utf8_lossy(&out.stdout)) {
            verdict @ (ProVerdict::NoFix | ProVerdict::FixAvailable) => verdict,
            _ => ProVerdict::Unclear,
        }
    };
    let (said, dropped) = keep_head(&command_text(&out), 3000);
    let mut text = format!("== pro fix --dry-run {cve} ==\n{said}");
    if dropped > 0 {
        text.push_str(&format!("[{dropped} more lines left out]\n"));
    }
    (verdict, text)
}

async fn dpkg_status(
    ctx: &Ctx,
    clock: &CallClock,
    cve: String,
    online: bool,
    paths: Arc<Paths>,
) -> Result<(String, bool), ToolError> {
    // The search shares the call's time with what may follow it.
    let time = Duration::from_secs(ctx.cfg().limits.command_timeout_secs.div_ceil(2).max(1));
    let limits = Limits::usual(time);
    let scan = {
        let (cve, paths) = (cve.clone(), paths.clone());
        blocking(ctx.clone(), move || {
            Ok(scan_docs(&paths.doc_root, &cve, limits))
        })
        .await?
    };
    let (mut verdict, details, mut fixed) = changelog_report(&cve, &scan);
    let mut pro_text = String::new();
    if online {
        let (pro, text) = ask_pro(ctx, clock, &cve).await;
        pro_text = text;
        let service = "according to the distribution's security service";
        match pro {
            ProVerdict::NotAffected => {
                verdict = format!("{cve}: NOT AFFECTED, {service}.");
                fixed = false;
            }
            ProVerdict::Fixed => {
                verdict = format!("{cve}: FIXED, {service}: the update is installed.");
                fixed = true;
            }
            ProVerdict::FixAvailable => {
                verdict = format!(
                    "{cve}: AFFECTED: a fix is available and is not installed, {service} \
                     (package_upgrade installs updates)."
                );
                fixed = false;
            }
            ProVerdict::NoFix => {
                verdict = format!("{cve}: AFFECTED: no fix is available yet, {service}.");
                fixed = false;
            }
            ProVerdict::Unclear => {}
        }
    }
    if fixed {
        let flags = paths.reboot_flags.clone();
        let reboot_pending = blocking(ctx.clone(), move || {
            Ok(flags
                .iter()
                .any(|flag| std::fs::symlink_metadata(flag).is_ok()))
        })
        .await
        .unwrap_or(false);
        verdict.push_str(running_caveat(reboot_pending));
    }

    let mut tail = format!(
        "Based on: the {} of installed packages under {}.",
        plural(scan.files, "changelog", "changelogs"),
        paths.doc_root.display()
    );
    if !scan.hits.is_empty() {
        tail.push_str(
            " Read the quoted lines: a changelog also names a CVE for a precautionary \
             rebuild, or to say that the package is not affected.",
        );
    }
    if scan.hits.is_empty() {
        tail.push_str(
            " Changelogs on disk can be shortened to their recent entries (Ubuntu does \
             this), so an older fix may not show.",
        );
        if !online {
            tail.push_str(
                " With online the distribution's security service is asked as well, which \
                 needs outbound network access and the host's configuration to allow it \
                 (package.cve_online).",
            );
        }
    }
    tail.push('\n');
    for note in &scan.incomplete {
        tail.push_str(&format!("[{note}]\n"));
    }

    let mut head = verdict;
    head.push('\n');
    head.push_str(&pro_text);
    // The per-package details are the part that can be long.
    let room = ctx
        .output_budget()
        .saturating_sub(head.len() + tail.len() + 120);
    let (details, dropped) = keep_head(&details, room);
    let mut text = head;
    text.push_str(&details);
    if dropped > 0 {
        text.push_str(&format!(
            "[{dropped} more lines left out to fit the output limit]\n"
        ));
    }
    text.push_str(&tail);
    Ok((text, true))
}

/// The advisory lines dnf printed: `RHSA-2024:6783 Important/Sec. openssl-libs-...`.
fn advisory_lines(out: &CmdOutput) -> Vec<String> {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| line.split_whitespace().count() >= 3)
        .take(200)
        .map(|line| cut(line, MAX_LINE))
        .collect()
}

async fn rpm_status(
    ctx: &Ctx,
    clock: &CallClock,
    cve: &str,
    online: bool,
) -> Result<(String, bool), ToolError> {
    let mut manager = None;
    for name in ["dnf", "yum"] {
        if ctx.optional_command(name)?.is_some() {
            manager = Some(name);
            break;
        }
    }
    let Some(manager) = manager else {
        return Err(ToolError::Failed(
            "neither dnf nor yum was found on this host".to_string(),
        ));
    };
    // -C: answer from the cache. Refreshing it is what `online` asks for.
    let base: &[&str] = if online { &["-q"] } else { &["-q", "-C"] };
    let mut outs = Vec::new();
    for extra in [&[][..], &["--installed"][..]] {
        let mut argv: Vec<&str> = base.to_vec();
        argv.extend(["updateinfo", "list"]);
        argv.extend(extra);
        argv.extend(["--cve", cve]);
        let out = run_within(ctx, ctx.command(manager)?.args(argv), clock.next())
            .await
            .map_err(ToolError::Failed)?;
        outs.push(out);
    }
    let (Some(pending), Some(installed)) = (outs.first(), outs.get(1)) else {
        return Err(ToolError::Internal(
            "two dnf runs were expected".to_string(),
        ));
    };
    let source = if online {
        format!("Based on: the advisories in the repositories, as {manager} just read them.\n")
    } else {
        format!(
            "Based on: the advisories in {manager}'s cached repository data (online reads \
             them afresh; package_upgrade with refresh updates the cache).\n"
        )
    };
    if !command_ok(pending) {
        let (said, _) = keep_head(&command_text(pending), 3000);
        return Ok((
            format!("{cve}: UNKNOWN: {manager} could not answer.\n{said}{source}"),
            false,
        ));
    }
    let list = |lines: &[String]| -> String {
        let mut text = String::new();
        for line in lines.iter().take(20) {
            text.push_str(&format!("  {line}\n"));
        }
        if let Some(more) = lines.len().checked_sub(20).filter(|more| *more > 0) {
            text.push_str(&format!("  [{more} more]\n"));
        }
        text
    };
    let pending_lines = advisory_lines(pending);
    let installed_lines = if command_ok(installed) {
        advisory_lines(installed)
    } else {
        Vec::new()
    };
    let text = if !pending_lines.is_empty() {
        format!(
            "{cve}: AFFECTED: an update that fixes it is available and is not installed \
             (package_upgrade installs updates).\n{}{source}",
            list(&pending_lines)
        )
    } else if !installed_lines.is_empty() {
        format!(
            "{cve}: FIXED: the update that fixes it is installed.{}\n{}{source}",
            running_caveat(false),
            list(&installed_lines)
        )
    } else {
        format!(
            "{cve}: UNKNOWN: {manager} lists no advisory for it, pending or installed. This \
             host is either not affected, or no fix has been published for it.\n{source}"
        )
    };
    Ok((text, true))
}

async fn cve_status(ctx: Ctx, args: Args, paths: Arc<Paths>) -> ToolResult {
    let cve = check_cve(required(&args, "cve")?)?;
    let online = args.bool("online") == Some(true);
    // AIDEV-NOTE: a host-wide limit, checked before the caller's grants like the others.
    // `online` makes the server run the vendor's tool as itself (usually root): `pro`
    // contacts Ubuntu's service, and dnf without -C fetches fresh metadata from every
    // configured repository and rewrites its cache. Whether this host may do that is the
    // operator's decision, not that of any caller who holds package.view.
    if online && !ctx.cfg().package.cve_online {
        return Err(ctx.deny(
            None,
            "online lookups are off on this host (package.cve_online)",
        ));
    }
    let auth = ctx.authorize(None)?;
    let clock = CallClock::start(&ctx);
    // As the package tools do: dpkg means Debian or Ubuntu, otherwise rpm.
    let (text, succeeded) = if ctx.optional_command("dpkg-query")?.is_some() {
        Box::pin(dpkg_status(&ctx, &clock, cve, online, paths)).await?
    } else if ctx.optional_command("rpm")?.is_some() {
        Box::pin(rpm_status(&ctx, &clock, &cve, online)).await?
    } else {
        return Err(ToolError::Failed(
            "no supported package manager (dpkg or rpm) was found on this host".to_string(),
        ));
    };
    auth.done(text, succeeded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::Host;
    use crate::tools::testing::{FakeBins, call, find, host, ok_text};
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use serde_json::{Value, json};
    use std::io::Write;

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_cve_id_is_a_year_and_a_number_and_is_used_in_upper_case() {
        for (given, wanted) in [
            ("CVE-2024-6119", "CVE-2024-6119"),
            ("cve-2024-6119", "CVE-2024-6119"),
            ("Cve-1999-0001", "CVE-1999-0001"),
            ("CVE-2021-1234567", "CVE-2021-1234567"),
            ("  CVE-2024-6119 ", "CVE-2024-6119"),
        ] {
            assert_eq!(check_cve(given).unwrap(), wanted, "{given}");
        }
        for bad in [
            "",
            "CVE",
            "2024-6119",
            "CVE-2024-611",
            "CVE-2024-12345678",
            "CVE-24-6119",
            "CVE-2024-6119x",
            "CVE-2024-61 19",
            "CVE_2024_6119",
            "CVE-2024-6119 CVE-2024-6120",
            "CVE-2024-6119;id",
            "--cve=CVE-2024-6119",
            "-CVE-2024-6119",
            "CVE-２０２４-6119",
        ] {
            assert!(
                matches!(check_cve(bad), Err(ToolError::Invalid(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn an_id_is_found_as_a_whole_id_only() {
        let cve = "CVE-2024-6119";
        for line in [
            "    - CVE-2024-6119",
            "  * SECURITY UPDATE: denial of service (CVE-2024-6119)",
            "    - debian/patches/CVE-2024-6119.patch: avoid type errors",
            "  * fix cve-2024-6119, cve-2024-0001",
            "CVE-2024-6119",
            "  * CVE-2024-61190 and CVE-2024-6119",
        ] {
            assert!(mentions_id(line, cve), "{line}");
        }
        for line in [
            "    - CVE-2024-61190",
            "    - CVE-2024-611",
            "    - XCVE-2024-6119",
            "    - CVE-2023-6119",
            "",
            "CVE-2024-",
        ] {
            assert!(!mentions_id(line, cve), "{line}");
        }
    }

    const OPENSSL: &str = "openssl (3.0.13-0ubuntu3.5) noble-security; urgency=medium

  * SECURITY UPDATE: something newer
    - debian/patches/CVE-2024-9143.patch: harden BN_GF2m_poly2arr.
    - CVE-2024-9143

 -- A Maintainer <maintainer@example.com>  Wed, 16 Oct 2024 09:30:00 +0000

openssl (3.0.13-0ubuntu3.4) noble-security; urgency=medium

  * SECURITY UPDATE: Possible denial of service in X.509 name checks
    - debian/patches/CVE-2024-6119.patch: avoid type errors in EDIPartyName.
    - CVE-2024-6119

 -- A Maintainer <maintainer@example.com>  Tue, 20 Aug 2024 13:21:00 +0000

openssl (3.0.13-0ubuntu3.3) noble; urgency=medium

  * An ordinary change.

 -- A Maintainer <maintainer@example.com>  Mon, 01 Jul 2024 08:00:00 +0000
";

    #[test]
    fn a_changelog_tells_which_entry_named_the_cve_and_what_is_installed() {
        let found = scan_changelog(OPENSSL, "CVE-2024-6119").unwrap();
        assert_eq!(
            found,
            Mention {
                source: "openssl".to_string(),
                installed: "3.0.13-0ubuntu3.5".to_string(),
                versions: strings(&["3.0.13-0ubuntu3.4"]),
                lines: strings(&[
                    "- debian/patches/CVE-2024-6119.patch: avoid type errors in EDIPartyName.",
                    "- CVE-2024-6119",
                ]),
            }
        );
        // named by the newest entry: the installed version is the one
        let newest = scan_changelog(OPENSSL, "CVE-2024-9143").unwrap();
        assert_eq!(newest.versions, strings(&["3.0.13-0ubuntu3.5"]));
        assert_eq!(scan_changelog(OPENSSL, "CVE-2020-0001"), None);
        assert_eq!(scan_changelog("", "CVE-2024-6119"), None);
    }

    #[test]
    fn a_cve_named_by_several_entries_lists_them_newest_first() {
        let text = "pkg (1.0-3) stable; urgency=medium\n\n  * Complete the fix for CVE-2024-0001.\n\n -- X <x@example.com>  Mon, 01 Jan 2024 00:00:00 +0000\n\n\
                    pkg (1.0-2) stable; urgency=high\n\n  * Fix CVE-2024-0001.\n  * Also CVE-2024-0001 in another place.\n\n -- X <x@example.com>  Sun, 31 Dec 2023 00:00:00 +0000\n";
        let found = scan_changelog(text, "CVE-2024-0001").unwrap();
        assert_eq!(found.versions, strings(&["1.0-3", "1.0-2"]));
        assert_eq!(found.installed, "1.0-3");
        assert_eq!(found.lines.len(), 3);
    }

    #[test]
    fn a_changelog_in_another_format_still_counts_but_gives_no_version() {
        let text = "2024-08-20  Somebody\n\n\t* x509: fix CVE-2024-6119\n";
        let found = scan_changelog(text, "CVE-2024-6119").unwrap();
        assert_eq!(found.source, "");
        assert_eq!(found.installed, "");
        assert!(found.versions.is_empty());
        assert_eq!(found.lines, strings(&["* x509: fix CVE-2024-6119"]));
    }

    #[test]
    fn what_a_changelog_says_is_repeated_only_in_small_safe_pieces() {
        let long = format!("  * CVE-2024-0001 {}\n", "x".repeat(900));
        let text = format!("pkg (1.0-1) stable; urgency=medium\n\n{}", long.repeat(40));
        let found = scan_changelog(&text, "CVE-2024-0001").unwrap();
        assert_eq!(found.lines.len(), 3);
        assert!(found.lines.iter().all(|line| line.chars().count() <= 203));
        // a header that is not a plausible package and version is not taken for one
        let odd = "pkg (1.0 ; rm -rf /) stable\n  * CVE-2024-0001\nwhat (ever\n  * CVE-2024-0001\n";
        let found = scan_changelog(odd, "CVE-2024-0001").unwrap();
        assert_eq!(found.source, "");
        assert!(found.versions.is_empty());
    }

    fn gz(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(text.as_bytes()).unwrap();
        std::fs::write(path, encoder.finish().unwrap()).unwrap();
    }

    fn docs() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        gz(&root.join("openssl/changelog.Debian.gz"), OPENSSL);
        gz(&root.join("libssl3t64/changelog.Debian.gz"), OPENSSL);
        gz(
            &root.join("bash/changelog.Debian.gz"),
            "bash (5.2.21-2ubuntu4) noble; urgency=medium\n\n  * Nothing of note.\n",
        );
        // a native package: its only changelog is in Debian's format
        gz(
            &root.join("base-files/changelog.gz"),
            "base-files (13ubuntu10.1) noble; urgency=medium\n\n  * Mention CVE-2024-7777 in passing.\n",
        );
        // an upstream changelog next to a Debian one is not searched
        gz(
            &root.join("bash/changelog.gz"),
            "upstream fixed CVE-2024-6119 here\n",
        );
        std::fs::create_dir_all(root.join("no-changelog")).unwrap();
        std::fs::write(root.join("a-file"), "CVE-2024-6119").unwrap();
        dir
    }

    fn usual() -> Limits {
        Limits::usual(Duration::from_secs(20))
    }

    #[test]
    fn every_installed_packages_changelog_is_searched_and_like_findings_are_grouped() {
        let dir = docs();
        let scan = scan_docs(dir.path(), "CVE-2024-6119", usual());
        assert_eq!(scan.incomplete, Vec::<String>::new());
        assert_eq!(scan.files, 4);
        assert_eq!(scan.hits.len(), 1, "{:?}", scan.hits);
        assert_eq!(scan.hits[0].packages, strings(&["libssl3t64", "openssl"]));
        assert_eq!(scan.hits[0].mention.installed, "3.0.13-0ubuntu3.5");
        // the native package's changelog.gz is read
        let native = scan_docs(dir.path(), "CVE-2024-7777", usual());
        assert_eq!(native.hits.len(), 1);
        assert_eq!(native.hits[0].packages, strings(&["base-files"]));
        // nothing names this one
        assert!(
            scan_docs(dir.path(), "CVE-2020-0001", usual())
                .hits
                .is_empty()
        );
    }

    #[test]
    fn a_documentation_directory_that_is_a_link_is_followed() {
        let dir = docs();
        std::os::unix::fs::symlink(dir.path().join("openssl"), dir.path().join("libssl-dev"))
            .unwrap();
        let scan = scan_docs(dir.path(), "CVE-2024-6119", usual());
        assert_eq!(
            scan.hits[0].packages,
            strings(&["libssl-dev", "libssl3t64", "openssl"])
        );
    }

    #[test]
    fn a_search_that_stops_early_says_so() {
        let dir = docs();
        let few = Limits {
            max_files: 2,
            ..usual()
        };
        let scan = scan_docs(dir.path(), "CVE-2024-6119", few);
        assert_eq!(scan.files, 2);
        assert_eq!(scan.incomplete.len(), 1, "{:?}", scan.incomplete);
        assert!(
            scan.incomplete[0].contains("2 changelogs"),
            "{:?}",
            scan.incomplete
        );

        let no_time = Limits {
            time: Duration::ZERO,
            ..usual()
        };
        let scan = scan_docs(dir.path(), "CVE-2024-6119", no_time);
        assert!(scan.incomplete[0].contains("time"), "{:?}", scan.incomplete);

        // a changelog longer than is read is searched as far as that goes, and noted
        let small = Limits {
            max_bytes: 200,
            ..usual()
        };
        let scan = scan_docs(dir.path(), "CVE-2024-6119", small);
        assert!(
            scan.incomplete.iter().any(|note| note.contains("longer")),
            "{:?}",
            scan.incomplete
        );
    }

    #[test]
    fn files_that_are_not_what_they_seem_do_not_stop_the_search() {
        let dir = docs();
        let root = dir.path();
        std::fs::create_dir_all(root.join("broken")).unwrap();
        std::fs::write(root.join("broken/changelog.Debian.gz"), b"not gzip at all").unwrap();
        // a directory where a file should be
        std::fs::create_dir_all(root.join("odd/changelog.Debian.gz")).unwrap();
        // a name no package has
        gz(&root.join("we ird;name/changelog.Debian.gz"), OPENSSL);
        let scan = scan_docs(root, "CVE-2024-6119", usual());
        assert_eq!(scan.hits.len(), 1);
        assert_eq!(scan.hits[0].packages, strings(&["libssl3t64", "openssl"]));
        assert!(
            scan_docs(&root.join("missing"), "CVE-2024-6119", usual())
                .hits
                .is_empty()
        );
    }

    #[test]
    fn the_words_of_pro_fix_are_turned_into_a_verdict() {
        let cases = [
            (
                "CVE-2024-6119: OpenSSL vulnerability\n - https://ubuntu.com/security/CVE-2024-6119\n\n1 affected source package is installed: openssl\n(1/1) openssl:\nA fix is available in Ubuntu standard updates.\nThe update is already installed.\n\n✔ CVE-2024-6119 is resolved.\n",
                ProVerdict::Fixed,
            ),
            (
                "CVE-2024-6119: OpenSSL vulnerability\n\nNo affected source packages are installed.\n\n✔ CVE-2024-6119 does not affect your system.\n",
                ProVerdict::NotAffected,
            ),
            (
                "WARNING: The option --dry-run is being used.\nNo packages will be installed when running this command.\nCVE-2024-6119: OpenSSL vulnerability\n\n1 affected source package is installed: openssl\n(1/1) openssl:\nA fix is available in Ubuntu standard updates.\n{ apt update && apt install --only-upgrade -y libssl3t64 openssl }\n\n✔ CVE-2024-6119 is resolved.\n",
                ProVerdict::FixAvailable,
            ),
            (
                "CVE-2024-0001: Something\n\n1 affected source package is installed: thing\n(1/1) thing:\nSorry, no fix is available.\n\n1 package is still affected: thing\n✘ CVE-2024-0001 is not resolved.\n",
                ProVerdict::NoFix,
            ),
            (
                "usage: pro fix [flags]\nerror: unrecognized arguments: --dry-run\n",
                ProVerdict::Unclear,
            ),
            ("", ProVerdict::Unclear),
        ];
        for (text, wanted) in cases {
            assert_eq!(pro_verdict(text), wanted, "{text}");
        }
    }

    // ---- the tool ----------------------------------------------------------------------

    /// A host whose configuration allows online lookups (`package.cve_online`).
    fn fixture(fake: &FakeBins) -> (Arc<Host>, MemorySink) {
        fixture_with(fake, "[package]\ncve_online = true\n")
    }

    fn fixture_with(fake: &FakeBins, extra: &str) -> (Arc<Host>, MemorySink) {
        host(&format!(
            "[roles.reader]\nallow = [\"@read\"]\n[roles.other]\nallow = [\"system.view\"]\n\
             [unix_users.rita]\nroles = [\"reader\"]\n[unix_users.nora]\nroles = [\"other\"]\n{extra}{}",
            fake.config_only()
        ))
    }

    /// Where a test's "a reboot is needed" marker would be: not a package directory.
    fn reboot_flag(docs: &Path) -> PathBuf {
        docs.join(".reboot-required")
    }

    async fn run_in(host: &Arc<Host>, docs: &Path, user: &str, arguments: Value) -> ToolResult {
        let tool = find(
            tools_with(Paths {
                doc_root: docs.to_path_buf(),
                reboot_flags: vec![reboot_flag(docs)],
            }),
            "cve_status",
        );
        call(host, user, &tool, arguments).await
    }

    fn dpkg() -> FakeBins {
        FakeBins::new().add("dpkg-query", "", 0)
    }

    #[test]
    fn it_is_a_read_tool_under_package_view() {
        let tool = find(tools(), "cve_status");
        assert_eq!(tool.access, Access::Read);
        assert_eq!(tool.permission, "package.view");
    }

    #[tokio::test]
    async fn a_fix_named_in_an_installed_changelog_is_reported_as_fixed() {
        let fake = dpkg();
        let (host, sink) = fixture(&fake);
        let dir = docs();
        let text =
            ok_text(run_in(&host, dir.path(), "rita", json!({"cve": "cve-2024-6119"})).await);
        let first = text.lines().next().unwrap();
        assert_eq!(
            first,
            "CVE-2024-6119: FIXED: openssl 3.0.13-0ubuntu3.5 (installed) names it in its \
             changelog, which normally means the fix is in. Programs that were already running \
             use it only after a restart, and a kernel only after a reboot."
        );
        assert!(
            text.contains("named in the changelog entry for 3.0.13-0ubuntu3.4"),
            "{text}"
        );
        assert!(text.contains("packages: libssl3t64, openssl"), "{text}");
        assert!(text.contains("- CVE-2024-6119"), "{text}");
        assert!(text.contains("Based on:"), "{text}");
        // offline: no program was run
        assert!(fake.calls("dpkg-query").is_empty());
        let records = sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["decision"], "allow");
    }

    /// AIDEV-NOTE: "FIXED" is about what is installed. After an upgrade of openssl, glibc
    /// or the kernel, what is RUNNING is still the old code until services restart or
    /// the host reboots, and the first line must not read as "nothing left to do".
    #[tokio::test]
    async fn a_fixed_verdict_says_when_the_host_is_waiting_for_a_reboot() {
        let fake = dpkg();
        let (host, _sink) = fixture(&fake);
        let dir = docs();
        std::fs::write(reboot_flag(dir.path()), "*** System restart required ***\n").unwrap();
        let text =
            ok_text(run_in(&host, dir.path(), "rita", json!({"cve": "CVE-2024-6119"})).await);
        let first = text.lines().next().unwrap();
        assert!(
            first.starts_with("CVE-2024-6119: FIXED: openssl "),
            "{first}"
        );
        assert!(
            first.ends_with(
                "use it only after a restart, and a kernel only after a reboot. A reboot is \
                 pending on this host (reboot-required)."
            ),
            "{first}"
        );
        // an UNKNOWN verdict carries neither sentence
        let text =
            ok_text(run_in(&host, dir.path(), "rita", json!({"cve": "CVE-2020-0001"})).await);
        let first = text.lines().next().unwrap();
        assert!(
            !first.contains("restart") && !first.contains("reboot"),
            "{first}"
        );
    }

    #[tokio::test]
    async fn the_security_services_fixed_verdict_carries_the_same_caveat() {
        let fake = dpkg().add_script(
            "pro",
            "printf 'CVE-2020-0001: Thing\\n1 affected source package is installed: openssl\\n(1/1) openssl:\\nA fix is available in Ubuntu standard updates.\\nThe update is already installed.\\n\\n CVE-2020-0001 is resolved.\\n'",
        );
        let (host, _sink) = fixture(&fake);
        let dir = docs();
        let text = ok_text(
            run_in(
                &host,
                dir.path(),
                "rita",
                json!({"cve": "CVE-2020-0001", "online": true}),
            )
            .await,
        );
        assert_eq!(
            text.lines().next().unwrap(),
            "CVE-2020-0001: FIXED, according to the distribution's security service: the \
             update is installed. Programs that were already running use it only after a \
             restart, and a kernel only after a reboot."
        );
    }

    /// AIDEV-NOTE: a minimal image ships no changelogs at all. "No installed package's
    /// changelog names it" would then be true of every CVE there is.
    #[tokio::test]
    async fn with_no_changelog_to_read_the_first_line_says_so() {
        let fake = dpkg();
        let (host, _sink) = fixture(&fake);
        let empty = tempfile::tempdir().unwrap();
        let text =
            ok_text(run_in(&host, empty.path(), "rita", json!({"cve": "CVE-2024-6119"})).await);
        assert_eq!(
            text.lines().next().unwrap(),
            "CVE-2024-6119: UNKNOWN: not one package changelog could be read on this host, so \
             the changelogs can say nothing about it (minimal images do not ship them)."
        );
        assert!(text.contains("the 0 changelogs"), "{text}");
        // the same from the function, whatever else the scan noted
        let scan = Scan {
            incomplete: vec!["/usr/share/doc cannot be read".to_string()],
            ..Scan::default()
        };
        let (verdict, _, fixed) = changelog_report("CVE-2024-6119", &scan);
        assert!(
            verdict.contains("not one package changelog could be read"),
            "{verdict}"
        );
        assert!(!fixed);
    }

    /// AIDEV-NOTE: `online` makes the server (as root) run the vendor's tool, which
    /// contacts the vendor and, on rpm hosts, refreshes the repository cache. That is the
    /// operator's choice to make, host by host, not any package.view caller's.
    #[tokio::test]
    async fn online_is_refused_unless_the_host_allows_it() {
        let fake = dpkg().add("pro", "does not affect your system", 0);
        let (host, sink) = fixture_with(&fake, "");
        let dir = docs();
        match run_in(
            &host,
            dir.path(),
            "rita",
            json!({"cve": "CVE-2024-6119", "online": true}),
        )
        .await
        {
            Err(ToolError::Denied(message)) => {
                assert!(
                    message.contains("online lookups are off on this host (package.cve_online)"),
                    "{message}"
                );
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(fake.calls("pro").is_empty());
        let records = sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["decision"], "deny");
        assert_eq!(
            records[0]["reason"],
            "online lookups are off on this host (package.cve_online)"
        );
        // the offline answer is still there for the asking
        let text =
            ok_text(run_in(&host, dir.path(), "rita", json!({"cve": "CVE-2024-6119"})).await);
        assert!(text.starts_with("CVE-2024-6119: FIXED:"), "{text}");
        // and so is the hint, which now names the setting too
        let text =
            ok_text(run_in(&host, dir.path(), "rita", json!({"cve": "CVE-2020-0001"})).await);
        assert!(text.contains("package.cve_online"), "{text}");

        // on an rpm host too: dnf is not asked to refresh anything
        let fake = dnf("", "");
        let (host, _sink) = fixture_with(&fake, "");
        let result = run_in(
            &host,
            dir.path(),
            "rita",
            json!({"cve": "CVE-2024-6119", "online": true}),
        )
        .await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        assert!(fake.calls("dnf").is_empty());
    }

    fn hit(source: &str, version: &str, lines: &[&str]) -> Hit {
        Hit {
            packages: vec![source.to_string()],
            mention: Mention {
                source: source.to_string(),
                installed: version.to_string(),
                versions: vec![version.to_string()],
                lines: lines.iter().map(|line| line.to_string()).collect(),
            },
        }
    }

    /// AIDEV-NOTE: found on a real Ubuntu 24.04: CVE-2024-3094 (the xz backdoor) is named
    /// by 56 packages, every one of them as "No-change rebuild for CVE-2024-3094". None
    /// of them fixed anything, so that must not read as FIXED.
    #[test]
    fn a_cve_named_only_as_the_reason_for_rebuilds_is_not_reported_as_fixed() {
        let scan = Scan {
            hits: vec![
                hit(
                    "bash",
                    "5.2.21-2ubuntu4",
                    &["* No-change rebuild for CVE-2024-3094"],
                ),
                hit(
                    "dash",
                    "0.5.12-6ubuntu5",
                    &["* No change rebuild for CVE-2024-3094."],
                ),
                hit(
                    "coreutils",
                    "9.4-3ubuntu6",
                    &["* no-change rebuild for CVE-2024-3094"],
                ),
            ],
            ..Scan::default()
        };
        let (verdict, details, fixed) = changelog_report("CVE-2024-3094", &scan);
        assert!(
            verdict.starts_with("CVE-2024-3094: UNKNOWN: 3 installed packages name it only"),
            "{verdict}"
        );
        assert!(verdict.contains("rebuil"), "{verdict}");
        assert!(!verdict.contains("FIXED"), "{verdict}");
        assert!(!fixed);
        // the rebuilt packages are named on one line, not given a block each
        assert!(details.contains("bash, dash, coreutils"), "{details}");
        assert_eq!(details.matches("No-change rebuild").count(), 0, "{details}");
    }

    #[test]
    fn a_real_fix_is_reported_ahead_of_packages_that_were_only_rebuilt() {
        let scan = Scan {
            hits: vec![
                hit(
                    "bash",
                    "5.2.21-2ubuntu4",
                    &["* No-change rebuild for CVE-2024-3094"],
                ),
                hit(
                    "xz-utils",
                    "5.6.1+really5.4.5-1ubuntu0.2",
                    &["* Revert to 5.4.5 because of CVE-2024-3094"],
                ),
                hit(
                    "dash",
                    "0.5.12-6ubuntu5",
                    &["* No-change rebuild for CVE-2024-3094"],
                ),
            ],
            ..Scan::default()
        };
        let (verdict, details, fixed) = changelog_report("CVE-2024-3094", &scan);
        assert_eq!(
            verdict,
            "CVE-2024-3094: FIXED: xz-utils 5.6.1+really5.4.5-1ubuntu0.2 (installed) names it \
             in its changelog, which normally means the fix is in."
        );
        assert!(fixed);
        assert!(details.contains("Revert to 5.4.5"), "{details}");
        assert!(
            details.contains("2 other packages name it only as the reason for a rebuild"),
            "{details}"
        );
        assert!(details.contains("bash, dash"), "{details}");
    }

    #[test]
    fn a_line_that_names_a_rebuild_and_a_fix_counts_as_a_fix() {
        assert!(only_rebuilt(
            &hit("a", "1", &["* No-change rebuild for CVE-2024-3094"]).mention
        ));
        assert!(only_rebuilt(
            &hit(
                "a",
                "1",
                &["* No change rebuild against the fixed xz (CVE-2024-3094)"]
            )
            .mention
        ));
        // nothing quoted: nothing says it was only a rebuild
        assert!(!only_rebuilt(&hit("a", "1", &[]).mention));
        assert!(!only_rebuilt(
            &hit("a", "1", &["- CVE-2024-3094: fix the backdoor"]).mention
        ));
        assert!(!only_rebuilt(
            &hit(
                "a",
                "1",
                &[
                    "* No-change rebuild for CVE-2024-3094",
                    "- CVE-2024-3094: also patch x"
                ]
            )
            .mention
        ));
    }

    #[tokio::test]
    async fn nothing_found_is_unknown_and_says_why_that_is_all_that_can_be_said() {
        let fake = dpkg();
        let (host, _sink) = fixture(&fake);
        let dir = docs();
        let text =
            ok_text(run_in(&host, dir.path(), "rita", json!({"cve": "CVE-2020-0001"})).await);
        assert!(
            text.starts_with("CVE-2020-0001: UNKNOWN: no installed package's changelog names it."),
            "{text}"
        );
        assert!(text.contains("not affected or not yet fixed"), "{text}");
        assert!(text.contains("4 changelogs"), "{text}");
        assert!(text.contains("online"), "{text}");
    }

    #[tokio::test]
    async fn online_asks_pro_with_dry_run_and_takes_its_verdict() {
        let fake = dpkg().add_script(
            "pro",
            "printf 'CVE-2020-0001: Thing\\n\\nNo affected source packages are installed.\\n\\n\\342\\234\\224 CVE-2020-0001 does not affect your system.\\n'",
        );
        let (host, _sink) = fixture(&fake);
        let dir = docs();
        let text = ok_text(
            run_in(
                &host,
                dir.path(),
                "rita",
                json!({"cve": "CVE-2020-0001", "online": true}),
            )
            .await,
        );
        assert!(
            text.starts_with(
                "CVE-2020-0001: NOT AFFECTED, according to the distribution's security service."
            ),
            "{text}"
        );
        assert!(
            text.contains("No affected source packages are installed."),
            "{text}"
        );
        // AIDEV-NOTE: without --dry-run, `pro fix` would install packages.
        assert_eq!(
            fake.calls("pro"),
            vec![strings(&["fix", "--dry-run", "CVE-2020-0001"])]
        );
    }

    #[tokio::test]
    async fn online_finding_a_pending_fix_says_affected() {
        let fake = dpkg().add_script(
            "pro",
            "printf '1 affected source package is installed: openssl\\n(1/1) openssl:\\nA fix is available in Ubuntu standard updates.\\n{ apt update && apt install --only-upgrade -y openssl }\\n'",
        );
        let (host, _sink) = fixture(&fake);
        let dir = docs();
        let text = ok_text(
            run_in(
                &host,
                dir.path(),
                "rita",
                json!({"cve": "CVE-2020-0001", "online": true}),
            )
            .await,
        );
        assert!(
            text.starts_with("CVE-2020-0001: AFFECTED: a fix is available and is not installed"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn online_without_pro_or_with_an_unclear_answer_keeps_the_offline_verdict() {
        let dir = docs();
        let fake = dpkg();
        let (host, _sink) = fixture(&fake);
        let text = ok_text(
            run_in(
                &host,
                dir.path(),
                "rita",
                json!({"cve": "CVE-2024-6119", "online": true}),
            )
            .await,
        );
        assert!(text.starts_with("CVE-2024-6119: FIXED:"), "{text}");
        assert!(text.contains("pro is not installed"), "{text}");

        let fake = dpkg().add_script(
            "pro",
            "echo 'error: unrecognized arguments: --dry-run' >&2\nexit 2",
        );
        let (host, _sink) = fixture(&fake);
        let text = ok_text(
            run_in(
                &host,
                dir.path(),
                "rita",
                json!({"cve": "CVE-2024-6119", "online": true}),
            )
            .await,
        );
        assert!(text.starts_with("CVE-2024-6119: FIXED:"), "{text}");
        assert!(text.contains("unrecognized arguments"), "{text}");
    }

    #[tokio::test]
    async fn offline_never_runs_pro() {
        let fake = dpkg().add("pro", "does not affect your system", 0);
        let (host, _sink) = fixture(&fake);
        let dir = docs();
        ok_text(run_in(&host, dir.path(), "rita", json!({"cve": "CVE-2024-6119"})).await);
        assert!(fake.calls("pro").is_empty());
    }

    fn dnf(pending: &str, installed: &str) -> FakeBins {
        FakeBins::new().add("rpm", "", 0).add_script(
            "dnf",
            &format!(
                "for a in \"$@\"; do if [ \"$a\" = --installed ]; then printf '%s' '{installed}'; exit 0; fi; done\nprintf '%s' '{pending}'"
            ),
        )
    }

    #[tokio::test]
    async fn on_an_rpm_host_dnf_answers_from_its_cache() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dnf(
            "RHSA-2024:6783 Important/Sec. openssl-libs-1:3.0.7-28.el9_4.x86_64\n",
            "",
        );
        let (host, _sink) = fixture(&fake);
        let text =
            ok_text(run_in(&host, dir.path(), "rita", json!({"cve": "CVE-2024-6119"})).await);
        assert!(
            text.starts_with(
                "CVE-2024-6119: AFFECTED: an update that fixes it is available and is not installed"
            ),
            "{text}"
        );
        assert!(text.contains("RHSA-2024:6783"), "{text}");
        assert_eq!(
            fake.calls("dnf"),
            vec![
                strings(&["-q", "-C", "updateinfo", "list", "--cve", "CVE-2024-6119"]),
                strings(&[
                    "-q",
                    "-C",
                    "updateinfo",
                    "list",
                    "--installed",
                    "--cve",
                    "CVE-2024-6119"
                ]),
            ]
        );

        let fake = dnf(
            "",
            "RHSA-2024:6783 Important/Sec. openssl-libs-1:3.0.7-28.el9_4.x86_64\n",
        );
        let (host, _sink) = fixture(&fake);
        let text =
            ok_text(run_in(&host, dir.path(), "rita", json!({"cve": "CVE-2024-6119"})).await);
        assert!(
            text.starts_with(
                "CVE-2024-6119: FIXED: the update that fixes it is installed. Programs that \
                 were already running use it only after a restart, and a kernel only after a \
                 reboot.\n"
            ),
            "{text}"
        );

        let fake = dnf("", "");
        let (host, _sink) = fixture(&fake);
        let text = ok_text(
            run_in(
                &host,
                dir.path(),
                "rita",
                json!({"cve": "CVE-2024-6119", "online": true}),
            )
            .await,
        );
        assert!(text.starts_with("CVE-2024-6119: UNKNOWN:"), "{text}");
        // online: the cache-only flag is dropped
        assert_eq!(
            fake.calls("dnf")[0],
            strings(&["-q", "updateinfo", "list", "--cve", "CVE-2024-6119"])
        );
    }

    #[tokio::test]
    async fn dnf_failing_is_a_failure_not_an_all_clear() {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeBins::new().add("rpm", "", 0).add_script(
            "dnf",
            "echo 'Error: Cache-only enabled but no cache for baseos' >&2\nexit 1",
        );
        let (host, _sink) = fixture(&fake);
        let result = run_in(&host, dir.path(), "rita", json!({"cve": "CVE-2024-6119"}))
            .await
            .unwrap();
        assert!(result.is_error());
        assert!(
            result.text().starts_with("CVE-2024-6119: UNKNOWN:"),
            "{}",
            result.text()
        );
        assert!(
            result.text().contains("no cache for baseos"),
            "{}",
            result.text()
        );
    }

    #[tokio::test]
    async fn an_id_that_is_not_a_cve_is_refused_before_anything_else() {
        let fake = dpkg().add("pro", "", 0);
        let (host, sink) = fixture(&fake);
        let dir = docs();
        for bad in ["CVE-2024-6119; id", "--help", "openssl"] {
            match run_in(
                &host,
                dir.path(),
                "rita",
                json!({"cve": bad, "online": true}),
            )
            .await
            {
                Err(ToolError::Invalid(_)) => {}
                other => panic!("{bad}: expected invalid arguments, got {other:?}"),
            }
        }
        assert!(fake.calls("pro").is_empty());
        assert!(sink.records().is_empty());
    }

    #[tokio::test]
    async fn it_needs_package_view_and_a_package_manager() {
        let fake = dpkg();
        let (host, _sink) = fixture(&fake);
        let dir = docs();
        match run_in(&host, dir.path(), "nora", json!({"cve": "CVE-2024-6119"})).await {
            Err(ToolError::Denied(message)) => {
                assert!(message.contains("package.view"), "{message}")
            }
            other => panic!("expected a denial, got {other:?}"),
        }
        let fake = FakeBins::new();
        let (host, _sink) = fixture(&fake);
        match run_in(&host, dir.path(), "rita", json!({"cve": "CVE-2024-6119"})).await {
            Err(ToolError::Failed(message)) => {
                assert!(message.contains("dpkg or rpm"), "{message}")
            }
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_output_stays_within_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        for n in 0..300 {
            gz(
                &dir.path().join(format!("pkg{n}/changelog.Debian.gz")),
                &format!(
                    "src{n} (1.{n}-1) stable; urgency=medium\n\n  * Fix CVE-2024-0001 in a way that takes a good many words to describe, {n}.\n"
                ),
            );
        }
        let fake = dpkg();
        let (host, _sink) = host(&format!(
            "[roles.reader]\nallow = [\"@read\"]\n[unix_users.rita]\nroles = [\"reader\"]\n[limits]\nmax_output_bytes = 4096\n{}",
            fake.config_only()
        ));
        let text =
            ok_text(run_in(&host, dir.path(), "rita", json!({"cve": "CVE-2024-0001"})).await);
        assert!(text.len() <= 4096, "{}", text.len());
        assert!(text.starts_with("CVE-2024-0001: FIXED:"), "{text}");
        assert!(text.contains("and 299 other source packages"), "{text}");
        assert!(text.contains("left out to fit the output limit"), "{text}");
    }
}
