//! Packages: what is installed, what is pending, and applying updates.
//!
//! Two families are supported: dpkg with apt (Debian, Ubuntu) and rpm with dnf, or yum
//! where there is no dnf. Which one a host has is decided by the programs found on it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, UNIX_EPOCH};

use super::args::{Args, Param};
use super::{
    Authorized, Ctx, Tool, ToolError, ToolResult, blocking, command_ok, command_text,
    command_text_tail, format_table, required,
};
use crate::exec::{Cmd, CmdOutput};
use crate::policy::Access;
use crate::sanitize::keep_head;
use crate::timefmt::{human_duration, now_secs, rfc3339_utc};

const QUERY_ACTIONS: [&str; 5] = ["info", "list", "files", "owner", "verify"];

/// Where package_updates reads its facts from. Tests point these at a temporary
/// directory.
#[derive(Clone, Debug)]
pub struct Paths {
    /// Exists when an installed update needs a reboot (Debian, Ubuntu).
    pub reboot_required: PathBuf,
    /// The packages that asked for that reboot, one per line.
    pub reboot_required_pkgs: PathBuf,
    /// Touched by apt each time the package lists are refreshed successfully.
    pub lists_stamp: PathBuf,
    /// The package lists themselves: used when there is no stamp.
    pub lists_dir: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Paths {
            reboot_required: PathBuf::from("/var/run/reboot-required"),
            reboot_required_pkgs: PathBuf::from("/var/run/reboot-required.pkgs"),
            lists_stamp: PathBuf::from("/var/lib/apt/periodic/update-success-stamp"),
            lists_dir: PathBuf::from("/var/lib/apt/lists"),
        }
    }
}

pub fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "package_query",
            "Look up installed packages (dpkg on Debian and Ubuntu, rpm elsewhere). info \
             shows one package's version and status; list shows the installed packages \
             whose name matches a pattern such as 'nginx*'; files shows what a package \
             installed; owner shows which package a file belongs to; verify shows which of \
             a package's files differ from what was installed.",
            Access::Read,
            "package.view",
            vec![
                Param::choice("action", "What to look up", &QUERY_ACTIONS).required(),
                Param::str(
                    "name",
                    "Package name (info, files, verify), or a pattern with * and ? for list \
                     (default: every package)",
                )
                .max_len(128),
                Param::str("path", "For owner: the absolute path of a file").max_len(4096),
            ],
            package_query,
        ),
        Tool::new(
            "package_updates",
            "Show the package updates that are pending on this host: package, installed and \
             available version, and which are security updates; plus held packages, \
             whether a reboot is required and, where needrestart is installed, which \
             services still run outdated code. It works from the package lists as last \
             refreshed and never refreshes them itself (package_upgrade with refresh does).",
            Access::Read,
            "package.view",
            vec![Param::bool(
                "security_only",
                "Show only the security updates",
            )],
            |ctx, args| package_updates_at(ctx, args, Paths::default()),
        ),
        Tool::new(
            "package_upgrade",
            "Upgrade installed packages: the named ones, or everything pending with all. \
             Only packages that are installed already can be named; an upgrade may bring in \
             new packages it depends on. On apt hosts it never removes a package (an update \
             that would need one removed stays pending) and configuration files that were \
             changed locally are kept; on dnf hosts dnf's own upgrade rules apply, which \
             can replace an obsoleted package and remove old kernels. refresh updates the \
             package lists first; dry_run shows what would happen without changing \
             anything. A real run \
             is started as its own systemd unit so that it cannot be cut off half way: if \
             it takes longer than this call may, the call returns the unit's name and the \
             upgrade carries on.",
            Access::Write,
            "package.modify",
            vec![
                Param::list("packages", "Names of the installed packages to upgrade"),
                Param::bool("all", "Upgrade every package that has an update pending"),
                Param::bool(
                    "refresh",
                    "Refresh the package lists first (alone: only refresh them)",
                ),
                Param::bool(
                    "dry_run",
                    "Only show what would be upgraded; change nothing",
                ),
            ],
            package_upgrade,
        ),
    ]
}

/// Checks a package name: letters, digits and `+ . _ : -`, starting with a letter or a
/// digit. With `patterns`, `*` and `?` are allowed too (and may come first).
///
/// AIDEV-NOTE: this keeps out anything the package tools would read as an option (a
/// leading `-`), as a version or release selector (`=`, `/`), or as a pattern where a
/// single package is meant.
pub fn check_name(name: &str, patterns: bool) -> Result<(), ToolError> {
    let plain = |c: char| c.is_ascii_alphanumeric() || "+._:-".contains(c);
    let wild = |c: char| patterns && (c == '*' || c == '?');
    let first_ok = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric() || wild(c));
    if !first_ok || name.len() > 128 || !name.chars().all(|c| plain(c) || wild(c)) {
        let extra = if patterns {
            "; a pattern may also use * and ?"
        } else {
            ""
        };
        return Err(ToolError::Invalid(format!(
            "{name:?} is not a package name (letters, digits and + . _ : - only, starting \
             with a letter or a digit{extra})"
        )));
    }
    Ok(())
}

/// Checks the path given to `owner`: absolute, and free of the characters the package
/// tools would read as a pattern.
pub fn check_owner_path(path: &str) -> Result<(), ToolError> {
    if !path.starts_with('/') || path.contains(['*', '?', '[', ']', '\\']) {
        return Err(ToolError::Invalid(format!(
            "{path:?} must be the absolute path of one file, without wildcards"
        )));
    }
    Ok(())
}

/// A name that is safe to show in a unit description or a message to logged-in users:
/// anything but letters, digits and `_ . : @ -` becomes `_`.
pub fn plain_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "_.:@-".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// The start of a small file (at most `max` bytes), or `None` if it cannot be read.
pub fn read_small(path: &Path, max: u64) -> Option<String> {
    use std::io::Read;
    let mut data = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(max)
        .read_to_end(&mut data)
        .ok()?;
    Some(String::from_utf8_lossy(&data).into_owned())
}

/// One update that apt would install.
#[derive(Debug, PartialEq, Eq)]
pub struct Pending {
    pub name: String,
    /// `None` for a package that is not installed yet (a new dependency).
    pub installed: Option<String>,
    pub available: String,
    pub security: bool,
}

/// Parses one `Inst` line of `apt-get -s` output:
/// `Inst NAME [INSTALLED] (AVAILABLE ORIGIN, ORIGIN... [ARCH])`.
pub fn parse_inst(line: &str) -> Option<Pending> {
    let rest = line.strip_prefix("Inst ")?;
    let (name, rest) = rest.split_once(' ')?;
    let rest = rest.trim_start();
    let (installed, rest) = match rest.strip_prefix('[') {
        Some(after) => {
            let (installed, after) = after.split_once(']')?;
            (Some(installed.to_string()), after.trim_start())
        }
        None => (None, rest),
    };
    let (candidate, _) = rest.strip_prefix('(')?.split_once(')')?;
    let (available, origin) = candidate.split_once(' ').unwrap_or((candidate, ""));
    if name.is_empty() || available.is_empty() {
        return None;
    }
    // Ubuntu: "Ubuntu:22.04/jammy-security"; Debian: "Debian-Security:12/stable-security".
    let origin = origin.to_ascii_lowercase();
    Some(Pending {
        name: name.to_string(),
        installed,
        available: available.to_string(),
        security: origin.contains("-security") || origin.contains("debian-security"),
    })
}

/// What a simulated `apt-get dist-upgrade` would install, and what it would remove.
pub fn parse_simulation(text: &str) -> (Vec<Pending>, Vec<String>) {
    let mut pending = Vec::new();
    let mut removals = Vec::new();
    for line in text.lines() {
        if let Some(update) = parse_inst(line) {
            pending.push(update);
        } else if let Some(name) = line
            .strip_prefix("Remv ")
            .and_then(|rest| rest.split_whitespace().next())
        {
            removals.push(name.to_string());
        }
    }
    (pending, removals)
}

/// The rows of `dpkg-query -W` output (name, version, status) for packages that are, or
/// were, installed: entries dpkg merely knows the name of are left out.
pub fn installed_rows(listing: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    for line in listing.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        let [name, version, status] = fields.as_slice() else {
            continue;
        };
        let status = status.trim();
        // The second letter is the state: `n` is "not installed".
        if name.is_empty() || matches!(status.chars().nth(1), None | Some('n')) {
            continue;
        }
        rows.push(vec![
            name.to_string(),
            version.to_string(),
            status.to_string(),
        ]);
    }
    rows
}

/// The names that a `NAME<TAB>STATUS` listing reports as installed.
pub fn installed_names(listing: &str) -> BTreeSet<String> {
    listing
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .filter(|(_, status)| status.trim() == "installed")
        .map(|(name, _)| name.to_string())
        .collect()
}

/// What `needrestart -b` found, as sentences. Empty if the text is not its batch output.
pub fn needrestart_lines(text: &str) -> Vec<String> {
    let mut seen = false;
    let (mut running, mut expected, mut state) = (None, None, None);
    let mut services = Vec::new();
    for line in text.lines() {
        let Some((key, value)) = line
            .strip_prefix("NEEDRESTART-")
            .and_then(|rest| rest.split_once(':'))
        else {
            continue;
        };
        seen = true;
        let value = value.trim();
        match key {
            "KCUR" => running = Some(value),
            "KEXP" => expected = Some(value),
            "KSTA" => state = Some(value),
            "SVC" => services.push(value),
            _ => {}
        }
    }
    if !seen {
        return Vec::new();
    }
    let mut lines = Vec::new();
    match (state, running, expected) {
        (Some("1"), Some(running), _) => lines.push(format!(
            "Kernel: the newest installed kernel is running ({running})."
        )),
        (Some("2" | "3"), Some(running), Some(expected)) => lines.push(format!(
            "Kernel: {running} is running but {expected} is installed: a reboot is needed to use it."
        )),
        _ => {}
    }
    if services.is_empty() {
        lines.push("No service is running outdated code.".to_string());
    } else {
        let shown: Vec<&str> = services.iter().copied().take(40).collect();
        let more = match services.len() - shown.len() {
            0 => String::new(),
            more => format!(" and {more} more"),
        };
        lines.push(format!(
            "Services still running outdated code ({}): {}{more}",
            services.len(),
            shown.join(", ")
        ));
    }
    lines
}

/// The name of the systemd unit for one package run.
pub fn unit_name(unix_secs: i64, random: [u8; 2]) -> String {
    format!("opsmcp-pkg-{unix_secs}-{:02x}{:02x}", random[0], random[1])
}

/// Which package tools a host has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    /// dpkg and apt: Debian, Ubuntu.
    Apt,
    /// rpm with dnf or yum.
    Rpm,
}

fn family(ctx: &Ctx) -> Result<Family, ToolError> {
    if ctx.bins().find("dpkg-query").is_ok() {
        Ok(Family::Apt)
    } else if ctx.bins().find("rpm").is_ok() {
        Ok(Family::Rpm)
    } else {
        Err(ToolError::Failed(
            "no supported package manager (dpkg or rpm) was found on this host".to_string(),
        ))
    }
}

/// `dnf`, or `yum` on a host that has no dnf.
fn dnf_name(ctx: &Ctx) -> Result<&'static str, ToolError> {
    ["dnf", "yum"]
        .into_iter()
        .find(|name| ctx.bins().find(name).is_ok())
        .ok_or_else(|| ToolError::Failed("neither dnf nor yum was found on this host".to_string()))
}

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// `text`, cut to the output limit at a line end, with a note if anything was cut.
fn fit(ctx: &Ctx, text: &str) -> String {
    let (kept, dropped) = keep_head(text, ctx.output_budget().saturating_sub(160));
    if dropped == 0 {
        return kept;
    }
    format!("{kept}[{dropped} more lines left out to fit the output limit; narrow the query]\n")
}

const DPKG_INFO_FORMAT: &str = "-f=Package: ${Package}\\nVersion: ${Version}\\nArchitecture: ${Architecture}\\nStatus: ${db:Status-Status}\\nSummary: ${binary:Summary}\\n\\n";
const DPKG_LIST_FORMAT: &str = "-f=${Package}\\t${Version}\\t${db:Status-Abbrev}\\n";
const DPKG_INSTALLED_FORMAT: &str = "-f=${Package}\\t${db:Status-Status}\\n";
const RPM_LIST_FORMAT: &str = "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n";
const RPM_NAME_FORMAT: &str = "%{NAME}\\n";

/// The program and arguments for one lookup. `subject` (a checked name, pattern or
/// path) always comes last, after `--`.
fn query_command(family: Family, action: &str, subject: &str) -> (&'static str, Vec<String>) {
    let (program, options): (&'static str, &[&str]) = match (family, action) {
        (Family::Apt, "info") => ("dpkg-query", &["-W", DPKG_INFO_FORMAT]),
        (Family::Apt, "list") => ("dpkg-query", &["-W", DPKG_LIST_FORMAT]),
        (Family::Apt, "files") => ("dpkg-query", &["-L"]),
        (Family::Apt, "owner") => ("dpkg-query", &["-S"]),
        (Family::Apt, _) => ("dpkg", &["--verify"]),
        (Family::Rpm, "info") => ("rpm", &["-qi"]),
        (Family::Rpm, "list") => ("rpm", &["-qa", "--qf", RPM_LIST_FORMAT]),
        (Family::Rpm, "files") => ("rpm", &["-ql"]),
        (Family::Rpm, "owner") => ("rpm", &["-qf"]),
        (Family::Rpm, _) => ("rpm", &["-V"]),
    };
    let mut argv = strings(options);
    argv.push("--".to_string());
    argv.push(subject.to_string());
    (program, argv)
}

async fn run_query(
    ctx: &Ctx,
    family: Family,
    action: &str,
    subject: &str,
) -> Result<CmdOutput, ToolError> {
    let (program, argv) = query_command(family, action, subject);
    ctx.run(ctx.command(program)?.args(argv)).await
}

/// The installed packages of a listing as a table, or a sentence if there are none.
fn list_table(family: Family, listing: &str, pattern: &str) -> String {
    let (rows, last_column, legend) = match family {
        Family::Apt => (
            installed_rows(listing),
            "STATUS",
            "; STATUS ii = installed, rc = removed but its configuration remains, hi = held",
        ),
        Family::Rpm => {
            let mut rows: Vec<Vec<String>> = listing
                .lines()
                .map(|line| line.split('\t').map(str::to_string).collect::<Vec<_>>())
                .filter(|fields| fields.len() == 3)
                .collect();
            rows.sort();
            (rows, "ARCH", "")
        }
    };
    if rows.is_empty() {
        return format!("No installed package matches {pattern}.\n");
    }
    let plural = if rows.len() == 1 { "" } else { "s" };
    let mut text = format_table(&["PACKAGE", "VERSION", last_column], &rows, &[false; 3]);
    text.push_str(&format!("[{} package{plural}{legend}]\n", rows.len()));
    text
}

async fn package_query(ctx: Ctx, args: Args) -> ToolResult {
    let action = required(&args, "action")?.to_string();
    let name = args.str("name");
    let path = args.str("path");
    let subject = match (action.as_str(), name, path) {
        ("owner", None, Some(path)) => {
            check_owner_path(path)?;
            path.to_string()
        }
        ("owner", ..) => {
            return Err(ToolError::Invalid(
                "owner takes path (the absolute path of a file) and no name".to_string(),
            ));
        }
        (_, _, Some(_)) => {
            return Err(ToolError::Invalid(
                "path is only used with action=owner".to_string(),
            ));
        }
        ("list", name, None) => {
            let pattern = name.unwrap_or("*");
            check_name(pattern, true)?;
            pattern.to_string()
        }
        (_, Some(name), None) => {
            check_name(name, false)?;
            name.to_string()
        }
        (_, None, None) => {
            return Err(ToolError::Invalid(format!(
                "{action} needs name: the package to look up"
            )));
        }
    };
    let auth = ctx.authorize(None)?;
    let family = family(&ctx)?;
    let mut out = run_query(&ctx, family, &action, &subject).await?;

    // AIDEV-NOTE: /bin, /sbin and /lib are links into /usr on current systems, and the
    // package database lists a file under only one of the two names. When the path as
    // written has no owner, the path it really is gets one try as well.
    if action == "owner" && !command_ok(&out) && !out.timed_out {
        let asked = subject.clone();
        let real = blocking(ctx.clone(), move || {
            Ok(std::fs::canonicalize(&asked)
                .ok()
                .and_then(|real| real.to_str().map(str::to_string))
                .filter(|real| *real != asked && check_owner_path(real).is_ok()))
        })
        .await?;
        if let Some(real) = real {
            let second = run_query(&ctx, family, &action, &real).await?;
            if command_ok(&second) {
                out = second;
            }
        }
    }

    // AIDEV-NOTE: dpkg-query and rpm exit 1 for "no such package", "no package owns
    // this" and (rpm -V) "files differ". That is the answer to the question, with the
    // explanation in the output; 2 and above mean the query itself went wrong.
    let answered_no = out.code == Some(1) && !out.timed_out;
    if answered_no {
        out.code = Some(0);
    }
    let succeeded = command_ok(&out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let silent = stdout.trim().is_empty() && out.stderr.iter().all(u8::is_ascii_whitespace);
    let text = match action.as_str() {
        // AIDEV-NOTE: one sentence of our own, not the package manager's words. rpm
        // tells "there is no such file" apart from "no package owns that file", which
        // would let a caller with only package.view find out which paths exist.
        "owner" if answered_no => format!("No installed package owns {subject}.\n"),
        "list" if succeeded => list_table(family, &stdout, &subject),
        "verify" if succeeded && silent => {
            format!("No file of {subject} differs from what the package installed.\n")
        }
        "verify" if succeeded => format!(
            "{}[each line: what differs (5 = content, ? = could not be checked), c for a \
             configuration file, then the file]\n",
            command_text(&out)
        ),
        _ => command_text(&out),
    };
    auth.done(fit(&ctx, &text), succeeded)
}

/// What package_updates reads from files.
struct Facts {
    reboot_required: bool,
    reboot_packages: Vec<String>,
    /// When the package lists were last refreshed (Unix seconds), if that can be told.
    lists_refreshed: Option<i64>,
}

fn read_facts(paths: &Paths) -> Facts {
    let mut reboot_packages: Vec<String> = Vec::new();
    for line in read_small(&paths.reboot_required_pkgs, 64 * 1024)
        .unwrap_or_default()
        .lines()
    {
        let name = line.trim();
        if !name.is_empty()
            && reboot_packages.len() < 20
            && !reboot_packages.iter().any(|p| p == name)
        {
            reboot_packages.push(name.to_string());
        }
    }
    let modified = |path: &Path| {
        let time = std::fs::metadata(path).ok()?.modified().ok()?;
        i64::try_from(time.duration_since(UNIX_EPOCH).ok()?.as_secs()).ok()
    };
    Facts {
        reboot_required: paths.reboot_required.exists(),
        reboot_packages,
        lists_refreshed: modified(&paths.lists_stamp).or_else(|| modified(&paths.lists_dir)),
    }
}

async fn apt_updates(ctx: &Ctx, auth: Authorized, paths: Paths, security_only: bool) -> ToolResult {
    // A simulation: it changes nothing, takes no lock, and works for any user.
    let simulation = ctx
        .run(
            ctx.command("apt-get")?
                .args(["-s", "-o", "Debug::NoLocking=true", "dist-upgrade"]),
        )
        .await?;
    if !command_ok(&simulation) {
        let mut text = command_text(&simulation);
        text.push_str("apt could not work out what is pending.\n");
        return auth.failed(fit(ctx, &text));
    }
    let (pending, removals) = parse_simulation(&String::from_utf8_lossy(&simulation.stdout));

    let mut summary = String::new();
    let mut table = String::new();
    if pending.is_empty() {
        summary.push_str("No updates are pending.\n");
    } else {
        let security = match pending.iter().filter(|update| update.security).count() {
            0 => "none is a security update".to_string(),
            1 => "1 is a security update".to_string(),
            count => format!("{count} are security updates"),
        };
        summary.push_str(&format!(
            "Pending updates: {}, of which {security}.\n",
            pending.len()
        ));
        let rows: Vec<Vec<String>> = pending
            .iter()
            .filter(|update| update.security || !security_only)
            .map(|update| {
                vec![
                    update.name.clone(),
                    update
                        .installed
                        .clone()
                        .unwrap_or_else(|| "(new)".to_string()),
                    update.available.clone(),
                    if update.security { "yes" } else { "-" }.to_string(),
                ]
            })
            .collect();
        if !rows.is_empty() {
            let headers = ["PACKAGE", "INSTALLED", "AVAILABLE", "SECURITY"];
            table = format_table(&headers, &rows, &[false; 4]);
        }
    }

    let mut notes = String::new();
    if simulation.truncated {
        notes.push_str(
            "[apt printed more than is read: more updates may be pending than are counted here]\n",
        );
    }
    if security_only && !pending.is_empty() {
        notes.push_str("[showing only the security updates]\n");
    }
    if !removals.is_empty() {
        notes.push_str(&format!(
            "A full upgrade would also remove: {} (package_upgrade does not remove packages here, so the updates that need this stay pending).\n",
            removals.join(", ")
        ));
    }
    match ctx.optional_command("apt-mark") {
        Ok(Some(apt_mark)) => {
            let out = ctx.run(apt_mark.args(["showhold"])).await?;
            let listing = String::from_utf8_lossy(&out.stdout);
            let held: Vec<&str> = listing
                .lines()
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .take(50)
                .collect();
            if !command_ok(&out) {
                notes.push_str("[held packages were not checked: apt-mark showhold failed]\n");
            } else if !held.is_empty() {
                notes.push_str(&format!("Held back: {}\n", held.join(", ")));
            }
        }
        Ok(None) => {
            notes.push_str("[held packages were not checked: apt-mark is not installed]\n");
        }
        Err(ToolError::Failed(why)) => {
            notes.push_str(&format!("[held packages were not checked: {why}]\n"));
        }
        Err(other) => return Err(other),
    }
    let facts = blocking(ctx.clone(), move || Ok(read_facts(&paths))).await?;
    notes.push_str(
        &match (facts.reboot_required, facts.reboot_packages.is_empty()) {
            (false, _) => "Reboot required: no\n".to_string(),
            (true, true) => "Reboot required: yes\n".to_string(),
            (true, false) => format!(
                "Reboot required: yes ({})\n",
                facts.reboot_packages.join(", ")
            ),
        },
    );
    match ctx.optional_command("needrestart") {
        Ok(Some(needrestart)) => {
            // batch output, list only: it restarts nothing
            let out = ctx.run(needrestart.args(["-b", "-r", "l"])).await?;
            if out.timed_out {
                notes.push_str("[needrestart did not finish in time]\n");
            }
            for line in needrestart_lines(&String::from_utf8_lossy(&out.stdout)) {
                notes.push_str(&line);
                notes.push('\n');
            }
        }
        Ok(None) => notes.push_str(
            "[services needing a restart were not checked: needrestart is not installed]\n",
        ),
        Err(ToolError::Failed(why)) => notes.push_str(&format!(
            "[services needing a restart were not checked: {why}]\n"
        )),
        Err(other) => return Err(other),
    }
    match facts.lists_refreshed {
        Some(at) => {
            let age = u64::try_from(now_secs().saturating_sub(at)).unwrap_or(0);
            notes.push_str(&format!(
                "Package lists last refreshed {} ago ({}).\n",
                human_duration(age),
                rfc3339_utc(at)
            ));
            if age > 86_400 {
                notes.push_str(
                    "[the package lists are more than a day old, so newer updates may be \
                     missing here: package_upgrade with refresh updates them]\n",
                );
            }
        }
        None => notes.push_str("It is not known when the package lists were last refreshed.\n"),
    }

    // The table is the part that can be long: cut it, never the notes.
    let room = ctx
        .output_budget()
        .saturating_sub(summary.len() + notes.len() + 160);
    let (table, dropped) = keep_head(&table, room);
    let mut text = summary;
    text.push_str(&table);
    if dropped > 0 {
        text.push_str(&format!(
            "[{dropped} more updates left out to fit the output limit]\n"
        ));
    }
    text.push_str(&notes);
    auth.ok(text)
}

async fn rpm_updates(ctx: &Ctx, auth: Authorized, security_only: bool) -> ToolResult {
    let manager = dnf_name(ctx)?;
    // -C: answer from the cache. Refreshing it is a change, which this tool never makes.
    let mut argv = strings(&["-q", "-C", "check-update"]);
    if security_only {
        argv.push("--security".to_string());
    }
    let out = ctx.run(ctx.command(manager)?.args(argv)).await?;
    let listing = String::from_utf8_lossy(&out.stdout);
    let mut text = match out.code {
        Some(0) if !out.timed_out => "No updates are pending.\n".to_string(),
        // check-update exits 100 when there are updates
        Some(100) if !out.timed_out => {
            let count = listing
                .lines()
                .take_while(|line| !line.starts_with("Obsoleting"))
                .filter(|line| line.split_whitespace().count() == 3)
                .count();
            let only = if security_only {
                "[showing only the security updates]\n"
            } else {
                ""
            };
            let room = ctx.output_budget().saturating_sub(1024);
            let (kept, dropped) = keep_head(listing.trim_start_matches('\n'), room);
            let cut = match dropped {
                0 => String::new(),
                dropped => format!("[{dropped} more lines left out to fit the output limit]\n"),
            };
            format!("Pending updates: {count}\n{kept}{cut}{only}")
        }
        _ => {
            let mut text = command_text(&out);
            text.push_str(&format!(
                "{manager} could not tell from its cache what is pending; package_upgrade \
                 with refresh fills the cache.\n"
            ));
            return auth.failed(fit(ctx, &text));
        }
    };
    if let Ok(needs_restarting) = ctx.command("needs-restarting") {
        // exits 1 when a reboot is needed: the sentence it prints is the answer
        let out = ctx.run(needs_restarting.args(["-r"])).await?;
        let (said, _) = keep_head(&String::from_utf8_lossy(&out.stdout), 1024);
        text.push_str(&said);
    }
    auth.ok(text)
}

pub async fn package_updates_at(ctx: Ctx, args: Args, paths: Paths) -> ToolResult {
    let security_only = args.bool("security_only") == Some(true);
    let auth = ctx.authorize(None)?;
    match family(&ctx)? {
        Family::Apt => apt_updates(&ctx, auth, paths, security_only).await,
        Family::Rpm => rpm_updates(&ctx, auth, security_only).await,
    }
}

/// Environment for apt: never stop to ask a question (there is nobody to answer), and
/// leave restarting services to the operator.
fn apt_env() -> Vec<(String, String)> {
    [
        ("DEBIAN_FRONTEND", "noninteractive"),
        ("NEEDRESTART_MODE", "l"),
        ("APT_LISTCHANGES_FRONTEND", "none"),
    ]
    .iter()
    .map(|(key, value)| (key.to_string(), value.to_string()))
    .collect()
}

/// The package manager's arguments for an upgrade of `packages` (all pending, if empty).
///
/// AIDEV-NOTE: these are what make the promises in the tool's description true. apt:
/// `--only-upgrade` ignores a named package that is not installed (new dependencies of
/// an upgraded package are still installed), `--no-remove` refuses any solution that
/// removes a package, and the two dpkg options keep a locally changed configuration
/// file instead of asking. dnf's `upgrade` only ever upgrades what is installed.
fn upgrade_argv(family: Family, packages: &[String], dry_run: bool) -> Vec<String> {
    let mut argv = Vec::new();
    match family {
        Family::Apt => {
            if dry_run {
                argv.push("-s".to_string());
            }
            argv.extend(strings(&[
                "-y",
                "-o",
                "Dpkg::Options::=--force-confdef",
                "-o",
                "Dpkg::Options::=--force-confold",
                "--no-remove",
            ]));
            if packages.is_empty() {
                // --with-new-pkgs: an upgrade that newly depends on another package
                // (every new kernel does) is carried out, not left pending for ever.
                // --no-remove above still forbids removing anything.
                argv.extend(strings(&["--with-new-pkgs", "upgrade"]));
            } else {
                argv.extend(strings(&["--only-upgrade", "install", "--"]));
            }
        }
        Family::Rpm => {
            // --assumeno: work the transaction out, show it, then answer "no"
            argv.push(if dry_run { "--assumeno" } else { "-y" }.to_string());
            argv.push("upgrade".to_string());
            if !packages.is_empty() {
                argv.push("--".to_string());
            }
        }
    }
    argv.extend(packages.iter().cloned());
    argv
}

/// A package name without its `:architecture` qualifier.
fn bare_name(name: &str) -> &str {
    name.split(':').next().unwrap_or(name)
}

/// Refuses the upgrade unless every named package is installed, under exactly that name.
///
/// AIDEV-NOTE: this is more than a courtesy. apt treats an argument that is not the
/// name of a package as something else: `name-` removes `name`, `name+` installs it,
/// and older versions fall back to a regular expression over all package names. Each
/// argument was authorized as ONE package; only an exact, installed name is certain to
/// be read by apt as that one package.
async fn check_installed(ctx: &Ctx, family: Family, packages: &[String]) -> Result<(), ToolError> {
    let (program, mut argv) = match family {
        Family::Apt => ("dpkg-query", strings(&["-W", DPKG_INSTALLED_FORMAT, "--"])),
        Family::Rpm => ("rpm", strings(&["-q", "--qf", RPM_NAME_FORMAT, "--"])),
    };
    argv.extend(packages.iter().cloned());
    let out = ctx.run(ctx.command(program)?.args(argv)).await?;
    if out.timed_out {
        return Err(ToolError::Failed(format!(
            "{program} did not say in time whether the packages are installed; nothing was changed"
        )));
    }
    let listing = String::from_utf8_lossy(&out.stdout);
    let installed: BTreeSet<String> = match family {
        Family::Apt => installed_names(&listing),
        // rpm prints the name of each installed package, and a sentence for the others
        Family::Rpm => listing
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.contains(' '))
            .map(str::to_string)
            .collect(),
    };
    let missing: Vec<&str> = packages
        .iter()
        .map(String::as_str)
        .filter(|name| {
            let known = match family {
                Family::Apt => bare_name(name),
                Family::Rpm => name,
            };
            !installed.contains(known)
        })
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    Err(ToolError::Failed(format!(
        "not installed: {}. package_upgrade only upgrades packages that are installed \
         already (package_query lists them); nothing was changed",
        missing.join(", ")
    )))
}

/// Checks the command line of a unit: nothing in it may contain `$` or `%`.
///
/// AIDEV-NOTE: systemd expands `$VAR`, `${VAR}` and `%` specifiers in the command line
/// of a unit, also of one started with systemd-run. Nothing we pass needs them (package
/// names cannot contain either character), so their presence means something is wrong:
/// refuse, rather than run a command line that differs from the one that was checked.
pub fn check_unit_command(argv: &[String]) -> Result<(), ToolError> {
    match argv.iter().find(|arg| arg.contains(['$', '%'])) {
        Some(arg) => Err(ToolError::Failed(format!(
            "refusing to start a systemd unit with {arg:?} in its command line: systemd \
             would expand the $ or % in it"
        ))),
        None => Ok(()),
    }
}

/// One package run to be started as a systemd unit.
struct Job {
    systemd_run: PathBuf,
    /// The package manager, by absolute path.
    program: PathBuf,
    argv: Vec<String>,
    env: Vec<(String, String)>,
    /// What is being upgraded, for messages.
    what: String,
    /// How long this call can wait for it.
    wait: Duration,
    /// What the call has to say already (a refresh's output).
    text: String,
}

/// `active`, `inactive`, `failed`... or `unknown` if systemd would not say.
async fn unit_state(ctx: &Ctx, service: &str) -> String {
    let Ok(systemctl) = ctx.command("systemctl") else {
        return "unknown".to_string();
    };
    match ctx.run(systemctl.args(["is-active", "--", service])).await {
        Ok(out) if !out.timed_out && !out.stdout.is_empty() => {
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }
        _ => "unknown".to_string(),
    }
}

/// What a unit wrote, read back from the journal: the newest `room` bytes of it.
async fn unit_output(ctx: &Ctx, service: &str, room: usize) -> String {
    let elsewhere = format!(
        "[the output could not be read back; it is in the journal: journal_query unit={service}]\n"
    );
    let Ok(journalctl) = ctx.command("journalctl") else {
        return elsewhere;
    };
    let argv = [
        "--no-pager".to_string(),
        "--quiet".to_string(),
        "--output=cat".to_string(),
        format!("--unit={service}"),
    ];
    match ctx.run(journalctl.args(argv)).await {
        Ok(out) if command_ok(&out) && !out.stdout.is_empty() => command_text_tail(&out, room),
        Ok(out) if command_ok(&out) => "[the unit wrote no output]\n".to_string(),
        _ => elsewhere,
    }
}

/// Starts a package run as a transient systemd unit and waits for it as long as this
/// call may.
///
/// AIDEV-NOTE: a package run must never be killed half way: that leaves dpkg or rpm
/// with half-configured packages. Run as a child of this server it would be killed when
/// the call's time limit passes, or when the client goes away. Started through
/// `systemd-run` it belongs to systemd instead: when the wait below ends, only the
/// waiting `systemd-run` client is stopped and the unit runs on to its end. There is
/// deliberately no `--pipe`: with it the unit would write to pipes that close when we
/// stop waiting. Its output goes to the journal and is read back from there. The unit's
/// name starts with `opsmcp`, which `services.protected` covers by default, so
/// service_control cannot stop it either.
async fn run_detached(ctx: &Ctx, auth: Authorized, job: Job) -> ToolResult {
    let mut random = [0u8; 2];
    getrandom::fill(&mut random)
        .map_err(|e| ToolError::Failed(format!("cannot get random bytes: {e}")))?;
    let unit = unit_name(now_secs(), random);
    let service = format!("{unit}.service");
    let program = job.program.to_str().ok_or_else(|| {
        ToolError::Failed("the package manager's path is not valid UTF-8".to_string())
    })?;
    let mut argv = vec![
        format!("--unit={unit}"),
        format!(
            "--description=opsmcp package upgrade requested by {}",
            plain_name(&ctx.principal().name)
        ),
        "--collect".to_string(),
        "--wait".to_string(),
        "--quiet".to_string(),
        // without the right to start a unit, fail at once instead of asking for a password
        "--no-ask-password".to_string(),
    ];
    for (key, value) in &job.env {
        argv.push(format!("--setenv={key}={value}"));
    }
    let mut command = vec![program.to_string()];
    command.extend(job.argv);
    check_unit_command(&command)?;
    argv.push("--".to_string());
    argv.extend(command);
    let out = ctx
        .run(ctx.command_at(job.systemd_run).timeout(job.wait).args(argv))
        .await?;

    let what = job.what;
    let mut text = job.text;
    text.push_str(&format!(
        "== upgrade of {what}, as systemd unit {service} ==\n"
    ));
    let room = ctx.output_budget().saturating_sub(text.len() + 1024);
    if out.timed_out {
        // Only the wait ended. Whether the run is still going is systemd's to say.
        match unit_state(ctx, &service).await.as_str() {
            "inactive" | "failed" => {
                text.push_str(&unit_output(ctx, &service, room).await);
                text.push_str(
                    "The run ended just as this call's time limit passed, and its result \
                     was not seen. The output above is what it wrote; package_updates \
                     shows what is still pending.\n",
                );
                return auth.failed(text);
            }
            "active" | "activating" | "reloading" | "deactivating" => text.push_str(&format!(
                "The upgrade is still running as {service}. It was not interrupted and \
                 will run to its end.\n"
            )),
            _ => text.push_str(&format!(
                "The upgrade was started as {service} and had not finished when this \
                 call's time limit passed; it was not interrupted. Whether it is still \
                 running could not be found out.\n"
            )),
        }
        text.push_str(&format!(
            "Follow it with journal_query (unit={service}) or service_status; afterwards \
             package_updates shows what is still pending.\n"
        ));
        return auth.ok(text);
    }

    let succeeded = command_ok(&out);
    // journald takes what a unit wrote a moment after the unit has ended
    tokio::time::sleep(Duration::from_millis(200)).await;
    text.push_str(&unit_output(ctx, &service, room).await);
    // anything systemd-run itself had to say, and the exit status
    text.push_str(&command_text(&out));
    if succeeded {
        text.push_str(&format!(
            "Upgrade of {what}: done.\npackage_updates shows what is still pending and \
             whether a reboot is needed.\n"
        ));
    } else {
        text.push_str(&format!("Upgrade of {what}: FAILED.\n"));
    }
    auth.done(text, succeeded)
}

async fn package_upgrade(ctx: Ctx, args: Args) -> ToolResult {
    let started = Instant::now();
    let all = args.bool("all") == Some(true);
    let refresh = args.bool("refresh") == Some(true);
    let dry_run = args.bool("dry_run") == Some(true);
    let mut packages: Vec<String> = Vec::new();
    for name in args.list("packages").unwrap_or_default() {
        check_name(name, false)?;
        if name.ends_with('-') {
            return Err(ToolError::Invalid(format!(
                "{name:?} is not a package name (a trailing - would ask apt to remove a package)"
            )));
        }
        if !packages.iter().any(|known| known == name) {
            packages.push(name.to_string());
        }
    }
    if all && !packages.is_empty() {
        return Err(ToolError::Invalid(
            "give either packages or all, not both".to_string(),
        ));
    }
    if !all && packages.is_empty() && !refresh {
        return Err(ToolError::Invalid(
            "nothing to do: name the packages to upgrade, or pass all, or pass refresh".to_string(),
        ));
    }
    if dry_run && refresh {
        return Err(ToolError::Invalid(
            "refresh changes the package lists, so it cannot be part of a dry run".to_string(),
        ));
    }

    // AIDEV-NOTE: every named package is judged, and audited, on its own, and ALL must
    // pass before anything is looked up or run. A package is judged by its name without
    // any `:architecture`, so that `openssl:amd64` cannot slip past a rule written for
    // `openssl`. Everything pending, or only refreshing the lists, names no package and
    // so needs a grant that is not limited to some packages.
    let mut proof = None;
    if packages.is_empty() {
        proof = Some(ctx.authorize(None)?);
    }
    for name in &packages {
        proof = Some(ctx.authorize(Some(bare_name(name)))?);
    }
    let Some(auth) = proof else {
        return Err(ToolError::Internal(
            "package_upgrade: nothing was authorized".to_string(),
        ));
    };

    let family = family(&ctx)?;
    let manager = match family {
        Family::Apt => "apt-get",
        Family::Rpm => dnf_name(&ctx)?,
    };
    let program = ctx.bins().find(manager).map_err(ToolError::Failed)?;
    let upgrading = all || !packages.is_empty();
    // Found out before anything is changed, so that a refresh is not all that happens.
    let systemd_run = if upgrading && !dry_run {
        Some(ctx.bins().find("systemd-run").map_err(|_| {
            ToolError::Failed(
                "package_upgrade starts a real upgrade as a systemd unit (with systemd-run), \
                 so that it cannot be cut off half way, and systemd-run was not found on \
                 this host. Nothing was changed. A dry run is still possible."
                    .to_string(),
            )
        })?)
    } else {
        None
    };
    if !packages.is_empty() {
        check_installed(&ctx, family, &packages).await?;
    }

    // What is left of this call's time, keeping some back for reading the output.
    let remaining = |ctx: &Ctx| {
        ctx.cfg()
            .limits
            .call_timeout_secs
            .saturating_sub(15)
            .saturating_sub(started.elapsed().as_secs())
            .max(2)
    };
    let direct = |ctx: &Ctx| -> Cmd {
        let mut cmd = ctx.command_at(program.clone());
        if family == Family::Apt {
            cmd.env = apt_env();
        }
        cmd
    };
    let budget = ctx.output_budget();
    let mut text = String::new();

    if refresh {
        let argv: &[&str] = match family {
            Family::Apt => &["update"],
            Family::Rpm => &["-q", "makecache"],
        };
        // Cutting a refresh short does no harm, so it may use what time the call has.
        let limit = Duration::from_secs(remaining(&ctx));
        let out = ctx
            .run(direct(&ctx).timeout(limit).args(argv.iter().copied()))
            .await?;
        text.push_str("== refreshing the package lists ==\n");
        text.push_str(&command_text_tail(&out, budget / 4));
        if !command_ok(&out) {
            text.push_str(if upgrading {
                "Refreshing the package lists FAILED; nothing was upgraded.\n"
            } else {
                "Refreshing the package lists FAILED.\n"
            });
            return auth.failed(text);
        }
        if !upgrading {
            text.push_str("Package lists refreshed.\n");
            return auth.ok(text);
        }
    }

    let what = if packages.is_empty() {
        "all pending packages".to_string()
    } else {
        packages.join(", ")
    };
    let argv = upgrade_argv(family, &packages, dry_run);
    let Some(systemd_run) = systemd_run else {
        // A dry run: a simulation, run directly like any other read.
        let mut out = ctx.run(direct(&ctx).args(argv)).await?;
        let said = |needle: &[u8]| {
            [&out.stdout, &out.stderr]
                .iter()
                .any(|stream| stream.windows(needle.len()).any(|part| part == needle))
        };
        // dnf --assumeno shows the transaction, answers "no" for us, and exits 1
        if family == Family::Rpm
            && out.code == Some(1)
            && !out.timed_out
            && said(b"Operation aborted")
        {
            out.code = Some(0);
        }
        let succeeded = command_ok(&out);
        text.push_str(&command_text_tail(&out, budget.saturating_sub(512)));
        text.push_str(&if succeeded {
            format!("Dry run: this is what an upgrade of {what} would do; nothing was changed.\n")
        } else {
            "The dry run FAILED; nothing was changed.\n".to_string()
        });
        return auth.done(text, succeeded);
    };

    let env = match family {
        Family::Apt => apt_env(),
        Family::Rpm => Vec::new(),
    };
    let wait = Duration::from_secs(remaining(&ctx));
    let job = Job {
        systemd_run,
        program,
        argv,
        env,
        what,
        wait,
        text,
    };
    run_detached(&ctx, auth, job).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::Host;
    use crate::tools::testing::{self, FakeBins, call, find, host, ok_text};
    use serde_json::{Value, json};
    use std::sync::Arc;

    type Calls = Vec<Vec<String>>;

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn check_name_accepts_package_names_and_patterns_only_where_asked() {
        for good in [
            "nginx",
            "libssl3",
            "g++",
            "libc6:amd64",
            "python3.12",
            "a_b-c",
        ] {
            assert!(check_name(good, false).is_ok(), "{good}");
            assert!(check_name(good, true).is_ok(), "{good}");
        }
        for pattern in ["nginx*", "*ssl*", "lib?", "*"] {
            assert!(check_name(pattern, true).is_ok(), "{pattern}");
            assert!(check_name(pattern, false).is_err(), "{pattern}");
        }
        let long = "x".repeat(129);
        for bad in [
            "",
            "-y",
            "--purge",
            "+x",
            ".hidden",
            "a b",
            "a/b",
            "a=1.0",
            "nginx;id",
            "$(id)",
            "a[bc]",
            long.as_str(),
        ] {
            assert!(check_name(bad, false).is_err(), "{bad:?}");
            assert!(check_name(bad, true).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn check_owner_path_wants_a_plain_absolute_path() {
        for good in ["/usr/bin/ls", "/etc/nginx/nginx.conf", "/opt/my app/tool"] {
            assert!(check_owner_path(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "ls",
            "bin/ls",
            "/usr/bin/*",
            "/usr/bin/l?",
            "/usr/[b]in",
            "/a\\b",
        ] {
            assert!(check_owner_path(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn parse_inst_reads_versions_and_spots_security_updates() {
        assert_eq!(
            parse_inst(
                "Inst libssl3 [3.0.2-0ubuntu1.15] (3.0.2-0ubuntu1.16 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])"
            ),
            Some(Pending {
                name: "libssl3".to_string(),
                installed: Some("3.0.2-0ubuntu1.15".to_string()),
                available: "3.0.2-0ubuntu1.16".to_string(),
                security: true,
            })
        );
        assert_eq!(
            parse_inst(
                "Inst nginx [1.18.0-6ubuntu14.4] (1.18.0-6ubuntu14.5 Ubuntu:22.04/jammy-updates [amd64]) []"
            ),
            Some(Pending {
                name: "nginx".to_string(),
                installed: Some("1.18.0-6ubuntu14.4".to_string()),
                available: "1.18.0-6ubuntu14.5".to_string(),
                security: false,
            })
        );
        // a new dependency: nothing installed yet
        assert_eq!(
            parse_inst("Inst newdep (1.0-1 Ubuntu:22.04/jammy [all])"),
            Some(Pending {
                name: "newdep".to_string(),
                installed: None,
                available: "1.0-1".to_string(),
                security: false,
            })
        );
        // Debian names its security archive differently
        let debian = parse_inst(
            "Inst openssl [3.0.11-1~deb12u1] (3.0.11-1~deb12u2 Debian-Security:12/stable-security [amd64])",
        );
        assert!(debian.unwrap().security);
        for other in [
            "",
            "Conf libssl3 (3.0.2-0ubuntu1.16 Ubuntu:22.04/jammy-updates [amd64])",
            "Remv oldlib [1.0]",
            "Inst",
            "Inst broken [1.0",
            "Inst broken [1.0] no-parenthesis",
            "NOTE: This is only a simulation!",
        ] {
            assert_eq!(parse_inst(other), None, "{other:?}");
        }
    }

    const SIMULATION: &str = "NOTE: This is only a simulation!\n\
        Reading package lists...\n\
        Inst libssl3 [3.0.2-0ubuntu1.15] (3.0.2-0ubuntu1.16 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])\n\
        Inst nginx [1.18.0-6ubuntu14.4] (1.18.0-6ubuntu14.5 Ubuntu:22.04/jammy-updates [amd64]) []\n\
        Inst newdep (1.0-1 Ubuntu:22.04/jammy [all])\n\
        Remv oldlib [1.0]\n\
        Conf libssl3 (3.0.2-0ubuntu1.16 Ubuntu:22.04/jammy-updates [amd64])\n";

    #[test]
    fn parse_simulation_lists_what_would_be_installed_and_removed() {
        let (pending, removals) = parse_simulation(SIMULATION);
        let names: Vec<&str> = pending.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["libssl3", "nginx", "newdep"]);
        assert_eq!(removals, ["oldlib"]);
        assert_eq!(parse_simulation(""), (vec![], vec![]));
    }

    #[test]
    fn installed_rows_leaves_out_packages_dpkg_only_knows_by_name() {
        let listing = "nginx\t1.24.0-2\tii \nnginx-doc\t\tun \nold-thing\t0.9\trc \nheld\t2.0\thi \ngone\t\tpn \nnot a row\n";
        assert_eq!(
            installed_rows(listing),
            vec![
                strings(&["nginx", "1.24.0-2", "ii"]),
                strings(&["old-thing", "0.9", "rc"]),
                strings(&["held", "2.0", "hi"]),
            ]
        );
    }

    #[test]
    fn installed_names_takes_only_what_is_installed() {
        let got = installed_names("nginx\tinstalled\nold\tconfig-files\nghost\tnot-installed\n\n");
        assert_eq!(got.into_iter().collect::<Vec<_>>(), ["nginx"]);
    }

    #[test]
    fn needrestart_lines_report_the_kernel_and_the_services() {
        let text = "NEEDRESTART-VER: 3.5\nNEEDRESTART-KCUR: 5.15.0-91-generic\n\
                    NEEDRESTART-KEXP: 5.15.0-94-generic\nNEEDRESTART-KSTA: 3\n\
                    NEEDRESTART-SVC: cron.service\nNEEDRESTART-SVC: nginx.service\n";
        let lines = needrestart_lines(text);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(
            lines[0].contains("5.15.0-91-generic") && lines[0].contains("5.15.0-94-generic"),
            "{lines:?}"
        );
        assert!(lines[0].contains("reboot"), "{lines:?}");
        assert!(
            lines[1].contains("cron.service, nginx.service"),
            "{lines:?}"
        );
        assert!(lines[1].contains('2'), "{lines:?}");
        // the newest kernel is running and nothing needs a restart: say that
        let quiet = needrestart_lines(
            "NEEDRESTART-KCUR: 6.8.0-45-generic\nNEEDRESTART-KEXP: 6.8.0-45-generic\nNEEDRESTART-KSTA: 1\n",
        );
        assert_eq!(quiet.len(), 2, "{quiet:?}");
        assert!(quiet[0].contains("newest"), "{quiet:?}");
        assert!(quiet[1].contains("No service"), "{quiet:?}");
        // output that is not needrestart's batch format says nothing
        assert_eq!(needrestart_lines("something else\n"), Vec::<String>::new());
    }

    #[test]
    fn unit_name_is_a_plain_systemd_unit_name() {
        assert_eq!(
            unit_name(1_763_600_000, [0xa1, 0x0b]),
            "opsmcp-pkg-1763600000-a10b"
        );
        // covered by the default `opsmcp*` entry of services.protected, so that the
        // run cannot be stopped half way through service_control
        assert!(crate::glob::glob_match(
            "opsmcp*",
            &format!("{}.service", unit_name(1, [0, 0]))
        ));
    }

    #[test]
    fn unit_command_refuses_what_systemd_would_expand() {
        let plain = strings(&[
            "/usr/bin/apt-get",
            "-y",
            "Dpkg::Options::=--force-confold",
            "--",
            "g++",
        ]);
        assert!(check_unit_command(&plain).is_ok());
        for bad in ["$HOME", "${PATH}", "a$b", "%n", "100%"] {
            let mut argv = plain.clone();
            argv.push(bad.to_string());
            assert!(check_unit_command(&argv).is_err(), "{bad}");
        }
    }

    const ROLES: &str = r#"
[roles.admin]
allow = ["@all"]
[roles.reader]
allow = ["@read"]
[roles.web]
allow = ["package.modify:nginx*"]
[roles.nossl]
allow = ["package.modify"]
deny = ["package.modify:openssl"]
[unix_users.adam]
roles = ["admin"]
[unix_users.rita]
roles = ["reader"]
[unix_users.wendy]
roles = ["web"]
[unix_users.nora]
roles = ["nossl"]
"#;

    fn fixture(fake: &FakeBins) -> (Arc<Host>, MemorySink) {
        host(&format!("{ROLES}{}", fake.config_only()))
    }

    async fn run(host: &Arc<Host>, user: &str, tool: &str, arguments: Value) -> ToolResult {
        call(host, user, &find(tools(), tool), arguments).await
    }

    /// A stand-in dpkg-query. It knows nginx (and whatever else is asked about, except
    /// names starting with `ghost` or `nosuch`).
    const DPKG_QUERY: &str = r#"
for last; do :; done
case "$1" in
  -W)
    case "$2" in
      *Summary*)
        if [ "$last" = nosuch ]; then
          echo "dpkg-query: no packages found matching nosuch" >&2; exit 1
        fi
        printf 'Package: %s\nVersion: 1.24.0-2\nArchitecture: amd64\nStatus: installed\nSummary: a web server\n\n' "$last" ;;
      *Status-Abbrev*)
        printf 'nginx\t1.24.0-2\tii \nnginx-common\t1.24.0-2\tii \nnginx-doc\t\tun \nold-thing\t0.9\trc \n' ;;
      *)
        rc=0
        shift 3
        for name; do
          case "$name" in
            ghost*) echo "dpkg-query: no packages found matching $name" >&2; rc=1 ;;
            *) printf '%s\tinstalled\n' "${name%%:*}" ;;
          esac
        done
        exit $rc ;;
    esac ;;
  -L) printf '/.\n/usr\n/usr/sbin/nginx\n' ;;
  -S)
    case "$last" in
      */real/tool|/usr/sbin/nginx) echo "nginx-core: $last" ;;
      *) echo "dpkg-query: no path found matching pattern $last" >&2; exit 1 ;;
    esac ;;
  *) echo "dpkg-query: error: unknown option" >&2; exit 2 ;;
esac
"#;

    fn apt_family() -> FakeBins {
        FakeBins::new()
            .add_script("dpkg-query", DPKG_QUERY)
            .add_script(
                "dpkg",
                r#"for last; do :; done
case "$last" in
  changed) echo '??5?????? c /etc/changed/changed.conf' ;;
  nosuch) echo "dpkg: error: package 'nosuch' is not installed" >&2; exit 2 ;;
esac"#,
            )
    }

    const INFO_FORMAT: &str = "-f=Package: ${Package}\\nVersion: ${Version}\\nArchitecture: ${Architecture}\\nStatus: ${db:Status-Status}\\nSummary: ${binary:Summary}\\n\\n";

    #[tokio::test]
    async fn query_info_asks_dpkg_about_exactly_that_package() {
        let fake = apt_family();
        let (host, audit) = fixture(&fake);
        let arguments = json!({"action": "info", "name": "nginx"});
        let text = ok_text(run(&host, "rita", "package_query", arguments).await);
        assert!(text.contains("Version: 1.24.0-2"), "{text}");
        assert_eq!(
            fake.calls("dpkg-query"),
            vec![strings(&["-W", INFO_FORMAT, "--", "nginx"])]
        );
        let records = audit.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["permission"], "package.view");
        assert_eq!(records[0]["decision"], "allow");
    }

    #[tokio::test]
    async fn query_treats_not_installed_as_an_answer_and_a_broken_query_as_an_error() {
        let fake = apt_family();
        let (host, _audit) = fixture(&fake);
        let arguments = json!({"action": "info", "name": "nosuch"});
        let text = ok_text(run(&host, "rita", "package_query", arguments).await);
        assert!(text.contains("no packages found matching nosuch"), "{text}");
        assert!(!text.contains("exit status"), "{text}");
        // dpkg exits 2 when something is actually wrong
        let arguments = json!({"action": "verify", "name": "nosuch"});
        let output = run(&host, "rita", "package_query", arguments)
            .await
            .unwrap();
        assert!(output.is_error(), "{output:?}");
        assert!(output.text().contains("not installed"), "{output:?}");
    }

    #[tokio::test]
    async fn query_list_shows_installed_packages_as_a_table() {
        let fake = apt_family();
        let (host, _audit) = fixture(&fake);
        let arguments = json!({"action": "list", "name": "nginx*"});
        let text = ok_text(run(&host, "rita", "package_query", arguments).await);
        assert!(text.starts_with("PACKAGE "), "{text}");
        assert!(text.contains("nginx-common  1.24.0-2  ii"), "{text}");
        assert!(text.contains("old-thing"), "{text}");
        assert!(!text.contains("nginx-doc"), "{text}");
        assert!(text.contains("3 packages"), "{text}");
        assert_eq!(
            fake.calls("dpkg-query"),
            vec![strings(&[
                "-W",
                "-f=${Package}\\t${Version}\\t${db:Status-Abbrev}\\n",
                "--",
                "nginx*"
            ])]
        );
        // no name: every package
        ok_text(run(&host, "rita", "package_query", json!({"action": "list"})).await);
        assert_eq!(fake.calls("dpkg-query")[1][3], "*");
    }

    #[tokio::test]
    async fn query_files_owner_and_verify_run_the_matching_command() {
        let fake = apt_family();
        let (host, _audit) = fixture(&fake);
        let files = json!({"action": "files", "name": "nginx"});
        let text = ok_text(run(&host, "rita", "package_query", files).await);
        assert!(text.contains("/usr/sbin/nginx"), "{text}");
        let owner = json!({"action": "owner", "path": "/usr/sbin/nginx"});
        let text = ok_text(run(&host, "rita", "package_query", owner).await);
        assert!(text.contains("nginx-core: /usr/sbin/nginx"), "{text}");
        assert_eq!(
            fake.calls("dpkg-query"),
            vec![
                strings(&["-L", "--", "nginx"]),
                strings(&["-S", "--", "/usr/sbin/nginx"])
            ]
        );
        let changed = json!({"action": "verify", "name": "changed"});
        let text = ok_text(run(&host, "rita", "package_query", changed).await);
        assert!(text.contains("/etc/changed/changed.conf"), "{text}");
        let clean = json!({"action": "verify", "name": "nginx"});
        let text = ok_text(run(&host, "rita", "package_query", clean).await);
        assert!(text.contains("No file of nginx differs"), "{text}");
        assert_eq!(
            fake.calls("dpkg"),
            vec![
                strings(&["--verify", "--", "changed"]),
                strings(&["--verify", "--", "nginx"])
            ]
        );
    }

    #[tokio::test]
    async fn query_owner_also_tries_where_a_linked_path_really_is() {
        // /bin is a link to /usr/bin on current systems, and dpkg knows only one of them
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("real")).unwrap();
        std::fs::write(dir.path().join("real/tool"), "").unwrap();
        std::os::unix::fs::symlink(dir.path().join("real"), dir.path().join("link")).unwrap();
        let asked = format!("{}/link/tool", dir.path().display());
        let real = std::fs::canonicalize(&asked).unwrap().display().to_string();

        let fake = apt_family();
        let (host, _audit) = fixture(&fake);
        let arguments = json!({"action": "owner", "path": asked});
        let text = ok_text(run(&host, "rita", "package_query", arguments).await);
        assert!(text.contains(&format!("nginx-core: {real}")), "{text}");
        assert_eq!(
            fake.calls("dpkg-query"),
            vec![
                strings(&["-S", "--", asked.as_str()]),
                strings(&["-S", "--", real.as_str()])
            ]
        );
        // a path nothing owns, with no other name to try: one question, one answer
        let arguments = json!({"action": "owner", "path": "/nonexistent/x"});
        let text = ok_text(run(&host, "rita", "package_query", arguments).await);
        assert_eq!(text, "No installed package owns /nonexistent/x.\n");
        assert_eq!(fake.calls("dpkg-query").len(), 3);
    }

    #[tokio::test]
    async fn query_refuses_unusable_arguments_before_anything_else() {
        let fake = apt_family();
        let (host, audit) = fixture(&fake);
        for arguments in [
            json!({"action": "info"}),
            json!({"action": "info", "name": "--help"}),
            json!({"action": "info", "name": "nginx*"}),
            json!({"action": "files", "name": "a b"}),
            json!({"action": "verify"}),
            json!({"action": "owner"}),
            json!({"action": "owner", "path": "sbin/nginx"}),
            json!({"action": "owner", "path": "/usr/sbin/*"}),
            json!({"action": "owner", "name": "nginx"}),
            json!({"action": "info", "name": "nginx", "path": "/usr/sbin/nginx"}),
            json!({"action": "list", "name": "-x*"}),
        ] {
            let result = run(&host, "rita", "package_query", arguments.clone()).await;
            assert!(
                matches!(result, Err(ToolError::Invalid(_))),
                "{arguments}: {result:?}"
            );
        }
        assert_eq!(fake.calls("dpkg-query"), Calls::new());
        assert_eq!(fake.calls("dpkg"), Calls::new());
        assert_eq!(audit.records().len(), 0);
    }

    #[tokio::test]
    async fn query_and_updates_need_the_view_permission() {
        let fake = apt_family().add("apt-get", "", 0);
        let (host, audit) = fixture(&fake);
        // wendy may upgrade nginx packages, but was not given package.view
        let arguments = json!({"action": "info", "name": "nginx"});
        let result = run(&host, "wendy", "package_query", arguments).await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        let result = run(&host, "wendy", "package_updates", json!({})).await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        assert_eq!(fake.calls("dpkg-query"), Calls::new());
        assert_eq!(fake.calls("apt-get"), Calls::new());
        assert_eq!(audit.records().len(), 2);
    }

    /// A stand-in rpm.
    const RPM: &str = r#"
for last; do :; done
case "$1" in
  -qi) printf 'Name        : %s\nVersion     : 1.20.1\n' "$last" ;;
  -qa) printf 'nginx\t1.20.1-14.el9\tx86_64\nbash\t5.1.8-9.el9\tx86_64\n' ;;
  -qf) echo "file $last is not owned by any package"; exit 1 ;;
  -q)
    rc=0
    shift 4
    for name; do
      case "$name" in
        ghost*) echo "package $name is not installed"; rc=1 ;;
        *) echo "$name" ;;
      esac
    done
    exit $rc ;;
esac
"#;

    #[tokio::test]
    async fn query_uses_rpm_where_there_is_no_dpkg() {
        let fake = FakeBins::new().add_script("rpm", RPM);
        let (host, _audit) = fixture(&fake);
        let arguments = json!({"action": "info", "name": "nginx"});
        let text = ok_text(run(&host, "rita", "package_query", arguments).await);
        assert!(text.contains("1.20.1"), "{text}");
        let text = ok_text(run(&host, "rita", "package_query", json!({"action": "list"})).await);
        // sorted, as a table
        assert!(
            text.find("bash").unwrap() < text.find("nginx").unwrap(),
            "{text}"
        );
        assert!(text.contains("2 packages"), "{text}");
        // AIDEV-NOTE: rpm words "there is no such file" differently from "no package
        // owns that file". Passing that on would tell a caller with only package.view
        // which paths exist, anywhere on the host: both get the same answer.
        let owner = json!({"action": "owner", "path": "/nonexistent/x"});
        let text = ok_text(run(&host, "rita", "package_query", owner).await);
        assert_eq!(text, "No installed package owns /nonexistent/x.\n");
        assert_eq!(
            fake.calls("rpm"),
            vec![
                strings(&["-qi", "--", "nginx"]),
                strings(&[
                    "-qa",
                    "--qf",
                    "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n",
                    "--",
                    "*"
                ]),
                strings(&["-qf", "--", "/nonexistent/x"]),
            ]
        );
    }

    #[tokio::test]
    async fn a_host_without_a_known_package_manager_says_so() {
        let fake = FakeBins::new();
        let (host, _audit) = fixture(&fake);
        for (user, tool, arguments) in [
            ("rita", "package_query", json!({"action": "list"})),
            ("rita", "package_updates", json!({})),
            (
                "adam",
                "package_upgrade",
                json!({"all": true, "dry_run": true}),
            ),
        ] {
            match run(&host, user, tool, arguments).await {
                Err(ToolError::Failed(message)) => {
                    assert!(message.contains("package manager"), "{tool}: {message}")
                }
                other => panic!("{tool}: expected a failure, got {other:?}"),
            }
        }
    }

    /// A stand-in apt-get. It prints the environment the real one depends on, so tests
    /// can see what it was given.
    const APT_GET: &str = r#"
echo "FRONTEND=$DEBIAN_FRONTEND RESTART=$NEEDRESTART_MODE CHANGES=$APT_LISTCHANGES_FRONTEND"
case "$*" in
  *dist-upgrade*)
    echo 'NOTE: This is only a simulation!'
    echo 'Inst libssl3 [3.0.2-0ubuntu1.15] (3.0.2-0ubuntu1.16 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])'
    echo 'Inst nginx [1.18.0-6ubuntu14.4] (1.18.0-6ubuntu14.5 Ubuntu:22.04/jammy-updates [amd64]) []'
    echo 'Inst newdep (1.0-1 Ubuntu:22.04/jammy [all])'
    echo 'Remv oldlib [1.0]'
    echo 'Conf libssl3 (3.0.2-0ubuntu1.16 Ubuntu:22.04/jammy-updates [amd64])' ;;
  update) echo 'Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease' ;;
  *broken*) echo 'E: Unable to correct problems, you have held broken packages.' >&2; exit 100 ;;
  *) echo '1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.' ;;
esac
"#;

    struct Facts {
        dir: tempfile::TempDir,
    }

    impl Facts {
        fn new() -> Facts {
            Facts {
                dir: tempfile::tempdir().unwrap(),
            }
        }

        fn paths(&self) -> Paths {
            let at = |name: &str| self.dir.path().join(name);
            Paths {
                reboot_required: at("reboot-required"),
                reboot_required_pkgs: at("reboot-required.pkgs"),
                lists_stamp: at("update-success-stamp"),
                lists_dir: at("lists"),
            }
        }

        /// Marks the package lists as refreshed `secs_ago` seconds ago.
        fn refreshed(&self, secs_ago: u64) {
            let stamp = self.paths().lists_stamp;
            std::fs::write(&stamp, "").unwrap();
            let when = std::time::SystemTime::now() - std::time::Duration::from_secs(secs_ago);
            let file = std::fs::File::options().write(true).open(&stamp).unwrap();
            file.set_modified(when).unwrap();
        }
    }

    async fn updates(host: &Arc<Host>, user: &str, facts: &Facts, arguments: Value) -> ToolResult {
        let tool = find(tools(), "package_updates");
        let args = Args::parse(&tool.params, Some(&arguments)).map_err(ToolError::Invalid)?;
        let ctx = testing::ctx(host, user, "package.view", Access::Read);
        package_updates_at(ctx, args, facts.paths()).await
    }

    #[tokio::test]
    async fn updates_says_what_it_could_not_check() {
        // no apt-mark and no needrestart on this host
        let fake = apt_family().add_script("apt-get", APT_GET);
        let (host, _audit) = fixture(&fake);
        let facts = Facts::new();
        let text = ok_text(updates(&host, "rita", &facts, json!({})).await);
        assert!(
            text.contains("[held packages were not checked: apt-mark is not installed]"),
            "{text}"
        );
        assert!(
            text.contains(
                "[services needing a restart were not checked: needrestart is not installed]"
            ),
            "{text}"
        );
    }

    #[tokio::test]
    async fn updates_says_when_apt_printed_more_than_was_read() {
        // far more pending updates than fit in what is kept of a command's output
        let fake = apt_family().add_script(
            "apt-get",
            "i=0; while [ $i -lt 30000 ]; do echo \"Inst pkg$i [1.0] (2.0 Ubuntu:22.04/jammy-updates [amd64])\"; i=$((i+1)); done",
        );
        let (host, _audit) = fixture(&fake);
        let facts = Facts::new();
        let text = ok_text(updates(&host, "rita", &facts, json!({})).await);
        assert!(text.contains("more updates may be pending"), "{text}");
    }

    #[tokio::test]
    async fn updates_lists_what_is_pending_with_everything_that_goes_with_it() {
        let fake = apt_family()
            .add_script("apt-get", APT_GET)
            .add("apt-mark", "docker-ce\nkubelet\n", 0)
            .add(
                "needrestart",
                "NEEDRESTART-KCUR: 5.15.0-91-generic\nNEEDRESTART-KEXP: 5.15.0-94-generic\nNEEDRESTART-KSTA: 3\nNEEDRESTART-SVC: nginx.service\n",
                0,
            );
        let (host, _audit) = fixture(&fake);
        let facts = Facts::new();
        std::fs::write(
            facts.paths().reboot_required,
            "*** System restart required ***\n",
        )
        .unwrap();
        std::fs::write(
            facts.paths().reboot_required_pkgs,
            "linux-image-5.15.0-94-generic\nlibc6\nlibc6\n",
        )
        .unwrap();
        facts.refreshed(3 * 86_400);

        let text = ok_text(updates(&host, "rita", &facts, json!({})).await);
        assert!(text.contains("Pending updates: 3"), "{text}");
        assert!(text.contains("1 is a security update"), "{text}");
        assert!(
            text.contains("libssl3  3.0.2-0ubuntu1.15   3.0.2-0ubuntu1.16   yes"),
            "{text}"
        );
        assert!(
            text.contains("nginx    1.18.0-6ubuntu14.4  1.18.0-6ubuntu14.5  -"),
            "{text}"
        );
        assert!(text.contains("newdep   (new)"), "{text}");
        assert!(text.contains("remove: oldlib"), "{text}");
        assert!(text.contains("Held back: docker-ce, kubelet"), "{text}");
        assert!(
            text.contains("Reboot required: yes (linux-image-5.15.0-94-generic, libc6)"),
            "{text}"
        );
        assert!(text.contains("5.15.0-94-generic"), "{text}");
        assert!(text.contains("nginx.service"), "{text}");
        assert!(text.contains("3d 0h 0m ago"), "{text}");
        assert!(text.contains("more than a day old"), "{text}");
        assert!(text.contains("refresh"), "{text}");
        assert_eq!(
            fake.calls("apt-get"),
            vec![strings(&[
                "-s",
                "-o",
                "Debug::NoLocking=true",
                "dist-upgrade"
            ])]
        );
        assert_eq!(fake.calls("apt-mark"), vec![strings(&["showhold"])]);
        assert_eq!(fake.calls("needrestart"), vec![strings(&["-b", "-r", "l"])]);
    }

    #[tokio::test]
    async fn updates_can_show_only_the_security_updates() {
        let fake = apt_family().add_script("apt-get", APT_GET);
        let (host, _audit) = fixture(&fake);
        let facts = Facts::new();
        facts.refreshed(600);
        let text = ok_text(updates(&host, "rita", &facts, json!({"security_only": true})).await);
        assert!(text.contains("Pending updates: 3"), "{text}");
        assert!(text.contains("libssl3"), "{text}");
        assert!(!text.contains("nginx "), "{text}");
        assert!(text.contains("only the security updates"), "{text}");
        // nothing else is installed on this host: no hold list, no needrestart
        assert!(text.contains("Reboot required: no"), "{text}");
        assert!(!text.contains("more than a day old"), "{text}");
    }

    #[tokio::test]
    async fn updates_says_so_when_nothing_is_pending_or_apt_cannot_tell() {
        let fake = apt_family().add("apt-get", "Reading package lists...\n", 0);
        let (host, _audit) = fixture(&fake);
        let facts = Facts::new();
        let text = ok_text(updates(&host, "rita", &facts, json!({})).await);
        assert!(text.contains("No updates are pending"), "{text}");
        assert!(text.contains("not known"), "{text}");

        let fake = apt_family().add_script(
            "apt-get",
            "echo 'E: dpkg was interrupted, you must manually run dpkg --configure -a' >&2; exit 100",
        );
        let (host, _audit) = fixture(&fake);
        let output = updates(&host, "rita", &facts, json!({})).await.unwrap();
        assert!(output.is_error());
        assert!(output.text().contains("dpkg was interrupted"), "{output:?}");
    }

    #[tokio::test]
    async fn updates_asks_dnf_from_its_cache() {
        let dnf = "printf 'nginx.x86_64  1:1.20.1-16.el9  appstream\\nbash.x86_64  5.1.8-10.el9  baseos\\n'; exit 100";
        let fake = FakeBins::new()
            .add_script("rpm", RPM)
            .add_script("dnf", dnf)
            .add_script(
                "needs-restarting",
                "echo 'Reboot is required to fully utilize these updates.'; exit 1",
            );
        let (host, _audit) = fixture(&fake);
        let facts = Facts::new();
        let text = ok_text(updates(&host, "rita", &facts, json!({"security_only": true})).await);
        assert!(text.contains("Pending updates: 2"), "{text}");
        assert!(text.contains("nginx.x86_64"), "{text}");
        assert!(text.contains("Reboot is required"), "{text}");
        assert_eq!(
            fake.calls("dnf"),
            vec![strings(&["-q", "-C", "check-update", "--security"])]
        );
        assert_eq!(fake.calls("needs-restarting"), vec![strings(&["-r"])]);

        // exit 0: nothing pending; any other status: dnf could not tell
        let fake = FakeBins::new().add_script("rpm", RPM).add("yum", "", 0);
        let (host, _audit) = fixture(&fake);
        let text = ok_text(updates(&host, "rita", &facts, json!({})).await);
        assert!(text.contains("No updates are pending"), "{text}");
        assert_eq!(
            fake.calls("yum"),
            vec![strings(&["-q", "-C", "check-update"])]
        );
        let fake = FakeBins::new()
            .add_script("rpm", RPM)
            .add_script("dnf", "echo 'Error: cache is empty' >&2; exit 1");
        let (host, _audit) = fixture(&fake);
        let output = updates(&host, "rita", &facts, json!({})).await.unwrap();
        assert!(output.is_error());
        assert!(output.text().contains("cache is empty"), "{output:?}");
    }

    /// A stand-in systemd-run: it applies `--setenv` and runs the command after `--`,
    /// so the stand-in package manager records how it was really started.
    const SYSTEMD_RUN: &str = r#"
while [ $# -gt 0 ]; do
  case "$1" in
    --setenv=*) export "${1#--setenv=}" ;;
    --) shift; break ;;
  esac
  shift
done
"$@"
"#;

    const JOURNAL: &str =
        "Unpacking nginx (1.24.0-3) over (1.24.0-2) ...\nSetting up nginx (1.24.0-3) ...\n";

    fn apt_host() -> FakeBins {
        apt_family()
            .add_script("apt-get", APT_GET)
            .add_script("systemd-run", SYSTEMD_RUN)
            .add("journalctl", JOURNAL, 0)
            .add("systemctl", "active\n", 0)
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

    /// What `upgrade` is given on top: packages that an upgrade newly depends on (a new
    /// kernel) are installed, while `--no-remove` still forbids removing anything.
    const APT_ALL: [&str; 2] = ["--with-new-pkgs", "upgrade"];

    const APT_OPTIONS: [&str; 6] = [
        "-y",
        "-o",
        "Dpkg::Options::=--force-confdef",
        "-o",
        "Dpkg::Options::=--force-confold",
        "--no-remove",
    ];

    fn apt_argv(before: &[&str], after: &[&str]) -> Vec<String> {
        let mut argv = strings(before);
        argv.extend(strings(&APT_OPTIONS));
        argv.extend(strings(after));
        argv
    }

    #[tokio::test]
    async fn upgrade_needs_to_be_told_what_to_do_and_checks_every_name() {
        let fake = apt_host();
        let (host, audit) = fixture(&fake);
        for arguments in [
            json!({}),
            json!({"dry_run": true}),
            json!({"packages": []}),
            json!({"packages": ["nginx"], "all": true}),
            json!({"all": true, "refresh": true, "dry_run": true}),
            json!({"packages": ["--allow-downgrades"]}),
            json!({"packages": ["nginx", "openssl=1.0"]}),
            json!({"packages": ["nginx*"]}),
            json!({"packages": ["nginx-"]}),
            json!({"packages": ["nginx/jammy"]}),
        ] {
            let result = run(&host, "adam", "package_upgrade", arguments.clone()).await;
            assert!(
                matches!(result, Err(ToolError::Invalid(_))),
                "{arguments}: {result:?}"
            );
        }
        for name in ["dpkg-query", "apt-get", "systemd-run"] {
            assert_eq!(fake.calls(name), Calls::new(), "{name}");
        }
        assert_eq!(audit.records().len(), 0);
    }

    #[tokio::test]
    async fn upgrade_needs_a_grant_for_every_package_before_anything_runs() {
        let fake = apt_host();
        let (host, audit) = fixture(&fake);
        // wendy holds package.modify:nginx* only
        let arguments = json!({"packages": ["nginx", "openssl"], "dry_run": true});
        let result = run(&host, "wendy", "package_upgrade", arguments).await;
        match result {
            Err(ToolError::Denied(message)) => assert!(message.contains("openssl"), "{message}"),
            other => panic!("expected a denial, got {other:?}"),
        }
        let records = audit.records();
        assert_eq!(records.len(), 2);
        assert_eq!(
            (&records[0]["resource"], &records[0]["decision"]),
            (&json!("nginx"), &json!("allow"))
        );
        assert_eq!(
            (&records[1]["resource"], &records[1]["decision"]),
            (&json!("openssl"), &json!("deny"))
        );
        // everything pending, or only refreshing the lists, names no package: that
        // takes a grant that is not limited to some packages
        for arguments in [json!({"all": true}), json!({"refresh": true})] {
            let result = run(&host, "wendy", "package_upgrade", arguments).await;
            assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        }
        // a reader has no package.modify at all
        let arguments = json!({"packages": ["nginx"], "dry_run": true});
        let result = run(&host, "rita", "package_upgrade", arguments).await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        for name in ["dpkg-query", "apt-get", "systemd-run"] {
            assert_eq!(fake.calls(name), Calls::new(), "{name}");
        }
    }

    #[tokio::test]
    async fn upgrade_judges_a_package_by_its_name_without_the_architecture() {
        let fake = apt_host();
        let (host, audit) = fixture(&fake);
        // nora may upgrade anything except openssl; `openssl:amd64` is still openssl
        let arguments = json!({"packages": ["openssl:amd64"], "dry_run": true});
        let result = run(&host, "nora", "package_upgrade", arguments).await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        assert_eq!(audit.records()[0]["resource"], "openssl");
        assert_eq!(fake.calls("apt-get"), Calls::new());
        // and what she may upgrade goes to apt as she wrote it
        let arguments = json!({"packages": ["nginx:amd64"], "dry_run": true});
        ok_text(run(&host, "nora", "package_upgrade", arguments).await);
        assert_eq!(
            fake.calls("apt-get"),
            vec![apt_argv(
                &["-s"],
                &["--only-upgrade", "install", "--", "nginx:amd64"]
            )]
        );
    }

    #[tokio::test]
    async fn a_dry_run_simulates_directly_and_changes_nothing() {
        let fake = apt_host();
        let (host, _audit) = fixture(&fake);
        let arguments = json!({"packages": ["nginx", "nginx-common", "nginx"], "dry_run": true});
        let text = ok_text(run(&host, "wendy", "package_upgrade", arguments).await);
        assert!(text.contains("1 upgraded"), "{text}");
        assert!(text.contains("Dry run"), "{text}");
        assert!(text.contains("nothing was changed"), "{text}");
        // the environment that keeps apt from asking questions
        assert!(
            text.contains("FRONTEND=noninteractive RESTART=l CHANGES=none"),
            "{text}"
        );
        // a name given twice is asked for once
        assert_eq!(
            fake.calls("apt-get"),
            vec![apt_argv(
                &["-s"],
                &["--only-upgrade", "install", "--", "nginx", "nginx-common"]
            )]
        );
        assert_eq!(fake.calls("systemd-run"), Calls::new());

        let text = ok_text(
            run(
                &host,
                "adam",
                "package_upgrade",
                json!({"all": true, "dry_run": true}),
            )
            .await,
        );
        assert!(text.contains("Dry run"), "{text}");
        assert_eq!(fake.calls("apt-get")[1], apt_argv(&["-s"], &APT_ALL));
    }

    #[tokio::test]
    async fn a_real_upgrade_runs_as_its_own_systemd_unit() {
        let fake = apt_host();
        let (host, _audit) = fixture(&fake);
        let arguments = json!({"packages": ["nginx"]});
        let text = ok_text(run(&host, "wendy", "package_upgrade", arguments).await);

        let started = fake.calls("systemd-run");
        assert_eq!(started.len(), 1);
        let unit = started[0][0].strip_prefix("--unit=").unwrap().to_string();
        let (stamp, random) = unit
            .strip_prefix("opsmcp-pkg-")
            .unwrap()
            .split_once('-')
            .unwrap();
        assert!(stamp.parse::<u64>().unwrap() > 1_700_000_000, "{unit}");
        assert!(
            random.len() == 4 && random.chars().all(|c| c.is_ascii_hexdigit()),
            "{unit}"
        );
        let mut want = vec![
            format!("--unit={unit}"),
            "--description=opsmcp package upgrade requested by wendy".to_string(),
        ];
        want.extend(strings(&[
            "--collect",
            "--wait",
            "--quiet",
            "--no-ask-password",
            "--setenv=DEBIAN_FRONTEND=noninteractive",
            "--setenv=NEEDRESTART_MODE=l",
            "--setenv=APT_LISTCHANGES_FRONTEND=none",
            "--",
        ]));
        want.push(path_of(&fake, "apt-get"));
        want.extend(apt_argv(&[], &["--only-upgrade", "install", "--", "nginx"]));
        assert_eq!(started[0], want);
        // the package manager itself was started only through the unit
        assert_eq!(
            fake.calls("apt-get"),
            vec![apt_argv(&[], &["--only-upgrade", "install", "--", "nginx"])]
        );
        // what it wrote is read back from the journal
        assert_eq!(
            fake.calls("journalctl"),
            vec![strings(&[
                "--no-pager",
                "--quiet",
                "--output=cat",
                &format!("--unit={unit}.service")
            ])]
        );
        assert!(text.contains("Setting up nginx (1.24.0-3)"), "{text}");
        assert!(text.contains("Upgrade of nginx: done"), "{text}");
        assert!(text.contains(&format!("{unit}.service")), "{text}");
        // only installed packages may be named: that was checked first
        assert_eq!(
            fake.calls("dpkg-query"),
            vec![strings(&[
                "-W",
                "-f=${Package}\\t${db:Status-Status}\\n",
                "--",
                "nginx"
            ])]
        );
    }

    #[tokio::test]
    async fn upgrading_everything_runs_a_plain_upgrade_in_the_unit() {
        let fake = apt_host();
        let (host, _audit) = fixture(&fake);
        let text = ok_text(run(&host, "adam", "package_upgrade", json!({"all": true})).await);
        assert_eq!(fake.calls("apt-get"), vec![apt_argv(&[], &APT_ALL)]);
        assert_eq!(fake.calls("dpkg-query"), Calls::new());
        assert!(
            text.contains("Upgrade of all pending packages: done"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn a_package_that_is_not_installed_stops_the_upgrade_before_it_starts() {
        let fake = apt_host();
        let (host, _audit) = fixture(&fake);
        for dry_run in [true, false] {
            let arguments = json!({"packages": ["nginx", "ghost-pkg"], "dry_run": dry_run});
            match run(&host, "adam", "package_upgrade", arguments).await {
                Err(ToolError::Failed(message)) => {
                    assert!(message.contains("ghost-pkg"), "{message}");
                    assert!(!message.contains("nginx,"), "{message}");
                    assert!(message.contains("not installed"), "{message}");
                }
                other => panic!("expected a failure, got {other:?}"),
            }
        }
        assert_eq!(fake.calls("apt-get"), Calls::new());
        assert_eq!(fake.calls("systemd-run"), Calls::new());
    }

    #[tokio::test]
    async fn a_failed_upgrade_is_reported_as_an_error_with_its_output() {
        let fake = apt_host();
        let (host, _audit) = fixture(&fake);
        let arguments = json!({"packages": ["broken"]});
        let output = run(&host, "adam", "package_upgrade", arguments)
            .await
            .unwrap();
        assert!(output.is_error(), "{output:?}");
        assert!(output.text().contains("FAILED"), "{output:?}");
        assert!(output.text().contains("exit status 100"), "{output:?}");
        // the journal is still read: that is where the reason is
        assert_eq!(fake.calls("journalctl").len(), 1);
    }

    #[tokio::test]
    async fn an_upgrade_that_outlasts_the_call_is_left_running() {
        // a systemd-run that never comes back (a busy loop: stand-ins have only shell
        // built-ins), on a host whose calls may take 16 s: the wait is cut to 2 s
        let fake = apt_family()
            .add_script("apt-get", APT_GET)
            .add_script("systemd-run", "while :; do :; done")
            .add("journalctl", JOURNAL, 0)
            .add("systemctl", "active\n", 0);
        let (host, _audit) = host(&format!(
            "{ROLES}[limits]\ncommand_timeout_secs = 1\ncall_timeout_secs = 16\n{}",
            fake.config_only()
        ));
        let started = std::time::Instant::now();
        let arguments = json!({"packages": ["nginx"]});
        let text = ok_text(run(&host, "adam", "package_upgrade", arguments).await);
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        let unit = fake.calls("systemd-run")[0][0]
            .strip_prefix("--unit=")
            .unwrap()
            .to_string();
        assert!(text.contains("still running"), "{text}");
        assert!(text.contains(&format!("{unit}.service")), "{text}");
        assert!(text.contains("journal_query"), "{text}");
        assert_eq!(
            fake.calls("systemctl"),
            vec![strings(&["is-active", "--", &format!("{unit}.service")])]
        );
    }

    #[tokio::test]
    async fn a_run_that_ended_unseen_is_reported_as_unknown_not_as_done() {
        // systemd-run was cut off at the time limit, and the unit is no longer there
        let fake = apt_family()
            .add_script("apt-get", APT_GET)
            .add_script("systemd-run", "while :; do :; done")
            .add("journalctl", JOURNAL, 0)
            .add_script("systemctl", "echo inactive; exit 3");
        let (host, _audit) = host(&format!(
            "{ROLES}[limits]\ncommand_timeout_secs = 1\ncall_timeout_secs = 16\n{}",
            fake.config_only()
        ));
        let output = run(&host, "adam", "package_upgrade", json!({"all": true}))
            .await
            .unwrap();
        assert!(output.is_error(), "{output:?}");
        assert!(output.text().contains("not seen"), "{output:?}");
        assert!(output.text().contains("Setting up nginx"), "{output:?}");
    }

    #[tokio::test]
    async fn without_systemd_run_only_a_dry_run_is_possible() {
        let fake = apt_family().add_script("apt-get", APT_GET);
        let (host, _audit) = fixture(&fake);
        for arguments in [
            json!({"packages": ["nginx"]}),
            json!({"all": true}),
            json!({"all": true, "refresh": true}),
        ] {
            match run(&host, "adam", "package_upgrade", arguments).await {
                Err(ToolError::Failed(message)) => {
                    assert!(message.contains("systemd-run"), "{message}")
                }
                other => panic!("expected a failure, got {other:?}"),
            }
        }
        // nothing was started, not even the refresh that was asked for with it
        assert_eq!(fake.calls("apt-get"), Calls::new());
        let arguments = json!({"packages": ["nginx"], "dry_run": true});
        ok_text(run(&host, "adam", "package_upgrade", arguments).await);
        assert_eq!(fake.calls("apt-get").len(), 1);
    }

    #[tokio::test]
    async fn refresh_updates_the_lists_first_or_alone() {
        let fake = apt_host();
        let (host, _audit) = fixture(&fake);
        let text = ok_text(run(&host, "adam", "package_upgrade", json!({"refresh": true})).await);
        assert_eq!(fake.calls("apt-get"), vec![strings(&["update"])]);
        assert_eq!(fake.calls("systemd-run"), Calls::new());
        assert!(text.contains("jammy InRelease"), "{text}");
        assert!(text.contains("Package lists refreshed"), "{text}");

        let arguments = json!({"packages": ["nginx"], "refresh": true});
        let text = ok_text(run(&host, "wendy", "package_upgrade", arguments).await);
        let calls = fake.calls("apt-get");
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[1], strings(&["update"]));
        assert_eq!(
            calls[2],
            apt_argv(&[], &["--only-upgrade", "install", "--", "nginx"])
        );
        assert!(text.contains("Upgrade of nginx: done"), "{text}");
    }

    #[tokio::test]
    async fn a_failed_refresh_stops_before_the_upgrade() {
        let fake = apt_family()
            .add_script(
                "apt-get",
                "echo 'E: Failed to fetch http://archive.ubuntu.com/ubuntu/dists/jammy/InRelease' >&2; exit 100",
            )
            .add_script("systemd-run", SYSTEMD_RUN)
            .add("journalctl", JOURNAL, 0);
        let (host, _audit) = fixture(&fake);
        let arguments = json!({"packages": ["nginx"], "refresh": true});
        let output = run(&host, "adam", "package_upgrade", arguments)
            .await
            .unwrap();
        assert!(output.is_error());
        assert!(output.text().contains("Failed to fetch"), "{output:?}");
        assert!(output.text().contains("nothing was upgraded"), "{output:?}");
        assert_eq!(fake.calls("apt-get"), vec![strings(&["update"])]);
        assert_eq!(fake.calls("systemd-run"), Calls::new());
    }

    /// A stand-in dnf.
    const DNF: &str = r#"
case "$*" in
  *--assumeno*) echo 'Upgrading: nginx 1:1.20.1-16.el9'; echo 'Operation aborted.'; exit 1 ;;
  *makecache*) echo 'Metadata cache created.' ;;
  *) echo 'Upgraded: nginx-1:1.20.1-16.el9.x86_64'; echo 'Complete!' ;;
esac
"#;

    #[tokio::test]
    async fn upgrade_uses_dnf_on_an_rpm_host() {
        let fake = FakeBins::new()
            .add_script("rpm", RPM)
            .add_script("dnf", DNF)
            .add_script("systemd-run", SYSTEMD_RUN)
            .add("journalctl", "Complete!\n", 0);
        let (host, _audit) = fixture(&fake);
        // a dry run: dnf is told to answer "no", which makes it exit 1 by design
        let arguments = json!({"packages": ["nginx"], "dry_run": true});
        let text = ok_text(run(&host, "wendy", "package_upgrade", arguments).await);
        assert!(text.contains("Upgrading: nginx"), "{text}");
        assert!(text.contains("Dry run"), "{text}");
        assert!(!text.contains("exit status"), "{text}");
        // the real thing, with the lists refreshed first
        let arguments = json!({"packages": ["nginx"], "refresh": true});
        let text = ok_text(run(&host, "wendy", "package_upgrade", arguments).await);
        assert!(text.contains("Upgrade of nginx: done"), "{text}");
        assert_eq!(
            fake.calls("dnf"),
            vec![
                strings(&["--assumeno", "upgrade", "--", "nginx"]),
                strings(&["-q", "makecache"]),
                strings(&["-y", "upgrade", "--", "nginx"]),
            ]
        );
        let started = &fake.calls("systemd-run")[0];
        assert_eq!(
            started[6..],
            [
                "--".to_string(),
                path_of(&fake, "dnf"),
                "-y".to_string(),
                "upgrade".to_string(),
                "--".to_string(),
                "nginx".to_string()
            ]
        );
        assert_eq!(
            fake.calls("rpm")[0],
            strings(&["-q", "--qf", "%{NAME}\\n", "--", "nginx"])
        );
        // a package rpm does not have installed is refused here too
        let arguments = json!({"packages": ["ghost-pkg"]});
        let result = run(&host, "adam", "package_upgrade", arguments).await;
        assert!(matches!(result, Err(ToolError::Failed(_))), "{result:?}");
        assert_eq!(fake.calls("dnf").len(), 3);
    }
}
