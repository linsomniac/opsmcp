//! Scheduled jobs: systemd timers and cron.

use std::io::Read;
use std::path::{Path, PathBuf};

use super::args::{Args, Param};
use super::service::normalize_unit;
use super::{Ctx, Tool, ToolError, ToolResult, blocking, command_ok, command_text};
use crate::policy::Access;
use crate::sanitize::{keep_head, redact_text};

const KINDS: [&str; 3] = ["all", "timers", "cron"];
/// Most activated units whose last result is looked up.
const MAX_TIMER_UNITS: usize = 50;
/// Most bytes read from one crontab.
pub const MAX_CRONTAB_BYTES: usize = 256 * 1024;
/// Most crontab files read in one call.
const MAX_CRON_FILES: usize = 200;
/// Most names taken from one directory.
const MAX_NAMES: usize = 2000;
const PERIODIC: [&str; 4] = ["cron.hourly", "cron.daily", "cron.weekly", "cron.monthly"];

pub fn tools() -> Vec<Tool> {
    vec![Tool::new(
        "scheduled_jobs",
        "Show what is scheduled to run on this host: systemd timers (next and last run, \
         and the units whose last run failed) and cron jobs (/etc/crontab, /etc/cron.d, \
         users' crontabs and the scripts in cron.hourly, daily, weekly and monthly). Use \
         it to find what ran at a given time, or why a periodic job did not. Cron keeps \
         no record of runs: for those, query the journal.",
        Access::Read,
        "schedule.view",
        vec![Param::choice(
            "kind",
            "What to show: all (default), timers or cron",
            &KINDS,
        )],
        scheduled_jobs,
    )]
}

/// The units started by the timers in `systemctl list-timers` output, in order, each
/// once.
///
/// AIDEV-NOTE: the names go on a systemctl command line next, so only what
/// `normalize_unit` accepts as a complete unit name is taken: nothing that could be
/// read as an option or a pattern, whatever the listing contains.
pub fn activated_units(listing: &str) -> Vec<String> {
    let mut units: Vec<String> = Vec::new();
    for line in listing.lines() {
        // ... UNIT ACTIVATES are the last two columns; the dates before them have spaces
        let words: Vec<&str> = line.split_whitespace().collect();
        let [.., timer, activates] = words.as_slice() else {
            continue;
        };
        if !timer.ends_with(".timer") {
            continue;
        }
        let Ok(unit) = normalize_unit(activates) else {
            continue;
        };
        if unit != *activates || units.contains(&unit) {
            continue;
        }
        units.push(unit);
    }
    units
}

/// What is said about how the timers' units last ended. `failed` describes the ones that
/// did not succeed, among the `checked` units that were asked about, out of `total`.
pub fn last_runs_text(failed: &[String], checked: usize, total: usize) -> String {
    // AIDEV-NOTE: never claims more than was looked at. With more timers than are asked
    // about, "every unit succeeded" would be a statement about units nobody checked.
    let scope = if checked < total {
        format!(
            "[only the first {checked} of {total} units were checked; service_status shows any other]\n"
        )
    } else {
        String::new()
    };
    let mut text = String::new();
    if !failed.is_empty() {
        text.push_str("Units whose last run did NOT succeed (service_status shows why):\n");
        for line in failed {
            text.push_str(&format!("  {line}\n"));
        }
    } else if checked < total {
        text.push_str(
            "Last runs: the units that were checked ended successfully the last time they ran.\n",
        );
    } else {
        text.push_str(
            "Last runs: every unit these timers start ended successfully the last time it ran.\n",
        );
    }
    text.push_str(&scope);
    text
}

/// How a unit's most recent run ended.
#[derive(Debug, PartialEq, Eq)]
pub struct LastRun {
    pub unit: String,
    /// systemd's `Result`: success, exit-code, signal, timeout, core-dump...
    pub result: String,
    /// The main process's exit status, when systemd reports one.
    pub status: Option<String>,
}

/// Reads `systemctl show --property=Id,Result,ExecMainStatus` output for several units
/// (one block per unit, separated by blank lines). Units without a `Result` (anything
/// that is not a service) are left out.
pub fn parse_results(show: &str) -> Vec<LastRun> {
    let mut runs = Vec::new();
    let mut block: Vec<&str> = Vec::new();
    for line in show.lines().chain(std::iter::once("")) {
        if !line.trim().is_empty() {
            block.push(line);
            continue;
        }
        let field = |name: &str| {
            block.iter().find_map(|line| {
                let (key, value) = line.split_once('=')?;
                (key == name).then_some(value.trim())
            })
        };
        // What systemd printed is repeated in the answer: hold it to the form it has.
        let word = |v: &&str| {
            !v.is_empty() && v.len() <= 32 && v.chars().all(|c| c.is_ascii_lowercase() || c == '-')
        };
        let number =
            |v: &&str| !v.is_empty() && v.len() <= 6 && v.chars().all(|c| c.is_ascii_digit());
        if let (Some(unit), Some(result)) = (
            field("Id").filter(|id| normalize_unit(id).is_ok()),
            field("Result").filter(word),
        ) {
            runs.push(LastRun {
                unit: unit.to_string(),
                result: result.to_string(),
                status: field("ExecMainStatus").filter(number).map(str::to_string),
            });
        }
        block.clear();
    }
    runs
}

fn describe(run: &LastRun) -> String {
    match (run.result.as_str(), &run.status) {
        ("exit-code", Some(status)) => format!("{}: exit-code (exit status {status})", run.unit),
        (result, _) => format!("{}: {result}", run.unit),
    }
}

/// The systemd timers section, and whether systemd answered.
async fn timers(ctx: &Ctx) -> Result<(String, bool), ToolError> {
    let systemctl = match ctx.command("systemctl") {
        Ok(cmd) => cmd,
        // not a systemd host: say so and carry on with cron
        Err(ToolError::Failed(problem)) => {
            return Ok((format!("[systemd timers: {problem}]\n"), true));
        }
        Err(other) => return Err(other),
    };
    let listing = ctx
        .run(
            systemctl
                .clone()
                .args(["list-timers", "--all", "--no-pager"]),
        )
        .await?;
    let mut text = String::from("== systemd timers ==\n");
    text.push_str(&command_text(&listing));
    if !text.ends_with('\n') {
        text.push('\n');
    }
    if !command_ok(&listing) {
        return Ok((text, false));
    }
    let mut units = activated_units(&String::from_utf8_lossy(&listing.stdout));
    if units.is_empty() {
        return Ok((text, true));
    }
    let total = units.len();
    units.truncate(MAX_TIMER_UNITS);
    let checked = units.len();
    // One call for all of them: how did each unit's last run end?
    let mut argv = vec![
        "show".to_string(),
        "--property=Id,Result,ExecMainStatus".to_string(),
        "--".to_string(),
    ];
    argv.extend(units);
    let shown = ctx.run(systemctl.args(argv)).await?;
    if !command_ok(&shown) {
        text.push_str(&format!(
            "[how the last runs ended could not be read: {}]\n",
            command_text(&shown).trim()
        ));
        return Ok((text, true));
    }
    let failed: Vec<String> = parse_results(&String::from_utf8_lossy(&shown.stdout))
        .iter()
        .filter(|run| run.result != "success")
        .map(describe)
        .collect();
    text.push_str(&last_runs_text(&failed, checked, total));
    Ok((text, true))
}

/// Where cron's files are. The real locations, except in tests.
#[derive(Clone, Debug)]
pub struct CronRoots {
    /// Holds `crontab`, `cron.d` and the `cron.hourly`... directories.
    pub etc: PathBuf,
    /// Holds users' crontabs: in `crontabs/` (Debian, Ubuntu) or directly (RHEL).
    pub spool: PathBuf,
}

impl Default for CronRoots {
    fn default() -> Self {
        CronRoots {
            etc: PathBuf::from("/etc"),
            spool: PathBuf::from("/var/spool/cron"),
        }
    }
}

/// The lines of a crontab that say something: no comments, no blank lines, and with
/// what looks like a secret masked.
///
/// AIDEV-NOTE: cron lines are command lines and environment assignments, and they do
/// carry passwords and tokens. Tabs are turned into spaces first so that each field is a
/// word of its own to `redact_text` (it splits on spaces only).
pub fn crontab_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| redact_text(&line.replace('\t', " ")))
        .collect()
}

enum Crontab {
    /// The file's lines, and whether it was longer than is read.
    Lines(Vec<String>, bool),
    NotRegular,
    Unreadable(String),
}

/// Reads one crontab.
///
/// AIDEV-NOTE: the final component is never followed if it is a link, and only a
/// regular file is read. A user owns their crontab's content, and other software drops
/// files into cron.d: a link there must not make this tool (running as root) read
/// whatever it points to.
fn read_crontab(path: &Path) -> Crontab {
    use rustix::fs::{Mode, OFlags};
    let flags =
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::NOCTTY | OFlags::CLOEXEC;
    let file = match rustix::fs::open(path, flags, Mode::empty()) {
        Ok(fd) => std::fs::File::from(fd),
        Err(rustix::io::Errno::LOOP) => return Crontab::NotRegular,
        Err(e) => return Crontab::Unreadable(std::io::Error::from(e).to_string()),
    };
    match file.metadata() {
        Ok(meta) if meta.is_file() => {}
        Ok(_) => return Crontab::NotRegular,
        Err(e) => return Crontab::Unreadable(e.to_string()),
    }
    let mut data = Vec::new();
    if let Err(e) = file
        .take(MAX_CRONTAB_BYTES as u64 + 1)
        .read_to_end(&mut data)
    {
        return Crontab::Unreadable(e.to_string());
    }
    let truncated = data.len() > MAX_CRONTAB_BYTES;
    if truncated {
        data.truncate(MAX_CRONTAB_BYTES);
        // the cut falls inside a line: leave that line out
        let whole = data.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        data.truncate(whole);
    }
    Crontab::Lines(crontab_lines(&String::from_utf8_lossy(&data)), truncated)
}

/// The names in a directory, sorted, without hidden ones. A directory that does not
/// exist has no names; one that cannot be read is an error.
/// Whether Debian's and Ubuntu's cron and run-parts accept a file name: letters,
/// digits, `_` and `-` only. (Others, such as the `.dpkg-old` files a package upgrade
/// leaves behind, are skipped there; Red Hat's cron is less strict.)
fn debian_runs(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// A script in cron.daily and the like, marked if cron would not run it. A script is
/// switched off by taking away its execute permission, so listing it unmarked would say
/// that something is scheduled which is not.
fn periodic_label(dir: &Path, name: &str) -> String {
    use std::os::unix::fs::PermissionsExt;
    // metadata only (following a link, as run-parts does); nothing is read
    let executable = std::fs::metadata(dir.join(name))
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0);
    if !executable {
        format!("{name} (not executable: not run)")
    } else if !debian_runs(name) {
        format!("{name} (name not accepted by run-parts on Debian and Ubuntu: not run there)")
    } else {
        name.to_string()
    }
}

fn names_in(dir: &Path) -> Result<Vec<String>, String> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.to_string()),
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
        .filter(|name| !name.starts_with('.'))
        .take(MAX_NAMES)
        .collect();
    names.sort();
    Ok(names)
}

/// The cron section as it is built up.
#[derive(Default)]
struct CronReport {
    text: String,
    notes: Vec<String>,
    files: usize,
    /// Files not read because `MAX_CRON_FILES` had been reached.
    beyond_limit: usize,
    found: bool,
}

impl CronReport {
    /// Adds one crontab: `owner` is the user whose crontab it is, for those in the spool.
    fn file(&mut self, path: &Path, owner: Option<&str>) {
        if self.files >= MAX_CRON_FILES {
            self.beyond_limit += 1;
            return;
        }
        self.files += 1;
        let shown = path.display();
        match read_crontab(path) {
            Crontab::Lines(lines, truncated) => {
                if lines.is_empty() && !truncated {
                    return;
                }
                self.found = true;
                match owner {
                    Some(user) => self.text.push_str(&format!("{shown} (user {user}):\n")),
                    None => self.text.push_str(&format!("{shown}:\n")),
                }
                for line in lines {
                    self.text.push_str(&format!("  {line}\n"));
                }
                if truncated {
                    self.text.push_str(&format!(
                        "  [only the first {} KiB of this file were read]\n",
                        MAX_CRONTAB_BYTES / 1024
                    ));
                }
            }
            Crontab::NotRegular => self.notes.push(format!(
                "{shown} is not a regular file (a link, perhaps): it was not read"
            )),
            Crontab::Unreadable(why) => {
                self.notes.push(format!("{shown} cannot be read: {why}"));
            }
        }
    }

    /// Adds every crontab in `dir`. `user_crontabs`: the file names are user names.
    fn directory(&mut self, dir: &Path, user_crontabs: bool) {
        let names = match names_in(dir) {
            Ok(names) => names,
            Err(why) => {
                let what = if user_crontabs {
                    "users' crontabs: "
                } else {
                    ""
                };
                self.notes
                    .push(format!("{what}{} cannot be read: {why}", dir.display()));
                return;
            }
        };
        for name in names {
            let path = dir.join(&name);
            // sub-directories (the spool holds `crontabs`, `atjobs`...) are not crontabs
            if std::fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_dir()) {
                continue;
            }
            self.file(&path, user_crontabs.then_some(name.as_str()));
            if !user_crontabs && !debian_runs(&name) {
                self.notes.push(format!(
                    "{} has a name that cron on Debian and Ubuntu ignores (only letters, \
                     digits, _ and - are read there)",
                    path.display()
                ));
            }
        }
    }
}

/// The cron section: every place cron reads its jobs from.
fn cron_report(roots: &CronRoots) -> String {
    let mut report = CronReport::default();
    let system = roots.etc.join("crontab");
    if std::fs::symlink_metadata(&system).is_ok() {
        report.file(&system, None);
    }
    report.directory(&roots.etc.join("cron.d"), false);
    report.directory(&roots.spool.join("crontabs"), true);
    report.directory(&roots.spool, true);
    for name in PERIODIC {
        match names_in(&roots.etc.join(name)) {
            Ok(scripts) if !scripts.is_empty() => {
                report.found = true;
                let dir = roots.etc.join(name);
                let labels: Vec<String> = scripts
                    .iter()
                    .map(|script| periodic_label(&dir, script))
                    .collect();
                report
                    .text
                    .push_str(&format!("{name}: {}\n", labels.join(", ")));
            }
            Ok(_) => {}
            Err(why) => report.notes.push(format!(
                "{} cannot be read: {why}",
                roots.etc.join(name).display()
            )),
        }
    }

    let mut text = String::from("== cron ==\n");
    if report.found {
        text.push_str(&report.text);
    } else {
        text.push_str("(no cron jobs found)\n");
    }
    if report.beyond_limit > 0 {
        text.push_str(&format!(
            "[{} more crontab files were not read: only the first {MAX_CRON_FILES} are]\n",
            report.beyond_limit
        ));
    }
    for note in &report.notes {
        text.push_str(&format!("[{note}]\n"));
    }
    if report.found {
        text.push_str(
            "[cron does not record when a job last ran or how it ended: the journal has that \
             (journal_query with identifier CRON, or crond on some systems)]\n",
        );
    }
    text
}

async fn scheduled_jobs(ctx: Ctx, args: Args) -> ToolResult {
    let kind = args.str("kind").unwrap_or("all").to_string();
    scheduled_jobs_at(ctx, &kind, CronRoots::default()).await
}

/// `scheduled_jobs` with cron's files looked for under `roots`.
pub async fn scheduled_jobs_at(ctx: Ctx, kind: &str, roots: CronRoots) -> ToolResult {
    let auth = ctx.authorize(None)?;
    let mut text = String::new();
    let mut answered = true;
    if kind != "cron" {
        let (section, ok) = timers(&ctx).await?;
        text.push_str(&section);
        answered = ok;
    }
    if kind != "timers" {
        let section = blocking(ctx.clone(), move || Ok(cron_report(&roots))).await?;
        text.push_str(&section);
    }
    // Timers come first and are short; if there is too much, it is cron lines that go.
    let (mut kept, dropped) = keep_head(&text, ctx.output_budget().saturating_sub(160));
    if dropped > 0 {
        kept.push_str(&format!(
            "[{dropped} more lines left out to fit the output limit; ask for kind=timers and \
             kind=cron separately]\n"
        ));
    }
    auth.done(kept, answered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::policy::Access;
    use crate::tools::testing::{FakeBins, call, ctx, find, host, ok_text};
    use crate::tools::{Host, ToolError, ToolResult};
    use serde_json::{Value, json};
    use std::path::Path;
    use std::sync::Arc;

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    const NO_CALLS: Vec<Vec<String>> = Vec::new();

    const TIMERS: &str = "\
NEXT                        LEFT          LAST                        PASSED       UNIT                         ACTIVATES
Fri 2026-11-20 10:39:00 UTC 12min left    Fri 2026-11-20 10:09:00 UTC 17min ago    phpsessionclean.timer        phpsessionclean.service
Sat 2026-11-21 00:00:00 UTC 13h left      Fri 2026-11-20 00:00:01 UTC 10h ago      logrotate.timer              logrotate.service
Sat 2026-11-21 03:10:00 UTC 16h left      Fri 2026-11-20 03:10:00 UTC 7h ago       backup.timer                 backup.service
n/a                         n/a           n/a                         n/a          apt-daily.timer              apt-daily.service
n/a                         n/a           n/a                         n/a          broken.timer                 n/a

5 timers listed.
";

    const SHOWN: &str = "\
Id=phpsessionclean.service
Result=success
ExecMainStatus=0

Result=exit-code
ExecMainStatus=1
Id=backup.service

Id=logrotate.service
Result=success
ExecMainStatus=0

Id=apt-daily.service
Result=timeout
ExecMainStatus=0
";

    #[test]
    fn the_units_that_timers_activate_are_read_from_the_listing() {
        assert_eq!(
            activated_units(TIMERS),
            [
                "phpsessionclean.service",
                "logrotate.service",
                "backup.service",
                "apt-daily.service"
            ]
        );
        assert_eq!(activated_units(""), Vec::<String>::new());
        assert_eq!(activated_units("0 timers listed.\n"), Vec::<String>::new());
    }

    #[test]
    fn only_real_unit_names_are_taken_from_the_listing() {
        // a listing is program output: nothing from it may become an option or a pattern
        let odd = "n/a n/a a.timer --now\nn/a n/a b.timer ssh*.service\nn/a n/a c.timer ok.service\n\
                   n/a n/a d.timer ok.service\nn/a n/a e.timer plain\nn/a n/a f.notatimer x.service\n";
        assert_eq!(activated_units(odd), ["ok.service"]);
        let many: String = (0..80)
            .map(|i| format!("n/a n/a t{i}.timer job{i}.service\n"))
            .collect();
        // every one is found; how many are then asked about is the caller's business
        assert_eq!(activated_units(&many).len(), 80);
    }

    #[test]
    fn the_last_runs_line_only_claims_what_was_checked() {
        assert_eq!(
            last_runs_text(&[], 12, 12),
            "Last runs: every unit these timers start ended successfully the last time it ran.\n"
        );
        // AIDEV-NOTE: with more timers than are asked about, "every unit succeeded"
        // would be a claim about units nobody looked at.
        let partial = last_runs_text(&[], 50, 80);
        assert!(partial.contains("first 50 of 80"), "{partial}");
        assert!(!partial.contains("every unit"), "{partial}");
        let failed = last_runs_text(&["backup.service: failed".to_string()], 50, 80);
        assert!(failed.contains("did NOT succeed"), "{failed}");
        assert!(failed.contains("  backup.service: failed\n"), "{failed}");
        assert!(failed.contains("first 50 of 80"), "{failed}");
    }

    #[test]
    fn periodic_scripts_that_cron_would_not_run_are_marked() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, roots) = cron_tree();
        let daily = roots.etc.join("cron.daily");
        // switched off the usual way: chmod -x
        std::fs::write(daily.join("disabled"), "#!/bin/sh\n").unwrap();
        // left behind by a package upgrade: run-parts skips names with a dot
        std::fs::write(daily.join("logrotate.dpkg-old"), "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(
            daily.join("logrotate.dpkg-old"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::fs::write(
            roots.etc.join("cron.d/sysstat.dpkg-dist"),
            "5 * * * * root old-job\n",
        )
        .unwrap();
        let text = cron_report(&roots);
        assert!(
            text.contains(
                "cron.daily: apt-compat, disabled (not executable: not run), logrotate, \
                 logrotate.dpkg-old (name not accepted by run-parts on Debian and Ubuntu: not run there)\n"
            ),
            "{text}"
        );
        assert!(text.contains("old-job"), "{text}");
        assert!(
            text.contains(
                "cron.d/sysstat.dpkg-dist has a name that cron on Debian and Ubuntu ignores"
            ),
            "{text}"
        );
    }

    #[test]
    fn last_results_are_read_block_by_block_in_any_order() {
        let runs = parse_results(SHOWN);
        let brief: Vec<(&str, &str, Option<&str>)> = runs
            .iter()
            .map(|r| (r.unit.as_str(), r.result.as_str(), r.status.as_deref()))
            .collect();
        assert_eq!(
            brief,
            [
                ("phpsessionclean.service", "success", Some("0")),
                ("backup.service", "exit-code", Some("1")),
                ("logrotate.service", "success", Some("0")),
                ("apt-daily.service", "timeout", Some("0")),
            ]
        );
        // a unit with no Result (a target, say) has nothing to report
        assert_eq!(parse_results("Id=multi-user.target\n").len(), 0);
        // values that are not what systemd prints are not passed on
        assert_eq!(
            parse_results("Id=a.service\nResult=$(id)\nExecMainStatus=0\n").len(),
            0
        );
    }

    #[test]
    fn crontab_lines_drop_comments_and_mask_secrets() {
        let text = "# m h dom mon dow user command\n\nSHELL=/bin/sh\n  # indented comment\n\
                    17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly\n\
                    0 3 * * * postgres PGPASSWORD=hunter2 pg_dump --password=hunter3 db\n";
        // tabs become spaces, so that each field is looked at on its own for secrets
        assert_eq!(
            crontab_lines(text),
            [
                "SHELL=/bin/sh",
                "17 * * * * root    cd / && run-parts --report /etc/cron.hourly",
                "0 3 * * * postgres PGPASSWORD=<redacted> pg_dump --password=<redacted> db",
            ]
        );
        // a secret in a tab-separated field is still found
        assert_eq!(
            crontab_lines("0 3 * * *\troot\tAPI_TOKEN=abc123\t/usr/local/bin/sync\n"),
            ["0 3 * * * root API_TOKEN=<redacted> /usr/local/bin/sync"]
        );
    }

    fn fake_systemctl() -> FakeBins {
        let emit = |text: &str| {
            format!(
                "while IFS= read -r line; do printf '%s\\n' \"$line\"; done <<'EOF'\n{}\nEOF\n",
                text.trim_end()
            )
        };
        FakeBins::new().add_script(
            "systemctl",
            &format!(
                "case \"$1\" in\n list-timers) {} ;;\n show) {} ;;\nesac",
                emit(TIMERS),
                emit(SHOWN)
            ),
        )
    }

    fn fixture(fake: &FakeBins, extra: &str) -> (Arc<Host>, MemorySink) {
        host(&format!(
            r#"
[roles.reader]
allow = ["@read"]
[roles.other]
allow = ["system.view"]
[unix_users.rita]
roles = ["reader"]
[unix_users.otto]
roles = ["other"]
{extra}
{}"#,
            fake.config_only()
        ))
    }

    /// A small /etc and cron spool under a temporary directory.
    fn cron_tree() -> (tempfile::TempDir, CronRoots) {
        let dir = tempfile::tempdir().unwrap();
        let etc = dir.path().join("etc");
        let spool = dir.path().join("spool");
        for sub in ["cron.d", "cron.daily", "cron.hourly", "cron.weekly"] {
            std::fs::create_dir_all(etc.join(sub)).unwrap();
        }
        std::fs::create_dir_all(spool.join("crontabs")).unwrap();
        let write = |path: &Path, text: &str| std::fs::write(path, text).unwrap();
        write(
            &etc.join("crontab"),
            "# system crontab\nSHELL=/bin/sh\n17 * * * * root run-parts /etc/cron.hourly\n",
        );
        write(
            &etc.join("cron.d/sysstat"),
            "# sysstat\n5-55/10 * * * * root debian-sa1 1 1\n",
        );
        write(
            &etc.join("cron.d/backup"),
            "0 3 * * * root /usr/local/bin/backup --token abc123 /srv\n",
        );
        write(&etc.join("cron.d/.placeholder"), "# hidden\n");
        write(&etc.join("cron.daily/logrotate"), "#!/bin/sh\n");
        write(&etc.join("cron.daily/apt-compat"), "#!/bin/sh\n");
        write(&etc.join("cron.daily/.placeholder"), "");
        write(&etc.join("cron.weekly/man-db"), "#!/bin/sh\n");
        for script in [
            "cron.daily/logrotate",
            "cron.daily/apt-compat",
            "cron.weekly/man-db",
        ] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(etc.join(script), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        write(
            &spool.join("crontabs/www-data"),
            "# DO NOT EDIT THIS FILE\n*/5 * * * * /usr/local/bin/job\n",
        );
        let roots = CronRoots { etc, spool };
        (dir, roots)
    }

    async fn at(host: &Arc<Host>, user: &str, kind: &str, roots: &CronRoots) -> ToolResult {
        scheduled_jobs_at(
            ctx(host, user, "schedule.view", Access::Read),
            kind,
            roots.clone(),
        )
        .await
    }

    async fn run(host: &Arc<Host>, user: &str, arguments: Value) -> ToolResult {
        call(host, user, &find(tools(), "scheduled_jobs"), arguments).await
    }

    #[tokio::test]
    async fn timers_are_listed_with_the_units_whose_last_run_failed() {
        let fake = fake_systemctl();
        let (host, audit) = fixture(&fake, "");
        let (_dir, roots) = cron_tree();
        let text = ok_text(at(&host, "rita", "timers", &roots).await);
        assert!(text.contains("== systemd timers =="), "{text}");
        assert!(text.contains("logrotate.timer"), "{text}");
        assert!(text.contains("5 timers listed."), "{text}");
        assert!(
            text.contains("backup.service: exit-code (exit status 1)"),
            "{text}"
        );
        assert!(text.contains("apt-daily.service: timeout"), "{text}");
        assert!(!text.contains("logrotate.service: "), "{text}");
        // nothing about cron was asked for
        assert!(!text.contains("cron"), "{text}");
        assert_eq!(
            fake.calls("systemctl"),
            [
                strings(&["list-timers", "--all", "--no-pager"]),
                strings(&[
                    "show",
                    "--property=Id,Result,ExecMainStatus",
                    "--",
                    "phpsessionclean.service",
                    "logrotate.service",
                    "backup.service",
                    "apt-daily.service"
                ]),
            ]
        );
        let record = audit.records().last().unwrap().clone();
        assert_eq!(record["decision"], "allow");
        assert!(record.get("resource").is_none(), "{record}");
    }

    #[tokio::test]
    async fn all_timers_succeeding_is_said_in_one_line() {
        let fine = "Id=a.service\nResult=success\nExecMainStatus=0\n";
        let fake = FakeBins::new().add_script(
            "systemctl",
            &format!(
                "case \"$1\" in\n list-timers) echo 'n/a n/a a.timer a.service' ;;\n show) printf '{}' ;;\nesac",
                fine.replace('\n', "\\n")
            ),
        );
        let (host, _audit) = fixture(&fake, "");
        let (_dir, roots) = cron_tree();
        let text = ok_text(at(&host, "rita", "timers", &roots).await);
        assert!(text.contains("ended successfully"), "{text}");
    }

    #[tokio::test]
    async fn cron_jobs_are_shown_from_every_place_cron_reads() {
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake, "");
        let (_dir, roots) = cron_tree();
        let text = ok_text(at(&host, "rita", "cron", &roots).await);
        let etc = roots.etc.display().to_string();
        let spool = roots.spool.display().to_string();
        assert!(text.contains(&format!("{etc}/crontab:\n")), "{text}");
        assert!(
            text.contains("  17 * * * * root run-parts /etc/cron.hourly\n"),
            "{text}"
        );
        assert!(text.contains("  SHELL=/bin/sh\n"), "{text}");
        assert!(text.contains(&format!("{etc}/cron.d/sysstat:\n")), "{text}");
        assert!(text.contains("debian-sa1 1 1"), "{text}");
        assert!(
            text.contains(&format!("{spool}/crontabs/www-data (user www-data):\n")),
            "{text}"
        );
        assert!(
            text.contains("  */5 * * * * /usr/local/bin/job\n"),
            "{text}"
        );
        assert!(
            text.contains("cron.daily: apt-compat, logrotate\n"),
            "{text}"
        );
        assert!(text.contains("cron.weekly: man-db\n"), "{text}");
        // comments, hidden files and empty directories are not shown
        assert!(!text.contains("DO NOT EDIT"), "{text}");
        assert!(!text.contains("placeholder"), "{text}");
        assert!(!text.contains("cron.hourly:"), "{text}");
        // secrets on command lines are masked
        assert!(!text.contains("abc123"), "{text}");
        assert!(text.contains("--token <redacted>"), "{text}");
        // cron keeps no record of runs: say where to look instead
        assert!(text.contains("does not record"), "{text}");
        assert_eq!(fake.calls("systemctl"), NO_CALLS);
    }

    #[tokio::test]
    async fn a_symbolic_link_among_the_crontabs_is_not_followed() {
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake, "");
        let (dir, roots) = cron_tree();
        let secret = dir.path().join("secret");
        std::fs::write(&secret, "0 0 * * * root echo TOP-SECRET-CONTENT\n").unwrap();
        std::os::unix::fs::symlink(&secret, roots.etc.join("cron.d/link")).unwrap();
        std::os::unix::fs::symlink(&secret, roots.spool.join("crontabs/mallory")).unwrap();
        let text = ok_text(at(&host, "rita", "cron", &roots).await);
        assert!(!text.contains("TOP-SECRET-CONTENT"), "{text}");
        assert!(text.contains("cron.d/link"), "{text}");
        assert!(text.contains("not a regular file"), "{text}");
        // the real files are still shown
        assert!(text.contains("debian-sa1"), "{text}");
    }

    #[tokio::test]
    async fn an_oversized_crontab_is_cut_and_said_to_be() {
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake, "[limits]\nmax_output_bytes = 1048576\n");
        let (_dir, roots) = cron_tree();
        let mut big = String::new();
        for i in 0..9000 {
            big.push_str(&format!(
                "{} 1 * * * root /usr/local/bin/job-number-{i}\n",
                i % 60
            ));
        }
        assert!(big.len() > MAX_CRONTAB_BYTES);
        std::fs::write(roots.etc.join("cron.d/big"), &big).unwrap();
        let text = ok_text(at(&host, "rita", "cron", &roots).await);
        assert!(text.contains("job-number-0\n"), "{text}");
        assert!(
            !text.contains("job-number-8999"),
            "the end is beyond the cap"
        );
        assert!(text.contains("only the first"), "{text}");
    }

    #[tokio::test]
    async fn an_unreadable_spool_directory_gets_one_note() {
        use std::os::unix::fs::PermissionsExt;
        if rustix::process::geteuid().is_root() {
            return; // root can read anything: nothing to test
        }
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake, "");
        let (_dir, roots) = cron_tree();
        let crontabs = roots.spool.join("crontabs");
        std::fs::set_permissions(&crontabs, std::fs::Permissions::from_mode(0o000)).unwrap();
        let text = ok_text(at(&host, "rita", "cron", &roots).await);
        std::fs::set_permissions(&crontabs, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(text.matches("cannot be read").count(), 1, "{text}");
        assert!(text.contains("crontabs"), "{text}");
        assert!(!text.contains("www-data"), "{text}");
        // what could be read is still shown
        assert!(text.contains("debian-sa1"), "{text}");
    }

    #[tokio::test]
    async fn a_host_without_cron_directories_says_so_plainly() {
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake, "");
        let dir = tempfile::tempdir().unwrap();
        let roots = CronRoots {
            etc: dir.path().join("etc"),
            spool: dir.path().join("spool"),
        };
        let text = ok_text(at(&host, "rita", "cron", &roots).await);
        assert!(text.contains("no cron jobs found"), "{text}");
    }

    #[tokio::test]
    async fn everything_is_shown_by_default_and_a_missing_systemctl_is_only_a_note() {
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake, "");
        let (_dir, roots) = cron_tree();
        let text = ok_text(at(&host, "rita", "all", &roots).await);
        assert!(text.contains("== systemd timers =="), "{text}");
        assert!(text.contains("== cron =="), "{text}");
        assert!(
            text.find("== systemd timers ==") < text.find("== cron =="),
            "{text}"
        );

        let none = FakeBins::new().add("unrelated", "", 0);
        let (host, _audit) = fixture(&none, "");
        let text = ok_text(at(&host, "rita", "all", &roots).await);
        assert!(text.contains("[systemd timers:"), "{text}");
        assert!(text.contains("systemctl"), "{text}");
        assert!(text.contains("debian-sa1"), "{text}");
    }

    #[tokio::test]
    async fn a_failing_systemctl_is_reported_as_an_error_but_cron_is_still_shown() {
        let fake = FakeBins::new().add_script(
            "systemctl",
            "echo 'System has not been booted with systemd as init system' >&2; exit 1",
        );
        let (host, _audit) = fixture(&fake, "");
        let (_dir, roots) = cron_tree();
        let output = at(&host, "rita", "all", &roots).await.unwrap();
        assert!(output.is_error());
        assert!(
            output.text().contains("not been booted"),
            "{}",
            output.text()
        );
        assert!(output.text().contains("debian-sa1"), "{}", output.text());
        // only the listing was attempted
        assert_eq!(fake.calls("systemctl").len(), 1);
    }

    #[tokio::test]
    async fn long_output_is_cut_to_the_limit_with_a_note() {
        let fake = fake_systemctl();
        let (host, _audit) = fixture(&fake, "[limits]\nmax_output_bytes = 4096\n");
        let (_dir, roots) = cron_tree();
        let mut many = String::new();
        for i in 0..2000 {
            many.push_str(&format!(
                "{} 2 * * * root /usr/local/bin/task-{i}\n",
                i % 60
            ));
        }
        std::fs::write(roots.etc.join("cron.d/many"), many).unwrap();
        let text = ok_text(at(&host, "rita", "all", &roots).await);
        assert!(text.len() <= 4096, "{} bytes", text.len());
        assert!(text.contains("left out"), "{text}");
        assert!(text.contains("== systemd timers =="), "{text}");
    }

    #[tokio::test]
    async fn the_tool_takes_a_kind_and_nothing_runs_without_the_permission() {
        let fake = fake_systemctl();
        let (host, audit) = fixture(&fake, "");
        // through the registered tool: the kind is validated and passed on
        let text = ok_text(run(&host, "rita", json!({"kind": "timers"})).await);
        assert!(text.contains("== systemd timers =="), "{text}");
        assert!(!text.contains("== cron =="), "{text}");
        let result = run(&host, "rita", json!({"kind": "at"})).await;
        assert!(matches!(result, Err(ToolError::Invalid(_))), "{result:?}");

        let before = fake.calls("systemctl").len();
        let result = run(&host, "otto", json!({})).await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        assert_eq!(audit.records().last().unwrap()["decision"], "deny");
        assert_eq!(fake.calls("systemctl").len(), before);
    }
}
