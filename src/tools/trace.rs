//! Tracing system calls and profiling CPU use.
//!
//! AIDEV-NOTE: both tools attach an instrument to a running process, so both are off
//! until the host's configuration says which processes may be attached to
//! (`trace.processes`) or that the whole host may be sampled (`trace.system_wide`).

use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::args::{Args, Param};
use super::fs::Names;
use super::process::{Proc, resource_of};
use super::{
    Authorized, CallClock, Ctx, Tool, ToolError, ToolResult, blocking, command_ok, command_text,
    required,
};
use crate::exec::CmdOutput;
use crate::glob::glob_match;
use crate::policy::Access;
use crate::sanitize::{keep_head, keep_tail, redact_text};

/// The kinds of system call a call trace can be limited to (strace's `%class` names).
const SYSCALL_CLASSES: [&str; 8] = [
    "all", "file", "network", "process", "signal", "ipc", "desc", "memory",
];
const MAX_PID: i64 = 4_194_304;
/// How many times a second perf samples each CPU. An odd number, so that sampling does
/// not fall into step with anything that runs on a round-numbered timer.
const SAMPLE_HZ: u32 = 99;
/// After the interrupt that ends a trace, how long strace gets before it is killed.
const KILL_AFTER_SECS: u64 = 3;
/// What is added to a trace's own time to get the limit after which the server itself
/// ends it: the backstop, should `timeout` fail to.
const TRACE_SLACK_SECS: u64 = 8;
/// How long perf may take, on top of the sampling time, to write its data out.
const RECORD_SLACK_SECS: u64 = 15;
/// Most that is shown of what perf says when it cannot record.
const PERF_FAILURE_BYTES: usize = 1500;
const HOST_REFUSAL: &str = "attaching to this process is not allowed on this host \
                            (trace.processes in the configuration)";

/// Where cpu_profile may keep its scratch files. Tests point this at a temporary
/// directory.
#[derive(Clone, Debug)]
pub struct Env {
    /// Directories in which the private scratch directory may be made, in order of
    /// preference.
    pub scratch_bases: Vec<PathBuf>,
}

impl Env {
    pub fn system() -> Env {
        // AIDEV-NOTE: fixed places, never $TMPDIR. The server's environment belongs to
        // whoever started it; under sudo that is the caller, and root must not be told
        // by a caller where to create files. /run is root's own; a non-root server
        // cannot create there and falls through to /tmp, whose sticky bit keeps other
        // users' hands off what we make.
        Env {
            scratch_bases: vec![PathBuf::from("/run"), PathBuf::from("/tmp")],
        }
    }
}

pub fn tools() -> Vec<Tool> {
    tools_with(Env::system())
}

pub fn tools_with(env: Env) -> Vec<Tool> {
    vec![
        // AIDEV-NOTE: process_trace changes nothing lasting on the host, yet it is tagged
        // WRITE on purpose. strace stops the process at every system call (a busy
        // process can run many times slower while traced) and shows the files and
        // addresses it uses. `@read` must never include that. See packet_capture for
        // the same reasoning.
        Tool::new(
            "process_trace",
            "Trace the system calls of one process with strace, for a few seconds: either a \
             summary (calls, errors and time per system call) or the calls themselves. Use \
             it to see what a stuck or slow process is doing: which call it hangs in, which \
             file or address it keeps failing on. The process runs much slower while it is \
             traced. The contents of what it reads and writes are never shown; file names \
             and network addresses are. Only processes this host's configuration lists can \
             be traced, and you must give the process's name as well as its pid.",
            Access::Write,
            "process.trace",
            vec![
                Param::int("pid", "Process id", 1, MAX_PID).required(),
                Param::str(
                    "name",
                    "The process's name (as in process_list), to confirm the target",
                )
                .max_len(64)
                .required(),
                Param::int("seconds", "How long to trace (default 5)", 1, 30),
                Param::choice(
                    "mode",
                    "summary: a table of calls, errors and time per system call (default). \
                     calls: the system calls themselves, newest last",
                    &["summary", "calls"],
                ),
                Param::choice(
                    "class",
                    "For mode calls: only this kind of system call (default all)",
                    &SYSCALL_CLASSES,
                ),
                Param::int(
                    "lines",
                    "For mode calls: most lines to keep, the newest (default 200)",
                    10,
                    500,
                ),
            ],
            process_trace,
        ),
        Tool::new(
            "cpu_profile",
            "Sample with perf for a few seconds and show where CPU time goes: the busiest \
             functions, processes or libraries of one process (give pid and name) or of the \
             whole host (give neither). Use it when something uses a lot of CPU and you need \
             to know what it is doing. Sampling costs little and shows only names, never \
             data. One process can be profiled only if this host's configuration lists it; \
             the whole host only if the configuration allows that.",
            Access::Read,
            "process.profile",
            vec![
                Param::int(
                    "pid",
                    "Process id (with name). Leave both out to profile the whole host",
                    1,
                    MAX_PID,
                ),
                Param::str(
                    "name",
                    "The process's name (as in process_list), to confirm the target",
                )
                .max_len(64),
                Param::int("seconds", "How long to sample (default 10)", 1, 30),
                Param::choice(
                    "by",
                    "What to total the samples by (default function)",
                    &["function", "process", "library"],
                ),
                Param::int("limit", "Most rows to show (default 30)", 5, 100),
            ],
            move |ctx, args| cpu_profile(ctx, args, env.clone()),
        ),
    ]
}

// ---- which process ----------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Purpose {
    Trace,
    Profile,
}

/// A process that may be attached to: every check has passed.
struct Target {
    pid: i32,
    name: String,
    owner: String,
    /// When it started, in clock ticks after boot: what tells it from a later process
    /// that was given the same pid.
    starttime: u64,
    auth: Authorized,
}

/// Decides whether the process with this pid may be traced or profiled.
fn examine(ctx: &Ctx, pid: i32, expected: &str, purpose: Purpose) -> Result<Target, ToolError> {
    let process =
        Proc::read(pid).ok_or_else(|| ToolError::Failed(format!("there is no process {pid}")))?;
    let owner = Names::default().user(process.uid).to_string();
    let resource = resource_of(&owner, &process);
    if purpose == Purpose::Trace {
        let refusal = if pid == 1 {
            Some("pid 1 (init) cannot be traced through opsmcp")
        } else if u32::try_from(pid).is_ok_and(|p| p == std::process::id()) {
            Some("opsmcp will not trace itself")
        } else if process.is_kernel_thread() {
            Some("kernel threads cannot be traced")
        } else {
            None
        };
        if let Some(reason) = refusal {
            return Err(ctx.deny(Some(&resource), reason));
        }
    }
    let host_allows = ctx
        .cfg()
        .trace
        .processes
        .iter()
        .any(|pattern| glob_match(pattern, &resource));
    // AIDEV-NOTE: the host-wide limit comes first, as everywhere, but it is only SAID to
    // a caller whose own grant covers this process. The caller gave a pid, not a name:
    // if everyone were told "the host does not list this process", a caller allowed to
    // trace only nginx could learn from the two different refusals whether any pid they
    // pick matches the host's list, and so something about whose process it is. A caller
    // without the grant gets the plain permission refusal either way, which names
    // nothing.
    if !host_allows && ctx.permits(&resource) {
        return Err(ctx.deny(Some(&resource), HOST_REFUSAL));
    }
    let auth = ctx.authorize_hidden(Some(&resource))?;
    if !host_allows {
        // Not reached: without the host's leave the policy refused just above. Kept so
        // that no later change to that logic can let a process through.
        return Err(ctx.deny(Some(&resource), HOST_REFUSAL));
    }
    // After the permission check, as in process_signal: otherwise wrong guesses would
    // read off the name of any pid.
    if process.stat.comm != expected {
        let verb = match purpose {
            Purpose::Trace => "traced",
            Purpose::Profile => "profiled",
        };
        return Err(ToolError::Invalid(format!(
            "process {pid} is named {:?}, not {expected:?}; nothing was {verb}",
            process.stat.comm
        )));
    }
    Ok(Target {
        pid,
        name: process.stat.comm,
        owner,
        starttime: process.stat.starttime,
        auth,
    })
}

/// What has become of the process that was examined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Identity {
    /// Still there.
    Same,
    /// It has ended and nothing has its pid.
    Gone,
    /// It has ended and ANOTHER process has been given its pid.
    Replaced,
}

/// Compares the start time the examined process had with the start time of whatever has
/// its pid now (`None`: nothing has).
pub fn identity(expected_start: u64, now_start: Option<u64>) -> Identity {
    match now_start {
        None => Identity::Gone,
        Some(start) if start == expected_start => Identity::Same,
        Some(_) => Identity::Replaced,
    }
}

/// AIDEV-NOTE: strace and perf are given a pid, and a pid is only a number: unlike the
/// signal in process_signal there is no way to hand them the pinned process itself. So
/// the start time is compared immediately before the command starts and again when it
/// has finished. A different process under the same pid afterwards means that what was
/// captured may not be the process that was checked, and it is thrown away. What is left
/// is a process that ends, has its pid reused AND that second process ends too, all
/// within the few seconds of one trace: the kernel hands out pids in sequence, so that
/// takes a full wrap of the pid space in that time.
async fn identity_now(ctx: &Ctx, pid: i32, starttime: u64) -> Result<Identity, ToolError> {
    blocking(ctx.clone(), move || {
        Ok(identity(
            starttime,
            Proc::read(pid).map(|process| process.stat.starttime),
        ))
    })
    .await
}

fn replaced_text(pid: i32) -> String {
    format!(
        "Process {pid} ended and its pid was given to another process while this was being \
         set up or running, so what was captured may not be from the process you named. \
         Nothing is shown.\n"
    )
}

/// How long to trace or sample: what was asked for (1 to 30 seconds), but always leaving
/// `reserve` seconds of the call's own time limit for everything else.
pub fn bounded_seconds(asked: i64, call_timeout_secs: u64, reserve: u64) -> u64 {
    u64::try_from(asked.clamp(1, 30))
        .unwrap_or(1)
        .min(call_timeout_secs.saturating_sub(reserve))
        .max(1)
}

/// The full path of a program that another program is told to run. It is the path the
/// server itself found in its configured directories (and, as root, checked), so that
/// nothing is looked up through a search path a second time.
fn program_path(ctx: &Ctx, name: &str, missing: &str) -> Result<String, ToolError> {
    let found = ctx.bins().lookup(name).map_err(ToolError::Failed)?;
    let Some(path) = found else {
        return Err(ToolError::Failed(missing.to_string()));
    };
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| ToolError::Failed(format!("the path of {name} is not valid UTF-8")))
}

// ---- process_trace ----------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Summary,
    Calls,
}

/// The arguments for `timeout`, which runs strace and ends it.
///
/// AIDEV-NOTE: strace is ended by SIGINT from `timeout`, never by the server's own time
/// limit, which kills. On SIGINT strace detaches from the process cleanly and prints
/// its summary; killed, it prints nothing. `-k` makes timeout kill it if it ignores the
/// interrupt. The short options are used because BusyBox's timeout has only those.
///
/// `-s 0` (in a call trace) is what keeps data out: strace prints nothing of the
/// buffers a process reads and writes, of the arguments it starts programs with, or of
/// any other string. File names and network addresses are not strings to strace and
/// are printed in full; that is what the tool is for.
pub fn trace_argv(strace: &str, pid: i32, seconds: u64, mode: Mode, class: &str) -> Vec<String> {
    let mut argv = vec![
        "-s".to_string(),
        "INT".to_string(),
        "-k".to_string(),
        KILL_AFTER_SECS.to_string(),
        seconds.to_string(),
        strace.to_string(),
        // -f: the process's threads too, and any children it starts meanwhile
        "-f".to_string(),
    ];
    match mode {
        Mode::Summary => argv.extend(["-c", "-S", "time"].map(String::from)),
        Mode::Calls => {
            argv.extend(["-tt", "-T", "-s", "0"].map(String::from));
            if class != "all" {
                argv.extend(["-e".to_string(), format!("trace=%{class}")]);
            }
        }
    }
    argv.extend(["-p".to_string(), pid.to_string()]);
    argv
}

/// What to show of a finished trace, and whether it counts as a success.
pub fn trace_text(out: &CmdOutput, mode: Mode, lines: usize, budget: usize) -> (String, bool) {
    // strace writes to stderr; nothing is expected on stdout.
    let mut said = String::from_utf8_lossy(&out.stdout).into_owned();
    said.push_str(&String::from_utf8_lossy(&out.stderr));
    // Paths and addresses can carry a password (a URL, a query string).
    let said = redact_text(&said);

    let mut notes = Vec::new();
    if out.truncated {
        notes.push(
            "[strace printed more than is kept: what is shown ends before the end of the \
             trace; trace for fewer seconds or choose a class]"
                .to_string(),
        );
    }
    // 124 is how timeout(1) says that it ended the command: the normal end of a trace.
    // 0 means strace finished by itself, because the process ended.
    let ok = if out.timed_out {
        notes.push("[strace did not stop when its time was up, and was killed]".to_string());
        false
    } else {
        match (out.code, out.signal) {
            (Some(124), _) | (Some(0), _) => true,
            (Some(137), _) => {
                notes.push(
                    "[strace did not stop when it was interrupted, and was killed]".to_string(),
                );
                false
            }
            (Some(code), _) => {
                notes.push(format!("[exit status {code}]"));
                false
            }
            (None, signal) => {
                let signal = signal.map_or_else(|| "?".to_string(), |s| s.to_string());
                notes.push(format!("[strace was killed by signal {signal}]"));
                false
            }
        }
    };
    let notes: String = notes.iter().map(|note| format!("{note}\n")).collect();
    let room = budget.saturating_sub(notes.len() + 100);

    let mut text = String::new();
    if said.trim().is_empty() {
        text.push_str("(strace printed nothing)\n");
    } else {
        match mode {
            Mode::Summary => {
                // With -f strace announces every thread and child it attaches to and
                // lets go of. A process that starts many would push the table, which
                // comes last, out of what fits: the notices are counted instead.
                let mut attached = 0usize;
                let mut table = String::new();
                for line in said.lines() {
                    match attach_notice(line) {
                        Some(true) => attached += 1,
                        Some(false) => {}
                        None => {
                            table.push_str(line);
                            table.push('\n');
                        }
                    }
                }
                if table.trim().is_empty() && ok {
                    // strace -c only counts calls that FINISH. A process asleep in one
                    // call for the whole trace gives no table at all.
                    table.push_str(
                        "No system call finished during the trace: the process was idle, or \
                         blocked in one call the whole time. mode=calls shows the call it \
                         is in.\n",
                    );
                }
                let (kept, dropped) = keep_head(&table, room);
                text.push_str(&kept);
                end_line(&mut text);
                if dropped > 0 {
                    text.push_str(&format!("[{dropped} more lines left out]\n"));
                }
                // one is the process itself: worth a line only when there were more
                if attached > 1 {
                    text.push_str(&format!(
                        "[strace attached to {attached} processes and threads]\n"
                    ));
                }
            }
            Mode::Calls => {
                let all: Vec<&str> = said.lines().collect();
                let skipped = all.len().saturating_sub(lines);
                let newest = all.get(skipped..).unwrap_or(&[]).join("\n");
                let (kept, dropped) = keep_tail(&newest, room);
                let left_out = skipped.saturating_add(dropped);
                if left_out > 0 {
                    text.push_str(&format!(
                        "[{left_out} earlier lines left out; the newest are shown]\n"
                    ));
                }
                text.push_str(&kept);
                end_line(&mut text);
            }
        }
    }
    text.push_str(&notes);
    (text, ok)
}

/// Whether a line is strace's notice that it attached to (`Some(true)`) or let go of
/// (`Some(false)`) a process or thread. strace starts its own messages with the name it
/// was started by, which here is its full path.
fn attach_notice(line: &str) -> Option<bool> {
    let (program, rest) = line.split_once(": Process ")?;
    if !program.ends_with("strace") {
        return None;
    }
    let (pid, what) = rest.split_once(' ')?;
    if pid.is_empty() || !pid.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    match what {
        "attached" => Some(true),
        "detached" => Some(false),
        _ => None,
    }
}

fn end_line(text: &mut String) {
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
}

async fn process_trace(ctx: Ctx, args: Args) -> ToolResult {
    let pid = i32::try_from(args.int("pid").unwrap_or(0)).unwrap_or(0);
    let expected = required(&args, "name")?.to_string();
    let mode = match args.str("mode") {
        Some("calls") => Mode::Calls,
        _ => Mode::Summary,
    };
    let class = args.str("class").unwrap_or("all").to_string();
    // The dispatcher has checked this against the choices; it goes into a command line,
    // so it is checked here as well.
    if !SYSCALL_CLASSES.contains(&class.as_str()) {
        return Err(ToolError::Invalid(format!(
            "{class:?} is not a kind of system call"
        )));
    }
    let lines = usize::try_from(args.int("lines").unwrap_or(200).clamp(10, 500)).unwrap_or(200);
    let asked = args.int("seconds").unwrap_or(5).clamp(1, 30);
    let seconds = bounded_seconds(
        asked,
        ctx.cfg().limits.call_timeout_secs,
        TRACE_SLACK_SECS + 4,
    );

    let target = blocking(ctx.clone(), {
        let ctx = ctx.clone();
        move || examine(&ctx, pid, &expected, Purpose::Trace)
    })
    .await?;
    let Target {
        name,
        owner,
        starttime,
        auth,
        ..
    } = target;

    let strace = program_path(
        &ctx,
        "strace",
        "strace is not installed on this host (package strace)",
    )?;
    let mut cmd = ctx
        .command("timeout")?
        .args(trace_argv(&strace, pid, seconds, mode, &class))
        .timeout(Duration::from_secs(seconds + TRACE_SLACK_SECS));
    cmd.max_output = match mode {
        Mode::Summary => 256 * 1024,
        Mode::Calls => 4 << 20,
    };

    if identity_now(&ctx, pid, starttime).await? != Identity::Same {
        return auth.failed(format!(
            "Process {pid} ended before the trace began; nothing was traced.\n"
        ));
    }
    let out = ctx.run(cmd).await?;
    let after = identity_now(&ctx, pid, starttime).await?;
    if after == Identity::Replaced {
        return auth.failed(replaced_text(pid));
    }

    let what = match mode {
        Mode::Summary => "system calls by time spent".to_string(),
        Mode::Calls if class == "all" => "its system calls, newest last".to_string(),
        Mode::Calls => format!("its {class} system calls, newest last"),
    };
    let mut notes = String::new();
    if u64::try_from(asked).is_ok_and(|asked| asked > seconds) {
        notes.push_str(&format!(
            "[{asked} s were asked for; this host's time limit for a call leaves {seconds} s]\n"
        ));
    }
    let room = ctx.output_budget().saturating_sub(notes.len() + 400);
    let (body, ok) = trace_text(&out, mode, lines, room);
    // The first line says what happened: a trace that could not attach traced nothing.
    let mut text = if ok {
        format!(
            "Traced {name} (pid {pid}, owned by {owner}) and its threads for {seconds} s: {what}.\n"
        )
    } else {
        format!("The trace of {name} (pid {pid}, owned by {owner}) did not succeed.\n")
    };
    text.push_str(&notes);
    text.push_str(&body);
    if after == Identity::Gone {
        text.push_str(&format!("[process {pid} ended during the trace]\n"));
    }
    auth.done(text, ok)
}

// ---- cpu_profile ------------------------------------------------------------------------

/// Whether a private scratch directory may be made in `dir`: it must be a directory
/// that belongs to root or to the server's own user, and in which nobody else can
/// rename or remove what we create (not writable by group or others, or sticky as /tmp
/// is).
///
/// AIDEV-NOTE: perf, running as the server's user (usually root), writes its data file
/// by NAME inside the scratch directory. If another user could swap that directory for
/// one of their own, they could make root write through a link of their choosing.
pub fn usable_base(dir: &Path, euid: u32) -> bool {
    let Ok(meta) = std::fs::metadata(dir) else {
        return false;
    };
    let owner_ok = meta.uid() == 0 || meta.uid() == euid;
    let others_kept_out = meta.mode() & 0o022 == 0 || meta.mode() & 0o1000 != 0;
    meta.is_dir() && owner_ok && others_kept_out
}

/// A private directory for perf's files, removed again when this value is dropped:
/// whether the profile succeeds, fails, or the call is abandoned half way.
pub struct Scratch {
    path: PathBuf,
}

impl Scratch {
    /// Makes `base/name`, readable by nobody else. Fails if anything of that name is
    /// already there: a directory is never adopted, only created.
    pub fn create(base: &Path, name: &str) -> std::io::Result<Scratch> {
        let path = base.join(name);
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Scratch { path })
    }

    /// Makes a scratch directory with a random name in the first of `bases` where that
    /// is safe and possible.
    pub fn create_in(bases: &[PathBuf]) -> Result<Scratch, String> {
        let euid = rustix::process::geteuid().as_raw();
        let mut problems = Vec::new();
        for base in bases {
            if !usable_base(base, euid) {
                problems.push(format!(
                    "{} is not a directory that only root or this server's user controls",
                    base.display()
                ));
                continue;
            }
            let mut random = [0u8; 8];
            getrandom::fill(&mut random).map_err(|e| format!("cannot get random bytes: {e}"))?;
            let hex: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
            match Scratch::create(base, &format!("opsmcp-perf-{hex}")) {
                Ok(scratch) => return Ok(scratch),
                Err(e) => problems.push(format!("{}: {e}", base.display())),
            }
        }
        Err(format!(
            "cannot make a scratch directory for perf ({})",
            problems.join("; ")
        ))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // A handful of unlinks in a directory only we use: done here, not on a blocking
        // thread, so that it also happens when the call is cut off.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// The arguments for `perf record`: sample one process, or every CPU, for as long as
/// `sleep SECONDS` runs. `-N`: do not copy binaries into perf's build-id cache.
pub fn record_argv(data: &str, pid: Option<i32>, sleep: &str, seconds: u64) -> Vec<String> {
    let mut argv = vec![
        "record".to_string(),
        "-F".to_string(),
        SAMPLE_HZ.to_string(),
        "-N".to_string(),
        "-o".to_string(),
        data.to_string(),
    ];
    match pid {
        Some(pid) => argv.extend(["-p".to_string(), pid.to_string()]),
        None => argv.push("-a".to_string()),
    }
    argv.extend(["--".to_string(), sleep.to_string(), seconds.to_string()]);
    argv
}

/// The arguments for `perf report`: a plain-text table, totalled as asked.
pub fn report_argv(data: &str, by: &str) -> Vec<String> {
    let sort = match by {
        "process" => "comm",
        "library" => "dso",
        _ => "comm,dso,sym",
    };
    [
        "report",
        "-i",
        data,
        "--stdio",
        "--sort",
        sort,
        "--percent-limit",
        "0.5",
    ]
    .map(String::from)
    .to_vec()
}

/// What is kept of a `perf report`.
pub struct Shaped {
    pub text: String,
    /// Rows kept.
    pub rows: usize,
    /// Rows beyond the limit.
    pub left_out: usize,
}

/// Keeps what matters of `perf report --stdio`: for each event the sample counts, the
/// column headings and the first `limit` rows. Its other remarks (lines starting `#`)
/// are dropped.
pub fn shape_report(report: &str, limit: usize) -> Shaped {
    let mut shaped = Shaped {
        text: String::new(),
        rows: 0,
        left_out: 0,
    };
    let mut rows_of_event = 0usize;
    for line in report.lines() {
        let line = line.trim_end();
        if line.trim().is_empty() {
            continue;
        }
        if let Some(remark) = line.strip_prefix('#') {
            let remark = remark.trim_start();
            if remark.starts_with("Samples:") {
                // a new event: its rows are counted from the start
                rows_of_event = 0;
            } else if !(remark.starts_with("Event count") || remark.starts_with("Overhead")) {
                continue;
            }
        } else {
            rows_of_event += 1;
            if rows_of_event > limit {
                shaped.left_out += 1;
                continue;
            }
            shaped.rows += 1;
        }
        shaped.text.push_str(line);
        shaped.text.push('\n');
    }
    shaped
}

async fn cpu_profile(ctx: Ctx, args: Args, env: Env) -> ToolResult {
    let clock = CallClock::start(&ctx);
    let by = args.str("by").unwrap_or("function").to_string();
    let limit = usize::try_from(args.int("limit").unwrap_or(30).clamp(5, 100)).unwrap_or(30);
    let asked = args.int("seconds").unwrap_or(10).clamp(1, 30);
    let seconds = bounded_seconds(
        asked,
        ctx.cfg().limits.call_timeout_secs,
        RECORD_SLACK_SECS + 10,
    );

    let (auth, target) = match (args.int("pid"), args.str("name")) {
        (Some(pid), Some(name)) => {
            let pid = i32::try_from(pid).unwrap_or(0);
            let expected = name.to_string();
            let target = blocking(ctx.clone(), {
                let ctx = ctx.clone();
                move || examine(&ctx, pid, &expected, Purpose::Profile)
            })
            .await?;
            let Target {
                pid,
                name,
                owner,
                starttime,
                auth,
            } = target;
            (auth, Some((pid, name, owner, starttime)))
        }
        (None, None) => {
            if !ctx.cfg().trace.system_wide {
                return Err(ctx.deny(
                    None,
                    "profiling the whole host is not allowed on this host (trace.system_wide \
                     in the configuration); name one process with pid and name instead",
                ));
            }
            (ctx.authorize(None)?, None)
        }
        _ => {
            return Err(ToolError::Invalid(
                "give pid and name together to profile one process, or neither to profile \
                 the whole host"
                    .to_string(),
            ));
        }
    };

    let perf = program_path(
        &ctx,
        "perf",
        "perf is not installed on this host (package linux-tools-common with the \
         linux-tools package for the running kernel on Ubuntu, linux-perf on Debian, perf \
         on Red Hat and Fedora)",
    )?;
    let sleep = program_path(
        &ctx,
        "sleep",
        "the sleep command is not installed on this host",
    )?;
    let scratch = blocking(ctx.clone(), move || {
        Scratch::create_in(&env.scratch_bases).map_err(ToolError::Failed)
    })
    .await?;
    let not_utf8 = || ToolError::Failed("the scratch directory's path is not valid UTF-8".into());
    let home = scratch.path().to_str().ok_or_else(not_utf8)?.to_string();
    let data = format!("{home}/perf.data");
    // AIDEV-NOTE: perf keeps a cache and a configuration under $HOME. It gets the scratch
    // directory, so that nothing of root's is read or written and nothing stays behind.
    let perf_env = ("HOME".to_string(), home);

    let pid = target.as_ref().map(|(pid, ..)| *pid);
    if let Some((pid, _, _, starttime)) = &target
        && identity_now(&ctx, *pid, *starttime).await? != Identity::Same
    {
        return auth.failed(format!(
            "Process {pid} ended before sampling began; nothing was profiled.\n"
        ));
    }
    let mut record = ctx
        .command_at(PathBuf::from(&perf))
        .args(record_argv(&data, pid, &sleep, seconds))
        .timeout(Duration::from_secs(seconds + RECORD_SLACK_SECS));
    record.env.push(perf_env.clone());
    let recorded = ctx.run(record).await?;
    let mut ended_meanwhile = false;
    if let Some((pid, _, _, starttime)) = &target {
        match identity_now(&ctx, *pid, *starttime).await? {
            Identity::Replaced => return auth.failed(replaced_text(*pid)),
            Identity::Gone => ended_meanwhile = true,
            Identity::Same => {}
        }
    }

    let budget = ctx.output_budget();
    if !command_ok(&recorded) {
        // perf explains a refusal at length, and more than once: the start says it all
        let (said, dropped) = keep_head(
            &redact_text(&command_text(&recorded)),
            PERF_FAILURE_BYTES.min(budget / 2),
        );
        let mut text = format!("perf could not take the samples:\n{said}");
        end_line(&mut text);
        if dropped > 0 {
            text.push_str(&format!(
                "[{dropped} more lines of perf's explanation left out]\n"
            ));
        }
        return auth.failed(text);
    }
    let Some(time_left) = clock.next() else {
        return auth.failed(
            "The samples were taken, but this call's time limit left none to report them. \
             Sample for fewer seconds.\n",
        );
    };
    let mut report = ctx
        .command_at(PathBuf::from(&perf))
        .args(report_argv(&data, &by))
        .timeout(time_left);
    report.env.push(perf_env);
    report.max_output = 4 << 20;
    let reported = ctx.run(report).await?;
    drop(scratch);

    let whom = match &target {
        Some((pid, name, owner, _)) => format!("{name} (pid {pid}, owned by {owner})"),
        None => "the whole host".to_string(),
    };
    let mut text = format!(
        "CPU profile of {whom} over {seconds} s, by {by} ({SAMPLE_HZ} samples a second on each CPU):\n"
    );
    if u64::try_from(asked).is_ok_and(|asked| asked > seconds) {
        text.push_str(&format!(
            "[{asked} s were asked for; this host's time limit for a call leaves {seconds} s]\n"
        ));
    }
    let shaped = shape_report(&String::from_utf8_lossy(&reported.stdout), limit);
    if shaped.rows == 0 {
        text.push_str(
            "(no samples: nothing ran on a CPU in that time, or perf was not able to sample it)\n",
        );
    }
    let (table, dropped) = keep_head(
        &redact_text(&shaped.text),
        budget.saturating_sub(text.len() + 2048),
    );
    text.push_str(&table);
    let left_out = shaped.left_out.saturating_add(dropped);
    if left_out > 0 {
        text.push_str(&format!(
            "[{left_out} more rows left out; raise limit to see more]\n"
        ));
    }
    if reported.truncated {
        text.push_str("[perf's report was longer than is kept]\n");
    }
    if ended_meanwhile && let Some(pid) = pid {
        text.push_str(&format!("[process {pid} ended while it was sampled]\n"));
    }
    // What perf itself had to say: how many samples it took, and above all why symbols
    // or samples are missing when they are.
    let mut silent = reported.clone();
    silent.stdout.clear();
    let mut remarks = String::from_utf8_lossy(&recorded.stderr).into_owned();
    end_line(&mut remarks);
    remarks.push_str(&command_text(&silent));
    if !remarks.trim().is_empty() {
        let (remarks, _) = keep_head(&redact_text(&remarks), 1500);
        text.push_str("\nperf's own remarks:\n");
        text.push_str(&remarks);
        end_line(&mut text);
    }
    auth.done(text, command_ok(&reported))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::policy::Access;
    use crate::tools::Host;
    use crate::tools::testing::{FakeBins, call, find, host, ok_text};
    use serde_json::{Value, json};
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Child, Command, Stdio};
    use std::sync::Arc;

    fn me() -> String {
        crate::identity::current().unwrap().user
    }

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn output(stdout: &str, stderr: &str, code: Option<i32>) -> CmdOutput {
        CmdOutput {
            code,
            signal: None,
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
            truncated: false,
            timed_out: false,
        }
    }

    // ---- pure parts ---------------------------------------------------------------

    #[test]
    fn the_tools_carry_the_intended_permissions() {
        let got: Vec<(String, Access, String)> = tools()
            .into_iter()
            .map(|t| (t.name, t.access, t.permission))
            .collect();
        assert_eq!(
            got,
            [
                // write on purpose: see the note on process_trace
                (
                    "process_trace".to_string(),
                    Access::Write,
                    "process.trace".to_string()
                ),
                (
                    "cpu_profile".to_string(),
                    Access::Read,
                    "process.profile".to_string()
                ),
            ]
        );
    }

    #[test]
    fn the_scratch_directory_is_never_looked_for_through_the_environment() {
        // AIDEV-NOTE: $TMPDIR belongs to whoever started the server (under sudo: the
        // caller). Root must not create files where that says.
        assert_eq!(
            Env::system().scratch_bases,
            [PathBuf::from("/run"), PathBuf::from("/tmp")]
        );
    }

    #[test]
    fn a_summary_trace_counts_calls_and_is_ended_by_an_interrupt() {
        assert_eq!(
            trace_argv("/usr/bin/strace", 4242, 5, Mode::Summary, "all"),
            strings(&[
                "-s",
                "INT",
                "-k",
                "3",
                "5",
                "/usr/bin/strace",
                "-f",
                "-c",
                "-S",
                "time",
                "-p",
                "4242"
            ])
        );
    }

    #[test]
    fn a_call_trace_never_prints_the_contents_of_buffers() {
        let argv = trace_argv("/usr/bin/strace", 7, 30, Mode::Calls, "all");
        assert_eq!(
            argv,
            strings(&[
                "-s",
                "INT",
                "-k",
                "3",
                "30",
                "/usr/bin/strace",
                "-f",
                "-tt",
                "-T",
                "-s",
                "0",
                "-p",
                "7"
            ])
        );
        let argv = trace_argv("/usr/bin/strace", 7, 30, Mode::Calls, "network");
        let strace_part = &argv[6..];
        assert_eq!(
            strace_part,
            strings(&[
                "-f",
                "-tt",
                "-T",
                "-s",
                "0",
                "-e",
                "trace=%network",
                "-p",
                "7"
            ])
        );
        // the string limit of 0 is there in every call trace
        for class in ["all", "file", "desc", "memory"] {
            let argv = trace_argv("/usr/bin/strace", 7, 5, Mode::Calls, class);
            let at = argv.iter().rposition(|a| a == "-s").unwrap();
            assert_eq!(argv[at + 1], "0", "{argv:?}");
        }
    }

    #[test]
    fn the_time_asked_for_stays_inside_what_a_call_may_take() {
        assert_eq!(bounded_seconds(5, 120, 12), 5);
        assert_eq!(bounded_seconds(30, 120, 12), 30);
        assert_eq!(bounded_seconds(99, 120, 12), 30);
        assert_eq!(bounded_seconds(0, 120, 12), 1);
        assert_eq!(bounded_seconds(30, 30, 12), 18);
        assert_eq!(bounded_seconds(30, 10, 12), 1);
    }

    #[test]
    fn a_process_is_the_same_only_while_its_start_time_is() {
        assert_eq!(identity(100, Some(100)), Identity::Same);
        assert_eq!(identity(100, None), Identity::Gone);
        assert_eq!(identity(100, Some(250)), Identity::Replaced);
    }

    const SUMMARY: &str = "strace: Process 4242 attached\n\
        % time     seconds  usecs/call     calls    errors syscall\n\
        ------ ----------- ----------- --------- --------- ----------------\n\
        \x2061.54    0.000008           8         1           restart_syscall\n\
        100.00    0.000013                     2         1 total\n";

    #[test]
    fn the_end_of_the_time_is_how_a_trace_normally_ends() {
        // timeout(1) reports 124 when it had to end the command: that is the plan
        let (text, ok) = trace_text(&output("", SUMMARY, Some(124)), Mode::Summary, 200, 60_000);
        assert!(ok, "{text}");
        assert!(text.contains("restart_syscall"), "{text}");
        assert!(!text.contains("exit status"), "{text}");
        // the traced process ended by itself
        let (_, ok) = trace_text(&output("", SUMMARY, Some(0)), Mode::Summary, 200, 60_000);
        assert!(ok);
    }

    /// AIDEV-NOTE: found against real strace: for a process asleep in one call, `-c`
    /// prints its attach and detach notices and no table, and the result read as empty.
    #[test]
    fn a_summary_with_no_finished_call_says_the_process_was_idle() {
        let (text, ok) = trace_text(
            &output(
                "",
                "/usr/bin/strace: Process 4242 attached\n/usr/bin/strace: Process 4242 detached\n",
                Some(124),
            ),
            Mode::Summary,
            200,
            4000,
        );
        assert!(ok);
        assert!(
            text.contains("No system call finished during the trace"),
            "{text}"
        );
        assert!(text.contains("mode=calls"), "{text}");
        // a real table is left alone
        let (text, _) = trace_text(&output("", SUMMARY, Some(124)), Mode::Summary, 200, 4000);
        assert!(!text.contains("No system call finished"), "{text}");
    }

    #[test]
    fn a_summary_is_not_buried_under_the_notices_of_attaching() {
        // with -f strace announces every thread and child it attaches to: a process
        // that starts many would push the table out of what fits
        let mut said = String::new();
        for pid in 5000..7000 {
            // strace names itself as it was started: by its full path
            said.push_str(&format!("/usr/bin/strace: Process {pid} attached\n"));
            said.push_str(&format!("/usr/bin/strace: Process {pid} detached\n"));
        }
        said.push_str(SUMMARY);
        let (text, ok) = trace_text(&output("", &said, Some(124)), Mode::Summary, 200, 4000);
        assert!(ok);
        assert!(text.contains("restart_syscall"), "{text}");
        assert!(text.contains("100.00"), "{text}");
        assert!(!text.contains("Process 5000 attached"), "{text}");
        assert!(
            text.contains("[strace attached to 2001 processes and threads]"),
            "{text}"
        );
        // only strace's own notices: not a line that merely looks like one
        let (text, _) = trace_text(
            &output(
                "",
                "nginx: Process 7 attached\nstrace: Process x attached\n",
                Some(124),
            ),
            Mode::Summary,
            200,
            4000,
        );
        assert!(text.contains("nginx: Process 7 attached"), "{text}");
        assert!(text.contains("strace: Process x attached"), "{text}");
        // in a call trace they are events like any other, and stay
        let (text, _) = trace_text(
            &output("", "strace: Process 5000 attached\n", Some(124)),
            Mode::Calls,
            200,
            4000,
        );
        assert!(text.contains("Process 5000 attached"), "{text}");
    }

    #[test]
    fn a_trace_that_could_not_attach_is_a_failure_with_strace_s_words() {
        let said = "strace: attach: ptrace(PTRACE_SEIZE, 4242): Operation not permitted\n";
        let (text, ok) = trace_text(&output("", said, Some(1)), Mode::Summary, 200, 60_000);
        assert!(!ok);
        assert!(text.contains("Operation not permitted"), "{text}");
        assert!(text.contains("[exit status 1]"), "{text}");
        // strace would not stop when interrupted, and was killed
        let (text, ok) = trace_text(&output("", "", Some(137)), Mode::Summary, 200, 60_000);
        assert!(!ok);
        assert!(text.contains("killed"), "{text}");
        let mut hung = output("", "", None);
        hung.timed_out = true;
        let (text, ok) = trace_text(&hung, Mode::Summary, 200, 60_000);
        assert!(!ok);
        assert!(text.contains("did not stop"), "{text}");
    }

    #[test]
    fn a_call_trace_keeps_the_newest_lines_and_says_how_many_it_left_out() {
        let calls: String = (1..=50)
            .map(|n| format!("12:00:00.{n:06} close({n}) = 0 <0.000010>\n"))
            .collect();
        let (text, ok) = trace_text(&output("", &calls, Some(124)), Mode::Calls, 10, 60_000);
        assert!(ok);
        assert!(
            text.contains("close(50)") && text.contains("close(41)"),
            "{text}"
        );
        assert!(!text.contains("close(40)"), "{text}");
        assert!(text.contains("[40 earlier lines left out"), "{text}");
        // and what is kept still has to fit the output limit
        let (text, _) = trace_text(&output("", &calls, Some(124)), Mode::Calls, 500, 600);
        assert!(text.len() <= 600, "{}", text.len());
        assert!(text.contains("close(50)"), "{text}");
        assert!(!text.contains("close(1) "), "{text}");
    }

    #[test]
    fn a_call_trace_cut_short_by_its_size_says_that_its_end_is_missing() {
        let mut out = output("", "12:00:00.000001 close(3) = 0 <0.000010>\n", Some(124));
        out.truncated = true;
        let (text, _) = trace_text(&out, Mode::Calls, 200, 60_000);
        assert!(text.contains("ends before the end of the trace"), "{text}");
    }

    #[test]
    fn what_strace_prints_has_likely_secrets_masked() {
        // masking is word by word, as for every other tool that shows command output
        let said =
            "12:00:00.000001 openat(AT_FDCWD, \"/srv/app/run\", O_RDONLY) = 3 password=hunter2\n";
        let (text, _) = trace_text(&output("", said, Some(124)), Mode::Calls, 200, 60_000);
        assert!(
            text.contains("openat") && text.contains("/srv/app/run"),
            "{text}"
        );
        assert!(!text.contains("hunter2"), "{text}");
    }

    #[test]
    fn perf_records_one_process_or_the_whole_host_for_as_long_as_sleep_runs() {
        assert_eq!(
            record_argv("/run/x/perf.data", Some(4242), "/usr/bin/sleep", 10),
            strings(&[
                "record",
                "-F",
                "99",
                "-N",
                "-o",
                "/run/x/perf.data",
                "-p",
                "4242",
                "--",
                "/usr/bin/sleep",
                "10"
            ])
        );
        assert_eq!(
            record_argv("/run/x/perf.data", None, "/usr/bin/sleep", 3),
            strings(&[
                "record",
                "-F",
                "99",
                "-N",
                "-o",
                "/run/x/perf.data",
                "-a",
                "--",
                "/usr/bin/sleep",
                "3"
            ])
        );
    }

    #[test]
    fn perf_reports_by_function_process_or_library() {
        let argv = |by: &str| report_argv("/run/x/perf.data", by);
        assert_eq!(
            argv("function"),
            strings(&[
                "report",
                "-i",
                "/run/x/perf.data",
                "--stdio",
                "--sort",
                "comm,dso,sym",
                "--percent-limit",
                "0.5"
            ])
        );
        assert_eq!(argv("process")[5], "comm");
        assert_eq!(argv("library")[5], "dso");
    }

    const REPORT: &str = "# To display the perf.data header info, please use --header/--header-only options.\n\
        #\n\
        #\n\
        # Total Lost Samples: 0\n\
        #\n\
        # Samples: 297  of event 'cycles'\n\
        # Event count (approx.): 7654321\n\
        #\n\
        # Overhead  Command  Shared Object      Symbol\n\
        # ........  .......  .................  ..........................\n\
        #\n\
        \x20   41.20%  nginx    nginx              [.] ngx_http_parse_request_line\n\
        \x20   20.10%  nginx    libc.so.6          [.] __memmove_avx_unaligned_erms\n\
        \x20    9.03%  nginx    [kernel.kallsyms]  [k] copy_user_enhanced_fast_string\n\
        \x20    2.00%  nginx    libssl.so.3        [.] ssl3_read_bytes\n\
        \n\
        \n\
        #\n\
        # (Tip: Save output of perf stat using: perf stat record <cmd>)\n\
        #\n";

    #[test]
    fn the_report_keeps_the_sample_counts_the_heading_and_the_first_rows() {
        let shaped = shape_report(REPORT, 3);
        assert_eq!(shaped.rows, 3);
        assert_eq!(shaped.left_out, 1);
        let lines: Vec<&str> = shaped.text.lines().collect();
        assert_eq!(
            lines,
            [
                "# Samples: 297  of event 'cycles'",
                "# Event count (approx.): 7654321",
                "# Overhead  Command  Shared Object      Symbol",
                "    41.20%  nginx    nginx              [.] ngx_http_parse_request_line",
                "    20.10%  nginx    libc.so.6          [.] __memmove_avx_unaligned_erms",
                "     9.03%  nginx    [kernel.kallsyms]  [k] copy_user_enhanced_fast_string",
            ]
        );
        let all = shape_report(REPORT, 30);
        assert_eq!((all.rows, all.left_out), (4, 0));
        assert!(!all.text.contains("Tip:"), "{}", all.text);
        let nothing = shape_report("# Samples: 0  of event 'cycles'\n#\n", 30);
        assert_eq!(nothing.rows, 0);
    }

    #[test]
    fn each_event_in_a_report_gets_its_own_rows() {
        let two = format!("{REPORT}{}", REPORT.replace("cycles", "cpu_atom/cycles/"));
        let shaped = shape_report(&two, 2);
        assert_eq!(shaped.rows, 4);
        assert_eq!(shaped.left_out, 4);
        assert_eq!(shaped.text.matches("# Samples:").count(), 2);
    }

    #[test]
    fn a_scratch_base_must_be_safe_from_other_users() {
        let euid = rustix::process::geteuid().as_raw();
        let dir = tempfile::tempdir().unwrap();
        let set = |mode: u32| {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        };
        set(0o700);
        assert!(usable_base(dir.path(), euid));
        set(0o755);
        assert!(usable_base(dir.path(), euid));
        // writable by others: they could swap the scratch directory for their own
        set(0o777);
        assert!(!usable_base(dir.path(), euid));
        set(0o775);
        assert!(!usable_base(dir.path(), euid));
        // ... unless it is sticky, as /tmp is: then only the owner of an entry can
        set(0o1777);
        assert!(usable_base(dir.path(), euid));
        set(0o700);
        // owned by someone who is neither root nor this server's user
        assert!(!usable_base(dir.path(), euid.wrapping_add(1).max(1)));
        assert!(!usable_base(&dir.path().join("missing"), euid));
        let file = dir.path().join("file");
        std::fs::write(&file, "x").unwrap();
        assert!(!usable_base(&file, euid));
    }

    #[test]
    fn the_scratch_directory_is_private_new_and_gone_afterwards() {
        let base = tempfile::tempdir().unwrap();
        let path = {
            let scratch = Scratch::create(base.path(), "opsmcp-perf-test").unwrap();
            let meta = std::fs::symlink_metadata(scratch.path()).unwrap();
            assert!(meta.is_dir());
            assert_eq!(meta.permissions().mode() & 0o7777, 0o700);
            // a name that is already there is never reused, whatever it is
            assert!(Scratch::create(base.path(), "opsmcp-perf-test").is_err());
            std::fs::write(scratch.path().join("perf.data"), "data").unwrap();
            std::fs::create_dir(scratch.path().join(".debug")).unwrap();
            scratch.path().to_path_buf()
        };
        assert!(!path.exists(), "the scratch directory was left behind");

        std::os::unix::fs::symlink("/", base.path().join("link")).unwrap();
        assert!(Scratch::create(base.path(), "link").is_err());

        let made =
            Scratch::create_in(&[base.path().join("missing"), base.path().to_path_buf()]).unwrap();
        assert!(made.path().starts_with(base.path()));
        let name = made
            .path()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            name.starts_with("opsmcp-perf-") && name.len() == 28,
            "{name}"
        );
        assert!(Scratch::create_in(&[base.path().join("missing")]).is_err());
    }

    // ---- the tools ----------------------------------------------------------------

    /// A `sleep` of our own to point the tools at.
    struct Sleeper(Child);

    impl Sleeper {
        fn start() -> Sleeper {
            let child = Command::new("sleep")
                .arg("60")
                .stdin(Stdio::null())
                .spawn()
                .unwrap();
            Sleeper(child)
        }

        fn pid(&self) -> u32 {
            self.0.id()
        }
    }

    impl Drop for Sleeper {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// adam may do everything, rita holds `@read`, sam may trace and profile only his
    /// own `sleep`, nina only a process called nginx. `trace` is the body of `[trace]`.
    fn fixture(fake: &FakeBins, trace: &str) -> (Arc<Host>, MemorySink) {
        let me = me();
        host(&format!(
            r#"
[roles.admin]
allow = ["@all"]
[roles.reader]
allow = ["@read"]
[roles.sleeper]
allow = ["process.trace:{me}/sleep", "process.profile:{me}/sleep"]
[roles.web]
allow = ["process.trace:{me}/nginx", "process.profile:{me}/nginx"]
[unix_users.adam]
roles = ["admin"]
[unix_users.rita]
roles = ["reader"]
[unix_users.sam]
roles = ["sleeper"]
[unix_users.nina]
roles = ["web"]
[trace]
{trace}
{}"#,
            fake.config_only()
        ))
    }

    fn allow_sleep() -> String {
        format!("processes = [\"{}/sleep\"]", me())
    }

    /// Shell (builtins only) that prints `text` on stderr, as strace does.
    fn on_stderr(text: &str) -> String {
        text.lines()
            .map(|line| format!("printf '%s\\n' '{line}' >&2\n"))
            .collect()
    }

    /// A `timeout` that says what strace would and exits with `code`, and a `strace`
    /// that would say so if it were ever run directly.
    fn tracer(said: &str, code: i32) -> FakeBins {
        FakeBins::new()
            .add_script("timeout", &format!("{}exit {code}", on_stderr(said)))
            .add("strace", "strace ran directly\n", 0)
    }

    async fn run_with(
        host: &Arc<Host>,
        user: &str,
        tool: &str,
        arguments: Value,
        base: &Path,
    ) -> ToolResult {
        let env = Env {
            scratch_bases: vec![base.to_path_buf()],
        };
        call(host, user, &find(tools_with(env), tool), arguments).await
    }

    async fn trace(host: &Arc<Host>, user: &str, arguments: Value) -> ToolResult {
        call(host, user, &find(tools(), "process_trace"), arguments).await
    }

    fn is_denied(result: ToolResult) -> String {
        match result {
            Err(ToolError::Denied(message)) => message,
            other => panic!("expected a denial, got {other:?}"),
        }
    }

    fn is_invalid(result: ToolResult) -> String {
        match result {
            Err(ToolError::Invalid(message)) => message,
            other => panic!("expected the arguments to be refused, got {other:?}"),
        }
    }

    fn is_failed(result: ToolResult) -> String {
        match result {
            Err(ToolError::Failed(message)) => message,
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn process_trace_is_refused_until_the_host_says_what_may_be_traced() {
        let fake = tracer(SUMMARY, 124);
        let (host, audit) = fixture(&fake, "");
        let child = Sleeper::start();
        let message =
            is_denied(trace(&host, "adam", json!({"pid": child.pid(), "name": "sleep"})).await);
        assert!(message.contains("trace.processes"), "{message}");
        assert!(fake.calls("timeout").is_empty());
        let records = audit.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["decision"], "deny");
        assert_eq!(records[0]["resource"], format!("{}/sleep", me()));
    }

    #[tokio::test]
    async fn process_trace_refuses_a_process_the_host_does_not_list() {
        let fake = tracer(SUMMARY, 124);
        let (host, _audit) = fixture(&fake, "processes = [\"www-data/*\", \"*/nginx\"]");
        let child = Sleeper::start();
        let message =
            is_denied(trace(&host, "adam", json!({"pid": child.pid(), "name": "sleep"})).await);
        assert!(message.contains("trace.processes"), "{message}");
        assert!(fake.calls("timeout").is_empty());
    }

    #[tokio::test]
    async fn process_trace_runs_strace_under_timeout_and_shows_what_it_counted() {
        let fake = tracer(SUMMARY, 124);
        let (host, audit) = fixture(&fake, &allow_sleep());
        let child = Sleeper::start();
        let pid = child.pid().to_string();
        let text = ok_text(
            trace(
                &host,
                "sam",
                json!({"pid": child.pid(), "name": "sleep", "seconds": 2}),
            )
            .await,
        );
        let calls = fake.calls("timeout");
        assert_eq!(calls.len(), 1, "{calls:?}");
        let argv = &calls[0];
        assert_eq!(argv[..5], strings(&["-s", "INT", "-k", "3", "2"]));
        // strace is named by the full path of the program the server found and checked
        assert!(
            argv[5].starts_with('/') && argv[5].ends_with("/strace"),
            "{argv:?}"
        );
        assert_eq!(argv[6..], strings(&["-f", "-c", "-S", "time", "-p", &pid]));
        assert!(fake.calls("strace").is_empty());

        let first = text.lines().next().unwrap();
        assert_eq!(
            first,
            format!(
                "Traced sleep (pid {pid}, owned by {}) and its threads for 2 s: system calls by time spent.",
                me()
            )
        );
        assert!(text.contains("restart_syscall"), "{text}");
        let records = audit.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["decision"], "allow");
        assert_eq!(records[0]["resource"], format!("{}/sleep", me()));
    }

    #[tokio::test]
    async fn process_trace_lists_calls_without_buffer_contents_when_asked() {
        let said = "12:00:00.000001 openat(AT_FDCWD, \"/etc/hosts\", O_RDONLY) = 3 <0.000020>\n\
                    12:00:00.000002 read(3, \"\"..., 4096) = 220 <0.000010>\n";
        let fake = tracer(said, 124);
        let (host, _audit) = fixture(&fake, &allow_sleep());
        let child = Sleeper::start();
        let text = ok_text(
            trace(
                &host,
                "adam",
                json!({"pid": child.pid(), "name": "sleep", "mode": "calls", "class": "file", "lines": 10}),
            )
            .await,
        );
        let argv = &fake.calls("timeout")[0];
        assert_eq!(
            argv[6..],
            strings(&[
                "-f",
                "-tt",
                "-T",
                "-s",
                "0",
                "-e",
                "trace=%file",
                "-p",
                &child.pid().to_string()
            ])
        );
        assert!(text.contains("/etc/hosts"), "{text}");
        assert!(text.lines().next().unwrap().contains("file"), "{text}");
    }

    #[tokio::test]
    async fn process_trace_needs_a_grant_for_the_process_and_is_not_part_of_read() {
        let fake = tracer(SUMMARY, 124);
        let (host, _audit) = fixture(&fake, "processes = [\"**\"]");
        let child = Sleeper::start();
        let arguments = json!({"pid": child.pid(), "name": "sleep"});
        for user in ["rita", "nina"] {
            let message = is_denied(trace(&host, user, arguments.clone()).await);
            assert!(message.contains("process.trace"), "{message}");
            // the caller gave a pid: the refusal must not tell them what it is
            assert!(!message.contains("sleep"), "{message}");
        }
        assert!(fake.calls("timeout").is_empty());
        ok_text(trace(&host, "sam", arguments).await);
    }

    #[tokio::test]
    async fn a_caller_without_the_grant_cannot_tell_whether_the_host_lists_a_process() {
        // nina may trace nginx only. Whether or not the host lists sleep, she is told
        // the same thing, and it names neither the process nor the host's setting.
        let mut messages = Vec::new();
        for listed in [String::new(), allow_sleep()] {
            let fake = tracer(SUMMARY, 124);
            let (host, _audit) = fixture(&fake, &listed);
            let child = Sleeper::start();
            let message =
                is_denied(trace(&host, "nina", json!({"pid": child.pid(), "name": "sleep"})).await);
            assert!(!message.contains("trace.processes"), "{message}");
            assert!(!message.contains("sleep"), "{message}");
            assert!(fake.calls("timeout").is_empty());
            messages.push(message);
        }
        assert_eq!(messages[0], messages[1]);
    }

    #[tokio::test]
    async fn process_trace_does_nothing_when_the_name_is_not_the_one_expected() {
        let fake = tracer(SUMMARY, 124);
        let (host, _audit) = fixture(&fake, "processes = [\"**\"]");
        let child = Sleeper::start();
        let message =
            is_invalid(trace(&host, "adam", json!({"pid": child.pid(), "name": "nginx"})).await);
        assert!(message.contains("nothing was traced"), "{message}");
        assert!(fake.calls("timeout").is_empty());
    }

    #[tokio::test]
    async fn process_trace_refuses_init_itself_and_a_missing_process() {
        let fake = tracer(SUMMARY, 124);
        let (host, _audit) = fixture(&fake, "processes = [\"**\"]");
        let message = is_denied(trace(&host, "adam", json!({"pid": 1, "name": "systemd"})).await);
        assert!(message.contains("pid 1"), "{message}");
        let own = std::fs::read_to_string("/proc/self/comm").unwrap();
        let message = is_denied(
            trace(
                &host,
                "adam",
                json!({"pid": std::process::id(), "name": own.trim()}),
            )
            .await,
        );
        assert!(message.contains("itself"), "{message}");
        let message =
            is_failed(trace(&host, "adam", json!({"pid": 4_194_303, "name": "sleep"})).await);
        assert!(message.contains("no process"), "{message}");
        assert!(fake.calls("timeout").is_empty());
    }

    #[tokio::test]
    async fn process_trace_says_which_package_is_missing() {
        let fake = FakeBins::new().add("timeout", "", 124);
        let (host, _audit) = fixture(&fake, "processes = [\"**\"]");
        let child = Sleeper::start();
        let message =
            is_failed(trace(&host, "adam", json!({"pid": child.pid(), "name": "sleep"})).await);
        assert!(message.contains("strace is not installed"), "{message}");
        assert!(message.contains("package strace"), "{message}");
        assert!(fake.calls("timeout").is_empty());
    }

    #[tokio::test]
    async fn process_trace_reports_a_failed_attach_as_a_failure() {
        let fake = tracer(
            "strace: attach: ptrace(PTRACE_SEIZE, 1): Operation not permitted",
            1,
        );
        let (host, _audit) = fixture(&fake, "processes = [\"**\"]");
        let child = Sleeper::start();
        let output = trace(&host, "adam", json!({"pid": child.pid(), "name": "sleep"}))
            .await
            .unwrap();
        assert!(output.is_error());
        let text = output.text();
        assert!(text.contains("Operation not permitted"), "{text}");
        // nothing was traced: the first line must not say that something was
        assert!(
            text.starts_with(&format!(
                "The trace of sleep (pid {}, owned by {}) did not succeed.\n",
                child.pid(),
                me()
            )),
            "{text}"
        );
    }

    #[tokio::test]
    async fn process_trace_says_when_the_process_ended_during_the_trace() {
        let mut child = Sleeper::start();
        let pid = child.pid();
        // the stand-in for timeout ends the process, as if it had exited while traced,
        // and waits until its pid is really gone
        let fake = FakeBins::new()
            .add_script(
                "timeout",
                &format!("kill -9 {pid}; while kill -0 {pid} 2>/dev/null; do :; done; exit 0"),
            )
            .add("strace", "", 0);
        let (host, _audit) = fixture(&fake, "processes = [\"**\"]");
        // reap it as soon as it is killed
        let reaper = std::thread::spawn(move || {
            let _ = child.0.wait();
            child
        });
        let text = ok_text(trace(&host, "adam", json!({"pid": pid, "name": "sleep"})).await);
        let _child = reaper.join().unwrap();
        assert!(
            text.contains(&format!("[process {pid} ended during the trace]")),
            "{text}"
        );
    }

    const PERF: &str = "case \"$1\" in\n\
        record) : > \"$6\"; printf '%s\\n' '[ perf record: Captured and wrote 0.031 MB perf.data (297 samples) ]' >&2;;\n\
        report) printf '%s\\n' '# Samples: 297  of event cycles' '# Overhead  Command  Symbol' '    41.20%  sleep  [k] do_nanosleep' '     2.00%  sleep  [k] schedule';;\n\
        esac";

    fn profiler() -> FakeBins {
        FakeBins::new().add_script("perf", PERF).add("sleep", "", 0)
    }

    #[tokio::test]
    async fn cpu_profile_of_the_whole_host_needs_the_host_to_allow_it() {
        let fake = profiler();
        let (host, audit) = fixture(&fake, "processes = [\"**\"]");
        let base = tempfile::tempdir().unwrap();
        let message =
            is_denied(run_with(&host, "adam", "cpu_profile", json!({}), base.path()).await);
        assert!(message.contains("trace.system_wide"), "{message}");
        assert!(fake.calls("perf").is_empty());
        let records = audit.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["decision"], "deny");
        assert!(records[0].get("resource").is_none());
    }

    #[tokio::test]
    async fn cpu_profile_samples_the_host_and_cleans_up_after_itself() {
        let fake = profiler();
        let (host, _audit) = fixture(&fake, "system_wide = true");
        let base = tempfile::tempdir().unwrap();
        // rita holds @read: profiling is a read
        let text = ok_text(
            run_with(
                &host,
                "rita",
                "cpu_profile",
                json!({"seconds": 2, "limit": 5}),
                base.path(),
            )
            .await,
        );
        let calls = fake.calls("perf");
        assert_eq!(calls.len(), 2, "{calls:?}");
        let record = &calls[0];
        let data = record[5].clone();
        assert!(data.starts_with(base.path().to_str().unwrap()), "{data}");
        assert!(data.ends_with("/perf.data"), "{data}");
        assert_eq!(record[..5], strings(&["record", "-F", "99", "-N", "-o"]));
        assert_eq!(record[6..8], strings(&["-a", "--"]));
        assert!(
            record[8].ends_with("/sleep") && record[8].starts_with('/'),
            "{record:?}"
        );
        assert_eq!(record[9], "2");
        assert_eq!(
            calls[1],
            strings(&[
                "report",
                "-i",
                &data,
                "--stdio",
                "--sort",
                "comm,dso,sym",
                "--percent-limit",
                "0.5"
            ])
        );
        assert!(
            text.starts_with("CPU profile of the whole host over 2 s, by function"),
            "{text}"
        );
        assert!(text.contains("do_nanosleep"), "{text}");
        assert!(text.contains("297 samples"), "{text}");
        // nothing is left behind
        let left: Vec<_> = std::fs::read_dir(base.path()).unwrap().collect();
        assert!(left.is_empty(), "{left:?}");
    }

    #[tokio::test]
    async fn cpu_profile_gives_perf_a_home_of_its_own() {
        // perf keeps a cache under $HOME: it must be the scratch directory, not root's
        let fake = FakeBins::new()
            .add_script(
                "perf",
                "case \"$1\" in record) : > \"$6\"; printf '%s\\n' \"home=$HOME\" >&2;; \
                 report) printf '%s\\n' \"# Samples: 1 of event cycles\" \"   100.00%  x  [k] y\"; printf '%s\\n' \"home=$HOME\" >&2;; esac",
            )
            .add("sleep", "", 0);
        let (host, _audit) = fixture(&fake, "system_wide = true");
        let base = tempfile::tempdir().unwrap();
        let text = ok_text(
            run_with(
                &host,
                "adam",
                "cpu_profile",
                json!({"seconds": 1}),
                base.path(),
            )
            .await,
        );
        let data = fake.calls("perf")[0][5].clone();
        let home = format!("home={}", data.trim_end_matches("/perf.data"));
        assert_eq!(text.matches(&home).count(), 2, "{text}");
    }

    #[tokio::test]
    async fn cpu_profile_of_one_process_needs_the_host_list_and_a_grant() {
        let child = Sleeper::start();
        let arguments = json!({"pid": child.pid(), "name": "sleep", "seconds": 1, "by": "library"});
        let base = tempfile::tempdir().unwrap();

        let fake = profiler();
        let (host, _audit) = fixture(&fake, "system_wide = true");
        let message =
            is_denied(run_with(&host, "adam", "cpu_profile", arguments.clone(), base.path()).await);
        assert!(message.contains("trace.processes"), "{message}");
        assert!(fake.calls("perf").is_empty());

        let (host, _audit) = fixture(&fake, &allow_sleep());
        let message =
            is_denied(run_with(&host, "nina", "cpu_profile", arguments.clone(), base.path()).await);
        assert!(!message.contains("sleep"), "{message}");
        assert!(fake.calls("perf").is_empty());

        let text =
            ok_text(run_with(&host, "sam", "cpu_profile", arguments.clone(), base.path()).await);
        let calls = fake.calls("perf");
        assert_eq!(calls[0][6..8], strings(&["-p", &child.pid().to_string()]));
        assert_eq!(calls[1][5], "dso");
        assert!(
            text.starts_with(&format!(
                "CPU profile of sleep (pid {}, owned by {}) over 1 s, by library",
                child.pid(),
                me()
            )),
            "{text}"
        );
        // the wrong name: nothing is run
        let mut wrong = arguments.clone();
        wrong["name"] = json!("nginx");
        let (host, _audit) = fixture(&fake, "processes = [\"**\"]");
        let before = fake.calls("perf").len();
        is_invalid(run_with(&host, "adam", "cpu_profile", wrong, base.path()).await);
        assert_eq!(fake.calls("perf").len(), before);
    }

    #[tokio::test]
    async fn cpu_profile_wants_a_pid_and_a_name_together() {
        let fake = profiler();
        let (host, audit) = fixture(&fake, "system_wide = true\nprocesses = [\"**\"]");
        let base = tempfile::tempdir().unwrap();
        for arguments in [json!({"pid": 1}), json!({"name": "sleep"})] {
            let message =
                is_invalid(run_with(&host, "adam", "cpu_profile", arguments, base.path()).await);
            assert!(message.contains("together"), "{message}");
        }
        assert!(fake.calls("perf").is_empty());
        assert!(audit.records().is_empty());
    }

    #[tokio::test]
    async fn cpu_profile_says_which_packages_provide_perf() {
        let fake = FakeBins::new().add("sleep", "", 0);
        let (host, _audit) = fixture(&fake, "system_wide = true");
        let base = tempfile::tempdir().unwrap();
        let message =
            is_failed(run_with(&host, "adam", "cpu_profile", json!({}), base.path()).await);
        assert!(message.contains("perf is not installed"), "{message}");
        assert!(message.contains("linux-tools"), "{message}");
        assert!(message.contains("linux-perf"), "{message}");
        let left: Vec<_> = std::fs::read_dir(base.path()).unwrap().collect();
        assert!(left.is_empty(), "{left:?}");
    }

    #[tokio::test]
    async fn cpu_profile_stops_at_a_failed_recording_and_still_cleans_up() {
        let fake = FakeBins::new()
            .add_script(
                "perf",
                "printf '%s\\n' 'Error: Access to performance monitoring and observability operations is limited.' >&2; exit 255",
            )
            .add("sleep", "", 0);
        let (host, _audit) = fixture(&fake, "system_wide = true");
        let base = tempfile::tempdir().unwrap();
        let output = run_with(
            &host,
            "adam",
            "cpu_profile",
            json!({"seconds": 1}),
            base.path(),
        )
        .await
        .unwrap();
        assert!(output.is_error());
        assert!(
            output.text().contains("performance monitoring"),
            "{}",
            output.text()
        );
        assert_eq!(
            fake.calls("perf").len(),
            1,
            "no report after a failed recording"
        );
        let left: Vec<_> = std::fs::read_dir(base.path()).unwrap().collect();
        assert!(left.is_empty(), "{left:?}");
    }

    #[tokio::test]
    async fn cpu_profile_cuts_a_long_explanation_of_a_failure_short() {
        let fake = FakeBins::new()
            .add_script(
                "perf",
                "n=0; while [ $n -lt 200 ]; do printf '%s\\n' \"line $n of a long explanation of why not\" >&2; n=$((n+1)); done; exit 255",
            )
            .add("sleep", "", 0);
        let (host, _audit) = fixture(&fake, "system_wide = true");
        let base = tempfile::tempdir().unwrap();
        let output = run_with(&host, "adam", "cpu_profile", json!({}), base.path())
            .await
            .unwrap();
        assert!(output.is_error());
        let text = output.text();
        assert!(
            text.starts_with("perf could not take the samples:\n"),
            "{text}"
        );
        assert!(text.contains("line 0 of a long explanation"), "{text}");
        assert!(!text.contains("line 199 of"), "{text}");
        assert!(text.len() < 1800, "{}", text.len());
        assert!(
            text.contains("more lines of perf's explanation left out]"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn cpu_profile_says_so_when_there_were_no_samples() {
        let fake = FakeBins::new()
            .add_script("perf", "case \"$1\" in record) : > \"$6\";; esac")
            .add("sleep", "", 0);
        let (host, _audit) = fixture(&fake, "system_wide = true");
        let base = tempfile::tempdir().unwrap();
        let text = ok_text(run_with(&host, "adam", "cpu_profile", json!({}), base.path()).await);
        assert!(text.contains("no samples"), "{text}");
    }
}
