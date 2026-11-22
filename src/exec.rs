//! Running external commands.
//!
//! AIDEV-NOTE: this is the only place opsmcp starts another program, and the rules are:
//!   - never a shell: a program path and an argument vector, nothing is ever re-parsed;
//!   - the program is found in configured directories, never through the caller's PATH,
//!     and when opsmcp runs as root it must be a root-owned file nobody else can replace;
//!   - a clean, fixed environment; stdin is /dev/null; the working directory is /;
//!   - a time limit, after which the command's whole process group is killed;
//!   - a cap on how much output is kept.

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use rustix::process::{Pid, Signal};
use tokio::io::AsyncReadExt;

use crate::config::{DEFAULT_SEARCH, PathsCfg};

/// A user to run a command as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunAs {
    pub uid: u32,
    pub gid: u32,
}

/// One command to run.
#[derive(Clone, Debug)]
pub struct Cmd {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub timeout: Duration,
    /// Bytes kept from each of stdout and stderr.
    pub max_output: usize,
    pub run_as: Option<RunAs>,
    /// Value of PATH for the command.
    pub path_env: String,
    /// Extra environment variables (the environment is otherwise empty apart from PATH,
    /// LANG and LC_ALL).
    pub env: Vec<(String, String)>,
}

impl Cmd {
    pub fn new(program: impl Into<PathBuf>) -> Cmd {
        Cmd {
            program: program.into(),
            args: Vec::new(),
            timeout: Duration::from_secs(30),
            max_output: 1024 * 1024,
            run_as: None,
            path_env: DEFAULT_SEARCH.join(":"),
            env: Vec::new(),
        }
    }

    pub fn args<I, S>(mut self, args: I) -> Cmd
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Cmd {
        self.timeout = timeout;
        self
    }
}

/// What a command did.
#[derive(Clone, Debug, Default)]
pub struct CmdOutput {
    /// Exit code, or `None` if the command was killed by a signal or by the time limit.
    pub code: Option<i32>,
    /// The signal that ended the command, if one did.
    pub signal: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Output beyond `max_output` was dropped.
    pub truncated: bool,
    /// The time limit expired and the command was killed.
    pub timed_out: bool,
}

/// Runs a command to completion (or to its time limit). An `Err` means it could not be
/// started at all.
pub async fn run(cmd: Cmd) -> Result<CmdOutput, String> {
    let mut command = tokio::process::Command::new(&cmd.program);
    command
        .args(&cmd.args)
        .env_clear()
        .env("PATH", &cmd.path_env)
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .envs(cmd.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        // Its own process group, so that the time limit can kill everything it started.
        .process_group(0);
    if let Some(run_as) = cmd.run_as {
        // AIDEV-NOTE: std sets the gid first, then (because we are root and gave no
        // explicit group list) clears the supplementary groups, then sets the uid. The
        // command therefore runs with exactly this uid and gid and none of root's groups.
        command.gid(run_as.gid).uid(run_as.uid);
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("cannot start {}: {e}", cmd.program.display()))?;
    let mut group = GroupGuard::new(child.id());
    let (Some(mut stdout), Some(mut stderr)) = (child.stdout.take(), child.stderr.take()) else {
        return Err(format!(
            "cannot capture output of {}",
            cmd.program.display()
        ));
    };

    let mut out = Capped::new(cmd.max_output);
    let mut err = Capped::new(cmd.max_output);
    let (mut out_open, mut err_open) = (true, true);
    let (mut out_chunk, mut err_chunk) = ([0u8; 8192], [0u8; 8192]);
    let mut status = None;
    let mut timed_out = false;

    let deadline = tokio::time::sleep(cmd.timeout);
    tokio::pin!(deadline);
    // Armed when the command exits: how long we keep reading pipes that something it
    // left running in the background still holds open.
    let linger = tokio::time::sleep(Duration::ZERO);
    tokio::pin!(linger);

    while status.is_none() || out_open || err_open {
        tokio::select! {
            read = stdout.read(&mut out_chunk), if out_open => match read {
                Ok(n) if n > 0 => out.push(&out_chunk[..n]),
                _ => out_open = false,
            },
            read = stderr.read(&mut err_chunk), if err_open => match read {
                Ok(n) if n > 0 => err.push(&err_chunk[..n]),
                _ => err_open = false,
            },
            exited = child.wait(), if status.is_none() => {
                let exited = exited
                    .map_err(|e| format!("waiting for {}: {e}", cmd.program.display()))?;
                status = Some(exited);
                // It ended by itself: whatever it left running is not ours to kill.
                group.disarm();
                linger.as_mut().reset(tokio::time::Instant::now() + PIPE_LINGER);
            }
            _ = &mut deadline, if status.is_none() => {
                timed_out = true;
                break;
            }
            _ = &mut linger, if status.is_some() => break,
        }
    }

    if status.is_none() {
        // Kill the group while the child is still unreaped, so the group id is still ours.
        group.kill();
        let _ = tokio::time::timeout(REAP_WAIT, child.wait()).await;
    }
    Ok(CmdOutput {
        code: status.and_then(|s| s.code()),
        signal: status.and_then(|s| s.signal()),
        truncated: out.truncated || err.truncated,
        stdout: out.bytes,
        stderr: err.bytes,
        timed_out,
    })
}

/// A long-running program whose stdin, stdout and stderr are connected to us: how the
/// fleet server holds an `ssh` session to a host.
pub struct Piped {
    pub stdin: tokio::process::ChildStdin,
    pub stdout: tokio::process::ChildStdout,
    pub stderr: tokio::process::ChildStderr,
    pub process: PipedProcess,
}

/// The running program itself. Dropping it kills the program's whole process group.
pub struct PipedProcess {
    child: tokio::process::Child,
    group: GroupGuard,
}

impl PipedProcess {
    /// Waits for the program to end by itself.
    pub async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        let status = self.child.wait().await?;
        // It ended by itself: whatever it left running is not ours to kill.
        self.group.disarm();
        Ok(status)
    }
}

/// Starts a program that stays running, with pipes to its stdin, stdout and stderr.
///
/// AIDEV-NOTE: the same rules as `run`, except that stdin is a pipe and there is no time
/// limit here: never a shell, a clean and fixed environment, the working directory `/`,
/// its own process group, and everything it started is killed when the `PipedProcess`
/// is dropped. `timeout`, `max_output` and `run_as` of the `Cmd` are not used.
pub fn spawn_piped(cmd: &Cmd) -> Result<Piped, String> {
    let mut command = tokio::process::Command::new(&cmd.program);
    command
        .args(&cmd.args)
        .env_clear()
        .env("PATH", &cmd.path_env)
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .envs(cmd.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    let mut child = command
        .spawn()
        .map_err(|e| format!("cannot start {}: {e}", cmd.program.display()))?;
    let group = GroupGuard::new(child.id());
    let (Some(stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        return Err(format!("cannot connect to {}", cmd.program.display()));
    };
    Ok(Piped {
        stdin,
        stdout,
        stderr,
        process: PipedProcess { child, group },
    })
}

const PIPE_LINGER: Duration = Duration::from_millis(250);
const REAP_WAIT: Duration = Duration::from_secs(2);

/// A byte buffer that keeps at most `max` bytes and remembers if it had to drop any.
struct Capped {
    bytes: Vec<u8>,
    max: usize,
    truncated: bool,
}

impl Capped {
    fn new(max: usize) -> Capped {
        Capped {
            bytes: Vec::new(),
            max,
            truncated: false,
        }
    }

    fn push(&mut self, chunk: &[u8]) {
        let room = self.max.saturating_sub(self.bytes.len());
        let take = room.min(chunk.len());
        self.bytes.extend_from_slice(&chunk[..take]);
        if take < chunk.len() {
            self.truncated = true;
        }
    }
}

/// Kills a command's process group if the command is abandoned before it exits (time
/// limit, cancelled call, client gone).
struct GroupGuard {
    pid: Option<Pid>,
}

impl GroupGuard {
    fn new(pid: Option<u32>) -> GroupGuard {
        let pid = pid
            .and_then(|p| i32::try_from(p).ok())
            .and_then(Pid::from_raw);
        GroupGuard { pid }
    }

    fn disarm(&mut self) {
        self.pid = None;
    }

    fn kill(&mut self) {
        if let Some(pid) = self.pid.take() {
            let _ = rustix::process::kill_process_group(pid, Signal::KILL);
        }
    }
}

impl Drop for GroupGuard {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Finds the system commands the tools use.
#[derive(Clone, Debug)]
pub struct Bins {
    search: Vec<PathBuf>,
    overrides: BTreeMap<String, PathBuf>,
    /// `Some` when found programs must pass `check_trusted_path` with these extra owners.
    trust: Option<Vec<u32>>,
}

impl Bins {
    /// `trust`: `Some(extra_owner_uids)` to require that every program found is owned by
    /// root (or one of the extra uids) and cannot be replaced by anyone else.
    pub fn new(paths: &PathsCfg, trust: Option<Vec<u32>>) -> Bins {
        Bins {
            search: paths.search.clone(),
            overrides: paths.bin.clone(),
            trust,
        }
    }

    /// The absolute path of a command, by bare name.
    pub fn find(&self, name: &str) -> Result<PathBuf, String> {
        self.lookup(name)?.ok_or_else(|| {
            format!(
                "the `{name}` command is not installed on this host (looked in {})",
                self.path_env()
            )
        })
    }

    /// Like `find`, but tells apart a command that is not installed (`Ok(None)`) from
    /// one that is there and may not be run (`Err`).
    ///
    /// AIDEV-NOTE: use this, not `find(..).is_err()`, wherever "the program is absent"
    /// is taken to mean something (no cluster on this host, say). A program that fails
    /// the trust check is not absent, and treating it as absent would fail open.
    pub fn lookup(&self, name: &str) -> Result<Option<PathBuf>, String> {
        if name.is_empty() || name.starts_with('.') || name.contains('/') {
            return Err(format!("{name:?} is not a bare command name"));
        }
        if let Some(path) = self.overrides.get(name) {
            if !is_executable_file(path) {
                return Err(format!(
                    "{name}: the configured location {} is not an executable file",
                    path.display()
                ));
            }
            self.check_program(path)?;
            return Ok(Some(path.clone()));
        }
        for dir in &self.search {
            let candidate = dir.join(name);
            if is_executable_file(&candidate) {
                // Fail closed: an untrusted match is an error, not a reason to look further.
                self.check_program(&candidate)?;
                return Ok(Some(candidate));
            }
        }
        Ok(None)
    }

    /// Like `find`, but for an operator-configured absolute path.
    pub fn check_program(&self, path: &Path) -> Result<(), String> {
        match &self.trust {
            Some(extra_owners) => check_trusted_path(path, extra_owners)
                .map_err(|e| format!("refusing to run {}: {e}", path.display())),
            None => Ok(()),
        }
    }

    /// The PATH given to commands: the configured search directories.
    pub fn path_env(&self) -> String {
        let dirs: Vec<String> = self
            .search
            .iter()
            .map(|d| d.to_string_lossy().into_owned())
            .collect();
        dirs.join(":")
    }
}

/// Checks that nobody but root (or one of `extra_owners`) can change what `path` refers
/// to: the file and every directory leading to it must be owned by a trusted user, the
/// file must not be writable by group or others, and a directory may only be writable by
/// group or others if it has the sticky bit (as /tmp and /nix/store do).
pub fn check_trusted_path(path: &Path, extra_owners: &[u32]) -> Result<(), String> {
    // Resolve links first: what matters is who controls the real file and the real
    // directories on the way to it.
    let real = std::fs::canonicalize(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let stat = |p: &Path| std::fs::metadata(p).map_err(|e| format!("{}: {e}", p.display()));
    let check_owner = |p: &Path, uid: u32| -> Result<(), String> {
        if uid == 0 || extra_owners.contains(&uid) {
            Ok(())
        } else {
            Err(format!(
                "{} is owned by uid {uid}, which is not trusted",
                p.display()
            ))
        }
    };

    let meta = stat(&real)?;
    check_owner(&real, meta.uid())?;
    if meta.mode() & 0o022 != 0 {
        return Err(format!("{} is writable by group or others", real.display()));
    }
    for dir in real.ancestors().skip(1) {
        let meta = stat(dir)?;
        check_owner(dir, meta.uid())?;
        let (writable, sticky) = (meta.mode() & 0o022 != 0, meta.mode() & 0o1000 != 0);
        if writable && !sticky {
            return Err(format!(
                "directory {} is writable by group or others",
                dir.display()
            ));
        }
    }
    Ok(())
}

fn is_executable_file(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Instant;

    fn sh(script: &str) -> Cmd {
        Cmd::new("/bin/sh").args(["-c", script])
    }

    #[tokio::test]
    async fn captures_stdout_stderr_and_the_exit_code() {
        let out = run(sh("echo out; echo err >&2; exit 3")).await.unwrap();
        assert_eq!(out.stdout, b"out\n");
        assert_eq!(out.stderr, b"err\n");
        assert_eq!(out.code, Some(3));
        assert!(!out.timed_out && !out.truncated);
    }

    #[tokio::test]
    async fn arguments_are_passed_verbatim_never_re_parsed() {
        let out = run(Cmd::new("/bin/sh").args([
            "-c",
            "printf '%s|' \"$@\"",
            "sh",
            "a b",
            "$(id)",
            ";ls",
            "*",
        ]))
        .await
        .unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout), "a b|$(id)|;ls|*|");
    }

    #[tokio::test]
    async fn the_environment_of_the_server_is_not_inherited() {
        // cargo sets CARGO_MANIFEST_DIR for the test process
        assert!(std::env::var("CARGO_MANIFEST_DIR").is_ok());
        let out = run(sh("echo \"[$CARGO_MANIFEST_DIR][$HOME][$LC_ALL]\""))
            .await
            .unwrap();
        assert_eq!(out.stdout, b"[][][C]\n");
    }

    #[tokio::test]
    async fn extra_environment_and_path_are_applied() {
        let mut cmd = sh("echo \"$GREETING $PATH\"");
        cmd.env.push(("GREETING".to_string(), "hello".to_string()));
        cmd.path_env = "/only/this".to_string();
        let out = run(cmd).await.unwrap();
        assert_eq!(out.stdout, b"hello /only/this\n");
    }

    #[tokio::test]
    async fn stdin_is_empty() {
        let out = run(sh("read line; echo \"[$line]\"")).await.unwrap();
        assert_eq!(out.stdout, b"[]\n");
    }

    #[tokio::test]
    async fn the_working_directory_is_the_root() {
        let out = run(sh("pwd")).await.unwrap();
        assert_eq!(out.stdout, b"/\n");
    }

    #[tokio::test]
    async fn a_command_killed_by_a_signal_reports_it() {
        let out = run(sh("kill -TERM $$")).await.unwrap();
        assert_eq!(out.code, None);
        assert_eq!(out.signal, Some(15));
    }

    #[tokio::test]
    async fn output_beyond_the_cap_is_dropped_and_flagged() {
        let script = "i=0; while [ $i -lt 5000 ]; do echo 0123456789012345678901234567890123456789; i=$((i+1)); done";
        let mut cmd = sh(script);
        cmd.max_output = 1000;
        let out = run(cmd).await.unwrap();
        assert_eq!(out.stdout.len(), 1000);
        assert!(out.truncated);
        assert_eq!(out.code, Some(0));
    }

    fn alive(pid: &str) -> bool {
        // a killed-but-unreaped process still has a /proc entry; look at its state
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => !stat.contains(") Z "),
            Err(_) => false,
        }
    }

    #[tokio::test]
    async fn a_piped_program_answers_on_stdout_what_it_is_sent_on_stdin() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let mut piped = spawn_piped(&sh("while read line; do echo \"got $line\"; done")).unwrap();
        let mut lines = BufReader::new(piped.stdout).lines();
        for word in ["one", "two"] {
            piped
                .stdin
                .write_all(format!("{word}\n").as_bytes())
                .await
                .unwrap();
            assert_eq!(
                lines.next_line().await.unwrap().unwrap(),
                format!("got {word}")
            );
        }
        // closing its stdin lets it end, and its exit status can be collected
        drop(piped.stdin);
        let status = tokio::time::timeout(Duration::from_secs(5), piped.process.wait())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.code(), Some(0));
    }

    #[tokio::test]
    async fn a_piped_program_gets_the_same_clean_environment_as_any_other() {
        use tokio::io::AsyncReadExt;
        assert!(std::env::var("CARGO_MANIFEST_DIR").is_ok());
        let mut cmd =
            sh("echo \"[$CARGO_MANIFEST_DIR][$HOME][$LC_ALL][$EXTRA]\"; pwd; echo oops >&2");
        cmd.env.push(("EXTRA".to_string(), "yes".to_string()));
        let mut piped = spawn_piped(&cmd).unwrap();
        let (mut out, mut err) = (String::new(), String::new());
        piped.stdout.read_to_string(&mut out).await.unwrap();
        piped.stderr.read_to_string(&mut err).await.unwrap();
        assert_eq!(out, "[][][C][yes]\n/\n");
        assert_eq!(err, "oops\n");
    }

    #[tokio::test]
    async fn dropping_a_piped_program_kills_everything_it_started() {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let piped = spawn_piped(&sh("sleep 300 & echo $!; echo $$; wait")).unwrap();
        let mut lines = BufReader::new(piped.stdout).lines();
        let child = lines.next_line().await.unwrap().unwrap();
        let shell = lines.next_line().await.unwrap().unwrap();
        assert!(alive(&child) && alive(&shell));
        drop(piped.process);
        for _ in 0..100 {
            if !alive(&child) && !alive(&shell) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!(
            "still running: sleep {} shell {}",
            alive(&child),
            alive(&shell)
        );
    }

    #[tokio::test]
    async fn a_piped_program_that_cannot_be_started_is_an_error() {
        let error = spawn_piped(&Cmd::new("/nonexistent/program"))
            .err()
            .unwrap();
        assert!(error.contains("/nonexistent/program"), "{error}");
    }

    #[tokio::test]
    async fn the_time_limit_kills_the_whole_process_group() {
        let started = Instant::now();
        // AIDEV-NOTE: the limit must leave the shell time to start and print the pid even
        // on a busy machine; at 300 ms this test failed now and then under load.
        let cmd = sh("sleep 30 & echo $!; wait").timeout(Duration::from_millis(1500));
        let out = run(cmd).await.unwrap();
        assert!(out.timed_out);
        assert_eq!(out.code, None);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "took {:?}",
            started.elapsed()
        );
        let child = String::from_utf8_lossy(&out.stdout).trim().to_string();
        assert!(
            !child.is_empty(),
            "the background pid should have been captured"
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        while alive(&child) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            !alive(&child),
            "background process {child} survived the time limit"
        );
    }

    #[tokio::test]
    async fn a_background_process_holding_the_pipes_does_not_stall_the_result() {
        let started = Instant::now();
        // the background sleep inherits stdout and stderr and outlives the shell
        let out = run(sh("sleep 4 & echo started")).await.unwrap();
        assert_eq!(out.stdout, b"started\n");
        assert_eq!(out.code, Some(0));
        assert!(!out.timed_out);
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn a_program_that_cannot_be_started_is_an_error() {
        assert!(run(Cmd::new("/nonexistent/program")).await.is_err());
    }

    fn make_file(dir: &Path, name: &str, mode: u32) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn lookup_tells_a_missing_program_from_one_that_may_not_be_run() {
        let dir = tempfile::tempdir().unwrap();
        make_file(dir.path(), "present", 0o755);
        let paths = PathsCfg {
            search: vec![dir.path().to_path_buf()],
            bin: BTreeMap::new(),
        };
        let any = Bins::new(&paths, None);
        assert_eq!(any.lookup("absent"), Ok(None));
        assert_eq!(any.lookup("present"), Ok(Some(dir.path().join("present"))));
        // owned by the user running the tests, not by root: not trusted
        if rustix::process::getuid().as_raw() != 0 {
            let strict = Bins::new(&paths, Some(Vec::new()));
            assert!(strict.lookup("present").is_err());
            assert_eq!(strict.lookup("absent"), Ok(None));
        }
        assert!(any.lookup("../bin/sh").is_err());
    }

    fn me() -> u32 {
        rustix::process::getuid().as_raw()
    }

    fn bins(dir: &Path, trust: Option<Vec<u32>>) -> Bins {
        let paths = PathsCfg {
            search: vec![PathBuf::from("/nonexistent-dir"), dir.to_path_buf()],
            bin: BTreeMap::new(),
        };
        Bins::new(&paths, trust)
    }

    #[test]
    fn find_returns_the_first_executable_in_the_search_directories() {
        let dir = tempfile::tempdir().unwrap();
        let tool = make_file(dir.path(), "mytool", 0o755);
        make_file(dir.path(), "notexec", 0o644);
        let bins = bins(dir.path(), None);
        assert_eq!(bins.find("mytool").unwrap(), tool);
        assert!(bins.find("notexec").is_err());
        let missing = bins.find("absent").unwrap_err();
        assert!(missing.contains("absent"), "{missing:?}");
    }

    #[test]
    fn find_only_takes_bare_names() {
        let dir = tempfile::tempdir().unwrap();
        make_file(dir.path(), "mytool", 0o755);
        let bins = bins(dir.path(), None);
        assert!(bins.find("../mytool").is_err());
        assert!(bins.find("/bin/sh").is_err());
        assert!(bins.find("").is_err());
    }

    #[test]
    fn a_configured_location_replaces_the_search() {
        let dir = tempfile::tempdir().unwrap();
        make_file(dir.path(), "mytool", 0o755);
        let other = tempfile::tempdir().unwrap();
        let elsewhere = make_file(other.path(), "renamed", 0o755);
        let mut paths = PathsCfg {
            search: vec![dir.path().to_path_buf()],
            bin: BTreeMap::new(),
        };
        paths.bin.insert("mytool".to_string(), elsewhere.clone());
        assert_eq!(Bins::new(&paths, None).find("mytool").unwrap(), elsewhere);
        // a configured location that does not exist is an error, not a fallback
        paths
            .bin
            .insert("mytool".to_string(), PathBuf::from("/nonexistent/mytool"));
        assert!(Bins::new(&paths, None).find("mytool").is_err());
    }

    #[test]
    fn when_trust_is_enforced_a_program_owned_by_someone_else_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let tool = make_file(dir.path(), "mytool", 0o755);
        // trusting our own uid: fine
        assert_eq!(
            bins(dir.path(), Some(vec![me()])).find("mytool").unwrap(),
            tool
        );
        if me() != 0 {
            // trusting only root: a file we own is refused
            assert!(bins(dir.path(), Some(vec![])).find("mytool").is_err());
            assert!(bins(dir.path(), Some(vec![])).check_program(&tool).is_err());
        }
        assert!(
            bins(dir.path(), Some(vec![me()]))
                .check_program(&tool)
                .is_ok()
        );
    }

    #[test]
    fn trusted_path_rejects_anything_another_user_could_replace() {
        let dir = tempfile::tempdir().unwrap();
        let trusted = [me()];

        let good = make_file(dir.path(), "good", 0o644);
        assert_eq!(check_trusted_path(&good, &trusted), Ok(()));

        let world = make_file(dir.path(), "world", 0o666);
        assert!(check_trusted_path(&world, &trusted).is_err());

        let group = make_file(dir.path(), "group", 0o664);
        assert!(check_trusted_path(&group, &trusted).is_err());

        let open_dir = dir.path().join("open");
        std::fs::create_dir(&open_dir).unwrap();
        let inside = make_file(&open_dir, "inside", 0o644);
        std::fs::set_permissions(&open_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(check_trusted_path(&inside, &trusted).is_err());
        // with the sticky bit others cannot replace our file there
        std::fs::set_permissions(&open_dir, std::fs::Permissions::from_mode(0o1777)).unwrap();
        assert_eq!(check_trusted_path(&inside, &trusted), Ok(()));

        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&world, &link).unwrap();
        assert!(
            check_trusted_path(&link, &trusted).is_err(),
            "a link is judged by its target"
        );

        assert!(check_trusted_path(&dir.path().join("absent"), &trusted).is_err());
    }

    #[test]
    fn trusted_path_requires_a_trusted_owner() {
        if me() == 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let mine = make_file(dir.path(), "mine", 0o644);
        let err = check_trusted_path(&mine, &[]).unwrap_err();
        assert!(err.contains("owned by"), "{err:?}");
    }
}
