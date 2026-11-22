//! Reaching a host over SSH: `ssh HOST opsmcp serve`, kept running, with MCP on its
//! stdin and stdout.
//!
//! AIDEV-NOTE: what makes this safe, all of it tested:
//!   - the system's own `ssh` is run, with an argument list (never a shell on our side);
//!   - everything on its command line comes from the configuration or the inventory,
//!     nothing from a caller: the caller only picked which inventory entry;
//!   - the session cannot prompt, cannot forward an agent, X11 or ports, has no
//!     terminal, and runs the one configured command;
//!   - host keys are checked (`StrictHostKeyChecking=yes` unless the configuration says
//!     `accept-new`); an unknown or changed key is a refusal, never a question;
//!   - with a key of the fleet's own, ssh is told to use that key and nothing else: no
//!     agent, no other identity file, no configuration file, no shared connection that
//!     another identity opened.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::time::Instant;

use serde_json::Value;

use crate::config::FleetSshCfg;
use crate::exec::Cmd;
use crate::fleet::link::{Link, LinkError};

/// Where `ssh` connects and as whom.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshTarget {
    pub address: String,
    pub port: Option<u16>,
    pub user: Option<String>,
    /// A private key of the fleet's own. `None`: whatever identity the user we run as
    /// has (their keys, their agent, their ssh configuration).
    pub key: Option<PathBuf>,
}

/// How often ssh checks that a quiet connection is still there, and how many missed
/// answers end it: a host that vanished is noticed within a minute.
const ALIVE_INTERVAL_SECS: u32 = 15;
const ALIVE_COUNT: u32 = 4;
/// How much of what ssh wrote to stderr is kept, for the reason a session ended.
const STDERR_KEPT: usize = 2048;
/// How much of it is quoted in a message.
const STDERR_SHOWN: usize = 400;

/// The arguments for `ssh`: options, `--`, the address, the remote command.
///
/// AIDEV-NOTE: ssh uses the FIRST value it is given for an option, so the order here is
/// the precedence: what must not change, then (with a key of the fleet's own) what
/// pins the identity, then the operator's options, then defaults the operator may have
/// overridden. Nothing here comes from a caller.
pub fn ssh_args(ssh: &FleetSshCfg, connect_timeout_secs: u64, target: &SshTarget) -> Vec<String> {
    let mut args: Vec<String> = Vec::new();
    let option = |args: &mut Vec<String>, setting: String| {
        args.push("-o".to_string());
        args.push(setting);
    };

    // No terminal, and never read a configuration file when the identity is the fleet's
    // own: what such a session does is then decided by this command line alone.
    args.push("-T".to_string());
    if target.key.is_some() {
        args.push("-F".to_string());
        args.push("none".to_string());
    }
    for fixed in [
        "BatchMode=yes",
        "ForwardAgent=no",
        "ForwardX11=no",
        "ForwardX11Trusted=no",
        "ClearAllForwardings=yes",
        "PermitLocalCommand=no",
        "RequestTTY=no",
        "EscapeChar=none",
        "LogLevel=ERROR",
    ] {
        option(&mut args, fixed.to_string());
    }
    option(&mut args, format!("ConnectTimeout={connect_timeout_secs}"));
    option(
        &mut args,
        format!("ServerAliveInterval={ALIVE_INTERVAL_SECS}"),
    );
    option(&mut args, format!("ServerAliveCountMax={ALIVE_COUNT}"));
    if let Some(key) = &target.key {
        for pinned in [
            "IdentitiesOnly=yes",
            "IdentityAgent=none",
            "PreferredAuthentications=publickey",
            "ControlMaster=no",
            "ControlPath=none",
        ] {
            option(&mut args, pinned.to_string());
        }
        args.push("-i".to_string());
        args.push(key.to_string_lossy().into_owned());
    }
    for configured in &ssh.options {
        option(&mut args, configured.clone());
    }
    option(&mut args, "StrictHostKeyChecking=yes".to_string());
    if let Some(port) = target.port.or(ssh.port) {
        args.push("-p".to_string());
        args.push(port.to_string());
    }
    if let Some(user) = &target.user {
        args.push("-l".to_string());
        args.push(user.clone());
    }
    args.push("--".to_string());
    args.push(target.address.clone());
    args.extend(ssh.remote_command.iter().cloned());
    args
}

/// What ssh (or the command on the host) wrote to stderr, on one line, safe to show.
fn said(stderr: &[u8]) -> String {
    let cleaned = crate::sanitize::clean_text(stderr);
    let flat: String = cleaned
        .chars()
        .map(|c| {
            if matches!(c, '\n' | '\t' | '\r') {
                ' '
            } else {
                c
            }
        })
        .collect();
    let flat = flat.trim();
    let count = flat.chars().count();
    if count > STDERR_SHOWN {
        // The end is where the reason usually is.
        let tail: String = flat.chars().skip(count - STDERR_SHOWN).collect();
        format!("...{tail}")
    } else {
        flat.to_string()
    }
}

/// Why the session ended, from how the process exited and what it wrote.
fn ending(status: std::io::Result<std::process::ExitStatus>, stderr: &[u8]) -> String {
    use std::os::unix::process::ExitStatusExt;
    let how = match status {
        // ssh's own exit status for "could not connect, or was not let in".
        Ok(status) if status.code() == Some(255) => "ssh could not connect or log in".to_string(),
        Ok(status) => match (status.code(), status.signal()) {
            (Some(code), _) => format!("the command on the host ended with status {code}"),
            (None, Some(signal)) => format!("ssh was ended by signal {signal}"),
            (None, None) => "ssh ended".to_string(),
        },
        Err(e) => format!("ssh could not be waited for ({e})"),
    };
    let words = said(stderr);
    if words.is_empty() {
        how
    } else {
        format!("{how}: {words}")
    }
}

/// How long a session that is being closed gets to end by itself, once its input has
/// been closed, before the `ssh` process is killed.
const CLOSE_GRACE: Duration = Duration::from_secs(2);

/// A live MCP connection to one host.
pub struct HostLink {
    /// `None` only while the link is being ended.
    link: Option<Link>,
    /// Set once the process has ended: why.
    ended: tokio::sync::watch::Receiver<Option<String>>,
    /// Watches the process, which it owns. `None` for a link with no process behind it.
    monitor: Option<tokio::task::JoinHandle<()>>,
    /// Tells the monitor that the link is being closed.
    closing: Arc<tokio::sync::Notify>,
    last_used: Mutex<Instant>,
}

impl Drop for HostLink {
    /// AIDEV-NOTE: closing is graceful. Dropping the link closes the pipe to `ssh`, so
    /// the host's `opsmcp serve` sees the end of its input, finishes what it is doing,
    /// writes its `session_end` audit record and exits. The monitor waits a moment for
    /// that and only then kills what is left. It is NOT aborted here.
    fn drop(&mut self) {
        self.link = None;
        self.closing.notify_one();
    }
}

impl HostLink {
    /// Starts `cmd` (an `ssh` command line) and checks that an opsmcp answers within
    /// `handshake`. A message from the host longer than `max_line` closes the link.
    pub async fn open(cmd: &Cmd, max_line: usize, handshake: Duration) -> Result<HostLink, String> {
        use tokio::io::AsyncReadExt;
        let piped = crate::exec::spawn_piped(cmd)?;
        let link = Link::start(piped.stdout, piped.stdin, max_line);
        let (ended_tx, ended) = tokio::sync::watch::channel(None);
        let closing = Arc::new(tokio::sync::Notify::new());

        let (closer, mut process, mut stderr) = (link.closer(), piped.process, piped.stderr);
        let told = closing.clone();
        let monitor = tokio::spawn(async move {
            // Keep the end of what is written to stderr while the process runs.
            let mut kept: Vec<u8> = Vec::new();
            let mut chunk = [0u8; 1024];
            let mut open = true;
            let mut grace = std::pin::pin!(tokio::time::sleep(Duration::MAX));
            let mut closing_seen = false;
            let status = loop {
                tokio::select! {
                    read = stderr.read(&mut chunk), if open => match read {
                        Ok(n) if n > 0 => {
                            kept.extend_from_slice(&chunk[..n]);
                            if kept.len() > STDERR_KEPT {
                                kept.drain(..kept.len() - STDERR_KEPT);
                            }
                        }
                        _ => open = false,
                    },
                    status = process.wait() => break status,
                    _ = told.notified(), if !closing_seen => {
                        // Its input is closed now; it should end by itself shortly.
                        closing_seen = true;
                        grace.as_mut().reset(tokio::time::Instant::now() + CLOSE_GRACE);
                    }
                    // It did not: returning drops the process, which kills it.
                    _ = &mut grace, if closing_seen => return,
                }
            };
            // What it wrote just before ending may still be in the pipe.
            let rest = async {
                while open {
                    match stderr.read(&mut chunk).await {
                        Ok(n) if n > 0 => kept.extend_from_slice(&chunk[..n]),
                        _ => open = false,
                    }
                }
            };
            let _ = tokio::time::timeout(Duration::from_millis(300), rest).await;
            if kept.len() > STDERR_KEPT {
                kept.drain(..kept.len() - STDERR_KEPT);
            }
            let why = ending(status, &kept);
            closer.close(&why);
            let _ = ended_tx.send(Some(why));
        });
        let host = HostLink {
            link: Some(link),
            ended,
            monitor: Some(monitor),
            closing,
            last_used: Mutex::new(Instant::now()),
        };

        let hello = serde_json::json!({
            "protocolVersion": crate::mcp::SUPPORTED_VERSIONS[0],
            "capabilities": {},
            "clientInfo": {"name": "opsmcp-fleet", "version": env!("CARGO_PKG_VERSION")},
        });
        let answer = match tokio::time::timeout(handshake, host.ask("initialize", hello)).await {
            Err(_) => {
                return Err(format!(
                    "it did not answer within {:.0} s (connecting, logging in and starting \
                     opsmcp there)",
                    handshake.as_secs_f64()
                ));
            }
            Ok(Err(LinkError::Closed { why, .. })) => return Err(host.why_ended(why).await),
            Ok(Err(LinkError::Oversized(why))) => return Err(why),
            Ok(Err(LinkError::Rpc { message, .. })) => {
                return Err(format!(
                    "it refused to start a session: {}",
                    said(message.as_bytes())
                ));
            }
            Ok(Ok(answer)) => answer,
        };
        // AIDEV-NOTE: a host that is not running opsmcp (a forced command, a login
        // banner, some other program on the port) must not be talked to as if it were.
        let name = answer
            .get("serverInfo")
            .and_then(|info| info.get("name"))
            .and_then(Value::as_str);
        if name != Some("opsmcp") {
            return Err("what answered there is not opsmcp".to_string());
        }
        if let Some(link) = &host.link {
            link.notify("notifications/initialized");
        }
        Ok(host)
    }

    /// Ends the session and waits (briefly) for the host's side to finish: its input is
    /// closed, it ends by itself, and whatever is left after a moment is killed.
    pub async fn end(mut self) {
        self.link = None;
        self.closing.notify_one();
        if let Some(monitor) = self.monitor.take() {
            let _ = tokio::time::timeout(CLOSE_GRACE + Duration::from_secs(1), monitor).await;
        }
    }

    async fn ask(&self, method: &str, params: Value) -> Result<Value, LinkError> {
        match &self.link {
            Some(link) => link.request(method, params).await,
            None => Err(LinkError::Closed {
                why: "the session is being closed".to_string(),
                sent: false,
            }),
        }
    }

    /// A link over a stream that is already connected, with no process behind it.
    #[cfg(test)]
    pub fn over(link: Link) -> HostLink {
        let (_keep, ended) = tokio::sync::watch::channel(None);
        HostLink {
            link: Some(link),
            ended,
            monitor: None,
            closing: Arc::new(tokio::sync::Notify::new()),
            last_used: Mutex::new(Instant::now()),
        }
    }

    /// The reason the session ended, as the process's exit tells it. That is known a
    /// moment after the stream closes, so wait briefly for it; `fallback` otherwise.
    async fn why_ended(&self, fallback: String) -> String {
        if self.monitor.is_none() {
            return fallback;
        }
        let mut ended = self.ended.clone();
        let known =
            tokio::time::timeout(Duration::from_secs(2), ended.wait_for(Option::is_some)).await;
        match known {
            Ok(Ok(why)) => why.clone().unwrap_or(fallback),
            _ => fallback,
        }
    }

    /// Sends a request and waits for its result.
    pub async fn request(&self, method: &str, params: Value) -> Result<Value, LinkError> {
        self.touch();
        let outcome = self.ask(method, params).await;
        self.touch();
        match outcome {
            Err(LinkError::Closed { why, sent }) => Err(LinkError::Closed {
                why: self.why_ended(why).await,
                sent,
            }),
            other => other,
        }
    }

    fn touch(&self) {
        *self
            .last_used
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Instant::now();
    }

    /// Whether the connection has ended.
    pub fn is_closed(&self) -> bool {
        self.link
            .as_ref()
            .is_none_or(|link| link.closed().is_some())
    }

    /// Requests sent and not yet answered.
    pub fn in_flight(&self) -> usize {
        self.link.as_ref().map_or(0, Link::in_flight)
    }

    /// How long ago the link was last used.
    pub fn idle_for(&self) -> Duration {
        self.last_used
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::testing::write_executable;
    use serde_json::json;

    fn target() -> SshTarget {
        SshTarget {
            address: "web1.example.com".to_string(),
            port: None,
            user: None,
            key: None,
        }
    }

    fn position(args: &[String], wanted: &str) -> usize {
        args.iter()
            .position(|a| a == wanted)
            .unwrap_or_else(|| panic!("{wanted:?} is not in {args:?}"))
    }

    /// The value of the first `-o KEY=...` on the command line, which is the one ssh uses.
    fn option<'a>(args: &'a [String], key: &str) -> Option<&'a str> {
        let prefix = format!("{}=", key.to_ascii_lowercase());
        args.windows(2)
            .filter(|pair| pair[0] == "-o")
            .find_map(|pair| {
                pair[1]
                    .to_ascii_lowercase()
                    .starts_with(&prefix)
                    .then(|| &pair[1][prefix.len()..])
            })
    }

    #[test]
    fn the_command_line_ends_with_the_address_and_the_remote_command() {
        let args = ssh_args(&FleetSshCfg::default(), 10, &target());
        let end = position(&args, "--");
        assert_eq!(
            args[end..],
            [
                "--",
                "web1.example.com",
                "sudo",
                "-n",
                "/usr/bin/opsmcp",
                "serve"
            ]
        );
        // and there is exactly one such separator: nothing after it is read as an option
        assert_eq!(args.iter().filter(|a| *a == "--").count(), 1);
    }

    #[test]
    fn the_session_cannot_prompt_forward_or_get_a_terminal() {
        let args = ssh_args(&FleetSshCfg::default(), 7, &target());
        assert!(args.contains(&"-T".to_string()));
        for (key, value) in [
            ("BatchMode", "yes"),
            ("ForwardAgent", "no"),
            ("ForwardX11", "no"),
            ("ClearAllForwardings", "yes"),
            ("PermitLocalCommand", "no"),
            ("RequestTTY", "no"),
            ("EscapeChar", "none"),
            ("StrictHostKeyChecking", "yes"),
            ("ConnectTimeout", "7"),
        ] {
            assert_eq!(option(&args, key), Some(value), "{key}");
        }
        assert!(option(&args, "ServerAliveInterval").is_some());
    }

    #[test]
    fn the_callers_own_identity_uses_their_ssh_settings_untouched() {
        let args = ssh_args(&FleetSshCfg::default(), 10, &target());
        for absent in ["-F", "-i", "-l", "-p"] {
            assert!(!args.contains(&absent.to_string()), "{absent} in {args:?}");
        }
        assert_eq!(option(&args, "IdentitiesOnly"), None);
        assert_eq!(option(&args, "IdentityAgent"), None);
    }

    #[test]
    fn a_key_of_the_fleets_own_is_the_only_identity_offered() {
        let mut target = target();
        target.user = Some("fleet-dev".to_string());
        target.key = Some(PathBuf::from("/etc/opsmcp/fleet/dev_ed25519"));
        let args = ssh_args(&FleetSshCfg::default(), 10, &target);
        assert_eq!(args[position(&args, "-F") + 1], "none");
        assert_eq!(
            args[position(&args, "-i") + 1],
            "/etc/opsmcp/fleet/dev_ed25519"
        );
        assert_eq!(args[position(&args, "-l") + 1], "fleet-dev");
        for (key, value) in [
            ("IdentitiesOnly", "yes"),
            ("IdentityAgent", "none"),
            ("ControlMaster", "no"),
            ("ControlPath", "none"),
            ("PreferredAuthentications", "publickey"),
        ] {
            assert_eq!(option(&args, key), Some(value), "{key}");
        }
        // everything is before the separator
        let end = position(&args, "--");
        assert!(position(&args, "-i") < end && position(&args, "-l") < end);
    }

    #[test]
    fn a_port_and_a_user_are_passed_as_options() {
        let mut target = target();
        target.port = Some(2222);
        target.user = Some("ops".to_string());
        let args = ssh_args(&FleetSshCfg::default(), 10, &target);
        assert_eq!(args[position(&args, "-p") + 1], "2222");
        assert_eq!(args[position(&args, "-l") + 1], "ops");
        assert!(position(&args, "-p") < position(&args, "--"));
    }

    #[test]
    fn configured_options_are_added_but_cannot_displace_the_fixed_ones() {
        let ssh = FleetSshCfg {
            options: vec![
                "ProxyJump=jump.example.com".to_string(),
                "StrictHostKeyChecking=accept-new".to_string(),
                // validation refuses these two; even if one got through, ssh takes the
                // first value it sees, and ours come first
                "BatchMode=no".to_string(),
                "IdentityAgent=/tmp/evil.sock".to_string(),
            ],
            ..FleetSshCfg::default()
        };
        let mut target = target();
        target.user = Some("fleet-dev".to_string());
        target.key = Some(PathBuf::from("/k"));
        let args = ssh_args(&ssh, 10, &target);
        assert_eq!(option(&args, "ProxyJump"), Some("jump.example.com"));
        assert_eq!(option(&args, "StrictHostKeyChecking"), Some("accept-new"));
        assert_eq!(option(&args, "BatchMode"), Some("yes"));
        assert_eq!(option(&args, "IdentityAgent"), Some("none"));
    }

    #[test]
    fn the_remote_command_and_the_default_port_come_from_the_configuration() {
        let ssh = FleetSshCfg {
            remote_command: vec!["/usr/local/bin/opsmcp".to_string(), "serve".to_string()],
            port: Some(2200),
            ..FleetSshCfg::default()
        };
        let args = ssh_args(&ssh, 10, &target());
        let end = position(&args, "--");
        assert_eq!(
            args[end..],
            ["--", "web1.example.com", "/usr/local/bin/opsmcp", "serve"]
        );
        assert_eq!(args[position(&args, "-p") + 1], "2200");
        // a port in the inventory entry wins over the default
        let mut target = target();
        target.port = Some(22);
        let args = ssh_args(&ssh, 10, &target);
        assert_eq!(args[position(&args, "-p") + 1], "22");
    }

    // ---- a stand-in for `ssh HOST opsmcp serve` ----

    /// A script that answers `initialize` and `tools/call` the way a host would, and
    /// writes its pid to `$PIDFILE`-like path given as its first argument.
    const FAKE_HOST: &str = r#"#!/bin/sh
echo $$ > "$1"
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  case "$line" in
    *'"method":"initialize"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","serverInfo":{"name":"%s","version":"t"}}}\n' "$id" "${2:-opsmcp}" ;;
    *'"die"'*)
      echo "sudo: a password is required" >&2
      exit 1 ;;
    *'"method":"tools/call"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"from the fake host"}],"isError":false}}\n' "$id" ;;
  esac
done
"#;

    struct Fake {
        dir: tempfile::TempDir,
    }

    impl Fake {
        fn new(script: &str) -> Fake {
            let dir = tempfile::tempdir().unwrap();
            write_executable(&dir.path().join("ssh"), script);
            Fake { dir }
        }

        fn cmd(&self) -> Cmd {
            Cmd::new(self.dir.path().join("ssh")).args([self
                .dir
                .path()
                .join("pid")
                .to_string_lossy()
                .into_owned()])
        }

        fn pid(&self) -> String {
            std::fs::read_to_string(self.dir.path().join("pid"))
                .unwrap()
                .trim()
                .to_string()
        }
    }

    fn alive(pid: &str) -> bool {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => !stat.contains(") Z "),
            Err(_) => false,
        }
    }

    async fn gone(pid: &str) -> bool {
        for _ in 0..150 {
            if !alive(pid) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    const SECOND: Duration = Duration::from_secs(1);

    #[tokio::test]
    async fn a_host_that_answers_as_opsmcp_can_be_called() {
        let fake = Fake::new(FAKE_HOST);
        let link = HostLink::open(&fake.cmd(), 1 << 20, 5 * SECOND)
            .await
            .unwrap();
        let result = link
            .request("tools/call", json!({"name": "x", "arguments": {}}))
            .await
            .unwrap();
        assert_eq!(result["content"][0]["text"], "from the fake host");
        assert!(!link.is_closed());
        assert_eq!(link.in_flight(), 0);
        assert!(link.idle_for() < 5 * SECOND);
    }

    #[tokio::test]
    async fn closing_the_link_ends_the_process() {
        let fake = Fake::new(FAKE_HOST);
        let link = HostLink::open(&fake.cmd(), 1 << 20, 5 * SECOND)
            .await
            .unwrap();
        let pid = fake.pid();
        assert!(alive(&pid));
        drop(link);
        assert!(gone(&pid).await);
    }

    #[tokio::test]
    async fn ending_a_session_lets_the_host_finish_by_itself() {
        // this host says goodbye when its input ends, as opsmcp writes its session_end
        let dir = tempfile::tempdir().unwrap();
        let script = format!("{}echo goodbye > \"$1.bye\"\n", FAKE_HOST);
        write_executable(&dir.path().join("ssh"), &script);
        let pid_file = dir.path().join("pid");
        let cmd = Cmd::new(dir.path().join("ssh")).args([pid_file.to_string_lossy().into_owned()]);
        let link = HostLink::open(&cmd, 1 << 20, 5 * SECOND).await.unwrap();
        let pid = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .to_string();
        link.end().await;
        // it was not killed: it got to write its last line, and it is gone
        assert_eq!(
            std::fs::read_to_string(dir.path().join("pid.bye")).unwrap(),
            "goodbye\n"
        );
        assert!(gone(&pid).await);
    }

    #[tokio::test]
    async fn a_session_that_will_not_end_by_itself_is_killed_after_a_moment() {
        // ignores the end of its input and sleeps on
        let fake = Fake::new(&format!("{FAKE_HOST}sleep 300\n"));
        let link = HostLink::open(&fake.cmd(), 1 << 20, 5 * SECOND)
            .await
            .unwrap();
        let pid = fake.pid();
        let started = Instant::now();
        link.end().await;
        assert!(started.elapsed() < 5 * SECOND, "{:?}", started.elapsed());
        assert!(gone(&pid).await);
    }

    #[tokio::test]
    async fn a_login_that_fails_is_reported_with_what_ssh_said() {
        let fake = Fake::new(
            "#!/bin/sh\necho 'sean@web1: Permission denied (publickey).' >&2\nexit 255\n",
        );
        let error = HostLink::open(&fake.cmd(), 1 << 20, 5 * SECOND)
            .await
            .err()
            .unwrap();
        assert!(error.contains("could not connect or log in"), "{error}");
        assert!(error.contains("Permission denied (publickey)"), "{error}");
    }

    #[tokio::test]
    async fn a_remote_command_that_refuses_is_reported_with_its_status_and_words() {
        let fake = Fake::new(
            "#!/bin/sh\necho 'opsmcp: user dev has no role in /etc/opsmcp/config.toml; nothing to serve' >&2\nexit 1\n",
        );
        let error = HostLink::open(&fake.cmd(), 1 << 20, 5 * SECOND)
            .await
            .err()
            .unwrap();
        assert!(error.contains("status 1"), "{error}");
        assert!(error.contains("has no role"), "{error}");
    }

    #[tokio::test]
    async fn what_ssh_said_cannot_smuggle_control_characters_or_run_on() {
        let fake = Fake::new(
            "#!/bin/sh\nprintf 'first line\\nsecond \\033[31mline\\n' >&2\ni=0; while [ $i -lt 400 ]; do printf 'padding ' >&2; i=$((i+1)); done\nexit 255\n",
        );
        let error = HostLink::open(&fake.cmd(), 1 << 20, 5 * SECOND)
            .await
            .err()
            .unwrap();
        assert!(
            !error.contains('\u{1b}') && !error.contains('\n'),
            "{error:?}"
        );
        assert!(error.len() < 900, "{} bytes", error.len());
    }

    #[tokio::test]
    async fn a_host_that_never_answers_is_given_up_on_and_its_process_ended() {
        let fake = Fake::new("#!/bin/sh\necho $$ > \"$1\"\nsleep 300\n");
        let started = Instant::now();
        let error = HostLink::open(&fake.cmd(), 1 << 20, Duration::from_millis(600))
            .await
            .err()
            .unwrap();
        assert!(error.contains("did not answer"), "{error}");
        assert!(started.elapsed() < 5 * SECOND);
        assert!(gone(&fake.pid()).await);
    }

    #[tokio::test]
    async fn something_other_than_opsmcp_answering_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        write_executable(&dir.path().join("ssh"), FAKE_HOST);
        let cmd = Cmd::new(dir.path().join("ssh")).args([
            dir.path().join("pid").to_string_lossy().into_owned(),
            "somebody-else".to_string(),
        ]);
        let error = HostLink::open(&cmd, 1 << 20, 5 * SECOND)
            .await
            .err()
            .unwrap();
        assert!(error.contains("not opsmcp"), "{error}");
    }

    #[tokio::test]
    async fn a_connection_that_dies_mid_call_says_so_and_why() {
        let fake = Fake::new(FAKE_HOST);
        let link = HostLink::open(&fake.cmd(), 1 << 20, 5 * SECOND)
            .await
            .unwrap();
        let error = link
            .request("tools/call", json!({"name": "die"}))
            .await
            .unwrap_err();
        let LinkError::Closed { why, sent } = error else {
            panic!("{error:?}");
        };
        assert!(sent);
        assert!(
            why.contains("status 1") && why.contains("a password is required"),
            "{why}"
        );
        assert!(link.is_closed());
    }

    #[tokio::test]
    async fn a_program_that_cannot_be_started_is_an_error() {
        let error = HostLink::open(&Cmd::new("/nonexistent/ssh"), 1 << 20, SECOND)
            .await
            .err()
            .unwrap();
        assert!(error.contains("/nonexistent/ssh"), "{error}");
    }
}
