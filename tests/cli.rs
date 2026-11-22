#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! End-to-end tests: the real `opsmcp` binary, run the way an operator or an agent runs it.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn opsmcp() -> Command {
    Command::new(env!("CARGO_BIN_EXE_opsmcp"))
}

/// The name of the user running the tests.
fn me() -> String {
    nix::unistd::User::from_uid(nix::unistd::getuid())
        .unwrap()
        .unwrap()
        .name
}

struct Setup {
    dir: tempfile::TempDir,
}

impl Setup {
    /// Writes `config` (with file auditing into the same directory) and returns the setup.
    fn new(config: &str) -> Setup {
        let dir = tempfile::tempdir().unwrap();
        let audit = dir.path().join("audit.jsonl");
        let text = format!(
            "{config}\n[audit]\nsyslog = false\nfile = \"{}\"\n",
            audit.display()
        );
        std::fs::write(dir.path().join("config.toml"), text).unwrap();
        Setup { dir }
    }

    fn config(&self) -> PathBuf {
        self.dir.path().join("config.toml")
    }

    fn run(&self, subcommand: &str) -> Output {
        opsmcp()
            .arg(subcommand)
            .arg("--config")
            .arg(self.config())
            .output()
            .unwrap()
    }

    fn audit(&self) -> Vec<Value> {
        let text = std::fs::read_to_string(self.dir.path().join("audit.jsonl")).unwrap_or_default();
        text.lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A configuration in which the user running the tests is a read-only caller.
fn reader_config() -> String {
    format!(
        "[roles.readonly]\nallow = [\"@read\"]\n[roles.admin]\nallow = [\"@all\"]\n\
         [unix_users.{}]\nroles = [\"readonly\"]\n[unix_groups.no-such-group-xyz]\nroles = [\"admin\"]\n",
        me()
    )
}

#[test]
fn check_config_accepts_a_valid_configuration_and_summarises_it() {
    let setup = Setup::new(&reader_config());
    let out = setup.run("check-config");
    let stdout = text(&out.stdout);
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    assert!(stdout.contains("is valid"), "{stdout}");
    // the readonly role can use tools, none of which change anything
    let readonly = stdout
        .lines()
        .find(|l| l.trim_start().starts_with("readonly"))
        .expect(&stdout);
    assert!(readonly.contains(" 0 that change"), "{readonly}");
    let admin = stdout
        .lines()
        .find(|l| l.trim_start().starts_with("admin"))
        .expect(&stdout);
    assert!(admin.contains("87 tools"), "{admin}");
    assert!(stdout.contains(&me()), "{stdout}");
}

#[test]
fn check_config_reports_every_problem_and_fails() {
    let setup =
        Setup::new("[roles.ops]\nallow = [\"@write\"]\n[unix_users.bob]\nroles = [\"missing\"]\n");
    let out = setup.run("check-config");
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("@write") && stderr.contains("missing"),
        "{stderr}"
    );
    assert_eq!(text(&out.stdout), "");
}

#[test]
fn a_misspelled_setting_is_an_error() {
    let setup = Setup::new("[roles.ops]\nalow = [\"@read\"]\n");
    let out = setup.run("check-config");
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("alow"), "{}", text(&out.stderr));
}

#[test]
fn a_configuration_file_that_others_can_write_is_refused() {
    let setup = Setup::new(&reader_config());
    std::fs::set_permissions(setup.config(), std::fs::Permissions::from_mode(0o666)).unwrap();
    for subcommand in ["check-config", "serve", "tools", "whoami"] {
        let out = setup.run(subcommand);
        assert_eq!(out.status.code(), Some(1), "{subcommand}");
        assert!(
            text(&out.stderr).contains("writable"),
            "{subcommand}: {}",
            text(&out.stderr)
        );
        assert_eq!(text(&out.stdout), "", "{subcommand}");
    }
}

#[test]
fn a_missing_configuration_file_is_a_clear_error() {
    let out = opsmcp()
        .args(["check-config", "--config", "/nonexistent/opsmcp.toml"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("/nonexistent/opsmcp.toml"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn new_token_prints_a_token_and_the_hash_to_configure() {
    let out = opsmcp().args(["new-token", "ci"]).output().unwrap();
    assert!(out.status.success());
    let stdout = text(&out.stdout);
    let token = stdout
        .split_whitespace()
        .find(|w| w.starts_with("opsmcp_"))
        .expect(&stdout);
    let digest: String = Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(
        stdout.contains(&format!("sha256 = \"{digest}\"")),
        "{stdout}"
    );
    assert!(stdout.contains("[tokens.ci]"), "{stdout}");
    // what it printed is accepted as configuration
    let stanza: String = stdout
        .lines()
        .skip_while(|l| !l.contains("[tokens.ci]"))
        .map(|l| format!("{}\n", l.trim()))
        .collect();
    let stanza = stanza.replace("roles = [\"CHANGE-ME\"]", "roles = [\"r\"]");
    let setup = Setup::new(&format!("[roles.r]\nallow = [\"@read\"]\n{stanza}"));
    let check = setup.run("check-config");
    assert!(check.status.success(), "{}", text(&check.stderr));
}

#[test]
fn new_token_rejects_a_name_that_is_not_a_plain_identifier() {
    let out = opsmcp().args(["new-token", "bad name]"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(text(&out.stdout), "");
}

#[test]
fn tools_lists_each_tool_with_its_access_and_permission() {
    let setup = Setup::new(&reader_config());
    let out = setup.run("tools");
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    let line = stdout
        .lines()
        .find(|l| l.starts_with("service_control"))
        .expect(&stdout);
    assert!(
        line.contains("write") && line.contains("service.control"),
        "{line}"
    );
    let line = stdout
        .lines()
        .find(|l| l.starts_with("system_info"))
        .expect(&stdout);
    assert!(
        line.contains("read") && line.contains("system.view"),
        "{line}"
    );
}

#[test]
fn whoami_shows_who_the_caller_is_and_what_they_may_use() {
    let setup = Setup::new(&reader_config());
    let out = setup.run("whoami");
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains(&me()) && stdout.contains("readonly"),
        "{stdout}"
    );
    assert!(stdout.contains("system_info"), "{stdout}");
    assert!(
        !stdout.contains("service_control"),
        "a read-only caller has no write tools: {stdout}"
    );
}

/// An MCP session with `opsmcp serve`.
struct Session {
    child: std::process::Child,
    stdin: Option<std::process::ChildStdin>,
    stdout: BufReader<std::process::ChildStdout>,
    next_id: u64,
}

impl Session {
    fn start(config: &Path) -> Session {
        Session::start_with(&["serve"], config, &[])
    }

    /// Starts `opsmcp ARGS --config CONFIG` with extra environment variables.
    fn start_with(args: &[&str], config: &Path, env: &[(&str, &str)]) -> Session {
        let mut child = opsmcp()
            .args(args)
            .arg("--config")
            .arg(config)
            .envs(env.iter().copied())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Session {
            child,
            stdin,
            stdout,
            next_id: 1,
        }
    }

    fn send(&mut self, message: Value) {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{message}").unwrap();
        stdin.flush().unwrap();
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        let reply: Value =
            serde_json::from_str(&line).unwrap_or_else(|e| panic!("bad reply {line:?}: {e}"));
        assert_eq!(reply["id"], id, "{reply}");
        reply
    }

    fn call(&mut self, tool: &str, arguments: Value) -> (String, bool) {
        let reply = self.request("tools/call", json!({"name": tool, "arguments": arguments}));
        let result = &reply["result"];
        (
            result["content"][0]["text"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            result["isError"].as_bool().unwrap(),
        )
    }

    /// Closes stdin and waits for the server to exit; returns (exit ok, stdout rest, stderr).
    fn finish(mut self) -> (bool, String, String) {
        drop(self.stdin.take());
        let mut rest = String::new();
        std::io::Read::read_to_string(&mut self.stdout, &mut rest).unwrap();
        let out = self.child.wait_with_output().unwrap();
        (out.status.success(), rest, text(&out.stderr))
    }
}

#[test]
fn serve_speaks_mcp_over_stdio_and_audits_what_was_done() {
    let setup = Setup::new(&reader_config());
    let mut session = Session::start(&setup.config());

    let init = session.request(
        "initialize",
        json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}),
    );
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(init["result"]["serverInfo"]["name"], "opsmcp");
    session.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));

    let listed = session.request("tools/list", json!({}));
    let names: Vec<&str> = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"system_info") && names.contains(&"process_list"),
        "{names:?}"
    );
    assert!(
        !names.contains(&"service_control"),
        "a read-only caller is not offered write tools: {names:?}"
    );

    let (overview, is_error) = session.call("system_info", json!({}));
    assert!(!is_error, "{overview}");
    assert!(overview.contains("Kernel:"), "{overview}");

    // a tool that exists but that this caller may not use
    let (refusal, is_error) = session.call(
        "service_control",
        json!({"unit": "nginx", "action": "restart"}),
    );
    assert!(is_error);
    assert!(refusal.contains("service.control"), "{refusal}");

    let (ok, rest, stderr) = session.finish();
    assert!(ok, "stderr: {stderr}");
    assert_eq!(rest, "", "nothing but replies may appear on stdout");

    let audit = setup.audit();
    let events: Vec<&str> = audit.iter().map(|r| r["event"].as_str().unwrap()).collect();
    assert_eq!(
        events,
        [
            "session_start",
            "tool_call",
            "tool_result",
            "tool_call",
            "tool_result",
            "session_end"
        ]
    );
    assert!(audit.iter().all(|r| r["principal"] == me()), "{audit:?}");
    assert_eq!(
        (audit[1]["tool"].as_str(), audit[1]["decision"].as_str()),
        (Some("system_info"), Some("allow"))
    );
    assert_eq!(
        (audit[3]["tool"].as_str(), audit[3]["decision"].as_str()),
        (Some("service_control"), Some("deny"))
    );
    assert_eq!(audit[0]["transport"], "stdio");
}

#[test]
fn serve_refuses_a_caller_who_holds_no_role() {
    let setup = Setup::new(
        "[roles.readonly]\nallow = [\"@read\"]\n[unix_users.somebody-else-xyz]\nroles = [\"readonly\"]\n",
    );
    let session = Session::start(&setup.config());
    let (ok, stdout, stderr) = session.finish();
    assert!(!ok);
    assert_eq!(stdout, "");
    assert!(
        stderr.contains(&me()) && stderr.contains("no role"),
        "{stderr}"
    );
    assert_eq!(setup.audit(), Vec::<Value>::new());
}

#[test]
fn serve_does_not_start_if_it_cannot_audit() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let text_ = format!(
        "{}[audit]\nsyslog = false\nfile = \"/nonexistent-dir/audit.jsonl\"\n",
        reader_config()
    );
    std::fs::write(&config, text_).unwrap();
    let session = Session::start(&config);
    let (ok, stdout, stderr) = session.finish();
    assert!(!ok);
    assert_eq!(stdout, "");
    assert!(stderr.contains("audit"), "{stderr}");
}

#[test]
fn a_bad_line_does_not_end_the_session() {
    let setup = Setup::new(&reader_config());
    let mut session = Session::start(&setup.config());
    writeln!(session.stdin.as_mut().unwrap(), "this is not json").unwrap();
    let mut line = String::new();
    session.stdout.read_line(&mut line).unwrap();
    let reply: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(reply["error"]["code"], -32700);
    assert_eq!(session.request("ping", json!({}))["result"], json!({}));
    assert!(session.finish().0);
}

/// Reads the server's stderr until it reports the address it is listening on.
fn listening_address(stderr: &mut BufReader<std::process::ChildStderr>) -> String {
    let mut seen = String::new();
    loop {
        let mut line = String::new();
        if stderr.read_line(&mut line).unwrap() == 0 {
            panic!("the server exited without listening; stderr was:\n{seen}");
        }
        seen.push_str(&line);
        if let Some(rest) = line.split("listening on https://").nth(1) {
            return rest.trim().trim_end_matches("/mcp").to_string();
        }
    }
}

/// One HTTPS request to `address`, trusting only `ca_pem`. Returns the raw reply.
fn https(address: &str, ca_pem: &str, request: &str) -> String {
    use rustls::pki_types::pem::PemObject;
    use std::io::Read;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from_pem_slice(ca_pem.as_bytes()).unwrap())
        .unwrap();
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut conn = rustls::ClientConnection::new(std::sync::Arc::new(config), name).unwrap();
    let mut socket = std::net::TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut socket);
    tls.write_all(request.as_bytes()).unwrap();
    let mut reply = Vec::new();
    let _ = tls.read_to_end(&mut reply);
    text(&reply)
}

/// Whether a server answers `request` with 200 when the client shows no certificate.
fn answers_without_a_certificate(address: &str, ca_pem: &str, request: &str) -> bool {
    let (address, ca_pem, request) = (address.to_string(), ca_pem.to_string(), request.to_string());
    // A server that insists on a certificate ends the handshake, which the helper
    // reports by panicking or by returning nothing, depending on when it notices.
    std::thread::spawn(move || https(&address, &ca_pem, &request))
        .join()
        .is_ok_and(|reply| reply.starts_with("HTTP/1.1 200"))
}

#[test]
fn serve_http_answers_over_tls_and_stops_cleanly_when_terminated() {
    // a self-signed certificate for localhost: it is its own CA
    let key = rcgen::KeyPair::generate().unwrap();
    let params =
        rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap();
    let cert = params.self_signed(&key).unwrap();

    let token = "opsmcp_end_to_end_token";
    let digest: String = Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let setup = Setup::new("");
    let dir = setup.dir.path();
    std::fs::write(dir.join("server.pem"), cert.pem()).unwrap();
    std::fs::write(dir.join("server.key"), key.serialize_pem()).unwrap();
    std::fs::set_permissions(
        dir.join("server.key"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let config = format!(
        "[roles.readonly]\nallow = [\"@read\"]\n[tokens.e2e]\nsha256 = \"{digest}\"\nroles = [\"readonly\"]\n\
         [http]\nlisten = \"127.0.0.1:0\"\ntls_cert = \"{d}/server.pem\"\ntls_key = \"{d}/server.key\"\n\
         [audit]\nsyslog = false\nfile = \"{d}/audit.jsonl\"\n",
        d = dir.display()
    );
    std::fs::write(setup.config(), config).unwrap();

    let mut child = opsmcp()
        .arg("serve-http")
        .arg("--config")
        .arg(setup.config())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let address = listening_address(&mut stderr);

    let health = https(
        &address,
        &cert.pem(),
        "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(
        health.starts_with("HTTP/1.1 200") && health.ends_with("ok\n"),
        "{health}"
    );

    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "system_info", "arguments": {}}}).to_string();
    let post = |authorization: &str| {
        format!(
            "POST /mcp HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{authorization}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    };
    let refused = https(&address, &cert.pem(), &post(""));
    assert!(refused.starts_with("HTTP/1.1 401"), "{refused}");
    let answered = https(
        &address,
        &cert.pem(),
        &post(&format!("Authorization: Bearer {token}\r\n")),
    );
    assert!(answered.starts_with("HTTP/1.1 200"), "{answered}");
    let reply: Value = serde_json::from_str(answered.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert!(
        reply["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("Kernel:"),
        "{reply}"
    );

    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id() as i32),
        nix::sys::signal::Signal::SIGTERM,
    )
    .unwrap();
    let status = child.wait().unwrap();
    assert!(status.success(), "{status:?}");

    let audit = setup.audit();
    let events: Vec<&str> = audit.iter().map(|r| r["event"].as_str().unwrap()).collect();
    assert_eq!(events, ["auth_failure", "tool_call", "tool_result"]);
    assert_eq!(audit[1]["principal"], "token:e2e");
    assert_eq!(audit[1]["transport"], "https");
}

#[test]
fn check_config_also_checks_that_this_host_can_run_the_configuration() {
    // TLS files that are not there
    let setup = Setup::new(&format!(
        "{}[http]\nlisten = \"127.0.0.1:0\"\ntls_cert = \"/nonexistent/server.pem\"\ntls_key = \"/nonexistent/server.key\"\n",
        reader_config()
    ));
    let out = setup.run("check-config");
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stdout));
    assert!(
        text(&out.stderr).contains("/nonexistent/server.pem"),
        "{}",
        text(&out.stderr)
    );

    // an audit file in a directory that is not there
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            "{}[audit]\nsyslog = false\nfile = \"/nonexistent-dir/audit.jsonl\"\n",
            reader_config()
        ),
    )
    .unwrap();
    let out = opsmcp()
        .arg("check-config")
        .arg("--config")
        .arg(&config)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stdout));
    assert!(
        text(&out.stderr).contains("/nonexistent-dir"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn output_into_a_closed_pipe_ends_quietly() {
    // `opsmcp tools | head -1`: the reader goes away while we are still printing
    let setup = Setup::new(&reader_config());
    let mut child = opsmcp()
        .arg("tools")
        .arg("--config")
        .arg(setup.config())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let out = child.wait_with_output().unwrap();
    assert!(
        !text(&out.stderr).contains("panicked"),
        "{}",
        text(&out.stderr)
    );
}

// ---- fleet mode ----

/// Creates an executable script. Written by a child process, never by this one: a file
/// this process held open for writing could be inherited by a test thread that forks at
/// that moment, and running the script would then fail with "Text file busy".
fn write_executable(path: &Path, content: &str) {
    let mut writer = Command::new("/bin/sh")
        .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    writer
        .stdin
        .take()
        .unwrap()
        .write_all(content.as_bytes())
        .unwrap();
    assert!(writer.wait().unwrap().success(), "writing {path:?}");
}

/// A fleet for end-to-end tests. Each host is a real `opsmcp serve` with its own
/// configuration and audit file; `ssh` is a stand-in that records how it was called and
/// then starts the opsmcp of the host it was asked to connect to.
struct FleetSetup {
    dir: tempfile::TempDir,
}

/// A host configuration in which the user running the tests holds `role`.
fn host_config(role: &str) -> String {
    format!(
        "[roles.readonly]\nallow = [\"@read\"]\n[roles.admin]\nallow = [\"@all\"]\n\
         [unix_users.{}]\nroles = [\"{role}\"]\n",
        me()
    )
}

impl FleetSetup {
    /// `fleet` is the fleet configuration without its `[audit]`, `[paths]` and
    /// inventory settings, which are added here; `{me}` in it is the user running the
    /// tests and `{dir}` the directory everything is in.
    fn new(fleet: &str, inventory: &str, hosts: &[(&str, String)]) -> FleetSetup {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().display().to_string();
        for (name, config) in hosts {
            let text =
                format!("{config}\n[audit]\nsyslog = false\nfile = \"{d}/{name}-audit.jsonl\"\n");
            std::fs::write(dir.path().join(format!("{name}.toml")), text).unwrap();
        }
        std::fs::write(dir.path().join("hosts.toml"), inventory).unwrap();
        let ssh = format!(
            "#!/bin/sh\n\
             dir='{d}'\n\
             printf '%s\\n' \"$*\" >> \"$dir/ssh-calls\"\n\
             env > \"$dir/ssh-env\"\n\
             while [ $# -gt 0 ]; do\n\
             \x20 if [ \"$1\" = \"--\" ]; then shift; break; fi\n\
             \x20 shift\n\
             done\n\
             host=\"$1\"\n\
             if [ ! -f \"$dir/$host.toml\" ]; then\n\
             \x20 echo \"ssh: connect to host $host port 22: No route to host\" >&2\n\
             \x20 exit 255\n\
             fi\n\
             exec '{}' serve --config \"$dir/$host.toml\"\n",
            env!("CARGO_BIN_EXE_opsmcp")
        );
        write_executable(&dir.path().join("ssh"), &ssh);
        let fleet = fleet.replace("{me}", &me()).replace("{dir}", &d);
        let text = format!(
            "{fleet}\n[paths.bin]\nssh = \"{d}/ssh\"\n\
             [audit]\nsyslog = false\nfile = \"{d}/fleet-audit.jsonl\"\n"
        );
        std::fs::write(dir.path().join("fleet.toml"), text).unwrap();
        FleetSetup { dir }
    }

    fn config(&self) -> PathBuf {
        self.dir.path().join("fleet.toml")
    }

    fn lines(&self, file: &str) -> Vec<String> {
        std::fs::read_to_string(self.dir.path().join(file))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn records(&self, file: &str) -> Vec<Value> {
        self.lines(file)
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn fleet_audit(&self) -> Vec<Value> {
        self.records("fleet-audit.jsonl")
    }

    fn host_audit(&self, host: &str) -> Vec<Value> {
        self.records(&format!("{host}-audit.jsonl"))
    }

    /// The command lines `ssh` was started with.
    fn ssh_calls(&self) -> Vec<String> {
        self.lines("ssh-calls")
    }
}

const OWN_SSH_FLEET: &str = r#"
[roles.ops]
allow = ["@all"]
[unix_users.{me}]
roles = ["ops"]
[fleet]
name = "testbastion"
inventory = "{dir}/hosts.toml"
retry_secs = 0
[[fleet.access]]
name = "ops-own"
roles = ["ops"]
hosts = ["*"]
via = "ssh"
identity = "caller"
"#;

fn two_web_hosts() -> FleetSetup {
    FleetSetup::new(
        OWN_SSH_FLEET,
        "[groups]\nweb = [\"web1\", \"web2\"]\ndb = [\"db1\"]\n",
        &[
            ("web1", host_config("admin")),
            ("web2", host_config("readonly")),
        ],
    )
}

#[test]
fn a_fleet_reaches_every_host_through_one_connection() {
    let setup = two_web_hosts();
    let mut session = Session::start_with(&["fleet"], &setup.config(), &[]);

    let init = session.request("initialize", json!({"protocolVersion": "2025-06-18"}));
    assert_eq!(init["result"]["serverInfo"]["name"], "opsmcp");
    let instructions = init["result"]["instructions"].as_str().unwrap();
    assert!(instructions.contains("fleet_hosts"), "{instructions}");

    let listed = session.request("tools/list", json!({}));
    let tools = listed["result"]["tools"].as_array().unwrap();
    let find = |name: &str| {
        tools
            .iter()
            .find(|t| t["name"] == name)
            .unwrap_or_else(|| panic!("{name}"))
    };
    assert_eq!(
        find("system_info")["inputSchema"]["required"],
        json!(["fleet_host"])
    );
    assert_eq!(
        find("service_control")["inputSchema"]["required"][0],
        "fleet_host"
    );
    find("fleet_hosts");
    // 87 built-in tools and the fleet's own three
    assert_eq!(tools.len(), 90);
    // nothing has been asked of any host yet
    assert!(setup.ssh_calls().is_empty());

    let (hosts, is_error) = session.call("fleet_hosts", json!({}));
    assert!(!is_error);
    assert!(
        hosts.contains("3 hosts") && hosts.contains("web1") && hosts.contains("db1"),
        "{hosts}"
    );
    assert!(hosts.contains("ssh as you"), "{hosts}");

    // one host
    let (info, is_error) = session.call("system_info", json!({"fleet_host": "web1"}));
    assert!(!is_error && info.contains("Kernel:"), "{info}");
    // a group
    let (both, is_error) = session.call("system_info", json!({"fleet_host": "group:web"}));
    assert!(!is_error, "{both}");
    assert!(both.starts_with("2 hosts asked: 2 answered."), "{both}");
    assert!(both.contains("| Kernel:"), "{both}");

    // each host was connected to once, with a command line nothing can prompt on
    let calls = setup.ssh_calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    for (call, host) in calls.iter().zip(["web1", "web2"]) {
        assert!(call.contains("-o BatchMode=yes"), "{call}");
        assert!(call.contains("-o StrictHostKeyChecking=yes"), "{call}");
        assert!(call.contains("-o ForwardAgent=no"), "{call}");
        assert!(
            call.ends_with(&format!("-- {host} sudo -n /usr/bin/opsmcp serve")),
            "{call}"
        );
    }

    let (ok, _, stderr) = session.finish();
    assert!(ok, "{stderr}");

    // the host's own trail names the person, and beside it what the fleet said
    let web1 = setup.host_audit("web1");
    let call = web1.iter().find(|r| r["event"] == "tool_call").unwrap();
    assert_eq!(call["principal"], me());
    assert_eq!(call["tool"], "system_info");
    assert_eq!(call["via"]["gateway"], "testbastion");
    assert_eq!(call["via"]["caller"], me());
    // the fleet's trail has one decision and one result per host and call
    let ours = setup.fleet_audit();
    let events: Vec<&str> = ours.iter().map(|r| r["event"].as_str().unwrap()).collect();
    assert_eq!(events.first(), Some(&"session_start"));
    assert_eq!(events.last(), Some(&"session_end"));
    // fleet_hosts; web1 alone; then web1 and web2 together (in whichever order)
    assert_eq!(events[1..4], ["fleet_result", "fleet_call", "fleet_result"]);
    let count = |event: &str| events.iter().filter(|e| **e == event).count();
    assert_eq!((count("fleet_call"), count("fleet_result")), (3, 4));
    assert_eq!(events.len(), 9);
    assert_eq!(ours[2]["host"], "web1");
    assert_eq!(ours[2]["rule"], "ops-own");
    assert_eq!(ours[2]["call"], call["via"]["call"]);
    // the hosts' sessions ended when ours did
    assert!(web1.iter().any(|r| r["event"] == "session_end"), "{web1:?}");
}

#[test]
fn a_fleet_passes_a_change_to_one_host_whose_own_roles_decide() {
    let setup = two_web_hosts();
    let mut session = Session::start_with(&["fleet"], &setup.config(), &[]);
    // the same person is an administrator on web1 and read-only on web2
    let args =
        |host: &str| json!({"fleet_host": host, "name": "kernel.no_such_setting", "value": "1"});
    let (on_web1, _) = session.call("sysctl_set", args("web1"));
    assert!(!on_web1.contains("Permission denied"), "{on_web1}");
    let (on_web2, is_error) = session.call("sysctl_set", args("web2"));
    assert!(
        is_error && on_web2.contains("Permission denied"),
        "{on_web2}"
    );
    // a change cannot be sent to both at once
    let (both, is_error) = session.call("sysctl_set", args("group:web"));
    assert!(is_error && both.contains("one host"), "{both}");
    session.finish();
    let decided = |host: &str| -> Vec<String> {
        setup
            .host_audit(host)
            .iter()
            .filter(|r| r["event"] == "tool_call")
            .map(|r| r["decision"].as_str().unwrap().to_string())
            .collect()
    };
    assert_eq!(decided("web2"), ["deny"]);
    // each host was asked once: the call for both at once reached neither
    for host in ["web1", "web2"] {
        let results = setup
            .host_audit(host)
            .iter()
            .filter(|r| r["event"] == "tool_result")
            .count();
        assert_eq!(results, 1, "{host}");
    }
}

#[test]
fn a_host_that_cannot_be_reached_is_reported_and_the_others_still_answer() {
    let setup = two_web_hosts();
    let mut session = Session::start_with(&["fleet"], &setup.config(), &[]);
    // db1 is in the inventory but is not there
    let (text, is_error) = session.call("system_info", json!({"fleet_host": "db1"}));
    assert!(is_error);
    assert!(
        text.starts_with("db1: could not be reached:") && text.contains("No route to host"),
        "{text}"
    );
    let (text, is_error) = session.call("system_info", json!({"fleet_host": "db1,web1"}));
    assert!(!is_error);
    assert!(
        text.starts_with("2 hosts asked: 1 answered, 1 gave no answer."),
        "{text}"
    );
    session.finish();
    let outcomes: Vec<String> = setup
        .fleet_audit()
        .iter()
        .filter(|r| r["event"] == "fleet_result")
        .map(|r| {
            format!(
                "{}:{}",
                r["host"].as_str().unwrap(),
                r["outcome"].as_str().unwrap()
            )
        })
        .collect();
    assert!(
        outcomes.contains(&"db1:unreachable".to_string()),
        "{outcomes:?}"
    );
    assert!(outcomes.contains(&"web1:ok".to_string()), "{outcomes:?}");
}

#[test]
fn a_read_only_fleet_session_sends_no_changes() {
    let setup = two_web_hosts();
    let mut session = Session::start_with(&["fleet", "--read-only"], &setup.config(), &[]);
    let listed = session.request("tools/list", json!({}));
    let names: Vec<&str> = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"system_info") && !names.contains(&"sysctl_set"),
        "{names:?}"
    );
    let (text, is_error) = session.call(
        "sysctl_set",
        json!({"fleet_host": "web1", "name": "vm.swappiness", "value": "10"}),
    );
    assert!(is_error && text.contains("read-only"), "{text}");
    assert!(setup.ssh_calls().is_empty());
    // a read goes out, and the host is told to hold it to that
    let (_, is_error) = session.call("system_info", json!({"fleet_host": "web1"}));
    assert!(!is_error);
    session.finish();
    let web1 = setup.host_audit("web1");
    let call = web1.iter().find(|r| r["event"] == "tool_call").unwrap();
    assert_eq!(call["read_only"], true);
    let start = &setup.fleet_audit()[0];
    assert_eq!(start["event"], "session_start");
    assert_eq!(start["read_only"], true);
}

#[test]
fn ssh_gets_the_callers_agent_and_nothing_else_from_the_environment() {
    let setup = two_web_hosts();
    let env = [
        ("SSH_AUTH_SOCK", "/tmp/agent-of-the-caller.sock"),
        ("AWS_SECRET_ACCESS_KEY", "do-not-leak"),
        ("LD_PRELOAD", "/tmp/evil.so"),
    ];
    let mut session = Session::start_with(&["fleet"], &setup.config(), &env);
    let (_, is_error) = session.call("system_info", json!({"fleet_host": "web1"}));
    assert!(!is_error);
    session.finish();
    let seen = setup.lines("ssh-env");
    assert!(
        seen.contains(&"SSH_AUTH_SOCK=/tmp/agent-of-the-caller.sock".to_string()),
        "{seen:?}"
    );
    assert!(
        !seen
            .iter()
            .any(|l| l.contains("do-not-leak") || l.contains("LD_PRELOAD")),
        "{seen:?}"
    );
}

const FLEET_KEY_RULES: &str = r#"
[roles.dev]
allow = ["@read"]
[unix_users.{me}]
roles = ["dev"]
[fleet]
name = "testbastion"
inventory = "{dir}/hosts.toml"
[[fleet.access]]
name = "dev-web"
roles = ["dev"]
hosts = ["group:web"]
via = "ssh"
identity = "fleet"
ssh_user = "fleet-dev"
ssh_key = "{dir}/dev_key"
read_only = true
"#;

/// A fleet whose one rule logs in with a key of the fleet's own.
fn fleet_with_its_own_key(mode: u32) -> FleetSetup {
    let setup = FleetSetup::new(
        FLEET_KEY_RULES,
        "[groups]\nweb = [\"web1\"]\n",
        &[("web1", host_config("admin"))],
    );
    let key = setup.dir.path().join("dev_key");
    std::fs::write(&key, "not really a key\n").unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(mode)).unwrap();
    setup
}

#[test]
fn a_rule_with_a_key_of_the_fleets_own_logs_in_with_that_key_and_nothing_else() {
    let setup = fleet_with_its_own_key(0o600);
    let env = [("SSH_AUTH_SOCK", "/tmp/agent-of-the-caller.sock")];
    let mut session = Session::start_with(&["fleet"], &setup.config(), &env);
    let (_, is_error) = session.call("system_info", json!({"fleet_host": "web1"}));
    assert!(!is_error);
    // a change is refused here: the rule is read-only
    let (text, is_error) = session.call(
        "sysctl_set",
        json!({"fleet_host": "web1", "name": "vm.swappiness", "value": "10"}),
    );
    assert!(is_error && text.contains("refused"), "{text}");
    session.finish();

    let call = &setup.ssh_calls()[0];
    let key = setup.dir.path().join("dev_key").display().to_string();
    assert!(call.contains(&format!("-i {key}")), "{call}");
    assert!(call.contains("-l fleet-dev"), "{call}");
    assert!(call.contains("-F none"), "{call}");
    assert!(
        call.contains("-o IdentitiesOnly=yes") && call.contains("-o IdentityAgent=none"),
        "{call}"
    );
    // the caller's agent is not handed to a session that is not the caller's
    let seen = setup.lines("ssh-env");
    assert!(
        !seen.iter().any(|l| l.starts_with("SSH_AUTH_SOCK")),
        "{seen:?}"
    );
    // the host is told who it was for, and to allow no change
    let web1 = setup.host_audit("web1");
    let call = web1.iter().find(|r| r["event"] == "tool_call").unwrap();
    assert_eq!(call["via"]["caller"], me());
    assert_eq!(call["read_only"], true);
    assert_eq!(web1.iter().filter(|r| r["event"] == "tool_call").count(), 1);
}

#[test]
fn a_fleet_does_not_start_with_a_credential_it_should_not_trust_or_cannot_read() {
    // the key is readable by others
    let setup = fleet_with_its_own_key(0o644);
    let out = opsmcp()
        .arg("fleet")
        .arg("--config")
        .arg(setup.config())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("dev_key") && stderr.contains("chmod 600"),
        "{stderr}"
    );
    // the key is not there
    let setup = fleet_with_its_own_key(0o600);
    std::fs::remove_file(setup.dir.path().join("dev_key")).unwrap();
    let out = opsmcp()
        .arg("fleet")
        .arg("--config")
        .arg(setup.config())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("dev_key"),
        "{}",
        text(&out.stderr)
    );
    // the inventory is not there
    let setup = two_web_hosts();
    std::fs::remove_file(setup.dir.path().join("hosts.toml")).unwrap();
    let out = opsmcp()
        .arg("fleet")
        .arg("--config")
        .arg(setup.config())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("hosts.toml"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(text(&out.stdout), "");
}

#[test]
fn a_fleet_configuration_and_a_host_configuration_are_not_interchangeable() {
    let setup = two_web_hosts();
    for subcommand in ["serve", "serve-http"] {
        let out = setup_run(&setup.config(), subcommand);
        assert_eq!(out.status.code(), Some(1), "{subcommand}");
        let stderr = text(&out.stderr);
        assert!(
            stderr.contains("[fleet]") && stderr.contains("opsmcp fleet"),
            "{subcommand}: {stderr}"
        );
    }
    let host = Setup::new(&reader_config());
    for subcommand in ["fleet", "fleet-http"] {
        let out = setup_run(&host.config(), subcommand);
        assert_eq!(out.status.code(), Some(1), "{subcommand}");
        assert!(
            text(&out.stderr).contains("[fleet]"),
            "{subcommand}: {}",
            text(&out.stderr)
        );
    }
}

fn setup_run(config: &Path, subcommand: &str) -> Output {
    opsmcp()
        .arg(subcommand)
        .arg("--config")
        .arg(config)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

#[test]
fn check_config_summarises_a_fleet_configuration() {
    let setup = two_web_hosts();
    let out = setup_run(&setup.config(), "check-config");
    let stdout = text(&out.stdout);
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    assert!(stdout.contains("is valid"), "{stdout}");
    assert!(stdout.contains("Fleet: 3 hosts in 2 groups"), "{stdout}");
    let rule = stdout
        .lines()
        .find(|l| l.contains("ops-own"))
        .unwrap_or_else(|| panic!("{stdout}"));
    assert!(
        rule.contains("ops") && rule.contains("3 hosts") && rule.contains("ssh"),
        "{rule}"
    );
    assert!(rule.contains("the caller's own"), "{rule}");

    // a rule whose hosts match nothing in the inventory is pointed out
    let text_of = std::fs::read_to_string(setup.config()).unwrap();
    std::fs::write(
        setup.config(),
        text_of.replace("hosts = [\"*\"]", "hosts = [\"group:cache\"]"),
    )
    .unwrap();
    let out = setup_run(&setup.config(), "check-config");
    let stdout = text(&out.stdout);
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    assert!(
        stdout.contains("group:cache") && stdout.contains("matches no host"),
        "{stdout}"
    );
}

#[test]
fn serve_read_only_offers_and_runs_only_tools_that_change_nothing() {
    let config = reader_config().replace("roles = [\"readonly\"]", "roles = [\"admin\"]");
    let setup = Setup::new(&config);
    let mut session = Session::start_with(&["serve", "--read-only"], &setup.config(), &[]);
    let listed = session.request("tools/list", json!({}));
    let names: Vec<&str> = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"system_info") && !names.contains(&"sysctl_set"),
        "{names:?}"
    );
    let (text, is_error) = session.call(
        "sysctl_set",
        json!({"name": "vm.swappiness", "value": "10"}),
    );
    assert!(is_error && text.contains("read-only"), "{text}");
    let (_, is_error) = session.call("system_info", json!({}));
    assert!(!is_error);
    session.finish();
    let audit = setup.audit();
    assert_eq!(audit[0]["event"], "session_start");
    assert_eq!(audit[0]["read_only"], true);
    let denied = audit.iter().find(|r| r["event"] == "tool_call").unwrap();
    assert_eq!(denied["decision"], "deny");
}

#[test]
fn a_fleet_over_https_reaches_hosts_with_a_key_of_its_own_and_says_who_asked() {
    let setup = fleet_with_its_own_key(0o600);
    let dir = setup.dir.path();
    let key = rcgen::KeyPair::generate().unwrap();
    let params =
        rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap();
    let cert = params.self_signed(&key).unwrap();
    std::fs::write(dir.join("server.pem"), cert.pem()).unwrap();
    std::fs::write(dir.join("server.key"), key.serialize_pem()).unwrap();
    std::fs::set_permissions(
        dir.join("server.key"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let token = "opsmcp_fleet_front_token";
    let digest: String = Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut config = std::fs::read_to_string(setup.config()).unwrap();
    config.push_str(&format!(
        "[tokens.dana]\nsha256 = \"{digest}\"\nroles = [\"dev\"]\n\
         [http]\nlisten = \"127.0.0.1:0\"\ntls_cert = \"{d}/server.pem\"\ntls_key = \"{d}/server.key\"\n",
        d = dir.display()
    ));
    std::fs::write(setup.config(), config).unwrap();

    let mut child = opsmcp()
        .arg("fleet-http")
        .arg("--config")
        .arg(setup.config())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let address = listening_address(&mut stderr);

    let post = |body: Value| {
        let body = body.to_string();
        let request = format!(
            "POST /mcp HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: Bearer {token}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let answered = https(&address, &cert.pem(), &request);
        assert!(answered.starts_with("HTTP/1.1 200"), "{answered}");
        serde_json::from_str::<Value>(answered.split("\r\n\r\n").nth(1).unwrap()).unwrap()
    };
    let call = |tool: &str, arguments: Value| {
        post(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": tool, "arguments": arguments}}))
    };
    let reply = call("system_info", json!({"fleet_host": "web1"}));
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    assert!(
        reply["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("Kernel:"),
        "{reply}"
    );
    // the session to the host is kept between requests
    call("memory_info", json!({"fleet_host": "web1"}));
    assert_eq!(setup.ssh_calls().len(), 1);

    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id() as i32),
        nix::sys::signal::Signal::SIGTERM,
    )
    .unwrap();
    assert!(child.wait().unwrap().success());

    // the host saw the fleet's account, and beside it the token's name, not the token
    let web1 = setup.host_audit("web1");
    let seen = web1.iter().find(|r| r["event"] == "tool_call").unwrap();
    assert_eq!(seen["via"]["caller"], "token:dana");
    assert_eq!(seen["read_only"], true);
    let ours = setup.fleet_audit();
    let decided = ours.iter().find(|r| r["event"] == "fleet_call").unwrap();
    assert_eq!(decided["principal"], "token:dana");
    assert_eq!(decided["transport"], "https");
    for file in [
        "fleet-audit.jsonl",
        "web1-audit.jsonl",
        "ssh-calls",
        "ssh-env",
    ] {
        assert!(
            !setup.lines(file).iter().any(|l| l.contains(token)),
            "{file}"
        );
    }
}

/// Writes a self-signed certificate for localhost (it is its own CA) as NAME.pem and
/// NAME.key in `dir`, and returns the certificate.
fn self_signed(dir: &Path, name: &str) -> String {
    let key = rcgen::KeyPair::generate().unwrap();
    let params =
        rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap();
    let cert = params.self_signed(&key).unwrap();
    std::fs::write(dir.join(format!("{name}.pem")), cert.pem()).unwrap();
    let key_file = dir.join(format!("{name}.key"));
    std::fs::write(&key_file, key.serialize_pem()).unwrap();
    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    cert.pem()
}

fn sha256_of(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Starts `opsmcp SUBCOMMAND --config CONFIG` as a server and waits for its address.
fn start_server(subcommand: &str, config: &Path) -> (std::process::Child, String) {
    let mut child = opsmcp()
        .arg(subcommand)
        .arg("--config")
        .arg(config)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let address = listening_address(&mut stderr);
    (child, address)
}

fn stop_server(mut child: std::process::Child) {
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id() as i32),
        nix::sys::signal::Signal::SIGTERM,
    )
    .unwrap();
    assert!(child.wait().unwrap().success());
}

#[test]
fn a_fleet_over_https_passes_the_callers_own_token_on_to_a_host_that_knows_it() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let known = "opsmcp_token_known_to_fleet_and_host";
    let fleet_only = "opsmcp_token_known_to_the_fleet_only";

    // The host: `opsmcp serve-http`, where the token is a read-only caller called dana.
    // It takes a token only from a client that also shows the fleet server's
    // certificate, so a token that has been passed on is of no use anywhere else.
    let host_ca = self_signed(d, "host");
    self_signed(d, "fleetclient");
    let host_config = d.join("host.toml");
    std::fs::write(
        &host_config,
        format!(
            "[roles.readonly]\nallow = [\"@read\"]\n[tokens.dana]\nsha256 = \"{}\"\nroles = [\"readonly\"]\n\
             [http]\nlisten = \"127.0.0.1:0\"\ntls_cert = \"{dir}/host.pem\"\ntls_key = \"{dir}/host.key\"\n\
             client_ca = \"{dir}/fleetclient.pem\"\nauth = \"mtls+token\"\n\
             [audit]\nsyslog = false\nfile = \"{dir}/host-audit.jsonl\"\n",
            sha256_of(known),
            dir = d.display()
        ),
    )
    .unwrap();
    let (host, host_address) = start_server("serve-http", &host_config);
    let host_port = host_address.rsplit(':').next().unwrap().to_string();

    // the fleet server: knows both tokens, and passes a caller's own token on
    let fleet_ca = self_signed(d, "fleet");
    std::fs::write(
        d.join("hosts.toml"),
        format!("[hosts.localhost]\nhttps_port = {host_port}\n"),
    )
    .unwrap();
    let fleet_config = d.join("fleet.toml");
    std::fs::write(
        &fleet_config,
        format!(
            "[roles.dev]\nallow = [\"@all\"]\n\
             [tokens.dana]\nsha256 = \"{}\"\nroles = [\"dev\"]\n\
             [tokens.erin]\nsha256 = \"{}\"\nroles = [\"dev\"]\n\
             [http]\nlisten = \"127.0.0.1:0\"\ntls_cert = \"{dir}/fleet.pem\"\ntls_key = \"{dir}/fleet.key\"\n\
             [audit]\nsyslog = false\nfile = \"{dir}/fleet-audit.jsonl\"\n\
             [fleet]\nname = \"testbastion\"\ninventory = \"{dir}/hosts.toml\"\n\
             [fleet.https]\nca = \"{dir}/host.pem\"\n\
             client_cert = \"{dir}/fleetclient.pem\"\nclient_key = \"{dir}/fleetclient.key\"\n\
             [[fleet.access]]\nname = \"own-token\"\nroles = [\"dev\"]\nhosts = [\"*\"]\nvia = \"https\"\nidentity = \"caller\"\n",
            sha256_of(known),
            sha256_of(fleet_only),
            dir = d.display()
        ),
    )
    .unwrap();
    let (fleet, fleet_address) = start_server("fleet-http", &fleet_config);

    let call = |token: &str, tool: &str, arguments: Value| -> (String, bool) {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": tool, "arguments": arguments}})
        .to_string();
        let request = format!(
            "POST /mcp HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: Bearer {token}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let answered = https(&fleet_address, &fleet_ca, &request);
        assert!(answered.starts_with("HTTP/1.1 200"), "{answered}");
        let reply: Value =
            serde_json::from_str(answered.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        (
            reply["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .to_string(),
            reply["result"]["isError"].as_bool().unwrap(),
        )
    };

    // the token both know: the host answers, under the token's own name there
    let (text, is_error) = call(known, "system_info", json!({"fleet_host": "localhost"}));
    assert!(!is_error && text.contains("Kernel:"), "{text}");
    // the fleet lets dana change things (@all); the host, which knows her as read-only,
    // has the last word
    let (text, is_error) = call(
        known,
        "sysctl_set",
        json!({"fleet_host": "localhost", "name": "vm.swappiness", "value": "10"}),
    );
    assert!(
        is_error && text.contains("Permission denied") && text.contains("token:dana"),
        "{text}"
    );
    // a token only the fleet knows gets in here and no further, and nothing else is tried
    let (text, is_error) = call(
        fleet_only,
        "system_info",
        json!({"fleet_host": "localhost"}),
    );
    assert!(is_error, "{text}");
    assert!(
        text.contains("could not be reached") && text.contains("refused the credential"),
        "{text}"
    );

    // The token that went through the fleet server to the host does nothing when it is
    // presented to the host directly, without the fleet server's certificate: what a
    // host learns by being sent a token cannot be used on another host.
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}).to_string();
    let direct = format!(
        "POST /mcp HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: Bearer {known}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    assert!(!answers_without_a_certificate(
        &host_address,
        &host_ca,
        &direct
    ));

    stop_server(fleet);
    stop_server(host);

    let read = |file: &str| -> Vec<Value> {
        std::fs::read_to_string(d.join(file))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    };
    let host_audit = read("host-audit.jsonl");
    let seen = host_audit
        .iter()
        .find(|r| r["event"] == "tool_call")
        .unwrap();
    assert_eq!(seen["principal"], "token:dana");
    assert_eq!(seen["via"]["gateway"], "testbastion");
    assert_eq!(seen["via"]["caller"], "token:dana");
    // the host turned the other token away once, as an unknown token
    let refused: Vec<&Value> = host_audit
        .iter()
        .filter(|r| r["event"] == "auth_failure")
        .collect();
    assert_eq!(refused.len(), 1, "{host_audit:?}");
    let fleet_audit = read("fleet-audit.jsonl");
    let decided = fleet_audit
        .iter()
        .find(|r| r["event"] == "fleet_call")
        .unwrap();
    assert_eq!(decided["rule"], "own-token");
    assert_eq!(decided["identity"], "caller");
    assert!(
        fleet_audit
            .iter()
            .any(|r| r["principal"] == "token:erin" && r["outcome"] == "unreachable")
    );
    // neither token is written down anywhere
    for file in ["host-audit.jsonl", "fleet-audit.jsonl"] {
        let text = std::fs::read_to_string(d.join(file)).unwrap();
        assert!(
            !text.contains(known) && !text.contains(fleet_only),
            "{file}"
        );
    }
}

// ---- a fleet's inventory: Ansible's, and read again while the server runs ----

/// Asks until the answer is the one waited for: what a server picks up by itself takes
/// a moment to show.
fn eventually(mut ask: impl FnMut() -> String, wanted: impl Fn(&str) -> bool) -> String {
    let started = std::time::Instant::now();
    loop {
        let answer = ask();
        if wanted(&answer) {
            return answer;
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "it never happened; the last answer was: {answer}"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[test]
fn a_fleet_picks_up_a_changed_inventory_file_without_a_restart() {
    let fleet = OWN_SSH_FLEET.replace(
        "retry_secs = 0",
        "retry_secs = 0\ninventory_refresh_secs = 1",
    );
    let setup = FleetSetup::new(
        &fleet,
        "[groups]\nweb = [\"web1\"]\n",
        &[
            ("web1", host_config("admin")),
            ("web2", host_config("admin")),
        ],
    );
    let mut session = Session::start_with(&["fleet"], &setup.config(), &[]);
    session.request("initialize", json!({"protocolVersion": "2025-06-18"}));
    let (text, is_error) = session.call("system_info", json!({"fleet_host": "web2"}));
    assert!(is_error && text.contains("no host you can reach"), "{text}");

    std::fs::write(
        setup.dir.path().join("hosts.toml"),
        "[groups]\nweb = [\"web1\", \"web2\"]\n",
    )
    .unwrap();
    let hosts = eventually(
        || session.call("fleet_hosts", json!({})).0,
        |text| text.contains("web2"),
    );
    assert!(hosts.contains("2 hosts"), "{hosts}");
    let (text, is_error) = session.call("system_info", json!({"fleet_host": "web2"}));
    assert!(!is_error && text.contains("Kernel:"), "{text}");

    // a file that is broken is not taken up: the hosts known stay, and it is said
    std::fs::write(
        setup.dir.path().join("hosts.toml"),
        "[hosts.\"not a name\"]\n",
    )
    .unwrap();
    let hosts = eventually(
        || session.call("fleet_hosts", json!({})).0,
        |text| text.contains("could not be read again"),
    );
    assert!(
        hosts.contains("2 hosts") && hosts.contains("web2"),
        "{hosts}"
    );
    let (text, is_error) = session.call("system_info", json!({"fleet_host": "web1"}));
    assert!(!is_error, "{text}");

    assert!(session.finish().0);
    let changes: Vec<Value> = setup
        .fleet_audit()
        .into_iter()
        .filter(|r| r["event"] == "fleet_inventory")
        .collect();
    assert_eq!(changes.len(), 2, "{changes:?}");
    assert_eq!(changes[0]["outcome"], "replaced");
    assert_eq!(
        changes[0]["added"],
        json!([{"host": "web2", "at": "web2", "groups": ["web"]}])
    );
    assert_eq!(changes[1]["outcome"], "failed");
    assert!(
        changes[1]["reason"]
            .as_str()
            .unwrap()
            .contains("not a name"),
        "{changes:?}"
    );
}

#[test]
fn a_fleet_reads_what_ansible_inventory_prints() {
    let fleet = OWN_SSH_FLEET.replace(
        "inventory = \"{dir}/hosts.toml\"",
        "inventory = \"{dir}/hosts.json\"\ninventory_format = \"ansible\"",
    );
    let setup = FleetSetup::new(
        &fleet,
        "",
        &[
            ("web1", host_config("admin")),
            ("web2", host_config("admin")),
        ],
    );
    // app1 is reached at the address Ansible has for it, on the port it has for it;
    // prod holds the hosts of web through being its parent; the host with `_` in its
    // name cannot be used and is left out.
    std::fs::write(
        setup.dir.path().join("hosts.json"),
        r#"{
            "_meta": {"hostvars": {
                "app1.example.com": {"ansible_host": "web1", "ansible_port": 2222,
                                     "db_password": "hunter2"},
                "build_1": {"ansible_host": "web2"}
            }},
            "all": {"children": ["ungrouped", "prod"]},
            "prod": {"children": ["web"]},
            "web": {"hosts": ["app1.example.com", "web2", "build_1"]}
        }"#,
    )
    .unwrap();

    let checked = opsmcp()
        .arg("check-config")
        .arg("--config")
        .arg(setup.config())
        .output()
        .unwrap();
    let report = String::from_utf8_lossy(&checked.stdout).to_string();
    assert!(checked.status.success(), "{report}");
    assert!(report.contains("Fleet: 2 hosts in 3 groups"), "{report}");
    assert!(report.contains("ansible-inventory --list"), "{report}");
    assert!(
        report.contains("left out of the inventory") && report.contains("build_1"),
        "{report}"
    );
    assert!(!report.contains("hunter2"), "{report}");

    let mut session = Session::start_with(&["fleet"], &setup.config(), &[]);
    session.request("initialize", json!({"protocolVersion": "2025-06-18"}));
    let (hosts, _) = session.call("fleet_hosts", json!({}));
    assert!(
        hosts.contains("2 hosts") && !hosts.contains("build_1"),
        "{hosts}"
    );
    let (text, is_error) = session.call("system_info", json!({"fleet_host": "group:prod"}));
    assert!(
        !is_error && text.starts_with("2 hosts asked: 2 answered."),
        "{text}"
    );
    assert!(session.finish().0);

    let calls = setup.ssh_calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    let to_app1 = calls
        .iter()
        .find(|line| line.contains("-p 2222"))
        .unwrap_or_else(|| panic!("{calls:?}"));
    // the address is where it goes, never the name it has in the inventory
    assert!(
        to_app1.ends_with(" -- web1 sudo -n /usr/bin/opsmcp serve"),
        "{to_app1}"
    );
    assert!(!to_app1.contains("app1.example.com"), "{to_app1}");
}

#[test]
fn a_fleet_daemon_reads_its_inventory_again_on_sighup_and_keeps_serving() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let token = "opsmcp_token_of_someone_in_ops";
    let fleet_ca = self_signed(d, "fleet");
    std::fs::write(d.join("hosts.toml"), "[groups]\nweb = [\"web1\"]\n").unwrap();
    let config = d.join("fleet.toml");
    std::fs::write(
        &config,
        format!(
            "[roles.ops]\nallow = [\"@all\"]\n\
             [tokens.olga]\nsha256 = \"{}\"\nroles = [\"ops\"]\n\
             [http]\nlisten = \"127.0.0.1:0\"\ntls_cert = \"{dir}/fleet.pem\"\ntls_key = \"{dir}/fleet.key\"\n\
             [audit]\nsyslog = false\nfile = \"{dir}/fleet-audit.jsonl\"\n\
             [fleet]\nname = \"testbastion\"\ninventory = \"{dir}/hosts.toml\"\ninventory_refresh_secs = 0\n\
             [fleet.https]\nca = \"{dir}/fleet.pem\"\nclient_cert = \"{dir}/fleet.pem\"\nclient_key = \"{dir}/fleet.key\"\n\
             [[fleet.access]]\nname = \"own-token\"\nroles = [\"ops\"]\nhosts = [\"*\"]\nvia = \"https\"\nidentity = \"caller\"\n",
            sha256_of(token),
            dir = d.display()
        ),
    )
    .unwrap();
    let (fleet, address) = start_server("fleet-http", &config);

    let hosts = || -> String {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "fleet_hosts", "arguments": {}}})
        .to_string();
        let request = format!(
            "POST /mcp HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: Bearer {token}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let answered = https(&address, &fleet_ca, &request);
        assert!(answered.starts_with("HTTP/1.1 200"), "{answered}");
        let reply: Value =
            serde_json::from_str(answered.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        reply["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert!(hosts().starts_with("1 host"), "{}", hosts());

    std::fs::write(
        d.join("hosts.toml"),
        "[groups]\nweb = [\"web1\", \"web2\"]\n",
    )
    .unwrap();
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(fleet.id() as i32),
        nix::sys::signal::Signal::SIGHUP,
    )
    .unwrap();
    let listed = eventually(&hosts, |text| text.contains("web2"));
    assert!(listed.starts_with("2 hosts"), "{listed}");

    // and again. Nobody reads this server's stderr any more (the test let go of it),
    // so what it had to say about the first reload could not be written: that must not
    // have cost it the ability to do the next one.
    std::fs::write(
        d.join("hosts.toml"),
        "[groups]\nweb = [\"web1\", \"web2\", \"web3\"]\n",
    )
    .unwrap();
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(fleet.id() as i32),
        nix::sys::signal::Signal::SIGHUP,
    )
    .unwrap();
    let listed = eventually(&hosts, |text| text.contains("web3"));
    assert!(listed.starts_with("3 hosts"), "{listed}");

    // it was told to read again, not to stop: SIGTERM still ends it, cleanly
    stop_server(fleet);
}
