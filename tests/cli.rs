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
    assert!(admin.contains("38 tools"), "{admin}");
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
        let mut child = opsmcp()
            .arg("serve")
            .arg("--config")
            .arg(config)
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
