//! Monitoring downtimes for this host.
//!
//! The tool talks to the Icinga 2 API over HTTPS as one ApiUser, whose password is in a
//! file on this host. Give that user no more than this host needs. In Icinga:
//!
//! ```text
//! object ApiUser "opsmcp-web1" {
//!   password = "..."
//!   permissions = [
//!     { permission = "actions/schedule-downtime"
//!       filter = {{ host.name == "web1.example.com" }} },
//!     { permission = "actions/remove-downtime"
//!       filter = {{ downtime.host_name == "web1.example.com" }} },
//!     { permission = "objects/query/Downtime"
//!       filter = {{ downtime.host_name == "web1.example.com" }} },
//!   ]
//! }
//! ```
//!
//! `objects/query/Downtime` serves `status`, and `schedule` too: before a downtime is
//! set, the ones opsmcp has already set for the host are counted, and no more than ten
//! may exist at once. Without that permission downtimes are still set, uncounted.
//!
//! AIDEV-NOTE: the security properties here, all of which have tests:
//!   - the host that is put in downtime comes from the configuration (or the kernel's
//!     host name), never from the caller: a caller can silence this host's alerts and
//!     no other host's;
//!   - values reach Icinga's filter language only as `filter_vars`, never as text in
//!     the filter, so nothing can change what a filter means;
//!   - HTTPS only, and the server's certificate is always verified, before the request
//!     (and so the password) is sent. Do not reuse the accepting verifier of `tls.rs`;
//!   - the password is read at call time from a file only its owner can read, and it
//!     is in no output, error or audit record;
//!   - redirects are not followed, the answer is capped, and everything has a time limit.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use rustix::fs::{Mode, OFlags};
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use serde_json::{Value, json};

use super::args::{Args, Param};
use super::package::plain_name;
use super::tls::CA_BUNDLES;
use super::users::b64_encode;
use super::{
    CallClock, Ctx, Tool, ToolError, ToolResult, blocking, format_table, one_line_cell, required,
};
use crate::config::{is_host_name, parse_https_origin};
use crate::policy::Access;
use crate::sanitize::keep_head;
use crate::timefmt::{now_secs, rfc3339_utc};

const ACTIONS: [&str; 3] = ["schedule", "cancel", "status"];
const DEFAULT_COMMENT: &str = "Maintenance through opsmcp";
/// The port of the Icinga 2 API when the URL names none.
const ICINGA_PORT: u16 = 5665;
/// Most bytes kept of one answer from Icinga.
const MAX_BODY: usize = 1024 * 1024;
/// Largest password file that is read.
const MAX_PASSWORD_BYTES: u64 = 1024;
/// How many downtimes set through opsmcp the host itself may have at once. A further
/// `schedule` is refused until some are cancelled or have ended.
const MAX_OWN_DOWNTIMES: usize = 10;
/// How many of the addresses of Icinga's name are tried.
const MAX_ADDRESSES: usize = 4;

/// What the tool needs from its surroundings. A parameter so that the tests can use
/// their own; the server always uses `Env::system()`.
#[derive(Clone, Debug)]
pub struct Env {
    /// Where the kernel's host name is read from when `monitoring.host` is not set.
    pub hostname_file: PathBuf,
    /// The CA bundles tried, in order, when `monitoring.icinga_ca` is not set.
    pub bundles: Vec<PathBuf>,
    /// Time allowed for connecting and completing the TLS handshake.
    pub connect_limit: Duration,
    /// Time allowed for the whole exchange with Icinga.
    pub total_limit: Duration,
}

impl Env {
    pub fn system() -> Env {
        Env {
            hostname_file: PathBuf::from("/proc/sys/kernel/hostname"),
            bundles: CA_BUNDLES.iter().map(PathBuf::from).collect(),
            connect_limit: Duration::from_secs(10),
            total_limit: Duration::from_secs(20),
        }
    }
}

pub fn tools() -> Vec<Tool> {
    tools_with(Env::system())
}

pub fn tools_with(env: Env) -> Vec<Tool> {
    let env = Arc::new(env);
    vec![Tool::new(
        "monitoring_downtime",
        "Set, cancel or show a downtime in the monitoring system (Icinga 2) for THIS host \
         and all of its services, so that planned work such as a reboot or an upgrade \
         does not alert anyone. schedule starts a downtime now for the given number of \
         minutes; it ends by itself. cancel removes the downtimes that were set through \
         this tool; status lists every downtime the host has. Only this host's own entry \
         can be touched, and how long a downtime may be is limited by this host's \
         configuration.",
        Access::Write,
        "monitoring.downtime",
        vec![
            Param::choice("action", "What to do", &ACTIONS).required(),
            Param::int(
                "minutes",
                "For schedule: how long the downtime lasts, from now (default 60)",
                1,
                10_080,
            ),
            Param::str(
                "comment",
                "For schedule: why, as shown in the monitoring system (at most 200 \
                 characters; default \"Maintenance through opsmcp\")",
            )
            .max_len(800),
        ],
        move |ctx, args| monitoring_downtime(env.clone(), ctx, args),
    )]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Schedule,
    Cancel,
    Status,
}

impl Action {
    fn parse(name: &str) -> Option<Action> {
        match name {
            "schedule" => Some(Action::Schedule),
            "cancel" => Some(Action::Cancel),
            "status" => Some(Action::Status),
            _ => None,
        }
    }

    /// Where the request goes.
    fn path(self) -> &'static str {
        match self {
            Action::Schedule => "/v1/actions/schedule-downtime",
            Action::Cancel => "/v1/actions/remove-downtime",
            Action::Status => "/v1/objects/downtimes",
        }
    }

    /// The Icinga API permission the ApiUser needs for it.
    fn permission(self) -> &'static str {
        match self {
            Action::Schedule => "actions/schedule-downtime",
            Action::Cancel => "actions/remove-downtime",
            Action::Status => "objects/query/Downtime",
        }
    }
}

/// Checks a downtime comment: 1 to 200 characters on one line, not blank.
pub fn check_comment(comment: &str) -> Result<(), ToolError> {
    let fits = comment.chars().count() <= 200;
    if comment.trim().is_empty() || !fits || comment.chars().any(char::is_control) {
        return Err(ToolError::Invalid(
            "the comment must be 1 to 200 printable characters on one line".to_string(),
        ));
    }
    Ok(())
}

/// The author recorded in Icinga for a downtime that `principal` set. `cancel` finds
/// opsmcp's downtimes again by the `opsmcp:` at its start.
pub fn author_of(principal: &str) -> String {
    let name: String = plain_name(principal).chars().take(100).collect();
    format!("opsmcp:{name}")
}

/// The body of the request that sets a downtime for the host and all its services.
///
/// AIDEV-NOTE: here and in the two requests below the filter is constant text and the
/// host's name goes in `filter_vars`. Never build a filter with `format!`.
pub fn schedule_request(host: &str, author: &str, comment: &str, start: i64, end: i64) -> Value {
    json!({
        "type": "Host",
        "filter": "host.name==host_name",
        "filter_vars": {"host_name": host},
        "all_services": true,
        "author": author,
        "comment": comment,
        "start_time": start,
        "end_time": end,
        "fixed": true,
    })
}

/// The body of the request that removes the downtimes opsmcp set: the host's own and its
/// services', and nobody else's.
///
/// AIDEV-NOTE: it matches every author that starts with `opsmcp:`, so `cancel` removes
/// the downtimes set through opsmcp for this host by ANY caller, not only the one
/// asking. That is intended: a downtime belongs to the host's maintenance, and whoever
/// may set one for the host may end it. Downtimes set by people in Icinga itself are
/// never touched.
pub fn cancel_request(host: &str) -> Value {
    json!({
        "type": "Downtime",
        "filter": "downtime.host_name==host_name && match(\"opsmcp:*\", downtime.author)",
        "filter_vars": {"host_name": host},
    })
}

/// The body of the request that lists the host's downtimes.
pub fn status_request(host: &str) -> Value {
    json!({
        "filter": "downtime.host_name==host_name",
        "filter_vars": {"host_name": host},
        "attrs": ["author", "comment", "start_time", "end_time", "service_name"],
    })
}

/// The body of the request that lists the downtimes opsmcp has set for the host itself
/// (not the ones on its services: `all_services` makes one of those per service). Asked
/// before a downtime is set, to keep their number bounded.
pub fn count_request(host: &str) -> Value {
    json!({
        "filter": "downtime.host_name==host_name && downtime.service_name==\"\" \
                   && match(\"opsmcp:*\", downtime.author)",
        "filter_vars": {"host_name": host},
        "attrs": ["author"],
    })
}

/// Reads the API user's password from its file: the file's one line.
///
/// AIDEV-NOTE: no message from here may contain any of the file's content.
fn read_password(path: &Path) -> Result<String, String> {
    let shown = path.display();
    // NONBLOCK: a FIFO or a device put in the file's place must not hang the call.
    let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    let descriptor = rustix::fs::open(path, flags, Mode::empty()).map_err(|e| {
        format!(
            "cannot read the Icinga password file {shown}: {}",
            std::io::Error::from(e)
        )
    })?;
    let file = File::from(descriptor);
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot examine the Icinga password file {shown}: {e}"))?;
    if !meta.is_file() {
        return Err(format!(
            "the Icinga password file {shown} is not a regular file"
        ));
    }
    let server_uid = rustix::process::geteuid().as_raw();
    if meta.uid() != 0 && meta.uid() != server_uid {
        return Err(format!(
            "the Icinga password file {shown} must be owned by root or by the user opsmcp runs as"
        ));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(format!(
            "the Icinga password file {shown} must not be accessible to group or others \
             (chmod 600)"
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_PASSWORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read the Icinga password file {shown}: {e}"))?;
    if bytes.len() as u64 > MAX_PASSWORD_BYTES {
        return Err(format!(
            "the Icinga password file {shown} is larger than {MAX_PASSWORD_BYTES} bytes: it \
             must hold the password and nothing else"
        ));
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| format!("the Icinga password file {shown} does not hold text"))?;
    let password = text.trim_end_matches(['\n', '\r']);
    if password.is_empty() {
        return Err(format!("the Icinga password file {shown} is empty"));
    }
    if password.chars().any(char::is_control) {
        return Err(format!(
            "the Icinga password file {shown} must hold one line: the password and nothing else"
        ));
    }
    Ok(password.to_string())
}

/// The certificate authorities the Icinga API's certificate must chain to: those in the
/// configured CA file, or else in the first of the host's bundles that has any.
fn load_trust(custom: Option<&Path>, bundles: &[PathBuf]) -> Result<RootCertStore, String> {
    let read = |path: &Path| -> Result<RootCertStore, String> {
        let blocks = CertificateDer::pem_file_iter(path).map_err(|e| format!("{e:?}"))?;
        let mut roots = RootCertStore::empty();
        // A bundle may hold certificates this library cannot use; they are passed over.
        let (added, _unusable) = roots.add_parsable_certificates(blocks.flatten());
        if added == 0 {
            return Err("it holds no usable CA certificate".to_string());
        }
        Ok(roots)
    };
    if let Some(path) = custom {
        // No falling back to the host's bundle: the operator said which CA to trust.
        return read(path).map_err(|problem| {
            format!(
                "monitoring.icinga_ca ({}) cannot be used: {problem}",
                path.display()
            )
        });
    }
    bundles
        .iter()
        .find_map(|path| read(path).ok())
        .ok_or_else(|| {
            "no bundle of trusted certificate authorities was found on this host: set \
             monitoring.icinga_ca to the CA that issued the Icinga API's certificate"
                .to_string()
        })
}

/// The name of this machine's host object in Icinga.
fn host_name(configured: Option<&str>, hostname_file: &Path) -> Result<String, String> {
    if let Some(name) = configured {
        return Ok(name.to_string());
    }
    let unusable = || {
        "this host's name in Icinga cannot be worked out from the kernel's host name: set \
         monitoring.host to the name of this machine's host object in Icinga"
            .to_string()
    };
    let mut text = String::new();
    File::open(hostname_file)
        .and_then(|file| file.take(256).read_to_string(&mut text))
        .map_err(|_| unusable())?;
    let name = text.trim();
    if !is_host_name(name) {
        return Err(unusable());
    }
    Ok(name.to_string())
}

/// What an answer needs before anything is sent.
struct Prepared {
    host_name: String,
    /// `Basic ...`, marked sensitive so that it is never printed.
    authorization: HeaderValue,
    roots: RootCertStore,
}

/// Where the Icinga API is.
struct Endpoint {
    host: String,
    port: u16,
    /// Whether the trusted CAs came from `monitoring.icinga_ca`.
    custom_ca: bool,
}

/// One request to Icinga.
struct Ask {
    path: &'static str,
    /// Icinga takes a query that has a body as a POST that says it is a GET.
    as_get: bool,
    body: Value,
}

/// Icinga's answer.
struct Reply {
    status: u16,
    body: Vec<u8>,
    /// The body was longer than `MAX_BODY`; only its start is in `body`.
    cut: bool,
}

/// Why there was no answer.
struct Trouble {
    message: String,
    /// The request may have reached Icinga (so a change may have been made).
    sent: bool,
}

/// Ends the task that drives a connection when the exchange is over, however it ends.
struct Driver(tokio::task::JoinHandle<()>);

impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Connects to the first of `addresses` that answers, trying at most `MAX_ADDRESSES`.
///
/// AIDEV-NOTE: each address gets a share of `limit` of its own. Connecting to a name
/// in one go tries its addresses one after another inside a single limit, so one that
/// never answers (an IPv6 address where IPv6 is not routed) would use the whole limit
/// before the address that works is tried. One share is kept back for what comes after
/// the connection (the TLS handshake), which the caller times as part of the same limit.
async fn connect_any(
    addresses: &[SocketAddr],
    limit: Duration,
) -> Result<tokio::net::TcpStream, String> {
    let tried = addresses
        .get(..addresses.len().min(MAX_ADDRESSES))
        .unwrap_or_default();
    if tried.is_empty() {
        return Err("its name has no address".to_string());
    }
    let shares = u32::try_from(tried.len()).unwrap_or(1).saturating_add(1);
    let share = limit / shares;
    let mut last = String::new();
    for address in tried {
        match tokio::time::timeout(share, tokio::net::TcpStream::connect(address)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => last = format!("{address}: {e}"),
            Err(_) => {
                last = format!("{address}: no answer within {:.1} s", share.as_secs_f64());
            }
        }
    }
    Err(match tried.len() {
        1 => last,
        count => format!("none of its {count} addresses could be connected to (the last, {last})"),
    })
}

/// Sends one request to Icinga over HTTPS and reads the answer.
///
/// AIDEV-NOTE: the certificate is verified (against `roots`, for the name in the URL)
/// during the handshake, which completes before the request, and so the password, is
/// written. There is deliberately no option to skip that. Redirects are not followed:
/// a 3xx is just an answer.
async fn exchange(
    endpoint: &Endpoint,
    roots: RootCertStore,
    authorization: HeaderValue,
    ask: Ask,
    connect_limit: Duration,
    total_limit: Duration,
) -> Result<Reply, Trouble> {
    let at = format!("{}:{}", endpoint.host, endpoint.port);
    let unsent = |message: String| Trouble {
        message,
        sent: false,
    };
    let started = Instant::now();

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| unsent(format!("TLS setup: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = ServerName::try_from(endpoint.host.clone()).map_err(|_| {
        unsent(format!(
            "{:?} cannot be used as a server name",
            endpoint.host
        ))
    })?;
    let body = serde_json::to_vec(&ask.body)
        .map_err(|e| unsent(format!("cannot write the request: {e}")))?;
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(ask.path)
        .header(header::HOST, at.as_str())
        .header(header::ACCEPT, "application/json")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::USER_AGENT, "opsmcp")
        .header(header::CONNECTION, "close")
        .header(header::AUTHORIZATION, authorization);
    if ask.as_get {
        request = request.header("x-http-method-override", "GET");
    }
    let request = request
        .body(Full::new(Bytes::from(body)))
        .map_err(|e| unsent(format!("cannot build the request: {e}")))?;

    let trusted = if endpoint.custom_ca {
        "the CA in monitoring.icinga_ca"
    } else {
        "a CA this host trusts (or set monitoring.icinga_ca)"
    };
    let connect_limit = connect_limit.min(total_limit);
    let connecting = async {
        let addresses: Vec<SocketAddr> =
            tokio::net::lookup_host((endpoint.host.as_str(), endpoint.port))
                .await
                .map_err(|e| {
                    format!(
                        "cannot connect to Icinga at {at}: its name could not be looked up ({e})"
                    )
                })?
                .collect();
        let tcp = connect_any(&addresses, connect_limit)
            .await
            .map_err(|why| format!("cannot connect to Icinga at {at}: {why}"))?;
        tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await
            .map_err(|e| {
                let why: String = e.to_string().chars().take(300).collect();
                format!(
                    "Icinga at {at} did not present a certificate that can be trusted, or \
                     the TLS handshake failed ({}). Its certificate must name {} and be \
                     issued by {trusted}",
                    one_line_cell(&why),
                    endpoint.host
                )
            })
    };
    let tls = match tokio::time::timeout(connect_limit, connecting).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(message)) => return Err(unsent(message)),
        Err(_) => {
            return Err(unsent(format!(
                "Icinga at {at} did not complete the connection within {:.1} s",
                connect_limit.as_secs_f64()
            )));
        }
    };

    let talking = async {
        let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
            .max_buf_size(64 * 1024)
            .max_headers(64)
            .handshake::<_, Full<Bytes>>(TokioIo::new(tls))
            .await
            .map_err(|e| format!("talking to Icinga at {at}: {e}"))?;
        let _driver = Driver(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let response = sender
            .send_request(request)
            .await
            .map_err(|e| format!("talking to Icinga at {at}: {e}"))?;
        let status = response.status().as_u16();
        let mut incoming = response.into_body();
        let mut body = Vec::new();
        let mut cut = false;
        while let Some(frame) = incoming.frame().await {
            let frame = frame.map_err(|e| format!("reading the answer of Icinga at {at}: {e}"))?;
            let Some(data) = frame.data_ref() else {
                continue;
            };
            let room = MAX_BODY.saturating_sub(body.len());
            if data.len() > room {
                body.extend_from_slice(data.get(..room).unwrap_or_default());
                cut = true;
                break;
            }
            body.extend_from_slice(data);
        }
        Ok::<Reply, String>(Reply { status, body, cut })
    };
    let left = total_limit.saturating_sub(started.elapsed());
    match tokio::time::timeout(left, talking).await {
        Ok(Ok(reply)) => Ok(reply),
        Ok(Err(message)) => Err(Trouble {
            message,
            sent: true,
        }),
        Err(_) => Err(Trouble {
            message: format!(
                "Icinga at {at} did not answer within {:.1} s",
                total_limit.as_secs_f64()
            ),
            sent: true,
        }),
    }
}

/// A short piece of text from Icinga, safe to put in a sentence.
fn brief(text: &str, max: usize) -> String {
    let cut: String = text.chars().take(max).collect();
    one_line_cell(cut.trim())
}

/// What Icinga said about one object an action touched.
struct Touched {
    ok: bool,
    said: String,
    /// How many of a host's services were put in downtime with it, when Icinga says.
    services: Option<usize>,
}

/// The per-object results of an action, from the `results` array of the answer.
fn touched(answer: &Value) -> Vec<Touched> {
    let Some(results) = answer.get("results").and_then(Value::as_array) else {
        return Vec::new();
    };
    results
        .iter()
        .map(|result| Touched {
            ok: result
                .get("code")
                .and_then(Value::as_f64)
                .is_some_and(|code| (200.0..300.0).contains(&code)),
            said: brief(
                result.get("status").and_then(Value::as_str).unwrap_or(""),
                200,
            ),
            services: result
                .get("service_downtimes")
                .and_then(Value::as_array)
                .map(Vec::len),
        })
        .collect()
}

/// What to tell the agent when Icinga answered with an error and no per-object results.
fn explain(action: Action, status: u16, said: &str, host: &str) -> String {
    match status {
        401 => "Icinga refused the user name or password (HTTP 401): check \
                monitoring.icinga_user and the password file."
            .to_string(),
        403 => format!(
            "Icinga does not let its API user do this (HTTP 403): the ApiUser needs the \
             permission {}, with a filter that includes this host.",
            action.permission()
        ),
        404 if action == Action::Schedule => no_such_host(host),
        other => {
            let mut text = format!("Icinga answered HTTP {other}");
            if !said.is_empty() {
                text.push_str(&format!(": {said}"));
            }
            if (300..400).contains(&other) {
                text.push_str(
                    " (redirects are not followed: monitoring.icinga_url must name the API itself)",
                );
            }
            text
        }
    }
}

fn no_such_host(host: &str) -> String {
    format!(
        "Icinga found no host named {host} that its API user may put in downtime. Set \
         monitoring.host to the name of this machine's host object in Icinga, or check \
         the filter on the ApiUser's permission."
    )
}

/// The result of a call: the text, and whether it succeeded.
type Outcome = (String, bool);

/// Deals with what every answer can be before its content is looked at: cut short, not
/// JSON, or an error without results. `Ok` is the parsed answer.
fn readable(action: Action, reply: &Reply, host: &str) -> Result<Value, Outcome> {
    let unknown = match action {
        Action::Schedule => " Whether the downtime was set is not known: check with action=status.",
        Action::Cancel => " Whether downtimes were removed is not known: check with action=status.",
        Action::Status => "",
    };
    if reply.cut {
        return Err((
            format!(
                "Icinga answered HTTP {}, but its answer is larger than {MAX_BODY} bytes and \
                 was not read.{unknown}\n",
                reply.status
            ),
            false,
        ));
    }
    let success = (200..300).contains(&reply.status);
    match serde_json::from_slice::<Value>(&reply.body) {
        Ok(answer) => {
            let has_results = answer
                .get("results")
                .and_then(Value::as_array)
                .is_some_and(|results| !results.is_empty());
            if success || has_results || reply.status == 404 {
                return Ok(answer);
            }
            let said = brief(
                answer.get("status").and_then(Value::as_str).unwrap_or(""),
                200,
            );
            Err((
                format!("{}\n", explain(action, reply.status, &said, host)),
                false,
            ))
        }
        Err(_) if success => Err((
            format!(
                "Icinga answered HTTP {}, but not with JSON, so its answer could not be \
                 read.{unknown}\n",
                reply.status
            ),
            false,
        )),
        Err(_) => Err((
            format!("{}\n", explain(action, reply.status, "", host)),
            false,
        )),
    }
}

/// The lines for objects Icinga could not change.
fn failures(results: &[Touched]) -> String {
    let mut text = String::new();
    for result in results.iter().filter(|result| !result.ok).take(10) {
        text.push_str(&format!("  {}\n", result.said));
    }
    text
}

/// How many downtimes Icinga listed in answer to `count_request`, or why that cannot be
/// told. An answer too long to read can only mean a great many.
fn count_of(reply: &Reply, host: &str) -> Result<usize, String> {
    if reply.cut {
        return Ok(usize::MAX);
    }
    // A query that matches nothing is answered with an empty list, or with 404.
    if reply.status == 404 {
        return Ok(0);
    }
    let answer = serde_json::from_slice::<Value>(&reply.body).ok();
    if (200..300).contains(&reply.status) {
        return answer
            .as_ref()
            .and_then(|answer| answer.get("results"))
            .and_then(Value::as_array)
            .map(Vec::len)
            .ok_or_else(|| "Icinga's answer could not be read".to_string());
    }
    let said = answer
        .as_ref()
        .and_then(|answer| answer.get("status"))
        .and_then(Value::as_str)
        .map(|said| brief(said, 200))
        .unwrap_or_default();
    Err(explain(Action::Status, reply.status, &said, host))
}

fn schedule_outcome(
    reply: &Reply,
    host: &str,
    author: &str,
    comment: &str,
    end: i64,
    minutes: i64,
) -> Outcome {
    let answer = match readable(Action::Schedule, reply, host) {
        Ok(answer) => answer,
        Err(outcome) => return outcome,
    };
    let results = touched(&answer);
    if results.is_empty() {
        return (format!("{}\n", no_such_host(host)), false);
    }
    if results.iter().any(|result| !result.ok) {
        return (
            format!(
                "Icinga could not set the downtime for {host}:\n{}",
                failures(&results)
            ),
            false,
        );
    }
    let reported: Vec<usize> = results
        .iter()
        .filter_map(|result| result.services)
        .collect();
    let services: usize = reported.iter().sum();
    let scope = match (reported.is_empty(), services) {
        (true, _) => host.to_string(),
        (false, 0) => format!("{host} (it has no services in Icinga)"),
        (false, 1) => format!("{host} and its 1 service"),
        (false, count) => format!("{host} and its {count} services"),
    };
    let mut text = format!(
        "Downtime set in Icinga for {scope}, from now until {} ({minutes} minutes).\n\
         Author: {author}. Comment: {}\n\
         It ends by itself; action=cancel removes it sooner.\n",
        rfc3339_utc(end),
        one_line_cell(comment)
    );
    if reported.is_empty() {
        text.push_str(
            "[this Icinga did not say whether the host's services are included: that needs \
             Icinga 2.11 or later; action=status shows what is in downtime]\n",
        );
    }
    (text, true)
}

fn cancel_outcome(reply: &Reply, host: &str) -> Outcome {
    let answer = match readable(Action::Cancel, reply, host) {
        Ok(answer) => answer,
        Err(outcome) => return outcome,
    };
    let results = touched(&answer);
    if results.is_empty() {
        // Icinga answers 404 "No objects found" when the filter matches no downtime.
        return (
            format!(
                "Icinga has no downtime that was set through opsmcp for {host}; nothing was \
                 removed.\n"
            ),
            true,
        );
    }
    let removed = results.iter().filter(|result| result.ok).count();
    let noun = if removed == 1 {
        "downtime"
    } else {
        "downtimes"
    };
    let mut text = format!(
        "Removed {removed} {noun} that had been set through opsmcp for {host} in Icinga \
         (the host's own and its services').\n"
    );
    let failed = results.len() - removed;
    if failed > 0 {
        text.push_str(&format!(
            "Icinga could not remove {failed}:\n{}",
            failures(&results)
        ));
    }
    (text, failed == 0)
}

/// Downtimes that share author, comment and period: the host's own, its services', or both.
#[derive(Default)]
struct Covered {
    host: bool,
    services: Vec<String>,
}

fn status_outcome(reply: &Reply, host: &str, now: i64, budget: usize) -> Outcome {
    let answer = match readable(Action::Status, reply, host) {
        Ok(answer) => answer,
        Err(outcome) => return outcome,
    };
    let empty = Vec::new();
    let results = answer
        .get("results")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    // (start, end, author, comment) -> what it covers. Setting a downtime for a host and
    // its services makes one downtime per service: they are shown as one line.
    let mut groups: BTreeMap<(i64, i64, String, String), Covered> = BTreeMap::new();
    for result in results {
        let Some(attrs) = result.get("attrs") else {
            continue;
        };
        let text = |key: &str, max: usize| {
            brief(attrs.get(key).and_then(Value::as_str).unwrap_or(""), max)
        };
        let time = |key: &str| attrs.get(key).and_then(Value::as_f64).unwrap_or(0.0) as i64;
        let key = (
            time("start_time"),
            time("end_time"),
            text("author", 60),
            text("comment", 120),
        );
        let covered = groups.entry(key).or_default();
        let service = text("service_name", 60);
        if service.is_empty() {
            covered.host = true;
        } else {
            covered.services.push(service);
        }
    }
    if groups.is_empty() {
        return (format!("No downtime is set for {host} in Icinga.\n"), true);
    }

    let mut rows = Vec::new();
    for ((start, end, author, comment), covered) in &groups {
        let services = covered.services.len();
        let scope = match (covered.host, services) {
            (true, 0) => "host".to_string(),
            (true, 1) => "host and 1 service".to_string(),
            (true, count) => format!("host and {count} services"),
            (false, 1) => format!(
                "service {}",
                covered.services.first().map_or("", String::as_str)
            ),
            (false, count) => format!("{count} services"),
        };
        let state = if now < *start {
            "not yet started"
        } else if now < *end {
            "in effect"
        } else {
            "ended"
        };
        rows.push(vec![
            scope,
            state.to_string(),
            rfc3339_utc(*start),
            rfc3339_utc(*end),
            author.clone(),
            comment.clone(),
        ]);
    }
    let mut text = format!(
        "Downtimes for {host} in Icinga: {} (times are UTC).\n",
        rows.len()
    );
    text.push_str(&format_table(
        &["COVERS", "STATE", "FROM", "UNTIL", "AUTHOR", "COMMENT"],
        &rows,
        &[false; 6],
    ));
    let (mut text, dropped) = keep_head(&text, budget.saturating_sub(100));
    if dropped > 0 {
        text.push_str(&format!(
            "[{dropped} more lines left out to fit the output limit]\n"
        ));
    }
    (text, true)
}

async fn monitoring_downtime(env: Arc<Env>, ctx: Ctx, args: Args) -> ToolResult {
    let asked = required(&args, "action")?;
    let action = Action::parse(asked)
        .ok_or_else(|| ToolError::Invalid(format!("{asked:?} is not a known action")))?;
    let minutes = args.int("minutes").unwrap_or(60);
    let comment = args.str("comment").unwrap_or(DEFAULT_COMMENT).to_string();
    check_comment(&comment)?;

    // Host-wide limits first: whether the tool is on at all, and how long a downtime
    // may be, are the operator's decisions whatever a role grants.
    let cfg = &ctx.cfg().monitoring;
    let Some(url) = cfg.icinga_url.as_deref() else {
        return Err(ctx.deny(
            None,
            "monitoring is not configured on this host (monitoring.icinga_url)",
        ));
    };
    if action == Action::Schedule && minutes > i64::from(cfg.max_minutes) {
        let reason = format!(
            "a downtime of {minutes} minutes is longer than this host allows \
             (monitoring.max_minutes is {})",
            cfg.max_minutes
        );
        return Err(ctx.deny(None, &reason));
    }
    // The tool only ever acts on this host's own entry, so there is no resource to name.
    let auth = ctx.authorize(None)?;
    let clock = CallClock::start(&ctx);

    let (host, port) = parse_https_origin(url, ICINGA_PORT)
        .map_err(|problem| ToolError::Failed(format!("monitoring.icinga_url: {problem}")))?;
    let (Some(user), Some(password_file)) =
        (cfg.icinga_user.clone(), cfg.icinga_password_file.clone())
    else {
        return Err(ToolError::Failed(
            "monitoring.icinga_user and monitoring.icinga_password_file must both be set"
                .to_string(),
        ));
    };
    let ca_file = cfg.icinga_ca.clone();
    let configured_host = cfg.host.clone();
    let endpoint = Endpoint {
        host,
        port,
        custom_ca: ca_file.is_some(),
    };
    let surroundings = env.clone();
    let prepared = blocking(ctx.clone(), move || {
        let host_name = host_name(configured_host.as_deref(), &surroundings.hostname_file)
            .map_err(ToolError::Failed)?;
        let password = read_password(&password_file).map_err(ToolError::Failed)?;
        let basic = format!(
            "Basic {}",
            b64_encode(format!("{user}:{password}").as_bytes(), true)
        );
        let mut authorization = HeaderValue::from_str(&basic)
            .map_err(|_| ToolError::Failed("cannot build the Icinga login".to_string()))?;
        authorization.set_sensitive(true);
        let roots =
            load_trust(ca_file.as_deref(), &surroundings.bundles).map_err(ToolError::Failed)?;
        Ok(Prepared {
            host_name,
            authorization,
            roots,
        })
    })
    .await?;
    let host_name = prepared.host_name;

    let author = author_of(&ctx.principal().name);
    let (roots, authorization) = (prepared.roots, prepared.authorization);
    // One request to Icinga, within what is left of this call.
    let send = |ask: Ask| {
        let total_limit = clock
            .next()
            .map_or(Duration::from_secs(1), |left| left.min(env.total_limit));
        exchange(
            &endpoint,
            roots.clone(),
            authorization.clone(),
            ask,
            env.connect_limit,
            total_limit,
        )
    };

    // AIDEV-NOTE: nothing else bounds how many downtimes can be piled onto the host
    // (each `schedule` makes one for the host and one per service), so a caller in a
    // loop could fill Icinga with them. Before one is set, the ones opsmcp has already
    // set for the host itself are counted, and at `MAX_OWN_DOWNTIMES` no more is set.
    // If they cannot be counted (the ApiUser may not query downtimes, or Icinga does not
    // answer the question), the downtime is set all the same and the result says that
    // the limit was not applied: planned work must not page people because of a count.
    let mut uncounted = None;
    if action == Action::Schedule {
        let ask = Ask {
            path: Action::Status.path(),
            as_get: true,
            body: count_request(&host_name),
        };
        match send(ask).await {
            // Icinga could not even be reached: the downtime could not be sent either.
            Err(trouble) if !trouble.sent => {
                return auth.failed(format!("{}. Nothing was sent.\n", trouble.message));
            }
            Err(trouble) => uncounted = Some(trouble.message),
            Ok(reply) => match count_of(&reply, &host_name) {
                Ok(count) if count >= MAX_OWN_DOWNTIMES => {
                    let found = if count == usize::MAX {
                        "more downtimes than could be counted".to_string()
                    } else {
                        format!("{count} downtimes")
                    };
                    return auth.failed(format!(
                        "Nothing was set: {found} set through opsmcp already exist for \
                         {host_name} in Icinga, and the limit is {MAX_OWN_DOWNTIMES}. Remove \
                         some first: action=cancel removes them all, action=status lists \
                         them.\n"
                    ));
                }
                Ok(_) => {}
                Err(why) => uncounted = Some(why),
            },
        }
    }
    let uncounted = uncounted.map(|why| {
        format!(
            "[how many downtimes opsmcp has already set for this host could not be checked \
             ({}), so the limit of {MAX_OWN_DOWNTIMES} was not applied]\n",
            why.trim_end_matches(['.', '\n'])
        )
    });

    let start = now_secs();
    let end = start + minutes * 60;
    let ask = Ask {
        path: action.path(),
        as_get: action == Action::Status,
        body: match action {
            Action::Schedule => schedule_request(&host_name, &author, &comment, start, end),
            Action::Cancel => cancel_request(&host_name),
            Action::Status => status_request(&host_name),
        },
    };
    let reply = match send(ask).await {
        Ok(reply) => reply,
        Err(trouble) => {
            let mut text = trouble.message;
            text.push_str(match (trouble.sent, action) {
                (false, _) => ". Nothing was sent.\n",
                (true, Action::Schedule) => {
                    ". Whether the downtime was set is not known: check with action=status.\n"
                }
                (true, Action::Cancel) => {
                    ". Whether downtimes were removed is not known: check with action=status.\n"
                }
                (true, Action::Status) => ".\n",
            });
            text.push_str(uncounted.as_deref().unwrap_or(""));
            return auth.failed(text);
        }
    };

    let (text, success) = match action {
        Action::Schedule => schedule_outcome(&reply, &host_name, &author, &comment, end, minutes),
        Action::Cancel => cancel_outcome(&reply, &host_name),
        Action::Status => status_outcome(&reply, &host_name, now_secs(), ctx.output_budget()),
    };
    let text = format!("{text}{}", uncounted.as_deref().unwrap_or(""));
    auth.done(text, success)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::timefmt::{now_secs, rfc3339_utc};
    use crate::tools::testing::{call, find, host, ok_text};
    use crate::tools::users::b64_encode;
    use crate::tools::{Host, ToolError, ToolResult};
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, DnType, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };
    use rustls::pki_types::PrivateKeyDer;
    use serde_json::{Value, json};
    use std::collections::VecDeque;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const PASSWORD: &str = "s3cret-pw-for-tests";

    // ---- a stand-in for the Icinga 2 API ----

    struct Authority {
        params: CertificateParams,
        key: KeyPair,
        cert: Certificate,
    }

    fn authority(name: &str) -> Authority {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.distinguished_name.push(DnType::CommonName, name);
        let cert = params.self_signed(&key).unwrap();
        Authority { params, key, cert }
    }

    fn issue(ca: &Authority, names: &[&str]) -> (Certificate, KeyPair) {
        let key = KeyPair::generate().unwrap();
        let mut params =
            CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "test icinga");
        let cert = params
            .signed_by(&key, &Issuer::from_params(&ca.params, &ca.key))
            .unwrap();
        (cert, key)
    }

    /// One request as the stand-in received it.
    #[derive(Clone, Debug)]
    struct Seen {
        line: String,
        /// Header names in lower case.
        headers: Vec<(String, String)>,
        body: String,
    }

    impl Seen {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_str())
        }

        fn json(&self) -> Value {
            serde_json::from_str(&self.body).unwrap()
        }
    }

    #[derive(Clone)]
    struct Canned {
        status: u16,
        headers: Vec<(&'static str, String)>,
        body: String,
    }

    /// How the stand-in answers the question schedule asks first: how many downtimes
    /// opsmcp has already set for the host.
    #[derive(Clone)]
    enum Counting {
        /// So many (0 unless a test says otherwise).
        Count(usize),
        /// This answer instead.
        Reply(Canned),
        /// Nothing, until the client gives up.
        Silent,
    }

    fn canned(status: u16, body: Value) -> Canned {
        Canned {
            status,
            headers: Vec::new(),
            body: body.to_string(),
        }
    }

    struct Icinga {
        dir: tempfile::TempDir,
        port: u16,
        seen: Arc<Mutex<Vec<Seen>>>,
        replies: Arc<Mutex<VecDeque<Canned>>>,
        connections: Arc<AtomicUsize>,
        /// The count queries received. They are kept apart from `seen` and answered
        /// from `counting`, not from `replies`.
        counts: Arc<Mutex<Vec<Seen>>>,
        counting: Arc<Mutex<Counting>>,
    }

    impl Icinga {
        /// The requests received, without the count queries.
        fn seen(&self) -> Vec<Seen> {
            self.seen.lock().unwrap().clone()
        }

        fn counts(&self) -> Vec<Seen> {
            self.counts.lock().unwrap().clone()
        }

        fn count_as(&self, counting: Counting) {
            *self.counting.lock().unwrap() = counting;
        }

        fn reply(&self, status: u16, body: Value) {
            self.replies.lock().unwrap().push_back(canned(status, body));
        }

        fn password_file(&self) -> PathBuf {
            self.dir.path().join("password")
        }

        fn ca_file(&self) -> PathBuf {
            self.dir.path().join("ca.pem")
        }

        /// The `[monitoring]` section that points at this stand-in.
        fn monitoring(&self, more: &str) -> String {
            format!(
                "[monitoring]\nicinga_url = \"https://localhost:{}\"\nicinga_user = \"opsmcp\"\n\
                 icinga_password_file = \"{}\"\nicinga_ca = \"{}\"\n{more}\n",
                self.port,
                self.password_file().display(),
                self.ca_file().display()
            )
        }
    }

    async fn read_request<S: AsyncReadExt + Unpin>(stream: &mut S) -> Option<Seen> {
        let mut buffer = Vec::new();
        let head_end = loop {
            if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                break at;
            }
            let mut chunk = [0u8; 4096];
            let count = stream.read(&mut chunk).await.ok()?;
            if count == 0 {
                return None;
            }
            buffer.extend_from_slice(&chunk[..count]);
        };
        let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
        let mut lines = head.split("\r\n");
        let line = lines.next()?.to_string();
        let headers: Vec<(String, String)> = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(key, value)| (key.trim().to_ascii_lowercase(), value.trim().to_string()))
            .collect();
        let length: usize = headers
            .iter()
            .find(|(key, _)| key == "content-length")
            .and_then(|(_, value)| value.parse().ok())
            .unwrap_or(0);
        let mut body = buffer[head_end + 4..].to_vec();
        while body.len() < length {
            let mut chunk = [0u8; 4096];
            let count = stream.read(&mut chunk).await.ok()?;
            if count == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..count]);
        }
        Some(Seen {
            line,
            headers,
            body: String::from_utf8_lossy(&body).into_owned(),
        })
    }

    /// Starts the stand-in. Its certificate is for `names`; the CA file handed to the
    /// tool is the issuing CA's, or another CA's when `trusted` is false. With no
    /// reply queued it reads the request and then says nothing.
    async fn icinga_with(names: &[&str], trusted: bool) -> Icinga {
        let dir = tempfile::tempdir().unwrap();
        let ca = authority("opsmcp test ca");
        let shown_ca = if trusted {
            ca.cert.pem()
        } else {
            authority("some other ca").cert.pem()
        };
        std::fs::write(dir.path().join("ca.pem"), shown_ca).unwrap();
        let password = dir.path().join("password");
        std::fs::write(&password, format!("{PASSWORD}\n")).unwrap();
        std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o600)).unwrap();

        let (leaf, key) = issue(&ca, names);
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let key = PrivateKeyDer::try_from(key.serialize_der()).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![leaf.der().clone()], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let replies: Arc<Mutex<VecDeque<Canned>>> = Arc::new(Mutex::new(VecDeque::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let counts = Arc::new(Mutex::new(Vec::new()));
        let counting = Arc::new(Mutex::new(Counting::Count(0)));
        let (counts_of_server, counting_of_server) = (counts.clone(), counting.clone());
        let (seen_by_server, replies_of_server, count) =
            (seen.clone(), replies.clone(), connections.clone());
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                let seen = seen_by_server.clone();
                let replies = replies_of_server.clone();
                let counts = counts_of_server.clone();
                let counting = counting_of_server.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let Some(request) = read_request(&mut tls).await else {
                        return;
                    };
                    // the question schedule asks first: only the host's own downtimes
                    let is_count = request.line.starts_with("POST /v1/objects/downtimes ")
                        && serde_json::from_str::<Value>(&request.body)
                            .ok()
                            .and_then(|body| {
                                let filter = body.get("filter")?.as_str()?;
                                Some(filter.contains("downtime.service_name==\"\""))
                            })
                            .unwrap_or(false);
                    let reply = if is_count {
                        counts.lock().unwrap().push(request);
                        let counting = counting.lock().unwrap().clone();
                        match counting {
                            Counting::Count(count) => {
                                let results: Vec<Value> = (0..count)
                                    .map(|n| {
                                        json!({"attrs": {"author": "opsmcp:olga"},
                                               "name": format!("web1.example.com!{n}"),
                                               "type": "Downtime"})
                                    })
                                    .collect();
                                Some(canned(200, json!({"results": results})))
                            }
                            Counting::Reply(reply) => Some(reply),
                            Counting::Silent => None,
                        }
                    } else {
                        seen.lock().unwrap().push(request);
                        replies.lock().unwrap().pop_front()
                    };
                    match reply {
                        Some(reply) => {
                            let mut head = format!(
                                "HTTP/1.1 {} Whatever\r\nContent-Type: application/json\r\n\
                                 Content-Length: {}\r\nConnection: close\r\n",
                                reply.status,
                                reply.body.len()
                            );
                            for (name, value) in &reply.headers {
                                head.push_str(&format!("{name}: {value}\r\n"));
                            }
                            head.push_str("\r\n");
                            let _ = tls.write_all(head.as_bytes()).await;
                            let _ = tls.write_all(reply.body.as_bytes()).await;
                            let _ = tls.shutdown().await;
                        }
                        None => {
                            // say nothing until the client gives up
                            let mut rest = [0u8; 16];
                            let _ = tls.read(&mut rest).await;
                        }
                    }
                });
            }
        });
        Icinga {
            dir,
            port,
            seen,
            replies,
            connections,
            counts,
            counting,
        }
    }

    async fn icinga() -> Icinga {
        icinga_with(&["localhost"], true).await
    }

    const ROLES: &str = r#"
[roles.reader]
allow = ["@read"]
[roles.oncall]
allow = ["monitoring.downtime"]
[unix_users.rita]
roles = ["reader"]
[unix_users.olga]
roles = ["oncall"]
"#;

    fn fixture(monitoring: &str) -> (Arc<Host>, MemorySink) {
        host(&format!("{ROLES}{monitoring}"))
    }

    /// A host whose monitoring settings point at `icinga`, as host web1.example.com.
    fn site(icinga: &Icinga) -> (Arc<Host>, MemorySink) {
        fixture(&icinga.monitoring("host = \"web1.example.com\"\nmax_minutes = 120"))
    }

    fn env() -> Env {
        Env {
            hostname_file: PathBuf::from("/nonexistent/hostname"),
            bundles: Vec::new(),
            connect_limit: Duration::from_secs(10),
            total_limit: Duration::from_secs(10),
        }
    }

    async fn run_with(host: &Arc<Host>, user: &str, env: Env, arguments: Value) -> ToolResult {
        let tool = find(tools_with(env), "monitoring_downtime");
        call(host, user, &tool, arguments).await
    }

    async fn run(host: &Arc<Host>, user: &str, arguments: Value) -> ToolResult {
        run_with(host, user, env(), arguments).await
    }

    fn failed_text(result: ToolResult) -> String {
        match result {
            Ok(output) if output.is_error() => output.into_parts().0,
            Err(ToolError::Failed(message)) => message,
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    /// What Icinga 2.11 and later answer when a host and its services are put in downtime.
    fn scheduled(services: usize) -> Value {
        let service_downtimes: Vec<Value> = (0..services)
            .map(|n| json!({"legacy_id": n + 2, "name": format!("web1.example.com!svc{n}!abc")}))
            .collect();
        json!({"results": [{
            "code": 200.0,
            "legacy_id": 1.0,
            "name": "web1.example.com!6a3b",
            "status": "Successfully scheduled downtime 'web1.example.com!6a3b' for object 'web1.example.com'.",
            "service_downtimes": service_downtimes,
        }]})
    }

    // ---- the requests ----

    #[test]
    fn the_schedule_request_names_the_host_through_a_variable() {
        let body = schedule_request(
            "web1.example.com",
            "opsmcp:olga",
            "kernel upgrade",
            1_700_000_000,
            1_700_003_600,
        );
        assert_eq!(
            body,
            json!({
                "type": "Host",
                "filter": "host.name==host_name",
                "filter_vars": {"host_name": "web1.example.com"},
                "all_services": true,
                "author": "opsmcp:olga",
                "comment": "kernel upgrade",
                "start_time": 1_700_000_000,
                "end_time": 1_700_003_600,
                "fixed": true,
            })
        );
    }

    #[test]
    fn the_cancel_request_only_matches_downtimes_that_opsmcp_set_for_this_host() {
        assert_eq!(
            cancel_request("web1.example.com"),
            json!({
                "type": "Downtime",
                "filter": "downtime.host_name==host_name && match(\"opsmcp:*\", downtime.author)",
                "filter_vars": {"host_name": "web1.example.com"},
            })
        );
    }

    #[test]
    fn the_status_request_asks_for_this_hosts_downtimes() {
        assert_eq!(
            status_request("web1.example.com"),
            json!({
                "filter": "downtime.host_name==host_name",
                "filter_vars": {"host_name": "web1.example.com"},
                "attrs": ["author", "comment", "start_time", "end_time", "service_name"],
            })
        );
    }

    #[test]
    fn a_value_never_becomes_part_of_the_filter_text() {
        // whatever the host is called or the caller says, the filter text is constant
        let hostile = "x\" || true || \"";
        for body in [
            schedule_request(hostile, hostile, hostile, 1, 2),
            cancel_request(hostile),
            status_request(hostile),
        ] {
            let filter = body["filter"].as_str().unwrap();
            assert!(!filter.contains("true"), "{filter}");
            assert_eq!(body["filter_vars"]["host_name"], hostile);
        }
    }

    #[test]
    fn a_comment_is_short_printable_text() {
        for good in ["kernel upgrade", "RG-1234: reboot for säkerhet", "x"] {
            assert!(check_comment(good).is_ok(), "{good}");
        }
        let long = "x".repeat(201);
        for bad in [
            "",
            "   ",
            "line one\nline two",
            "tab\there",
            "bell\u{7}",
            long.as_str(),
        ] {
            assert!(
                matches!(check_comment(bad), Err(ToolError::Invalid(_))),
                "{bad:?}"
            );
        }
        assert!(check_comment(&"x".repeat(200)).is_ok());
    }

    #[test]
    fn the_author_says_it_was_opsmcp_and_for_whom() {
        assert_eq!(author_of("olga"), "opsmcp:olga");
        assert_eq!(author_of("token:ci"), "opsmcp:token:ci");
        // nothing odd reaches the monitoring system's pages
        assert_eq!(author_of("a b\n<c>"), "opsmcp:a_b__c_");
        assert!(author_of(&"x".repeat(500)).len() <= 107);
    }

    // ---- schedule ----

    #[tokio::test]
    async fn schedule_posts_the_downtime_for_this_host_and_its_services() {
        let icinga = icinga().await;
        icinga.reply(200, scheduled(14));
        let (host, audit) = site(&icinga);
        let before = now_secs();
        let arguments = json!({"action": "schedule", "minutes": 45, "comment": "kernel upgrade"});
        let text = ok_text(run(&host, "olga", arguments).await);
        let after = now_secs();

        let seen = icinga.seen();
        assert_eq!(seen.len(), 1);
        let request = &seen[0];
        assert_eq!(request.line, "POST /v1/actions/schedule-downtime HTTP/1.1");
        assert_eq!(request.header("accept"), Some("application/json"));
        assert_eq!(request.header("content-type"), Some("application/json"));
        assert_eq!(request.header("connection"), Some("close"));
        assert_eq!(
            request.header("host"),
            Some(format!("localhost:{}", icinga.port).as_str())
        );
        let basic = format!(
            "Basic {}",
            b64_encode(format!("opsmcp:{PASSWORD}").as_bytes(), true)
        );
        assert_eq!(request.header("authorization"), Some(basic.as_str()));
        assert_eq!(request.header("x-http-method-override"), None);

        let body = request.json();
        let start = body["start_time"].as_i64().unwrap();
        let end = body["end_time"].as_i64().unwrap();
        assert!((before..=after).contains(&start), "{start}");
        assert_eq!(end - start, 45 * 60);
        assert_eq!(
            body,
            schedule_request(
                "web1.example.com",
                "opsmcp:olga",
                "kernel upgrade",
                start,
                end
            )
        );

        // the answer says what is in downtime, until when, and how to undo it
        assert!(text.contains("web1.example.com"), "{text}");
        assert!(text.contains("14"), "{text}");
        assert!(text.contains(&rfc3339_utc(end)), "{text}");
        assert!(text.contains("cancel"), "{text}");
        let records = audit.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["decision"], "allow");
        assert!(records[0].get("resource").is_none());
    }

    #[test]
    fn the_count_request_asks_only_for_what_opsmcp_set_on_the_host_itself() {
        assert_eq!(
            count_request("web1.example.com"),
            json!({
                "filter": "downtime.host_name==host_name && downtime.service_name==\"\" \
                           && match(\"opsmcp:*\", downtime.author)",
                "filter_vars": {"host_name": "web1.example.com"},
                "attrs": ["author"],
            })
        );
    }

    /// AIDEV-NOTE: nothing else bounds how many downtimes can be piled onto the host
    /// (each one is the host's own plus one per service). A caller in a loop would
    /// otherwise fill Icinga with them.
    #[tokio::test]
    async fn schedule_first_asks_how_many_downtimes_opsmcp_has_already_set() {
        let icinga = icinga().await;
        icinga.reply(200, scheduled(2));
        icinga.count_as(Counting::Count(9));
        let (host, _audit) = site(&icinga);
        let text = ok_text(run(&host, "olga", json!({"action": "schedule"})).await);
        assert!(text.starts_with("Downtime set in Icinga"), "{text}");

        let counts = icinga.counts();
        assert_eq!(counts.len(), 1);
        let asked = &counts[0];
        assert_eq!(asked.line, "POST /v1/objects/downtimes HTTP/1.1");
        assert_eq!(asked.header("x-http-method-override"), Some("GET"));
        let basic = format!(
            "Basic {}",
            b64_encode(format!("opsmcp:{PASSWORD}").as_bytes(), true)
        );
        assert_eq!(asked.header("authorization"), Some(basic.as_str()));
        assert_eq!(asked.json(), count_request("web1.example.com"));
        // and then the downtime itself, once
        assert_eq!(icinga.seen().len(), 1);
        // cancel and status ask no such thing
        icinga.reply(200, json!({"results": []}));
        ok_text(run(&host, "olga", json!({"action": "status"})).await);
        icinga.reply(404, json!({"error": 404, "status": "No objects found."}));
        ok_text(run(&host, "olga", json!({"action": "cancel"})).await);
        assert_eq!(icinga.counts().len(), 1);
    }

    #[tokio::test]
    async fn an_eleventh_downtime_is_refused_until_some_are_cancelled() {
        let icinga = icinga().await;
        icinga.count_as(Counting::Count(10));
        let (host, _audit) = site(&icinga);
        let text = failed_text(run(&host, "olga", json!({"action": "schedule"})).await);
        assert!(text.starts_with("Nothing was set"), "{text}");
        assert!(text.contains("10"), "{text}");
        assert!(text.contains("action=cancel"), "{text}");
        // the downtime was never asked for
        assert!(icinga.seen().is_empty());
        assert_eq!(icinga.counts().len(), 1);

        // an answer too long to read can only mean a great many
        let many: Vec<Value> = (0..40_000)
            .map(|n| json!({"attrs": {"author": "opsmcp:olga"}, "name": format!("web1.example.com!{n:040}")}))
            .collect();
        icinga.count_as(Counting::Reply(canned(200, json!({"results": many}))));
        let text = failed_text(run(&host, "olga", json!({"action": "schedule"})).await);
        assert!(text.starts_with("Nothing was set"), "{text}");
        assert!(icinga.seen().is_empty());
    }

    #[tokio::test]
    async fn a_count_that_cannot_be_made_does_not_stop_the_downtime() {
        // the API user may not query downtimes
        let icinga = icinga().await;
        icinga.count_as(Counting::Reply(canned(
            403,
            json!({"error": 403, "status": "Forbidden"}),
        )));
        icinga.reply(200, scheduled(2));
        let (host, _audit) = site(&icinga);
        let text = ok_text(run(&host, "olga", json!({"action": "schedule"})).await);
        assert!(text.starts_with("Downtime set in Icinga"), "{text}");
        assert!(
            text.contains(
                "[how many downtimes opsmcp has already set for this host could not be checked"
            ),
            "{text}"
        );
        assert!(text.contains("objects/query/Downtime"), "{text}");
        assert_eq!(icinga.seen().len(), 1);

        // nor does an Icinga that does not answer the question in time
        icinga.count_as(Counting::Silent);
        icinga.reply(200, scheduled(2));
        let quick = Env {
            total_limit: Duration::from_millis(700),
            ..env()
        };
        let text = ok_text(run_with(&host, "olga", quick, json!({"action": "schedule"})).await);
        assert!(text.starts_with("Downtime set in Icinga"), "{text}");
        assert!(text.contains("could not be checked"), "{text}");
        assert_eq!(icinga.seen().len(), 2);
    }

    // ---- connecting ----

    /// A local port that nothing listens on.
    async fn closed_port() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    }

    /// AIDEV-NOTE: a name can have several addresses, and one of them not answering
    /// (an IPv6 address on a host without IPv6 routing) must not use up the whole time
    /// allowed for connecting.
    #[tokio::test]
    async fn an_address_that_does_not_answer_leaves_time_for_the_next() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good = listener.local_addr().unwrap();
        // 192.0.2.0/24 is reserved for documentation and routed nowhere
        let dead: std::net::SocketAddr = "192.0.2.1:5665".parse().unwrap();
        let began = Instant::now();
        let stream = connect_any(&[dead, good], Duration::from_secs(4))
            .await
            .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), good);
        assert!(
            began.elapsed() < Duration::from_secs(3),
            "{:?}",
            began.elapsed()
        );
    }

    #[tokio::test]
    async fn connecting_tries_the_addresses_in_turn_and_at_most_four() {
        let refusing = closed_port().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good = listener.local_addr().unwrap();
        // the first refuses, the second answers
        let stream = connect_any(&[refusing, good], Duration::from_secs(4))
            .await
            .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), good);
        // none answers: the failure says how many were tried and why the last failed
        let problem = connect_any(&[refusing, refusing], Duration::from_secs(4))
            .await
            .unwrap_err();
        assert!(problem.contains("2 addresses"), "{problem}");
        assert!(problem.to_lowercase().contains("refused"), "{problem}");
        // a fifth address is not tried
        let problem = connect_any(
            &[refusing, refusing, refusing, refusing, good],
            Duration::from_secs(4),
        )
        .await
        .unwrap_err();
        assert!(problem.contains("4 addresses"), "{problem}");
        // no address at all
        let problem = connect_any(&[], Duration::from_secs(4)).await.unwrap_err();
        assert!(problem.contains("no address"), "{problem}");
    }

    #[tokio::test]
    async fn schedule_has_defaults_for_the_length_and_the_comment() {
        let icinga = icinga().await;
        icinga.reply(200, scheduled(0));
        let (host, _audit) = site(&icinga);
        ok_text(run(&host, "olga", json!({"action": "schedule"})).await);
        let body = icinga.seen()[0].json();
        assert_eq!(
            body["end_time"].as_i64().unwrap() - body["start_time"].as_i64().unwrap(),
            3600
        );
        assert_eq!(body["comment"], "Maintenance through opsmcp");
    }

    #[tokio::test]
    async fn an_older_icinga_that_says_nothing_about_services_gets_a_note() {
        let icinga = icinga().await;
        icinga.reply(
            200,
            json!({"results": [{"code": 200.0, "name": "web1.example.com!6a3b",
                "status": "Successfully scheduled downtime."}]}),
        );
        let (host, _audit) = site(&icinga);
        let text = ok_text(run(&host, "olga", json!({"action": "schedule"})).await);
        assert!(text.contains("2.11"), "{text}");
    }

    #[tokio::test]
    async fn the_password_is_never_shown_or_recorded() {
        let icinga = icinga().await;
        icinga.reply(200, scheduled(3));
        // an answer that fails, too: errors must not carry it either
        icinga.reply(500, json!({"error": 500, "status": "boom"}));
        let (host, audit) = site(&icinga);
        let first = ok_text(run(&host, "olga", json!({"action": "schedule"})).await);
        let second = failed_text(run(&host, "olga", json!({"action": "schedule"})).await);
        let encoded = b64_encode(format!("opsmcp:{PASSWORD}").as_bytes(), true);
        for text in [first, second, format!("{:?}", audit.records())] {
            assert!(!text.contains(PASSWORD), "{text}");
            assert!(!text.contains(&encoded), "{text}");
        }
    }

    #[tokio::test]
    async fn a_downtime_longer_than_the_host_allows_is_refused() {
        let icinga = icinga().await;
        let (host, audit) = site(&icinga);
        let result = run(&host, "olga", json!({"action": "schedule", "minutes": 121})).await;
        match result {
            Err(ToolError::Denied(message)) => {
                assert!(message.contains("monitoring.max_minutes"), "{message}")
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert_eq!(icinga.connections.load(Ordering::SeqCst), 0);
        let records = audit.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["decision"], "deny");
        // the limit itself is allowed
        icinga.reply(200, scheduled(0));
        ok_text(run(&host, "olga", json!({"action": "schedule", "minutes": 120})).await);
    }

    #[tokio::test]
    async fn the_tool_is_off_until_monitoring_is_configured() {
        let (host, audit) = fixture("");
        for action in ACTIONS {
            match run(&host, "olga", json!({"action": action})).await {
                Err(ToolError::Denied(message)) => {
                    assert!(message.contains("monitoring.icinga_url"), "{message}")
                }
                other => panic!("expected a refusal, got {other:?}"),
            }
        }
        assert!(audit.records().iter().all(|r| r["decision"] == "deny"));
    }

    #[tokio::test]
    async fn read_access_does_not_include_downtimes() {
        let icinga = icinga().await;
        let (host, _audit) = site(&icinga);
        for action in ACTIONS {
            assert!(matches!(
                run(&host, "rita", json!({"action": action})).await,
                Err(ToolError::Denied(_))
            ));
        }
        assert_eq!(icinga.connections.load(Ordering::SeqCst), 0);
        let tool = find(tools(), "monitoring_downtime");
        assert_eq!(tool.access, Access::Write);
        assert_eq!(tool.permission, "monitoring.downtime");
    }

    #[tokio::test]
    async fn a_bad_comment_is_refused_before_anything_else() {
        let icinga = icinga().await;
        let (host, audit) = site(&icinga);
        for comment in ["one\ntwo".to_string(), "x".repeat(201), "   ".to_string()] {
            let arguments = json!({"action": "schedule", "comment": comment});
            assert!(matches!(
                run(&host, "olga", arguments).await,
                Err(ToolError::Invalid(_))
            ));
        }
        assert_eq!(icinga.connections.load(Ordering::SeqCst), 0);
        assert!(audit.records().is_empty());
    }

    // ---- what Icinga may answer ----

    #[tokio::test]
    async fn icingas_refusals_are_explained() {
        let icinga = icinga().await;
        let (host, _audit) = site(&icinga);
        let schedule = json!({"action": "schedule"});

        icinga.reply(
            401,
            json!({"error": 401, "status": "Unauthorized. Please check your user credentials."}),
        );
        let text = failed_text(run(&host, "olga", schedule.clone()).await);
        assert!(text.contains("401"), "{text}");
        assert!(text.contains("monitoring.icinga_user"), "{text}");

        icinga.reply(403, json!({"error": 403, "status": "Forbidden."}));
        let text = failed_text(run(&host, "olga", schedule.clone()).await);
        assert!(text.contains("actions/schedule-downtime"), "{text}");

        icinga.reply(404, json!({"error": 404, "status": "No objects found."}));
        let text = failed_text(run(&host, "olga", schedule.clone()).await);
        assert!(text.contains("web1.example.com"), "{text}");
        assert!(text.contains("monitoring.host"), "{text}");

        icinga.reply(200, json!({"results": []}));
        let text = failed_text(run(&host, "olga", schedule.clone()).await);
        assert!(text.contains("monitoring.host"), "{text}");

        icinga.reply(503, json!({"error": 503, "status": "Icinga is reloading."}));
        let text = failed_text(run(&host, "olga", schedule).await);
        assert!(text.contains("503"), "{text}");
        assert!(text.contains("Icinga is reloading."), "{text}");

        icinga.reply(403, json!({"error": 403, "status": "Forbidden."}));
        let text = failed_text(run(&host, "olga", json!({"action": "status"})).await);
        assert!(text.contains("objects/query/Downtime"), "{text}");
    }

    #[tokio::test]
    async fn an_object_that_icinga_could_not_change_makes_the_result_a_failure() {
        let icinga = icinga().await;
        icinga.reply(
            500,
            json!({"results": [
                {"code": 500.0, "status": "Action execution failed: 'Error: boom'."}
            ]}),
        );
        let (host, _audit) = site(&icinga);
        let text = failed_text(run(&host, "olga", json!({"action": "schedule"})).await);
        assert!(text.contains("Action execution failed"), "{text}");
    }

    #[tokio::test]
    async fn an_answer_that_is_not_json_is_reported_without_being_echoed_at_length() {
        let icinga = icinga().await;
        icinga.replies.lock().unwrap().push_back(Canned {
            status: 200,
            headers: Vec::new(),
            body: format!("<html>{}</html>", "x".repeat(5000)),
        });
        let (host, _audit) = site(&icinga);
        let text = failed_text(run(&host, "olga", json!({"action": "schedule"})).await);
        assert!(
            text.contains("not JSON") || text.contains("could not be read"),
            "{text}"
        );
        assert!(text.len() < 1000, "{} bytes", text.len());
    }

    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        let icinga = icinga().await;
        icinga.replies.lock().unwrap().push_back(Canned {
            status: 302,
            headers: vec![(
                "Location",
                format!("https://localhost:{}/elsewhere", icinga.port),
            )],
            body: String::new(),
        });
        let (host, _audit) = site(&icinga);
        let text = failed_text(run(&host, "olga", json!({"action": "schedule"})).await);
        assert!(text.contains("302"), "{text}");
        assert_eq!(icinga.seen().len(), 1);
    }

    #[tokio::test]
    async fn an_answer_larger_than_the_limit_is_cut_off() {
        let icinga = icinga().await;
        icinga.replies.lock().unwrap().push_back(Canned {
            status: 200,
            headers: Vec::new(),
            body: format!("{{\"results\": [\"{}\"]}}", "x".repeat(2 * MAX_BODY)),
        });
        let (host, _audit) = site(&icinga);
        let text = failed_text(run(&host, "olga", json!({"action": "status"})).await);
        assert!(text.contains("larger than"), "{text}");
        assert!(text.len() < 1000, "{} bytes", text.len());
    }

    // ---- cancel ----

    #[tokio::test]
    async fn cancel_removes_what_opsmcp_set_and_says_how_many() {
        let icinga = icinga().await;
        icinga.reply(
            200,
            json!({"results": [
                {"code": 200.0, "status": "Successfully removed downtime 'web1.example.com!6a3b'."},
                {"code": 200.0, "status": "Successfully removed downtime 'web1.example.com!ping4!77aa'."},
            ]}),
        );
        let (host, _audit) = site(&icinga);
        let text = ok_text(run(&host, "olga", json!({"action": "cancel"})).await);
        let seen = icinga.seen();
        assert_eq!(seen[0].line, "POST /v1/actions/remove-downtime HTTP/1.1");
        assert_eq!(seen[0].json(), cancel_request("web1.example.com"));
        assert!(text.contains("2 downtimes"), "{text}");
        assert!(text.contains("web1.example.com"), "{text}");
    }

    #[tokio::test]
    async fn cancel_with_nothing_to_remove_is_not_a_failure() {
        let icinga = icinga().await;
        icinga.reply(404, json!({"error": 404, "status": "No objects found."}));
        let (host, _audit) = site(&icinga);
        let text = ok_text(run(&host, "olga", json!({"action": "cancel"})).await);
        assert!(text.contains("nothing was removed"), "{text}");
    }

    #[tokio::test]
    async fn cancel_is_not_held_to_the_limit_on_minutes() {
        let icinga = icinga().await;
        icinga.reply(404, json!({"error": 404, "status": "No objects found."}));
        let (host, _audit) = site(&icinga);
        let arguments = json!({"action": "cancel", "minutes": 5000});
        ok_text(run(&host, "olga", arguments).await);
    }

    // ---- status ----

    #[tokio::test]
    async fn status_lists_the_downtimes_with_services_grouped() {
        let icinga = icinga().await;
        let now = now_secs();
        let downtime = |service: &str, author: &str, comment: &str, from: i64, until: i64| {
            json!({"type": "Downtime", "name": "x", "attrs": {
                "author": author, "comment": comment, "service_name": service,
                "start_time": from as f64, "end_time": until as f64,
            }})
        };
        icinga.reply(
            200,
            json!({"results": [
                downtime("", "opsmcp:olga", "kernel upgrade", now - 60, now + 3000),
                downtime("ping4", "opsmcp:olga", "kernel upgrade", now - 60, now + 3000),
                downtime("ssh", "opsmcp:olga", "kernel upgrade", now - 60, now + 3000),
                downtime("disk", "alice", "replacing a disk\nPROBLEM: forged line", now + 7200, now + 9000),
            ]}),
        );
        let (host, _audit) = site(&icinga);
        let text = ok_text(run(&host, "olga", json!({"action": "status"})).await);

        let seen = icinga.seen();
        assert_eq!(seen[0].line, "POST /v1/objects/downtimes HTTP/1.1");
        assert_eq!(seen[0].header("x-http-method-override"), Some("GET"));
        assert_eq!(seen[0].json(), status_request("web1.example.com"));

        assert!(
            text.lines().next().unwrap().contains("web1.example.com"),
            "{text}"
        );
        let mine = text.lines().find(|l| l.contains("opsmcp:olga")).unwrap();
        assert!(mine.contains("host and 2 services"), "{text}");
        assert!(mine.contains("kernel upgrade"), "{text}");
        assert!(mine.contains(&rfc3339_utc(now + 3000)), "{text}");
        assert!(mine.contains("in effect"), "{text}");
        let other = text.lines().find(|l| l.contains("alice")).unwrap();
        assert!(other.contains("service disk"), "{text}");
        assert!(other.contains("not yet"), "{text}");
        // what someone typed into Icinga cannot add a line of its own
        assert!(!text.lines().any(|l| l.starts_with("PROBLEM")), "{text}");
    }

    #[tokio::test]
    async fn status_with_no_downtime_says_so() {
        let icinga = icinga().await;
        icinga.reply(200, json!({"results": []}));
        let (host, _audit) = site(&icinga);
        let text = ok_text(run(&host, "olga", json!({"action": "status"})).await);
        assert!(text.contains("No downtime"), "{text}");
        assert!(text.contains("web1.example.com"), "{text}");
    }

    // ---- the connection ----

    #[tokio::test]
    async fn a_certificate_from_an_unknown_authority_is_refused_before_anything_is_sent() {
        let icinga = icinga_with(&["localhost"], false).await;
        icinga.reply(200, scheduled(0));
        let (host, _audit) = site(&icinga);
        let text = failed_text(run(&host, "olga", json!({"action": "schedule"})).await);
        assert!(text.contains("certificate"), "{text}");
        // neither the request nor the password left this host
        assert!(icinga.seen().is_empty());
        assert_eq!(icinga.connections.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_certificate_for_another_name_is_refused_before_anything_is_sent() {
        let icinga = icinga_with(&["other.example.com"], true).await;
        icinga.reply(200, scheduled(0));
        let (host, _audit) = site(&icinga);
        let text = failed_text(run(&host, "olga", json!({"action": "schedule"})).await);
        assert!(text.contains("certificate"), "{text}");
        assert!(icinga.seen().is_empty());
    }

    #[tokio::test]
    async fn a_server_that_accepts_and_then_says_nothing_is_given_up_on() {
        // no TLS at all: the handshake never completes
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        let icinga = icinga().await; // for its password and CA files
        let monitoring = format!(
            "[monitoring]\nicinga_url = \"https://localhost:{port}\"\nicinga_user = \"opsmcp\"\n\
             icinga_password_file = \"{}\"\nicinga_ca = \"{}\"\nhost = \"web1.example.com\"\n",
            icinga.password_file().display(),
            icinga.ca_file().display()
        );
        let (host, _audit) = fixture(&monitoring);
        let quick = Env {
            connect_limit: Duration::from_millis(200),
            ..env()
        };
        let started = std::time::Instant::now();
        let text = failed_text(run_with(&host, "olga", quick, json!({"action": "status"})).await);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(text.contains("did not"), "{text}");
    }

    #[tokio::test]
    async fn a_server_that_takes_the_request_and_never_answers_is_given_up_on() {
        let icinga = icinga().await; // nothing queued: it reads and stays silent
        let (host, _audit) = site(&icinga);
        let quick = Env {
            total_limit: Duration::from_millis(300),
            ..env()
        };
        let started = std::time::Instant::now();
        let text = failed_text(run_with(&host, "olga", quick, json!({"action": "cancel"})).await);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(text.contains("did not answer"), "{text}");
        // a change that may or may not have happened is said to be unknown
        assert!(text.contains("not known"), "{text}");
    }

    #[tokio::test]
    async fn nothing_listening_is_a_plain_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let icinga = icinga().await;
        let monitoring = format!(
            "[monitoring]\nicinga_url = \"https://localhost:{port}\"\nicinga_user = \"opsmcp\"\n\
             icinga_password_file = \"{}\"\nicinga_ca = \"{}\"\nhost = \"web1.example.com\"\n",
            icinga.password_file().display(),
            icinga.ca_file().display()
        );
        let (host, _audit) = fixture(&monitoring);
        let text = failed_text(run(&host, "olga", json!({"action": "status"})).await);
        assert!(text.contains("cannot connect"), "{text}");
        assert!(text.contains(&format!("localhost:{port}")), "{text}");
    }

    // ---- this host's name ----

    #[tokio::test]
    async fn without_a_configured_name_the_kernels_host_name_is_used() {
        let icinga = icinga().await;
        icinga.reply(200, json!({"results": []}));
        let (host, _audit) = fixture(&icinga.monitoring(""));
        let name_file = icinga.dir.path().join("hostname");
        std::fs::write(&name_file, "db1.example.com\n").unwrap();
        let named = Env {
            hostname_file: name_file,
            ..env()
        };
        let text = ok_text(run_with(&host, "olga", named, json!({"action": "status"})).await);
        assert!(text.contains("db1.example.com"), "{text}");
        assert_eq!(
            icinga.seen()[0].json()["filter_vars"]["host_name"],
            "db1.example.com"
        );
    }

    #[tokio::test]
    async fn a_host_name_that_cannot_be_used_asks_for_the_setting() {
        let icinga = icinga().await;
        let (host, _audit) = fixture(&icinga.monitoring(""));
        let name_file = icinga.dir.path().join("hostname");
        for content in ["", "(none)\n", "two words\n"] {
            std::fs::write(&name_file, content).unwrap();
            let named = Env {
                hostname_file: name_file.clone(),
                ..env()
            };
            let text =
                failed_text(run_with(&host, "olga", named, json!({"action": "status"})).await);
            assert!(text.contains("monitoring.host"), "{text}");
        }
        // and when it cannot be read at all
        let text = failed_text(run(&host, "olga", json!({"action": "status"})).await);
        assert!(text.contains("monitoring.host"), "{text}");
        assert_eq!(icinga.connections.load(Ordering::SeqCst), 0);
    }

    // ---- the password file ----

    fn password_file(content: &[u8], mode: u32) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("password");
        std::fs::write(&path, content).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        (dir, path)
    }

    #[test]
    fn the_password_is_the_files_content_without_the_line_end() {
        let (_dir, path) = password_file(b"pa ss:w0rd\n", 0o600);
        assert_eq!(read_password(&path).unwrap(), "pa ss:w0rd");
        let (_dir, path) = password_file(b"pw-no-newline", 0o400);
        assert_eq!(read_password(&path).unwrap(), "pw-no-newline");
        let (_dir, path) = password_file(b"pw\r\n", 0o600);
        assert_eq!(read_password(&path).unwrap(), "pw");
    }

    #[test]
    fn a_password_file_others_can_read_is_not_used() {
        for mode in [0o640, 0o604, 0o660, 0o644, 0o620, 0o602] {
            let (_dir, path) = password_file(b"hunter2-secret\n", mode);
            let problem = read_password(&path).unwrap_err();
            assert!(problem.contains("group or others"), "{mode:o}: {problem}");
            assert!(!problem.contains("hunter2"), "{problem}");
        }
    }

    #[test]
    fn a_password_file_must_hold_one_short_line_of_text() {
        let (_dir, path) = password_file(b"", 0o600);
        assert!(read_password(&path).unwrap_err().contains("empty"));
        let (_dir, path) = password_file(b"\n\n", 0o600);
        assert!(read_password(&path).unwrap_err().contains("empty"));
        let (_dir, path) = password_file(b"one-secret\ntwo-secret\n", 0o600);
        let problem = read_password(&path).unwrap_err();
        assert!(problem.contains("one line"), "{problem}");
        assert!(!problem.contains("secret"), "{problem}");
        let (_dir, path) = password_file(&[b'x'; 1025], 0o600);
        assert!(read_password(&path).unwrap_err().contains("1024"));
        let (_dir, path) = password_file(&[0xff, 0xfe, b'x'], 0o600);
        assert!(read_password(&path).unwrap_err().contains("text"));
        // a directory, and nothing at all
        let dir = tempfile::tempdir().unwrap();
        assert!(
            read_password(dir.path())
                .unwrap_err()
                .contains("regular file")
        );
        let problem = read_password(&dir.path().join("missing")).unwrap_err();
        assert!(problem.contains("missing"), "{problem}");
    }

    #[tokio::test]
    async fn an_unusable_password_file_stops_the_call_before_it_connects() {
        let icinga = icinga().await;
        std::fs::set_permissions(
            icinga.password_file(),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let (host, _audit) = site(&icinga);
        let text = failed_text(run(&host, "olga", json!({"action": "schedule"})).await);
        assert!(text.contains("group or others"), "{text}");
        assert!(!text.contains(PASSWORD), "{text}");
        assert_eq!(icinga.connections.load(Ordering::SeqCst), 0);
    }

    // ---- the certificate authorities ----

    #[test]
    fn a_configured_ca_file_is_the_only_trust_and_must_hold_a_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, authority("a ca").cert.pem()).unwrap();
        let roots = load_trust(Some(&ca), &[]).unwrap();
        assert_eq!(roots.len(), 1);

        let empty = dir.path().join("empty.pem");
        std::fs::write(&empty, "nothing here\n").unwrap();
        // the bundles are not a fallback for a configured file that is unusable
        let problem = load_trust(Some(&empty), std::slice::from_ref(&ca)).unwrap_err();
        assert!(problem.contains("monitoring.icinga_ca"), "{problem}");
        let problem = load_trust(Some(&dir.path().join("missing.pem")), &[]).unwrap_err();
        assert!(problem.contains("monitoring.icinga_ca"), "{problem}");
    }

    #[test]
    fn without_a_configured_ca_the_first_usable_bundle_is_used() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty.pem");
        std::fs::write(&empty, "").unwrap();
        let bundle = dir.path().join("bundle.pem");
        let two = format!(
            "{}{}",
            authority("ca one").cert.pem(),
            authority("ca two").cert.pem()
        );
        std::fs::write(&bundle, two).unwrap();
        let candidates = [dir.path().join("missing.pem"), empty, bundle];
        assert_eq!(load_trust(None, &candidates).unwrap().len(), 2);
        let problem = load_trust(None, &candidates[..2]).unwrap_err();
        assert!(problem.contains("monitoring.icinga_ca"), "{problem}");
    }

    #[tokio::test]
    async fn the_hosts_ca_bundle_is_used_when_no_ca_is_configured() {
        let icinga = icinga().await;
        icinga.reply(200, json!({"results": []}));
        let monitoring = format!(
            "[monitoring]\nicinga_url = \"https://localhost:{}\"\nicinga_user = \"opsmcp\"\n\
             icinga_password_file = \"{}\"\nhost = \"web1.example.com\"\n",
            icinga.port,
            icinga.password_file().display()
        );
        let (host, _audit) = fixture(&monitoring);
        // with a bundle that does not hold the issuing CA, the server is not trusted
        let other = icinga.dir.path().join("other.pem");
        std::fs::write(&other, authority("unrelated ca").cert.pem()).unwrap();
        let wrong = Env {
            bundles: vec![other],
            ..env()
        };
        let text = failed_text(run_with(&host, "olga", wrong, json!({"action": "status"})).await);
        assert!(text.contains("certificate"), "{text}");
        assert!(icinga.seen().is_empty());
        // with the right one it is
        let right = Env {
            bundles: vec![icinga.ca_file()],
            ..env()
        };
        ok_text(run_with(&host, "olga", right, json!({"action": "status"})).await);
        assert_eq!(icinga.seen().len(), 1);
    }
}
