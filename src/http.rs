//! The HTTPS transport: MCP "Streamable HTTP" over TLS.
//!
//! One endpoint, `POST /mcp`: the body is a JSON-RPC message, the reply is the JSON-RPC
//! response as `application/json` (or `202 Accepted` when there is nothing to say). The
//! server keeps no session state, so any request can go to any instance. `GET /healthz`
//! answers `ok` without authentication, for monitoring.
//!
//! AIDEV-NOTE: security properties of this transport, all of which have tests:
//!   - TLS only (rustls); there is no plain-HTTP mode.
//!   - Every request is authenticated before its body is read: by bearer token, by TLS
//!     client certificate, or both, as `http.auth` says. A token that is presented must
//!     be valid; a bad token is never ignored in favour of another method.
//!   - Requests carrying a browser `Origin` are refused unless the origin is listed.
//!   - Bodies, headers, handshakes and connection counts are all bounded.

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::json;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use crate::audit::Severity;
use crate::config::{AuthMode, HttpCfg};
use crate::exec::check_trusted_path;
use crate::mcp::{SUPPORTED_VERSIONS, Server, Session};
use crate::policy::Principal;
use crate::timefmt::now_secs;
use crate::token::sha256_hex;

/// Time allowed for a client to complete the TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Time allowed for a client to send a request's headers.
const HEADER_TIMEOUT: Duration = Duration::from_secs(15);
/// Time allowed for a client to send a request's body.
const BODY_TIMEOUT: Duration = Duration::from_secs(30);
/// After this long a connection is closed once its current request is done. Clients
/// simply reconnect; it bounds how long an idle connection can hold a slot.
const MAX_CONNECTION_AGE: Duration = Duration::from_secs(15 * 60);
/// How long requests in progress get to finish when the server is stopping.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);
/// Authentication failures written to the audit log per 10 seconds, so that someone
/// hammering the port cannot flood the log.
const AUDITED_FAILURES_PER_WINDOW: u32 = 30;

type HttpResponse = Response<Full<Bytes>>;

/// Rate limit for authentication-failure audit records.
#[derive(Debug, Default)]
struct FailureWindow {
    /// When the current ten-second window began (Unix seconds).
    began: i64,
    /// Failures seen in it.
    seen: u32,
}

/// What to do about one authentication failure.
#[derive(Debug, PartialEq, Eq)]
struct Noted {
    /// Write an audit record for it.
    record: bool,
    /// Failures in the previous window that went unrecorded, to be reported now.
    suppressed_earlier: u32,
}

impl FailureWindow {
    fn note(&mut self, now: i64) -> Noted {
        let mut suppressed_earlier = 0;
        if now - self.began >= 10 {
            suppressed_earlier = self.seen.saturating_sub(AUDITED_FAILURES_PER_WINDOW);
            self.began = now;
            self.seen = 0;
        }
        self.seen += 1;
        Noted {
            record: self.seen <= AUDITED_FAILURES_PER_WINDOW,
            suppressed_earlier,
        }
    }
}

/// What every connection shares.
struct Shared {
    server: Arc<Server>,
    acceptor: TlsAcceptor,
    auth: AuthMode,
    allowed_origins: Vec<String>,
    failures: Mutex<FailureWindow>,
    /// Open connections per client address, and the most one address may have.
    per_address: Mutex<HashMap<IpAddr, usize>>,
    per_address_limit: usize,
}

/// A bound, ready-to-run HTTPS listener.
pub struct HttpServer {
    shared: Arc<Shared>,
    listener: TcpListener,
    slots: Arc<Semaphore>,
}

impl HttpServer {
    /// Loads the TLS material and binds the listening socket named in `[http]`.
    pub async fn bind(server: Arc<Server>) -> Result<HttpServer, String> {
        let host = server.host().clone();
        let http = host
            .cfg
            .http
            .as_ref()
            .ok_or_else(|| "the configuration has no [http] section".to_string())?;
        let tls = tls_config(http)?;
        let listener = TcpListener::bind(&http.listen)
            .await
            .map_err(|e| format!("cannot listen on {}: {e}", http.listen))?;
        let shared = Shared {
            server,
            acceptor: TlsAcceptor::from(Arc::new(tls)),
            auth: http.auth,
            allowed_origins: http.allowed_origins.clone(),
            failures: Mutex::new(FailureWindow::default()),
            per_address: Mutex::new(HashMap::new()),
            // AIDEV-NOTE: a connection holds a slot from before its TLS handshake, so
            // without this one client could take every slot just by connecting and
            // saying nothing. Half the slots is generous for a real client and leaves
            // room for the others. (It does not stop a flood from many addresses; that
            // is for the network in front of the server.)
            per_address_limit: (http.max_connections / 2).max(1),
        };
        Ok(HttpServer {
            shared: Arc::new(shared),
            listener,
            slots: Arc::new(Semaphore::new(http.max_connections)),
        })
    }

    /// The address actually bound (useful when the configuration asks for port 0).
    pub fn local_addr(&self) -> Result<SocketAddr, String> {
        self.listener.local_addr().map_err(|e| e.to_string())
    }

    /// Serves connections until `shutdown` completes, then lets requests in progress
    /// finish (within a grace period).
    pub async fn run<S>(self, shutdown: S) -> Result<(), String>
    where
        S: Future<Output = ()>,
    {
        tokio::pin!(shutdown);
        let (stopping, stop) = watch::channel(false);
        let mut connections = JoinSet::new();
        loop {
            while connections.try_join_next().is_some() {}
            // AIDEV-NOTE: a slot is taken BEFORE accepting, so at most max_connections
            // connections exist at once, handshakes included; further clients wait in the
            // kernel's accept queue instead of costing us memory.
            let slot = tokio::select! {
                slot = self.slots.clone().acquire_owned() => slot,
                _ = &mut shutdown => break,
            };
            let Ok(slot) = slot else {
                break;
            };
            let accepted = tokio::select! {
                accepted = self.listener.accept() => accepted,
                _ = &mut shutdown => break,
            };
            match accepted {
                Ok((tcp, peer)) => {
                    // Over its share: closed at once, before any work is done for it.
                    let Some(share) = AddressShare::take(&self.shared, peer.ip()) else {
                        log::debug!("{} has too many connections open; closing", peer.ip());
                        continue;
                    };
                    connections.spawn(connection(
                        self.shared.clone(),
                        tcp,
                        peer,
                        stop.clone(),
                        (slot, share),
                    ));
                }
                Err(e) => {
                    // Typically "too many open files": back off instead of spinning.
                    log::warn!("cannot accept a connection: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        drop(self.listener);
        let _ = stopping.send(true);
        let finish = async { while connections.join_next().await.is_some() {} };
        if tokio::time::timeout(SHUTDOWN_GRACE, finish).await.is_err() {
            connections.shutdown().await;
        }
        Ok(())
    }
}

/// Serves HTTPS as configured under `[http]` until `shutdown` completes.
pub async fn serve<S>(server: Arc<Server>, shutdown: S) -> Result<(), String>
where
    S: Future<Output = ()>,
{
    let http = HttpServer::bind(server).await?;
    log::info!("listening on https://{}/mcp", http.local_addr()?);
    http.run(shutdown).await
}

fn read_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let shown = path.display();
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
        .map_err(|e| format!("{shown}: {e}"))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{shown}: {e}"))?;
    if certs.is_empty() {
        return Err(format!("{shown}: contains no certificate"));
    }
    Ok(certs)
}

/// Checks that the TLS files named under `[http]` exist and load: for
/// `opsmcp check-config`.
pub fn check_tls(http: &HttpCfg) -> Result<(), String> {
    tls_config(http).map(|_| ())
}

/// Builds the TLS configuration for the chosen authentication mode.
fn tls_config(http: &HttpCfg) -> Result<rustls::ServerConfig, String> {
    // As root, the files that say who we are and whose certificates we accept must be
    // root's own.
    let as_root = rustix::process::geteuid().is_root();
    let trusted = |setting: &str, path: &Path| -> Result<(), String> {
        if as_root {
            check_trusted_path(path, &[])
                .map_err(|e| format!("refusing to use {setting} {}: {e}", path.display()))?;
        }
        Ok(())
    };
    trusted("http.tls_cert", &http.tls_cert)?;
    let certs = read_certs(&http.tls_cert)?;
    trusted("http.tls_key", &http.tls_key)?;
    let key = PrivateKeyDer::from_pem_file(&http.tls_key)
        .map_err(|e| format!("{}: {e}", http.tls_key.display()))?;
    if let Ok(meta) = std::fs::metadata(&http.tls_key)
        && meta.mode() & 0o077 != 0
    {
        log::warn!(
            "{} is readable by users other than its owner; it should be mode 0600",
            http.tls_key.display()
        );
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS setup: {e}"))?;
    let builder = if http.auth == AuthMode::Token {
        builder.with_no_client_auth()
    } else {
        let ca = http.client_ca.as_ref().ok_or_else(|| {
            "http.client_ca is required when http.auth uses client certificates".to_string()
        })?;
        trusted("http.client_ca", ca)?;
        let mut roots = rustls::RootCertStore::empty();
        for cert in read_certs(ca)? {
            roots
                .add(cert)
                .map_err(|e| format!("{}: {e}", ca.display()))?;
        }
        let verifier =
            rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider);
        // "mtls-or-token" lets a client connect without a certificate (it must then
        // present a token); a certificate that IS presented must still verify.
        let verifier = if http.auth == AuthMode::MtlsOrToken {
            verifier.allow_unauthenticated()
        } else {
            verifier
        };
        let verifier = verifier
            .build()
            .map_err(|e| format!("{}: {e}", ca.display()))?;
        builder.with_client_cert_verifier(verifier)
    };
    let mut config = builder.with_single_cert(certs, key).map_err(|e| {
        format!(
            "{} and {}: {e}",
            http.tls_cert.display(),
            http.tls_key.display()
        )
    })?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// The client certificate a connection presented (already verified against the CA).
struct ClientCert {
    fingerprint: String,
    /// The subject's common name, if it has exactly one.
    cn: Option<String>,
}

impl ClientCert {
    fn from_der(der: &[u8]) -> ClientCert {
        let cn = x509_parser::parse_x509_certificate(der)
            .ok()
            .and_then(|(_, cert)| {
                let mut names = cert.subject().iter_common_name();
                let first = names.next()?.as_str().ok()?.to_string();
                // More than one common name is ambiguous: match such a certificate by
                // fingerprint only.
                names.next().is_none().then_some(first)
            });
        ClientCert {
            fingerprint: sha256_hex(der),
            cn,
        }
    }
}

/// One connection's place in its client address's share; given back when dropped.
struct AddressShare {
    shared: Arc<Shared>,
    address: IpAddr,
}

impl AddressShare {
    /// Takes a place for `address`, or returns `None` if it already has its share.
    fn take(shared: &Arc<Shared>, address: IpAddr) -> Option<AddressShare> {
        let mut open = shared
            .per_address
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let count = open.entry(address).or_insert(0);
        if *count >= shared.per_address_limit {
            return None;
        }
        *count += 1;
        Some(AddressShare {
            shared: shared.clone(),
            address,
        })
    }
}

impl Drop for AddressShare {
    fn drop(&mut self) {
        let mut open = self
            .shared
            .per_address
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = open.get_mut(&self.address) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                open.remove(&self.address);
            }
        }
    }
}

/// What is known about one connection.
struct Conn {
    peer: SocketAddr,
    client_cert: Option<ClientCert>,
}

/// Serves one TCP connection: TLS handshake, then HTTP/1.1 requests until it closes.
async fn connection(
    shared: Arc<Shared>,
    tcp: TcpStream,
    peer: SocketAddr,
    mut stop: watch::Receiver<bool>,
    _held_while_open: (OwnedSemaphorePermit, AddressShare),
) {
    let _ = tcp.set_nodelay(true);
    let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, shared.acceptor.accept(tcp)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => {
            log::debug!("TLS handshake with {peer} failed: {e}");
            return;
        }
        Err(_) => {
            log::debug!("TLS handshake with {peer} timed out");
            return;
        }
    };
    let client_cert = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
        .map(|leaf| ClientCert::from_der(leaf.as_ref()));
    let conn = Arc::new(Conn { peer, client_cert });

    let service = service_fn(move |request| {
        let (shared, conn) = (shared.clone(), conn.clone());
        async move { Ok::<_, Infallible>(handle(&shared, &conn, request).await) }
    });
    let serving = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT)
        .keep_alive(true)
        .serve_connection(TokioIo::new(tls), service);
    tokio::pin!(serving);
    let too_old = tokio::time::sleep(MAX_CONNECTION_AGE);
    tokio::pin!(too_old);
    tokio::select! {
        _ = serving.as_mut() => return,
        _ = stop.changed() => {}
        _ = &mut too_old => {}
    }
    // Finish the request in progress, if any, then close.
    serving.as_mut().graceful_shutdown();
    let _ = serving.await;
}

fn reply(status: StatusCode, content_type: &'static str, body: impl Into<Bytes>) -> HttpResponse {
    let mut response = Response::new(Full::new(body.into()));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn text(status: StatusCode, message: &'static str) -> HttpResponse {
    reply(status, "text/plain; charset=utf-8", message)
}

fn method_not_allowed(allowed: &'static str) -> HttpResponse {
    let mut response = text(StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n");
    response
        .headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static(allowed));
    response
}

/// Handles one HTTP request.
async fn handle(shared: &Shared, conn: &Conn, request: Request<Incoming>) -> HttpResponse {
    let path = request.uri().path();
    if path == "/healthz" {
        return match *request.method() {
            Method::GET | Method::HEAD => text(StatusCode::OK, "ok\n"),
            _ => method_not_allowed("GET"),
        };
    }
    if path != "/mcp" {
        return text(StatusCode::NOT_FOUND, "not found\n");
    }
    // AIDEV-NOTE: a browser attaches an Origin header to cross-site requests, and other
    // clients send none. Refusing unlisted origins keeps a web page that a user happens
    // to visit from driving this server (DNS rebinding, CSRF with a client certificate).
    if let Some(origin) = request.headers().get(header::ORIGIN) {
        let listed = origin.to_str().is_ok_and(|origin| {
            shared
                .allowed_origins
                .iter()
                .any(|allowed| allowed == origin)
        });
        if !listed {
            return text(
                StatusCode::FORBIDDEN,
                "this origin may not use the server\n",
            );
        }
    }
    if request.method() != Method::POST {
        return method_not_allowed("POST");
    }
    let session = match authenticate(shared, conn, request.headers()) {
        Ok(session) => session,
        Err(refusal) => return refuse(shared, conn, refusal),
    };

    let is_json = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"));
    if !is_json {
        return text(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "the body must be application/json\n",
        );
    }
    if let Some(version) = request.headers().get("mcp-protocol-version") {
        let known = version
            .to_str()
            .is_ok_and(|v| SUPPORTED_VERSIONS.contains(&v));
        if !known {
            return text(
                StatusCode::BAD_REQUEST,
                "unsupported MCP-Protocol-Version\n",
            );
        }
    }

    let limit = shared.server.host().cfg.limits.max_request_bytes;
    let reading = Limited::new(request.into_body(), limit).collect();
    let body = match tokio::time::timeout(BODY_TIMEOUT, reading).await {
        Ok(Ok(body)) => body.to_bytes(),
        Ok(Err(e)) if e.downcast_ref::<LengthLimitError>().is_some() => {
            return text(
                StatusCode::PAYLOAD_TOO_LARGE,
                "the request body is too large\n",
            );
        }
        Ok(Err(_)) => {
            return text(
                StatusCode::BAD_REQUEST,
                "the request body could not be read\n",
            );
        }
        Err(_) => {
            return text(
                StatusCode::REQUEST_TIMEOUT,
                "the request body took too long to arrive\n",
            );
        }
    };

    match shared.server.handle(&session, &body).await {
        Some(answer) => reply(StatusCode::OK, "application/json", answer.to_string()),
        None => {
            // a notification, or a response: nothing to send back
            let mut response = Response::new(Full::new(Bytes::new()));
            *response.status_mut() = StatusCode::ACCEPTED;
            response
        }
    }
}

/// The bearer token of a request. `None`: no Authorization header at all. `Some(None)`:
/// there is one, but it is not a usable bearer token.
fn bearer_token(headers: &HeaderMap) -> Option<Option<&str>> {
    let value = headers.get(header::AUTHORIZATION)?;
    let token = value.to_str().ok().and_then(|value| {
        let (scheme, token) = value.split_once(' ')?;
        let token = token.trim();
        (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() && token.len() <= 512)
            .then_some(token)
    });
    Some(token)
}

/// Why a request was not authenticated: the status to answer with, and the reason for
/// the audit log (never sent to the client).
type Refusal = (StatusCode, &'static str);

/// Works out who is calling.
fn authenticate(shared: &Shared, conn: &Conn, headers: &HeaderMap) -> Result<Session, Refusal> {
    let cfg = &shared.server.host().cfg;
    let presented = bearer_token(headers);
    let by_token = || -> Result<Principal, (StatusCode, &'static str)> {
        let refused = |reason| (StatusCode::UNAUTHORIZED, reason);
        match presented {
            None => Err(refused("no bearer token")),
            Some(None) => Err(refused("malformed Authorization header")),
            Some(Some(token)) => cfg
                .principal_for_token(token, now_secs())
                .ok_or(refused("unknown or expired token")),
        }
    };
    let by_cert = || -> Result<Principal, (StatusCode, &'static str)> {
        let refused = |reason| (StatusCode::FORBIDDEN, reason);
        let cert = conn
            .client_cert
            .as_ref()
            .ok_or(refused("no client certificate"))?;
        cfg.principal_for_cert(&cert.fingerprint, cert.cn.as_deref())
            .ok_or(refused("the client certificate is not listed"))
    };
    let outcome = match shared.auth {
        AuthMode::Token => by_token(),
        AuthMode::Mtls => by_cert(),
        // The handshake has already required a certificate from the CA; this is a
        // second check that it is there. The token then says who the caller is.
        // AIDEV-NOTE: the certificate is NOT looked up under [client_certs] in this
        // mode: any certificate `http.client_ca` issued counts. A host that takes
        // tokens passed on by a fleet server therefore relies on that CA issuing the
        // fleet server's certificate and nothing else (the README says how: a
        // certificate that signs itself, named as `client_ca`). Checked against real
        // servers on 2026-11-22: a second certificate from the same CA was accepted
        // with a passed-on token.
        AuthMode::MtlsAndToken if conn.client_cert.is_none() => {
            Err((StatusCode::FORBIDDEN, "no client certificate"))
        }
        AuthMode::MtlsAndToken => by_token(),
        // AIDEV-NOTE: a token that is presented must be valid. A request with a bad
        // token is refused even if its certificate alone would have been enough.
        AuthMode::MtlsOrToken if presented.is_some() => by_token(),
        AuthMode::MtlsOrToken if conn.client_cert.is_some() => by_cert(),
        AuthMode::MtlsOrToken => Err((
            StatusCode::UNAUTHORIZED,
            "no bearer token or client certificate",
        )),
    };
    match outcome {
        Ok(principal) => {
            let mut session = Session::new(principal, "https", Some(conn.peer.to_string()));
            // AIDEV-NOTE: only a fleet server keeps the token a caller presented, and
            // only so that a rule with `identity = "caller"` can pass it on to a host.
            // It is kept if and only if it is what authenticated this request (the
            // principal is then `token:NAME`): a token that merely came along with a
            // certificate that did the authenticating is not the caller's identity here.
            if shared.server.is_fleet()
                && session.principal.name.starts_with("token:")
                && let Some(Some(token)) = presented
            {
                session.bearer = Some(crate::token::Secret::new(token));
            }
            Ok(session)
        }
        Err(refusal) => Err(refusal),
    }
}

/// The answer to a request that failed authentication. It says nothing about why.
fn refuse(shared: &Shared, conn: &Conn, (status, reason): Refusal) -> HttpResponse {
    audit_failure(shared, conn, reason);
    let mut response = text(status, "authentication failed\n");
    if status == StatusCode::UNAUTHORIZED {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    response
}

/// Records an authentication failure, within a rate limit.
fn audit_failure(shared: &Shared, conn: &Conn, reason: &str) {
    let noted = shared
        .failures
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .note(now_secs());
    let audit = &shared.server.host().audit;
    if noted.suppressed_earlier > 0 {
        // Say that there were more than were written down, so that a burst of failures
        // is visible in the trail even though it was not allowed to flood it.
        let event = json!({
            "event": "auth_failures_not_recorded",
            "transport": "https",
            "count": noted.suppressed_earlier,
        });
        let _ = audit.record(Severity::Warning, event);
    }
    if !noted.record {
        return;
    }
    let mut event = json!({
        "event": "auth_failure",
        "transport": "https",
        "peer": conn.peer.to_string(),
        "reason": reason,
    });
    if let (Some(fields), Some(cert)) = (event.as_object_mut(), &conn.client_cert) {
        fields.insert("client_cert_sha256".to_string(), json!(cert.fingerprint));
        fields.insert("client_cert_cn".to_string(), json!(cert.cn));
    }
    let _ = audit.record(Severity::Warning, event);
}

#[cfg(test)]
pub mod testing {
    //! A test certificate authority and an HTTPS server with the test tools of
    //! `mcp::testing`, for tests of this transport and of clients of it.
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::mcp::testing::{CONFIG, Effects, registry};
    use crate::token::sha256_hex;
    use crate::tools::testing::host;
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
        Issuer, KeyPair, KeyUsagePurpose,
    };
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    // ---- a small certificate authority for the tests ----

    pub struct Authority {
        pub params: CertificateParams,
        pub key: KeyPair,
        pub cert: Certificate,
    }

    pub fn authority(name: &str) -> Authority {
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

    /// Issues a certificate and writes NAME.pem and NAME.key into `dir`.
    pub fn issue(
        dir: &Path,
        ca: &Authority,
        name: &str,
        names: &[&str],
        usage: ExtendedKeyUsagePurpose,
    ) -> Certificate {
        let key = KeyPair::generate().unwrap();
        let mut params =
            CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        params.distinguished_name.push(DnType::CommonName, name);
        params.extended_key_usages = vec![usage];
        let cert = params
            .signed_by(&key, &Issuer::from_params(&ca.params, &ca.key))
            .unwrap();
        std::fs::write(dir.join(format!("{name}.pem")), cert.pem()).unwrap();
        let key_file = dir.join(format!("{name}.key"));
        std::fs::write(&key_file, key.serialize_pem()).unwrap();
        // a private key is its owner's alone
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        cert
    }

    // ---- the server under test ----

    pub struct Web {
        pub dir: tempfile::TempDir,
        pub addr: SocketAddr,
        pub audit: MemorySink,
        pub effects: Arc<Effects>,
        pub stop: Option<tokio::sync::oneshot::Sender<()>>,
        pub done: tokio::task::JoinHandle<Result<(), String>>,
    }

    pub const CI_TOKEN: &str = "opsmcp_ci_token";
    pub const OPS_TOKEN: &str = "opsmcp_ops_token";
    pub const OLD_TOKEN: &str = "opsmcp_old_token";

    /// Starts a server with the given `http.auth` mode and extra lines for `[http]`.
    ///
    /// Callers: tokens ci (reader), ops (writer) and old (expired); client certificates
    /// alice (listed by CN, writer), bob (listed by fingerprint, reader), carol (issued by
    /// the right CA but not listed) and mallory (issued by an unrelated CA).
    pub async fn web(auth: &str, extra: &str) -> Web {
        web_named(auth, extra, &["localhost", "127.0.0.1"]).await
    }

    /// Like `web`, with a server certificate for these names only.
    pub async fn web_named(auth: &str, extra: &str, names: &[&str]) -> Web {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let ca = authority("opsmcp test ca");
        std::fs::write(d.join("ca.pem"), ca.cert.pem()).unwrap();
        issue(d, &ca, "server", names, ExtendedKeyUsagePurpose::ServerAuth);
        issue(d, &ca, "alice", &[], ExtendedKeyUsagePurpose::ClientAuth);
        let bob = issue(d, &ca, "bob", &[], ExtendedKeyUsagePurpose::ClientAuth);
        issue(d, &ca, "carol", &[], ExtendedKeyUsagePurpose::ClientAuth);
        let other = authority("somebody else's ca");
        issue(
            d,
            &other,
            "mallory",
            &[],
            ExtendedKeyUsagePurpose::ClientAuth,
        );

        let config = format!(
            r#"{}
[tokens.ci]
sha256 = "{}"
roles = ["reader"]
[tokens.ops]
sha256 = "{}"
roles = ["writer"]
[tokens.old]
sha256 = "{}"
roles = ["writer"]
expires = "2020-01-01"
[client_certs.alice]
cn = "alice"
roles = ["writer"]
[client_certs.bob-pinned]
sha256 = "{}"
roles = ["reader"]
[http]
listen = "127.0.0.1:0"
tls_cert = "{dir}/server.pem"
tls_key = "{dir}/server.key"
client_ca = "{dir}/ca.pem"
auth = "{auth}"
{extra}
"#,
            CONFIG.replace(
                "max_concurrent_calls = 2",
                "max_concurrent_calls = 2\nmax_request_bytes = 4096"
            ),
            sha256_hex(CI_TOKEN.as_bytes()),
            sha256_hex(OPS_TOKEN.as_bytes()),
            sha256_hex(OLD_TOKEN.as_bytes()),
            sha256_hex(bob.der()),
            dir = d.display(),
        );
        let (host, audit) = host(&config);
        let effects = Arc::new(Effects::default());
        let server = Arc::new(Server::new(host, registry(&effects)));
        let http = HttpServer::bind(server).await.unwrap();
        let addr = http.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let done = tokio::spawn(http.run(async move {
            let _ = stopped.await;
        }));
        Web {
            dir,
            addr,
            audit,
            effects,
            stop: Some(stop),
            done,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use crate::mcp::testing::{Effects, registry};
    use crate::tools::testing::host;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use serde_json::{Value, json};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    // ---- a minimal HTTPS client ----

    #[derive(Debug)]
    struct Reply {
        status: u16,
        headers: Vec<(String, String)>,
        body: String,
    }

    impl Reply {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        }
        fn json(&self) -> Value {
            serde_json::from_str(&self.body)
                .unwrap_or_else(|e| panic!("not JSON ({e}): {:?}", self.body))
        }
    }

    impl Web {
        /// A TLS client that trusts the test CA and presents `identity`'s certificate.
        fn client(&self, identity: Option<&str>) -> tokio_rustls::TlsConnector {
            let d = self.dir.path();
            let mut roots = rustls::RootCertStore::empty();
            for cert in CertificateDer::pem_file_iter(d.join("ca.pem")).unwrap() {
                roots.add(cert.unwrap()).unwrap();
            }
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let builder = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots);
            let config = match identity {
                None => builder.with_no_client_auth(),
                Some(name) => {
                    let chain: Vec<CertificateDer> =
                        CertificateDer::pem_file_iter(d.join(format!("{name}.pem")))
                            .unwrap()
                            .map(Result::unwrap)
                            .collect();
                    let key = PrivateKeyDer::from_pem_file(d.join(format!("{name}.key"))).unwrap();
                    builder.with_client_auth_cert(chain, key).unwrap()
                }
            };
            tokio_rustls::TlsConnector::from(Arc::new(config))
        }

        /// Sends one raw HTTP request over a new TLS connection and reads the reply.
        async fn raw(&self, identity: Option<&str>, request: &str) -> Result<Reply, String> {
            let attempt = async {
                let tcp = TcpStream::connect(self.addr)
                    .await
                    .map_err(|e| e.to_string())?;
                let name = ServerName::try_from("localhost").unwrap();
                let mut tls = self
                    .client(identity)
                    .connect(name, tcp)
                    .await
                    .map_err(|e| e.to_string())?;
                tls.write_all(request.as_bytes())
                    .await
                    .map_err(|e| e.to_string())?;
                let mut raw = Vec::new();
                tls.read_to_end(&mut raw).await.map_err(|e| e.to_string())?;
                parse_reply(&raw)
            };
            tokio::time::timeout(Duration::from_secs(10), attempt)
                .await
                .map_err(|_| "timed out".to_string())?
        }

        /// `POST /mcp` with a JSON body and the given extra headers.
        async fn post(
            &self,
            identity: Option<&str>,
            headers: &[(&str, &str)],
            body: &str,
        ) -> Result<Reply, String> {
            let mut request = format!(
                "POST /mcp HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            );
            for (name, value) in headers {
                request.push_str(&format!("{name}: {value}\r\n"));
            }
            request.push_str("\r\n");
            request.push_str(body);
            self.raw(identity, &request).await
        }

        async fn with_token(&self, token: &str, body: &str) -> Reply {
            let bearer = format!("Bearer {token}");
            self.post(None, &[("Authorization", bearer.as_str())], body)
                .await
                .unwrap()
        }

        fn audited(&self, event: &str) -> Vec<Value> {
            self.audit
                .records()
                .into_iter()
                .filter(|r| r["event"] == event)
                .collect()
        }
    }

    fn parse_reply(raw: &[u8]) -> Result<Reply, String> {
        let text = String::from_utf8_lossy(raw);
        let (head, body) = text
            .split_once("\r\n\r\n")
            .ok_or_else(|| format!("no HTTP reply: {text:?}"))?;
        let mut lines = head.lines();
        let status_line = lines.next().unwrap_or_default();
        let status = status_line
            .strip_prefix("HTTP/1.1 ")
            .and_then(|rest| rest.split(' ').next())
            .and_then(|code| code.parse().ok())
            .ok_or_else(|| format!("bad status line: {status_line:?}"))?;
        let headers = lines
            .filter_map(|l| l.split_once(": "))
            .map(|(n, v)| (n.to_lowercase(), v.to_string()))
            .collect();
        Ok(Reply {
            status,
            headers,
            body: body.to_string(),
        })
    }

    const PING: &str = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;

    fn call(tool: &str, arguments: Value) -> String {
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}).to_string()
    }

    #[tokio::test]
    async fn a_request_with_a_valid_token_is_answered_as_json() {
        let web = web("token", "").await;
        let reply = web.with_token(CI_TOKEN, PING).await;
        assert_eq!(reply.status, 200);
        assert_eq!(reply.header("content-type"), Some("application/json"));
        assert_eq!(reply.header("cache-control"), Some("no-store"));
        assert_eq!(
            reply.json(),
            json!({"jsonrpc": "2.0", "id": 1, "result": {}})
        );
    }

    #[tokio::test]
    async fn missing_wrong_and_expired_tokens_are_refused_and_audited() {
        let web = web("token", "").await;
        let attempts: [&[(&str, &str)]; 6] = [
            &[],
            &[("Authorization", "Bearer opsmcp_wrong")],
            &[("Authorization", "Bearer opsmcp_old_token")],
            &[("Authorization", "Basic b3BzOm9wcw==")],
            &[("Authorization", "Bearer ")],
            &[("Authorization", "opsmcp_ci_token")],
        ];
        for headers in attempts {
            let reply = web.post(None, headers, PING).await.unwrap();
            assert_eq!(reply.status, 401, "{headers:?}");
            assert_eq!(
                reply.header("www-authenticate"),
                Some("Bearer"),
                "{headers:?}"
            );
            assert!(
                !reply.body.contains("result"),
                "{headers:?}: {}",
                reply.body
            );
        }
        let failures = web.audited("auth_failure");
        assert_eq!(failures.len(), 6);
        assert!(
            failures[0]["peer"]
                .as_str()
                .unwrap()
                .starts_with("127.0.0.1:"),
            "{}",
            failures[0]
        );
        assert_eq!(failures[0]["transport"], "https");
    }

    #[tokio::test]
    async fn a_tool_call_runs_as_the_tokens_principal_within_its_roles() {
        let web = web("token", "").await;
        let reply = web
            .with_token(CI_TOKEN, &call("echo", json!({"text": "over https"})))
            .await;
        assert_eq!(reply.json()["result"]["content"][0]["text"], "over https");
        let record = web.audited("tool_call").pop().unwrap();
        assert_eq!(record["principal"], "token:ci");
        assert_eq!(record["transport"], "https");
        assert!(
            record["peer"].as_str().unwrap().starts_with("127.0.0.1:"),
            "{record}"
        );

        // ci is a reader: it cannot use the write tool; ops (a writer) can
        let reply = web
            .with_token(CI_TOKEN, &call("touch", json!({"name": "alpha"})))
            .await;
        assert_eq!(reply.json()["result"]["isError"], true);
        assert_eq!(*web.effects.touched.lock().unwrap(), Vec::<String>::new());
        let reply = web
            .with_token(OPS_TOKEN, &call("touch", json!({"name": "alpha"})))
            .await;
        assert_eq!(reply.json()["result"]["isError"], false);
        assert_eq!(
            *web.effects.touched.lock().unwrap(),
            vec!["alpha".to_string()]
        );
    }

    #[tokio::test]
    async fn nothing_runs_for_an_unauthenticated_request() {
        let web = web("token", "").await;
        let reply = web
            .post(None, &[], &call("touch", json!({"name": "alpha"})))
            .await
            .unwrap();
        assert_eq!(reply.status, 401);
        assert_eq!(*web.effects.touched.lock().unwrap(), Vec::<String>::new());
        assert_eq!(web.audited("tool_call"), Vec::<Value>::new());
    }

    #[tokio::test]
    async fn a_notification_is_accepted_with_no_body() {
        let web = web("token", "").await;
        let reply = web
            .with_token(
                CI_TOKEN,
                r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            )
            .await;
        assert_eq!(reply.status, 202);
        assert_eq!(reply.body, "");
    }

    #[tokio::test]
    async fn malformed_json_gets_a_json_rpc_parse_error() {
        let web = web("token", "").await;
        let reply = web.with_token(CI_TOKEN, "{nope").await;
        assert_eq!(reply.json()["error"]["code"], -32700);
    }

    #[tokio::test]
    async fn healthz_answers_without_authentication() {
        let web = web("token", "").await;
        let reply = web
            .raw(
                None,
                "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        assert_eq!((reply.status, reply.body.as_str()), (200, "ok\n"));
    }

    #[tokio::test]
    async fn only_post_to_the_mcp_path_is_served() {
        let web = web("token", "").await;
        let auth = format!("Authorization: Bearer {CI_TOKEN}\r\n");
        for method in ["GET", "DELETE", "PUT"] {
            let request = format!(
                "{method} /mcp HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{auth}\r\n"
            );
            let reply = web.raw(None, &request).await.unwrap();
            assert_eq!(reply.status, 405, "{method}");
            assert_eq!(reply.header("allow"), Some("POST"), "{method}");
        }
        for path in ["/", "/other", "/mcp/extra", "/healthz/x"] {
            let request = format!(
                "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{PING}",
                PING.len()
            );
            let reply = web.raw(None, &request).await.unwrap();
            assert_eq!(reply.status, 404, "{path}");
        }
    }

    #[tokio::test]
    async fn requests_from_a_browser_origin_are_refused_unless_it_is_listed() {
        let bearer = format!("Bearer {CI_TOKEN}");
        let with_origin =
            |origin: &'static str| [("Authorization", bearer.as_str()), ("Origin", origin)];

        let web = web("token", "").await;
        let reply = web
            .post(None, &with_origin("https://evil.example"), PING)
            .await
            .unwrap();
        assert_eq!(reply.status, 403);

        let web = self::web("token", "allowed_origins = [\"https://ops.example\"]").await;
        assert_eq!(
            web.post(None, &with_origin("https://ops.example"), PING)
                .await
                .unwrap()
                .status,
            200
        );
        assert_eq!(
            web.post(None, &with_origin("https://evil.example"), PING)
                .await
                .unwrap()
                .status,
            403
        );
    }

    #[tokio::test]
    async fn a_body_over_the_size_limit_is_refused() {
        let web = web("token", "").await;
        let big = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"ping","params":{{"pad":"{}"}}}}"#,
            "x".repeat(5000)
        );
        let reply = web.with_token(CI_TOKEN, &big).await;
        assert_eq!(reply.status, 413);
    }

    #[tokio::test]
    async fn a_body_that_is_not_declared_as_json_is_refused() {
        let web = web("token", "").await;
        let request = format!(
            "POST /mcp HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: Bearer {CI_TOKEN}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{PING}",
            PING.len()
        );
        assert_eq!(web.raw(None, &request).await.unwrap().status, 415);
    }

    #[tokio::test]
    async fn an_unknown_protocol_version_header_is_refused() {
        let web = web("token", "").await;
        let bearer = format!("Bearer {CI_TOKEN}");
        let with_version = |v: &'static str| {
            [
                ("Authorization", bearer.as_str()),
                ("MCP-Protocol-Version", v),
            ]
        };
        assert_eq!(
            web.post(None, &with_version("2025-06-18"), PING)
                .await
                .unwrap()
                .status,
            200
        );
        assert_eq!(
            web.post(None, &with_version("1999-01-01"), PING)
                .await
                .unwrap()
                .status,
            400
        );
    }

    #[tokio::test]
    async fn several_requests_can_share_one_connection() {
        let web = web("token", "").await;
        let request = |connection: &str| {
            format!(
                "POST /mcp HTTP/1.1\r\nHost: localhost\r\nConnection: {connection}\r\nAuthorization: Bearer {CI_TOKEN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{PING}",
                PING.len()
            )
        };
        let both = format!("{}{}", request("keep-alive"), request("close"));
        let tcp = TcpStream::connect(web.addr).await.unwrap();
        let mut tls = web
            .client(None)
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        tls.write_all(both.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), tls.read_to_end(&mut raw))
            .await
            .unwrap()
            .unwrap();
        let text = String::from_utf8_lossy(&raw);
        assert_eq!(text.matches("HTTP/1.1 200 OK").count(), 2, "{text}");
    }

    #[tokio::test]
    async fn plain_http_is_not_served() {
        let web = web("token", "").await;
        let mut tcp = TcpStream::connect(web.addr).await.unwrap();
        tcp.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut raw = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), tcp.read_to_end(&mut raw))
            .await
            .unwrap();
        assert!(
            !raw.starts_with(b"HTTP/"),
            "{:?}",
            String::from_utf8_lossy(&raw)
        );
    }

    #[tokio::test]
    async fn mtls_serves_only_listed_client_certificates() {
        let web = web("mtls", "").await;
        // alice is listed by common name, bob by fingerprint
        let reply = web
            .post(Some("alice"), &[], &call("touch", json!({"name": "alpha"})))
            .await
            .unwrap();
        assert_eq!(reply.status, 200);
        assert_eq!(reply.json()["result"]["isError"], false);
        assert_eq!(
            web.audited("tool_call").pop().unwrap()["principal"],
            "cert:alice"
        );
        let reply = web
            .post(Some("bob"), &[], &call("echo", json!({"text": "hi"})))
            .await
            .unwrap();
        assert_eq!(reply.status, 200);
        assert_eq!(
            web.audited("tool_call").pop().unwrap()["principal"],
            "cert:bob-pinned"
        );

        // carol's certificate is genuine but she is not listed
        let reply = web.post(Some("carol"), &[], PING).await.unwrap();
        assert_eq!(reply.status, 403);
        assert_eq!(web.audited("auth_failure").len(), 1);
        // a token is not an alternative in this mode
        let reply = web
            .post(
                Some("carol"),
                &[("Authorization", "Bearer opsmcp_ci_token")],
                PING,
            )
            .await
            .unwrap();
        assert_eq!(reply.status, 403);

        // no certificate, or one from another CA: the TLS handshake itself fails
        assert!(web.post(None, &[], PING).await.is_err());
        assert!(web.post(Some("mallory"), &[], PING).await.is_err());
    }

    #[tokio::test]
    async fn mtls_and_token_needs_both() {
        let web = web("mtls+token", "").await;
        let bearer = [("Authorization", "Bearer opsmcp_ci_token")];
        // carol is not listed, and need not be: here the certificate only has to be
        // genuine, and the token says who is calling
        let reply = web
            .post(Some("carol"), &bearer, &call("echo", json!({"text": "hi"})))
            .await
            .unwrap();
        assert_eq!(reply.status, 200);
        assert_eq!(
            web.audited("tool_call").pop().unwrap()["principal"],
            "token:ci"
        );
        // a certificate without a token
        assert_eq!(
            web.post(Some("alice"), &[], PING).await.unwrap().status,
            401
        );
        // a token without a certificate
        assert!(web.post(None, &bearer, PING).await.is_err());
    }

    #[tokio::test]
    async fn mtls_or_token_accepts_either_but_never_ignores_a_bad_token() {
        let web = web("mtls-or-token", "").await;
        let good = [("Authorization", "Bearer opsmcp_ci_token")];
        let bad = [("Authorization", "Bearer opsmcp_wrong")];
        assert_eq!(web.post(None, &good, PING).await.unwrap().status, 200);
        assert_eq!(
            web.post(Some("alice"), &[], PING).await.unwrap().status,
            200
        );
        assert_eq!(web.post(None, &[], PING).await.unwrap().status, 401);
        assert_eq!(
            web.post(Some("carol"), &[], PING).await.unwrap().status,
            403
        );
        // alice's certificate would be enough, but a token was presented and it is wrong
        assert_eq!(
            web.post(Some("alice"), &bad, PING).await.unwrap().status,
            401
        );
        // a certificate from another CA is still refused at the handshake
        assert!(web.post(Some("mallory"), &good, PING).await.is_err());
    }

    #[test]
    fn auth_failures_beyond_the_limit_are_counted_and_reported_later() {
        let mut window = FailureWindow::default();
        // the first 30 in a ten-second window are recorded one by one
        for _ in 0..AUDITED_FAILURES_PER_WINDOW {
            assert_eq!(
                window.note(1000),
                Noted {
                    record: true,
                    suppressed_earlier: 0
                }
            );
        }
        // further ones in the same window are only counted
        assert_eq!(
            window.note(1003),
            Noted {
                record: false,
                suppressed_earlier: 0
            }
        );
        assert_eq!(
            window.note(1009),
            Noted {
                record: false,
                suppressed_earlier: 0
            }
        );
        // the next window records again, and says how many went unrecorded
        assert_eq!(
            window.note(1010),
            Noted {
                record: true,
                suppressed_earlier: 2
            }
        );
        assert_eq!(
            window.note(1011),
            Noted {
                record: true,
                suppressed_earlier: 0
            }
        );
    }

    #[tokio::test]
    async fn one_address_cannot_hold_every_connection_slot() {
        // four slots in all, so one address may hold two
        let web = web("token", "max_connections = 4").await;
        let idle_one = TcpStream::connect(web.addr).await.unwrap();
        let idle_two = TcpStream::connect(web.addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        // a third connection from the same address is turned away at once
        assert!(
            web.post(None, &[("Authorization", "Bearer opsmcp_ci_token")], PING)
                .await
                .is_err()
        );
        // when the idle ones go, there is room again
        drop((idle_one, idle_two));
        let mut answered = false;
        for _ in 0..50 {
            if let Ok(reply) = web
                .post(None, &[("Authorization", "Bearer opsmcp_ci_token")], PING)
                .await
            {
                assert_eq!(reply.status, 200);
                answered = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(answered, "the address was never let back in");
    }

    #[tokio::test]
    async fn the_server_stops_when_told_to() {
        let mut web = web("token", "").await;
        web.stop.take().unwrap().send(()).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), &mut web.done).await;
        assert_eq!(result.expect("the server to stop").unwrap(), Ok(()));
        assert!(
            TcpStream::connect(web.addr).await.is_err(),
            "the port should be closed"
        );
    }

    #[tokio::test]
    async fn bind_fails_clearly_when_tls_files_are_unusable() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().display();
        std::fs::write(dir.path().join("empty.pem"), "").unwrap();
        for (cert, key) in [("missing.pem", "missing.key"), ("empty.pem", "empty.pem")] {
            let config = format!(
                "[http]\nlisten = \"127.0.0.1:0\"\ntls_cert = \"{d}/{cert}\"\ntls_key = \"{d}/{key}\"\n"
            );
            let (host, _audit) = host(&config);
            let server = Arc::new(Server::new(host, registry(&Arc::new(Effects::default()))));
            match HttpServer::bind(server).await {
                Err(message) => assert!(message.contains(cert), "{message}"),
                Ok(_) => panic!("{cert}: bind should have failed"),
            }
        }
    }

    #[tokio::test]
    async fn bind_fails_without_an_http_section() {
        let (host, _audit) = host("");
        let server = Arc::new(Server::new(host, registry(&Arc::new(Effects::default()))));
        assert!(HttpServer::bind(server).await.is_err());
    }
}
