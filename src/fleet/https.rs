//! Reaching a host over HTTPS: one `POST /mcp` to its `opsmcp serve-http` per call.
//!
//! AIDEV-NOTE: what this relies on, all of it tested:
//!   - the host's certificate is verified, for the address in the inventory, against the
//!     configured CA (or this machine's bundle) BEFORE the token is written. There is no
//!     option to skip that;
//!   - the token is only ever put in the Authorization header of that verified
//!     connection. It is never in a message, a log line or an audit record;
//!   - redirects are not followed: a 3xx is just an answer that is not usable;
//!   - connecting, and the whole exchange, each have a time limit, and the answer a size
//!     limit.

use std::io::Read;
use std::net::{IpAddr, SocketAddr};
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
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use serde_json::{Value, json};

use crate::config::FleetHttpsCfg;
use crate::exec::check_trusted_path;
use crate::sanitize::clean_text;
use crate::token::Secret;

/// Largest credential file read.
const MAX_SECRET_BYTES: u64 = 1024;
/// Most addresses of one name that are tried.
const MAX_ADDRESSES: usize = 4;

/// Why a call over HTTPS got no result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HttpsError {
    /// Nothing reached the host's opsmcp: no connection, no certificate that could be
    /// trusted, or the credential was refused. Nothing was run.
    Unreachable(String),
    /// The request went out and no usable answer came back. It may have been acted on.
    Lost(String),
    /// The request went out and no answer came in time. It may have been acted on.
    Timeout(String),
    /// The host is there and answered, but would not take the request as such (it was
    /// too large, say). Nothing was run, and it says nothing about the host's health.
    NotAccepted(String),
    /// The host answered with a JSON-RPC error.
    Rpc { code: i64, message: String },
}

/// The users whose files are trusted besides root: the user we run as, unless that is
/// root.
pub fn trusted_owners() -> Vec<u32> {
    let me = rustix::process::geteuid().as_raw();
    if me == 0 { Vec::new() } else { vec![me] }
}

/// Reads a credential from a file that holds it and nothing else: one line.
///
/// AIDEV-NOTE: no message from here may contain any of the file's content. The file
/// must belong to root or to the user we run as, be closed to everyone else, and sit in
/// directories nobody else can write: whoever can write a directory on the way to it
/// can put a different file there, such as another rule's credential.
pub fn read_secret_file(path: &Path, what: &str) -> Result<Secret, String> {
    let shown = path.display();
    // NONBLOCK: a FIFO or a device put in the file's place must not hang us.
    let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    let descriptor = rustix::fs::open(path, flags, Mode::empty()).map_err(|e| {
        format!(
            "cannot read {what} from {shown}: {}",
            std::io::Error::from(e)
        )
    })?;
    let file = std::fs::File::from(descriptor);
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot examine {shown}, which should hold {what}: {e}"))?;
    if !meta.is_file() {
        return Err(format!(
            "{shown}, which should hold {what}, is not a regular file"
        ));
    }
    let me = rustix::process::geteuid().as_raw();
    if meta.uid() != 0 && meta.uid() != me {
        return Err(format!(
            "{shown}, which holds {what}, must be owned by root or by the user opsmcp runs as"
        ));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(format!(
            "{shown}, which holds {what}, must not be accessible to group or others (chmod 600)"
        ));
    }
    check_trusted_path(path, &trusted_owners())
        .map_err(|e| format!("refusing to use {shown}, which should hold {what}: {e}"))?;
    let mut bytes = Vec::new();
    file.take(MAX_SECRET_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read {what} from {shown}: {e}"))?;
    if bytes.len() as u64 > MAX_SECRET_BYTES {
        return Err(format!(
            "{shown} is larger than {MAX_SECRET_BYTES} bytes: it must hold {what} and nothing else"
        ));
    }
    let text = String::from_utf8(bytes).map_err(|_| format!("{shown} does not hold text"))?;
    let secret = text.trim_end_matches(['\n', '\r']);
    if secret.is_empty() {
        return Err(format!("{shown}, which should hold {what}, is empty"));
    }
    if secret.chars().any(|c| c.is_control() || c == ' ') {
        return Err(format!(
            "{shown} must hold one line with no spaces: {what} and nothing else"
        ));
    }
    Ok(Secret::new(secret))
}

/// The certificate authorities a host's certificate must chain to.
fn load_roots(custom: Option<&Path>, bundles: &[PathBuf]) -> Result<RootCertStore, String> {
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
        // No falling back to the machine's bundle: the operator said which CA to trust.
        return read(path).map_err(|problem| {
            format!(
                "fleet.https.ca ({}) cannot be used: {problem}",
                path.display()
            )
        });
    }
    bundles
        .iter()
        .find_map(|path| read(path).ok())
        .ok_or_else(|| {
            "no bundle of trusted certificate authorities was found on this machine: set \
         fleet.https.ca to the CA that issued the hosts' certificates"
                .to_string()
        })
}

/// What is needed to call hosts over HTTPS: whom to trust, and who we are to them.
pub struct HttpsClient {
    tls: Arc<rustls::ClientConfig>,
    connect_limit: Duration,
    max_body: usize,
}

/// Ends the task that drives a connection when the exchange is over, however it ends.
struct Driver(tokio::task::JoinHandle<()>);

impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Text from the other side, on one line and of bounded length, safe to show.
fn brief(text: &str) -> String {
    let cleaned = clean_text(text.as_bytes());
    let flat: String = cleaned
        .chars()
        .map(|c| {
            if matches!(c, '\n' | '\t' | '\r') {
                ' '
            } else {
                c
            }
        })
        .take(300)
        .collect();
    flat.trim().to_string()
}

/// Whether an error from the connection is the host's TLS layer turning us away (an
/// alert), as it does when it wants a client certificate we did not present. Such a
/// connection never carried a request to the host's opsmcp.
fn turned_away(error: &(dyn std::error::Error + 'static)) -> Option<String> {
    let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(current) = cause {
        let tls = current.downcast_ref::<rustls::Error>().or_else(|| {
            current
                .downcast_ref::<std::io::Error>()
                .and_then(|io| io.get_ref())
                .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        });
        if let Some(rustls::Error::AlertReceived(alert)) = tls {
            return Some(format!("{alert:?}"));
        }
        cause = current.source();
    }
    None
}

impl HttpsClient {
    /// Loads the CA the hosts' certificates must chain to (`https.ca`, or else the first
    /// of `bundles` that holds any) and the client certificate to present, if one is
    /// configured.
    pub fn new(
        https: &FleetHttpsCfg,
        bundles: &[PathBuf],
        connect_limit: Duration,
        max_body: usize,
    ) -> Result<HttpsClient, String> {
        // The files that say whom we trust and who we are must be ours (or root's) to
        // the last directory: nobody else may be able to change or replace them.
        let owners = trusted_owners();
        let trusted = |setting: &str, path: &Path| -> Result<(), String> {
            check_trusted_path(path, &owners)
                .map_err(|e| format!("refusing to use {setting} {}: {e}", path.display()))
        };
        if let Some(ca) = &https.ca {
            trusted("fleet.https.ca", ca)?;
        }
        let roots = load_roots(https.ca.as_deref(), bundles)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("TLS setup: {e}"))?
            .with_root_certificates(roots);
        let mut tls = match (&https.client_cert, &https.client_key) {
            (Some(cert), Some(key)) => {
                trusted("fleet.https.client_cert", cert)?;
                trusted("fleet.https.client_key", key)?;
                let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
                    .map_err(|e| format!("{}: {e}", cert.display()))?
                    .collect::<Result<_, _>>()
                    .map_err(|e| format!("{}: {e}", cert.display()))?;
                if certs.is_empty() {
                    return Err(format!("{}: contains no certificate", cert.display()));
                }
                let private = PrivateKeyDer::from_pem_file(key)
                    .map_err(|e| format!("{}: {e}", key.display()))?;
                // Like every other credential here: not readable by anyone else.
                if std::fs::metadata(key).is_ok_and(|meta| meta.mode() & 0o077 != 0) {
                    return Err(format!(
                        "fleet.https.client_key {} must not be accessible to group or \
                         others (chmod 600)",
                        key.display()
                    ));
                }
                builder
                    .with_client_auth_cert(certs, private)
                    .map_err(|e| format!("{} and {}: {e}", cert.display(), key.display()))?
            }
            _ => builder.with_no_client_auth(),
        };
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(HttpsClient {
            tls: Arc::new(tls),
            connect_limit,
            max_body,
        })
    }

    /// Connects and completes the TLS handshake, which is where the host's certificate
    /// is checked. Nothing of ours has been sent when this returns an error.
    async fn connect(
        &self,
        address: &str,
        port: u16,
        limit: Duration,
    ) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, String> {
        let name = ServerName::try_from(address.to_string())
            .map_err(|_| "its address cannot be used as a TLS server name".to_string())?;
        let addresses: Vec<SocketAddr> = match address.parse::<IpAddr>() {
            Ok(ip) => vec![SocketAddr::new(ip, port)],
            Err(_) => tokio::net::lookup_host((address, port))
                .await
                .map_err(|e| format!("its name could not be looked up ({e})"))?
                .take(MAX_ADDRESSES)
                .collect(),
        };
        if addresses.is_empty() {
            return Err("its name has no address".to_string());
        }
        // Each address gets a share of the limit, with one share kept for the handshake:
        // an address that never answers must not use up the time of one that would.
        let shares = u32::try_from(addresses.len())
            .unwrap_or(1)
            .saturating_add(1);
        let share = limit / shares;
        let mut tcp = None;
        let mut last = String::new();
        for candidate in &addresses {
            match tokio::time::timeout(share, tokio::net::TcpStream::connect(candidate)).await {
                Ok(Ok(stream)) => {
                    tcp = Some(stream);
                    break;
                }
                Ok(Err(e)) => last = format!("{candidate}: {e}"),
                Err(_) => {
                    last = format!("{candidate}: no answer within {:.1} s", share.as_secs_f64())
                }
            }
        }
        let tcp = tcp.ok_or_else(|| format!("cannot connect ({last})"))?;
        let _ = tcp.set_nodelay(true);
        tokio_rustls::TlsConnector::from(self.tls.clone())
            .connect(name, tcp)
            .await
            .map_err(|e| {
                format!(
                    "it did not present a certificate that can be trusted for {address}, or \
                     the TLS handshake failed ({})",
                    brief(&e.to_string())
                )
            })
    }

    /// Sends one MCP request to `https://ADDRESS:PORT/mcp` and returns its result.
    /// `limit` is for the whole exchange, connecting included.
    pub async fn request(
        &self,
        address: &str,
        port: u16,
        token: &Secret,
        method: &str,
        params: Value,
        limit: Duration,
    ) -> Result<Value, HttpsError> {
        let started = Instant::now();
        let at = if address.contains(':') {
            format!("[{address}]:{port}")
        } else {
            format!("{address}:{port}")
        };
        let unsent = HttpsError::Unreachable;

        let message = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let body = serde_json::to_vec(&message)
            .map_err(|e| unsent(format!("cannot write the request: {e}")))?;
        let mut authorization = HeaderValue::from_str(&format!("Bearer {}", token.expose()))
            .map_err(|_| unsent("the token cannot be sent in a header".to_string()))?;
        authorization.set_sensitive(true);
        let request = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header(header::HOST, at.as_str())
            .header(header::ACCEPT, "application/json")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::USER_AGENT, "opsmcp-fleet")
            .header(header::CONNECTION, "close")
            .header("mcp-protocol-version", crate::mcp::SUPPORTED_VERSIONS[0])
            .header(header::AUTHORIZATION, authorization)
            .body(Full::new(Bytes::from(body)))
            .map_err(|e| unsent(format!("cannot build the request: {e}")))?;

        // AIDEV-NOTE: the handshake, and with it the check of the host's certificate,
        // completes here, before the request (and so the token) is written below.
        let connect_limit = self.connect_limit.min(limit);
        let tls =
            match tokio::time::timeout(connect_limit, self.connect(address, port, connect_limit))
                .await
            {
                Ok(Ok(tls)) => tls,
                Ok(Err(why)) => return Err(unsent(why)),
                Err(_) => {
                    return Err(unsent(format!(
                        "it did not complete the connection within {:.1} s",
                        connect_limit.as_secs_f64()
                    )));
                }
            };

        let max_body = self.max_body;
        let talking = async {
            let failed = |e: hyper::Error| match turned_away(&e) {
                // The host's TLS layer refused us before any request was looked at.
                Some(alert) => HttpsError::Unreachable(format!(
                    "it refused the TLS connection ({alert}); if the hosts require a client \
                     certificate, set fleet.https.client_cert"
                )),
                None => {
                    HttpsError::Lost(format!("the connection failed ({})", brief(&e.to_string())))
                }
            };
            let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
                .max_buf_size(64 * 1024)
                .max_headers(64)
                .handshake::<_, Full<Bytes>>(TokioIo::new(tls))
                .await
                .map_err(failed)?;
            let _driver = Driver(tokio::spawn(async move {
                let _ = connection.await;
            }));
            let response = sender.send_request(request).await.map_err(failed)?;
            let status = response.status().as_u16();
            let mut incoming = response.into_body();
            let mut body = Vec::new();
            while let Some(frame) = incoming.frame().await {
                let frame = frame.map_err(failed)?;
                let Some(data) = frame.data_ref() else {
                    continue;
                };
                if body.len() + data.len() > max_body {
                    return Err(HttpsError::Lost(format!(
                        "its answer is larger than {max_body} bytes"
                    )));
                }
                body.extend_from_slice(data);
            }
            Ok::<(u16, Vec<u8>), HttpsError>((status, body))
        };
        let left = limit.saturating_sub(started.elapsed());
        let (status, body) = match tokio::time::timeout(left, talking).await {
            Ok(outcome) => outcome?,
            Err(_) => {
                return Err(HttpsError::Timeout(format!(
                    "no answer within {:.0} s",
                    limit.as_secs_f64()
                )));
            }
        };

        match status {
            200 => {}
            // The host authenticates a request before reading its body, so nothing ran.
            401 | 403 => {
                return Err(HttpsError::Unreachable(format!(
                    "it refused the credential (HTTP {status})"
                )));
            }
            // Other refusals of the request as such (too large, say): it was not acted
            // on either, but the host is plainly there and is not to be left alone
            // because one request was unwelcome.
            400..=499 => {
                return Err(HttpsError::NotAccepted(format!(
                    "it did not accept the request (HTTP {status}: {})",
                    brief(&String::from_utf8_lossy(&body))
                )));
            }
            _ => {
                return Err(HttpsError::Lost(format!(
                    "it answered HTTP {status}, which is not an answer from opsmcp"
                )));
            }
        }
        let answer: Value = serde_json::from_slice(&body)
            .map_err(|_| HttpsError::Lost("its answer is not JSON".to_string()))?;
        if let Some(error) = answer.get("error") {
            return Err(HttpsError::Rpc {
                code: error.get("code").and_then(Value::as_i64).unwrap_or(0),
                message: error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("the host reported an error without a message")
                    .chars()
                    .take(500)
                    .collect(),
            });
        }
        answer
            .get("result")
            .cloned()
            .ok_or_else(|| HttpsError::Lost("its answer is not an MCP answer".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::testing::{CI_TOKEN, OPS_TOKEN, Web, authority, web, web_named};
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    const SECOND: Duration = Duration::from_secs(1);

    fn cfg(web: &Web) -> FleetHttpsCfg {
        FleetHttpsCfg {
            ca: Some(web.dir.path().join("ca.pem")),
            ..FleetHttpsCfg::default()
        }
    }

    fn client(web: &Web) -> HttpsClient {
        HttpsClient::new(&cfg(web), &[], 5 * SECOND, 1 << 20).unwrap()
    }

    fn call(tool: &str, arguments: Value) -> Value {
        json!({"name": tool, "arguments": arguments})
    }

    async fn ask(
        client: &HttpsClient,
        web: &Web,
        token: &str,
        params: Value,
    ) -> Result<Value, HttpsError> {
        client
            .request(
                "localhost",
                web.addr.port(),
                &Secret::new(token),
                "tools/call",
                params,
                5 * SECOND,
            )
            .await
    }

    #[tokio::test]
    async fn a_call_with_a_token_the_host_knows_returns_its_result() {
        let web = web("token", "").await;
        let result = ask(
            &client(&web),
            &web,
            CI_TOKEN,
            call("echo", json!({"text": "hello"})),
        )
        .await
        .unwrap();
        assert_eq!(result["content"][0]["text"], "hello");
        assert_eq!(result["isError"], false);
        // the host knows who called: the token's own name, as if they had called directly
        let record = web
            .audit
            .records()
            .into_iter()
            .find(|r| r["event"] == "tool_call")
            .unwrap();
        assert_eq!(record["principal"], "token:ci");
    }

    #[tokio::test]
    async fn the_host_applies_its_own_roles_to_the_token() {
        let web = web("token", "").await;
        let touch = call("touch", json!({"name": "alpha1"}));
        // ci is a reader there: the host says no, in its own words, and nothing happens
        let result = ask(&client(&web), &web, CI_TOKEN, touch.clone())
            .await
            .unwrap();
        assert_eq!(result["isError"], true);
        assert!(
            result["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("Permission denied")
        );
        assert!(web.effects.touched.lock().unwrap().is_empty());
        // ops is a writer there
        let result = ask(&client(&web), &web, OPS_TOKEN, touch).await.unwrap();
        assert_eq!(result["isError"], false);
        assert_eq!(*web.effects.touched.lock().unwrap(), ["alpha1"]);
    }

    #[tokio::test]
    async fn a_token_the_host_does_not_know_is_refused_and_never_shown() {
        let web = web("token", "").await;
        let secret = "opsmcp_not_a_token_the_host_knows";
        let error = ask(
            &client(&web),
            &web,
            secret,
            call("echo", json!({"text": "x"})),
        )
        .await
        .unwrap_err();
        let HttpsError::Unreachable(why) = &error else {
            panic!("{error:?}");
        };
        assert!(why.contains("401") && why.contains("credential"), "{why}");
        assert!(!format!("{error:?}").contains(secret));
    }

    #[tokio::test]
    async fn a_host_whose_certificate_is_from_another_ca_is_not_sent_the_token() {
        let web = web("token", "").await;
        let other = authority("some other ca");
        let other_ca = web.dir.path().join("other-ca.pem");
        std::fs::write(&other_ca, other.cert.pem()).unwrap();
        let https = FleetHttpsCfg {
            ca: Some(other_ca),
            ..FleetHttpsCfg::default()
        };
        let client = HttpsClient::new(&https, &[], 5 * SECOND, 1 << 20).unwrap();
        let error = ask(&client, &web, CI_TOKEN, call("echo", json!({"text": "x"})))
            .await
            .unwrap_err();
        let HttpsError::Unreachable(why) = &error else {
            panic!("{error:?}");
        };
        assert!(why.contains("certificate"), "{why}");
        // the host never saw a request, let alone the token
        assert!(web.audit.records().is_empty(), "{:?}", web.audit.records());
    }

    #[tokio::test]
    async fn the_certificate_must_be_for_the_address_that_was_connected_to() {
        // this host's certificate names only "localhost"
        let web = web_named("token", "", &["localhost"]).await;
        let client = client(&web);
        let params = call("echo", json!({"text": "x"}));
        let by_name = client
            .request(
                "localhost",
                web.addr.port(),
                &Secret::new(CI_TOKEN),
                "tools/call",
                params.clone(),
                5 * SECOND,
            )
            .await;
        assert!(by_name.is_ok(), "{by_name:?}");
        let by_address = client
            .request(
                "127.0.0.1",
                web.addr.port(),
                &Secret::new(CI_TOKEN),
                "tools/call",
                params,
                5 * SECOND,
            )
            .await
            .unwrap_err();
        let HttpsError::Unreachable(why) = &by_address else {
            panic!("{by_address:?}");
        };
        assert!(why.contains("certificate"), "{why}");
    }

    #[tokio::test]
    async fn a_client_certificate_is_presented_when_one_is_configured() {
        // the host wants a certificate from its CA AND a token
        let web = web("mtls+token", "").await;
        let params = call("echo", json!({"text": "x"}));
        // without a certificate the token alone gets nowhere
        let error = ask(&client(&web), &web, CI_TOKEN, params.clone())
            .await
            .unwrap_err();
        assert!(matches!(error, HttpsError::Unreachable(_)), "{error:?}");
        // with one, the token says who is calling
        let https = FleetHttpsCfg {
            client_cert: Some(web.dir.path().join("alice.pem")),
            client_key: Some(web.dir.path().join("alice.key")),
            ..cfg(&web)
        };
        let with_cert = HttpsClient::new(&https, &[], 5 * SECOND, 1 << 20).unwrap();
        let result = ask(&with_cert, &web, CI_TOKEN, params.clone())
            .await
            .unwrap();
        assert_eq!(result["content"][0]["text"], "x");
        // and the certificate without a known token gets nowhere either
        let error = ask(&with_cert, &web, "opsmcp_unknown", params)
            .await
            .unwrap_err();
        assert!(matches!(error, HttpsError::Unreachable(_)), "{error:?}");
    }

    #[tokio::test]
    async fn nothing_listening_is_reported_quickly_as_unreachable() {
        let web = web("token", "").await;
        let client = client(&web);
        // a port nothing listens on: bind one and let it go
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let started = std::time::Instant::now();
        let error = client
            .request(
                "localhost",
                port,
                &Secret::new(CI_TOKEN),
                "ping",
                json!({}),
                5 * SECOND,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, HttpsError::Unreachable(_)), "{error:?}");
        assert!(started.elapsed() < 3 * SECOND);
    }

    #[tokio::test]
    async fn a_host_that_accepts_and_says_nothing_is_given_up_on() {
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = silent.local_addr().unwrap().port();
        let _accepting = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = silent.accept().await {
                held.push(stream);
            }
        });
        let web = web("token", "").await;
        let client =
            HttpsClient::new(&cfg(&web), &[], Duration::from_millis(400), 1 << 20).unwrap();
        let started = std::time::Instant::now();
        let error = client
            .request(
                "localhost",
                port,
                &Secret::new(CI_TOKEN),
                "ping",
                json!({}),
                5 * SECOND,
            )
            .await
            .unwrap_err();
        // the handshake never finished, so nothing was sent
        let HttpsError::Unreachable(why) = &error else {
            panic!("{error:?}");
        };
        assert!(why.contains("0.4 s"), "{why}");
        assert!(started.elapsed() < 3 * SECOND);
    }

    #[tokio::test]
    async fn an_answer_that_does_not_come_in_time_says_the_call_may_have_run() {
        let web = web("token", "").await;
        let error = client(&web)
            .request(
                "localhost",
                web.addr.port(),
                &Secret::new(CI_TOKEN),
                "tools/call",
                call("slow", json!({})),
                Duration::from_millis(500),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, HttpsError::Timeout(_)), "{error:?}");
        // the host notices that we hung up, and stops the call
        let mut outcome = None;
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if let Some(record) = web
                .audit
                .records()
                .iter()
                .find(|r| r["event"] == "tool_result")
            {
                outcome = Some(record["outcome"].clone());
                break;
            }
        }
        assert_eq!(outcome, Some(json!("cancelled")));
    }

    #[tokio::test]
    async fn an_error_from_the_host_is_returned_as_one() {
        let web = web("token", "").await;
        let error = client(&web)
            .request(
                "localhost",
                web.addr.port(),
                &Secret::new(CI_TOKEN),
                "no/such",
                json!({}),
                5 * SECOND,
            )
            .await
            .unwrap_err();
        assert_eq!(
            error,
            HttpsError::Rpc {
                code: -32601,
                message: "Method not found: no/such".to_string()
            }
        );
    }

    #[tokio::test]
    async fn a_request_the_host_will_not_take_is_not_the_host_being_down() {
        // the test host accepts requests of at most 4096 bytes
        let web = web("token", "").await;
        let padding: Vec<String> = (0..40).map(|n| format!("{n:0>200}")).collect();
        let error = ask(
            &client(&web),
            &web,
            CI_TOKEN,
            call("echo", json!({"text": "x", "extra": padding})),
        )
        .await
        .unwrap_err();
        // the host answered, so it is there; it did not act on the request
        let HttpsError::NotAccepted(why) = &error else {
            panic!("{error:?}");
        };
        assert!(why.contains("413"), "{why}");
        assert!(
            !web.audit
                .records()
                .iter()
                .any(|r| r["event"] == "tool_call"),
            "the host ran nothing"
        );
    }

    #[tokio::test]
    async fn an_answer_larger_than_allowed_is_not_used() {
        let web = web("token", "").await;
        let small = HttpsClient::new(&cfg(&web), &[], 5 * SECOND, 512).unwrap();
        let error = ask(&small, &web, CI_TOKEN, call("big", json!({})))
            .await
            .unwrap_err();
        let HttpsError::Lost(why) = &error else {
            panic!("{error:?}");
        };
        assert!(why.contains("512"), "{why}");
    }

    #[tokio::test]
    async fn the_request_carries_what_it_is_given_under_meta() {
        let web = web("token", "").await;
        let mut params = call("echo", json!({"text": "x"}));
        params["_meta"] =
            json!({"opsmcp/via": {"gateway": "bastion1", "caller": "token:sean", "call": "c-1"}});
        ask(&client(&web), &web, CI_TOKEN, params).await.unwrap();
        let record = web
            .audit
            .records()
            .into_iter()
            .find(|r| r["event"] == "tool_call")
            .unwrap();
        assert_eq!(record["via"]["caller"], "token:sean");
        assert_eq!(record["principal"], "token:ci");
    }

    #[test]
    fn the_trusted_ca_must_be_usable() {
        let dir = tempfile::tempdir().unwrap();
        let missing = FleetHttpsCfg {
            ca: Some(dir.path().join("nope.pem")),
            ..FleetHttpsCfg::default()
        };
        let error = HttpsClient::new(&missing, &[], SECOND, 1024).err().unwrap();
        assert!(error.contains("fleet.https.ca"), "{error}");
        let empty = dir.path().join("empty.pem");
        std::fs::write(&empty, "not a certificate\n").unwrap();
        let unusable = FleetHttpsCfg {
            ca: Some(empty.clone()),
            ..FleetHttpsCfg::default()
        };
        assert!(HttpsClient::new(&unusable, &[], SECOND, 1024).is_err());
        // with no CA configured the machine's own bundle is used, and one must exist
        let error = HttpsClient::new(&FleetHttpsCfg::default(), &[empty], SECOND, 1024)
            .err()
            .unwrap();
        assert!(error.contains("fleet.https.ca"), "{error}");
    }

    #[tokio::test]
    async fn a_client_key_that_others_can_read_is_refused() {
        let web = web("mtls+token", "").await;
        let key = web.dir.path().join("alice.key");
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let https = FleetHttpsCfg {
            client_cert: Some(web.dir.path().join("alice.pem")),
            client_key: Some(key),
            ..cfg(&web)
        };
        let error = HttpsClient::new(&https, &[], SECOND, 1024).err().unwrap();
        assert!(
            error.contains("alice.key") && error.contains("chmod 600"),
            "{error}"
        );
    }

    #[test]
    fn files_in_a_directory_others_can_write_are_not_trusted() {
        // whoever can write the directory can swap the file for another
        let dir = tempfile::tempdir().unwrap();
        let open = dir.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        let ca = authority("ca");
        let ca_file = open.join("ca.pem");
        std::fs::write(&ca_file, ca.cert.pem()).unwrap();
        let https = FleetHttpsCfg {
            ca: Some(ca_file),
            ..FleetHttpsCfg::default()
        };
        let error = HttpsClient::new(&https, &[], SECOND, 1024).err().unwrap();
        assert!(
            error.contains("fleet.https.ca") && error.contains("writable"),
            "{error}"
        );
        let token = open.join("token");
        std::fs::write(&token, "opsmcp_x\n").unwrap();
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
        let error = read_secret_file(&token, "the token").unwrap_err();
        assert!(error.contains("writable"), "{error}");
    }

    #[test]
    fn a_client_certificate_that_cannot_be_loaded_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let ca = authority("ca");
        std::fs::write(dir.path().join("ca.pem"), ca.cert.pem()).unwrap();
        let https = FleetHttpsCfg {
            ca: Some(dir.path().join("ca.pem")),
            client_cert: Some(dir.path().join("missing.pem")),
            client_key: Some(dir.path().join("missing.key")),
            ..FleetHttpsCfg::default()
        };
        let error = HttpsClient::new(&https, &[], SECOND, 1024).err().unwrap();
        assert!(error.contains("missing.pem"), "{error}");
    }

    fn secret_file(content: &str, mode: u32) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, content).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        (dir, path)
    }

    #[test]
    fn a_credential_file_holds_the_credential_and_nothing_else() {
        let (_dir, path) = secret_file("opsmcp_abc123\n", 0o600);
        assert_eq!(
            read_secret_file(&path, "the token").unwrap().expose(),
            "opsmcp_abc123"
        );
        let (_dir, path) = secret_file("opsmcp_abc123", 0o400);
        assert_eq!(
            read_secret_file(&path, "the token").unwrap().expose(),
            "opsmcp_abc123"
        );
        for bad in ["", "\n", "one\ntwo\n", "tab\there\n", "esc\u{1b}ape\n"] {
            let (_dir, path) = secret_file(bad, 0o600);
            assert!(read_secret_file(&path, "the token").is_err(), "{bad:?}");
        }
        let (_dir, path) = secret_file(&"x".repeat(2000), 0o600);
        assert!(read_secret_file(&path, "the token").is_err());
    }

    #[test]
    fn a_credential_file_others_can_read_is_refused_without_showing_it() {
        for mode in [0o644, 0o640, 0o604, 0o660] {
            let (_dir, path) = secret_file("opsmcp_very_secret\n", mode);
            let error = read_secret_file(&path, "the token").unwrap_err();
            assert!(
                error.contains("the token") && error.contains("chmod 600"),
                "{error}"
            );
            assert!(!error.contains("very_secret"), "{error}");
        }
        let (_dir, path) = secret_file("one\nopsmcp_very_secret\n", 0o600);
        assert!(
            !read_secret_file(&path, "the token")
                .unwrap_err()
                .contains("very_secret")
        );
    }

    #[test]
    fn a_credential_file_must_be_a_regular_file_that_exists() {
        let dir = tempfile::tempdir().unwrap();
        let error = read_secret_file(&dir.path().join("missing"), "the token").unwrap_err();
        assert!(error.contains("missing"), "{error}");
        assert!(read_secret_file(dir.path(), "the token").is_err());
    }
}
