//! An MCP client over a byte stream: one JSON-RPC message per line each way.
//!
//! This is the fleet server's end of `ssh host opsmcp serve`: requests go down the
//! process's stdin, answers come back on its stdout, matched by request id, so several
//! calls to one host can be in progress over one connection.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot};

use crate::stdio::{Line, read_line};

/// Messages waiting to be written before `request` has to wait.
const OUTBOX: usize = 64;

/// Why a request got no result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkError {
    /// The connection is gone. `sent` is whether the request may have reached the
    /// host, in which case what it asked for may have been done.
    Closed { why: String, sent: bool },
    /// The host answered with a JSON-RPC error.
    Rpc { code: i64, message: String },
    /// The host sent a message larger than this side accepts, and the link was closed.
    /// The request may have been acted on; asking again would get the same answer.
    Oversized(String),
}

/// A request that has been sent and not yet answered.
struct Pending {
    answer: oneshot::Sender<Value>,
    /// How long its message was, in bytes.
    size: usize,
}

struct State {
    /// Requests waiting for an answer, by id.
    pending: HashMap<u64, Pending>,
    /// Why the link is closed, once it is.
    closed: Option<String>,
    /// It was closed because the host sent a message larger than we accept.
    oversized: bool,
}

struct Shared {
    state: Mutex<State>,
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Closes the link (the first reason given is the one kept) and ends every request
    /// that is waiting.
    fn close(&self, why: &str) {
        let mut state = self.lock();
        if state.closed.is_none() {
            state.closed = Some(why.to_string());
        }
        state.pending.clear();
    }

    /// Closes the link because the host sent a message larger than we accept.
    fn close_oversized(&self, why: &str) {
        let mut state = self.lock();
        if state.closed.is_none() {
            state.closed = Some(why.to_string());
            state.oversized = true;
        }
        state.pending.clear();
    }
}

/// Lets something that does not own the link close it, with the reason: what watches
/// the `ssh` process knows why a session ended better than the stream does.
#[derive(Clone)]
pub struct Closer(Arc<Shared>);

impl Closer {
    /// Closes the link, giving `why` as the reason unless it already has one.
    pub fn close(&self, why: &str) {
        self.0.close(why);
    }
}

/// One connection to a host's `opsmcp serve`.
pub struct Link {
    shared: Arc<Shared>,
    outbox: mpsc::Sender<Vec<u8>>,
    next_id: AtomicU64,
    reader: tokio::task::JoinHandle<()>,
    writer: tokio::task::JoinHandle<()>,
}

impl Drop for Link {
    fn drop(&mut self) {
        self.reader.abort();
        self.writer.abort();
    }
}

/// Takes a request off the waiting list when its caller stops waiting, and tells the
/// host to stop working on it if it had not answered yet.
struct Waiting<'a> {
    link: &'a Link,
    id: u64,
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        let unanswered = {
            let mut state = self.link.shared.lock();
            state.pending.remove(&self.id).is_some() && state.closed.is_none()
        };
        if unanswered {
            // Best effort: if the outbox is full the host simply finishes the call.
            let notice = json!({
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": self.id},
            });
            if let Ok(mut line) = serde_json::to_vec(&notice) {
                line.push(b'\n');
                let _ = self.link.outbox.try_send(line);
            }
        }
    }
}

impl Link {
    /// Starts reading answers from `reader` and writing requests to `writer`. A message
    /// from the host longer than `max_line` bytes closes the link.
    pub fn start<R, W>(reader: R, writer: W, max_line: usize) -> Link
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                pending: HashMap::new(),
                closed: None,
                oversized: false,
            }),
        });
        let (outbox, mut inbox) = mpsc::channel::<Vec<u8>>(OUTBOX);

        let reading = shared.clone();
        let reader = tokio::spawn(async move {
            let mut reader = BufReader::new(reader);
            loop {
                match read_line(&mut reader, max_line).await {
                    Ok(Line::Text(bytes)) => deliver(&reading, &bytes),
                    Ok(Line::TooLong) => {
                        // Which request it answered cannot be known, so nothing on this
                        // connection can be relied on any more.
                        reading.close_oversized(&format!(
                            "the host sent a message larger than the {max_line} bytes \
                             accepted here (raise limits.max_output_bytes of the fleet \
                             server to at least the host's)"
                        ));
                        return;
                    }
                    Ok(Line::Eof) | Err(_) => {
                        reading.close("the host closed the connection");
                        return;
                    }
                }
            }
        });

        let writing = shared.clone();
        let writer = tokio::spawn(async move {
            let mut writer = writer;
            while let Some(line) = inbox.recv().await {
                if writer.write_all(&line).await.is_err() || writer.flush().await.is_err() {
                    writing.close("the connection to the host broke");
                    return;
                }
            }
            let _ = writer.shutdown().await;
        });

        Link {
            shared,
            outbox,
            next_id: AtomicU64::new(1),
            reader,
            writer,
        }
    }

    /// Sends a request and waits for its result. Dropping the future (a time limit, a
    /// caller who gave up) tells the host to stop working on it.
    pub async fn request(&self, method: &str, params: Value) -> Result<Value, LinkError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let unsent = |why: String| LinkError::Closed { why, sent: false };
        let message = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let mut line =
            serde_json::to_vec(&message).map_err(|e| unsent(format!("cannot encode: {e}")))?;
        line.push(b'\n');

        let (answer, answered) = oneshot::channel();
        {
            let mut state = self.shared.lock();
            if let Some(why) = &state.closed {
                return Err(unsent(why.clone()));
            }
            let size = line.len();
            state.pending.insert(id, Pending { answer, size });
        }
        let waiting = Waiting { link: self, id };
        if self.outbox.send(line).await.is_err() {
            let why = self
                .closed()
                .unwrap_or_else(|| "the link is closed".to_string());
            return Err(unsent(why));
        }
        // AIDEV-NOTE: from here on the request may have reached the host. If no answer
        // comes, whoever asked must be told that what they asked for may have been done.
        let reply = match answered.await {
            Ok(reply) => reply,
            Err(_) => {
                let (why, oversized) = {
                    let state = self.shared.lock();
                    (state.closed.clone(), state.oversized)
                };
                let why = why.unwrap_or_else(|| "the connection to the host ended".to_string());
                return Err(if oversized {
                    LinkError::Oversized(why)
                } else {
                    LinkError::Closed { why, sent: true }
                });
            }
        };
        drop(waiting);
        if let Some(error) = reply.get("error") {
            let code = error.get("code").and_then(Value::as_i64).unwrap_or(0);
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("the host reported an error without a message");
            return Err(LinkError::Rpc {
                code,
                message: message.chars().take(500).collect(),
            });
        }
        Ok(reply.get("result").cloned().unwrap_or(Value::Null))
    }

    /// Sends a notification: a message that gets no answer. Best effort.
    pub fn notify(&self, method: &str) {
        let notice = json!({"jsonrpc": "2.0", "method": method});
        if let Ok(mut line) = serde_json::to_vec(&notice) {
            line.push(b'\n');
            let _ = self.outbox.try_send(line);
        }
    }

    /// Why the link is closed, if it is.
    pub fn closed(&self) -> Option<String> {
        self.shared.lock().closed.clone()
    }

    /// Closes the link, giving `why` as the reason unless it already has one.
    #[cfg(test)]
    pub fn close(&self, why: &str) {
        self.shared.close(why);
    }

    /// A handle that can close the link without keeping it (and so the stream) alive.
    pub fn closer(&self) -> Closer {
        Closer(self.shared.clone())
    }

    /// Requests that have been sent and not yet answered.
    pub fn in_flight(&self) -> usize {
        self.shared.lock().pending.len()
    }
}

/// Hands one line from the host to the request it answers. Anything that is not the
/// answer to a request still waiting is ignored: `opsmcp serve` sends nothing else, and
/// a host must not be able to confuse the link by sending something unexpected.
fn deliver(shared: &Shared, bytes: &[u8]) {
    let Ok(Value::Object(message)) = serde_json::from_slice::<Value>(bytes) else {
        return;
    };
    if message.contains_key("method") {
        return; // a request or a notification, not an answer
    }
    if !(message.contains_key("result") || message.contains_key("error")) {
        return;
    }
    let waiting = match message.get("id") {
        Some(Value::Null) | None if message.contains_key("error") => {
            // AIDEV-NOTE: an error with no id is what `opsmcp serve` sends for a message
            // it could not read at all, which in practice means one longer than the host
            // accepts (what we send is always valid JSON). It cannot say which request
            // that was, so it is taken to be about the longest message still waiting.
            // Without this the request would wait out its whole time limit and then be
            // reported as "may have run", when the host never even read it.
            let mut state = shared.lock();
            let longest = state
                .pending
                .iter()
                .max_by_key(|(_, pending)| pending.size)
                .map(|(id, _)| *id);
            longest.and_then(|id| state.pending.remove(&id))
        }
        Some(id) => match id.as_u64() {
            Some(id) => shared.lock().pending.remove(&id),
            None => None,
        },
        None => None,
    };
    if let Some(pending) = waiting {
        let _ = pending.answer.send(Value::Object(message));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::testing::Fixture;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    /// A link to the test server of `mcp::testing`, as Unix user `user`.
    fn connect(fx: &Fixture, user: &str, max_line: usize) -> Link {
        let (ours, theirs) = tokio::io::duplex(256 * 1024);
        let (their_read, their_write) = tokio::io::split(theirs);
        let (server, session) = (fx.server.clone(), fx.session(user));
        tokio::spawn(async move {
            let reader = BufReader::new(their_read);
            let _ =
                crate::stdio::serve(server, session, reader, their_write, std::future::pending())
                    .await;
        });
        let (read, write) = tokio::io::split(ours);
        Link::start(read, write, max_line)
    }

    fn call(tool: &str, arguments: Value) -> Value {
        json!({"name": tool, "arguments": arguments})
    }

    fn text(result: &Value) -> &str {
        result["content"][0]["text"].as_str().unwrap()
    }

    #[tokio::test]
    async fn a_request_gets_its_result() {
        let fx = Fixture::new();
        let link = connect(&fx, "rita", 1 << 20);
        let result = link
            .request("tools/call", call("echo", json!({"text": "hello"})))
            .await
            .unwrap();
        assert_eq!(text(&result), "hello");
        assert_eq!(result["isError"], false);
        assert_eq!(link.in_flight(), 0);
        assert_eq!(link.closed(), None);
    }

    #[tokio::test]
    async fn requests_in_progress_together_each_get_their_own_answer() {
        let fx = Fixture::new();
        let link = Arc::new(connect(&fx, "rita", 1 << 20));
        let mut waiting = Vec::new();
        for n in 0..20 {
            let link = link.clone();
            waiting.push(tokio::spawn(async move {
                let said = format!("message {n}");
                let result = link
                    .request("tools/call", call("echo", json!({"text": said})))
                    .await
                    .unwrap();
                (said, text(&result).to_string())
            }));
        }
        for task in waiting {
            let (said, heard) = task.await.unwrap();
            assert_eq!(said, heard);
        }
    }

    #[tokio::test]
    async fn an_error_from_the_host_is_returned_as_one() {
        let fx = Fixture::new();
        let link = connect(&fx, "rita", 1 << 20);
        let error = link.request("no/such/method", json!({})).await.unwrap_err();
        let LinkError::Rpc { code, message } = error else {
            panic!("{error:?}");
        };
        assert_eq!(code, -32601);
        assert!(message.contains("Method not found"), "{message}");
        // the link is still good
        assert!(link.request("ping", json!({})).await.is_ok());
    }

    #[tokio::test]
    async fn a_request_that_is_dropped_is_cancelled_on_the_host() {
        let fx = Fixture::new();
        let link = connect(&fx, "rita", 1 << 20);
        let slow = link.request("tools/call", call("slow", json!({})));
        assert!(
            tokio::time::timeout(Duration::from_millis(200), slow)
                .await
                .is_err()
        );
        // the host stops the call: its audit trail says how it ended
        let mut outcome = None;
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if let Some(record) = fx.audited("tool_result").first() {
                outcome = Some(record["outcome"].clone());
                break;
            }
        }
        assert_eq!(outcome, Some(json!("cancelled")));
        assert_eq!(link.in_flight(), 0);
        // and the link is still good
        assert!(link.request("ping", json!({})).await.is_ok());
    }

    /// A link whose other end the test plays by hand.
    fn by_hand(max_line: usize) -> (Link, tokio::io::DuplexStream) {
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        let (read, write) = tokio::io::split(ours);
        (Link::start(read, write, max_line), theirs)
    }

    /// Reads one request line from the link's end of the pipe.
    async fn next_request(peer: &mut tokio::io::DuplexStream) -> Value {
        let mut line = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            peer.read_exact(&mut byte).await.unwrap();
            if byte[0] == b'\n' {
                return serde_json::from_slice(&line).unwrap();
            }
            line.push(byte[0]);
        }
    }

    #[tokio::test]
    async fn requests_are_well_formed_and_numbered() {
        let (link, mut peer) = by_hand(4096);
        let link = Arc::new(link);
        let asking = {
            let link = link.clone();
            tokio::spawn(async move { link.request("tools/list", json!({"a": 1})).await })
        };
        let request = next_request(&mut peer).await;
        assert_eq!(request["jsonrpc"], "2.0");
        assert_eq!(request["method"], "tools/list");
        assert_eq!(request["params"], json!({"a": 1}));
        let id = request["id"].as_u64().unwrap();
        let answer = json!({"jsonrpc": "2.0", "id": id, "result": {"tools": []}});
        peer.write_all(format!("{answer}\n").as_bytes())
            .await
            .unwrap();
        assert_eq!(asking.await.unwrap().unwrap(), json!({"tools": []}));
        // the next request has another id
        let again = {
            let link = link.clone();
            tokio::spawn(async move { link.request("ping", json!({})).await })
        };
        assert_ne!(next_request(&mut peer).await["id"].as_u64().unwrap(), id);
        again.abort();
    }

    #[tokio::test]
    async fn noise_from_the_host_is_ignored() {
        let (link, mut peer) = by_hand(4096);
        let asking = tokio::spawn(async move {
            let result = link.request("ping", json!({})).await;
            (result, link)
        });
        let id = next_request(&mut peer).await["id"].as_u64().unwrap();
        for noise in [
            "not json at all".to_string(),
            "[1, 2, 3]".to_string(),
            // an answer to a question nobody asked
            json!({"jsonrpc": "2.0", "id": id + 1000, "result": {"stray": true}}).to_string(),
            json!({"jsonrpc": "2.0", "id": "text-id", "result": {}}).to_string(),
            // a notification, and a request from the host: neither is an answer
            json!({"jsonrpc": "2.0", "method": "notifications/message", "params": {}}).to_string(),
            json!({"jsonrpc": "2.0", "id": id, "method": "sampling/createMessage"}).to_string(),
            String::new(),
        ] {
            peer.write_all(format!("{noise}\n").as_bytes())
                .await
                .unwrap();
        }
        let answer = json!({"jsonrpc": "2.0", "id": id, "result": {"real": true}});
        peer.write_all(format!("{answer}\n").as_bytes())
            .await
            .unwrap();
        let (result, link) = asking.await.unwrap();
        assert_eq!(result.unwrap(), json!({"real": true}));
        assert_eq!(link.closed(), None);
    }

    #[tokio::test]
    async fn when_the_host_goes_away_waiting_requests_end_and_later_ones_are_not_sent() {
        let (link, mut peer) = by_hand(4096);
        let link = Arc::new(link);
        let asking = {
            let link = link.clone();
            tokio::spawn(async move { link.request("tools/call", json!({})).await })
        };
        next_request(&mut peer).await;
        drop(peer);
        let error = asking.await.unwrap().unwrap_err();
        let LinkError::Closed { why, sent } = error else {
            panic!("{error:?}");
        };
        assert!(
            sent,
            "the request had gone out, so the host may have acted on it"
        );
        assert!(why.contains("closed the connection"), "{why}");
        assert!(link.closed().is_some());
        let error = link.request("ping", json!({})).await.unwrap_err();
        assert_eq!(
            error,
            LinkError::Closed {
                why: link.closed().unwrap(),
                sent: false
            }
        );
    }

    #[tokio::test]
    async fn a_message_larger_than_allowed_closes_the_link() {
        let fx = Fixture::new();
        // the test server caps a result at 2048 bytes; allow less than that per message
        let link = connect(&fx, "rita", 512);
        let error = link
            .request("tools/call", call("big", json!({})))
            .await
            .unwrap_err();
        // its own kind of error: asking again would only get the same answer again
        let LinkError::Oversized(why) = error else {
            panic!("{error:?}");
        };
        assert!(why.contains("512"), "{why}");
        // the link is closed; a later request was never sent
        let later = link.request("ping", json!({})).await.unwrap_err();
        assert!(
            matches!(later, LinkError::Closed { sent: false, .. }),
            "{later:?}"
        );
    }

    #[tokio::test]
    async fn an_error_without_an_id_goes_to_the_request_it_most_likely_answers() {
        // A host that cannot read a message (it is longer than the host accepts) cannot
        // say which request it was: its error has no id. That is about the longest
        // message waiting, which then fails at once instead of waiting out its time.
        let (link, mut peer) = by_hand(1 << 20);
        let link = Arc::new(link);
        let small = {
            let link = link.clone();
            tokio::spawn(async move { link.request("ping", json!({})).await })
        };
        let small_id = next_request(&mut peer).await["id"].as_u64().unwrap();
        let large = {
            let link = link.clone();
            let padding = "x".repeat(5000);
            tokio::spawn(async move { link.request("tools/call", json!({"pad": padding})).await })
        };
        next_request(&mut peer).await;
        let refusal = json!({"jsonrpc": "2.0", "id": null, "error":
            {"code": -32600, "message": "Invalid Request: a message may be at most 4096 bytes"}});
        peer.write_all(format!("{refusal}\n").as_bytes())
            .await
            .unwrap();
        let error = large.await.unwrap().unwrap_err();
        assert_eq!(
            error,
            LinkError::Rpc {
                code: -32600,
                message: "Invalid Request: a message may be at most 4096 bytes".to_string()
            }
        );
        // the other request is untouched, and is answered when its answer comes
        assert_eq!(link.in_flight(), 1);
        let answer = json!({"jsonrpc": "2.0", "id": small_id, "result": {"pong": true}});
        peer.write_all(format!("{answer}\n").as_bytes())
            .await
            .unwrap();
        assert_eq!(small.await.unwrap().unwrap(), json!({"pong": true}));
        // with nothing waiting, such an error is noise like any other
        peer.write_all(format!("{refusal}\n").as_bytes())
            .await
            .unwrap();
        assert!(link.request("ping", json!({})).await.is_err() || link.closed().is_none());
    }

    #[tokio::test]
    async fn the_first_reason_for_closing_is_the_one_kept() {
        let (link, peer) = by_hand(4096);
        link.close("ssh exited with status 255: Permission denied (publickey)");
        drop(peer);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            link.closed().as_deref(),
            Some("ssh exited with status 255: Permission denied (publickey)")
        );
    }
}
