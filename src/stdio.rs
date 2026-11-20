//! The stdio transport: one JSON-RPC message per line on stdin, replies on stdout.
//!
//! This is how a local agent talks to opsmcp, and how a remote one does over SSH
//! (`ssh host sudo opsmcp serve`): the caller is whoever started the process.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{Value, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::{AbortHandle, JoinSet};

use crate::mcp::{Server, Session};

/// Requests one client may have in progress before we stop reading more from it.
const MAX_IN_FLIGHT: usize = 32;

/// One line read from the client.
#[derive(Debug, PartialEq, Eq)]
pub enum Line {
    Text(Vec<u8>),
    /// The line was longer than allowed; it has been skipped.
    TooLong,
    Eof,
}

/// Reads one line of at most `max` bytes, without its newline. A longer line is consumed
/// to its end and reported as `TooLong`, so memory use is bounded whatever is sent.
pub async fn read_line<R>(reader: &mut R, max: usize) -> std::io::Result<Line>
where
    R: AsyncBufRead + Unpin,
{
    let mut line = Vec::new();
    let mut too_long = false;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            // End of input. A last line without a newline still counts.
            return Ok(if too_long {
                Line::TooLong
            } else if line.is_empty() {
                Line::Eof
            } else {
                Line::Text(line)
            });
        }
        let newline = available.iter().position(|b| *b == b'\n');
        let chunk = &available[..newline.unwrap_or(available.len())];
        if !too_long {
            if line.len() + chunk.len() > max {
                too_long = true;
                line = Vec::new();
            } else {
                line.extend_from_slice(chunk);
            }
        }
        let used = chunk.len() + usize::from(newline.is_some());
        reader.consume(used);
        if newline.is_some() {
            return Ok(if too_long {
                Line::TooLong
            } else {
                Line::Text(line)
            });
        }
    }
}

/// Serves one client until it closes its end, then waits for calls still in progress.
/// If `shutdown` completes first (a termination signal), calls in progress are stopped.
pub async fn serve<R, W, S>(
    server: Arc<Server>,
    session: Session,
    mut reader: R,
    writer: W,
    shutdown: S,
) -> std::io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
    S: Future<Output = ()>,
{
    let max_line = server.host().cfg.limits.max_request_bytes;

    // One task owns stdout, so replies from concurrent calls never interleave.
    let (replies, mut outbox) = mpsc::channel::<Value>(MAX_IN_FLIGHT);
    let mut writer_task = tokio::spawn(async move {
        let mut writer = writer;
        while let Some(reply) = outbox.recv().await {
            let Ok(mut line) = serde_json::to_vec(&reply) else {
                continue;
            };
            line.push(b'\n');
            if writer.write_all(&line).await.is_err() || writer.flush().await.is_err() {
                break; // the client is gone
            }
        }
        let _ = writer.shutdown().await;
    });

    // Requests in progress. A task returns its request id and the number it was started
    // with, so that it can be forgotten when it ends.
    let mut in_flight: JoinSet<Option<(String, u64)>> = JoinSet::new();
    let mut by_id: HashMap<String, (u64, AbortHandle)> = HashMap::new();
    let mut started: u64 = 0;
    tokio::pin!(shutdown);

    // AIDEV-NOTE: a client may reuse a request id while the earlier request with that id
    // is still being tidied up. An entry is therefore only forgotten by the task that
    // owns it (matched by its number), never by an older task with the same id.
    fn forget(by_id: &mut HashMap<String, (u64, AbortHandle)>, ended: Option<(String, u64)>) {
        if let Some((id, number)) = ended
            && by_id
                .get(&id)
                .is_some_and(|(current, _)| *current == number)
        {
            by_id.remove(&id);
        }
    }

    // AIDEV-NOTE: every wait in this function also watches `shutdown`. A client that has
    // stopped reading its replies can block the writer, then the calls waiting to reply,
    // then this loop; a termination signal has to get through regardless.
    let stopped_by_signal = 'serving: loop {
        // Bounded work per client: when this many requests are in progress, stop
        // reading until one finishes, so that a flood cannot queue without limit.
        while in_flight.len() >= MAX_IN_FLIGHT {
            tokio::select! {
                ended = in_flight.join_next() => forget(&mut by_id, ended.and_then(Result::ok).flatten()),
                _ = &mut shutdown => break 'serving true,
            }
        }
        while let Some(ended) = in_flight.try_join_next() {
            forget(&mut by_id, ended.ok().flatten());
        }

        let line = tokio::select! {
            line = read_line(&mut reader, max_line) => line,
            _ = &mut shutdown => break true,
        };
        let bytes = match line {
            Ok(Line::Text(bytes)) => bytes,
            Ok(Line::TooLong) => {
                let message = format!("Invalid Request: a message may be at most {max_line} bytes");
                tokio::select! {
                    _ = replies.send(error_reply(-32600, &message)) => {}
                    _ = &mut shutdown => break true,
                }
                continue;
            }
            Ok(Line::Eof) | Err(_) => break false,
        };
        if bytes.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let message: Value = match serde_json::from_slice(&bytes) {
            Ok(message) => message,
            Err(_) => {
                tokio::select! {
                    _ = replies.send(error_reply(-32700, "Parse error: not valid JSON")) => {}
                    _ = &mut shutdown => break true,
                }
                continue;
            }
        };
        if let Some(target) = cancelled_request(&message) {
            // Stop the call. Per the protocol a cancelled request gets no reply.
            if let Some((_, task)) = by_id.remove(&target) {
                task.abort();
            }
            continue;
        }

        let id = request_id(&message);
        started += 1;
        let number = started;
        let task = {
            let (server, session, replies, id) =
                (server.clone(), session.clone(), replies.clone(), id.clone());
            in_flight.spawn(async move {
                if let Some(reply) = server.handle_value(&session, message).await {
                    let _ = replies.send(reply).await;
                }
                id.map(|id| (id, number))
            })
        };
        if let Some(id) = id {
            by_id.insert(id, (number, task));
        }
    };

    if !stopped_by_signal {
        // The client closed its end: let what it already asked for run to completion,
        // and deliver the replies, unless we are told to stop first.
        let drained = async { while in_flight.join_next().await.is_some() {} };
        tokio::select! {
            _ = drained => {
                drop(replies);
                tokio::select! {
                    _ = &mut writer_task => {}
                    _ = &mut shutdown => writer_task.abort(),
                }
                return Ok(());
            }
            _ = &mut shutdown => {}
        }
    }
    // Told to stop: end the calls in progress, and do not wait on a client that may not
    // be reading.
    in_flight.shutdown().await;
    writer_task.abort();
    Ok(())
}

fn error_reply(code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": null, "error": {"code": code, "message": message}})
}

/// The id of a request, as a map key (`1` and `"1"` are different ids).
fn request_id(message: &Value) -> Option<String> {
    let id = message.get("id")?;
    (id.is_string() || id.is_number()).then(|| id.to_string())
}

/// For a `notifications/cancelled` message, the id of the request it cancels.
fn cancelled_request(message: &Value) -> Option<String> {
    if message.get("method")?.as_str()? != "notifications/cancelled" || message.get("id").is_some()
    {
        return None;
    }
    let target = message.get("params")?.get("requestId")?;
    (target.is_string() || target.is_number()).then(|| target.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::testing::Fixture;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, BufReader, DuplexStream};

    async fn lines_of(input: &[u8], max: usize) -> Vec<Line> {
        let mut reader = BufReader::with_capacity(8, input);
        let mut lines = Vec::new();
        loop {
            let line = read_line(&mut reader, max).await.unwrap();
            let done = line == Line::Eof;
            lines.push(line);
            if done {
                return lines;
            }
        }
    }

    fn text(s: &str) -> Line {
        Line::Text(s.as_bytes().to_vec())
    }

    #[tokio::test]
    async fn read_line_splits_on_newlines() {
        assert_eq!(
            lines_of(b"one\ntwo\n", 100).await,
            vec![text("one"), text("two"), Line::Eof]
        );
        assert_eq!(lines_of(b"", 100).await, vec![Line::Eof]);
        assert_eq!(lines_of(b"\n", 100).await, vec![text(""), Line::Eof]);
        // a final line without a newline still counts
        assert_eq!(
            lines_of(b"one\ntail", 100).await,
            vec![text("one"), text("tail"), Line::Eof]
        );
    }

    #[tokio::test]
    async fn read_line_skips_a_line_that_is_too_long_and_carries_on() {
        let input = b"0123456789ABCDEF\nok\n0123456789\n";
        assert_eq!(
            lines_of(input, 10).await,
            vec![Line::TooLong, text("ok"), text("0123456789"), Line::Eof]
        );
        // too long with no newline before the end
        assert_eq!(
            lines_of(b"0123456789ABC", 10).await,
            vec![Line::TooLong, Line::Eof]
        );
    }

    /// A served connection: write lines to `to_server`, read replies from `from_server`.
    struct Client {
        to_server: Option<DuplexStream>,
        from_server: BufReader<DuplexStream>,
        done: tokio::task::JoinHandle<std::io::Result<()>>,
    }

    fn connect(fx: &Fixture, user: &str) -> Client {
        let (to_server, server_in) = tokio::io::duplex(1 << 16);
        let (server_out, from_server) = tokio::io::duplex(1 << 16);
        let done = tokio::spawn(serve(
            fx.server.clone(),
            fx.session(user),
            BufReader::new(server_in),
            server_out,
            std::future::pending(),
        ));
        Client {
            to_server: Some(to_server),
            from_server: BufReader::new(from_server),
            done,
        }
    }

    impl Client {
        async fn send(&mut self, line: &str) {
            let pipe = self.to_server.as_mut().unwrap();
            pipe.write_all(line.as_bytes()).await.unwrap();
            pipe.write_all(b"\n").await.unwrap();
        }

        async fn reply(&mut self) -> Value {
            let mut line = String::new();
            let read = self.from_server.read_line(&mut line);
            let n = tokio::time::timeout(Duration::from_secs(10), read)
                .await
                .expect("a reply")
                .unwrap();
            assert!(n > 0, "the server closed the connection");
            assert!(line.ends_with('\n'));
            serde_json::from_str(&line).unwrap()
        }

        /// Closes our end and returns everything else the server wrote.
        async fn finish(mut self) -> String {
            drop(self.to_server.take());
            let mut rest = String::new();
            let read = self.from_server.read_to_string(&mut rest);
            tokio::time::timeout(Duration::from_secs(10), read)
                .await
                .expect("the server to finish")
                .unwrap();
            tokio::time::timeout(Duration::from_secs(10), self.done)
                .await
                .expect("serve to return")
                .unwrap()
                .unwrap();
            rest
        }
    }

    #[tokio::test]
    async fn each_request_line_gets_one_reply_line() {
        let fx = Fixture::new();
        let mut client = connect(&fx, "rita");
        client
            .send(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#)
            .await;
        assert_eq!(
            client.reply().await,
            json!({"jsonrpc": "2.0", "id": 1, "result": {}})
        );
        // a result with many lines of text still travels as one line
        client.send(r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"big","arguments":{}}}"#).await;
        let reply = client.reply().await;
        assert_eq!(reply["id"], 2);
        let text = reply["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with("line of text\nline of text\n"), "{text:?}");
        assert_eq!(client.finish().await, "");
    }

    #[tokio::test]
    async fn notifications_and_blank_lines_produce_no_output() {
        let fx = Fixture::new();
        let mut client = connect(&fx, "rita");
        client
            .send(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
            .await;
        client.send("").await;
        client.send("   ").await;
        client
            .send(r#"{"jsonrpc":"2.0","id":"last","method":"ping"}"#)
            .await;
        assert_eq!(client.reply().await["id"], "last");
        assert_eq!(client.finish().await, "");
    }

    #[tokio::test]
    async fn bad_lines_get_error_replies_and_do_not_end_the_session() {
        let fx = Fixture::new();
        let mut client = connect(&fx, "rita");
        client.send("{not json").await;
        assert_eq!(client.reply().await["error"]["code"], -32700);
        // larger than the configured request limit (1 MiB by default)
        let huge = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"ping","params":{{"pad":"{}"}}}}"#,
            "x".repeat(1 << 20)
        );
        client.send(&huge).await;
        let reply = client.reply().await;
        assert_eq!(reply["error"]["code"], -32600);
        assert_eq!(reply["id"], Value::Null);
        client
            .send(r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#)
            .await;
        assert_eq!(client.reply().await["id"], 3);
        client.finish().await;
    }

    #[tokio::test]
    async fn a_call_in_progress_is_finished_after_the_client_closes_its_end() {
        let fx = Fixture::new();
        let mut client = connect(&fx, "walt");
        client.send(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"touch","arguments":{"name":"alpha"}}}"#).await;
        let rest = client.finish().await;
        let reply: Value = serde_json::from_str(rest.trim_end()).unwrap();
        assert_eq!(reply["result"]["content"][0]["text"], "touched alpha");
        assert_eq!(fx.touched(), vec!["alpha".to_string()]);
    }

    #[tokio::test]
    async fn a_cancelled_request_is_stopped_and_never_answered() {
        let fx = Fixture::new();
        let mut client = connect(&fx, "rita");
        client.send(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"slow","arguments":{}}}"#).await;
        client.send(r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1,"reason":"user"}}"#).await;
        client
            .send(r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#)
            .await;
        assert_eq!(client.reply().await["id"], 2);
        // `slow` would otherwise hold the session open until the 5 second call limit
        let started = std::time::Instant::now();
        assert_eq!(client.finish().await, "");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn a_shutdown_signal_stops_calls_in_progress_and_ends_the_session() {
        let fx = Fixture::new();
        let (mut to_server, server_in) = tokio::io::duplex(1 << 16);
        let (server_out, _from_server) = tokio::io::duplex(1 << 16);
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let done = tokio::spawn(serve(
            fx.server.clone(),
            fx.session("rita"),
            BufReader::new(server_in),
            server_out,
            async move {
                let _ = stopped.await;
            },
        ));
        let call = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"slow","arguments":{}}}"#;
        to_server
            .write_all(format!("{call}\n").as_bytes())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!done.is_finished(), "the session should still be open");

        let started = std::time::Instant::now();
        stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(3), done)
            .await
            .expect("serve to return")
            .unwrap()
            .unwrap();
        // well before the slow tool's 5 second call limit
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    /// Starts a session whose output pipe holds only `out_capacity` bytes, and returns
    /// the pieces: the pipe to write requests to, the (unread) output, a trigger for
    /// shutdown, and the session task.
    fn manual(
        fx: &Fixture,
        out_capacity: usize,
    ) -> (
        DuplexStream,
        DuplexStream,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<std::io::Result<()>>,
    ) {
        let (to_server, server_in) = tokio::io::duplex(1 << 20);
        let (server_out, from_server) = tokio::io::duplex(out_capacity);
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let done = tokio::spawn(serve(
            fx.server.clone(),
            fx.session("rita"),
            BufReader::new(server_in),
            server_out,
            async move {
                let _ = stopped.await;
            },
        ));
        (to_server, from_server, stop, done)
    }

    async fn ends_within(done: tokio::task::JoinHandle<std::io::Result<()>>, limit: Duration) {
        let started = std::time::Instant::now();
        tokio::time::timeout(limit, done)
            .await
            .unwrap_or_else(|_| panic!("the session was still running after {limit:?}"))
            .unwrap()
            .unwrap();
        assert!(started.elapsed() < limit);
    }

    #[tokio::test]
    async fn shutdown_ends_a_session_whose_client_has_stopped_reading() {
        let fx = Fixture::new();
        // a tiny output pipe that nobody reads: replies back up, then requests do
        let (mut to_server, _unread, stop, done) = manual(&fx, 64);
        for id in 0..200 {
            let request = format!(
                r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"echo","arguments":{{"text":"t"}}}}}}"#
            );
            to_server
                .write_all(format!("{request}\n").as_bytes())
                .await
                .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!done.is_finished());
        stop.send(()).unwrap();
        ends_within(done, Duration::from_secs(2)).await;
    }

    #[tokio::test]
    async fn shutdown_is_honoured_after_the_client_has_closed_its_end() {
        let fx = Fixture::new();
        let (mut to_server, _output, stop, done) = manual(&fx, 1 << 16);
        let call = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"slow","arguments":{}}}"#;
        to_server
            .write_all(format!("{call}\n").as_bytes())
            .await
            .unwrap();
        drop(to_server);
        tokio::time::sleep(Duration::from_millis(100)).await;
        // the session is waiting for the call it was given (which would take 5 seconds)
        assert!(!done.is_finished());
        stop.send(()).unwrap();
        ends_within(done, Duration::from_secs(2)).await;
    }

    #[tokio::test]
    async fn a_reused_request_id_cancels_the_request_that_now_holds_it() {
        let fx = Fixture::new();
        let mut client = connect(&fx, "rita");
        // the same id twice: a quick call, then one that would run for 5 seconds
        client.send(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"quick"}}}"#).await;
        client.send(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"slow","arguments":{}}}"#).await;
        assert_eq!(
            client.reply().await["result"]["content"][0]["text"],
            "quick"
        );
        client
            .send(r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#)
            .await;
        assert_eq!(client.reply().await["id"], 2);
        client
            .send(
                r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}"#,
            )
            .await;
        let started = std::time::Instant::now();
        assert_eq!(client.finish().await, "");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn cancelling_an_unknown_request_is_harmless() {
        let fx = Fixture::new();
        let mut client = connect(&fx, "rita");
        client
            .send(
                r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":99}}"#,
            )
            .await;
        client
            .send(r#"{"jsonrpc":"2.0","method":"notifications/cancelled"}"#)
            .await;
        client
            .send(r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#)
            .await;
        assert_eq!(client.reply().await["id"], 2);
        client.finish().await;
    }

    #[tokio::test]
    async fn many_requests_at_once_are_all_answered() {
        let fx = Fixture::new();
        let mut client = connect(&fx, "rita");
        for id in 0..100 {
            client.send(&format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"echo","arguments":{{"text":"t{id}"}}}}}}"#)).await;
        }
        let mut seen = Vec::new();
        for _ in 0..100 {
            let reply = client.reply().await;
            let id = reply["id"].as_u64().unwrap();
            assert_eq!(reply["result"]["content"][0]["text"], format!("t{id}"));
            seen.push(id);
        }
        seen.sort_unstable();
        assert_eq!(seen, (0..100).collect::<Vec<u64>>());
        client.finish().await;
    }
}
