//! The audit trail: who asked for what, whether it was allowed, and how it ended.
//!
//! Records are single-line JSON objects. They go to the local syslog (so the host's
//! normal log shipping carries them off the machine) and optionally to a file.
//!
//! AIDEV-NOTE: with `fail_closed` (the default) a tool does not run unless its audit
//! record was written to every configured sink. Do not weaken that to "any sink".

use std::io::{ErrorKind, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use serde_json::{Map, Value};

use crate::config::AuditCfg;
use crate::timefmt::{now_secs, rfc3339_utc, utc_parts};

pub const SYSLOG_SOCKET: &str = "/dev/log";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Info,
    /// Denials and failures.
    Warning,
}

/// Somewhere audit records are written.
pub trait Sink: Send + Sync {
    fn write(&self, line: &str, severity: Severity) -> Result<(), String>;
    /// For messages: where this sink writes.
    fn describe(&self) -> String;
}

pub struct Audit {
    sinks: Vec<Box<dyn Sink>>,
    fail_closed: bool,
}

impl Audit {
    pub fn with_sinks(sinks: Vec<Box<dyn Sink>>, fail_closed: bool) -> Audit {
        Audit { sinks, fail_closed }
    }

    /// Opens the sinks the configuration asks for. Fails if one cannot be opened.
    pub fn open(cfg: &AuditCfg) -> Result<Audit, String> {
        let mut sinks: Vec<Box<dyn Sink>> = Vec::new();
        if cfg.syslog {
            let sink = SyslogSink::connect(Path::new(SYSLOG_SOCKET)).map_err(|e| {
                format!("{e} (set audit.syslog = false to run without syslog auditing)")
            })?;
            sinks.push(Box::new(sink));
        }
        if let Some(path) = &cfg.file {
            sinks.push(Box::new(FileSink::open(path)?));
        }
        Ok(Audit::with_sinks(sinks, cfg.fail_closed))
    }

    /// Problems that would stop auditing from working on this host, found without
    /// writing anything: for `opsmcp check-config`.
    pub fn problems(cfg: &AuditCfg) -> Vec<String> {
        let mut problems = Vec::new();
        if cfg.syslog
            && let Err(e) = SyslogSink::connect(Path::new(SYSLOG_SOCKET))
        {
            problems.push(format!("audit.syslog: {e}"));
        }
        if let Some(file) = &cfg.file {
            let parent = file.parent().unwrap_or(Path::new("/"));
            if !parent.is_dir() {
                problems.push(format!(
                    "audit.file: the directory {} does not exist",
                    parent.display()
                ));
            }
        }
        problems
    }

    /// Where records go, for the startup message.
    pub fn describe(&self) -> Vec<String> {
        self.sinks.iter().map(|s| s.describe()).collect()
    }

    /// Writes one record (a JSON object; a timestamp is added). Returns an error only
    /// when a sink failed and the configuration says to fail closed.
    pub fn record(&self, severity: Severity, event: Value) -> Result<(), String> {
        let Value::Object(fields) = event else {
            return Err("an audit record must be a JSON object".to_string());
        };
        let mut record = Map::new();
        record.insert("ts".to_string(), Value::String(rfc3339_utc(now_secs())));
        record.extend(fields);
        // serde_json escapes every control character, so a record is always one line.
        let line = serde_json::to_string(&Value::Object(record))
            .map_err(|e| format!("cannot encode audit record: {e}"))?;

        let failures: Vec<String> = self
            .sinks
            .iter()
            .filter_map(|sink| {
                sink.write(&line, severity)
                    .err()
                    .map(|e| format!("{}: {e}", sink.describe()))
            })
            .collect();
        if failures.is_empty() {
            return Ok(());
        }
        let message = format!("audit record not written ({})", failures.join("; "));
        log::error!("{message}");
        if self.fail_closed {
            Err(message)
        } else {
            Ok(())
        }
    }
}

const MAX_AUDIT_STRING: usize = 256;

fn shrink(value: &Value) -> Value {
    match value {
        Value::String(text) if text.len() > MAX_AUDIT_STRING => {
            Value::String(cut(text, MAX_AUDIT_STRING))
        }
        Value::Array(items) => Value::Array(items.iter().map(shrink).collect()),
        Value::Object(fields) => {
            Value::Object(fields.iter().map(|(k, v)| (k.clone(), shrink(v))).collect())
        }
        other => other.clone(),
    }
}

/// The first `keep` bytes of `text` (on a character boundary) and a note of its size.
fn cut(text: &str, keep: usize) -> String {
    let mut end = keep.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...[{} bytes]", &text[..end], text.len())
}

/// Tool arguments as they go into an audit record. Arguments whose JSON fits in
/// `max_total` bytes are kept exactly as given. Larger ones are shortened (long strings
/// cut, or the whole replaced by the start of its JSON text) and the flag is true.
pub fn bounded_args(args: &Value, max_total: usize) -> (Value, bool) {
    let fits =
        |value: &Value| serde_json::to_string(value).is_ok_and(|text| text.len() <= max_total);
    if fits(args) {
        return (args.clone(), false);
    }
    let shrunk = shrink(args);
    if fits(&shrunk) {
        return (shrunk, true);
    }
    let text = serde_json::to_string(&shrunk).unwrap_or_default();
    // Half the limit, because quoting the JSON text as a string can double its size.
    (Value::String(cut(&text, max_total / 2)), true)
}

/// The classic syslog datagram: `<PRI>Mmm dd hh:mm:ss opsmcp[PID]: MESSAGE`.
/// `priority` is facility*8 + severity. The timestamp is UTC.
pub fn syslog_frame(priority: u8, unix_secs: i64, pid: u32, message: &str) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let t = utc_parts(unix_secs);
    let month = usize::try_from(t.month - 1)
        .ok()
        .and_then(|i| MONTHS.get(i))
        .copied()
        .unwrap_or("Jan");
    format!(
        "<{priority}>{month} {:>2} {:02}:{:02}:{:02} opsmcp[{pid}]: {message}",
        t.day, t.hour, t.minute, t.second
    )
}

/// How long one record may wait for the syslog daemon to take it. The daemon normally
/// takes a datagram at once; this only matters when it is stuck.
const SYSLOG_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

/// Syslog facility authpriv: security and authorization messages.
const FACILITY_AUTHPRIV: u8 = 10;

fn open_syslog(path: &Path) -> Result<UnixDatagram, String> {
    let socket = UnixDatagram::unbound().map_err(|e| format!("cannot create a socket: {e}"))?;
    socket
        .connect(path)
        .map_err(|e| format!("cannot connect to syslog at {}: {e}", path.display()))?;
    // A stuck syslog daemon must not hang the server: give up and report the failure.
    socket
        .set_write_timeout(Some(SYSLOG_SEND_TIMEOUT))
        .map_err(|e| format!("cannot set a timeout on the syslog socket: {e}"))?;
    Ok(socket)
}

/// Writes to the local syslog daemon's datagram socket.
pub struct SyslogSink {
    path: PathBuf,
    socket: Mutex<Option<UnixDatagram>>,
}

impl SyslogSink {
    pub fn connect(path: &Path) -> Result<SyslogSink, String> {
        let socket = open_syslog(path)?;
        Ok(SyslogSink {
            path: path.to_path_buf(),
            socket: Mutex::new(Some(socket)),
        })
    }
}

impl Sink for SyslogSink {
    fn write(&self, line: &str, severity: Severity) -> Result<(), String> {
        let level = match severity {
            Severity::Info => 6,
            Severity::Warning => 4,
        };
        let frame = syslog_frame(
            FACILITY_AUTHPRIV * 8 + level,
            now_secs(),
            std::process::id(),
            line,
        );
        let mut socket = self.socket.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(connected) = socket.as_ref() {
            match connected.send(frame.as_bytes()) {
                Ok(_) => return Ok(()),
                // AIDEV-NOTE: the daemon is there but not reading (its queue is full).
                // Reconnecting would only wait a second time; report it now. With
                // fail_closed the call is then refused, which is the point: a stuck
                // audit sink must not turn into a stuck server.
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    return Err("syslog is not accepting messages (timed out)".to_string());
                }
                Err(_) => {}
            }
        }
        // The daemon may have restarted (a new socket at the same path): reconnect once.
        *socket = None;
        let fresh = open_syslog(&self.path)?;
        fresh
            .send(frame.as_bytes())
            .map_err(|e| format!("cannot send to syslog: {e}"))?;
        *socket = Some(fresh);
        Ok(())
    }

    fn describe(&self) -> String {
        format!("syslog ({})", self.path.display())
    }
}

/// Appends records to a file, one per line.
pub struct FileSink {
    path: PathBuf,
    file: Mutex<std::fs::File>,
}

impl FileSink {
    /// Opens (creating if needed, mode 0600) the file for appending.
    pub fn open(path: &Path) -> Result<FileSink, String> {
        let file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("cannot open audit file {}: {e}", path.display()))?;
        Ok(FileSink {
            path: path.to_path_buf(),
            file: Mutex::new(file),
        })
    }
}

impl Sink for FileSink {
    fn write(&self, line: &str, _severity: Severity) -> Result<(), String> {
        // One write per record, so concurrent appenders never interleave within a line.
        let mut data = String::with_capacity(line.len() + 1);
        data.push_str(line);
        data.push('\n');
        let mut file = self.file.lock().unwrap_or_else(PoisonError::into_inner);
        file.write_all(data.as_bytes())
            .map_err(|e| format!("cannot write: {e}"))
    }

    fn describe(&self) -> String {
        format!("file {}", self.path.display())
    }
}

#[cfg(test)]
pub mod testing {
    //! An in-memory sink for tests of code that audits.
    use super::*;
    use std::sync::Arc;

    #[derive(Clone, Default)]
    pub struct MemorySink {
        pub lines: Arc<Mutex<Vec<String>>>,
        pub fail: Arc<Mutex<bool>>,
    }

    impl MemorySink {
        /// The records written so far, parsed.
        pub fn records(&self) -> Vec<Value> {
            let lines = self.lines.lock().unwrap();
            lines
                .iter()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        }

        pub fn set_failing(&self, failing: bool) {
            *self.fail.lock().unwrap() = failing;
        }
    }

    impl Sink for MemorySink {
        fn write(&self, line: &str, _severity: Severity) -> Result<(), String> {
            if *self.fail.lock().unwrap() {
                return Err("sink is failing".to_string());
            }
            self.lines.lock().unwrap().push(line.to_string());
            Ok(())
        }

        fn describe(&self) -> String {
            "memory".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::MemorySink;
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn a_record_is_one_json_line_with_a_timestamp_first() {
        let sink = MemorySink::default();
        let audit = Audit::with_sinks(vec![Box::new(sink.clone())], true);
        audit
            .record(
                Severity::Info,
                json!({"event": "tool_call", "tool": "service_status"}),
            )
            .unwrap();
        let lines = sink.lines.lock().unwrap().clone();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with("{\"ts\":\"20"), "{}", lines[0]);
        let record = &sink.records()[0];
        assert_eq!(record["event"], "tool_call");
        assert_eq!(record["tool"], "service_status");
        let ts = record["ts"].as_str().unwrap();
        assert_eq!(ts.len(), 20, "{ts}");
        assert!(ts.ends_with('Z'), "{ts}");
    }

    #[test]
    fn a_value_with_a_newline_cannot_forge_a_second_record() {
        let sink = MemorySink::default();
        let audit = Audit::with_sinks(vec![Box::new(sink.clone())], true);
        let forged = "x\n{\"event\":\"tool_call\",\"decision\":\"allow\"}";
        audit
            .record(Severity::Info, json!({"event": "e", "arg": forged}))
            .unwrap();
        let lines = sink.lines.lock().unwrap().clone();
        assert_eq!(lines.len(), 1);
        assert!(!lines[0].contains('\n'));
        assert_eq!(sink.records()[0]["arg"], forged);
    }

    #[test]
    fn a_failing_sink_is_an_error_only_when_failing_closed() {
        let good = MemorySink::default();
        let bad = MemorySink::default();
        bad.set_failing(true);

        let closed = Audit::with_sinks(vec![Box::new(good.clone()), Box::new(bad.clone())], true);
        assert!(
            closed
                .record(Severity::Info, json!({"event": "e"}))
                .is_err()
        );

        let open = Audit::with_sinks(vec![Box::new(good.clone()), Box::new(bad.clone())], false);
        assert!(open.record(Severity::Info, json!({"event": "e"})).is_ok());
        // the working sink still got both records
        assert_eq!(good.records().len(), 2);
    }

    #[test]
    fn a_record_that_is_not_an_object_is_refused() {
        let audit = Audit::with_sinks(vec![Box::new(MemorySink::default())], true);
        assert!(audit.record(Severity::Info, json!("just text")).is_err());
    }

    #[test]
    fn bounded_args_keeps_arguments_that_fit_exactly_as_given() {
        let args = json!({"unit": "nginx.service", "grep": "x".repeat(1000), "lines": 50});
        assert_eq!(bounded_args(&args, 4000), (args.clone(), false));
    }

    #[test]
    fn bounded_args_cuts_what_does_not_fit_and_says_so() {
        let args = json!({"unit": "nginx.service", "grep": "x".repeat(1000), "lines": 50});
        let (bounded, cut) = bounded_args(&args, 500);
        assert!(cut);
        assert_eq!(bounded["unit"], "nginx.service");
        assert_eq!(bounded["lines"], 50);
        let grep = bounded["grep"].as_str().unwrap();
        assert!(grep.len() < 400, "{}", grep.len());
        assert!(grep.starts_with("xxxxxxxx"));
        assert!(grep.contains("1000"), "should say how long it was: {grep}");
    }

    #[test]
    fn bounded_args_never_exceeds_the_total_limit() {
        let many: Vec<String> = (0..100).map(|_| "y".repeat(100)).collect();
        let (bounded, cut) = bounded_args(&json!({"rule": many}), 1500);
        assert!(cut);
        let size = serde_json::to_string(&bounded).unwrap().len();
        assert!(size <= 1600, "bounded args are {size} bytes");
    }

    #[test]
    fn syslog_frame_uses_the_classic_format() {
        assert_eq!(
            syslog_frame(86, 1_795_091_696, 4242, "{\"a\":1}"),
            "<86>Nov 19 12:34:56 opsmcp[4242]: {\"a\":1}"
        );
        // single-digit days are padded with a space, as syslog(3) does
        assert_eq!(
            syslog_frame(84, 1_794_182_400, 1, "x"),
            "<84>Nov  9 00:00:00 opsmcp[1]: x"
        );
    }

    fn receive(socket: &UnixDatagram) -> String {
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut buf = [0u8; 4096];
        let n = socket.recv(&mut buf).unwrap();
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }

    #[test]
    fn the_syslog_sink_sends_framed_datagrams_with_the_right_priority() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let daemon = UnixDatagram::bind(&path).unwrap();
        let sink = SyslogSink::connect(&path).unwrap();

        sink.write("{\"event\":\"x\"}", Severity::Info).unwrap();
        let got = receive(&daemon);
        // authpriv (10) * 8 + info (6)
        assert!(got.starts_with("<86>"), "{got}");
        assert!(
            got.ends_with(&format!(
                "opsmcp[{}]: {{\"event\":\"x\"}}",
                std::process::id()
            )),
            "{got}"
        );

        sink.write("{}", Severity::Warning).unwrap();
        // authpriv (10) * 8 + warning (4)
        assert!(receive(&daemon).starts_with("<84>"));
    }

    #[test]
    fn the_syslog_sink_reconnects_after_the_daemon_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let first = UnixDatagram::bind(&path).unwrap();
        let sink = SyslogSink::connect(&path).unwrap();
        sink.write("one", Severity::Info).unwrap();
        assert!(receive(&first).ends_with("one"));

        drop(first);
        std::fs::remove_file(&path).unwrap();
        let second = UnixDatagram::bind(&path).unwrap();
        sink.write("two", Severity::Info).unwrap();
        assert!(receive(&second).ends_with("two"));
    }

    #[test]
    fn a_syslog_daemon_that_has_stopped_reading_fails_writes_quickly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let _stuck_daemon = UnixDatagram::bind(&path).unwrap();
        let sink = SyslogSink::connect(&path).unwrap();
        // fill the daemon's queue; then a write cannot be delivered
        let mut slowest = std::time::Duration::ZERO;
        let mut failed = false;
        for _ in 0..100_000 {
            let started = std::time::Instant::now();
            let result = sink.write("{\"event\":\"x\"}", Severity::Info);
            slowest = slowest.max(started.elapsed());
            if result.is_err() {
                failed = true;
                break;
            }
        }
        assert!(
            failed,
            "writes to a daemon that never reads cannot all succeed"
        );
        // the caller is told promptly rather than being held up
        assert!(
            slowest < std::time::Duration::from_millis(1500),
            "a write took {slowest:?}"
        );
    }

    #[test]
    fn the_syslog_sink_fails_when_there_is_no_daemon() {
        let dir = tempfile::tempdir().unwrap();
        assert!(SyslogSink::connect(&dir.path().join("absent")).is_err());
    }

    #[test]
    fn the_file_sink_appends_lines_to_a_private_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = FileSink::open(&path).unwrap();
        sink.write("one", Severity::Info).unwrap();
        sink.write("two", Severity::Info).unwrap();
        drop(sink);
        // reopening must append, never truncate
        let sink = FileSink::open(&path).unwrap();
        sink.write("three", Severity::Info).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "one\ntwo\nthree\n");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn the_file_sink_reports_a_path_it_cannot_open() {
        assert!(FileSink::open(Path::new("/nonexistent-dir/audit.jsonl")).is_err());
    }
}
