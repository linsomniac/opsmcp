//! Diagnostics on stderr. (stdout belongs to the MCP protocol in stdio mode; the audit
//! trail is separate, see `audit`.)

use std::io::Write;

use log::{Level, LevelFilter, Log, Metadata, Record};

use crate::sanitize::clean_text;

struct Stderr;

impl Log for Stderr {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let level = match record.level() {
            Level::Error => "error",
            Level::Warn => "warning",
            Level::Info => "info",
            Level::Debug | Level::Trace => "debug",
        };
        // Messages can quote data from peers and from the host: keep them to one clean line.
        let message = clean_text(record.args().to_string().as_bytes()).replace('\n', "\\n");
        // AIDEV-NOTE: not `eprintln!`, which panics when stderr cannot be written to
        // (whoever was reading it has gone). A diagnostic that cannot be delivered is
        // dropped; it must never end the part of the server that had something to say,
        // such as the task that keeps a fleet's inventory current.
        let _ = writeln!(std::io::stderr(), "opsmcp: {level}: {message}");
    }

    fn flush(&self) {}
}

/// Starts logging to stderr. Calling it twice is harmless.
pub fn init(verbose: bool) {
    let level = if verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    if log::set_logger(&Stderr).is_ok() {
        log::set_max_level(level);
    }
}
