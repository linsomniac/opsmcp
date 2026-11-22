//! Logs: files under the configured log directories, the systemd journal, and the kernel
//! message buffer.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;

use regex::Regex;

use super::args::{Args, Param};
use super::fs::{check_limits, dir_resource, list_directory, pin};
use super::service::normalize_unit;
use super::{Ctx, Tool, ToolError, ToolResult, blocking, command_ok, command_text_tail, required};
use crate::policy::Access;
use crate::sanitize::{keep_head, keep_tail};
use crate::timefmt::{human_bytes, now_secs, rfc3339_utc};

/// Most bytes of a log (after decompression) examined for one request.
const MAX_SCAN_BYTES: u64 = 64 * 1024 * 1024;
/// Longest line returned; longer ones are cut.
const MAX_LINE_BYTES: usize = 16 * 1024;
const LINE_CUT_MARK: &str = " ...[line cut]";

pub fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "log_list",
            "List log files: name, size and modification time. Without a directory, lists \
             each log directory this host's configuration allows (usually /var/log).",
            Access::Read,
            "logs.view",
            vec![
                Param::str("dir", "Absolute path of a log directory or subdirectory").max_len(4096),
                Param::int(
                    "limit",
                    "Most entries to show per directory (default 200)",
                    1,
                    2000,
                ),
            ],
            log_list,
        ),
        Tool::new(
            "log_read",
            "Read lines from a log file: the last lines by default, or the first with \
             from=head. Optionally keep only lines matching a regular expression. Reads \
             gzip-compressed (rotated) logs too. For the systemd journal use journal_query.",
            Access::Read,
            "logs.view",
            vec![
                Param::str("path", "Absolute path of the log file")
                    .max_len(4096)
                    .required(),
                Param::int("lines", "Number of lines to return (default 100)", 1, 5000),
                Param::choice(
                    "from",
                    "Which end of the file to read (default tail)",
                    &["tail", "head"],
                ),
                Param::str("grep", "Only lines matching this regular expression").max_len(256),
                Param::bool("ignore_case", "Match grep without regard to case"),
            ],
            log_read,
        ),
        Tool::new(
            "journal_query",
            "Query the systemd journal (journalctl): the most recent entries, optionally for \
             one unit, a priority, a time range or a pattern.",
            Access::Read,
            "journal.view",
            journal_params(),
            journal_query,
        ),
        Tool::new(
            "kernel_log",
            "Show the kernel message buffer (what dmesg shows): the most recent messages, \
             optionally only those at or above a severity or matching a regular expression.",
            Access::Read,
            "kernel_log.view",
            vec![
                Param::int(
                    "lines",
                    "Number of messages to return (default 200)",
                    1,
                    5000,
                ),
                Param::choice(
                    "level",
                    "Least severe level to include (default debug: everything)",
                    &LEVELS,
                ),
                Param::str("grep", "Only messages matching this regular expression").max_len(256),
                Param::bool("ignore_case", "Match grep without regard to case"),
            ],
            kernel_log,
        ),
    ]
}

/// Syslog severities, most severe first; the index is the numeric level.
pub(super) const LEVELS: [&str; 8] = [
    "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
];

/// Compiles a caller-supplied pattern. The regex engine used is linear-time, so a
/// hostile pattern cannot make matching slow; the size limit bounds memory.
pub fn compile_pattern(args: &Args) -> Result<Option<Regex>, ToolError> {
    let Some(pattern) = args.str("grep") else {
        return Ok(None);
    };
    regex::RegexBuilder::new(pattern)
        .case_insensitive(args.bool("ignore_case").unwrap_or(false))
        .size_limit(1 << 20)
        .build()
        .map(Some)
        .map_err(|e| ToolError::Invalid(format!("grep is not a valid regular expression: {e}")))
}

/// What to take from a log.
pub struct ReadOpts {
    pub lines: usize,
    pub from_tail: bool,
    pub pattern: Option<Regex>,
}

/// Lines taken from a log, and notes about anything that limited the reading.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Excerpt {
    pub lines: Vec<String>,
    pub notes: Vec<String>,
}

/// The byte offset at which the last `lines` lines of a plain file start. Reads backwards
/// in blocks, so a huge file costs no more than its tail. The flag is true when the scan
/// budget ran out first (the returned offset is then mid-line).
pub fn tail_offset(file: &mut File, size: u64, lines: usize) -> std::io::Result<(u64, bool)> {
    const BLOCK: u64 = 64 * 1024;
    if size == 0 || lines == 0 {
        return Ok((0, false));
    }
    let mut block = vec![0u8; BLOCK as usize];
    let mut found = 0;
    let mut pos = size;
    while pos > 0 {
        if size - pos >= MAX_SCAN_BYTES {
            return Ok((pos, true));
        }
        let start = pos.saturating_sub(BLOCK);
        let len = usize::try_from(pos - start).unwrap_or(0);
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(&mut block[..len])?;
        for index in (0..len).rev() {
            if block[index] != b'\n' {
                continue;
            }
            let at = start + index as u64;
            if at == size - 1 {
                continue; // the newline that ends the last line, not a line boundary
            }
            found += 1;
            if found == lines {
                return Ok((at + 1, false));
            }
        }
        pos = start;
    }
    Ok((0, false))
}

/// The compression format named by a file's first bytes, if it is one we cannot read.
fn unsupported_compression(magic: &[u8]) -> Option<&'static str> {
    if magic.starts_with(b"\xfd7zXZ\x00") {
        Some("xz")
    } else if magic.starts_with(b"\x28\xb5\x2f\xfd") {
        Some("zstd")
    } else if magic.starts_with(b"BZh") {
        Some("bzip2")
    } else {
        None
    }
}

/// Reads one line into `line`, without its newline (or CR LF), keeping at most
/// `MAX_LINE_BYTES` of it. Returns how many bytes were consumed (0 at the end of input)
/// and whether the line had to be cut.
fn next_line<R: BufRead>(reader: &mut R, line: &mut Vec<u8>) -> std::io::Result<(u64, bool)> {
    line.clear();
    let mut consumed = 0u64;
    let mut cut = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            break;
        }
        let newline = available.iter().position(|b| *b == b'\n');
        let chunk = &available[..newline.unwrap_or(available.len())];
        let room = MAX_LINE_BYTES.saturating_sub(line.len());
        if chunk.len() > room {
            cut = true;
        }
        line.extend_from_slice(&chunk[..chunk.len().min(room)]);
        let used = chunk.len() + usize::from(newline.is_some());
        reader.consume(used);
        consumed += used as u64;
        if newline.is_some() {
            break;
        }
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    Ok((consumed, cut))
}

/// Collects the wanted lines from `reader`: the first `opts.lines` matches, or (from the
/// tail) the last ones. Stops after `MAX_SCAN_BYTES`.
fn scan<R: BufRead>(mut reader: R, opts: &ReadOpts, excerpt: &mut Excerpt) -> Result<(), String> {
    let io = |e: std::io::Error| e.to_string();
    if reader.fill_buf().map_err(io)?.contains(&0) {
        return Err("it looks like a binary file, not text".to_string());
    }
    let mut kept: VecDeque<String> = VecDeque::new();
    let mut scanned = 0u64;
    let mut line = Vec::new();
    loop {
        let (consumed, cut) = next_line(&mut reader, &mut line).map_err(io)?;
        if consumed == 0 {
            break;
        }
        scanned += consumed;
        let mut text = String::from_utf8_lossy(&line).into_owned();
        if cut {
            text.push_str(LINE_CUT_MARK);
        }
        if opts.pattern.as_ref().is_none_or(|p| p.is_match(&text)) {
            kept.push_back(text);
            if !opts.from_tail && kept.len() >= opts.lines {
                break;
            }
            if opts.from_tail && kept.len() > opts.lines {
                kept.pop_front();
            }
        }
        if scanned >= MAX_SCAN_BYTES {
            excerpt.notes.push(format!(
                "stopped after examining {} of the file",
                human_bytes(MAX_SCAN_BYTES)
            ));
            break;
        }
    }
    excerpt.lines = kept.into();
    Ok(())
}

/// Reads the wanted lines from an open log file (plain text or gzip).
pub fn read_log(mut file: File, size: u64, opts: &ReadOpts) -> Result<Excerpt, String> {
    let io = |e: std::io::Error| e.to_string();
    let mut magic = Vec::new();
    (&mut file).take(6).read_to_end(&mut magic).map_err(io)?;
    if let Some(kind) = unsupported_compression(&magic) {
        return Err(format!(
            "it is {kind}-compressed, which is not supported (gzip is)"
        ));
    }
    file.seek(SeekFrom::Start(0)).map_err(io)?;
    let mut excerpt = Excerpt::default();

    if magic.starts_with(&[0x1f, 0x8b]) {
        // No seeking in a compressed stream: read it through, keeping what is wanted.
        let reader = BufReader::new(flate2::read::MultiGzDecoder::new(file));
        scan(reader, opts, &mut excerpt)?;
        if opts.from_tail && !excerpt.notes.is_empty() {
            // The scan stopped before the end: these are not the file's last lines.
            excerpt.notes = vec![format!(
                "this compressed log is larger than {} unpacked: these lines are the last \
                 within its first {}, NOT the end of the file",
                human_bytes(MAX_SCAN_BYTES),
                human_bytes(MAX_SCAN_BYTES)
            )];
        }
        return Ok(excerpt);
    }

    // Plain text. From the tail, start as close to the end as possible.
    let mut start = 0;
    let mut mid_line = false;
    if opts.from_tail {
        if opts.pattern.is_none() {
            (start, mid_line) = tail_offset(&mut file, size, opts.lines).map_err(io)?;
        } else if size > MAX_SCAN_BYTES {
            (start, mid_line) = (size - MAX_SCAN_BYTES, true);
        }
    }
    file.seek(SeekFrom::Start(start)).map_err(io)?;
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    if mid_line {
        excerpt.notes.push(format!(
            "only the last {} of the file were examined",
            human_bytes(MAX_SCAN_BYTES)
        ));
        let mut partial = Vec::new();
        next_line(&mut reader, &mut partial).map_err(io)?;
    }
    scan(reader, opts, &mut excerpt)?;
    Ok(excerpt)
}

async fn log_list(ctx: Ctx, args: Args) -> ToolResult {
    let asked = args.str("dir").map(str::to_string);
    let limit = usize::try_from(args.int("limit").unwrap_or(200)).unwrap_or(200);
    blocking(ctx.clone(), move || {
        let dirs: Vec<String> = match &asked {
            Some(dir) => vec![dir.clone()],
            None => ctx
                .cfg()
                .logs
                .dirs
                .iter()
                .map(|d| d.to_string_lossy().into_owned())
                .collect(),
        };
        let mut text = String::new();
        let mut auth = None;
        for dir in dirs {
            let opened = match pin(&ctx, &dir, true, &ctx.cfg().logs.dirs, "logs.dirs") {
                Ok(opened) => opened,
                // A configured directory that does not exist on this host is not an error.
                Err(ToolError::Failed(problem)) if asked.is_none() => {
                    text.push_str(&format!("[{problem}]\n"));
                    continue;
                }
                Err(e) => return Err(e),
            };
            let resource = dir_resource(&opened.real);
            check_limits(
                &ctx,
                &opened.real,
                &resource,
                &ctx.cfg().logs.dirs,
                "logs.dirs",
            )?;
            if !opened.meta.is_dir() {
                return Err(ToolError::Invalid(format!(
                    "{} is not a directory",
                    opened.real
                )));
            }
            auth = Some(ctx.authorize(Some(&resource))?);
            text.push_str(&list_directory(&opened, limit)?);
        }
        match auth {
            Some(auth) => auth.ok(text),
            None => Err(ToolError::Failed(format!(
                "none of the configured log directories exist on this host\n{text}"
            ))),
        }
    })
    .await
}

async fn log_read(ctx: Ctx, args: Args) -> ToolResult {
    let path = required(&args, "path")?.to_string();
    let opts = ReadOpts {
        lines: usize::try_from(args.int("lines").unwrap_or(100)).unwrap_or(100),
        from_tail: args.str("from") != Some("head"),
        pattern: compile_pattern(&args)?,
    };
    blocking(ctx.clone(), move || {
        let opened = pin(&ctx, &path, true, &ctx.cfg().logs.dirs, "logs.dirs")?;
        let real = opened.real.clone();
        check_limits(&ctx, &real, &real, &ctx.cfg().logs.dirs, "logs.dirs")?;
        if !opened.meta.is_file() {
            return Err(ToolError::Invalid(format!("{real} is not a regular file")));
        }
        let auth = ctx.authorize(Some(&real))?;

        let failed = |e: String| ToolError::Failed(format!("{real}: {e}"));
        let file = opened.reopen_read().map_err(|e| failed(e.to_string()))?;
        let excerpt = read_log(file, opened.meta.len(), &opts).map_err(failed)?;

        let mut body: String = excerpt.lines.iter().map(|line| format!("{line}\n")).collect();
        let mut notes = excerpt.notes.clone();
        if opts.from_tail {
            // AIDEV-NOTE: when the tail is too big to return, it is the OLDEST lines
            // that go. Left to the final cut (which keeps the start of the text), a
            // "last 1000 lines" would silently lose its newest lines instead.
            let (kept, dropped) = keep_tail(&body, ctx.output_budget());
            if dropped > 0 {
                notes.push(format!(
                    "{dropped} older lines were left out to fit the output limit: ask for fewer lines, or narrow them with grep"
                ));
            }
            body = kept;
        } else {
            let (kept, dropped) = keep_head(&body, ctx.output_budget());
            if dropped > 0 {
                notes.push(format!(
                    "{dropped} later lines were left out to fit the output limit: ask for fewer lines, or narrow them with grep"
                ));
            }
            body = kept;
        }
        let which = if opts.from_tail { "last" } else { "first" };
        let matching = if opts.pattern.is_some() { " matching" } else { "" };
        let mut text = format!(
            "# {real}: {}, modified {}; the {which} {}{matching} lines\n",
            human_bytes(opened.meta.len()),
            rfc3339_utc(opened.meta.mtime()),
            body.lines().count(),
        );
        text.push_str(&body);
        for note in &notes {
            text.push_str(&format!("[{note}]\n"));
        }
        auth.ok(text)
    })
    .await
}

fn journal_params() -> Vec<Param> {
    vec![
        Param::str("unit", "Only entries of this unit, e.g. nginx.service").max_len(255),
        Param::int(
            "lines",
            "Number of entries to return (default 100)",
            1,
            5000,
        ),
        Param::choice(
            "priority",
            "Only entries at this severity or worse",
            &LEVELS,
        ),
        Param::str(
            "since",
            "Start time, e.g. '2026-11-19 10:00', 'yesterday', '-2h'",
        )
        .max_len(64),
        Param::str("until", "End time, in the same forms as since").max_len(64),
        Param::str("grep", "Only entries whose message matches this pattern (a PCRE2 regular expression, as journalctl --grep takes)").max_len(256),
        Param::bool("ignore_case", "Match grep without regard to case"),
        Param::str(
            "identifier",
            "Only entries with this syslog identifier (program name)",
        )
        .max_len(64),
        Param::int(
            "boot",
            "Which boot: 0 is the current one, -1 the one before (default: all boots)",
            -1000,
            0,
        ),
        Param::bool(
            "kernel",
            "Only kernel messages, from every boot in the period (give boot to keep to one)",
        ),
        Param::choice(
            "output",
            "Entry format (default short-iso)",
            &["short-iso", "cat", "verbose"],
        ),
    ]
}

/// The journalctl arguments for a query, and the unit it is limited to (the resource the
/// caller must be allowed to view).
pub fn journal_args(args: &Args) -> Result<(Vec<String>, Option<String>), ToolError> {
    // AIDEV-NOTE: every value is passed as `--option=value` in one argument, so no value
    // can be read by journalctl as an option of its own.
    let mut argv = vec![
        "--no-pager".to_string(),
        "--quiet".to_string(),
        format!("--output={}", args.str("output").unwrap_or("short-iso")),
        format!("--lines={}", args.int("lines").unwrap_or(100)),
    ];
    let unit = args.str("unit").map(normalize_unit).transpose()?;
    if let Some(unit) = &unit {
        argv.push(format!("--unit={unit}"));
    }
    if let Some(priority) = args.str("priority") {
        argv.push(format!("--priority={priority}"));
    }
    for key in ["since", "until"] {
        if let Some(when) = args.str(key) {
            let plain = |c: char| c.is_ascii_alphanumeric() || " :.+@-".contains(c);
            if when.is_empty() || !when.chars().all(plain) {
                return Err(ToolError::Invalid(format!(
                    "{key} must be a time such as '2026-11-19 10:00', 'yesterday' or '-2h'"
                )));
            }
            argv.push(format!("--{key}={when}"));
        }
    }
    if let Some(pattern) = args.str("grep") {
        argv.push(format!("--grep={pattern}"));
        if args.bool("ignore_case") == Some(true) {
            argv.push("--case-sensitive=false".to_string());
        }
    }
    if let Some(identifier) = args.str("identifier") {
        let plain = |c: char| c.is_ascii_alphanumeric() || "_.@/-".contains(c);
        if identifier.is_empty() || !identifier.chars().all(plain) {
            return Err(ToolError::Invalid(
                "identifier must be a program name (letters, digits and _ . @ / -)".to_string(),
            ));
        }
        argv.push(format!("--identifier={identifier}"));
    }
    if let Some(boot) = args.int("boot") {
        argv.push(format!("--boot={boot}"));
    }
    if args.bool("kernel") == Some(true) {
        // AIDEV-NOTE: the match, not `--dmesg`: that option also means `--boot`, which
        // would silently limit the query to the current boot. Kernel messages from
        // before a crash are what such a query is usually for. A positional match, so
        // it stays last.
        argv.push("_TRANSPORT=kernel".to_string());
    }
    Ok((argv, unit))
}

async fn journal_query(ctx: Ctx, args: Args) -> ToolResult {
    let (argv, unit) = journal_args(&args)?;
    // A query for one unit needs a grant covering that unit; any other query needs an
    // unscoped grant, because it can return every unit's entries.
    let auth = ctx.authorize(unit.as_deref())?;
    let out = ctx.run(ctx.command("journalctl")?.args(argv)).await?;
    let quiet = out.stdout.is_empty() && out.stderr.is_empty() && !out.timed_out;
    if quiet && matches!(out.code, Some(0) | Some(1)) {
        // journalctl --quiet prints nothing (and may exit 1) when nothing matched.
        return auth.ok("(no matching journal entries)\n");
    }
    // journalctl prints oldest first: if there is too much, keep the newest.
    auth.done(
        command_text_tail(&out, ctx.output_budget()),
        command_ok(&out),
    )
}

/// One record from /dev/kmsg.
#[derive(Debug, PartialEq, Eq)]
pub struct KmsgRecord {
    pub facility: u32,
    /// 0 (emerg) to 7 (debug)
    pub level: u32,
    /// Microseconds since boot.
    pub usec: u64,
    pub message: String,
}

/// Parses one /dev/kmsg record: `PRIORITY,SEQUENCE,MICROSECONDS,FLAGS[,...];MESSAGE`
/// followed by optional ` KEY=value` continuation lines, which are dropped.
pub fn parse_kmsg(record: &[u8]) -> Option<KmsgRecord> {
    let text = String::from_utf8_lossy(record);
    let (header, rest) = text.split_once(';')?;
    let mut fields = header.split(',');
    let priority: u32 = fields.next()?.parse().ok()?;
    let _sequence: u64 = fields.next()?.parse().ok()?;
    let usec: u64 = fields.next()?.parse().ok()?;
    let message = rest.split('\n').next().unwrap_or_default().to_string();
    Some(KmsgRecord {
        facility: priority >> 3,
        level: priority & 7,
        usec,
        message,
    })
}

/// `TIMESTAMP [SECONDS.MICROS] LEVEL MESSAGE`, with the wall-clock time worked out from
/// when the host booted.
pub fn format_kmsg(record: &KmsgRecord, boot_unix_secs: i64) -> String {
    let secs = record.usec / 1_000_000;
    let level = usize::try_from(record.level)
        .ok()
        .and_then(|l| LEVELS.get(l))
        .unwrap_or(&"?");
    format!(
        "{} [{secs:>5}.{:06}] {level:<7} {}",
        rfc3339_utc(boot_unix_secs.saturating_add(i64::try_from(secs).unwrap_or(0))),
        record.usec % 1_000_000,
        record.message
    )
}

/// Collects the last `lines` kernel messages that pass the filters. `read_record` is one
/// read of /dev/kmsg: each call yields one record, `WouldBlock` once there are no more,
/// and `BrokenPipe` when a record was overwritten before it could be read (skipped).
pub fn collect_kmsg<F>(
    mut read_record: F,
    lines: usize,
    max_level: u32,
    pattern: Option<&Regex>,
) -> Vec<KmsgRecord>
where
    F: FnMut(&mut [u8]) -> std::io::Result<usize>,
{
    use std::io::ErrorKind;
    /// More reads than any real kernel buffer holds: a bound, in case a source never ends.
    const MAX_READS: usize = 4_000_000;
    let mut kept = VecDeque::new();
    let mut buf = vec![0u8; 8192];
    for _ in 0..MAX_READS {
        let n = match read_record(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            // The record was overwritten before we got to it, or the read was interrupted.
            Err(e) if matches!(e.kind(), ErrorKind::BrokenPipe | ErrorKind::Interrupted) => {
                continue;
            }
            // WouldBlock means we have read everything; anything else ends the read too.
            Err(_) => break,
        };
        let Some(record) = buf.get(..n).and_then(parse_kmsg) else {
            continue;
        };
        if record.level <= max_level && pattern.is_none_or(|p| p.is_match(&record.message)) {
            kept.push_back(record);
            if kept.len() > lines {
                kept.pop_front();
            }
        }
    }
    kept.into()
}

/// Seconds since the host booted.
pub fn uptime_secs() -> Option<f64> {
    let text = std::fs::read_to_string("/proc/uptime").ok()?;
    text.split_whitespace().next()?.parse().ok()
}

async fn kernel_log(ctx: Ctx, args: Args) -> ToolResult {
    let lines = usize::try_from(args.int("lines").unwrap_or(200)).unwrap_or(200);
    let max_level = args
        .str("level")
        .and_then(|name| LEVELS.iter().position(|l| *l == name))
        .and_then(|index| u32::try_from(index).ok())
        .unwrap_or(7);
    let pattern = compile_pattern(&args)?;
    let auth = ctx.authorize(None)?;
    blocking(ctx.clone(), move || {
        use rustix::fs::{Mode, OFlags};
        // Non-blocking: reads return each buffered record, then "would block" at the end.
        let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
        let mut kmsg = File::from(rustix::fs::open("/dev/kmsg", flags, Mode::empty()).map_err(
            |e| {
                ToolError::Failed(format!(
                    "cannot open /dev/kmsg: {}. Reading the kernel log needs root unless \
                 kernel.dmesg_restrict is 0; journal_query with kernel=true may work instead.",
                    std::io::Error::from(e)
                ))
            },
        )?);
        let records = collect_kmsg(|buf| kmsg.read(buf), lines, max_level, pattern.as_ref());
        let boot = now_secs() - uptime_secs().unwrap_or(0.0) as i64;
        let all: String = records
            .iter()
            .map(|record| format!("{}\n", format_kmsg(record, boot)))
            .collect();
        let (kept, dropped) = keep_tail(&all, ctx.output_budget());
        let mut text = String::new();
        if dropped > 0 {
            text.push_str(&format!(
                "[{dropped} older messages left out to fit the output limit]\n"
            ));
        }
        text.push_str(&kept);
        if records.is_empty() {
            text.push_str("(no matching kernel messages)\n");
        }
        auth.ok(text)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::Host;
    use crate::tools::testing::{FakeBins, call, find, host, ok_text};
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use serde_json::{Value, json};
    use std::io::Write;
    use std::sync::Arc;

    fn temp_file(content: &[u8]) -> (tempfile::TempDir, File, u64) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        std::fs::write(&path, content).unwrap();
        (dir, File::open(&path).unwrap(), content.len() as u64)
    }

    fn numbered(count: usize) -> String {
        (1..=count).map(|i| format!("line{i}\n")).collect()
    }

    fn opts(lines: usize, from_tail: bool, pattern: Option<&str>) -> ReadOpts {
        ReadOpts {
            lines,
            from_tail,
            pattern: pattern.map(|p| Regex::new(p).unwrap()),
        }
    }

    fn excerpt(content: &[u8], opts: &ReadOpts) -> Vec<String> {
        let (_dir, file, size) = temp_file(content);
        read_log(file, size, opts).unwrap().lines
    }

    #[test]
    fn tail_offset_finds_where_the_last_lines_start() {
        let cases: &[(&str, usize, u64)] = &[
            ("a\nb\nc\n", 1, 4),
            ("a\nb\nc\n", 2, 2),
            ("a\nb\nc\n", 3, 0),
            ("a\nb\nc\n", 9, 0),
            ("a\nb\nc", 1, 4),
            ("a\nb\nc", 2, 2),
            ("", 3, 0),
            ("\n\n\n", 2, 1),
            ("only", 1, 0),
        ];
        for (content, lines, want) in cases {
            let (_dir, mut file, size) = temp_file(content.as_bytes());
            let got = tail_offset(&mut file, size, *lines).unwrap();
            assert_eq!(got, (*want, false), "content {content:?} lines {lines}");
        }
    }

    #[test]
    fn tail_returns_the_last_lines_in_order() {
        assert_eq!(
            excerpt(numbered(10).as_bytes(), &opts(3, true, None)),
            ["line8", "line9", "line10"]
        );
        assert_eq!(
            excerpt(numbered(2).as_bytes(), &opts(3, true, None)),
            ["line1", "line2"]
        );
        assert_eq!(excerpt(b"", &opts(3, true, None)), Vec::<String>::new());
    }

    #[test]
    fn head_returns_the_first_lines() {
        assert_eq!(
            excerpt(numbered(10).as_bytes(), &opts(2, false, None)),
            ["line1", "line2"]
        );
    }

    #[test]
    fn a_last_line_without_a_newline_is_still_a_line() {
        assert_eq!(
            excerpt(b"one\ntwo\nthree", &opts(2, true, None)),
            ["two", "three"]
        );
        assert_eq!(
            excerpt(b"one\ntwo\nthree", &opts(5, false, None)),
            ["one", "two", "three"]
        );
    }

    #[test]
    fn carriage_returns_at_line_ends_are_dropped() {
        assert_eq!(
            excerpt(b"one\r\ntwo\r\n", &opts(5, true, None)),
            ["one", "two"]
        );
    }

    #[test]
    fn a_pattern_keeps_only_matching_lines() {
        let text = numbered(10);
        assert_eq!(
            excerpt(text.as_bytes(), &opts(2, true, Some("line[13579]$"))),
            ["line7", "line9"]
        );
        assert_eq!(
            excerpt(text.as_bytes(), &opts(2, false, Some("line[13579]$"))),
            ["line1", "line3"]
        );
        assert_eq!(
            excerpt(text.as_bytes(), &opts(5, true, Some("nothing"))),
            Vec::<String>::new()
        );
    }

    #[test]
    fn the_tail_of_a_large_file_is_found_across_read_blocks() {
        let text: String = (0..200_000).map(|i| format!("entry {i:06}\n")).collect();
        assert_eq!(
            excerpt(text.as_bytes(), &opts(3, true, None)),
            ["entry 199997", "entry 199998", "entry 199999"]
        );
        assert_eq!(
            excerpt(text.as_bytes(), &opts(2, true, Some("entry 1000[01]0"))),
            ["entry 100000", "entry 100010"]
        );
    }

    #[test]
    fn a_very_long_line_is_cut_not_returned_whole() {
        let mut text = "x".repeat(100_000);
        text.push_str("\nend\n");
        let lines = excerpt(text.as_bytes(), &opts(2, true, None));
        assert_eq!(lines.len(), 2);
        assert!(lines[0].len() < 20_000, "{} bytes", lines[0].len());
        assert!(
            lines[0].starts_with("xxxx") && lines[0].ends_with("[line cut]"),
            "{}",
            &lines[0][lines[0].len() - 30..]
        );
        assert_eq!(lines[1], "end");
    }

    fn gzip(content: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(content).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn a_gzip_log_is_read_like_a_plain_one() {
        let packed = gzip(numbered(10).as_bytes());
        assert_eq!(
            excerpt(&packed, &opts(3, true, None)),
            ["line8", "line9", "line10"]
        );
        assert_eq!(excerpt(&packed, &opts(2, false, None)), ["line1", "line2"]);
        assert_eq!(
            excerpt(&packed, &opts(1, true, Some("line[12]$"))),
            ["line2"]
        );
    }

    #[test]
    fn files_that_are_not_text_are_refused() {
        let (_dir, file, size) = temp_file(b"\x00\x01\x02binary\x00data\n");
        let error = read_log(file, size, &opts(5, true, None)).unwrap_err();
        assert!(error.contains("binary"), "{error}");

        let (_dir, file, size) = temp_file(b"\xfd7zXZ\x00\x00rest");
        let error = read_log(file, size, &opts(5, true, None)).unwrap_err();
        assert!(error.contains("xz"), "{error}");
    }

    fn parsed(params: &[Param], arguments: Value) -> Args {
        Args::parse(params, Some(&arguments)).unwrap()
    }

    #[test]
    fn compile_pattern_honours_ignore_case_and_rejects_bad_patterns() {
        let params = [Param::str("grep", "g"), Param::bool("ignore_case", "i")];
        assert!(
            compile_pattern(&parsed(&params, json!({})))
                .unwrap()
                .is_none()
        );
        let exact = compile_pattern(&parsed(&params, json!({"grep": "error"})))
            .unwrap()
            .unwrap();
        assert!(exact.is_match("an error") && !exact.is_match("an ERROR"));
        let loose = compile_pattern(&parsed(
            &params,
            json!({"grep": "error", "ignore_case": true}),
        ))
        .unwrap()
        .unwrap();
        assert!(loose.is_match("an ERROR"));
        assert!(matches!(
            compile_pattern(&parsed(&params, json!({"grep": "(unclosed"}))),
            Err(ToolError::Invalid(_))
        ));
    }

    struct Logs {
        _dir: tempfile::TempDir,
        root: String,
        outside: String,
        host: Arc<Host>,
        audit: MemorySink,
    }

    /// base/log/{syslog, nginx/access.log, escape -> ../secret}, base/secret
    fn logs() -> Logs {
        let dir = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(dir.path()).unwrap();
        let root = base.join("log");
        std::fs::create_dir_all(root.join("nginx")).unwrap();
        std::fs::write(root.join("syslog"), numbered(20)).unwrap();
        std::fs::write(root.join("nginx/access.log"), "GET /\nPOST /login\n").unwrap();
        std::fs::write(base.join("secret"), "s3cret\n").unwrap();
        std::os::unix::fs::symlink("../secret", root.join("escape")).unwrap();
        let root = root.to_string_lossy().into_owned();
        let config = format!(
            r#"
[roles.reader]
allow = ["@read"]
[roles.web]
allow = ["logs.view:{root}/nginx/**"]
[unix_users.rita]
roles = ["reader"]
[unix_users.wendy]
roles = ["web"]
[logs]
dirs = ["{root}"]
"#
        );
        let (host, audit) = host(&config);
        Logs {
            outside: base.join("secret").to_string_lossy().into_owned(),
            _dir: dir,
            root,
            host,
            audit,
        }
    }

    impl Logs {
        async fn run(&self, user: &str, tool: &str, arguments: Value) -> ToolResult {
            call(&self.host, user, &find(tools(), tool), arguments).await
        }
    }

    #[tokio::test]
    async fn log_read_returns_the_tail_with_a_header_naming_the_file() {
        let l = logs();
        let path = format!("{}/syslog", l.root);
        let text = ok_text(
            l.run("rita", "log_read", json!({"path": path, "lines": 2}))
                .await,
        );
        assert!(text.lines().next().unwrap().contains(&path), "{text}");
        assert!(text.ends_with("line19\nline20\n"), "{text}");
        assert!(!text.contains("line18"), "{text}");
        assert_eq!(l.audit.records().last().unwrap()["resource"], path);
    }

    #[tokio::test]
    async fn log_read_keeps_the_newest_lines_when_the_tail_is_too_big_to_return() {
        let l = logs();
        // 2000 lines of 100 bytes: far more than the 64 KiB a result may hold
        let path = format!("{}/big.log", l.root);
        let content: String = (1..=2000)
            .map(|i| format!("{i:05} {}\n", "x".repeat(93)))
            .collect();
        std::fs::write(&path, content).unwrap();
        let text = ok_text(
            l.run("rita", "log_read", json!({"path": path, "lines": 2000}))
                .await,
        );
        assert!(text.len() <= 64 * 1024, "{} bytes", text.len());
        // the end of the log is what a tail is for
        assert!(text.contains("\n02000 "), "the newest line is missing");
        assert!(
            !text.contains("\n00001 "),
            "the oldest line should have been left out"
        );
        // and the result says what it really holds
        let header = text.lines().next().unwrap();
        assert!(!header.contains("2000 lines"), "{header}");
        assert!(
            text.contains("left out"),
            "should say that older lines were left out"
        );
        // from the head, it is the first lines that are kept
        let text = ok_text(
            l.run(
                "rita",
                "log_read",
                json!({"path": path, "lines": 2000, "from": "head"}),
            )
            .await,
        );
        assert!(text.contains("\n00001 ") && !text.contains("\n02000 "));
    }

    #[tokio::test]
    async fn log_read_filters_with_grep() {
        let l = logs();
        let path = format!("{}/nginx/access.log", l.root);
        let text = ok_text(
            l.run(
                "rita",
                "log_read",
                json!({"path": path, "grep": "^post", "ignore_case": true}),
            )
            .await,
        );
        assert!(text.ends_with("POST /login\n"), "{text}");
        assert!(!text.contains("GET /"), "{text}");
        assert!(matches!(
            l.run("rita", "log_read", json!({"path": path, "grep": "("}))
                .await,
            Err(ToolError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn log_read_refuses_files_outside_the_log_directories() {
        let l = logs();
        for path in [
            l.outside.clone(),
            format!("{}/escape", l.root),
            format!("{}/../secret", l.root),
        ] {
            match l.run("rita", "log_read", json!({"path": path})).await {
                Err(ToolError::Denied(message)) => {
                    assert!(message.contains("logs.dirs"), "{message}")
                }
                other => panic!("{path}: expected a denial, got {other:?}"),
            }
            assert_eq!(l.audit.records().last().unwrap()["resource"], l.outside);
        }
    }

    #[tokio::test]
    async fn log_read_honours_a_grant_limited_to_one_subdirectory() {
        let l = logs();
        ok_text(
            l.run(
                "wendy",
                "log_read",
                json!({"path": format!("{}/nginx/access.log", l.root)}),
            )
            .await,
        );
        assert!(matches!(
            l.run(
                "wendy",
                "log_read",
                json!({"path": format!("{}/syslog", l.root)})
            )
            .await,
            Err(ToolError::Denied(_))
        ));
    }

    #[tokio::test]
    async fn log_list_shows_the_configured_directories_by_default() {
        let l = logs();
        let text = ok_text(l.run("rita", "log_list", json!({})).await);
        assert!(text.contains("syslog") && text.contains("nginx/"), "{text}");
        let text = ok_text(
            l.run(
                "rita",
                "log_list",
                json!({"dir": format!("{}/nginx", l.root)}),
            )
            .await,
        );
        assert!(text.contains("access.log"), "{text}");
    }

    #[tokio::test]
    async fn log_list_refuses_directories_outside_the_log_directories() {
        let l = logs();
        assert!(matches!(
            l.run("rita", "log_list", json!({"dir": "/"})).await,
            Err(ToolError::Denied(_))
        ));
        // a grant for one subdirectory lists that subdirectory and nothing above it
        ok_text(
            l.run(
                "wendy",
                "log_list",
                json!({"dir": format!("{}/nginx", l.root)}),
            )
            .await,
        );
        assert!(matches!(
            l.run("wendy", "log_list", json!({"dir": l.root})).await,
            Err(ToolError::Denied(_))
        ));
        assert!(matches!(
            l.run("wendy", "log_list", json!({})).await,
            Err(ToolError::Denied(_))
        ));
    }

    fn journal(arguments: Value) -> Result<(Vec<String>, Option<String>), ToolError> {
        journal_args(&parsed(&journal_params(), arguments))
    }

    #[test]
    fn journal_args_default_to_the_last_hundred_entries() {
        let (argv, unit) = journal(json!({})).unwrap();
        assert_eq!(
            argv,
            ["--no-pager", "--quiet", "--output=short-iso", "--lines=100"]
        );
        assert_eq!(unit, None);
    }

    #[test]
    fn journal_args_pass_every_filter_as_a_single_argument() {
        let (argv, unit) = journal(json!({
            "unit": "nginx", "lines": 20, "priority": "err", "since": "-2h",
            "until": "2026-11-19 10:00:00", "grep": "time out", "ignore_case": true,
            "identifier": "nginx", "boot": -1, "kernel": true, "output": "cat"
        }))
        .unwrap();
        assert_eq!(
            argv,
            [
                "--no-pager",
                "--quiet",
                "--output=cat",
                "--lines=20",
                "--unit=nginx.service",
                "--priority=err",
                "--since=-2h",
                "--until=2026-11-19 10:00:00",
                "--grep=time out",
                "--case-sensitive=false",
                "--identifier=nginx",
                "--boot=-1",
                "_TRANSPORT=kernel",
            ]
        );
        assert_eq!(unit, Some("nginx.service".to_string()));
    }

    /// AIDEV-NOTE: `journalctl --dmesg` is `--boot` plus a match on kernel messages: it
    /// silently limits a query to the CURRENT boot. After a crash and reboot, "kernel
    /// messages since yesterday" then shows nothing from before the reboot, which is
    /// exactly what was being looked for. The match alone has no such limit.
    #[test]
    fn kernel_messages_are_selected_without_limiting_the_query_to_this_boot() {
        let (argv, _) = journal(json!({"kernel": true, "since": "-3d"})).unwrap();
        assert!(argv.iter().any(|a| a == "_TRANSPORT=kernel"), "{argv:?}");
        assert!(
            !argv.iter().any(|a| a == "--dmesg" || a == "-k"),
            "{argv:?}"
        );
        // the match is a positional argument, so it comes after every option
        assert_eq!(argv.last().map(String::as_str), Some("_TRANSPORT=kernel"));
    }

    #[test]
    fn journal_args_reject_values_that_are_not_what_they_claim() {
        for bad in [
            json!({"unit": "nginx*"}),
            json!({"unit": "-M"}),
            json!({"unit": "a/b"}),
            json!({"since": "$(reboot)"}),
            json!({"until": "now; reboot"}),
            json!({"identifier": "a b"}),
        ] {
            assert!(
                matches!(journal(bad.clone()), Err(ToolError::Invalid(_))),
                "{bad}"
            );
        }
    }

    fn journal_host(fake: &FakeBins) -> (Arc<Host>, MemorySink) {
        host(&format!(
            r#"
[roles.reader]
allow = ["@read"]
[roles.web]
allow = ["journal.view:nginx.service"]
[unix_users.rita]
roles = ["reader"]
[unix_users.wendy]
roles = ["web"]
{}"#,
            fake.config()
        ))
    }

    #[tokio::test]
    async fn journal_query_runs_journalctl_with_the_built_arguments() {
        let fake = FakeBins::new().add("journalctl", "Nov 19 nginx[1]: started\n", 0);
        let (host, _audit) = journal_host(&fake);
        let tool = find(tools(), "journal_query");
        let text = ok_text(call(&host, "rita", &tool, json!({"unit": "nginx", "lines": 5})).await);
        assert_eq!(text, "Nov 19 nginx[1]: started\n");
        assert_eq!(
            fake.calls("journalctl"),
            [[
                "--no-pager",
                "--quiet",
                "--output=short-iso",
                "--lines=5",
                "--unit=nginx.service"
            ]]
        );
    }

    #[tokio::test]
    async fn journal_query_checks_the_unit_against_the_grant_before_running_anything() {
        let fake = FakeBins::new().add("journalctl", "entries\n", 0);
        let (host, audit) = journal_host(&fake);
        let tool = find(tools(), "journal_query");
        // wendy may only see nginx's journal
        ok_text(call(&host, "wendy", &tool, json!({"unit": "nginx.service"})).await);
        assert_eq!(fake.calls("journalctl").len(), 1);
        for arguments in [json!({"unit": "sshd"}), json!({})] {
            assert!(matches!(
                call(&host, "wendy", &tool, arguments).await,
                Err(ToolError::Denied(_))
            ));
        }
        assert_eq!(
            fake.calls("journalctl").len(),
            1,
            "a refused query must not run journalctl"
        );
        assert_eq!(audit.records().last().unwrap()["decision"], "deny");
    }

    #[tokio::test]
    async fn journal_query_keeps_the_newest_entries_when_there_are_too_many_to_return() {
        let entries: String = (1..=2000)
            .map(|i| format!("{i:05} {}\n", "y".repeat(93)))
            .collect();
        let fake = FakeBins::new().add("journalctl", &entries, 0);
        let (host, _audit) = journal_host(&fake);
        let text = ok_text(
            call(
                &host,
                "rita",
                &find(tools(), "journal_query"),
                json!({"lines": 2000}),
            )
            .await,
        );
        assert!(text.len() <= 64 * 1024, "{} bytes", text.len());
        assert!(text.contains("\n02000 ") && !text.contains("\n00001 "));
        assert!(
            text.starts_with('['),
            "should open by saying entries were left out"
        );
    }

    #[tokio::test]
    async fn journal_query_reports_a_failing_journalctl() {
        let fake = FakeBins::new().add("journalctl", "Failed to open journal\n", 2);
        let (host, _audit) = journal_host(&fake);
        let result = call(&host, "rita", &find(tools(), "journal_query"), json!({}))
            .await
            .unwrap();
        assert!(result.is_error());
        assert!(result.text().contains("exit status 2"), "{}", result.text());
    }

    #[test]
    fn parse_kmsg_reads_the_header_and_drops_continuation_lines() {
        let record = b"6,1234,5678901,-;usb 1-1: new device\n SUBSYSTEM=usb\n DEVICE=+usb:1-1\n";
        assert_eq!(
            parse_kmsg(record),
            Some(KmsgRecord {
                facility: 0,
                level: 6,
                usec: 5_678_901,
                message: "usb 1-1: new device".to_string()
            })
        );
        // priority 30 is facility 3 (daemon), level 6; later header fields are ignored
        assert_eq!(
            parse_kmsg(b"30,5,100,c,caller=T1;systemd[1]: started\n"),
            Some(KmsgRecord {
                facility: 3,
                level: 6,
                usec: 100,
                message: "systemd[1]: started".to_string()
            })
        );
    }

    #[test]
    fn parse_kmsg_rejects_what_is_not_a_record() {
        for bad in [
            &b"garbage"[..],
            b"x,1,2,-;message",
            b"6,1;message",
            b"",
            b";",
        ] {
            assert_eq!(parse_kmsg(bad), None, "{:?}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn format_kmsg_shows_wall_clock_boot_time_and_level() {
        let record = KmsgRecord {
            facility: 0,
            level: 3,
            usec: 5_678_901,
            message: "disk failure".to_string(),
        };
        // booted at 12:34:51, so 5.678901 seconds later it is 12:34:56
        assert_eq!(
            format_kmsg(&record, 1_795_091_691),
            "2026-11-19T12:34:56Z [    5.678901] err     disk failure"
        );
    }

    fn feed(
        records: Vec<std::io::Result<&'static [u8]>>,
    ) -> impl FnMut(&mut [u8]) -> std::io::Result<usize> {
        let mut queue: VecDeque<std::io::Result<&'static [u8]>> = records.into();
        move |buf: &mut [u8]| match queue.pop_front() {
            Some(Ok(record)) => {
                buf[..record.len()].copy_from_slice(record);
                Ok(record.len())
            }
            Some(Err(e)) => Err(e),
            None => Err(std::io::ErrorKind::WouldBlock.into()),
        }
    }

    fn messages(records: &[KmsgRecord]) -> Vec<&str> {
        records.iter().map(|r| r.message.as_str()).collect()
    }

    #[test]
    fn collect_kmsg_keeps_the_last_messages_that_pass_the_filters() {
        let all = || {
            feed(vec![
                Ok(b"6,1,10,-;boot message\n"),
                Ok(b"3,2,20,-;disk error\n"),
                Ok(b"7,3,30,-;debug chatter\n"),
                Ok(b"4,4,40,-;temperature warning\n"),
            ])
        };
        assert_eq!(
            messages(&collect_kmsg(all(), 2, 7, None)),
            ["debug chatter", "temperature warning"]
        );
        // level 4 (warning) or more severe
        assert_eq!(
            messages(&collect_kmsg(all(), 10, 4, None)),
            ["disk error", "temperature warning"]
        );
        let pattern = Regex::new("error|boot").unwrap();
        assert_eq!(
            messages(&collect_kmsg(all(), 10, 7, Some(&pattern))),
            ["boot message", "disk error"]
        );
    }

    #[test]
    fn collect_kmsg_skips_overwritten_records_and_stops_at_other_errors() {
        let source = feed(vec![
            Ok(b"6,1,10,-;first\n"),
            Err(std::io::ErrorKind::BrokenPipe.into()),
            Ok(b"not a record"),
            Ok(b"6,3,30,-;third\n"),
            Err(std::io::ErrorKind::PermissionDenied.into()),
            Ok(b"6,4,40,-;never reached\n"),
        ]);
        assert_eq!(
            messages(&collect_kmsg(source, 10, 7, None)),
            ["first", "third"]
        );
    }
}
