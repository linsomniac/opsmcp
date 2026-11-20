//! Making host-derived text safe to hand to an agent.
//!
//! AIDEV-NOTE: everything a tool returns (log lines, process names, file contents, command
//! output) is attacker-influenced host data. `clean_text` removes the ways such data can
//! tamper with a terminal or hide text from a human reviewer. It does NOT make the content
//! trustworthy: prompt injection in a log line is still there, in plain sight. The secret
//! redaction below is best effort and must never be relied on as a security boundary.

/// Converts raw bytes to text that is safe to display: invalid UTF-8 is replaced, control
/// characters (other than newline and tab) and invisible/bidirectional formatting
/// characters are shown as visible escapes, and CRLF becomes LF.
pub fn clean_text(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        clean_char(c, chars.peek().copied(), &mut out);
    }
    out
}

/// Appends the cleaned form of one character; `next` is the character that follows it.
fn clean_char(c: char, next: Option<char>, out: &mut String) {
    match c {
        '\n' | '\t' => out.push(c),
        '\r' if next == Some('\n') => {}
        c if (c as u32) < 0x20 || c == '\u{7f}' => {
            out.push_str(&format!("\\x{:02x}", c as u32));
        }
        c if is_hidden_formatting(c) => {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        }
        c => out.push(c),
    }
}

/// C1 controls, plus the invisible and bidirectional formatting characters that can hide
/// or reorder text on screen.
fn is_hidden_formatting(c: char) -> bool {
    matches!(
        c as u32,
        0x80..=0x9f
            | 0xad
            | 0x61c
            | 0x200b..=0x200f
            | 0x202a..=0x202e
            | 0x2060..=0x2064
            | 0x2066..=0x2069
            | 0xfeff
    )
}

/// Limits `text` to at most `max_bytes` of content, cutting at a line boundary when there
/// is one, and appends a notice saying how much was kept. Text within the limit is
/// returned unchanged.
pub fn cap_text(text: String, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text;
    }
    let mut cut = max_bytes;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    // Prefer ending on a whole line, unless that would throw away most of what fits.
    if let Some(newline) = text[..cut].rfind('\n')
        && newline + 1 >= cut / 2
    {
        cut = newline + 1;
    }
    let mut out = text[..cut].to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&format!(
        "[output truncated: showing {cut} of {} bytes]\n",
        text.len()
    ));
    out
}

/// Keeps the END of `text`: cleans it (as `clean_text` does) and, if the result is longer
/// than `max_bytes`, drops lines from the front until it fits. Returns the kept text and
/// the number of lines dropped. For output whose newest part matters most (log tails).
pub fn keep_tail(text: &str, max_bytes: usize) -> (String, usize) {
    let cleaned = clean_text(text.as_bytes());
    if cleaned.len() <= max_bytes {
        return (cleaned, 0);
    }
    let newlines = |part: &str| part.bytes().filter(|b| *b == b'\n').count();
    // What is kept must start at or after this byte, and at the start of a line.
    let earliest = cleaned.len() - max_bytes;
    let line_start = cleaned.as_bytes()[earliest - 1..]
        .iter()
        .position(|b| *b == b'\n')
        .map(|found| earliest + found)
        .filter(|start| *start < cleaned.len());
    match line_start {
        Some(start) => (cleaned[start..].to_string(), newlines(&cleaned[..start])),
        None => {
            // The last line alone is too long: keep the end of it.
            let mut start = earliest;
            while !cleaned.is_char_boundary(start) {
                start += 1;
            }
            (
                cleaned[start..].to_string(),
                newlines(&cleaned[..start]) + 1,
            )
        }
    }
}

/// Keeps the START of `text`: cleans it and, if the result is longer than `max_bytes`,
/// drops lines from the end until it fits. Returns the kept text and the number of
/// lines dropped.
pub fn keep_head(text: &str, max_bytes: usize) -> (String, usize) {
    let cleaned = clean_text(text.as_bytes());
    if cleaned.len() <= max_bytes {
        return (cleaned, 0);
    }
    let mut end = max_bytes;
    while !cleaned.is_char_boundary(end) {
        end -= 1;
    }
    // End on a whole line if there is one; otherwise in the middle of the first line.
    if let Some(newline) = cleaned[..end].rfind('\n') {
        end = newline + 1;
    }
    let rest = &cleaned[end..];
    let dropped = rest.lines().count().max(1);
    (cleaned[..end].to_string(), dropped)
}

/// The length of the longest prefix of `bytes` whose cleaned form (see `clean_text`) is
/// at most `max_bytes` long, and which does not end part-way through a UTF-8 character.
pub fn fit_prefix(bytes: &[u8], max_bytes: usize) -> usize {
    let mut used = 0; // cleaned bytes so far
    let mut taken = 0; // input bytes they came from
    let mut one = String::new();
    for chunk in bytes.utf8_chunks() {
        let mut chars = chunk.valid().chars().peekable();
        while let Some(c) = chars.next() {
            one.clear();
            clean_char(c, chars.peek().copied(), &mut one);
            if used + one.len() > max_bytes {
                return taken;
            }
            used += one.len();
            taken += c.len_utf8();
        }
        // An invalid sequence is shown as one replacement character (three bytes).
        if !chunk.invalid().is_empty() {
            if used + 3 > max_bytes {
                return taken;
            }
            used += 3;
            taken += chunk.invalid().len();
        }
    }
    taken
}

/// Best-effort masking of secrets in free text that contains command lines (such as
/// `systemctl status` output): each line is treated as a command line, keeping its
/// spacing.
pub fn redact_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let (body, ending) = match line.strip_suffix('\n') {
            Some(body) => (body, "\n"),
            None => (line, ""),
        };
        // Split on single spaces so that runs of spaces (indentation) survive.
        let pieces: Vec<&str> = body.split(' ').collect();
        let words: Vec<String> = pieces
            .iter()
            .filter(|p| !p.is_empty())
            .map(|p| p.to_string())
            .collect();
        let mut masked = redact_args(&words).into_iter();
        let rebuilt: Vec<String> = pieces
            .iter()
            .map(|piece| {
                if piece.is_empty() {
                    String::new()
                } else {
                    masked.next().unwrap_or_default()
                }
            })
            .collect();
        out.push_str(&rebuilt.join(" "));
        out.push_str(ending);
    }
    out
}

/// Best-effort masking of secrets in a command line (argv form).
pub fn redact_args(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut redact_next = false;
    for arg in args {
        if redact_next {
            redact_next = false;
            if !arg.starts_with('-') {
                out.push(REDACTED.to_string());
                continue;
            }
        }
        match arg.split_once('=') {
            // --password=value or API_KEY=value
            Some((name, value))
                if !value.is_empty() && is_option_name(name) && is_sensitive(name) =>
            {
                out.push(format!("{name}={REDACTED}"));
            }
            // --password value
            None if arg.starts_with('-') && is_sensitive(arg) => {
                redact_next = true;
                out.push(arg.clone());
            }
            _ => out.push(redact_url_password(arg)),
        }
    }
    out
}

const REDACTED: &str = "<redacted>";

fn is_option_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c))
}

fn is_sensitive(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    ["pass", "secret", "token", "key", "credential", "auth"]
        .iter()
        .any(|word| name.contains(word))
}

/// `scheme://user:password@host/...` becomes `scheme://user:<redacted>@host/...`.
fn redact_url_password(arg: &str) -> String {
    let Some(scheme_end) = arg.find("://") else {
        return arg.to_string();
    };
    let (prefix, rest) = arg.split_at(scheme_end + 3);
    let authority = &rest[..rest.find('/').unwrap_or(rest.len())];
    let Some(at) = authority.rfind('@') else {
        return arg.to_string();
    };
    let Some(colon) = authority[..at].find(':') else {
        return arg.to_string();
    };
    format!("{prefix}{}:{REDACTED}{}", &authority[..colon], &rest[at..])
}

/// Hides the value of a `NAME=value` environment entry, keeping the name.
pub fn redact_env(entry: &str) -> String {
    match entry.split_once('=') {
        Some((name, _)) => format!("{name}={REDACTED}"),
        None => entry.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_text_escapes_what_could_tamper_with_a_display() {
        let cases: &[(&[u8], &str)] = &[
            (b"hello\nworld\ttab", "hello\nworld\ttab"),
            (b"a\x1b[31mred", "a\\x1b[31mred"),
            (b"a\r\nb", "a\nb"),
            (b"progress\rdone", "progress\\x0ddone"),
            (b"nul\x00", "nul\\x00"),
            (b"\x7f", "\\x7f"),
            (b"bad\xffutf8", "bad\u{fffd}utf8"),
            ("a\u{202e}b".as_bytes(), "a\\u{202e}b"),
            ("a\u{0085}b".as_bytes(), "a\\u{85}b"),
            ("zero\u{200b}width".as_bytes(), "zero\\u{200b}width"),
            ("caf\u{e9} \u{2603}".as_bytes(), "caf\u{e9} \u{2603}"),
        ];
        for (input, want) in cases {
            assert_eq!(clean_text(input), *want, "input {input:?}");
        }
    }

    #[test]
    fn cap_text_leaves_short_text_alone() {
        assert_eq!(cap_text("abc\n".to_string(), 4), "abc\n");
    }

    #[test]
    fn cap_text_cuts_at_a_line_boundary_and_says_so() {
        let out = cap_text("aaaa\nbbbb\ncccc".to_string(), 12);
        assert!(out.starts_with("aaaa\nbbbb\n"), "got {out:?}");
        assert!(!out.contains("cccc"), "got {out:?}");
        assert!(out.contains("10 of 14 bytes"), "got {out:?}");
    }

    #[test]
    fn cap_text_never_splits_a_character() {
        // Three two-byte characters; a 3-byte limit falls in the middle of the second.
        let out = cap_text("\u{e9}\u{e9}\u{e9}".to_string(), 3);
        assert!(out.starts_with('\u{e9}'), "got {out:?}");
        assert!(out.contains("2 of 6 bytes"), "got {out:?}");
    }

    #[test]
    fn keep_tail_drops_whole_lines_from_the_front_until_the_rest_fits() {
        let text = "line1\nline2\nline3\n";
        assert_eq!(keep_tail(text, 100), (text.to_string(), 0));
        assert_eq!(keep_tail(text, 18), (text.to_string(), 0));
        assert_eq!(keep_tail(text, 17), ("line2\nline3\n".to_string(), 1));
        assert_eq!(keep_tail(text, 12), ("line2\nline3\n".to_string(), 1));
        assert_eq!(keep_tail(text, 11), ("line3\n".to_string(), 2));
        assert_eq!(keep_tail("", 10), (String::new(), 0));
    }

    #[test]
    fn keep_tail_measures_the_text_after_cleaning() {
        // each ESC byte becomes four characters once cleaned
        let text = "\x1b\x1b\x1b\x1b\x1b\nend\n";
        assert_eq!(keep_tail(text, 8), ("end\n".to_string(), 1));
        assert_eq!(
            keep_tail(text, 25),
            ("\\x1b\\x1b\\x1b\\x1b\\x1b\nend\n".to_string(), 0)
        );
    }

    #[test]
    fn keep_tail_cuts_inside_a_single_line_that_is_too_long_on_its_own() {
        let (kept, dropped) = keep_tail(&"\u{e9}".repeat(100), 11);
        // five whole two-byte characters: never half of one
        assert_eq!(
            (kept.as_str(), dropped),
            ("\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}", 1)
        );
    }

    #[test]
    fn keep_head_drops_whole_lines_from_the_end_until_the_rest_fits() {
        let text = "line1\nline2\nline3\n";
        assert_eq!(keep_head(text, 100), (text.to_string(), 0));
        assert_eq!(keep_head(text, 18), (text.to_string(), 0));
        assert_eq!(keep_head(text, 17), ("line1\nline2\n".to_string(), 1));
        assert_eq!(keep_head(text, 12), ("line1\nline2\n".to_string(), 1));
        assert_eq!(keep_head(text, 11), ("line1\n".to_string(), 2));
        // a first line that is too long on its own is cut, on a character boundary
        assert_eq!(
            keep_head(&"\u{e9}".repeat(100), 11),
            ("\u{e9}".repeat(5), 1)
        );
    }

    #[test]
    fn fit_prefix_takes_everything_that_fits() {
        assert_eq!(fit_prefix(b"hello\nworld\n", 100), 12);
        assert_eq!(fit_prefix(b"hello\nworld\n", 12), 12);
        assert_eq!(fit_prefix(b"hello\nworld\n", 7), 7);
        assert_eq!(fit_prefix(b"", 10), 0);
    }

    #[test]
    fn fit_prefix_accounts_for_bytes_that_grow_when_cleaned() {
        // ten ESC bytes clean to forty characters; only five fit in twenty
        assert_eq!(fit_prefix(&[0x1b; 10], 20), 5);
        // an invalid byte becomes a three-byte replacement character
        assert_eq!(fit_prefix(&[0xff; 10], 9), 3);
    }

    #[test]
    fn fit_prefix_never_ends_inside_a_character() {
        let text = "\u{e9}".repeat(10); // 20 bytes
        assert_eq!(fit_prefix(text.as_bytes(), 7), 6);
        assert_eq!(fit_prefix(text.as_bytes(), 6), 6);
        let snowmen = "\u{2603}".repeat(4); // 12 bytes, three each
        assert_eq!(fit_prefix(snowmen.as_bytes(), 8), 6);
    }

    #[test]
    fn redact_text_masks_command_lines_and_keeps_the_layout() {
        let cases: &[(&str, &str)] = &[
            (
                "             |-1234 /usr/bin/app --password=hunter2 --port 80\n",
                "             |-1234 /usr/bin/app --password=<redacted> --port 80\n",
            ),
            (
                "    Process: 99 ExecStart=/bin/x --token abc123 (code=exited)\n",
                "    Process: 99 ExecStart=/bin/x --token <redacted> (code=exited)\n",
            ),
            (
                "     Active: active (running) since Tue\n",
                "     Active: active (running) since Tue\n",
            ),
            ("a  b   c", "a  b   c"),
            (
                "two\nlines DB_PASSWORD=x\n",
                "two\nlines DB_PASSWORD=<redacted>\n",
            ),
            ("", ""),
        ];
        for (input, want) in cases {
            assert_eq!(redact_text(input), *want, "input {input:?}");
        }
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn redact_args_masks_common_secret_shapes() {
        let cases: &[(&[&str], &[&str])] = &[
            (
                &["mysql", "--password=hunter2", "-uroot"],
                &["mysql", "--password=<redacted>", "-uroot"],
            ),
            (
                &["curl", "--token", "abc123", "https://x"],
                &["curl", "--token", "<redacted>", "https://x"],
            ),
            (
                &["psql", "postgres://bob:s3cret@db/x"],
                &["psql", "postgres://bob:<redacted>@db/x"],
            ),
            (
                &["env", "API_KEY=xyz", "PATH=/bin"],
                &["env", "API_KEY=<redacted>", "PATH=/bin"],
            ),
            (
                &["nginx", "-g", "daemon off;"],
                &["nginx", "-g", "daemon off;"],
            ),
            (&["--secret"], &["--secret"]),
        ];
        for (input, want) in cases {
            assert_eq!(redact_args(&args(input)), args(want), "input {input:?}");
        }
    }

    #[test]
    fn redact_env_hides_every_value() {
        assert_eq!(redact_env("DB_URL=postgres://x"), "DB_URL=<redacted>");
        assert_eq!(redact_env("PATH=/usr/bin"), "PATH=<redacted>");
        assert_eq!(redact_env("NOVALUE"), "NOVALUE");
        assert_eq!(redact_env("EMPTY="), "EMPTY=<redacted>");
    }
}
