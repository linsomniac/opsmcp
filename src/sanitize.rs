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

/// C1 controls, plus the characters that are invisible on screen or reorder what is
/// shown: bidirectional and zero-width formatting, the Unicode line and paragraph
/// separators (which some viewers treat as a line break), and the characters that can
/// carry text nobody sees (tag characters, variation selectors, blank fillers).
///
/// AIDEV-NOTE: tag characters (U+E0000..) and variation selectors render as nothing and
/// can spell out whole sentences. Host data reaches a language model through here, so
/// invisible text is not a cosmetic matter: it is how instructions get smuggled past
/// the human who reviews what the model was shown. When in doubt, add a range.
fn is_hidden_formatting(c: char) -> bool {
    matches!(
        c as u32,
        0x80..=0x9f
            | 0xad
            | 0x34f
            | 0x61c
            | 0x115f..=0x1160
            | 0x180b..=0x180e
            | 0x200b..=0x200f
            | 0x2028..=0x202e
            | 0x2060..=0x2069
            | 0x3164
            | 0xfe00..=0xfe0f
            | 0xfeff
            | 0xffa0
            | 0xfff9..=0xfffb
            | 0xe0000..=0xe007f
            | 0xe0100..=0xe01ef
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
/// `systemctl status` output, or a crontab): each line is treated as a command line,
/// keeping its spacing.
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
        let mut masked = redact_words(&words, true).into_iter();
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
    redact_words(args, false)
}

const REDACTED: &str = "<redacted>";

/// The opening quote of a word that starts a quoted string and does not also end it.
fn opens_quote(word: &str) -> Option<char> {
    let quote = word.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    (word.len() == 1 || !word.ends_with(quote)).then_some(quote)
}

/// The masking behind `redact_args` and `redact_text`. One element of the result per
/// word. With `text`, the words came from splitting a line at spaces, so a quoted value
/// may be spread over several of them; those are masked up to the closing quote.
///
/// AIDEV-NOTE: this is a list of the usual ways a secret ends up on a command line, not
/// a guarantee. Each rule errs towards masking too much, except where that would hide
/// something an operator needs every day (a port after `-p`, a host:path after `-u`).
/// The rules:
/// - `NAME=value` and `--name value` where the name says it is a secret
///   (pass, pwd, secret, token, key, credential, auth, cookie);
/// - `-u user:pass` and `--user=user:pass` (curl), keeping the user;
/// - `-pPASS` and `-p PASS` after a mysql-family program or sshpass;
/// - HTTP headers that carry a secret: the well-known ones anywhere
///   (`Authorization: ...`, `Cookie: ...`), and after `-H`/`--header` any header whose
///   name says so. Not every `Word:` with such a name: sudo's `NOPASSWD:` is a tag;
/// - the password in `scheme://user:password@host`.
fn redact_words(words: &[String], text: bool) -> Vec<String> {
    let mut out = Vec::with_capacity(words.len());
    // The value of a `--password`-style option comes next.
    let mut secret_next = false;
    // `user:password` may come next (after -u / --user).
    let mut userpass_next = false;
    // A password comes next (after -p, for the programs below).
    let mut p_next = false;
    // The value of a secret header comes next; the quote the header was opened with.
    let mut header: Option<Option<char>> = None;
    // Inside a quoted secret that runs on to a word ending with this quote.
    let mut until_quote: Option<char> = None;
    let (mut mysql, mut sshpass) = (false, false);
    // The previous word was -H or --header.
    let mut header_option = false;

    for word in words {
        let after_header_option = std::mem::replace(
            &mut header_option,
            matches!(word.as_str(), "-H" | "--header"),
        );
        if let Some(quote) = until_quote {
            if word.ends_with(quote) {
                until_quote = None;
                out.push(quote.to_string());
            } else {
                out.push(String::new());
            }
            continue;
        }
        if secret_next || p_next {
            let was_p = p_next;
            (secret_next, p_next) = (false, false);
            if !word.starts_with('-') {
                if text {
                    until_quote = opens_quote(word);
                }
                out.push(REDACTED.to_string());
                continue;
            }
            // an option follows where a value was expected: fall through to judge it
            let _ = was_p;
        }
        if let Some(quote) = header {
            let scheme = ["bearer", "basic", "token", "digest"]
                .iter()
                .any(|scheme| word.eq_ignore_ascii_case(scheme));
            if scheme {
                out.push(word.clone());
                continue;
            }
            header = None;
            match quote {
                Some(quote) if word.ends_with(quote) => out.push(format!("{REDACTED}{quote}")),
                Some(quote) => {
                    until_quote = Some(quote);
                    out.push(REDACTED.to_string());
                }
                None => out.push(REDACTED.to_string()),
            }
            continue;
        }
        if userpass_next {
            userpass_next = false;
            if let Some(masked) = mask_user_password(word) {
                out.push(masked);
                continue;
            }
        }

        // Programs whose -p option takes a password.
        let program = word.rsplit('/').next().unwrap_or(word);
        if program.starts_with("mysql") || program.starts_with("mariadb") {
            mysql = true;
        } else if program == "sshpass" {
            sshpass = true;
        }
        if (mysql || sshpass) && word.starts_with("-p") && !word.starts_with("--") {
            // sshpass takes one password; what follows it is another program's options
            sshpass = false;
            if word.len() == 2 {
                p_next = true;
                out.push(word.clone());
            } else {
                out.push(format!("-p{REDACTED}"));
            }
            continue;
        }
        if matches!(word.as_str(), "-u" | "--user" | "--proxy-user") {
            userpass_next = true;
            out.push(word.clone());
            continue;
        }
        // A whole header in one argument: `Authorization: Bearer abc`.
        if let Some((name, value)) = word.split_once(": ")
            && !value.is_empty()
            && is_secret_header(name, after_header_option)
        {
            out.push(format!("{name}: {REDACTED}"));
            continue;
        }
        // A header name on its own (`"Authorization:`), its value in the words after it.
        let (quote, bare) = match word.chars().next() {
            Some(quote @ ('"' | '\'')) => (Some(quote), &word[1..]),
            _ => (None, word.as_str()),
        };
        if let Some(name) = bare.strip_suffix(':')
            && is_secret_header(name, after_header_option)
        {
            header = Some(quote);
            out.push(word.clone());
            continue;
        }

        match word.split_once('=') {
            // --user=admin:password
            Some((name, value)) if matches!(name, "--user" | "--proxy-user") => {
                match mask_user_password(value) {
                    Some(masked) => out.push(format!("{name}={masked}")),
                    None => out.push(word.clone()),
                }
            }
            // --password=value or API_KEY=value
            Some((name, value))
                if !value.is_empty() && is_option_name(name) && is_sensitive(name) =>
            {
                if text {
                    until_quote = opens_quote(value);
                }
                out.push(format!("{name}={REDACTED}"));
            }
            // --password value
            None if word.starts_with('-') && is_sensitive(word) => {
                secret_next = true;
                out.push(word.clone());
            }
            _ => out.push(redact_url_password(word)),
        }
    }
    out
}

/// `user:password` with the password masked, if `word` has that form. A word with a
/// `/` after the colon is taken to be `host:/path` (rsync, scp) and left alone.
fn mask_user_password(word: &str) -> Option<String> {
    let (user, password) = word.split_once(':')?;
    let plausible = !user.is_empty()
        && !user.starts_with('-')
        && !password.is_empty()
        && !password.contains('/');
    plausible.then(|| format!("{user}:{REDACTED}"))
}

/// Whether `name` is an HTTP header whose value is a secret. `as_header`: it was given
/// to an option that takes a header, so any name that sounds like a secret counts.
fn is_secret_header(name: &str, as_header: bool) -> bool {
    const KNOWN: [&str; 7] = [
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
    ];
    let lower = name.to_ascii_lowercase();
    KNOWN.contains(&lower.as_str()) || (as_header && is_option_name(name) && is_sensitive(name))
}

fn is_option_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c))
}

fn is_sensitive(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "pass",
        "pwd",
        "secret",
        "token",
        "key",
        "credential",
        "auth",
        "cookie",
    ]
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
    fn invisible_characters_that_can_carry_hidden_text_are_shown_as_escapes() {
        // AIDEV-NOTE: tag characters and variation selectors render as nothing, and can
        // spell out text (instructions for a model) that a human reviewer never sees.
        let hidden = [
            '\u{e0001}',
            '\u{e0041}',
            '\u{e007f}', // tag characters
            '\u{fe00}',
            '\u{fe0f}',
            '\u{e0100}',
            '\u{e01ef}', // variation selectors
            '\u{34f}',
            '\u{180b}',
            '\u{180e}', // joiner, Mongolian selectors
            '\u{115f}',
            '\u{1160}',
            '\u{3164}',
            '\u{ffa0}', // Hangul fillers
            '\u{fff9}',
            '\u{fffb}',
            '\u{2065}',
        ];
        for c in hidden {
            let text = format!("a{c}b");
            assert_eq!(
                clean_text(text.as_bytes()),
                format!("a\\u{{{:x}}}b", c as u32),
                "U+{:04X}",
                c as u32
            );
        }
        // ordinary non-ASCII text is untouched
        assert_eq!(clean_text("naïve 日本語 ✓".as_bytes()), "naïve 日本語 ✓");
    }

    fn masked(args: &[&str]) -> Vec<String> {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        redact_args(&args)
    }

    #[test]
    fn redact_args_knows_the_usual_ways_of_passing_a_password() {
        let cases: &[(&[&str], &[&str])] = &[
            (
                &["env", "MYSQL_PWD=hunter2", "mysqldump", "db"],
                &["env", "MYSQL_PWD=<redacted>", "mysqldump", "db"],
            ),
            (
                &["mysqldump", "-uroot", "-phunter2", "db"],
                &["mysqldump", "-uroot", "-p<redacted>", "db"],
            ),
            (
                &["/usr/bin/mysql", "-u", "root", "-p", "hunter2"],
                &["/usr/bin/mysql", "-u", "root", "-p", "<redacted>"],
            ),
            (
                &["sshpass", "-p", "hunter2", "ssh", "-p", "2222", "host"],
                &["sshpass", "-p", "<redacted>", "ssh", "-p", "2222", "host"],
            ),
            (
                &["sshpass", "-phunter2", "ssh", "host"],
                &["sshpass", "-p<redacted>", "ssh", "host"],
            ),
            (
                &["curl", "-u", "admin:hunter2", "https://x/"],
                &["curl", "-u", "admin:<redacted>", "https://x/"],
            ),
            (
                &["curl", "--user=admin:hunter2", "https://x/"],
                &["curl", "--user=admin:<redacted>", "https://x/"],
            ),
            (
                &["curl", "-H", "Authorization: Bearer abc123", "https://x/"],
                &["curl", "-H", "Authorization: <redacted>", "https://x/"],
            ),
            (
                &["curl", "-H", "X-Api-Key: abc123"],
                &["curl", "-H", "X-Api-Key: <redacted>"],
            ),
        ];
        for (given, want) in cases {
            assert_eq!(masked(given), *want, "{given:?}");
        }
    }

    #[test]
    fn redact_args_leaves_lookalikes_alone() {
        let unchanged: &[&[&str]] = &[
            &["ssh", "-p", "2222", "host"],
            &["tar", "-pxzf", "a.tgz"],
            &["mkdir", "-p", "/srv/www"],
            &["rsync", "-u", "src", "host:/backup/"],
            &["mysql", "-u", "root", "db"],
            &["curl", "-H", "Accept: text/plain", "https://x/"],
            &["id", "-u", "www-data"],
        ];
        for given in unchanged {
            assert_eq!(masked(given), *given, "{given:?}");
        }
    }

    #[test]
    fn a_word_that_merely_ends_in_a_colon_is_not_taken_for_a_secret_header() {
        // sudo -l output: NOPASSWD: is a tag, and what follows is the command
        let line = "    (ALL) NOPASSWD: /usr/bin/app --password=hunter2";
        assert_eq!(
            redact_text(line),
            "    (ALL) NOPASSWD: /usr/bin/app --password=<redacted>"
        );
        // but a well-known secret header is masked wherever it appears
        assert_eq!(
            redact_text("> Authorization: Bearer abc123"),
            "> Authorization: Bearer <redacted>"
        );
    }

    #[test]
    fn redact_text_masks_the_whole_of_a_quoted_secret() {
        let lines = [
            "0 3 * * * root DB_PASSWORD=\"hunter2 hunter3\" /usr/local/bin/backup --quiet",
            "0 3 * * * root /usr/local/bin/backup --password 'hunter2 hunter3' --quiet",
            "*/5 * * * * www curl -H \"Authorization: Bearer hunter2\" https://x/ping --quiet",
            "*/5 * * * * www curl -H 'X-Api-Key: hunter2' https://x/ping --quiet",
            "*/5 * * * * www curl -H 'Cookie: a=hunter2; b=hunter3' https://x/ping --quiet",
            "*/5 * * * * www curl -u admin:hunter2 https://x/ping --quiet",
            "@daily root MYSQL_PWD=hunter2 mysqldump -uroot -phunter3 db --quiet",
        ];
        for line in lines {
            let out = redact_text(line);
            assert!(!out.contains("hunter"), "{line:?} became {out:?}");
            // what follows the secret is still there
            assert!(out.ends_with("--quiet"), "{line:?} became {out:?}");
            assert!(out.contains(REDACTED), "{out:?}");
        }
        // text that only looks similar is left alone
        let plain = "Accept: text/plain for \"a b\" at 10:30: done";
        assert_eq!(redact_text(plain), plain);
    }

    #[test]
    fn unicode_line_and_paragraph_separators_are_shown_as_escapes() {
        // Some viewers break the line at U+2028 and U+2029, so data containing them could
        // pass off the rest of its line as a line of the tool's own.
        assert_eq!(
            clean_text("job ok\u{2028}[all checks passed]\u{2029}x".as_bytes()),
            "job ok\\u{2028}[all checks passed]\\u{2029}x"
        );
    }

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
