//! Glob matching for permission patterns and permission resources.
//!
//! Syntax (deliberately tiny, so a grant is easy to read and hard to get wrong):
//!
//! - `*`  matches any run of characters except `/`
//! - `**` matches any run of characters, including `/`
//! - `?`  matches exactly one character other than `/`
//! - everything else matches itself (there are no escapes and no character classes)

/// Returns true when `text` matches `pattern` in full.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let tokens = tokenize(pattern);
    let text: Vec<char> = text.chars().collect();
    let n = text.len();

    // AIDEV-NOTE: dynamic programming, O(pattern x text) time with no backtracking, so a
    // hostile pattern or resource name cannot make matching slow.
    // reach[j] is true when the tokens consumed so far can match the first j characters.
    let mut reach = vec![false; n + 1];
    if let Some(first) = reach.first_mut() {
        *first = true;
    }
    for token in &tokens {
        let mut next = vec![false; n + 1];
        match token {
            Token::Literal(c) => {
                for j in 0..n {
                    next[j + 1] = reach[j] && text[j] == *c;
                }
            }
            Token::AnyOne => {
                for j in 0..n {
                    next[j + 1] = reach[j] && text[j] != '/';
                }
            }
            Token::Star => {
                next[0] = reach[0];
                for j in 1..=n {
                    next[j] = reach[j] || (next[j - 1] && text[j - 1] != '/');
                }
            }
            Token::DoubleStar => {
                next[0] = reach[0];
                for j in 1..=n {
                    next[j] = reach[j] || next[j - 1];
                }
            }
        }
        reach = next;
    }
    reach[n]
}

enum Token {
    Literal(char),
    AnyOne,
    Star,
    DoubleStar,
}

fn tokenize(pattern: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '*' => {
                let mut double = false;
                while chars.peek() == Some(&'*') {
                    chars.next();
                    double = true;
                }
                tokens.push(if double {
                    Token::DoubleStar
                } else {
                    Token::Star
                });
            }
            '?' => tokens.push(Token::AnyOne),
            other => tokens.push(Token::Literal(other)),
        }
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::glob_match;

    #[test]
    fn matches_follow_the_documented_syntax() {
        let cases: &[(&str, &str, bool)] = &[
            // literals
            ("nginx.service", "nginx.service", true),
            ("nginx.service", "nginx.servicex", false),
            ("nginx.service", "nginx.servic", false),
            ("", "", true),
            ("", "a", false),
            // single star stays inside one path segment
            ("nginx*", "nginx.service", true),
            ("*", "", true),
            ("*", "a/b", false),
            ("/var/log/*", "/var/log/syslog", true),
            ("/var/log/*", "/var/log/nginx/access.log", false),
            ("/etc/*.conf", "/etc/a.conf", true),
            ("/etc/*.conf", "/etc/a/b.conf", false),
            ("/proc/*/environ", "/proc/123/environ", true),
            ("net.ipv4.*", "net.ipv4.ip_forward", true),
            ("net.ipv4.*", "net.ipv6.ip_forward", false),
            ("www-data/*", "www-data/nginx", true),
            ("www-data/*", "root/nginx", false),
            // double star crosses segments
            ("**", "a/b", true),
            ("/var/log/**", "/var/log/nginx/access.log", true),
            ("/var/log/**", "/var/log/", true),
            ("/var/log/**", "/var/log", false),
            ("/var/log/**", "/var/logs/x", false),
            ("**/*.key", "/etc/ssl/private/server.key", true),
            ("**/*.key", "/etc/ssl/private/server.crt", false),
            ("**/.ssh/**", "/root/.ssh/id_rsa", true),
            // question mark
            ("a?c", "abc", true),
            ("a?c", "a/c", false),
            ("a?c", "ac", false),
            // non-ASCII text is matched per character, not per byte
            ("é*", "été", true),
            ("?", "é", true),
        ];
        for (pattern, text, want) in cases {
            assert_eq!(
                glob_match(pattern, text),
                *want,
                "glob_match({pattern:?}, {text:?})"
            );
        }
    }

    #[test]
    fn many_stars_do_not_cause_exponential_backtracking() {
        // A naive backtracking matcher takes longer than the age of the universe on this.
        let pattern = "*a".repeat(40) + "b";
        let text = "a".repeat(200);
        assert!(!glob_match(&pattern, &text));
    }
}
