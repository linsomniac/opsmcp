//! Bearer tokens for the HTTPS transport.
//!
//! AIDEV-NOTE: tokens are 256 bits from the kernel CSPRNG, so the configuration stores a
//! plain SHA-256 of the token. A slow password hash would add nothing here: there is no
//! low-entropy secret to protect from guessing.

use sha2::{Digest, Sha256};

/// Lowercase hex SHA-256 of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    hex(Sha256::digest(data).as_slice())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A newly generated token and the hash to put in the configuration.
pub struct NewToken {
    pub token: String,
    pub sha256: String,
}

/// Generates a token. Fails only if the kernel cannot supply random bytes.
pub fn generate() -> Result<NewToken, String> {
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).map_err(|e| format!("cannot get random bytes: {e}"))?;
    let token = format!("opsmcp_{}", hex(&secret));
    let sha256 = sha256_hex(token.as_bytes());
    Ok(NewToken { token, sha256 })
}

/// A credential held in memory: a bearer token that is passed on, or one read from a file.
///
/// AIDEV-NOTE: there is deliberately no `Display`, and `Debug` prints a placeholder, so a
/// secret cannot end up in a log line, an error message or an audit record by way of a
/// format string. The only way to the text is `expose`, which is easy to search for.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(text: impl Into<String>) -> Secret {
        Secret(text.into())
    }

    /// The secret itself. Only for handing it to whatever it authenticates to.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[secret]")
    }
}

/// Normalizes a SHA-256 written as hex, with or without `:` separators and in either
/// case, to 64 lowercase hex digits. Returns `None` if it is not a SHA-256.
pub fn normalize_sha256(text: &str) -> Option<String> {
    let digits: String = text
        .chars()
        .filter(|c| *c != ':')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    (digits.len() == 64 && digits.bytes().all(|b| b.is_ascii_hexdigit())).then_some(digits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_matches_the_published_test_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn a_generated_token_is_prefixed_random_and_hashes_to_its_stored_form() {
        let a = generate().unwrap();
        let b = generate().unwrap();
        assert!(a.token.starts_with("opsmcp_"), "{}", a.token);
        let secret = &a.token["opsmcp_".len()..];
        assert_eq!(secret.len(), 64);
        assert!(secret.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a.token, b.token);
        assert_eq!(sha256_hex(a.token.as_bytes()), a.sha256);
    }

    #[test]
    fn normalize_sha256_accepts_openssl_style_fingerprints() {
        let plain = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let openssl = "BA:78:16:BF:8F:01:CF:EA:41:41:40:DE:5D:AE:22:23:B0:03:61:A3:96:17:7A:9C:B4:10:FF:61:F2:00:15:AD";
        assert_eq!(normalize_sha256(plain).as_deref(), Some(plain));
        assert_eq!(normalize_sha256(openssl).as_deref(), Some(plain));
        assert_eq!(normalize_sha256(&plain[..62]), None);
        assert_eq!(normalize_sha256(&plain.replace('b', "g")), None);
        assert_eq!(normalize_sha256(""), None);
    }

    #[test]
    fn a_secret_does_not_show_itself_when_printed() {
        let secret = Secret::new("opsmcp_hunter2");
        assert_eq!(format!("{secret:?}"), "[secret]");
        assert_eq!(format!("{:?}", Some(secret.clone())), "Some([secret])");
        assert_eq!(secret.expose(), "opsmcp_hunter2");
    }
}
