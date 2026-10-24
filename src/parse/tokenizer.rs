//! Byte-level tokenizer: classifies each whitespace-separated run of
//! characters into a [`TokenType`].
//!
//! Hot-path contract: `classify` must not allocate. The caller provides a
//! `Vec<Token>` buffer which is `clear()`-ed and filled.

use crate::parse::Token;
use crate::types::TokenType;

/// Split the line on ASCII whitespace, strip trailing punctuation (`.,;:!?`)
/// and classify each piece.
///
/// Zero allocations when `out`'s capacity is sufficient.
///
/// **Security note.** Log lines can carry ANSI/CSI escape sequences —
/// either from a program that mistakenly logs its own TTY output, or
/// deliberately crafted by an attacker who knows the output will be read
/// in a terminal. Any token containing a C0 control byte (except TAB) is
/// skipped here before it reaches the skeleton or the TUI. The tokenizer
/// never emits a control-char-bearing token.
pub fn classify<'a>(line: &'a str, out: &mut Vec<Token<'a>>) {
    out.clear();
    for raw in line.split_ascii_whitespace() {
        let piece = strip_trailing_punct(raw);
        if piece.is_empty() || contains_control(piece) {
            continue;
        }
        out.push(Token {
            ty: classify_one(piece),
            text: piece,
        });
    }
}

#[inline]
fn contains_control(s: &str) -> bool {
    s.bytes()
        .any(|b| b < 0x20 && b != b'\t' || b == 0x7f /* DEL */)
}

#[inline]
fn strip_trailing_punct(s: &str) -> &str {
    s.trim_end_matches(['.', ',', ';', ':', '!', '?'])
}

/// Classify a single whitespace-delimited piece.
///
/// The ordering of checks matters: we test the most-specific shapes first
/// so e.g. a UUID doesn't match the generic HEX HASH rule first.
pub fn classify_one(s: &str) -> TokenType {
    if s.is_empty() {
        return TokenType::Word;
    }
    // Fast rejects: pure alphabetic words.
    if is_all_alpha(s) {
        return TokenType::Word;
    }

    if is_uuid(s) {
        return TokenType::Uuid;
    }
    // Dates before IPv6 — HH:MM:SS has two colons and all-hex digits so a
    // permissive IPv6 predicate would steal it.
    if is_date_like(s) {
        return TokenType::Date;
    }
    if is_ipv4(s) || is_ipv6(s) {
        return TokenType::Ip;
    }
    if is_email(s) {
        return TokenType::Email;
    }
    if is_url(s) {
        return TokenType::Url;
    }
    if is_path(s) {
        return TokenType::Path;
    }
    if is_long_hex(s) {
        return TokenType::Hash;
    }
    if is_all_digits(s) {
        // Port vs. generic number is decided by context (bundle context_types).
        // Lone numeric runs are classified NUM; the context pass (P2) can
        // promote a NUM to PORT when preceded by the word "port".
        return TokenType::Num;
    }

    TokenType::Word
}

// ─────────────────────────────────────────────────────────────────────────────
// predicates
// ─────────────────────────────────────────────────────────────────────────────

#[inline]
fn is_all_alpha(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_alphabetic())
}

#[inline]
fn is_all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Four dot-separated octets each 0–255. Trailing port like `1.2.3.4:22`
/// is split at the colon before we see it (caller's split is on whitespace,
/// not colons), so we only need the pure form here.
fn is_ipv4(s: &str) -> bool {
    let mut parts = 0usize;
    for seg in s.split('.') {
        parts += 1;
        if parts > 4 {
            return false;
        }
        if seg.is_empty() || seg.len() > 3 {
            return false;
        }
        let n: u32 = match seg.parse() {
            Ok(n) => n,
            Err(_) => return false,
        };
        if n > 255 {
            return false;
        }
    }
    parts == 4
}

/// Permissive IPv6: at least two colons, only hex and colons, optional
/// trailing `%scope` or embedded `::`. We don't need RFC-strict parsing here.
fn is_ipv6(s: &str) -> bool {
    let body = s.split('%').next().unwrap_or(s);
    let colons = body.bytes().filter(|&b| b == b':').count();
    if colons < 2 {
        return false;
    }
    body.bytes().all(|b| b == b':' || b.is_ascii_hexdigit())
}

fn is_uuid(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        let want_dash = i == 8 || i == 13 || i == 18 || i == 23;
        if want_dash {
            if b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

fn is_email(s: &str) -> bool {
    let (local, domain) = match s.split_once('@') {
        Some(p) => p,
        None => return false,
    };
    !local.is_empty() && domain.contains('.') && !domain.contains('@')
}

fn is_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://") || s.starts_with("ftp://")
}

fn is_path(s: &str) -> bool {
    (s.starts_with('/') && s.len() > 1 && !s.starts_with("//"))
        || s.starts_with("./")
        || s.starts_with("../")
        || s.starts_with("~/")
}

/// Looks like a date/time shape. We accept a few common ones without being
/// strict — tokenizer errs on the side of over-tagging as DATE because the
/// skeleton treats date tokens as variables and that's the desired fold.
fn is_date_like(s: &str) -> bool {
    // ISO-8601-ish: 2026-10-24T12:34:56
    if s.len() >= 10 && s.as_bytes().get(4) == Some(&b'-') && s.as_bytes().get(7) == Some(&b'-') {
        return true;
    }
    // HH:MM:SS
    if s.len() == 8 && s.as_bytes()[2] == b':' && s.as_bytes()[5] == b':' {
        return s.as_bytes()[0..2]
            .iter()
            .chain(&s.as_bytes()[3..5])
            .chain(&s.as_bytes()[6..8])
            .all(|b| b.is_ascii_digit());
    }
    // syslog-style month abbrev (Oct, Nov, …) is a plain WORD; the day/time
    // tokens following are caught by the HH:MM:SS branch above.
    false
}

/// A long run of hex digits — git shas, md5, sha256, etc. Lower bound of 7
/// matches short git shas; upper bound unbounded.
fn is_long_hex(s: &str) -> bool {
    s.len() >= 7
        && s.bytes().all(|b| b.is_ascii_hexdigit())
        && s.bytes().any(|b| !b.is_ascii_digit()) // at least one hex letter — pure digits are NUM
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tok<'a>(s: &'a str, buf: &mut Vec<Token<'a>>) -> Vec<(TokenType, &'a str)> {
        classify(s, buf);
        buf.iter().map(|t| (t.ty, t.text)).collect()
    }

    #[test]
    fn classifies_primitives() {
        assert_eq!(classify_one("Accepted"), TokenType::Word);
        assert_eq!(classify_one("192.168.1.1"), TokenType::Ip);
        assert_eq!(classify_one("fe80::1"), TokenType::Ip);
        assert_eq!(classify_one("22"), TokenType::Num);
        assert_eq!(classify_one("/var/log/auth.log"), TokenType::Path);
        assert_eq!(classify_one("alice@example.com"), TokenType::Email);
        assert_eq!(classify_one("https://x.io/y"), TokenType::Url);
        assert_eq!(
            classify_one("550e8400-e29b-41d4-a716-446655440000"),
            TokenType::Uuid
        );
        assert_eq!(classify_one("deadbeef1234"), TokenType::Hash);
        assert_eq!(classify_one("2026-10-24T12:34:56"), TokenType::Date);
    }

    #[test]
    fn whitespace_split_strips_punct() {
        let mut buf = Vec::new();
        let got = tok(
            "Accepted password for alice from 10.0.0.1 port 22 ssh2",
            &mut buf,
        );
        let types: Vec<_> = got.iter().map(|(t, _)| *t).collect();
        assert_eq!(
            types,
            vec![
                TokenType::Word, // Accepted
                TokenType::Word, // password
                TokenType::Word, // for
                TokenType::Word, // alice
                TokenType::Word, // from
                TokenType::Ip,   // 10.0.0.1
                TokenType::Word, // port
                TokenType::Num,  // 22
                TokenType::Word, // ssh2
            ]
        );
    }

    #[test]
    fn pure_digits_are_num_not_hash() {
        assert_eq!(classify_one("1234567"), TokenType::Num);
        assert_eq!(classify_one("abcdef1"), TokenType::Hash);
    }

    #[test]
    fn empty_input_yields_no_tokens() {
        let mut buf = Vec::new();
        classify("   \t  ", &mut buf);
        assert!(buf.is_empty());
    }

    #[test]
    fn drops_tokens_containing_control_chars() {
        // A line like "GET /\x1b[31mred\x1b[0m HTTP" — the CSI escape
        // bytes vanish, surrounding real tokens survive.
        let mut buf = Vec::new();
        classify("GET /path \x1b[31mATTACK\x1b[0m HTTP/1.1", &mut buf);
        let texts: Vec<&str> = buf.iter().map(|t| t.text).collect();
        assert_eq!(texts, vec!["GET", "/path", "HTTP/1.1"]);
    }
}
