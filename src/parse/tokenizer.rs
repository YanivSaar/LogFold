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
        let (piece, bracketed) = strip_wrapping_punct(raw);
        if piece.is_empty() || contains_control(piece) {
            continue;
        }
        let ty = if bracketed && looks_like_uptime(piece) {
            // `[1.319177]`, `[    41.316966]` only — a bare numeric
            // decimal in the middle of a line stays NUM so a latency
            // value like `latency=0.123456` doesn't collapse to DATE.
            TokenType::Date
        } else {
            classify_one(piece)
        };
        out.push(Token { ty, text: piece });
    }
}

#[inline]
fn contains_control(s: &str) -> bool {
    s.bytes()
        .any(|b| b < 0x20 && b != b'\t' || b == 0x7f /* DEL */)
}

/// Strip at most one leading bracket/quote and at most one trailing
/// bracket/quote, then strip trailing clause-enders. Returns the
/// stripped slice plus a flag telling the caller whether a *square*
/// bracket was adjacent on either side — the uptime-float heuristic
/// consults that flag so only bracketed decimals (dmesg stamps) are
/// treated as dates.
///
/// Treats leading and trailing independently because dmesg's padded
/// format `[    1.319177]` is whitespace-split into `[` and
/// `1.319177]`: neither token is wrapped as a pair, but each has a
/// bracket on one side.
///
/// The old iterative `trim_matches` version stripped repeatedly and
/// mangled nested punctuation; this one strips at most one from each
/// end so `[text](url)` becomes `text](url`, `[1,2,3]` becomes
/// `1,2,3`, and `[abc` (unmatched) stays `[abc` only in the sense
/// that it's reported as bracketed on the left.
#[inline]
fn strip_wrapping_punct(s: &str) -> (&str, bool) {
    let bytes = s.as_bytes();
    let (mut start, mut end) = (0usize, bytes.len());
    let mut bracketed = false;
    if end > start {
        match bytes[start] {
            b'[' => {
                bracketed = true;
                start += 1;
            }
            b'(' | b'{' | b'<' | b'"' | b'\'' => start += 1,
            _ => {}
        }
    }
    if end > start {
        match bytes[end - 1] {
            b']' => {
                bracketed = true;
                end -= 1;
            }
            b')' | b'}' | b'>' | b'"' | b'\'' => end -= 1,
            _ => {}
        }
    }
    let unwrapped = &s[start..end];
    let trimmed = unwrapped.trim_end_matches(['.', ',', ';', ':', '!', '?']);
    (trimmed, bracketed)
}

/// Dmesg-style monotonic uptime stamp: `digits.digits` with 4+
/// fractional digits. Only invoked when the raw token was surrounded
/// by `[…]` so we don't fold ordinary high-precision decimals.
fn looks_like_uptime(s: &str) -> bool {
    let s = s.trim_start_matches(' ');
    if let Some(dot) = s.find('.') {
        let (int, frac) = (&s[..dot], &s[dot + 1..]);
        return !int.is_empty()
            && frac.len() >= 4
            && int.bytes().all(|b| b.is_ascii_digit())
            && frac.bytes().all(|b| b.is_ascii_digit());
    }
    false
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
    // HH:MM:SS.sss or HH:MM:SS,sss  (common in syslog/apps). The
    // fractional tail must be digits — the old implementation only
    // validated positions 0..8, so `12:34:56.foo` passed.
    if s.len() >= 10
        && s.as_bytes()[2] == b':'
        && s.as_bytes()[5] == b':'
        && (s.as_bytes()[8] == b'.' || s.as_bytes()[8] == b',')
    {
        return s.as_bytes()[0..2].iter().all(|b| b.is_ascii_digit())
            && s.as_bytes()[3..5].iter().all(|b| b.is_ascii_digit())
            && s.as_bytes()[6..8].iter().all(|b| b.is_ascii_digit())
            && s.as_bytes()[9..].iter().all(|b| b.is_ascii_digit());
    }
    // Note: dmesg uptime `[1.319177]` is detected in `classify()` via
    // `looks_like_uptime` + a bracketed-raw guard. We don't attempt to
    // match it here because a bare decimal like `latency=0.123456`
    // would otherwise collapse to {DATE} and erase the measurement.
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
    fn kernel_uptime_is_date() {
        // dmesg format: `[    1.319177] kernel: ...`
        let mut buf = Vec::new();
        classify("[    1.319177] kernel vmentry_ctrl", &mut buf);
        let types: Vec<_> = buf.iter().map(|t| t.ty).collect();
        // `[    1.319177]` strips to `1.319177` → Date; rest Words.
        assert_eq!(
            types,
            vec![TokenType::Date, TokenType::Word, TokenType::Word]
        );
    }

    #[test]
    fn wrapping_brackets_stripped() {
        assert_eq!(classify_one("[192.168.1.1]"), TokenType::Word); // classify_one doesn't strip
        let mut buf = Vec::new();
        classify("peer [192.168.1.1] joined", &mut buf);
        let got: Vec<_> = buf.iter().map(|t| (t.ty, t.text)).collect();
        assert_eq!(
            got,
            vec![
                (TokenType::Word, "peer"),
                (TokenType::Ip, "192.168.1.1"),
                (TokenType::Word, "joined"),
            ]
        );
    }

    #[test]
    fn plain_decimals_stay_word() {
        // Short-fraction decimals must NOT be classified as Date.
        assert_eq!(classify_one("1.5"), TokenType::Word);
        assert_eq!(classify_one("3.14159"), TokenType::Word);
        // Even a long-fraction decimal is Word if it's not bracketed —
        // the regression this guards is a measurement like `latency=0.123456`
        // being folded to {DATE} and erasing the number.
        assert_eq!(classify_one("0.123456"), TokenType::Word);
        assert_eq!(classify_one("34.1234567"), TokenType::Word);
    }

    #[test]
    fn uptime_requires_brackets() {
        let mut buf = Vec::new();
        // Bracketed: Date.
        classify("[1.319177] kernel ok", &mut buf);
        let types: Vec<_> = buf.iter().map(|t| t.ty).collect();
        assert_eq!(types[0], TokenType::Date);
        // Un-bracketed: Word.
        classify("latency 1.319177 ms", &mut buf);
        let types: Vec<_> = buf.iter().map(|t| t.ty).collect();
        assert_eq!(types[1], TokenType::Word);
    }

    #[test]
    fn hhmmss_fractional_tail_validated() {
        // Pre-fix bug: `12:34:56.foo` passed the HH:MM:SS.sss branch.
        assert_eq!(classify_one("12:34:56.foo"), TokenType::Word);
        assert_eq!(classify_one("12:34:56.789"), TokenType::Date);
    }

    #[test]
    fn strip_wrapping_once_only() {
        // Pre-fix bug: iterative trim ate matching pairs greedily and
        // mangled nested punctuation. `[1,2,3]` must become `1,2,3`,
        // not `1,2,3` with internal commas also trimmed; `[text](url)`
        // must become `text](url` (strip only the outer `[` + `]`
        // when they actually match as a pair, or nothing).
        let (s, b) = strip_wrapping_punct("[1,2,3]");
        assert_eq!(s, "1,2,3");
        assert!(b);
        // Leading `[` is still stripped and reported bracketed; the
        // dmesg case `[1.319177` (if ever un-closed) must still fold.
        let (s, b) = strip_wrapping_punct("[abc");
        assert_eq!(s, "abc");
        assert!(b);
        // `[1.319177]` tolerates leading whitespace inside the brackets
        // after split_ascii_whitespace, which collapses it anyway.
        let (s, b) = strip_wrapping_punct("[1.319177]");
        assert_eq!(s, "1.319177");
        assert!(b);
    }

    #[test]
    fn ms_fractional_time_is_date() {
        assert_eq!(classify_one("12:34:56.789"), TokenType::Date);
        assert_eq!(classify_one("12:34:56,789"), TokenType::Date);
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
