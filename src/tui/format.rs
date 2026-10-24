//! Shared TUI display helpers: thousands-grouped counts and
//! control-char-safe string sanitisation.
//!
//! Everything here is pure: no state, no I/O, no ratatui calls.

use unicode_width::UnicodeWidthStr;

/// Group a `u64` into thousands with commas. Hot enough that we avoid
/// `format!` and intermediate allocations.
pub fn fmt_count(n: u64) -> String {
    if n < 1_000 {
        return n.to_string();
    }
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    let first = bytes.len() % 3;
    if first > 0 {
        out.push_str(&s[..first]);
    }
    for (i, chunk) in bytes[first..].chunks(3).enumerate() {
        if i > 0 || first > 0 {
            out.push(',');
        }
        // Safe: `s` is ASCII digits.
        out.push_str(std::str::from_utf8(chunk).unwrap());
    }
    out
}

/// Replace every C0 / C1 control char and the DEL byte with `·`, so a
/// hostile log line can't inject ANSI escapes, reposition the cursor,
/// or hide payload behind backspaces when ratatui renders it. Keeps
/// combining marks, wide chars and emoji intact.
pub fn sanitize_for_display(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\n' | '\r' | '\t' => out.push(' '),
            c if (c as u32) < 0x20 => out.push('·'),
            c if (0x7f..=0x9f).contains(&(c as u32)) => out.push('·'),
            c => out.push(c),
        }
    }
    out
}

/// Truncate `s` to at most `max_cols` display columns (grapheme-wise
/// approximation via `unicode_width`), appending `…` when truncated.
/// Preserves char boundaries.
pub fn truncate_cols(s: &str, max_cols: usize) -> String {
    if s.width() <= max_cols {
        return s.to_string();
    }
    if max_cols == 0 {
        return String::new();
    }
    let mut out = String::with_capacity(s.len().min(max_cols * 2));
    let mut used = 0usize;
    for ch in s.chars() {
        let w = unicode_width::UnicodeWidthChar::width(ch).unwrap_or(0);
        if used + w + 1 > max_cols {
            out.push('…');
            return out;
        }
        used += w;
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_count_edges() {
        assert_eq!(fmt_count(0), "0");
        assert_eq!(fmt_count(999), "999");
        assert_eq!(fmt_count(1_000), "1,000");
        assert_eq!(fmt_count(1_000_000), "1,000,000");
        assert_eq!(fmt_count(u64::MAX), "18,446,744,073,709,551,615");
    }

    #[test]
    fn sanitize_strips_escapes() {
        let evil = "ok\x1b[31mRED\x1b[0m\x07\x7f";
        let s = sanitize_for_display(evil);
        assert!(!s.contains('\x1b'));
        assert!(!s.contains('\x07'));
        assert!(!s.contains('\x7f'));
    }

    #[test]
    fn sanitize_keeps_unicode() {
        let s = sanitize_for_display("héllo 日本 👨‍👩‍👧");
        assert!(s.contains('é'));
        assert!(s.contains('日'));
        assert!(s.contains('👨'));
    }

    #[test]
    fn sanitize_tabs_become_spaces() {
        assert_eq!(sanitize_for_display("a\tb\nc"), "a b c");
    }

    #[test]
    fn truncate_cols_ascii() {
        assert_eq!(truncate_cols("hello", 10), "hello");
        assert_eq!(truncate_cols("hello", 4), "hel…");
    }

    #[test]
    fn truncate_cols_wide() {
        // CJK chars are width 2 each.
        let s = "日本語テスト";
        let t = truncate_cols(s, 6);
        // Should fit about 2 chars + "…" within 6 cols.
        assert!(t.ends_with('…'));
        assert!(t.width() <= 6);
    }
}
