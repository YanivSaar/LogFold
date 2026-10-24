//! Minimal syslog parser (RFC 3164 and 5424).
//!
//! Strips the envelope (optional `<pri>`, timestamp, hostname,
//! `process[pid]:`) and hands back the message body plus whatever
//! structured header fields it could recognise. The folding engine then
//! tokenises `msg` instead of the full line, which stops `sshd[1030]:`
//! and `sshd[1050]:` from anchoring separate patterns.
//!
//! Format detection is heuristic and cheap: the parser returns `None`
//! if the line doesn't look like syslog at all, and the caller falls
//! back to raw tokenisation.

use crate::parse::Token;
use crate::types::TokenType;

/// A parsed syslog header plus the free-form message body.
///
/// All header slots borrow from the input line. `msg` is always set to
/// the final message substring (it is the line itself when no header
/// matched, but [`parse`] returns `None` in that case anyway).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSyslog<'a> {
    pub timestamp: Option<&'a str>,
    pub host: Option<&'a str>,
    pub process: Option<&'a str>,
    pub pid: Option<&'a str>,
    pub msg: &'a str,
}

/// Try to parse `line` as syslog. Returns `None` if the line doesn't
/// look like either RFC 3164 or RFC 5424, so callers can fall back to
/// raw tokenisation without a second pass.
pub fn parse(line: &str) -> Option<ParsedSyslog<'_>> {
    let s = strip_pri(line);
    if let Some(p) = parse_5424(s) {
        return Some(p);
    }
    parse_3164(s)
}

/// Build a header-typed slot stream for the parsed syslog envelope, in
/// the order the header fields appear on the wire. Used by the engine
/// when it wants per-pattern variables for `host` and `process` too,
/// not just the body.
pub fn header_tokens<'a>(p: &ParsedSyslog<'a>, out: &mut Vec<Token<'a>>) {
    out.clear();
    if let Some(ts) = p.timestamp {
        out.push(Token {
            ty: TokenType::Date,
            text: ts,
        });
    }
    if let Some(h) = p.host {
        out.push(Token {
            ty: TokenType::Word,
            text: h,
        });
    }
    if let Some(proc) = p.process {
        out.push(Token {
            ty: TokenType::Word,
            text: proc,
        });
    }
    if let Some(pid) = p.pid {
        out.push(Token {
            ty: TokenType::Num,
            text: pid,
        });
    }
}

/// Strip an optional `<pri>` prefix (RFC 3164 and 5424 both allow it).
/// Returns the remainder, or the input unchanged on no prefix.
fn strip_pri(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'<') {
        return s;
    }
    let end = match bytes.iter().position(|&b| b == b'>') {
        Some(p) => p,
        None => return s,
    };
    // digits only between < and >, 1-3 of them.
    if end <= 1 || end > 4 {
        return s;
    }
    if !bytes[1..end].iter().all(|b| b.is_ascii_digit()) {
        return s;
    }
    &s[end + 1..]
}

/// RFC 3164: `Mmm dd HH:MM:SS host process[pid]: msg`.
/// Day can be `d` or `dd` (with or without leading space).
fn parse_3164(s: &str) -> Option<ParsedSyslog<'_>> {
    // 1. Month abbrev (3 ascii alpha chars) + space.
    let month = s.get(..3)?;
    if !is_month_abbrev(month) {
        return None;
    }
    let rest = s.get(3..)?.strip_prefix(' ')?;

    // 2. Day: 1 or 2 digits, optional leading space ("Oct  3" vs "Oct 23").
    let (day_end, rest) = read_day(rest)?;
    let day = &rest[..day_end];
    let rest = &rest[day_end..].trim_start_matches(' ');

    // 3. Time: HH:MM:SS
    let time = rest.get(..8)?;
    if !is_hhmmss(time) {
        return None;
    }
    let rest = rest.get(8..)?.strip_prefix(' ')?;

    // Combine month + day + time into one timestamp slice spanning the
    // original string. Day is 1 or 2 bytes, "Mmm " is 4 bytes, " HH:MM:SS"
    // is 9 bytes; the slice ends at the current `rest` pointer in `s`.
    let ts_start = 0usize;
    let ts_end = s.len() - rest.len() - 1; // -1 for the trailing space
    let timestamp = Some(&s[ts_start..ts_end]);

    // 4. Host: run of non-space.
    let (host, rest) = read_until_space(rest)?;
    let rest = rest.strip_prefix(' ')?;

    // 5. Optional "process[pid]:" or "process:" prefix.
    let (process, pid, msg) = split_proc_prefix(rest).unwrap_or((None, None, rest));

    // We only need day as a header slot via timestamp above; the local
    // `day` and `month` bindings exist for readability but aren't
    // surfaced separately.
    let _ = (month, day);

    Some(ParsedSyslog {
        timestamp,
        host: Some(host),
        process,
        pid,
        msg,
    })
}

/// RFC 5424: `VERSION ISO-TS HOST APP PID MSGID [SD]* MSG` (after `<pri>`).
///
/// The VERSION field is a single digit, usually `1`. We only accept
/// `1 ` as the opener to keep the hot path cheap.
fn parse_5424(s: &str) -> Option<ParsedSyslog<'_>> {
    let rest = s.strip_prefix("1 ")?;
    // ISO timestamp up to the next space. Must start with a digit.
    if !rest.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return None;
    }
    let (timestamp, rest) = read_until_space(rest)?;
    let rest = rest.strip_prefix(' ')?;
    let (host, rest) = read_until_space(rest)?;
    let rest = rest.strip_prefix(' ')?;
    let (app, rest) = read_until_space(rest)?;
    let rest = rest.strip_prefix(' ')?;
    let (pid, rest) = read_until_space(rest)?;
    let rest = rest.strip_prefix(' ')?;
    let (_msgid, rest) = read_until_space(rest)?;
    let mut rest = rest.strip_prefix(' ')?;

    // Structured data: either a single `-` NILVALUE, or one or more
    // `[...]` groups. v0.2 treats the entire SD section as opaque;
    // v0.3 will promote fields into typed variables.
    if let Some(after_dash) = rest.strip_prefix("- ") {
        rest = after_dash;
    } else if rest == "-" {
        rest = "";
    } else {
        while rest.starts_with('[') {
            let close = rest.find(']')?;
            rest = &rest[close + 1..];
            if let Some(stripped) = rest.strip_prefix(' ') {
                rest = stripped;
            }
        }
    }

    // A sole `-` means no SD and no body. If the body is `-`, treat as empty.
    let msg = if rest == "-" { "" } else { rest };

    Some(ParsedSyslog {
        timestamp: dash_as_none(timestamp),
        host: dash_as_none(host),
        process: dash_as_none(app),
        pid: dash_as_none(pid),
        msg,
    })
}

#[inline]
fn dash_as_none(s: &str) -> Option<&str> {
    if s == "-" {
        None
    } else {
        Some(s)
    }
}

/// Split `process[pid]: msg` or `process: msg`. Returns `None` if the
/// prefix doesn't look like a process tag at all (caller treats the
/// whole thing as msg).
fn split_proc_prefix(s: &str) -> Option<(Option<&str>, Option<&str>, &str)> {
    // Find the first ':' or '[' within the first ~64 bytes (longer than
    // any real process name, bounds the scan on hostile input).
    let scan_end = s.len().min(64);
    let colon = s.as_bytes()[..scan_end].iter().position(|&b| b == b':')?;
    let bracket = s.as_bytes()[..colon].iter().position(|&b| b == b'[');

    let (proc, pid) = match bracket {
        Some(bi) => {
            // process[pid]:
            let close = s.as_bytes()[bi..colon].iter().position(|&b| b == b']')?;
            let proc = &s[..bi];
            let pid = &s[bi + 1..bi + close];
            if proc.is_empty() || !pid.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            (Some(proc), Some(pid))
        }
        None => {
            let proc = &s[..colon];
            if proc.is_empty() || !is_proc_name(proc) {
                return None;
            }
            (Some(proc), None)
        }
    };

    let after = s.get(colon + 1..)?;
    let msg = after.strip_prefix(' ').unwrap_or(after);
    Some((proc, pid, msg))
}

#[inline]
fn is_month_abbrev(s: &str) -> bool {
    matches!(
        s,
        "Jan"
            | "Feb"
            | "Mar"
            | "Apr"
            | "May"
            | "Jun"
            | "Jul"
            | "Aug"
            | "Sep"
            | "Oct"
            | "Nov"
            | "Dec"
    )
}

#[inline]
fn is_hhmmss(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() == 8
        && b[2] == b':'
        && b[5] == b':'
        && b[0..2].iter().all(|c| c.is_ascii_digit())
        && b[3..5].iter().all(|c| c.is_ascii_digit())
        && b[6..8].iter().all(|c| c.is_ascii_digit())
}

/// Read the day portion of an RFC 3164 timestamp: 1 or 2 digits, with
/// an optional *leading* space (`"Oct  3"`).
fn read_day(s: &str) -> Option<(usize, &str)> {
    let s2 = s.strip_prefix(' ').unwrap_or(s);
    let bytes = s2.as_bytes();
    let n = match (bytes.first(), bytes.get(1)) {
        (Some(a), Some(b)) if a.is_ascii_digit() && b.is_ascii_digit() => 2,
        (Some(a), _) if a.is_ascii_digit() => 1,
        _ => return None,
    };
    Some((n, s2))
}

fn read_until_space(s: &str) -> Option<(&str, &str)> {
    let i = s.bytes().position(|b| b == b' ')?;
    Some((&s[..i], &s[i..]))
}

#[inline]
fn is_proc_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_classic_sshd_line() {
        let line =
            "Oct 23 09:14:10 host sshd[1030]: Failed password for alice from 203.0.113.5 port 60000 ssh2";
        let p = parse(line).expect("should parse");
        assert_eq!(p.timestamp, Some("Oct 23 09:14:10"));
        assert_eq!(p.host, Some("host"));
        assert_eq!(p.process, Some("sshd"));
        assert_eq!(p.pid, Some("1030"));
        assert_eq!(
            p.msg,
            "Failed password for alice from 203.0.113.5 port 60000 ssh2"
        );
    }

    #[test]
    fn single_digit_day_with_double_space() {
        let line = "Oct  3 09:14:10 host sshd[1030]: Accepted key for root";
        let p = parse(line).expect("should parse");
        assert_eq!(p.timestamp, Some("Oct  3 09:14:10"));
        assert_eq!(p.pid, Some("1030"));
        assert_eq!(p.msg, "Accepted key for root");
    }

    #[test]
    fn strips_optional_pri() {
        let line = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed";
        let p = parse(line).expect("should parse");
        assert_eq!(p.host, Some("mymachine"));
        assert_eq!(p.process, Some("su"));
        assert_eq!(p.pid, None);
        assert_eq!(p.msg, "'su root' failed");
    }

    #[test]
    fn parses_rfc5424() {
        let line =
            "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 [exampleSDID@32473 iut=\"3\"] 'su root' failed";
        let p = parse(line).expect("should parse");
        assert_eq!(p.timestamp, Some("2003-10-11T22:14:15.003Z"));
        assert_eq!(p.host, Some("mymachine.example.com"));
        assert_eq!(p.process, Some("su"));
        assert_eq!(p.pid, None); // field was "-"
        assert_eq!(p.msg, "'su root' failed");
    }

    #[test]
    fn rfc5424_no_structured_data() {
        let line = "<34>1 2003-10-11T22:14:15.003Z host app 12 msgid - hello world";
        let p = parse(line).expect("should parse");
        assert_eq!(p.pid, Some("12"));
        assert_eq!(p.msg, "hello world");
    }

    #[test]
    fn returns_none_on_non_syslog() {
        assert!(parse("not a syslog line").is_none());
        assert!(
            parse("127.0.0.1 - - [10/Oct/2000:13:55:36] \"GET / HTTP/1.0\" 200 2326").is_none()
        );
    }

    #[test]
    fn no_process_prefix_leaves_whole_msg() {
        // Host line without a trailing `process[pid]:` block.
        let line = "Oct 23 09:14:10 host something arbitrary with no colon";
        let p = parse(line).expect("should parse");
        assert_eq!(p.host, Some("host"));
        assert_eq!(p.process, None);
        assert_eq!(p.pid, None);
        assert_eq!(p.msg, "something arbitrary with no colon");
    }
}
