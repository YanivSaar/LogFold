//! Key=value pair log line parser (logfmt / syslog-ng KV / nginx key=value).
//!
//! Handles both bare `key=value` runs and double-quoted values with
//! embedded spaces and escaped quotes. Returns the recognised message
//! field plus a few known tags; the rest is discarded (v0.4 scope).

/// A KV-parsed log line.
#[derive(Debug, Clone)]
pub struct ParsedKv<'a> {
    pub msg: &'a str,
    pub level: Option<&'a str>,
    pub timestamp: Option<&'a str>,
    pub service: Option<&'a str>,
}

/// Keys that count as the free-form message body.
const MSG_KEYS: &[&str] = &["msg", "message", "event", "log"];

/// Parse `key=value` pairs from `line`. Returns `None` if no `=` is
/// present at all (so single-key logs still work) or no recognised
/// message field was found.
pub fn parse(line: &str) -> Option<ParsedKv<'_>> {
    // Fast reject: a KV line must contain at least one '=' preceded by
    // a word char. logfmt lines always do.
    if !line.contains('=') {
        return None;
    }

    let mut msg = None;
    let mut level = None;
    let mut timestamp = None;
    let mut service = None;

    for (k, v) in KvIter::new(line) {
        if msg.is_none() && MSG_KEYS.contains(&k) {
            msg = Some(v);
        } else if level.is_none() && matches!(k, "level" | "lvl" | "severity") {
            level = Some(v);
        } else if timestamp.is_none() && matches!(k, "timestamp" | "ts" | "time" | "@timestamp") {
            timestamp = Some(v);
        } else if service.is_none()
            && matches!(k, "service" | "svc" | "component" | "app" | "application")
        {
            service = Some(v);
        }
    }

    msg.map(|m| ParsedKv {
        msg: m,
        level,
        timestamp,
        service,
    })
}

/// Zero-alloc iterator over `k=v` pairs in a logfmt-style line.
///
/// Grammar handled:
///
/// * `key` is ASCII word (letters, digits, `_`, `-`, `.`).
/// * Values are either a bare run of non-whitespace, or a double-
///   quoted string with `\"` and `\\` escapes.
/// * Keys without `=` are skipped.
struct KvIter<'a> {
    rest: &'a str,
}

impl<'a> KvIter<'a> {
    fn new(s: &'a str) -> Self {
        KvIter { rest: s }
    }
}

impl<'a> Iterator for KvIter<'a> {
    type Item = (&'a str, &'a str);
    fn next(&mut self) -> Option<Self::Item> {
        // Skip whitespace.
        self.rest = self.rest.trim_start();
        if self.rest.is_empty() {
            return None;
        }

        // Read key chars.
        let key_end = self
            .rest
            .find(|c: char| !is_key_char(c))
            .unwrap_or(self.rest.len());
        if key_end == 0 {
            // Not a key start; skip one char and continue.
            let skip = self
                .rest
                .char_indices()
                .nth(1)
                .map(|(i, _)| i)
                .unwrap_or(self.rest.len());
            self.rest = &self.rest[skip..];
            return self.next();
        }
        let key = &self.rest[..key_end];
        let after_key = &self.rest[key_end..];

        if !after_key.starts_with('=') {
            // No value for this key; advance past it.
            self.rest = after_key;
            return self.next();
        }
        let after_eq = &after_key[1..];

        // Value: either a quoted string or a run of non-whitespace.
        let (value, consumed) = if let Some(stripped) = after_eq.strip_prefix('"') {
            // Scan for an unescaped closing quote.
            let bytes = stripped.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                match bytes[i] {
                    b'\\' => i = (i + 2).min(bytes.len()),
                    b'"' => break,
                    _ => i += 1,
                }
            }
            let end = i.min(bytes.len());
            // consumed = 1 (opening quote) + end + 1 (closing quote if present)
            let close = if end < bytes.len() { 1 } else { 0 };
            (&stripped[..end], 1 + end + close)
        } else {
            let end = after_eq
                .find(|c: char| c.is_ascii_whitespace())
                .unwrap_or(after_eq.len());
            (&after_eq[..end], end)
        };

        self.rest = &after_eq[consumed..];
        Some((key, value))
    }
}

fn is_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '@')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_logfmt() {
        let line = r#"level=info msg="request complete" status=200 duration=12ms"#;
        let p = parse(line).unwrap();
        assert_eq!(p.msg, "request complete");
        assert_eq!(p.level, Some("info"));
    }

    #[test]
    fn parses_syslog_ng_kv_shape() {
        let line =
            r#"time="2026-10-24T12:00:00Z" level=warn message=rate_limit_exceeded service=api"#;
        let p = parse(line).unwrap();
        assert_eq!(p.msg, "rate_limit_exceeded");
        assert_eq!(p.service, Some("api"));
        assert_eq!(p.level, Some("warn"));
    }

    #[test]
    fn returns_none_without_recognised_msg_key() {
        let line = "foo=bar baz=qux";
        assert!(parse(line).is_none());
    }

    #[test]
    fn handles_escaped_quotes_in_value() {
        let line = r#"msg="said \"hello\" to user" level=info"#;
        let p = parse(line).unwrap();
        assert!(p.msg.contains(r#"said \"hello\""#));
    }

    #[test]
    fn returns_none_without_any_eq() {
        assert!(parse("just a plain line of text").is_none());
    }
}
