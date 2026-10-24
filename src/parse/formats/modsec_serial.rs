//! ModSecurity v2 serial audit log parser.
//!
//! The serial format is a multi-section ASCII dump, one event per
//! transaction, delimited by `--<unique_id>-A--` through
//! `--<unique_id>-Z--`. The multiline assembler in
//! [`crate::ingest::multiline`] joins the sections into a single
//! `String`; this parser then plucks out the triage-relevant fields
//! and synthesises a compact fold-key the engine can tokenise cleanly.
//!
//! Without this preprocess, the raw tokeniser keeps the random
//! `unique_id` literal in the skeleton, which means every single
//! transaction becomes its own "pattern" — turning millions of
//! lines into thousands of near-identical rows at the same middling
//! score. See `tests/modsec_serial_tests.rs`.
//!
//! The fold-key shape intentionally matches the v3 JSON parser's
//! output so Detail / Score views don't need to know which flavour
//! produced the event:
//!
//! ```text
//! modsec {verdict} rule {rule_id} [{severity}]: {msg} // {method} {uri} -> {status}
//! ```

use std::sync::OnceLock;

use regex::Regex;

/// A parsed ModSec v2 serial transaction. The `fold_key` is what
/// the hot path tokenises; the other fields are kept for richer
/// future Detail views (per-rule top-K, per-URI top-K, etc.).
#[derive(Debug, Clone)]
pub struct ParsedModsecSerial {
    pub fold_key: String,
    pub rule_ids: Vec<String>,
    pub severity: Option<String>,
    pub msg: Option<String>,
    pub client_ip: Option<String>,
    pub method: Option<String>,
    pub uri: Option<String>,
    pub host: Option<String>,
    pub status: Option<u32>,
    pub verdict: Verdict,
}

/// What the WAF decided for this transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Verdict {
    #[default]
    Pass,
    Warning,
    Denied,
}

impl Verdict {
    fn label(self) -> &'static str {
        match self {
            Verdict::Pass => "pass",
            Verdict::Warning => "warn",
            Verdict::Denied => "deny",
        }
    }
}

/// Parse an assembled multi-section ModSec serial event.
///
/// Returns `None` if the event doesn't look like a ModSec entry at
/// all (no section markers) so the engine falls back to raw folding.
pub fn parse(event: &str) -> Option<ParsedModsecSerial> {
    // Fast reject: must have at least one `-A--` opener.
    if !event.contains("-A--") {
        return None;
    }
    let sections = split_sections(event);
    let section_a = sections.get("A").copied().unwrap_or("");
    let section_b = sections.get("B").copied().unwrap_or("");
    let section_f = sections.get("F").copied().unwrap_or("");
    let section_h = sections.get("H").copied().unwrap_or("");

    let client_ip = parse_client_ip(section_a);
    let (method, uri) = parse_request_line(section_b);
    let host = parse_header(section_b, "Host");
    let status = parse_status(section_f);

    let (verdict, rule_ids, severity, msg) = parse_section_h(section_h);

    // Primary rule drives the fold key. "-" when no rule matched.
    let primary_rule = rule_ids.first().cloned().unwrap_or_else(|| "-".into());
    let sev_tag = severity.as_deref().unwrap_or("");
    let msg_short = msg.as_deref().map(|s| truncate(s, 80)).unwrap_or("");
    let uri_shape = uri.as_deref().map(normalise_uri).unwrap_or_else(|| "-".into());
    let method_s = method.as_deref().unwrap_or("-");
    let status_s = status
        .map(|c| c.to_string())
        .unwrap_or_else(|| "-".into());

    let fold_key = format!(
        "modsec {verdict} rule {rule} [{sev}]: {msg} // {method} {uri} -> {status}",
        verdict = verdict.label(),
        rule = primary_rule,
        sev = sev_tag,
        msg = msg_short,
        method = method_s,
        uri = uri_shape,
        status = status_s,
    );

    Some(ParsedModsecSerial {
        fold_key,
        rule_ids,
        severity,
        msg,
        client_ip,
        method,
        uri,
        host,
        status,
        verdict,
    })
}

// ---- section splitting ----

/// Split a joined event into a `{"A": "...", "B": "...", ...}` map
/// keyed by the one-letter section tag. Opening lines (`--id-X--`)
/// are consumed and discarded.
fn split_sections(event: &str) -> std::collections::HashMap<&'static str, &str> {
    static MARKER: OnceLock<Regex> = OnceLock::new();
    let re = MARKER.get_or_init(|| {
        Regex::new(r"(?m)^-{2,}[A-Za-z0-9@._-]+-([A-KZ])-{2,}\s*$").expect("valid marker regex")
    });

    let mut out = std::collections::HashMap::new();
    let bytes = event;
    let mut last_tag: Option<char> = None;
    let mut last_body_start = 0usize;
    for m in re.find_iter(bytes) {
        // Close the previous section.
        if let Some(tag) = last_tag.take() {
            let body = bytes[last_body_start..m.start()].trim_matches('\n');
            out.insert(section_slot(tag), body);
        }
        // Open the next.
        let cap = re.captures(m.as_str()).and_then(|c| c.get(1));
        if let Some(c) = cap {
            let tag = c.as_str().chars().next().unwrap();
            last_tag = Some(tag);
            last_body_start = m.end() + 1; // skip the newline after the marker
            if last_body_start > bytes.len() {
                last_body_start = bytes.len();
            }
        }
    }
    if let Some(tag) = last_tag {
        let body = bytes[last_body_start..].trim_matches('\n');
        out.insert(section_slot(tag), body);
    }
    out
}

fn section_slot(tag: char) -> &'static str {
    match tag {
        'A' => "A",
        'B' => "B",
        'C' => "C",
        'D' => "D",
        'E' => "E",
        'F' => "F",
        'G' => "G",
        'H' => "H",
        'I' => "I",
        'J' => "J",
        'K' => "K",
        'Z' => "Z",
        _ => "?",
    }
}

// ---- field extraction ----

fn parse_client_ip(section_a: &str) -> Option<String> {
    // Section A line: `[timestamp] uniqueid client_ip client_port server_ip server_port`.
    let line = section_a.lines().next()?;
    let after_bracket = line.rfind(']')?;
    let tail = line[after_bracket + 1..].trim();
    let parts: Vec<&str> = tail.split_whitespace().collect();
    parts.get(1).map(|s| s.to_string())
}

fn parse_request_line(section_b: &str) -> (Option<String>, Option<String>) {
    let line = match section_b.lines().next() {
        Some(l) => l,
        None => return (None, None),
    };
    let mut parts = line.split_whitespace();
    let method = parts.next().map(|s| s.to_string());
    let uri = parts.next().map(|s| s.to_string());
    (method, uri)
}

fn parse_header(section_b: &str, name: &str) -> Option<String> {
    let prefix = format!("{name}: ");
    for line in section_b.lines() {
        if let Some(v) = line.strip_prefix(prefix.as_str()) {
            return Some(v.trim().to_string());
        }
    }
    None
}

fn parse_status(section_f: &str) -> Option<u32> {
    let line = section_f.lines().next()?;
    // "HTTP/1.1 200 OK"
    let mut parts = line.split_whitespace();
    parts.next()?; // HTTP/1.1
    parts.next()?.parse().ok()
}

fn parse_section_h(
    section_h: &str,
) -> (Verdict, Vec<String>, Option<String>, Option<String>) {
    static TAG_RE: OnceLock<Regex> = OnceLock::new();
    let tag_re = TAG_RE.get_or_init(|| {
        Regex::new(r#"\[(id|msg|severity|unique_id|hostname|uri)\s+"([^"]+)"\]"#)
            .expect("tag regex")
    });

    let mut verdict = Verdict::Pass;
    let mut rule_ids = Vec::new();
    let mut severities: Vec<String> = Vec::new();
    let mut messages: Vec<String> = Vec::new();

    for line in section_h.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("ModSecurity:") {
            let rest = rest.trim_start();
            if rest.starts_with("Access denied") || rest.starts_with("Access Denied") {
                verdict = Verdict::Denied;
            } else if rest.starts_with("Warning") {
                verdict = Verdict::Warning;
            } else if rest.starts_with("Pass") {
                // leave default
            }
        }
        for cap in tag_re.captures_iter(line) {
            let key = &cap[1];
            let val = &cap[2];
            match key {
                "id" => rule_ids.push(val.to_string()),
                "severity" => severities.push(val.to_string()),
                "msg" => messages.push(val.to_string()),
                _ => {}
            }
        }
    }

    (
        verdict,
        rule_ids,
        severities.into_iter().next(),
        messages.into_iter().next(),
    )
}

/// Replace query-string values and numeric path segments with
/// placeholders so `/user/42` folds with `/user/1337` and
/// `/x?id=abc` folds with `/x?id=def`.
fn normalise_uri(uri: &str) -> String {
    let (path, query) = match uri.find('?') {
        Some(i) => (&uri[..i], Some(&uri[i + 1..])),
        None => (uri, None),
    };
    let mut out = String::with_capacity(uri.len());
    let segments: Vec<&str> = path.split('/').collect();
    for (i, seg) in segments.iter().enumerate() {
        if i > 0 {
            out.push('/');
        }
        if seg.is_empty() {
            continue;
        }
        if seg.chars().all(|c| c.is_ascii_digit()) {
            out.push_str("{NUM}");
        } else {
            out.push_str(seg);
        }
    }
    if let Some(q) = query {
        out.push('?');
        let mut first = true;
        for pair in q.split('&') {
            if !first {
                out.push('&');
            }
            first = false;
            if let Some(eq) = pair.find('=') {
                out.push_str(&pair[..eq]);
                out.push_str("={*}");
            } else {
                out.push_str(pair);
            }
        }
    }
    out
}

fn truncate(s: &str, n: usize) -> &str {
    if s.len() <= n {
        s
    } else {
        // Walk back to a char boundary.
        let mut cut = n;
        while cut > 0 && !s.is_char_boundary(cut) {
            cut -= 1;
        }
        &s[..cut]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS_EVENT: &str = r#"--abc-A--
[24/Oct/2026:22:30:42 +0300] abc 10.0.0.1 51234 192.168.1.1 443
--abc-B--
GET /assets/main.css HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
--abc-F--
HTTP/1.1 200 OK
Server: Apache/2.4.52
--abc-H--
ModSecurity: Pass. [hostname "example.com"] [unique_id "abc"]
--abc-Z--
"#;

    const SQLI_EVENT: &str = r#"--xyz-A--
[24/Oct/2026:22:30:43 +0300] xyz 203.0.113.5 51234 192.168.1.1 443
--xyz-B--
POST /wp-login.php HTTP/1.1
Host: wp-portal.net
--xyz-F--
HTTP/1.1 403 OK
--xyz-H--
ModSecurity: Access denied with code 403 (phase 2). Pattern match "attack" at ARGS:q. [file "x.conf"] [line "88"] [id "942100"] [msg "SQL Injection Attack"] [severity "CRITICAL"] [hostname "wp-portal.net"] [uri "POST"] [unique_id "xyz"]
--xyz-Z--
"#;

    #[test]
    fn parses_a_pass() {
        let p = parse(PASS_EVENT).unwrap();
        assert_eq!(p.verdict, Verdict::Pass);
        assert_eq!(p.method.as_deref(), Some("GET"));
        assert_eq!(p.uri.as_deref(), Some("/assets/main.css"));
        assert_eq!(p.host.as_deref(), Some("example.com"));
        assert_eq!(p.status, Some(200));
        assert_eq!(p.client_ip.as_deref(), Some("10.0.0.1"));
        assert!(p.rule_ids.is_empty());
        assert!(p.fold_key.contains("pass"));
        assert!(p.fold_key.contains("rule -"));
        assert!(!p.fold_key.contains("abc"));
    }

    #[test]
    fn parses_a_denial_with_rule_metadata() {
        let p = parse(SQLI_EVENT).unwrap();
        assert_eq!(p.verdict, Verdict::Denied);
        assert_eq!(p.rule_ids, vec!["942100".to_string()]);
        assert_eq!(p.severity.as_deref(), Some("CRITICAL"));
        assert_eq!(p.msg.as_deref(), Some("SQL Injection Attack"));
        assert_eq!(p.status, Some(403));
        assert!(p.fold_key.contains("deny"));
        assert!(p.fold_key.contains("942100"));
        assert!(p.fold_key.contains("CRITICAL"));
        assert!(p.fold_key.contains("POST"));
    }

    #[test]
    fn fold_keys_merge_across_unique_ids() {
        // Same WAF decision, different random boundary ids → same fold-key.
        let a = parse(&SQLI_EVENT.replace("xyz", "aaaaaa")).unwrap();
        let b = parse(&SQLI_EVENT.replace("xyz", "bbbbbb")).unwrap();
        assert_eq!(a.fold_key, b.fold_key);
    }

    #[test]
    fn normalise_uri_strips_numeric_segments_and_query_values() {
        assert_eq!(normalise_uri("/user/42"), "/user/{NUM}");
        assert_eq!(normalise_uri("/x?id=abc&y=1"), "/x?id={*}&y={*}");
        assert_eq!(normalise_uri("/api/v1/x"), "/api/v1/x");
    }

    #[test]
    fn returns_none_on_non_modsec_event() {
        assert!(parse("plain text with no sections").is_none());
    }
}
