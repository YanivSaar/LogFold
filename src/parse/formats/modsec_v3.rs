//! ModSecurity v3 JSON serial audit log parser. v0.8.
//!
//! Modern libmodsecurity (v3.x, used by nginx-modsec and the Nginx
//! Connector) writes one JSON object per transaction. The record is
//! deeply nested; we only pull the fields that matter for folding
//! and triage:
//!
//! * `transaction.client_ip`
//! * `transaction.request.uri`
//! * `transaction.request.method`
//! * `transaction.response.http_code`
//! * `transaction.messages[].details.ruleId`
//! * `transaction.messages[].details.severity`
//! * `transaction.messages[].message` (short description)
//!
//! The fold key is a synthesised string:
//!
//! ```text
//! modsec rule {ruleId} {severity}: {message}  // {method} {uri} -> {status}
//! ```
//!
//! That gives us one line per unique (rule, method, uri shape) that
//! tokenises cleanly through the existing fold hot path.

use serde::Deserialize;

/// A parsed ModSec v3 transaction, flattened to a single fold-key
/// string and a handful of structured fields.
#[derive(Debug, Clone)]
pub struct ParsedModsecV3 {
    pub fold_key: String,
    pub rule_ids: Vec<String>,
    pub client_ip: Option<String>,
    pub uri: Option<String>,
    pub method: Option<String>,
    pub status: Option<u32>,
}

/// Try to parse `line` as a ModSec v3 JSON transaction record.
pub fn parse(line: &str) -> Option<ParsedModsecV3> {
    let trimmed = line.trim_start();
    if !trimmed.starts_with('{') {
        return None;
    }
    let outer: Outer = serde_json::from_str(trimmed).ok()?;
    let t = outer.transaction?;

    let client_ip = t.client_ip.clone();
    let method = t.request.as_ref().and_then(|r| r.method.clone());
    let uri = t.request.as_ref().and_then(|r| r.uri.clone());
    let status = t.response.as_ref().and_then(|r| r.http_code);

    let mut rule_ids = Vec::new();
    let mut primary = None;
    for m in t.messages.unwrap_or_default() {
        if let Some(d) = m.details.as_ref() {
            if let Some(id) = &d.rule_id {
                rule_ids.push(id.clone());
                if primary.is_none() {
                    primary = Some((id.clone(), d.severity.clone(), m.message.clone()));
                }
            }
        }
    }

    // Fold-key: cover the common WAF triage question. If no rule
    // matched, we still get a usable fold with method+uri+status.
    let (rule_id, severity, message) = primary
        .map(|(a, b, c)| (a, b.unwrap_or_default(), c.unwrap_or_default()))
        .unwrap_or_else(|| (String::from("-"), String::new(), String::new()));

    let fold_key = format!(
        "modsec rule {rule} {sev}: {msg} // {method} {uri} -> {status}",
        rule = rule_id,
        sev = severity,
        msg = truncate(&message, 80),
        method = method.as_deref().unwrap_or("-"),
        uri = uri.as_deref().unwrap_or("-"),
        status = status.map(|c| c.to_string()).unwrap_or_else(|| "-".into()),
    );

    Some(ParsedModsecV3 {
        fold_key,
        rule_ids,
        client_ip,
        uri,
        method,
        status,
    })
}

fn truncate(s: &str, n: usize) -> &str {
    // ModSec rule messages are usually short, but some embed matched
    // request bodies. Cap for the fold key so one giant payload
    // doesn't inflate the skeleton.
    if s.len() <= n {
        s
    } else {
        &s[..n]
    }
}

// ---- JSON schema (only the fields we need) ----

#[derive(Deserialize)]
struct Outer {
    transaction: Option<Transaction>,
}

#[derive(Deserialize)]
struct Transaction {
    client_ip: Option<String>,
    request: Option<Request>,
    response: Option<Response>,
    messages: Option<Vec<Message>>,
}

#[derive(Deserialize)]
struct Request {
    method: Option<String>,
    uri: Option<String>,
}

#[derive(Deserialize)]
struct Response {
    http_code: Option<u32>,
}

#[derive(Deserialize)]
struct Message {
    message: Option<String>,
    details: Option<Details>,
}

#[derive(Deserialize)]
struct Details {
    #[serde(rename = "ruleId")]
    rule_id: Option<String>,
    severity: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "transaction": {
            "client_ip": "203.0.113.5",
            "time_stamp": "Fri Oct 24 12:00:00 2026",
            "unique_id": "abc123",
            "request": {
                "method": "GET",
                "uri": "/admin?x=../etc/passwd",
                "http_version": 1.1
            },
            "response": {
                "body": "",
                "http_code": 403,
                "headers": {}
            },
            "messages": [
                {
                    "message": "Path Traversal Attack (/../)",
                    "details": {
                        "ruleId": "930110",
                        "severity": "CRITICAL",
                        "match": "Matched Data: /../",
                        "data": "x=../etc/passwd"
                    }
                }
            ]
        }
    }"#;

    #[test]
    fn parses_v3_sample() {
        let p = parse(SAMPLE).unwrap();
        assert_eq!(p.client_ip.as_deref(), Some("203.0.113.5"));
        assert_eq!(p.method.as_deref(), Some("GET"));
        assert_eq!(p.status, Some(403));
        assert_eq!(p.rule_ids, vec!["930110".to_string()]);
        assert!(p.fold_key.contains("rule 930110"));
        assert!(p.fold_key.contains("CRITICAL"));
        assert!(p.fold_key.contains("GET"));
        assert!(p.fold_key.contains("-> 403"));
    }

    #[test]
    fn returns_none_on_non_object() {
        assert!(parse("not json").is_none());
        assert!(parse("[]").is_none());
    }

    #[test]
    fn returns_none_without_transaction_wrapper() {
        assert!(parse(r#"{"client_ip":"1.2.3.4"}"#).is_none());
    }

    #[test]
    fn tolerates_missing_messages() {
        let line = r#"{"transaction":{"client_ip":"1.2.3.4","request":{"method":"POST","uri":"/x"},"response":{"http_code":200}}}"#;
        let p = parse(line).unwrap();
        assert!(p.rule_ids.is_empty());
        assert_eq!(p.status, Some(200));
        assert!(p.fold_key.contains("POST"));
        assert!(p.fold_key.contains("rule -"));
    }

    #[test]
    fn truncates_long_messages() {
        let long_msg = "A".repeat(500);
        let line = format!(
            r#"{{"transaction":{{"client_ip":"1.2.3.4","messages":[{{"message":"{}","details":{{"ruleId":"999999","severity":"NOTICE"}}}}]}}}}"#,
            long_msg
        );
        let p = parse(&line).unwrap();
        // Fold key must not blow out to 500+ chars just from the message.
        assert!(p.fold_key.len() < 300);
    }
}
