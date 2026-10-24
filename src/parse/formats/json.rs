//! JSON / NDJSON log line parser.
//!
//! Covers the common case: one JSON object per line, with a free-form
//! message field under a well-known name. Returns owned strings
//! because serde_json unescapes into owned storage; the fold hot
//! path pays one allocation per JSON line, which is dominated by
//! the serde_json parse itself.
//!
//! Unknown shapes return `None`; the caller falls back to raw
//! tokenisation of the whole line.

use serde_json::Value;

/// Field names, in priority order, that we treat as the free-form
/// message body. Covers logrus (`msg`), slog / tracing (`message`,
/// `event`), zap, winston, Loki (`log`), journald JSON exports
/// (`MESSAGE`), and the fairly common `description`.
const MSG_FIELDS: &[&str] = &["msg", "message", "event", "log", "MESSAGE", "description"];

/// A JSON-parsed log line reduced to what the fold path needs: the
/// message body plus a short list of promoted-known fields. Owned
/// strings because serde_json unescapes into owned storage.
#[derive(Debug, Clone)]
pub struct ParsedJson {
    pub msg: String,
    pub level: Option<String>,
    pub timestamp: Option<String>,
    pub service: Option<String>,
    pub request_id: Option<String>,
}

/// Try to parse `line` as a JSON object. Returns `None` if the line
/// isn't a JSON object or doesn't carry any of the recognised message
/// fields.
pub fn parse(line: &str) -> Option<ParsedJson> {
    // Fast reject: must start with '{' (whitespace is cheap to skip).
    let trimmed = line.trim_start();
    if !trimmed.starts_with('{') {
        return None;
    }

    let value: Value = serde_json::from_str(trimmed).ok()?;
    let obj = value.as_object()?;

    // Find the first recognised message field.
    let msg = MSG_FIELDS
        .iter()
        .find_map(|k| obj.get(*k).and_then(stringy_value))?;

    Some(ParsedJson {
        msg,
        level: ["level", "lvl", "severity"]
            .iter()
            .find_map(|k| obj.get(*k).and_then(stringy_value)),
        timestamp: ["timestamp", "ts", "time", "@timestamp"]
            .iter()
            .find_map(|k| obj.get(*k).and_then(stringy_value)),
        service: ["service", "svc", "application", "app", "component"]
            .iter()
            .find_map(|k| obj.get(*k).and_then(stringy_value)),
        request_id: ["request_id", "req_id", "trace_id", "correlation_id"]
            .iter()
            .find_map(|k| obj.get(*k).and_then(stringy_value)),
    })
}

/// Convert `Value` to an owned `String` if it's a string, number, or
/// bool. Objects and arrays return `None` because we don't want to
/// recursively flatten structured values on the fold hot path.
fn stringy_value(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_logrus_style() {
        let line = r#"{"level":"error","msg":"connection reset","ts":"2026-10-24T12:00:00Z"}"#;
        let p = parse(line).unwrap();
        assert_eq!(p.msg, "connection reset");
        assert_eq!(p.level.as_deref(), Some("error"));
    }

    #[test]
    fn parses_zap_style() {
        let line = r#"{"level":"INFO","message":"request complete","service":"api"}"#;
        let p = parse(line).unwrap();
        assert_eq!(p.msg, "request complete");
        assert_eq!(p.service.as_deref(), Some("api"));
    }

    #[test]
    fn parses_journald_message_field() {
        let line = r#"{"MESSAGE":"Started something","PRIORITY":"6"}"#;
        let p = parse(line).unwrap();
        assert_eq!(p.msg, "Started something");
    }

    #[test]
    fn returns_none_on_non_object() {
        assert!(parse("hello world").is_none());
        assert!(parse("[1,2,3]").is_none());
        assert!(parse(r#""just a string""#).is_none());
    }

    #[test]
    fn returns_none_on_object_without_known_msg_field() {
        let line = r#"{"foo":"bar","baz":42}"#;
        assert!(parse(line).is_none());
    }

    #[test]
    fn primitive_message_values_are_stringified() {
        let line = r#"{"msg":200,"level":"info"}"#;
        let p = parse(line).unwrap();
        assert_eq!(p.msg, "200");
    }
}
