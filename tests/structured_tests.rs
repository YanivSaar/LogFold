//! v0.4: integration tests for the structured-format parsers
//! (JSON, logfmt KV, CEF, LEEF) wired through the real bundle
//! registry and fold path.

use std::fs;
use std::time::Instant;

use compact_str::CompactString;
use logfold::detect::registry::{BundleRegistry, ParseFormat};
use logfold::engine::registry::PatternRegistry;
use logfold::parse::formats::{cef, json, kv, leef};
use logfold::parse::{skeleton, tokenizer, Token};

fn fold_count<F>(path: &str, extract: F) -> usize
where
    F: for<'a> Fn(&'a str) -> &'a str,
{
    let text = fs::read_to_string(path).unwrap();
    let eng = PatternRegistry::new(1024);
    let mut skel = CompactString::default();
    let mut slots = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let effective = extract(line);
        let mut tokens: Vec<Token<'_>> = Vec::new();
        tokenizer::classify(effective, &mut tokens);
        if tokens.is_empty() {
            continue;
        }
        skeleton::build(&tokens, &mut skel, &mut slots);
        eng.upsert(&skel, &slots, &tokens, "test", Instant::now());
    }
    eng.len()
}

#[test]
fn json_bundle_declares_json_format() {
    let reg = BundleRegistry::load(None).unwrap();
    let b = reg.by_id("generic/json").unwrap();
    assert_eq!(b.format, ParseFormat::Json);
}

#[test]
fn cef_and_leef_bundles_declare_their_formats() {
    let reg = BundleRegistry::load(None).unwrap();
    assert_eq!(reg.by_id("security/cef").unwrap().format, ParseFormat::Cef);
    assert_eq!(
        reg.by_id("security/leef").unwrap().format,
        ParseFormat::Leef
    );
}

#[test]
fn logfmt_bundle_declares_kv_format() {
    let reg = BundleRegistry::load(None).unwrap();
    assert_eq!(reg.by_id("generic/logfmt").unwrap().format, ParseFormat::Kv);
}

#[test]
fn json_fixture_folds_on_msg_only() {
    // 8 JSON lines in the fixture across 4 distinct `msg` shapes.
    // Folding on msg alone should collapse the 3 "request complete"
    // lines together even though their status and durations vary.
    let n = fold_count("tests/fixtures/json-logs/sample.log", |line| {
        // We call into json::parse but take `.msg` by reference.
        // The owner lives inside this closure's frame.
        match json::parse(line) {
            Some(p) => Box::leak(p.msg.into_boxed_str()),
            None => line,
        }
    });
    assert!(n <= 5, "expected ≤ 5 patterns, got {n}");
    assert!(n >= 2, "expected ≥ 2 patterns, got {n}");
}

#[test]
fn logfmt_fixture_folds_on_msg_only() {
    let n = fold_count("tests/fixtures/logfmt/sample.log", |line| {
        kv::parse(line).map(|p| p.msg).unwrap_or(line)
    });
    // 6 lines, 4 distinct msg shapes.
    assert!(n <= 5, "expected ≤ 5 patterns, got {n}");
    assert!(n >= 2, "expected ≥ 2 patterns, got {n}");
}

#[test]
fn cef_fixture_folds_on_name_field() {
    let n = fold_count("tests/fixtures/cef/sample.log", |line| {
        cef::parse(line).map(|p| p.name).unwrap_or(line)
    });
    // 5 lines: 3 "detected port scan", 1 "blocked outbound", 1 malware.
    assert!(n <= 4, "expected ≤ 4 patterns, got {n}");
}

#[test]
fn leef_fixture_folds_on_event_id() {
    let n = fold_count("tests/fixtures/leef/sample.log", |line| {
        leef::parse(line).map(|p| p.event_id).unwrap_or(line)
    });
    // LEEF event IDs are pure-digit tokens, which the tokeniser types
    // as NUM; four event-ID lines fold into a single {NUM} skeleton.
    // The test proves the parser extracts just the event ID (if we
    // tokenised the full LEEF header we'd get many more patterns
    // because the header fields vary across lines).
    assert_eq!(n, 1, "expected 1 fold (all event IDs reduce to {{NUM}})");
}

#[test]
fn leef_parser_extracts_distinct_event_ids() {
    use std::collections::HashSet;
    let text = std::fs::read_to_string("tests/fixtures/leef/sample.log").unwrap();
    let ids: HashSet<&str> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(leef::parse)
        .map(|p| p.event_id)
        .collect::<HashSet<_>>()
        .iter()
        .map(|s| Box::leak(s.to_string().into_boxed_str()) as &str)
        .collect();
    // Fixture ships event IDs 6013 (three times) and 7013 (once).
    assert_eq!(ids.len(), 2);
}

#[test]
fn cef_escaped_pipe_in_name_survives() {
    let line =
        "CEF:0|Vendor|AV|1.1|555|malware detected: \\| in filename|8|file=/tmp/x act=quarantined";
    let p = cef::parse(line).expect("escaped pipe should parse");
    assert_eq!(p.severity, "8");
    assert!(p.name.contains("malware detected"));
    assert!(p.extension.starts_with("file=/tmp/x"));
}
