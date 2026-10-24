//! v0.8: ModSec v3 JSON audit log integration tests.

use std::fs;
use std::time::Instant;

use compact_str::CompactString;
use logfold::detect::registry::{BundleRegistry, ParseFormat};
use logfold::engine::registry::PatternRegistry;
use logfold::parse::formats::modsec_v3;
use logfold::parse::{skeleton, tokenizer, Token};

#[test]
fn modsec_v3_bundle_declares_format() {
    let reg = BundleRegistry::load(None).unwrap();
    let b = reg.by_id("modsec-v3").expect("modsec-v3 bundle shipped");
    assert_eq!(b.format, ParseFormat::ModsecV3);
}

#[test]
fn two_different_uris_same_rule_fold_together() {
    // Both are rule 930110 CRITICAL path-traversal GETs returning 403.
    // Only the attack payload differs. The fold key normalises that.
    let a = r#"{"transaction":{"client_ip":"1.1.1.1","request":{"method":"GET","uri":"/a?x=../etc/passwd"},"response":{"http_code":403},"messages":[{"message":"Path Traversal","details":{"ruleId":"930110","severity":"CRITICAL"}}]}}"#;
    let b = r#"{"transaction":{"client_ip":"2.2.2.2","request":{"method":"GET","uri":"/b?x=../etc/shadow"},"response":{"http_code":403},"messages":[{"message":"Path Traversal","details":{"ruleId":"930110","severity":"CRITICAL"}}]}}"#;

    let pa = modsec_v3::parse(a).unwrap();
    let pb = modsec_v3::parse(b).unwrap();

    // Both fold keys mention rule 930110, severity CRITICAL, GET, 403.
    // Only the URI (which gets tokenised to {PATH}) differs.
    let eng = PatternRegistry::new(1024);
    let mut skel = CompactString::default();
    let mut slots = Vec::new();
    for key in [&pa.fold_key, &pb.fold_key] {
        let mut tokens: Vec<Token<'_>> = Vec::new();
        tokenizer::classify(key, &mut tokens);
        skeleton::build(&tokens, &mut skel, &mut slots);
        eng.upsert(&skel, &slots, &tokens, "modsec-v3", Instant::now());
    }
    assert_eq!(
        eng.len(),
        1,
        "same rule+method+status should fold to one pattern"
    );
}

#[test]
fn fixture_folds_to_a_small_number_of_patterns() {
    let text = fs::read_to_string("tests/fixtures/modsec-v3/sample.log").unwrap();
    let eng = PatternRegistry::new(1024);
    let mut skel = CompactString::default();
    let mut slots = Vec::new();
    let mut parsed = 0usize;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Some(p) = modsec_v3::parse(line) else {
            continue;
        };
        parsed += 1;
        let mut tokens: Vec<Token<'_>> = Vec::new();
        tokenizer::classify(&p.fold_key, &mut tokens);
        skeleton::build(&tokens, &mut skel, &mut slots);
        eng.upsert(&skel, &slots, &tokens, "modsec-v3", Instant::now());
    }
    assert_eq!(parsed, 4, "fixture has four audit entries");
    // Rule 930110 (two hits), rule 942100 (one), the clean-200 entry
    // (no messages). Expected ~3 fold-key skeletons.
    assert!(eng.len() <= 3, "expected <= 3 patterns, got {}", eng.len());
}
