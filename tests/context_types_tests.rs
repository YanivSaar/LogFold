//! v0.2 part 2: integration tests for bundle `[[context_types]]`.
//!
//! Verifies that the sshd bundle's declared rules promote the word
//! after "for"/"user"/"port"/"by" into a typed slot in the final
//! skeleton, so sshd failure lines fold cleanly on the real text.

use std::time::Instant;

use compact_str::CompactString;
use logfold::detect::registry::BundleRegistry;
use logfold::engine::registry::PatternRegistry;
use logfold::parse::formats::syslog;
use logfold::parse::{skeleton, tokenizer, Token};

#[test]
fn sshd_bundle_declares_context_rules() {
    let reg = BundleRegistry::load(None).unwrap();
    let b = reg.by_id("sshd").expect("sshd bundle shipped");
    assert!(
        !b.context_types.is_empty(),
        "sshd should declare context_types"
    );
    let anchors: Vec<_> = b.context_types.iter().map(|r| r.after.as_str()).collect();
    assert!(anchors.contains(&"for"));
    assert!(anchors.contains(&"port"));
}

#[test]
fn sshd_context_rules_promote_user_and_port() {
    let reg = BundleRegistry::load(None).unwrap();
    let b = reg.by_id("sshd").unwrap();

    let line =
        "Oct 23 09:14:10 host sshd[1030]: Failed password for alice from 203.0.113.5 port 60000 ssh2";
    let msg = syslog::parse(line).unwrap().msg;

    let mut tokens: Vec<Token<'_>> = Vec::new();
    tokenizer::classify(msg, &mut tokens);

    let mut skel = CompactString::default();
    let mut slots = Vec::new();
    skeleton::build_with_context(&tokens, &b.context_types, &mut skel, &mut slots);

    // The anchor "for" promotes "alice" (WORD) to USER; "port" promotes "60000" (NUM) to PORT.
    assert!(skel.contains("{USER}"), "got {skel}");
    assert!(skel.contains("{PORT}"), "got {skel}");
    assert!(skel.contains("{IP}"), "got {skel}");
    // "from" is not an anchor in sshd (would promote IP→USER which we explicitly rejected).
    assert!(!skel.contains("from {USER}"), "got {skel}");
}

#[test]
fn two_sshd_lines_with_different_users_fold_identically() {
    let reg = BundleRegistry::load(None).unwrap();
    let b = reg.by_id("sshd").unwrap();

    let make_skel = |line: &str| {
        let msg = syslog::parse(line).unwrap().msg;
        let mut tokens: Vec<Token<'_>> = Vec::new();
        tokenizer::classify(msg, &mut tokens);
        let mut skel = CompactString::default();
        let mut slots = Vec::new();
        skeleton::build_with_context(&tokens, &b.context_types, &mut skel, &mut slots);
        skel
    };

    let a = make_skel(
        "Oct 23 09:14:10 host sshd[1030]: Failed password for alice from 203.0.113.5 port 60000 ssh2",
    );
    let b = make_skel(
        "Oct 23 09:14:11 host sshd[1031]: Failed password for bob   from 203.0.113.7 port 60001 ssh2",
    );
    assert_eq!(
        a, b,
        "sshd Failed-password shape should fold across user and IP"
    );
}

#[test]
fn fixture_folds_tighter_with_context() {
    // End-to-end: with the real sshd bundle (syslog + context_types),
    // the sshd fixture should land in a very small pattern count.
    let reg = BundleRegistry::load(None).unwrap();
    let b = reg.by_id("sshd").unwrap();
    let text = std::fs::read_to_string("tests/fixtures/sshd/sample.log").unwrap();

    let eng = PatternRegistry::new(1024);
    let mut skel = CompactString::default();
    let mut slots = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let msg = syslog::parse(line).map(|p| p.msg).unwrap_or(line);
        let mut tokens: Vec<Token<'_>> = Vec::new();
        tokenizer::classify(msg, &mut tokens);
        if tokens.is_empty() {
            continue;
        }
        skeleton::build_with_context(&tokens, &b.context_types, &mut skel, &mut slots);
        eng.upsert(&skel, &slots, &tokens, "sshd", Instant::now());
    }
    // The 23-line sshd fixture at v0.1 produced ~10 patterns before any
    // envelope / context work. With syslog stripping it drops to ~6, and
    // context promotion keeps it at that floor (user and port tokens
    // now fold cleanly). We cap at 6 and treat lower as a bonus.
    assert!(
        eng.len() <= 6,
        "expected ≤ 6 patterns with syslog + context_types, got {}",
        eng.len()
    );
}
