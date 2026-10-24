//! Integration tests: feed real log fixtures through the engine and assert
//! on the folded pattern set.

use std::fs;
use std::time::Instant;

use compact_str::CompactString;
use logfold::engine::registry::PatternRegistry;
use logfold::parse::{skeleton, tokenizer, Token};

fn fold_all(path: &str) -> PatternRegistry {
    let text = fs::read_to_string(path).expect("fixture missing");
    let reg = PatternRegistry::new(10_000);
    let mut skel = CompactString::default();
    let mut slots = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let mut tokens: Vec<Token<'_>> = Vec::new();
        tokenizer::classify(line, &mut tokens);
        if tokens.is_empty() {
            continue;
        }
        skeleton::build(&tokens, &mut skel, &mut slots);
        reg.upsert(&skel, &slots, &tokens, "unknown", Instant::now());
    }
    reg
}

#[test]
fn sshd_fixture_folds_cleanly() {
    let reg = fold_all("tests/fixtures/sshd/sample.log");
    let snaps = reg.snapshot();

    // 23 lines across (roughly) these distinct shapes:
    //   - Accepted publickey (3 → one pattern)
    //   - Failed password (12 → one pattern; fuzzy fold handles different ports)
    //   - Invalid user (3 → one pattern)
    //   - Accepted password for root (1 — distinct from publickey case)
    //   - Disconnected from authenticating user (1)
    //   - sudo (1)
    //   - Connection closed (1)
    //
    // Fuzzy folding may merge some of the 1-count shapes with their neighbours.
    // We assert the pattern count stays small and that the big folds are big.
    assert!(
        snaps.len() <= 10,
        "expected ≤ 10 patterns, got {}: {:#?}",
        snaps.len(),
        snaps
            .iter()
            .map(|s| (&s.skeleton, s.count))
            .collect::<Vec<_>>()
    );

    let max_count = snaps.iter().map(|s| s.count).max().unwrap();
    assert!(
        max_count >= 10,
        "expected the Failed-password fold to have ≥ 10 occurrences, got {max_count}"
    );
}

#[test]
fn repeated_lines_fold_to_one() {
    let reg = PatternRegistry::new(1024);
    let mut skel = CompactString::default();
    let mut slots = Vec::new();

    for _ in 0..100 {
        let mut tokens: Vec<Token<'_>> = Vec::new();
        tokenizer::classify("info connection reset", &mut tokens);
        skeleton::build(&tokens, &mut skel, &mut slots);
        reg.upsert(&skel, &slots, &tokens, "unknown", Instant::now());
    }
    assert_eq!(reg.len(), 1);
    assert_eq!(reg.snapshot()[0].count, 100);
}
