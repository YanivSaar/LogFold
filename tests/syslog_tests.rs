//! v0.2: integration tests for the base syslog parser.
//!
//! Verifies that `[parse] format = "syslog"` on a bundle strips the
//! envelope before the engine folds, dropping skeleton divergence
//! caused by varying PIDs and timestamps.

use std::fs;
use std::time::Instant;

use compact_str::CompactString;
use logfold::detect::registry::{BundleRegistry, ParseFormat};
use logfold::engine::registry::PatternRegistry;
use logfold::parse::formats::syslog;
use logfold::parse::{skeleton, tokenizer, Token};

#[test]
fn sshd_bundle_declares_syslog_format() {
    let reg = BundleRegistry::load(None).unwrap();
    let b = reg.by_id("sshd").expect("sshd bundle shipped");
    assert_eq!(b.format, ParseFormat::Syslog);
}

#[test]
fn syslog_envelope_strip_tightens_sshd_fold() {
    // Compare raw folding (no envelope strip) vs. syslog-aware folding
    // on the same fixture. The syslog pass should produce fewer or
    // equal patterns, never more, since envelope-only differences
    // (PID, timestamp) stop anchoring separate skeletons.
    let text = fs::read_to_string("tests/fixtures/sshd/sample.log").unwrap();

    let raw_count = fold_count(&text, false);
    let syslog_count = fold_count(&text, true);

    assert!(
        syslog_count <= raw_count,
        "syslog fold ({syslog_count}) should be ≤ raw fold ({raw_count})"
    );
    // The sshd fixture carries ~5 distinct message shapes. With
    // envelope stripping we expect to be close to that lower bound.
    assert!(
        syslog_count <= 6,
        "syslog fold produced {syslog_count} patterns, expected ≤ 6"
    );
}

#[test]
fn parsed_sshd_line_has_zero_pid_divergence() {
    // Direct check: two lines that differ only by PID collapse to
    // the same message under the syslog parser.
    let a = "Oct 23 09:14:10 host sshd[1030]: Failed password for alice from 203.0.113.5 port 60000 ssh2";
    let b = "Oct 23 09:14:11 host sshd[1031]: Failed password for alice from 203.0.113.5 port 60001 ssh2";

    let pa = syslog::parse(a).unwrap();
    let pb = syslog::parse(b).unwrap();
    assert_eq!(pa.process, pb.process);
    assert_ne!(pa.pid, pb.pid, "PIDs differ in the raw line");

    // Skeletons over msg only must be identical (ports differ, both
    // get folded to {NUM} in the skeleton).
    let sa = skel_of(pa.msg);
    let sb = skel_of(pb.msg);
    assert_eq!(sa, sb, "message-body skeletons must match");
}

fn fold_count(text: &str, syslog_strip: bool) -> usize {
    let reg = PatternRegistry::new(10_000);
    let mut skel = CompactString::default();
    let mut slots = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let effective: &str = if syslog_strip {
            syslog::parse(line).map(|p| p.msg).unwrap_or(line)
        } else {
            line
        };
        let mut tokens: Vec<Token<'_>> = Vec::new();
        tokenizer::classify(effective, &mut tokens);
        if tokens.is_empty() {
            continue;
        }
        skeleton::build(&tokens, &mut skel, &mut slots);
        reg.upsert(&skel, &slots, &tokens, "sshd", Instant::now());
    }
    reg.len()
}

fn skel_of(msg: &str) -> CompactString {
    let mut skel = CompactString::default();
    let mut slots = Vec::new();
    let mut tokens: Vec<Token<'_>> = Vec::new();
    tokenizer::classify(msg, &mut tokens);
    skeleton::build(&tokens, &mut skel, &mut slots);
    skel
}
