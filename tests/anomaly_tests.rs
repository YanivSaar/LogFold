//! Regression tests for the anomaly scorer.

use compact_str::CompactString;
use std::time::Instant;

use logfold::engine::pattern::{PatternSnapshot, VarStatsSnapshot};
use logfold::engine::scorer::{self, NEW_SCORE_FLOOR};
use logfold::types::{Severity, TokenType};

fn snap(count: u64, severity: Severity, vars: Vec<VarStatsSnapshot>) -> PatternSnapshot {
    PatternSnapshot {
        id: 1,
        skeleton: CompactString::new("x"),
        label: None,
        bundle_id: CompactString::new("sshd"),
        severity_hint: severity,
        count,
        first_seen: Instant::now(),
        last_seen: Instant::now(),
        peak_bucket: 0,
        mean_bucket: 0.0,
        vars,
    }
}

#[test]
fn sudo_from_tmp_scores_high() {
    let s = snap(
        1,
        Severity::High,
        vec![VarStatsSnapshot {
            ty: TokenType::Path,
            distinct_approx: 1,
            total: 1,
            top: vec![(CompactString::new("/tmp/evil.sh"), 1)],
        }],
    );
    let score = scorer::compute_score(&s, &[]);
    // frequency 60 + path 20 + severity 20 = ≥ 100 (clamped)
    assert!(score >= 90, "expected ≥ 90, got {score}");
}

#[test]
fn brute_force_fold_is_not_an_anomaly() {
    // High count, no suspicious vars → low score, Fold badge.
    let s = snap(1500, Severity::Low, vec![]);
    let score = scorer::compute_score(&s, &[]);
    assert!(score < NEW_SCORE_FLOOR);
}

#[test]
fn cross_correlating_ip_bumps_score() {
    let s = snap(
        50,
        Severity::Low,
        vec![VarStatsSnapshot {
            ty: TokenType::Ip,
            distinct_approx: 1,
            total: 50,
            top: vec![(CompactString::new("1.2.3.4"), 50)],
        }],
    );
    let peers = vec![(TokenType::Ip, "1.2.3.4")];
    let with_peer = scorer::compute_score(&s, &peers);
    let without_peer = scorer::compute_score(&s, &[]);
    assert_eq!(with_peer, without_peer + 15);
}
