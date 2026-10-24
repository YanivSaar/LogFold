//! Anomaly scorer: combines frequency, rate-spike, cross-correlation,
//! path-suspicion, and bundle severity into an integer score 0–100.

use crate::engine::pattern::PatternSnapshot;
use crate::types::{Badge, TokenType};

/// Score threshold at or above which a pattern is flagged as `[NEW]`.
pub const NEW_SCORE_FLOOR: u32 = 60;
/// Score threshold for `[RARE]`.
pub const RARE_SCORE_FLOOR: u32 = 30;
/// Score threshold for `[SPIKE]`.
pub const SPIKE_SCORE_FLOOR: u32 = 25;

/// Suspicious-path substrings used by [`path_suspicion`].
const SUSPICIOUS_PATHS: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/", "/private/tmp/"];

/// Compute a composite anomaly score (0–100) for `snap`.
///
/// `peer_vars` is a flat list of (TokenType, value) tuples drawn from
/// *other* patterns' top-K; it's used by [`cross_correlation`]. The caller
/// (`PatternRegistry::score_all`) builds this once per pass.
pub fn compute_score(snap: &PatternSnapshot, peer_vars: &[(TokenType, &str)]) -> u32 {
    let mut score = 0u32;

    score += frequency(snap.count);
    score += rate_spike(snap.peak_bucket, snap.mean_bucket);
    score += cross_correlation(snap, peer_vars);
    score += path_suspicion(snap);
    score += snap.severity_hint.score_bonus();

    score.min(100)
}

fn frequency(count: u64) -> u32 {
    match count {
        1 => 60,
        2..=3 => 40,
        4..=10 => 20,
        _ => 0,
    }
}

fn rate_spike(peak: u32, mean: f32) -> u32 {
    if mean < 1.0 {
        return 0;
    }
    let ratio = peak as f32 / mean;
    if ratio > 5.0 {
        25
    } else if ratio > 3.0 {
        12
    } else {
        0
    }
}

fn cross_correlation(snap: &PatternSnapshot, peer_vars: &[(TokenType, &str)]) -> u32 {
    for v in &snap.vars {
        if !matches!(v.ty, TokenType::Ip | TokenType::User | TokenType::Email) {
            continue;
        }
        for (val, _) in &v.top {
            if peer_vars
                .iter()
                .any(|(peer_ty, peer_val)| *peer_ty == v.ty && *peer_val == val.as_str())
            {
                return 15;
            }
        }
    }
    0
}

fn path_suspicion(snap: &PatternSnapshot) -> u32 {
    for v in &snap.vars {
        if v.ty != TokenType::Path {
            continue;
        }
        for (val, _) in &v.top {
            if SUSPICIOUS_PATHS
                .iter()
                .any(|needle| val.as_str().starts_with(needle))
            {
                return 20;
            }
        }
    }
    0
}

/// Classify a pattern into one of the display badges.
pub fn classify_badge(snap: &PatternSnapshot, score: u32, fold_threshold: u64) -> Badge {
    if score >= NEW_SCORE_FLOOR && snap.count == 1 {
        Badge::New
    } else if score >= SPIKE_SCORE_FLOOR && snap.peak_bucket as f32 > snap.mean_bucket * 3.0 {
        Badge::Spike
    } else if snap.count <= 3 && score >= RARE_SCORE_FLOOR {
        Badge::Rare
    } else if snap.count >= fold_threshold {
        Badge::Fold
    } else {
        Badge::Norm
    }
}

/// Build the (TokenType, value) list used by [`compute_score`] for the
/// cross-correlation pass. We flatten each pattern's top-K entries of
/// cross-correlatable variable types.
pub fn build_peer_vars(snaps: &[PatternSnapshot]) -> Vec<(TokenType, &str)> {
    let mut out = Vec::new();
    for s in snaps {
        for v in &s.vars {
            if !matches!(v.ty, TokenType::Ip | TokenType::User | TokenType::Email) {
                continue;
            }
            for (val, _) in &v.top {
                out.push((v.ty, val.as_str()));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::pattern::VarStatsSnapshot;
    use crate::types::Severity;
    use compact_str::CompactString;
    use std::time::Instant;

    fn mk_snap(count: u64, severity: Severity) -> PatternSnapshot {
        PatternSnapshot {
            id: 1,
            skeleton: CompactString::new("x"),
            label: None,
            bundle_id: CompactString::new("unknown"),
            severity_hint: severity,
            count,
            first_seen: Instant::now(),
            last_seen: Instant::now(),
            peak_bucket: 0,
            mean_bucket: 0.0,
            vars: vec![],
        }
    }

    #[test]
    fn single_occurrence_scores_as_new() {
        let s = mk_snap(1, Severity::Info);
        let score = compute_score(&s, &[]);
        assert!(score >= NEW_SCORE_FLOOR);
        assert_eq!(classify_badge(&s, score, 5), Badge::New);
    }

    #[test]
    fn high_count_is_fold() {
        let s = mk_snap(1000, Severity::Info);
        let score = compute_score(&s, &[]);
        assert!(score < NEW_SCORE_FLOOR);
        assert_eq!(classify_badge(&s, score, 5), Badge::Fold);
    }

    #[test]
    fn tmp_path_bumps_score() {
        let s = PatternSnapshot {
            vars: vec![VarStatsSnapshot {
                ty: TokenType::Path,
                distinct_approx: 1,
                total: 1,
                top: vec![(CompactString::new("/tmp/evil.sh"), 1)],
            }],
            ..mk_snap(1, Severity::Info)
        };
        let score = compute_score(&s, &[]);
        assert!(score >= 60 + 20);
    }

    #[test]
    fn cross_correlation_detected() {
        let s = PatternSnapshot {
            vars: vec![VarStatsSnapshot {
                ty: TokenType::Ip,
                distinct_approx: 1,
                total: 1,
                top: vec![(CompactString::new("1.2.3.4"), 1)],
            }],
            ..mk_snap(5, Severity::Info)
        };
        let peers = vec![(TokenType::Ip, "1.2.3.4")];
        let score = compute_score(&s, &peers);
        assert!(score >= 15);
    }
}
