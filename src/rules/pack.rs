//! Shipped v0.9 rule pack.
//!
//! Each rule is a thin impl of [`super::Rule`] that walks the snapshot
//! set and decides which patterns deserve the extra points. Keep the
//! predicates simple: regex-free substring tests, bundle-id prefix,
//! and a `count >= N` floor.

use super::Rule;
use crate::engine::pattern::PatternSnapshot;

/// Build the compiled-in default rule set.
pub fn default_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(SshBruteForce),
        Box::new(PathFromTmp),
        Box::new(ModsecCritical),
        Box::new(NginxErrorFlood),
        Box::new(CrossSshdFailedThenAccepted),
    ]
}

/// Lots of Failed-password lines in sshd. Pattern-count floor, not
/// rate-bucket floor, so the rule still fires on a cold replay.
pub struct SshBruteForce;
impl Rule for SshBruteForce {
    fn id(&self) -> &'static str {
        "ssh-brute-force"
    }
    fn label(&self) -> &'static str {
        "SSH brute-force"
    }
    fn score_bump(&self) -> u32 {
        25
    }
    fn evaluate(&self, snaps: &[PatternSnapshot]) -> Vec<u64> {
        snaps
            .iter()
            .filter(|s| {
                s.bundle_id.starts_with("sshd")
                    && s.skeleton.contains("Failed password")
                    && s.count >= 20
            })
            .map(|s| s.id)
            .collect()
    }
}

/// A path variable with a value under /tmp/, /dev/shm/, or /var/tmp.
///
/// The base scorer already has `path_suspicion` for the same signal;
/// the rule exists to produce a named badge on top of the base
/// score so operators recognise it.
pub struct PathFromTmp;
impl Rule for PathFromTmp {
    fn id(&self) -> &'static str {
        "exec-from-tmp"
    }
    fn label(&self) -> &'static str {
        "Exec from /tmp"
    }
    fn score_bump(&self) -> u32 {
        10
    }
    fn evaluate(&self, snaps: &[PatternSnapshot]) -> Vec<u64> {
        const SUSPICIOUS: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/", "/private/tmp/"];
        snaps
            .iter()
            .filter(|s| {
                s.vars.iter().any(|v| {
                    v.ty == crate::types::TokenType::Path
                        && v.top
                            .iter()
                            .any(|(val, _)| SUSPICIOUS.iter().any(|n| val.starts_with(n)))
                })
            })
            .map(|s| s.id)
            .collect()
    }
}

/// Any ModSec event whose fold-key contains `CRITICAL`.
pub struct ModsecCritical;
impl Rule for ModsecCritical {
    fn id(&self) -> &'static str {
        "modsec-critical"
    }
    fn label(&self) -> &'static str {
        "ModSec CRITICAL"
    }
    fn score_bump(&self) -> u32 {
        30
    }
    fn evaluate(&self, snaps: &[PatternSnapshot]) -> Vec<u64> {
        snaps
            .iter()
            .filter(|s| s.bundle_id.starts_with("modsec") && s.skeleton.contains("CRITICAL"))
            .map(|s| s.id)
            .collect()
    }
}

/// nginx access logs with a lot of 4xx or 5xx entries folding into one
/// pattern. The skeleton contains ` 4xx ` or ` 5xx ` after the request
/// line.
pub struct NginxErrorFlood;
impl Rule for NginxErrorFlood {
    fn id(&self) -> &'static str {
        "nginx-error-flood"
    }
    fn label(&self) -> &'static str {
        "HTTP 4xx/5xx flood"
    }
    fn score_bump(&self) -> u32 {
        15
    }
    fn evaluate(&self, snaps: &[PatternSnapshot]) -> Vec<u64> {
        snaps
            .iter()
            .filter(|s| {
                let is_web = s.bundle_id.starts_with("nginx")
                    || s.bundle_id.starts_with("apache")
                    || s.bundle_id.starts_with("web/")
                    || s.bundle_id.contains("access");
                let looks_erroneous = s.skeleton.contains(" 4")
                    || s.skeleton.contains(" 5")
                    || s.skeleton.contains("{NUM}"); // generic hit; most access logs have status NUM
                is_web && looks_erroneous && s.count >= 100
            })
            .map(|s| s.id)
            .collect()
    }
}

/// Cross-pattern: a snapshot set that has BOTH an sshd Failed-password
/// pattern (count >= 10) AND an sshd Accepted-password pattern is a
/// strong brute-force-success indicator. Every matching Accepted
/// pattern gets the bump.
pub struct CrossSshdFailedThenAccepted;
impl Rule for CrossSshdFailedThenAccepted {
    fn id(&self) -> &'static str {
        "cross-sshd-brute-success"
    }
    fn label(&self) -> &'static str {
        "Brute-force then accepted"
    }
    fn score_bump(&self) -> u32 {
        40
    }
    fn evaluate(&self, snaps: &[PatternSnapshot]) -> Vec<u64> {
        let has_failed = snaps.iter().any(|s| {
            s.bundle_id.starts_with("sshd")
                && s.skeleton.contains("Failed password")
                && s.count >= 10
        });
        if !has_failed {
            return Vec::new();
        }
        snaps
            .iter()
            .filter(|s| s.bundle_id.starts_with("sshd") && s.skeleton.contains("Accepted password"))
            .map(|s| s.id)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use compact_str::CompactString;
    use std::time::Instant;

    fn mk(id: u64, skel: &str, bundle: &str, count: u64) -> PatternSnapshot {
        PatternSnapshot {
            id,
            skeleton: CompactString::new(skel),
            label: None,
            bundle_id: CompactString::new(bundle),
            severity_hint: crate::types::Severity::Info,
            count,
            first_seen: Instant::now(),
            last_seen: Instant::now(),
            peak_bucket: 0,
            mean_bucket: 0.0,
            rate_buckets: [0; 24],
            last_bucket_epoch: 0,
            vars: vec![],
        }
    }

    #[test]
    fn brute_force_fires_above_threshold() {
        let r = SshBruteForce;
        let snaps = vec![
            mk(1, "Failed password for {USER}", "sshd", 25),
            mk(2, "Accepted publickey for {USER}", "sshd", 100),
            mk(3, "Failed password for {USER}", "sshd", 5), // below threshold
        ];
        let hits = r.evaluate(&snaps);
        assert_eq!(hits, vec![1]);
    }

    #[test]
    fn cross_rule_only_fires_when_both_present() {
        let r = CrossSshdFailedThenAccepted;

        let only_failed = vec![mk(1, "Failed password for {USER}", "sshd", 50)];
        assert!(r.evaluate(&only_failed).is_empty());

        let both = vec![
            mk(1, "Failed password for {USER}", "sshd", 50),
            mk(2, "Accepted password for {USER}", "sshd", 1),
        ];
        assert_eq!(r.evaluate(&both), vec![2]);
    }

    #[test]
    fn modsec_critical_fires_on_critical_fold_key() {
        let r = ModsecCritical;
        let snaps = vec![
            mk(
                1,
                "modsec rule 930110 CRITICAL: path traversal // GET {PATH}",
                "modsec-v3",
                3,
            ),
            mk(
                2,
                "modsec rule 999999 NOTICE: something // GET {PATH}",
                "modsec-v3",
                3,
            ),
        ];
        assert_eq!(r.evaluate(&snaps), vec![1]);
    }
}
