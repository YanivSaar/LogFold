//! Correlation rules. v0.9.
//!
//! A thin cousin of Sigma: each rule looks at the current pattern
//! snapshot set and decides whether a pattern (or a combination of
//! patterns) deserves an extra badge and a score bump. Rules run on
//! the snapshot path, not the hot path, so a rule can afford to
//! walk every pattern.
//!
//! v0.9 ships five hardcoded rules in [`pack::default_rules`]. A
//! YAML DSL for user-authored rules is on the roadmap.
//!
//! Design shape:
//!
//! * [`Rule`] is a boxed trait so each rule can carry its own
//!   evaluation logic. The trait is `Sync` because the snapshot
//!   pass is single-threaded today but may fan out later.
//! * [`RuleSet::evaluate_all`] returns a `HashMap<pattern_id,
//!   RuleHit>` with the aggregated bump across all rules that fired
//!   for that pattern.
//! * Score additions clamp to u32 and are capped at the same 100
//!   ceiling as the base scorer.

pub mod pack;

use std::collections::HashMap;

use crate::engine::pattern::PatternSnapshot;

/// A rule that may fire for one or more patterns in the current
/// snapshot set.
pub trait Rule: Sync + Send {
    /// Short machine-readable id (`"ssh-brute-force"`).
    fn id(&self) -> &'static str;
    /// Human-readable label shown next to the score bump.
    fn label(&self) -> &'static str;
    /// Points added when the rule fires.
    fn score_bump(&self) -> u32;
    /// Walk the snapshot set and return every pattern id this rule
    /// wants to tag. The returned pattern ids must be a subset of
    /// `snaps`.
    fn evaluate(&self, snaps: &[PatternSnapshot]) -> Vec<u64>;
}

/// Result of running every rule against the snapshot set.
#[derive(Debug, Default, Clone)]
pub struct RuleHit {
    /// Rule ids that fired for this pattern.
    pub rule_ids: Vec<&'static str>,
    /// Combined score bump.
    pub score_bump: u32,
}

/// Collection of rules evaluated together.
pub struct RuleSet {
    rules: Vec<Box<dyn Rule>>,
}

impl RuleSet {
    pub fn empty() -> Self {
        RuleSet { rules: Vec::new() }
    }

    /// Build the compiled-in default rule pack.
    pub fn default_pack() -> Self {
        RuleSet {
            rules: pack::default_rules(),
        }
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Add a rule to the set.
    pub fn push(&mut self, rule: Box<dyn Rule>) {
        self.rules.push(rule);
    }

    /// Run every rule against `snaps`. Returns a map keyed by
    /// pattern id with the aggregated bump + fired rule ids.
    pub fn evaluate_all(&self, snaps: &[PatternSnapshot]) -> HashMap<u64, RuleHit> {
        let mut out: HashMap<u64, RuleHit> = HashMap::new();
        for rule in &self.rules {
            let hits = rule.evaluate(snaps);
            for id in hits {
                let entry = out.entry(id).or_default();
                entry.rule_ids.push(rule.id());
                entry.score_bump = entry.score_bump.saturating_add(rule.score_bump());
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use compact_str::CompactString;
    use std::time::Instant;

    fn snap(id: u64, skel: &str, bundle: &str, count: u64) -> PatternSnapshot {
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
    fn default_pack_has_rules() {
        let rs = RuleSet::default_pack();
        assert!(!rs.is_empty());
    }

    #[test]
    fn aggregated_hit_counts_rule_ids() {
        struct AlwaysFires {
            id: &'static str,
            score: u32,
        }
        impl Rule for AlwaysFires {
            fn id(&self) -> &'static str {
                self.id
            }
            fn label(&self) -> &'static str {
                self.id
            }
            fn score_bump(&self) -> u32 {
                self.score
            }
            fn evaluate(&self, snaps: &[PatternSnapshot]) -> Vec<u64> {
                snaps.iter().map(|s| s.id).collect()
            }
        }
        let mut rs = RuleSet::empty();
        rs.push(Box::new(AlwaysFires { id: "a", score: 10 }));
        rs.push(Box::new(AlwaysFires { id: "b", score: 15 }));
        let snaps = vec![snap(1, "x", "sshd", 1)];
        let hits = rs.evaluate_all(&snaps);
        let hit = hits.get(&1).unwrap();
        assert_eq!(hit.score_bump, 25);
        assert_eq!(hit.rule_ids.len(), 2);
    }
}
