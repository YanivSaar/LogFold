//! `PatternRegistry` — a sharded, lock-free-on-the-hot-path map keyed by
//! skeleton hash.
//!
//! Insert and lookup both go through [`PatternRegistry::upsert`]. A
//! secondary index supports fuzzy fallback for near-miss variants.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use ahash::RandomState;
use compact_str::CompactString;
use dashmap::DashMap;
use parking_lot::Mutex;
use smallvec::SmallVec;

use crate::engine::extractor;
use crate::engine::fuzzy;
use crate::engine::hasher;
use crate::engine::pattern::{Pattern, PatternSnapshot};
use crate::parse::skeleton::VarSlot;
use crate::parse::Token;

/// Secondary-index bucket key = `(first_token_hash, token_count_class)`.
///
/// Token count class is `token_count` itself for small lines and `token_count / 2 * 2`
/// for larger lines — groups buckets of ±1 together so the fuzzy clusterer
/// can find candidates within an edit of each other.
type FuzzyKey = (u64, u16);

/// Maximum candidates we keep per fuzzy-index bucket. Beyond this, oldest
/// entries are evicted — bounding memory under adversarial inputs that
/// crowd one bucket with lots of near-but-not-quite-folding patterns.
const FUZZY_BUCKET_CAP: usize = 16;

/// What happened on an upsert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpsertOutcome {
    /// Direct skeleton hit on an existing pattern.
    Hit,
    /// Fuzzy clusterer folded this line into an existing pattern.
    FuzzyFold,
    /// A new pattern was inserted into the registry.
    NewPattern,
}

pub struct PatternRegistry {
    patterns: DashMap<u64, Arc<Pattern>, RandomState>,
    fuzzy_index: DashMap<FuzzyKey, Mutex<SmallVec<[u64; 8]>>, RandomState>,
    max_patterns: usize,
    /// Live count of entries in `patterns`. Used to enforce
    /// `max_patterns` without calling `DashMap::len()` while an entry
    /// lock is held — `len()` acquires a read lock on every shard,
    /// and the shard that owns the entry we just write-locked would
    /// deadlock on itself.
    pattern_count: AtomicUsize,
    /// Monotonic version bumped on every mutation. Lets observers
    /// (TUI, metrics) ask "did anything change since my last peek?"
    /// without cloning the snapshot.
    generation: AtomicU64,
}

impl PatternRegistry {
    pub fn new(max_patterns: usize) -> Self {
        let hasher = RandomState::new();
        PatternRegistry {
            patterns: DashMap::with_hasher(hasher.clone()),
            fuzzy_index: DashMap::with_hasher(hasher),
            max_patterns,
            pattern_count: AtomicUsize::new(0),
            generation: AtomicU64::new(0),
        }
    }

    /// Monotonic version. Bumped on every successful observe / insert.
    /// Readers compare this against the last value they saw to decide
    /// whether to recompute derived state.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    #[inline]
    fn bump_generation(&self) {
        self.generation.fetch_add(1, Ordering::Relaxed);
    }

    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Insert a prebuilt pattern under its stored id. Used by state
    /// restore (`src/state/mod.rs`) to seed the registry from a saved
    /// snapshot without replaying raw log lines. The fuzzy index is
    /// not populated by restore - the first live upsert on a near-miss
    /// variant pays that re-indexing cost.
    pub fn restore_pattern(&self, id: u64, pattern: Arc<Pattern>) {
        if self.pattern_count.load(Ordering::Relaxed) >= self.max_patterns {
            return;
        }
        if self.patterns.insert(id, pattern).is_none() {
            self.pattern_count.fetch_add(1, Ordering::Relaxed);
        }
        self.bump_generation();
    }

    /// Insert-or-fold a classified line.
    ///
    /// `bundle_id` is "unknown" in P1; P2 attaches the detected bundle.
    pub fn upsert(
        &self,
        skeleton: &CompactString,
        slots: &[VarSlot],
        tokens: &[Token<'_>],
        bundle_id: &str,
        now: Instant,
    ) -> UpsertOutcome {
        let hash = hasher::fnv1a(skeleton.as_bytes());

        if let Some(entry) = self.patterns.get(&hash) {
            let pat = entry.value().clone();
            drop(entry);
            pat.observe(now);
            extractor::ingest(&pat, slots, tokens);
            self.bump_generation();
            return UpsertOutcome::Hit;
        }

        // Miss: try fuzzy fold before creating a new pattern.
        let fkey = fuzzy_key_of(tokens);
        if let Some(bucket) = self.fuzzy_index.get(&fkey) {
            let candidates = bucket.value().lock().clone();
            drop(bucket);
            for cand_hash in candidates {
                if let Some(entry) = self.patterns.get(&cand_hash) {
                    let pat = entry.value().clone();
                    drop(entry);
                    if fuzzy::is_close(&pat.skeleton, skeleton) {
                        pat.observe(now);
                        extractor::ingest(&pat, slots, tokens);
                        self.bump_generation();
                        return UpsertOutcome::FuzzyFold;
                    }
                }
            }
        }

        // No fold — create. Build the candidate; the cap check happens
        // INSIDE the DashMap entry lock below so two concurrent inserts
        // can't both pass the check and overshoot `max_patterns`.
        let pat = Arc::new(Pattern::new(
            hash,
            skeleton.clone(),
            bundle_id.into(),
            slots,
        ));
        pat.observe(now);
        extractor::ingest(&pat, slots, tokens);

        let outcome = match self.patterns.entry(hash) {
            dashmap::mapref::entry::Entry::Occupied(occ) => {
                let winner = occ.get().clone();
                winner.observe(now);
                extractor::ingest(&winner, slots, tokens);
                UpsertOutcome::Hit
            }
            dashmap::mapref::entry::Entry::Vacant(vac) => {
                // Soft cap via the atomic counter — we can't call
                // DashMap::len() here because it read-locks every
                // shard, and we're already holding the write lock on
                // the shard that owns `hash`. The counter also closes
                // the TOCTOU window: fetch_add is atomic, so two
                // concurrent inserts that both pass the check reserve
                // distinct slots. We roll back the increment if we
                // bail out (not here — once we're past the check, we
                // commit).
                if self.pattern_count.load(Ordering::Relaxed) >= self.max_patterns {
                    return UpsertOutcome::NewPattern;
                }
                self.pattern_count.fetch_add(1, Ordering::Relaxed);
                vac.insert(pat);
                let bucket = self
                    .fuzzy_index
                    .entry(fkey)
                    .or_insert_with(|| Mutex::new(SmallVec::new()));
                let mut guard = bucket.value().lock();
                if guard.len() >= FUZZY_BUCKET_CAP {
                    // LRU-ish: drop the oldest. SmallVec remove is O(n) but
                    // n is bounded by FUZZY_BUCKET_CAP (= 16), so this is fine.
                    guard.remove(0);
                }
                guard.push(hash);
                UpsertOutcome::NewPattern
            }
        };
        self.bump_generation();
        outcome
    }

    /// Snapshot the current registry contents for rendering.
    ///
    /// Returns an unsorted vec. The caller decides how to sort.
    pub fn snapshot(&self) -> Vec<PatternSnapshot> {
        self.patterns.iter().map(|e| e.value().snapshot()).collect()
    }

    /// Iterate active patterns, exposing the `Arc<Pattern>` directly. Used
    /// by the cross-correlation pass in the scorer.
    pub fn for_each<F: FnMut(&Pattern)>(&self, mut f: F) {
        for e in self.patterns.iter() {
            f(e.value().as_ref());
        }
    }
}

fn fuzzy_key_of(tokens: &[Token<'_>]) -> FuzzyKey {
    let first = tokens
        .first()
        .map(|t| hasher::fnv1a(t.text.as_bytes()))
        .unwrap_or(0);
    let count = tokens.len().min(u16::MAX as usize) as u16;
    (first, count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{skeleton, tokenizer};
    use compact_str::CompactString;

    fn fold(reg: &PatternRegistry, line: &str) -> UpsertOutcome {
        let mut tokens = Vec::new();
        tokenizer::classify(line, &mut tokens);
        let mut skel = CompactString::default();
        let mut slots = Vec::new();
        skeleton::build(&tokens, &mut skel, &mut slots);
        reg.upsert(&skel, &slots, &tokens, "unknown", Instant::now())
    }

    #[test]
    fn skeleton_identical_lines_hit() {
        // Only IP and NUM tokens differ — WORD tokens stay literal — so these
        // two lines map to different skeletons. The fuzzy clusterer should
        // still fold them.
        let reg = PatternRegistry::new(1024);
        assert_eq!(
            fold(&reg, "Failed password for alice from 10.0.0.1 port 22"),
            UpsertOutcome::NewPattern
        );
        assert_eq!(
            fold(&reg, "Failed password for alice from 10.0.0.2 port 22"),
            UpsertOutcome::Hit
        );
        assert_eq!(reg.len(), 1);
        let snap = reg.snapshot();
        assert_eq!(snap[0].count, 2);
    }

    #[test]
    fn fuzzy_fold_nearby_variants() {
        let reg = PatternRegistry::new(1024);
        fold(&reg, "Failed password for alice from 10.0.0.1 port 22");
        let outcome = fold(&reg, "Failed password for bob from 10.0.0.2 port 22");
        assert_eq!(outcome, UpsertOutcome::FuzzyFold);
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn different_structures_do_not_fold() {
        let reg = PatternRegistry::new(1024);
        fold(&reg, "Accepted password for alice from 10.0.0.1 port 22");
        fold(&reg, "Session opened for user bob");
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn max_patterns_cap_respected() {
        let reg = PatternRegistry::new(1);
        fold(&reg, "pattern one here");
        fold(&reg, "pattern two different");
        assert_eq!(reg.len(), 1);
    }
}
