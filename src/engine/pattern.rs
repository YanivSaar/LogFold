//! `Pattern` — one entry in the registry.
//!
//! A pattern records: the canonical skeleton, how many times it was seen,
//! when, at what rate, and (via `VarStats`) which concrete values filled
//! each `{TAG}` slot.
//!
//! Hot-path accesses are atomic; variable sampling takes a short mutex.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use compact_str::CompactString;
use indexmap::IndexMap;
use parking_lot::Mutex;
use smallvec::SmallVec;

use crate::parse::skeleton::VarSlot;
use crate::types::{Severity, TokenType};

/// Number of 5-minute rate buckets we keep per pattern (= 2 hours).
pub const RATE_BUCKETS: usize = 24;
/// Bucket width.
pub const BUCKET_SECS: u64 = 5 * 60;

/// Cap on variable slots sampled per pattern.
pub const MAX_VARS: usize = 16;

/// Point at which an exact [`IndexMap`] of values is promoted to a
/// Count-Min Sketch to keep memory bounded.
pub const EXACT_TO_SKETCH_THRESHOLD: usize = 32;

/// Top-K exemplar count kept per variable.
pub const TOP_K: usize = 10;

/// One pattern. Shared via `Arc<Pattern>` so the TUI can snapshot cheaply.
pub struct Pattern {
    pub id: u64,
    pub skeleton: CompactString,

    /// Optional label from a bundle `[[pattern]]` entry.
    pub label: Option<CompactString>,

    /// Which bundle this pattern was observed under. "unknown" when no
    /// detection has run (P1 default).
    pub bundle_id: CompactString,

    pub severity_hint: Severity,

    pub count: AtomicU64,
    pub first_seen: Instant,
    pub last_seen: Mutex<Instant>,

    /// Rate-bucket ring. `last_bucket_epoch` holds the integer bucket index
    /// the ring was last touched in; crossing an epoch zeros stale buckets.
    pub rate_buckets: [AtomicU32; RATE_BUCKETS],
    pub last_bucket_epoch: AtomicU64,

    /// Variable stats. Fixed order matches `skeleton`'s `{TAG}` slot order.
    /// Mutex contention is near-zero because the same skeleton hash always
    /// routes to the same DashMap shard, so one worker owns each pattern.
    pub vars: Mutex<SmallVec<[VarStats; 8]>>,
}

impl Pattern {
    pub fn new(
        id: u64,
        skeleton: CompactString,
        bundle_id: CompactString,
        slots: &[VarSlot],
    ) -> Self {
        let vars = slots
            .iter()
            .take(MAX_VARS)
            .map(|slot| VarStats::new(slot.ty))
            .collect();

        let now = Instant::now();
        Pattern {
            id,
            skeleton,
            label: None,
            bundle_id,
            severity_hint: Severity::Info,
            count: AtomicU64::new(0),
            first_seen: now,
            last_seen: Mutex::new(now),
            // AtomicU32 is not Copy, so can't just `[AtomicU32::new(0); 24]`.
            rate_buckets: std::array::from_fn(|_| AtomicU32::new(0)),
            last_bucket_epoch: AtomicU64::new(0),
            vars: Mutex::new(vars),
        }
    }

    /// Observe one hit at `now`, updating count, last_seen, rate bucket.
    pub fn observe(&self, now: Instant) {
        self.count.fetch_add(1, Ordering::Relaxed);
        *self.last_seen.lock() = now;
        self.bump_rate_bucket(now);
    }

    fn bump_rate_bucket(&self, now: Instant) {
        let secs_since_first = now.saturating_duration_since(self.first_seen).as_secs();
        let epoch = secs_since_first / BUCKET_SECS;
        let idx = (epoch as usize) % RATE_BUCKETS;

        let prev_epoch = self.last_bucket_epoch.load(Ordering::Relaxed);
        if prev_epoch != epoch {
            // Rolled into a new bucket (possibly skipping several). Clear
            // stale buckets between prev_epoch (exclusive) and epoch
            // (inclusive). Bounded loop by RATE_BUCKETS.
            let gap = (epoch - prev_epoch).min(RATE_BUCKETS as u64) as usize;
            for step in 1..=gap {
                let clear_idx =
                    (((prev_epoch + step as u64) as usize) % RATE_BUCKETS).min(RATE_BUCKETS - 1);
                self.rate_buckets[clear_idx].store(0, Ordering::Relaxed);
            }
            self.last_bucket_epoch.store(epoch, Ordering::Relaxed);
        }

        self.rate_buckets[idx].fetch_add(1, Ordering::Relaxed);
    }

    /// Peak count across the ring.
    pub fn peak_bucket(&self) -> u32 {
        self.rate_buckets
            .iter()
            .map(|b| b.load(Ordering::Relaxed))
            .max()
            .unwrap_or(0)
    }

    /// Arithmetic mean of ring buckets.
    pub fn mean_bucket(&self) -> f32 {
        let sum: u64 = self
            .rate_buckets
            .iter()
            .map(|b| b.load(Ordering::Relaxed) as u64)
            .sum();
        sum as f32 / RATE_BUCKETS as f32
    }

    /// Age of pattern in whole seconds.
    pub fn age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.first_seen)
    }

    pub fn snapshot(&self) -> PatternSnapshot {
        let vars = self
            .vars
            .lock()
            .iter()
            .map(|v| VarStatsSnapshot {
                ty: v.ty,
                distinct_approx: v.distinct_approx(),
                total: v.total,
                top: v.top().into_iter().map(|(k, v)| (k.clone(), v)).collect(),
            })
            .collect();

        // Snapshot the rate-bucket ring in chronological order. The
        // raw ring is indexed `(epoch % RATE_BUCKETS)`, so to walk it
        // oldest-to-newest we start one past the current epoch index.
        let last_epoch = self.last_bucket_epoch.load(Ordering::Relaxed);
        let current_idx = (last_epoch as usize) % RATE_BUCKETS;
        let mut rate_buckets = [0u32; RATE_BUCKETS];
        for (out_i, slot) in rate_buckets.iter_mut().enumerate() {
            let src_i = (current_idx + 1 + out_i) % RATE_BUCKETS;
            *slot = self.rate_buckets[src_i].load(Ordering::Relaxed);
        }

        PatternSnapshot {
            id: self.id,
            skeleton: self.skeleton.clone(),
            label: self.label.clone(),
            bundle_id: self.bundle_id.clone(),
            severity_hint: self.severity_hint,
            count: self.count.load(Ordering::Relaxed),
            first_seen: self.first_seen,
            last_seen: *self.last_seen.lock(),
            peak_bucket: self.peak_bucket(),
            mean_bucket: self.mean_bucket(),
            rate_buckets,
            last_bucket_epoch: last_epoch,
            vars,
        }
    }
}

/// Per-variable statistics. Starts exact (IndexMap), promotes to a sketch.
#[derive(Debug)]
pub struct VarStats {
    pub ty: TokenType,
    pub total: u64,
    pub exact: Option<IndexMap<CompactString, u64, ahash::RandomState>>,
    pub sketch: Option<CountMinSketch>,
    /// Top-K exemplars by count. Only populated once the exact map is
    /// promoted — before promotion the IndexMap itself serves as top-K.
    pub topk: Option<Vec<(CompactString, u64)>>,
}

impl VarStats {
    pub fn new(ty: TokenType) -> Self {
        VarStats {
            ty,
            total: 0,
            exact: Some(IndexMap::with_capacity_and_hasher(
                16,
                ahash::RandomState::default(),
            )),
            sketch: None,
            topk: None,
        }
    }

    pub fn observe(&mut self, value: &str) {
        self.total += 1;

        if let Some(exact) = self.exact.as_mut() {
            match exact.get_full_mut(value) {
                Some((_, _, counter)) => *counter += 1,
                None => {
                    exact.insert(CompactString::new(value), 1);
                }
            }

            if exact.len() > EXACT_TO_SKETCH_THRESHOLD {
                self.promote_to_sketch();
            }
            return;
        }

        // Sketch-promoted path.
        if let Some(sketch) = self.sketch.as_mut() {
            sketch.add(value.as_bytes());
            if let Some(topk) = self.topk.as_mut() {
                maybe_push_topk(topk, value, sketch.estimate(value.as_bytes()));
            }
        }
    }

    fn promote_to_sketch(&mut self) {
        let Some(exact) = self.exact.take() else {
            return;
        };
        let mut sketch = CountMinSketch::new();
        let mut topk: Vec<(CompactString, u64)> = Vec::with_capacity(TOP_K);

        for (k, v) in &exact {
            for _ in 0..*v {
                sketch.add(k.as_bytes());
            }
            maybe_push_topk(&mut topk, k, *v);
        }

        self.sketch = Some(sketch);
        self.topk = Some(topk);
    }

    /// Approximate distinct value count.
    pub fn distinct_approx(&self) -> u64 {
        if let Some(exact) = &self.exact {
            exact.len() as u64
        } else {
            // Lower bound = exemplar count. We don't track an exact distinct
            // count in sketch mode — the sketch is for frequency, not
            // cardinality. If we need true cardinality later we can add a
            // HyperLogLog.
            self.topk.as_ref().map_or(0, |t| t.len() as u64)
        }
    }

    /// Top-K exemplars by count (sorted desc).
    pub fn top(&self) -> Vec<(&CompactString, u64)> {
        if let Some(exact) = &self.exact {
            let mut pairs: Vec<_> = exact.iter().map(|(k, v)| (k, *v)).collect();
            pairs.sort_unstable_by_key(|p| std::cmp::Reverse(p.1));
            pairs.truncate(TOP_K);
            pairs
        } else if let Some(topk) = &self.topk {
            let mut pairs: Vec<_> = topk.iter().map(|(k, v)| (k, *v)).collect();
            pairs.sort_unstable_by_key(|p| std::cmp::Reverse(p.1));
            pairs
        } else {
            Vec::new()
        }
    }
}

fn maybe_push_topk(topk: &mut Vec<(CompactString, u64)>, value: &str, count: u64) {
    if let Some(existing) = topk.iter_mut().find(|(k, _)| k.as_str() == value) {
        existing.1 = count;
        return;
    }
    if topk.len() < TOP_K {
        topk.push((CompactString::new(value), count));
        return;
    }
    // Evict smallest if this count is bigger.
    if let Some((idx, _)) = topk.iter().enumerate().min_by_key(|(_, (_, c))| *c) {
        if topk[idx].1 < count {
            topk[idx] = (CompactString::new(value), count);
        }
    }
}

/// Minimal Count-Min Sketch for approximate frequency.
#[derive(Debug)]
pub struct CountMinSketch {
    /// `[depth][width]` counters.
    cells: Box<[[u32; Self::WIDTH]; Self::DEPTH]>,
    seeds: [u64; Self::DEPTH],
}

impl Default for CountMinSketch {
    fn default() -> Self {
        Self::new()
    }
}

impl CountMinSketch {
    const DEPTH: usize = 4;
    const WIDTH: usize = 1024;

    pub fn new() -> Self {
        CountMinSketch {
            cells: Box::new([[0u32; Self::WIDTH]; Self::DEPTH]),
            seeds: [
                0x9E37_79B9_7F4A_7C15,
                0xBF58_476D_1CE4_E5B9,
                0x94D0_49BB_1331_11EB,
                0x2545_F491_4F6C_DD1D,
            ],
        }
    }

    pub fn add(&mut self, bytes: &[u8]) {
        for (i, &seed) in self.seeds.iter().enumerate() {
            let idx = (hash_with_seed(bytes, seed) as usize) % Self::WIDTH;
            self.cells[i][idx] = self.cells[i][idx].saturating_add(1);
        }
    }

    pub fn estimate(&self, bytes: &[u8]) -> u64 {
        let mut est = u32::MAX;
        for (i, &seed) in self.seeds.iter().enumerate() {
            let idx = (hash_with_seed(bytes, seed) as usize) % Self::WIDTH;
            est = est.min(self.cells[i][idx]);
        }
        est as u64
    }
}

fn hash_with_seed(bytes: &[u8], seed: u64) -> u64 {
    // FNV-1a flavoured with a seed. Not cryptographic; just needs to vary
    // the index across sketch rows.
    let mut h = seed;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

// ─────────────────────────────────────────────────────────────────────────────
// Snapshot types — immutable views for the TUI / output layer.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PatternSnapshot {
    pub id: u64,
    pub skeleton: CompactString,
    pub label: Option<CompactString>,
    pub bundle_id: CompactString,
    pub severity_hint: Severity,
    pub count: u64,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub peak_bucket: u32,
    pub mean_bucket: f32,
    /// Rate-bucket ring in chronological order, oldest-first. 24
    /// buckets of 5 minutes each = 2 hours of history. v0.3 wiring.
    pub rate_buckets: [u32; RATE_BUCKETS],
    /// Current epoch index (bucket count since first_seen). Lets the
    /// Timeline view compute wall-clock labels per bucket if it wants
    /// to.
    pub last_bucket_epoch: u64,
    pub vars: Vec<VarStatsSnapshot>,
}

#[derive(Debug, Clone)]
pub struct VarStatsSnapshot {
    pub ty: TokenType,
    pub distinct_approx: u64,
    pub total: u64,
    pub top: Vec<(CompactString, u64)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observe_increments_count() {
        let p = Pattern::new(1, "x".into(), "unknown".into(), &[]);
        let now = Instant::now();
        p.observe(now);
        p.observe(now);
        assert_eq!(p.count.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn var_stats_exact_then_promotes() {
        let mut v = VarStats::new(TokenType::Ip);
        for i in 0..40 {
            v.observe(&format!("10.0.0.{i}"));
        }
        assert!(v.exact.is_none(), "expected promotion past 32 distinct");
        assert!(v.sketch.is_some());
        assert_eq!(v.total, 40);
    }

    #[test]
    fn top_k_tracks_frequent_values() {
        let mut v = VarStats::new(TokenType::Word);
        for _ in 0..5 {
            v.observe("alice");
        }
        for _ in 0..2 {
            v.observe("bob");
        }
        v.observe("carol");
        let top = v.top();
        assert_eq!(top[0].0.as_str(), "alice");
        assert_eq!(top[0].1, 5);
    }

    #[test]
    fn bucket_rotates_across_epochs() {
        // Simulate observation at t0 and then far in the future; the far
        // observation should not accumulate in the old slot.
        let p = Pattern::new(1, "x".into(), "unknown".into(), &[]);
        p.observe(p.first_seen);
        p.observe(p.first_seen + Duration::from_secs(BUCKET_SECS));
        // Two different buckets, each with one hit.
        let hits: u32 = p
            .rate_buckets
            .iter()
            .map(|b| b.load(Ordering::Relaxed))
            .sum();
        assert_eq!(hits, 2);
    }
}
