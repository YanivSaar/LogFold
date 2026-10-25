//! On-disk state snapshot. v0.10.
//!
//! When `--state <path>` is supplied, logfold writes a JSON snapshot
//! of the pattern registry at shutdown and restores from it on the
//! next start. Keeps the fold set alive across restarts of a
//! long-running `--follow` deployment.
//!
//! Format: JSON (serde_json). Human-readable so operators can `jq`
//! into a state file and prune by hand. Not stable across major
//! version bumps; v1.0 freezes the schema.

use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;
use std::sync::atomic::{AtomicU32, AtomicU64};
use std::sync::Arc;
use std::time::Instant;

use color_eyre::eyre::{Context, Result};
use compact_str::CompactString;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use crate::engine::pattern::{Pattern, RATE_BUCKETS};
use crate::engine::registry::PatternRegistry;
use crate::types::{Severity, TokenType};

/// Serializable per-pattern state. Captures what the engine needs
/// to reconstruct a `Pattern` without replaying the raw log.
#[derive(Debug, Serialize, Deserialize)]
pub struct StatePattern {
    pub id: u64,
    pub skeleton: String,
    pub bundle_id: String,
    pub label: Option<String>,
    pub severity_hint: Severity,
    pub count: u64,
    pub rate_buckets: [u32; 24],
    pub last_bucket_epoch: u64,
    /// Milliseconds since UNIX epoch at which the pattern was first
    /// seen. Used to approximate the restored `first_seen` on load.
    pub first_seen_unix_ms: u128,
    pub last_seen_unix_ms: u128,
    pub vars: Vec<StateVar>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StateVar {
    pub ty: TokenType,
    pub total: u64,
    pub top: Vec<(String, u64)>,
}

/// The on-disk wrapper. Carries a version tag so future readers can
/// refuse to load an incompatible snapshot.
#[derive(Debug, Serialize, Deserialize)]
pub struct StateFile {
    pub version: u32,
    pub saved_at_unix_ms: u128,
    pub patterns: Vec<StatePattern>,
}

/// Current schema version.
pub const STATE_VERSION: u32 = 1;

/// Serialise the current registry snapshot and write it to `path`.
///
/// Atomic: writes to `<path>.tmp` first then renames so a partial
/// write on crash doesn't corrupt the previous snapshot.
pub fn save(path: &Path, registry: &PatternRegistry) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let now_instant = Instant::now();

    let patterns: Vec<StatePattern> = registry
        .snapshot()
        .into_iter()
        .map(|s| {
            let first_delta = now_instant
                .saturating_duration_since(s.first_seen)
                .as_millis();
            let last_delta = now_instant
                .saturating_duration_since(s.last_seen)
                .as_millis();
            StatePattern {
                id: s.id,
                skeleton: s.skeleton.to_string(),
                bundle_id: s.bundle_id.to_string(),
                label: s.label.map(|l| l.to_string()),
                severity_hint: s.severity_hint,
                count: s.count,
                rate_buckets: s.rate_buckets,
                last_bucket_epoch: s.last_bucket_epoch,
                first_seen_unix_ms: now.saturating_sub(first_delta),
                last_seen_unix_ms: now.saturating_sub(last_delta),
                vars: s
                    .vars
                    .into_iter()
                    .map(|v| StateVar {
                        ty: v.ty,
                        total: v.total,
                        top: v.top.into_iter().map(|(k, c)| (k.to_string(), c)).collect(),
                    })
                    .collect(),
            }
        })
        .collect();

    let file = StateFile {
        version: STATE_VERSION,
        saved_at_unix_ms: now,
        patterns,
    };

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating state directory {}", parent.display()))?;
        }
    }
    let tmp = path.with_extension("tmp");
    {
        let f =
            File::create(&tmp).with_context(|| format!("creating state file {}", tmp.display()))?;
        let mut w = BufWriter::new(f);
        serde_json::to_writer(&mut w, &file)
            .with_context(|| format!("serialising state to {}", tmp.display()))?;
        // fsync before rename: BufWriter::drop flushes to the OS but
        // doesn't flush to disk. Power loss between rename and the OS
        // page-cache flush would otherwise truncate the state file.
        let inner = w
            .into_inner()
            .with_context(|| format!("flushing state to {}", tmp.display()))?;
        inner
            .sync_all()
            .with_context(|| format!("fsync {}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    tracing::info!(path = %path.display(), patterns = file.patterns.len(), "state saved");
    Ok(())
}

/// Read a state file and seed the registry with its patterns. Returns
/// the number of patterns injected, or `Ok(0)` if the file doesn't
/// exist (fresh start). Logs a warning and keeps going on schema
/// mismatch - no reason to make a stale state file an outage.
pub fn load(path: &Path, registry: &PatternRegistry) -> Result<usize> {
    if !path.exists() {
        return Ok(0);
    }
    let f = File::open(path).with_context(|| format!("opening state file {}", path.display()))?;
    let mut r = BufReader::new(f);
    let file: StateFile = match serde_json::from_reader(&mut r) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "state file unreadable; starting fresh");
            return Ok(0);
        }
    };
    if file.version != STATE_VERSION {
        tracing::warn!(
            path = %path.display(),
            got = file.version,
            want = STATE_VERSION,
            "state schema mismatch; starting fresh"
        );
        return Ok(0);
    }

    // Reconstruct Patterns in-place. We can't use upsert() because that
    // builds a fresh pattern and increments the count by one; we want
    // to install the pattern with its historical counters intact.
    let now = Instant::now();
    let now_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let mut injected = 0usize;
    for p in file.patterns {
        let first_delta_ms = now_unix_ms.saturating_sub(p.first_seen_unix_ms) as u64;
        let last_delta_ms = now_unix_ms.saturating_sub(p.last_seen_unix_ms) as u64;
        // checked_sub: a stale or forward-dated state file (clock skew,
        // zero timestamp, deserialisation bug) would otherwise panic on
        // Instant arithmetic underflow. Fall back to `now` so the worst
        // case is losing the historical first_seen, not crashing boot.
        let first_seen = now
            .checked_sub(std::time::Duration::from_millis(first_delta_ms))
            .unwrap_or(now);
        let last_seen = now
            .checked_sub(std::time::Duration::from_millis(last_delta_ms))
            .unwrap_or(now);

        let pattern = Pattern {
            id: p.id,
            skeleton: CompactString::new(&p.skeleton),
            label: p.label.map(CompactString::new),
            bundle_id: CompactString::new(&p.bundle_id),
            severity_hint: p.severity_hint,
            count: AtomicU64::new(p.count),
            first_seen,
            last_seen: Mutex::new(last_seen),
            rate_buckets: std::array::from_fn(|i| {
                AtomicU32::new(*p.rate_buckets.get(i).unwrap_or(&0))
            }),
            last_bucket_epoch: AtomicU64::new(p.last_bucket_epoch),
            vars: Mutex::new(build_var_stats(&p.vars)),
        };

        let _ = RATE_BUCKETS; // keep the import referenced on no-change builds
        registry.restore_pattern(p.id, Arc::new(pattern));
        injected += 1;
    }
    tracing::info!(path = %path.display(), injected, "state restored");
    Ok(injected)
}

fn build_var_stats(vars: &[StateVar]) -> SmallVec<[crate::engine::pattern::VarStats; 8]> {
    let mut out: SmallVec<[crate::engine::pattern::VarStats; 8]> = SmallVec::new();
    for v in vars {
        let mut vs = crate::engine::pattern::VarStats::new(v.ty);
        // Restore each exemplar with its saved count. The old code
        // called `observe(val)` once per entry, which clobbered the
        // historical count to 1 — breaking cross-correlation and
        // ModSec triage across restarts.
        if let Some(exact) = vs.exact.as_mut() {
            for (val, c) in &v.top {
                exact.insert(CompactString::new(val), *c);
            }
        }
        vs.total = v.total;
        out.push(vs);
    }
    out
}
