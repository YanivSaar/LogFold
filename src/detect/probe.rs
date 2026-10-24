//! Detection FSM.
//!
//! Each source starts `Detecting`, scores its bundle candidates from path
//! hints eagerly, and either shortcuts to `Decided` (path confidence
//! crosses [`EARLY_WIN`]) or buffers up to `probe_lines` of content for a
//! line-probe decision.
//!
//! Call sites:
//! - `attach` once per source, with the (optional) path and process name.
//! - `observe` per line while still in `Detecting`.
//! - `decide` to force a decision (used on EOF or on timeout).

use std::path::PathBuf;
use std::time::Instant;

use crate::detect::path_hint::{self, PathScore};
use crate::detect::registry::{BundleRegistry, DetectConfig};

/// Composite-score threshold above which the detector shortcuts to Decided
/// without any line probing. A full-path glob match (+1.0) crosses this
/// alone; a partial match (+0.5) does not.
pub const EARLY_WIN: f32 = 0.95;

/// Composite score required to pick a bundle. Below this the generic
/// fallback is chosen.
pub const WIN_THRESHOLD: f32 = 0.7;

/// A single candidate score for display in the Sources view.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub bundle_id: String,
    pub path: f32,
    pub proc: f32,
    pub probe: f32,
}

impl Candidate {
    pub fn total(&self) -> f32 {
        self.path + self.proc + self.probe
    }
}

/// Final verdict handed back to the caller.
#[derive(Debug, Clone)]
pub struct Verdict {
    pub bundle_id: String,
    pub score: f32,
    pub candidates: Vec<Candidate>,
}

/// Per-source state. Owns a buffer of pending lines so content detection
/// can be replayed after a decision.
pub struct Detector<'a> {
    cfg: DetectConfig,
    registry: &'a BundleRegistry,

    /// Base scores from path + process. One entry per bundle, in registry order.
    base_scores: Vec<PathScore>,

    /// Bitmask of which probes have matched at least one line, per bundle.
    /// Bit `i` is set if the bundle's probe pattern index `i` matched.
    probe_mask: Vec<u64>,
    probe_counts: Vec<u32>,

    /// Lines seen so far during detection.
    lines_seen: u32,

    /// Pending lines, re-dispatched post-decision.
    pending: Vec<String>,

    started_at: Instant,
    pub path: Option<PathBuf>,
    pub process: Option<String>,
}

impl<'a> Detector<'a> {
    pub fn attach(
        registry: &'a BundleRegistry,
        cfg: DetectConfig,
        path: Option<PathBuf>,
        process: Option<String>,
    ) -> Self {
        let base_scores = path_hint::score_all(registry, path.as_deref(), process.as_deref());
        let n = registry.bundles().len();
        Detector {
            cfg,
            registry,
            probe_mask: vec![0u64; n],
            probe_counts: vec![0u32; n],
            base_scores,
            lines_seen: 0,
            pending: Vec::new(),
            started_at: Instant::now(),
            path,
            process,
        }
    }

    /// Return `Some(bundle_id)` if path hints alone have already crossed
    /// [`EARLY_WIN`]. Caller then uses that bundle without buffering.
    pub fn early_win(&self) -> Option<String> {
        let (idx, score) = argmax(&self.base_scores)?;
        if score >= EARLY_WIN {
            Some(self.registry.bundles()[idx].id.to_string())
        } else {
            None
        }
    }

    /// Record one more sampled line's probe hits. Returns true when a
    /// decision is now ready (buffer full OR timeout elapsed).
    pub fn observe(&mut self, line: &str) -> bool {
        self.lines_seen += 1;
        self.pending.push(line.to_string());

        for (i, bundle) in self.registry.bundles().iter().enumerate() {
            if let Some(set) = bundle.line_probes.as_ref() {
                let matches = set.matches(line);
                let mut hit_any = false;
                for idx in matches.iter() {
                    hit_any = true;
                    if idx < 64 {
                        self.probe_mask[i] |= 1u64 << idx;
                    }
                }
                if hit_any {
                    self.probe_counts[i] += 1;
                }
            }
        }

        self.lines_seen as usize >= self.cfg.probe_lines
            || self.started_at.elapsed().as_millis() as u64 >= self.cfg.decision_timeout_ms
    }

    /// Finalise the detection and return the ordered candidate list plus
    /// the chosen bundle id.
    pub fn decide(&self) -> Verdict {
        let probe_lines = self.lines_seen.max(1) as f32;

        let mut candidates: Vec<Candidate> = self
            .registry
            .bundles()
            .iter()
            .enumerate()
            .map(|(i, b)| {
                // Specificity bonus: 0.3 per distinct probe anchor matched.
                let distinct = self.probe_mask[i].count_ones() as f32;
                // Base signal: fraction of sampled lines where any probe hit,
                // scaled up to a cap.
                let ratio = self.probe_counts[i] as f32 / probe_lines;
                let probe_score = ((ratio * 2.0).min(2.0) + distinct * 0.3).min(3.5);
                Candidate {
                    bundle_id: b.id.to_string(),
                    path: self.base_scores[i].path,
                    proc: self.base_scores[i].process,
                    probe: probe_score,
                }
            })
            .collect();

        candidates.sort_by(|a, b| {
            b.total()
                .partial_cmp(&a.total())
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let (bundle_id, score) = match candidates.first() {
            Some(c) if c.total() >= WIN_THRESHOLD => (c.bundle_id.clone(), c.total()),
            _ => ("generic/syslog".to_string(), 0.0),
        };

        Verdict {
            bundle_id,
            score,
            candidates,
        }
    }

    /// Pending lines accumulated during detection.
    pub fn drain_pending(&mut self) -> Vec<String> {
        std::mem::take(&mut self.pending)
    }
}

fn argmax(scores: &[PathScore]) -> Option<(usize, f32)> {
    scores
        .iter()
        .enumerate()
        .map(|(i, s)| (i, s.total()))
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn path_hint_shortcuts_decision() {
        let reg = BundleRegistry::load(None).unwrap();
        let d = Detector::attach(
            &reg,
            DetectConfig::default(),
            Some(Path::new("/var/log/auth.log").to_path_buf()),
            None,
        );
        // At least one bundle must match this path.
        let v = d.decide();
        assert!(
            v.candidates.first().map(|c| c.path).unwrap_or(0.0) > 0.0,
            "no bundle has path_hints covering /var/log/auth.log"
        );
    }

    #[test]
    fn line_probing_picks_sshd_without_path() {
        let reg = BundleRegistry::load(None).unwrap();
        let mut d = Detector::attach(&reg, DetectConfig::default(), None, None);
        for _ in 0..5 {
            d.observe("Oct 23 09:14:10 host sshd[1030]: Failed password for alice from 203.0.113.5 port 60000 ssh2");
            d.observe("Oct 23 09:14:11 host sshd[1031]: Accepted publickey for bob from 10.0.0.1 port 22 ssh2");
        }
        let v = d.decide();
        assert_eq!(v.bundle_id, "sshd", "candidates were {:#?}", v.candidates);
    }
}
