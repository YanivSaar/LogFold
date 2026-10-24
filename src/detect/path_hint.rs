//! Score a source path (and optional process/journald unit name) against
//! every loaded bundle. Pure function — called by the detector FSM.

use std::path::Path;

use crate::detect::registry::{Bundle, BundleRegistry};

/// Score contributions for a given candidate.
#[derive(Debug, Clone, Copy, Default)]
pub struct PathScore {
    pub path: f32,
    pub process: f32,
}

impl PathScore {
    pub fn total(&self) -> f32 {
        self.path + self.process
    }
}

/// Score every bundle against `path` + `process` and return the composite
/// scores in registry order.
pub fn score_all(
    registry: &BundleRegistry,
    path: Option<&Path>,
    process: Option<&str>,
) -> Vec<PathScore> {
    registry
        .bundles()
        .iter()
        .map(|b| score_one(b, path, process))
        .collect()
}

pub fn score_one(bundle: &Bundle, path: Option<&Path>, process: Option<&str>) -> PathScore {
    let mut score = PathScore::default();

    if let (Some(path), Some(globs)) = (path, bundle.path_globs.as_ref()) {
        if globs.is_match(path) {
            score.path += 1.0;
        } else if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
            if globs.is_match(name) {
                score.path += 0.5;
            }
        }
    }

    if let Some(proc) = process {
        let lower = proc.to_ascii_lowercase();
        for hint in &bundle.process_hints {
            if hint.eq_ignore_ascii_case(&lower) {
                score.process += 0.8;
                break;
            }
            if lower.contains(hint.as_str()) {
                score.process += 0.6;
                break;
            }
        }
    }

    score
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::registry::BundleRegistry;

    #[test]
    fn matches_default_bundle_by_path() {
        let reg = BundleRegistry::load(None).unwrap();
        let scores = score_all(&reg, Some(Path::new("/var/log/auth.log")), None);
        // Expect at least one of the auth bundles to score ≥ 0.5.
        let max = scores.iter().map(|s| s.total()).fold(0.0_f32, f32::max);
        assert!(max >= 0.5, "no bundle matched /var/log/auth.log");
    }
}
