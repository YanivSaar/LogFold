//! Plain-text renderer for the no-TUI mode.
//!
//! Produces two sections:
//!
//! ```text
//! ANOMALIES
//!   SCORE  COUNT   TAG     PATTERN
//!   97         1   [NEW]   Accepted password for {USER} from {IP} ...
//!
//! PATTERNS
//!   SCORE  COUNT   TAG     PATTERN
//!   12  49,812    [FOLD]   Failed password for {USER} from {IP} ...
//! ```

use std::io::Write;

use crate::engine::pattern::PatternSnapshot;
use crate::engine::scorer;
use crate::enrich::{self, Enricher};
use crate::types::Badge;

/// Config knobs the renderer needs.
pub struct TextConfig {
    pub top: usize,
    pub min_fold: u64,
    pub anomaly_threshold: u32,
}

/// Render into any `Write` sink. Returns the number of rows printed.
pub fn render<W: Write>(
    out: &mut W,
    snaps: &[PatternSnapshot],
    cfg: &TextConfig,
    enricher: &Enricher,
) -> std::io::Result<usize> {
    let peers = scorer::build_peer_vars(snaps);
    let mut scored: Vec<(u32, Badge, &PatternSnapshot)> = snaps
        .iter()
        .map(|s| {
            let score = scorer::compute_score(s, &peers) + enrich::score_bump(s, enricher);
            let badge = scorer::classify_badge(s, score, cfg.min_fold);
            (score, badge, s)
        })
        .collect();

    // Anomalies: sort by score desc.
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(b.2.count.cmp(&a.2.count)));

    writeln!(out, "ANOMALIES")?;
    writeln!(
        out,
        "  {:>5}  {:>7}  {:<7}  PATTERN",
        "SCORE", "COUNT", "TAG"
    )?;
    let mut rows = 0;
    for (score, badge, snap) in scored
        .iter()
        .filter(|(s, _, _)| *s >= cfg.anomaly_threshold)
        .take(cfg.top)
    {
        writeln!(
            out,
            "  {:>5}  {:>7}  [{:<5}] {}",
            score,
            fmt_count(snap.count),
            badge.label(),
            snap.skeleton
        )?;
        rows += 1;
    }
    if rows == 0 {
        writeln!(out, "  (none)")?;
    }

    writeln!(out)?;
    writeln!(out, "PATTERNS")?;
    writeln!(
        out,
        "  {:>5}  {:>7}  {:<7}  PATTERN",
        "SCORE", "COUNT", "TAG"
    )?;

    // Patterns: sort by count desc. Show patterns NOT in anomalies.
    let mut fold: Vec<_> = scored
        .iter()
        .filter(|(s, _, _)| *s < cfg.anomaly_threshold)
        .collect();
    fold.sort_by_key(|row| std::cmp::Reverse(row.2.count));
    for (score, badge, snap) in fold.iter().take(cfg.top) {
        writeln!(
            out,
            "  {:>5}  {:>7}  [{:<5}] {}",
            score,
            fmt_count(snap.count),
            badge.label(),
            snap.skeleton
        )?;
        rows += 1;
    }

    Ok(rows)
}

fn fmt_count(n: u64) -> String {
    if n < 1_000 {
        return n.to_string();
    }
    // Thousands separators without pulling a locale crate.
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    let first = bytes.len() % 3;
    if first > 0 {
        out.push_str(&s[..first]);
    }
    for (i, chunk) in s.as_bytes()[first..].chunks(3).enumerate() {
        if i > 0 || first > 0 {
            out.push(',');
        }
        out.push_str(std::str::from_utf8(chunk).unwrap());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thousands_separators() {
        assert_eq!(fmt_count(0), "0");
        assert_eq!(fmt_count(999), "999");
        assert_eq!(fmt_count(1_000), "1,000");
        assert_eq!(fmt_count(52_915), "52,915");
        assert_eq!(fmt_count(1_234_567), "1,234,567");
    }
}
