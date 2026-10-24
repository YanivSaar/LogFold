//! Timeline view: per-pattern rate ribbon.
//!
//! Each top-N pattern gets a two-line block: a header line showing the
//! total count, peak-per-5min and the (truncated) skeleton, followed by
//! an inline Unicode block-bar ribbon spanning the full inner width.
//! The ribbon is log-scaled so a pattern with one 40k-count bucket and
//! 23 near-zero buckets still shows a readable silhouette instead of
//! quantising to a single visible cell.

use ratatui::prelude::*;
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::engine::pattern::PatternSnapshot;
use crate::tui::format::{fmt_count, sanitize_for_display, truncate_cols};
use crate::tui::theme;

/// Eighth-blocks for ribbon bars; index 0 is "empty cell".
const BLOCKS: [char; 9] = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

pub fn render(frame: &mut Frame<'_>, area: Rect, snaps: &[PatternSnapshot]) {
    let outer = Block::default()
        .borders(Borders::ALL)
        .title(" timeline — top 8 by count, last 2h in 5-min buckets ")
        .style(theme::body_style());
    let inner = outer.inner(area);
    frame.render_widget(outer, area);

    if snaps.is_empty() {
        let msg = Paragraph::new("No patterns yet.").style(theme::muted_style());
        frame.render_widget(msg, inner);
        return;
    }

    let mut sorted: Vec<&PatternSnapshot> = snaps.iter().collect();
    sorted.sort_by_key(|s| std::cmp::Reverse(s.count));

    // Each row is a header line + ribbon line + blank separator. Fit
    // as many as the inner area allows (minimum 2 rows per entry, cap
    // of 8). Also reserve a bottom axis line.
    let axis_rows = 1u16;
    let per_entry: u16 = 3; // header + ribbon + spacer
    let usable = inner.height.saturating_sub(axis_rows);
    let n_fit = (usable / per_entry) as usize;
    let n = sorted.len().min(8).min(n_fit.max(1));
    let top: Vec<&PatternSnapshot> = sorted.into_iter().take(n).collect();

    let mut row_specs: Vec<Constraint> = (0..n).map(|_| Constraint::Length(per_entry)).collect();
    row_specs.push(Constraint::Length(axis_rows));
    row_specs.push(Constraint::Min(0));
    let chunks = Layout::vertical(row_specs).split(inner);

    for (snap, &slot) in top.iter().zip(chunks.iter()) {
        render_entry(frame, slot, snap);
    }

    // Axis line, aligned with the ribbon width.
    if let Some(axis_slot) = chunks.get(n) {
        let w = axis_slot.width as usize;
        let axis = axis_label(w);
        let p = Paragraph::new(axis).style(theme::muted_style());
        frame.render_widget(p, *axis_slot);
    }
}

fn render_entry(frame: &mut Frame<'_>, area: Rect, snap: &PatternSnapshot) {
    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .split(area);

    // Header line.
    let skel_budget = (area.width as usize).saturating_sub(32).max(10);
    let skel = truncate_cols(&sanitize_for_display(&snap.skeleton), skel_budget);
    let header = Line::from(vec![
        Span::styled(
            format!("{:>9}", fmt_count(snap.count)),
            Style::default()
                .fg(theme::score_color((snap.count.min(100)) as u32))
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  peak "),
        Span::styled(
            format!("{:>6}", fmt_count(snap.peak_bucket as u64)),
            Style::default().fg(theme::score_color(snap.peak_bucket.min(100))),
        ),
        Span::raw("/5m  "),
        Span::styled(skel, Style::default().fg(theme::FG)),
    ]);
    frame.render_widget(Paragraph::new(header), rows[0]);

    // Ribbon line: one cell per bucket, scaled across the full width.
    let ribbon = ribbon_line(&snap.rate_buckets, rows[1].width as usize);
    let ribbon_style = Style::default().fg(theme::score_color(snap.peak_bucket.min(100)));
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(ribbon, ribbon_style))),
        rows[1],
    );
}

/// Build a width-wide block-ribbon from the oldest-first bucket ring.
///
/// Scaling: log1p over max, so a single giant bucket next to many
/// near-zero ones still produces a readable gradient instead of one
/// full-height cell and 23 empties. Each output cell averages the
/// buckets that map to it (ring has 24, ribbon is `width`).
fn ribbon_line(buckets: &[u32], width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let n = buckets.len();
    if n == 0 {
        return " ".repeat(width);
    }
    let max = *buckets.iter().max().unwrap_or(&0) as f64;
    if max <= 0.0 {
        return "·".repeat(width);
    }
    let scale = (max + 1.0).ln();

    let mut out = String::with_capacity(width * 3);
    for i in 0..width {
        // Average the ring buckets that fall into this ribbon cell.
        // When width > n (common on wide terminals), several cells
        // share one bucket; when width < n, several buckets collapse
        // into one cell.
        let (lo, hi) = bucket_range(i, width, n);
        let count = hi - lo;
        if count == 0 {
            out.push(' ');
            continue;
        }
        let mean: f64 = buckets[lo..hi].iter().map(|&b| b as f64).sum::<f64>() / count as f64;
        let frac = (mean + 1.0).ln() / scale;
        let step = (frac * 8.0).round().clamp(0.0, 8.0) as usize;
        out.push(BLOCKS[step]);
    }
    out
}

/// Map ribbon cell `i` of `width` back to a `[lo, hi)` range in a
/// bucket slice of length `n`. Guarantees `lo <= hi <= n` and
/// `hi - lo >= 1` so the ribbon never silently drops data.
fn bucket_range(i: usize, width: usize, n: usize) -> (usize, usize) {
    let lo = i * n / width.max(1);
    let hi = ((i + 1) * n / width.max(1)).max(lo + 1).min(n);
    (lo.min(n), hi)
}

fn axis_label(width: usize) -> String {
    // Three anchors: -2h, -1h, now. Keep aligned to the ribbon.
    if width < 20 {
        return "-2h ─ now".to_string();
    }
    let left = "-2h";
    let mid = "-1h";
    let right = "now";
    let mid_pos = width / 2;
    let right_pos = width.saturating_sub(right.len());
    let mut row = vec![' '; width];
    for (i, c) in left.chars().enumerate() {
        if i < row.len() {
            row[i] = c;
        }
    }
    for (i, c) in mid.chars().enumerate() {
        let p = mid_pos + i;
        if p < row.len() {
            row[p] = c;
        }
    }
    for (i, c) in right.chars().enumerate() {
        let p = right_pos + i;
        if p < row.len() {
            row[p] = c;
        }
    }
    row.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ribbon_handles_empty() {
        assert_eq!(ribbon_line(&[], 10), "          ");
        assert_eq!(ribbon_line(&[0, 0, 0], 10), "··········");
    }

    #[test]
    fn ribbon_spike_is_visible() {
        // One huge value + many zeros. Pre-fix sparkline collapsed to
        // a single pixel; log-scaled ribbon preserves the shape.
        let mut buckets = vec![0u32; 24];
        buckets[12] = 40_000;
        let r = ribbon_line(&buckets, 24);
        assert!(r.chars().any(|c| c != ' ' && c != '·'));
        assert!(r.contains('█'));
    }

    #[test]
    fn bucket_range_covers_all() {
        let n = 24;
        let w = 10;
        let mut covered = vec![false; n];
        for i in 0..w {
            let (lo, hi) = bucket_range(i, w, n);
            assert!(lo < hi);
            for slot in covered.iter_mut().take(hi).skip(lo) {
                *slot = true;
            }
        }
        assert!(covered.iter().all(|&c| c));
    }

    #[test]
    fn axis_label_has_markers() {
        let a = axis_label(40);
        assert!(a.starts_with("-2h"));
        assert!(a.contains("-1h"));
        assert!(a.trim_end().ends_with("now"));
    }
}
