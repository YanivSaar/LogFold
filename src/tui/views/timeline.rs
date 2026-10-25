//! Timeline view.
//!
//! Top block: `BarChart` of total event volume across ALL patterns,
//! bucketed into the 24 five-minute slots of the last 2h. Gives a
//! single at-a-glance "when did things happen" shape.
//!
//! Bottom block: the top-N patterns by count, each with its own
//! inline sparkline + a plain-English last-seen note. Readable at a
//! glance even when a single pattern dominates the volume.

use ratatui::prelude::*;
use ratatui::text::Span;
use ratatui::widgets::{BarChart, Block, Borders, Paragraph};

use crate::engine::pattern::{PatternSnapshot, RATE_BUCKETS};
use crate::tui::format::{fmt_count, sanitize_for_display, truncate_cols};
use crate::tui::theme;

/// Eighth-blocks for ribbon bars; index 0 is "empty cell".
const BLOCKS: [char; 9] = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

pub fn render(frame: &mut Frame<'_>, area: Rect, snaps: &[PatternSnapshot]) {
    let outer = Block::default()
        .borders(Borders::ALL)
        .title(" timeline — last 2h in 5-min buckets ")
        .style(theme::body_style());
    let inner = outer.inner(area);
    frame.render_widget(outer, area);

    if snaps.is_empty() {
        let msg = Paragraph::new("No patterns yet.").style(theme::muted_style());
        frame.render_widget(msg, inner);
        return;
    }

    // Reserve the top 10 rows for the global BarChart, 1 row for the
    // axis, then the rest for per-pattern entries.
    let bar_h: u16 = 10.min(inner.height.saturating_sub(4));
    let chunks = Layout::vertical([
        Constraint::Length(bar_h),
        Constraint::Length(1),
        Constraint::Min(0),
    ])
    .split(inner);

    render_global_bars(frame, chunks[0], snaps);
    frame.render_widget(
        Paragraph::new(axis_label(chunks[1].width as usize)).style(theme::muted_style()),
        chunks[1],
    );
    render_per_pattern(frame, chunks[2], snaps);
}

fn render_global_bars(frame: &mut Frame<'_>, area: Rect, snaps: &[PatternSnapshot]) {
    if area.height == 0 {
        return;
    }
    // Sum per-bucket across every pattern.
    let mut totals = [0u64; RATE_BUCKETS];
    for s in snaps {
        for (i, &v) in s.rate_buckets.iter().enumerate() {
            totals[i] = totals[i].saturating_add(v as u64);
        }
    }
    // Prepare BarChart data: each slot gets a short label (relative
    // time) and the per-bucket total. BarChart expects (&str, u64).
    let labels: Vec<String> = (0..RATE_BUCKETS)
        .map(|i| {
            // bucket 0 is 2h-ago; bucket RATE_BUCKETS-1 is now.
            let mins_ago = (RATE_BUCKETS - 1 - i) * 5;
            if mins_ago == 0 {
                "now".to_string()
            } else if mins_ago >= 60 {
                format!("-{}h", mins_ago / 60)
            } else {
                format!("-{mins_ago}m")
            }
        })
        .collect();
    let data: Vec<(&str, u64)> = labels.iter().map(|s| s.as_str()).zip(totals).collect();

    let max = totals.iter().copied().max().unwrap_or(0);
    let bar = BarChart::default()
        .data(&data)
        .bar_width(2)
        .bar_gap(1)
        .max(max.max(1))
        .bar_style(Style::default().fg(theme::ACCENT))
        .value_style(Style::default().fg(theme::FG).add_modifier(Modifier::BOLD))
        .label_style(theme::muted_style());
    frame.render_widget(bar, area);
}

fn render_per_pattern(frame: &mut Frame<'_>, area: Rect, snaps: &[PatternSnapshot]) {
    if area.height < 2 {
        return;
    }
    // Partial-sort top-N by count. 8 by default, fewer if the area
    // can't fit them (each entry is 2 rows: title + ribbon).
    let mut sorted: Vec<&PatternSnapshot> = snaps.iter().collect();
    if sorted.len() > 8 {
        sorted.select_nth_unstable_by_key(7, |s| std::cmp::Reverse(s.count));
        sorted.truncate(8);
    }
    sorted.sort_by_key(|s| std::cmp::Reverse(s.count));

    let per_entry: u16 = 2;
    let max_n = (area.height / per_entry) as usize;
    let n = sorted.len().min(max_n);
    if n == 0 {
        return;
    }
    let specs: Vec<Constraint> = (0..n).map(|_| Constraint::Length(per_entry)).collect();
    let chunks = Layout::vertical(specs).split(area);
    for (snap, &slot) in sorted.iter().take(n).zip(chunks.iter()) {
        render_entry(frame, slot, snap);
    }
}

fn render_entry(frame: &mut Frame<'_>, area: Rect, snap: &PatternSnapshot) {
    let rows = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(area);

    // Title line: count, peak, last-bucket age in plain English, skel.
    let last_bucket_mins = last_nonzero_age(&snap.rate_buckets);
    let age_text = match last_bucket_mins {
        Some(0) => "now".to_string(),
        Some(m) if m < 60 => format!("{m}m ago"),
        Some(m) => format!("{}h ago", m / 60),
        None => "quiet 2h+".to_string(),
    };
    let skel_budget = (area.width as usize).saturating_sub(42).max(10);
    let skel = truncate_cols(&sanitize_for_display(&snap.skeleton), skel_budget);
    let title = Line::from(vec![
        Span::styled(
            format!("{:>9}", fmt_count(snap.count)),
            Style::default().fg(theme::FG).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  peak "),
        Span::styled(
            format!("{:>5}", fmt_count(snap.peak_bucket as u64)),
            Style::default().fg(theme::FG),
        ),
        Span::raw("/5m  "),
        Span::styled(format!("{:>10}", age_text), theme::muted_style()),
        Span::raw("  "),
        Span::styled(skel, Style::default().fg(theme::FG)),
    ]);
    frame.render_widget(Paragraph::new(title), rows[0]);

    // Ribbon coloured by spike ratio (peak/mean). Steady state stays
    // muted; a sudden burst stands out.
    let ratio = if snap.mean_bucket > 0.5 {
        (snap.peak_bucket as f32 / snap.mean_bucket).min(20.0)
    } else {
        0.0
    };
    let ratio_score = (ratio * 5.0) as u32;
    let ribbon = ribbon_line(&snap.rate_buckets, rows[1].width as usize);
    let ribbon_style = Style::default().fg(theme::score_color(ratio_score));
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(ribbon, ribbon_style))),
        rows[1],
    );
}

/// Build a width-wide block-ribbon from the oldest-first bucket ring.
/// Log1p scaling so a single huge bucket next to many near-zero ones
/// still reads as a gradient rather than quantising to one visible
/// cell.
pub(crate) fn ribbon_line(buckets: &[u32], width: usize) -> String {
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

fn bucket_range(i: usize, width: usize, n: usize) -> (usize, usize) {
    let lo = i * n / width.max(1);
    let hi = ((i + 1) * n / width.max(1)).max(lo + 1).min(n);
    (lo.min(n), hi)
}

/// How many minutes ago the last non-zero bucket is, counting from the
/// most-recent (last) bucket as 0. Returns None if the ring is all zero.
fn last_nonzero_age(buckets: &[u32]) -> Option<u32> {
    for (i, &v) in buckets.iter().enumerate().rev() {
        if v > 0 {
            return Some(((buckets.len() - 1 - i) * 5) as u32);
        }
    }
    None
}

fn axis_label(width: usize) -> String {
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

    #[test]
    fn last_nonzero_age_returns_minutes() {
        let mut b = vec![0u32; 24];
        b[23] = 5;
        assert_eq!(last_nonzero_age(&b), Some(0));
        b[23] = 0;
        b[22] = 1;
        assert_eq!(last_nonzero_age(&b), Some(5));
        b = vec![0u32; 24];
        assert_eq!(last_nonzero_age(&b), None);
    }
}
