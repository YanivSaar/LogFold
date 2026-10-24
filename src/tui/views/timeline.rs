//! Timeline view: per-pattern rate sparkline.
//!
//! v0.3: wired to the real `rate_buckets` ring on each snapshot. The
//! ring is already in chronological order (oldest-first) at snapshot
//! time, so each `u32` here is one 5-minute slice of the last 2 hours.

use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph, Sparkline};

use crate::engine::pattern::PatternSnapshot;
use crate::tui::theme;

pub fn render(frame: &mut Frame<'_>, area: Rect, snaps: &[PatternSnapshot]) {
    if snaps.is_empty() {
        let msg = Paragraph::new("No patterns yet.").style(theme::muted_style());
        frame.render_widget(msg, area);
        return;
    }

    let mut sorted: Vec<&PatternSnapshot> = snaps.iter().collect();
    sorted.sort_by_key(|s| std::cmp::Reverse(s.count));
    let top: Vec<&PatternSnapshot> = sorted.into_iter().take(8).collect();

    let outer = Block::default()
        .borders(Borders::ALL)
        .title(" timeline - top 8 by count, last 2h in 5-min buckets ");
    let inner = outer.inner(area);
    frame.render_widget(outer, area);

    let constraints: Vec<Constraint> = top.iter().map(|_| Constraint::Length(3)).collect();
    let chunks = Layout::vertical(constraints).split(inner);

    for (snap, &area) in top.iter().zip(chunks.iter()) {
        let peak = snap.peak_bucket;
        let label = format!(
            " {:>7}  peak {:>5}/5m  {} ",
            snap.count, peak, snap.skeleton
        );
        let p = Paragraph::new(label).style(theme::body_style());
        let row = Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)])
            .split(area);
        frame.render_widget(p, row[0]);

        // The ring is already oldest-first in the snapshot; feed it
        // straight to the sparkline widget.
        let data: Vec<u64> = snap.rate_buckets.iter().map(|&b| b as u64).collect();
        let spark = Sparkline::default()
            .data(&data)
            .style(Style::default().fg(theme::score_color(snap.count.min(100) as u32)));
        frame.render_widget(spark, row[1]);
    }
}
