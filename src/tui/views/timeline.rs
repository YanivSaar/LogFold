//! Timeline view: per-pattern rate sparkline.
//!
//! P3 minimal implementation — one row per top-N pattern, sparkline
//! sourced from each pattern's rate_buckets. Interaction (hover /
//! bucket inspection) lands with P4 live redraw.

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
        .title(" timeline — top 8 by count ");
    let inner = outer.inner(area);
    frame.render_widget(outer, area);

    let constraints: Vec<Constraint> = top.iter().map(|_| Constraint::Length(3)).collect();
    let chunks = Layout::vertical(constraints).split(inner);

    for (snap, &area) in top.iter().zip(chunks.iter()) {
        let label = format!(" {:>7}  {} ", snap.count, snap.skeleton);
        let p = Paragraph::new(label).style(theme::body_style());
        let row = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);
        frame.render_widget(p, row[0]);

        // Placeholder bar — the pattern snapshot doesn't yet surface
        // rate_buckets. Proper per-bucket values land with the live-redraw
        // loop in P4.
        let data = [snap.peak_bucket as u64; 24];
        let spark = Sparkline::default()
            .data(&data)
            .style(Style::default().fg(theme::score_color(snap.count.min(100) as u32)));
        frame.render_widget(spark, row[1]);
    }
}
