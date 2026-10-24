//! Overview view: anomalies on top, folded patterns below.

use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Cell, Row, Table, TableState};

use crate::engine::pattern::PatternSnapshot;
use crate::engine::scorer;
use crate::tui::theme;
use crate::types::Badge;

pub struct OverviewState {
    pub selected: usize,
    pub rows: Vec<ScoredRow>,
    anomaly_count: usize,
}

#[derive(Clone)]
pub struct ScoredRow {
    pub score: u32,
    pub badge: Badge,
    pub snap: PatternSnapshot,
}

impl OverviewState {
    pub fn build(snaps: &[PatternSnapshot], min_fold: u64, anomaly_threshold: u32) -> Self {
        Self::build_filtered(snaps, min_fold, anomaly_threshold, None)
    }

    /// Same as [`build`] but applies an optional substring filter on
    /// the skeleton text. Case-insensitive. Keeps the anomaly /
    /// pattern partition inside the filtered set.
    pub fn build_filtered(
        snaps: &[PatternSnapshot],
        min_fold: u64,
        anomaly_threshold: u32,
        filter: Option<&str>,
    ) -> Self {
        let peers = scorer::build_peer_vars(snaps);
        let needle = filter.map(|s| s.to_ascii_lowercase());

        let mut scored: Vec<ScoredRow> = snaps
            .iter()
            .filter(|snap| match &needle {
                Some(f) if !f.is_empty() => {
                    let skel = snap.skeleton.to_ascii_lowercase();
                    let bundle = snap.bundle_id.to_ascii_lowercase();
                    skel.contains(f.as_str()) || bundle.contains(f.as_str())
                }
                _ => true,
            })
            .cloned()
            .map(|snap| {
                let score = scorer::compute_score(&snap, &peers);
                let badge = scorer::classify_badge(&snap, score, min_fold);
                ScoredRow { score, badge, snap }
            })
            .collect();

        // Partition: anomalies by score desc, patterns by count desc.
        let mut anomalies: Vec<ScoredRow> = scored
            .iter()
            .filter(|r| r.score >= anomaly_threshold)
            .cloned()
            .collect();
        anomalies.sort_by(|a, b| b.score.cmp(&a.score).then(b.snap.count.cmp(&a.snap.count)));

        let mut folds: Vec<ScoredRow> = scored
            .drain(..)
            .filter(|r| r.score < anomaly_threshold)
            .collect();
        folds.sort_by_key(|r| std::cmp::Reverse(r.snap.count));

        let anomaly_count = anomalies.len();
        let mut rows = anomalies;
        rows.extend(folds);

        OverviewState {
            selected: 0,
            rows,
            anomaly_count,
        }
    }

    pub fn move_up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    pub fn move_down(&mut self) {
        if !self.rows.is_empty() && self.selected + 1 < self.rows.len() {
            self.selected += 1;
        }
    }

    pub fn selected_row(&self) -> Option<&ScoredRow> {
        self.rows.get(self.selected)
    }
}

pub fn render(frame: &mut Frame<'_>, area: Rect, state: &OverviewState) {
    let chunks = Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).split(area);

    let header_text = format!(
        " ANOMALIES ─ {} items (score ≥ threshold) ",
        state.anomaly_count
    );
    let header = ratatui::widgets::Paragraph::new(header_text).style(theme::header_style());
    frame.render_widget(header, chunks[0]);

    let header_cells = ["SCORE", "COUNT", "TAG", "PATTERN"]
        .iter()
        .map(|h| Cell::from(*h).style(theme::muted_style()));
    let header_row = Row::new(header_cells).height(1);

    let rows: Vec<Row<'_>> = state
        .rows
        .iter()
        .map(|r| {
            let score_style = Style::default().fg(theme::score_color(r.score));
            let badge_label = format!(" {} ", r.badge.label());
            Row::new(vec![
                Cell::from(format!("● {:>3}", r.score)).style(score_style),
                Cell::from(format!("{:>7}", fmt_count(r.snap.count))),
                Cell::from(badge_label).style(theme::badge_style(r.badge.label())),
                Cell::from(r.snap.skeleton.to_string()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(7),
            Constraint::Length(9),
            Constraint::Length(8),
            Constraint::Min(20),
        ],
    )
    .header(header_row)
    .block(Block::default().borders(Borders::ALL).title(" patterns "))
    .highlight_style(theme::selected_style());

    let mut ts = TableState::default();
    ts.select(Some(state.selected));
    frame.render_stateful_widget(table, chunks[1], &mut ts);
}

fn fmt_count(n: u64) -> String {
    if n < 1_000 {
        return n.to_string();
    }
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
