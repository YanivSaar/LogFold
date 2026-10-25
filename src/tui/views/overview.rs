//! Overview view: anomalies on top, folded patterns below.

use ratatui::prelude::*;
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Cell, Row, Table, TableState};

use crate::tui::views::timeline::ribbon_line;

use crate::engine::pattern::PatternSnapshot;
use crate::engine::scorer;
use crate::enrich::{self, Enricher};
use crate::tui::format::{fmt_count, sanitize_for_display};
use crate::tui::theme;
use crate::types::{Badge, TokenType};

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
        let peers = scorer::build_peer_vars(snaps);
        Self::build_filtered(
            snaps,
            &peers,
            min_fold,
            anomaly_threshold,
            None,
            &Enricher::empty(),
        )
    }

    /// Same as [`build`] but applies an optional substring filter on
    /// the skeleton text. Case-insensitive. Keeps the anomaly /
    /// pattern partition inside the filtered set.
    ///
    /// `peers` is caller-owned so an outer refresh loop can compute it
    /// once per snapshot generation and reuse it for every rebuild
    /// (filter typing, re-sort). Previously each stroke recomputed it
    /// — the biggest TUI hot-path win.
    pub fn build_filtered<'a>(
        snaps: &'a [PatternSnapshot],
        peers: &[(u64, TokenType, &'a str)],
        min_fold: u64,
        anomaly_threshold: u32,
        filter: Option<&str>,
        enricher: &Enricher,
    ) -> Self {
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
                let score =
                    scorer::compute_score(&snap, peers) + enrich::score_bump(&snap, enricher);
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

    pub fn jump_top(&mut self) {
        self.selected = 0;
    }

    pub fn jump_bottom(&mut self) {
        if !self.rows.is_empty() {
            self.selected = self.rows.len() - 1;
        }
    }

    /// Move selection to the next row whose score >= threshold.
    /// Wraps. No-op if no anomalies.
    pub fn next_anomaly(&mut self, threshold: u32) {
        if self.rows.is_empty() {
            return;
        }
        let n = self.rows.len();
        let start = self.selected;
        for off in 1..=n {
            let i = (start + off) % n;
            if self.rows[i].score >= threshold {
                self.selected = i;
                return;
            }
        }
    }

    pub fn prev_anomaly(&mut self, threshold: u32) {
        if self.rows.is_empty() {
            return;
        }
        let n = self.rows.len();
        let start = self.selected;
        for off in 1..=n {
            let i = (start + n - off) % n;
            if self.rows[i].score >= threshold {
                self.selected = i;
                return;
            }
        }
    }

    pub fn selected_row(&self) -> Option<&ScoredRow> {
        self.rows.get(self.selected)
    }

    pub fn anomaly_count(&self) -> usize {
        self.anomaly_count
    }
}

pub fn render(frame: &mut Frame<'_>, area: Rect, state: &OverviewState) {
    // One-line banner above the table. The old Length(3) layout left
    // two blank rows that ratatui never actively painted; on a view
    // switch those cells kept whatever the previous view drew, which
    // read as "hpatterns" / "SCORE 6COUNT" glyphs leaking into the
    // table border.
    let chunks = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).split(area);

    let header_text = format!(
        " ANOMALIES ─ {} items (score ≥ threshold) ",
        state.anomaly_count
    );
    let header = ratatui::widgets::Paragraph::new(header_text).style(theme::header_style());
    frame.render_widget(header, chunks[0]);

    let header_cells = [" ", "SCORE", "COUNT", "TAG", "RATE/2h", "PATTERN"]
        .iter()
        .map(|h| Cell::from(*h).style(theme::muted_style()));
    let header_row = Row::new(header_cells).height(1);

    // Build rows with a left-edge severity swatch and a mid-list
    // separator between the anomaly group and the folded group so the
    // partition is readable without consulting the header count.
    let mut rows: Vec<Row<'_>> = Vec::with_capacity(state.rows.len() + 1);
    for (i, r) in state.rows.iter().enumerate() {
        if i == state.anomaly_count
            && state.anomaly_count > 0
            && state.anomaly_count < state.rows.len()
        {
            // Separator row — all cells muted, visible as a dim band.
            rows.push(
                Row::new(vec![
                    Cell::from("─"),
                    Cell::from("─────").style(theme::muted_style()),
                    Cell::from("───────").style(theme::muted_style()),
                    Cell::from("──────").style(theme::muted_style()),
                    Cell::from("──────────").style(theme::muted_style()),
                    Cell::from(" folded patterns ").style(theme::muted_style()),
                ])
                .height(1),
            );
        }
        let score_style = Style::default().fg(theme::score_color(r.score));
        let badge_label = format!(" {} ", r.badge.label());
        let swatch = if r.score >= 50 { "▍" } else { " " };
        // 10-wide inline ribbon of the last 2h of 5-min buckets. This
        // is the single biggest triage uplift from the UX plan — a
        // screen of "all 75 NEW" rows is unreadable without a per-row
        // volume shape to differentiate them.
        let ribbon = ribbon_line(&r.snap.rate_buckets, 10);
        rows.push(Row::new(vec![
            Cell::from(Span::styled(swatch, score_style)),
            Cell::from(format!("● {:>3}", r.score)).style(score_style),
            Cell::from(format!("{:>7}", fmt_count(r.snap.count))),
            Cell::from(badge_label).style(theme::badge_style(r.badge.label())),
            Cell::from(Span::styled(ribbon, score_style)),
            Cell::from(sanitize_for_display(&r.snap.skeleton)),
        ]));
    }

    let table = Table::new(
        rows,
        [
            Constraint::Length(1),
            Constraint::Length(7),
            Constraint::Length(9),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Min(20),
        ],
    )
    .header(header_row)
    .block(Block::default().borders(Borders::ALL).title(" patterns "))
    .row_highlight_style(theme::selected_style());

    // The separator row shifted the index of real rows past it by one;
    // compensate so arrow-key navigation still lines up with the user's
    // visual selection.
    let display_selected = if state.selected >= state.anomaly_count
        && state.anomaly_count > 0
        && state.anomaly_count < state.rows.len()
    {
        state.selected + 1
    } else {
        state.selected
    };
    let mut ts = TableState::default();
    ts.select(Some(display_selected));
    frame.render_stateful_widget(table, chunks[1], &mut ts);
}
