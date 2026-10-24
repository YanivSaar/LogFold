//! Detail view: expanded view of the pattern selected in Overview.
//!
//! Three sub-tabs:
//! * **Variables** (v) — per-slot distinct count, total, top values.
//! * **Score Breakdown** (s) — contribution per scorer component.
//! * **Raw Lines** (r) — synthesised example lines from top-K vars.

use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap};

use crate::engine::pattern::PatternSnapshot;
use crate::engine::scorer::{self, ScoreBreakdown};
use crate::tui::theme;

/// Which sub-tab the Detail view is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Variables,
    ScoreBreakdown,
    RawLines,
}

impl Tab {
    pub fn next(self) -> Self {
        match self {
            Tab::Variables => Tab::ScoreBreakdown,
            Tab::ScoreBreakdown => Tab::RawLines,
            Tab::RawLines => Tab::Variables,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Tab::Variables => "Variables",
            Tab::ScoreBreakdown => "Score Breakdown",
            Tab::RawLines => "Raw Lines",
        }
    }

    pub fn key_hint(self) -> &'static str {
        match self {
            Tab::Variables => "[v]",
            Tab::ScoreBreakdown => "[s]",
            Tab::RawLines => "[r]",
        }
    }
}

pub fn render(
    frame: &mut Frame<'_>,
    area: Rect,
    snap: Option<&PatternSnapshot>,
    peers: &[(crate::types::TokenType, &str)],
    tab: Tab,
) {
    let Some(snap) = snap else {
        let msg = Paragraph::new("No pattern selected - go to [1] Overview and pick one.")
            .style(theme::muted_style())
            .wrap(Wrap { trim: true });
        frame.render_widget(msg, area);
        return;
    };

    let chunks = Layout::vertical([
        Constraint::Length(5),
        Constraint::Length(1),
        Constraint::Min(0),
    ])
    .split(area);

    let summary = format!(
        "skeleton : {}\nbundle   : {}\ncount    : {}  |  peak/5m : {}  |  mean/5m : {:.1}",
        snap.skeleton, snap.bundle_id, snap.count, snap.peak_bucket, snap.mean_bucket
    );
    let p = Paragraph::new(summary)
        .block(Block::default().borders(Borders::ALL).title(" pattern "))
        .style(theme::body_style());
    frame.render_widget(p, chunks[0]);

    // Sub-tab bar.
    let bar = format!(
        " {} Variables   {} Score Breakdown   {} Raw Lines    <- {} ",
        Tab::Variables.key_hint(),
        Tab::ScoreBreakdown.key_hint(),
        Tab::RawLines.key_hint(),
        tab.label(),
    );
    let bar_p = Paragraph::new(bar).style(theme::header_style());
    frame.render_widget(bar_p, chunks[1]);

    match tab {
        Tab::Variables => render_variables(frame, chunks[2], snap),
        Tab::ScoreBreakdown => render_score(frame, chunks[2], snap, peers),
        Tab::RawLines => render_raw_lines(frame, chunks[2], snap),
    }
}

fn render_variables(frame: &mut Frame<'_>, area: Rect, snap: &PatternSnapshot) {
    let header = Row::new(
        ["VAR#", "TYPE", "DISTINCT", "TOTAL", "TOP VALUES"]
            .iter()
            .map(|h| Cell::from(*h).style(theme::muted_style())),
    );
    let rows: Vec<Row<'_>> = snap
        .vars
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let top = v
                .top
                .iter()
                .take(3)
                .map(|(k, c)| format!("{k} ({c})"))
                .collect::<Vec<_>>()
                .join(", ");
            Row::new(vec![
                Cell::from(format!("{i}")),
                Cell::from(v.ty.tag()),
                Cell::from(v.distinct_approx.to_string()),
                Cell::from(v.total.to_string()),
                Cell::from(top),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(5),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Min(20),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(" variables "));

    frame.render_widget(table, area);
}

fn render_score(
    frame: &mut Frame<'_>,
    area: Rect,
    snap: &PatternSnapshot,
    peers: &[(crate::types::TokenType, &str)],
) {
    let b: ScoreBreakdown = scorer::compute_score_components(snap, peers);
    let total = b.total();

    let header = Row::new(
        ["COMPONENT", "POINTS", "WHY"]
            .iter()
            .map(|h| Cell::from(*h).style(theme::muted_style())),
    );
    let rows = vec![
        Row::new(vec![
            Cell::from("frequency"),
            Cell::from(b.frequency.to_string()),
            Cell::from(freq_explain(snap.count)),
        ]),
        Row::new(vec![
            Cell::from("rate_spike"),
            Cell::from(b.rate_spike.to_string()),
            Cell::from(spike_explain(snap.peak_bucket, snap.mean_bucket)),
        ]),
        Row::new(vec![
            Cell::from("cross_correlation"),
            Cell::from(b.cross_correlation.to_string()),
            Cell::from(if b.cross_correlation > 0 {
                "shared variable value with another pattern"
            } else {
                "no shared values with peers"
            }),
        ]),
        Row::new(vec![
            Cell::from("path_suspicion"),
            Cell::from(b.path_suspicion.to_string()),
            Cell::from(if b.path_suspicion > 0 {
                "path variable touches /tmp, /dev/shm, /var/tmp"
            } else {
                "no suspicious path variable"
            }),
        ]),
        Row::new(vec![
            Cell::from("severity hint"),
            Cell::from(b.severity.to_string()),
            Cell::from(format!("bundle severity: {:?}", snap.severity_hint)),
        ]),
        Row::new(vec![
            Cell::from("TOTAL".to_string()).style(theme::header_style()),
            Cell::from(total.to_string()).style(theme::header_style()),
            Cell::from("sum, clamped to 100").style(theme::muted_style()),
        ]),
    ];

    let table = Table::new(
        rows,
        [
            Constraint::Length(20),
            Constraint::Length(8),
            Constraint::Min(20),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" score breakdown "),
    );
    frame.render_widget(table, area);
}

fn freq_explain(count: u64) -> String {
    match count {
        1 => "first time ever seeing this pattern".into(),
        2..=3 => format!("very rare (count = {count})"),
        4..=10 => format!("uncommon (count = {count})"),
        _ => format!("common (count = {count})"),
    }
}

fn spike_explain(peak: u32, mean: f32) -> String {
    if mean < 1.0 {
        "mean bucket too small to detect spike".into()
    } else {
        let r = peak as f32 / mean;
        format!("peak {peak} / mean {mean:.2} = {r:.1}x (bands: >5x +25, >3x +12)")
    }
}

fn render_raw_lines(frame: &mut Frame<'_>, area: Rect, snap: &PatternSnapshot) {
    // We don't store the raw lines per pattern, but we can synthesise
    // representative examples by walking the skeleton and plugging in
    // the top-K value for each `{TAG}` slot. This gives the operator
    // concrete anchors even though we're not keeping raw text yet.
    let lines = synthesise_examples(snap, 5);

    let body = if lines.is_empty() {
        "No example variables captured yet. Raw-line retention lands with v0.6 webhook work."
            .to_string()
    } else {
        let mut s = String::new();
        s.push_str("Representative example lines synthesised from top-K variable values:\n\n");
        for (i, line) in lines.iter().enumerate() {
            s.push_str(&format!("  {}. {}\n", i + 1, line));
        }
        s.push_str(
            "\n(Full raw-line retention is a v0.6 feature; v0.3 reconstructs from the TopK heap.)",
        );
        s
    };

    let p = Paragraph::new(body)
        .block(Block::default().borders(Borders::ALL).title(" raw lines "))
        .style(theme::body_style())
        .wrap(Wrap { trim: false });
    frame.render_widget(p, area);
}

/// Walk `snap.skeleton` and replace `{TAG}` slots with top-K exemplars
/// drawn from the matching variable. Produces up to `n` distinct example
/// lines.
pub fn synthesise_examples(snap: &PatternSnapshot, n: usize) -> Vec<String> {
    if snap.vars.is_empty() || n == 0 {
        return vec![snap.skeleton.to_string()];
    }

    // How many "variants" per variable to try. We iterate the top-K
    // of each variable in parallel: variant i picks each var's i-th
    // exemplar, falling back to the first.
    let mut out = Vec::new();
    for i in 0..n {
        let mut line = String::new();
        let mut cursor = snap.skeleton.as_str();
        let mut var_idx = 0;
        while let Some(start) = cursor.find('{') {
            line.push_str(&cursor[..start]);
            let after_brace = &cursor[start..];
            if let Some(end) = after_brace.find('}') {
                // Pick a value from the var's top-K at index i, fall back to [0].
                let value = snap
                    .vars
                    .get(var_idx)
                    .and_then(|v| v.top.get(i).or_else(|| v.top.first()))
                    .map(|(k, _)| k.as_str())
                    .unwrap_or_else(|| &after_brace[..=end]);
                line.push_str(value);
                cursor = &after_brace[end + 1..];
                var_idx += 1;
            } else {
                line.push_str(after_brace);
                cursor = "";
                break;
            }
        }
        line.push_str(cursor);
        if !out.contains(&line) {
            out.push(line);
        }
    }
    out
}
