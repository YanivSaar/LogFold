//! Sources view: shows every input source + detected bundle + score.

use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Cell, Row, Table};

use crate::ingest::source::SourceReport;
use crate::tui::theme;

pub fn render(frame: &mut Frame<'_>, area: Rect, reports: &[SourceReport]) {
    let header_cells = ["SOURCE", "DETECTED AS", "SCORE", "LINES"]
        .iter()
        .map(|h| Cell::from(*h).style(theme::muted_style()));
    let header_row = Row::new(header_cells).height(1);

    let rows: Vec<Row<'_>> = reports
        .iter()
        .map(|r| {
            Row::new(vec![
                Cell::from(r.source.label()),
                Cell::from(r.verdict.bundle_id.to_string()),
                Cell::from(format!("{:>5.2}", r.verdict.score)),
                Cell::from(format!("{:>7}", r.lines)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(45),
            Constraint::Percentage(30),
            Constraint::Length(8),
            Constraint::Length(10),
        ],
    )
    .header(header_row)
    .block(Block::default().borders(Borders::ALL).title(" sources "));

    frame.render_widget(table, area);
}
