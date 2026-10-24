//! Detail view: expanded view of the pattern selected in Overview.

use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap};

use crate::engine::pattern::PatternSnapshot;
use crate::tui::theme;

pub fn render(frame: &mut Frame<'_>, area: Rect, snap: Option<&PatternSnapshot>) {
    let Some(snap) = snap else {
        let msg = Paragraph::new("No pattern selected — go to [1] Overview and pick one.")
            .style(theme::muted_style())
            .wrap(Wrap { trim: true });
        frame.render_widget(msg, area);
        return;
    };

    let chunks = Layout::vertical([Constraint::Length(5), Constraint::Min(0)]).split(area);

    let summary = format!(
        "skeleton : {}\nbundle   : {}\ncount    : {}  |  peak/5m : {}  |  mean/5m : {:.1}",
        snap.skeleton, snap.bundle_id, snap.count, snap.peak_bucket, snap.mean_bucket
    );
    let p = Paragraph::new(summary)
        .block(Block::default().borders(Borders::ALL).title(" pattern "))
        .style(theme::body_style());
    frame.render_widget(p, chunks[0]);

    // Variables table.
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

    frame.render_widget(table, chunks[1]);
}
