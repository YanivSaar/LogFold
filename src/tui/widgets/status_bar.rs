//! Bottom status bar — three-cell layout.
//!
//! Left (`Min`) carries the long context (ingest totals + bundle),
//! middle (`Length`) carries counts and filter state, right (`Length`)
//! carries key hints. Each cell truncates independently so a long
//! bundle name on the left can't push the key hints off the right.

use ratatui::prelude::*;
use ratatui::widgets::Paragraph;

use crate::tui::format::sanitize_for_display;
use crate::tui::theme;

pub fn render(frame: &mut Frame<'_>, area: Rect, left: &str, middle: &str, right: &str) {
    let left_s = sanitize_for_display(left);
    let middle_s = sanitize_for_display(middle);
    let right_s = sanitize_for_display(right);

    // Dynamically size middle/right so narrow terminals keep the hints
    // visible by preference over the ingest total.
    let right_w = (right_s.chars().count() as u16).min(area.width);
    let middle_w = (middle_s.chars().count() as u16).min(area.width.saturating_sub(right_w));
    let chunks = Layout::horizontal([
        Constraint::Min(0),
        Constraint::Length(middle_w),
        Constraint::Length(right_w),
    ])
    .split(area);

    let style = theme::header_style();
    frame.render_widget(Paragraph::new(left_s).style(style), chunks[0]);
    frame.render_widget(
        Paragraph::new(middle_s)
            .style(style)
            .alignment(Alignment::Center),
        chunks[1],
    );
    frame.render_widget(
        Paragraph::new(right_s)
            .style(style)
            .alignment(Alignment::Right),
        chunks[2],
    );
}
