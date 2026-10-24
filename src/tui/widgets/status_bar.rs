//! Bottom status bar.

use ratatui::prelude::*;
use ratatui::widgets::Paragraph;

use crate::tui::theme;

pub fn render(frame: &mut Frame<'_>, area: Rect, text: &str) {
    let p = Paragraph::new(text).style(theme::header_style());
    frame.render_widget(p, area);
}
