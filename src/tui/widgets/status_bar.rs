//! Bottom status bar.

use ratatui::prelude::*;
use ratatui::widgets::Paragraph;

use crate::tui::format::sanitize_for_display;
use crate::tui::theme;

pub fn render(frame: &mut Frame<'_>, area: Rect, text: &str) {
    // Scrub control chars - a log line that reaches the status bar
    // (e.g. via a bundle id with an injected ANSI escape) must not
    // reposition the cursor or recolour the frame.
    let safe = sanitize_for_display(text);
    let p = Paragraph::new(safe).style(theme::header_style());
    frame.render_widget(p, area);
}
