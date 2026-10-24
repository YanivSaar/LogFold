//! Help overlay — rendered when the user presses `?`.

use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

use crate::tui::theme;

const HELP_LINES: &[(&str, &str)] = &[
    (
        "1 2 3 4",
        "Switch to Overview / Detail / Sources / Timeline",
    ),
    ("Tab", "Next view (or next Detail sub-tab if in Detail)"),
    ("Up Down / j k", "Move selection"),
    ("Enter / Right", "Open Detail view for the selected pattern"),
    ("Esc", "Back to Overview from Detail; quit elsewhere"),
    ("", ""),
    (
        "v / s / r",
        "Detail sub-tabs: Variables / Score / Raw Lines",
    ),
    ("", ""),
    ("f or /", "Filter pattern list by substring"),
    ("Backspace", "Edit the filter"),
    ("Esc (in filter)", "Clear the filter"),
    ("Enter (in filter)", "Keep the filter, exit edit mode"),
    ("", ""),
    ("w", "Change time window (v0.5)"),
    ("c", "Copy selected to clipboard (v0.6)"),
    ("e", "Export current view (v0.11)"),
    ("p", "Pause / resume ingest (v0.5)"),
    ("q", "Quit"),
    ("?", "Toggle this help overlay"),
];

pub fn render(frame: &mut Frame<'_>, area: Rect) {
    // Centred overlay sized to content.
    let w = 56u16;
    let h = HELP_LINES.len() as u16 + 4;
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    let overlay = Rect::new(x, y, w.min(area.width), h.min(area.height));

    frame.render_widget(Clear, overlay);

    let mut text: Vec<Line<'_>> = HELP_LINES
        .iter()
        .map(|(key, desc)| {
            Line::from(vec![
                Span::styled(format!("  {key:<10} "), theme::muted_style()),
                Span::styled(*desc, Style::default().fg(theme::FG)),
            ])
        })
        .collect();
    text.insert(0, Line::from(""));

    let p = Paragraph::new(text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" keybindings — press ? to close "),
        )
        .wrap(Wrap { trim: false })
        .style(theme::body_style());

    frame.render_widget(p, overlay);
}
