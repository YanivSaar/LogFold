//! Help overlay — rendered when the user presses `?`.
//!
//! Grouped by section, scrollable, dynamically sized. Only lists keys
//! that are actually wired up in `App::handle_key`.

use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState};

use crate::tui::theme;

/// A help entry: a (section_header, "") marks a new group; a
/// (key, description) is a binding line. `""` for both is a spacer.
const HELP_LINES: &[(&str, &str)] = &[
    ("~Navigation", ""),
    ("1..4", "Overview / Detail / Sources / Timeline"),
    ("Tab", "Next view (or next Detail sub-tab)"),
    ("Esc", "Back to Overview from Detail; quit elsewhere"),
    ("", ""),
    ("~Overview", ""),
    ("↑ ↓ / j k", "Move selection"),
    ("g / G", "Jump to top / bottom"),
    ("n / N", "Next / previous anomaly"),
    ("Enter / →", "Open Detail for the selected pattern"),
    ("", ""),
    ("~Detail", ""),
    ("v / s / r", "Variables / Score / Raw-Lines sub-tab"),
    ("", ""),
    ("~Filter", ""),
    ("/  or  f", "Start filter (search skeleton + bundle)"),
    ("Backspace", "Edit the filter"),
    ("Enter", "Keep the filter, exit edit mode"),
    ("Esc (in filter)", "Clear and exit"),
    ("", ""),
    ("~Global", ""),
    ("m", "Toggle mouse capture"),
    ("q / Ctrl+C", "Quit"),
    ("?", "Toggle this help overlay"),
];

#[derive(Default)]
pub struct HelpState {
    pub scroll: usize,
}

impl HelpState {
    pub fn scroll_up(&mut self) {
        self.scroll = self.scroll.saturating_sub(1);
    }

    pub fn scroll_down(&mut self) {
        if self.scroll + 1 < HELP_LINES.len() {
            self.scroll += 1;
        }
    }

    pub fn reset(&mut self) {
        self.scroll = 0;
    }
}

pub fn render(frame: &mut Frame<'_>, area: Rect, state: &HelpState) {
    // Dynamic size: capped at 72 cols so wide terminals don't stretch
    // the overlay, but shrinks to the screen on narrow ones.
    let w = area.width.clamp(40, 72);
    let max_h = area.height.saturating_sub(2);
    let content_rows = HELP_LINES.len() as u16 + 2; // + title and footer
    let h = content_rows.min(max_h).max(5);
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    let overlay = Rect::new(x, y, w, h);

    frame.render_widget(Clear, overlay);

    let items: Vec<ListItem<'_>> = HELP_LINES
        .iter()
        .map(|(k, d)| {
            if let Some(section) = k.strip_prefix('~') {
                // Group heading.
                ListItem::new(Line::from(vec![Span::styled(
                    format!(" {section} "),
                    theme::header_style(),
                )]))
            } else if k.is_empty() && d.is_empty() {
                ListItem::new(Line::from(""))
            } else {
                ListItem::new(Line::from(vec![
                    Span::styled(format!("  {k:<16}"), theme::muted_style()),
                    Span::styled(*d, Style::default().fg(theme::FG)),
                ]))
            }
        })
        .collect();

    let title = format!(" keybindings — logfold v{} ", env!("CARGO_PKG_VERSION"));
    let footer = " ↑/↓ scroll · ? close ";

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::accent_border_style())
                .title(title)
                .title_bottom(footer),
        )
        .style(theme::body_style());

    let mut ls = ListState::default();
    ls.select(Some(state.scroll));
    frame.render_stateful_widget(list, overlay, &mut ls);
}
