//! Centralised colour and style constants.

use ratatui::style::{Color, Modifier, Style};

// Palette rebuilt for high contrast on dark terminals. The old
// values were close to Github dark but tested poorly on terminals
// that render RGB slightly dim — scores and badges blended into
// the background. These are brighter, less saturated, and legible
// even on terminals that quantise RGB to the ANSI 256 palette.
pub const CRITICAL: Color = Color::Rgb(255, 100, 100);
pub const WARNING: Color = Color::Rgb(255, 190, 80);
pub const INFO: Color = Color::Rgb(130, 190, 255);
pub const SUCCESS: Color = Color::Rgb(120, 220, 120);
pub const MUTED: Color = Color::Rgb(170, 170, 170);
pub const ACCENT: Color = Color::Rgb(160, 140, 255);
pub const FG: Color = Color::Rgb(230, 235, 245);
pub const BG: Color = Color::Rgb(13, 17, 23);

pub fn score_color(score: u32) -> Color {
    match score {
        80..=100 => CRITICAL,
        50..=79 => WARNING,
        20..=49 => INFO,
        _ => MUTED,
    }
}

pub fn badge_style(label: &str) -> Style {
    let (fg, bg) = match label {
        "NEW" => (Color::Black, CRITICAL),
        "RARE" | "SPIKE" => (Color::Black, WARNING),
        "CROSS" => (Color::Black, ACCENT),
        "FOLD" => (SUCCESS, BG),
        "NORM" => (MUTED, BG),
        _ => (FG, BG),
    };
    Style::default().fg(fg).bg(bg).add_modifier(Modifier::BOLD)
}

pub fn header_style() -> Style {
    // Explicit fg + bg rather than REVERSED: terminals that interpret
    // REVERSED as "swap current fg/bg" lose the ACCENT colour entirely
    // and end up with whatever the terminal's default bg happens to
    // be behind text — unreadable on themes with a transparent bg.
    Style::default()
        .fg(Color::Rgb(20, 20, 30))
        .bg(ACCENT)
        .add_modifier(Modifier::BOLD)
}

pub fn body_style() -> Style {
    Style::default().fg(FG).bg(BG)
}

pub fn muted_style() -> Style {
    Style::default().fg(MUTED)
}

pub fn selected_style() -> Style {
    Style::default()
        .fg(FG)
        .bg(ACCENT)
        .add_modifier(Modifier::BOLD)
}

pub fn accent_border_style() -> Style {
    Style::default().fg(ACCENT)
}

pub fn accent_style() -> Style {
    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
}
