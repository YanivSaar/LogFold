//! Centralised colour and style constants.

use ratatui::style::{Color, Modifier, Style};

pub const CRITICAL: Color = Color::Rgb(255, 80, 72);
pub const WARNING: Color = Color::Rgb(230, 162, 40);
pub const INFO: Color = Color::Rgb(88, 166, 255);
pub const SUCCESS: Color = Color::Rgb(56, 185, 80);
pub const MUTED: Color = Color::Rgb(130, 130, 130);
pub const ACCENT: Color = Color::Rgb(121, 96, 221);
pub const FG: Color = Color::Rgb(201, 209, 217);
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
    Style::default()
        .fg(ACCENT)
        .add_modifier(Modifier::BOLD | Modifier::REVERSED)
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
