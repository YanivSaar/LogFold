//! Ratatui-based TUI.
//!
//! Compiled only with the `tui` feature. The entry point [`run`] takes
//! ownership of the terminal, draws until the user quits, and returns.
//!
//! The TUI reads from a [`PatternRegistry`] snapshot — it never writes
//! to it, so the ingest and TUI loops are decoupled.

#[cfg(feature = "tui")]
pub mod app;
#[cfg(feature = "tui")]
pub mod format;
#[cfg(feature = "tui")]
pub mod theme;
#[cfg(feature = "tui")]
pub mod views;
#[cfg(feature = "tui")]
pub mod widgets;

#[cfg(feature = "tui")]
pub use app::run;

#[cfg(not(feature = "tui"))]
pub fn run(
    _: &crate::engine::registry::PatternRegistry,
    _: &[crate::ingest::source::SourceReport],
) -> color_eyre::eyre::Result<()> {
    color_eyre::eyre::bail!("logfold was built without the `tui` feature")
}
