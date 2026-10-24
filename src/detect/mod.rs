//! Format detection: load pattern bundles, score candidates against a
//! source, and decide which bundle a source should be parsed as.
//!
//! The flow for a source is:
//!
//! 1. If a path/journald-unit is available, [`probe::score_hints`] gives
//!    an immediate composite path/process score.
//! 2. If that score crosses [`probe::EARLY_WIN`], the FSM shortcuts to
//!    `Decided` without touching line content.
//! 3. Otherwise the first `probe_lines` events are run through each
//!    bundle's line_probes; the composite winner is chosen.
//! 4. Buffered events are replayed through the parse worker with the
//!    chosen bundle attached.

pub mod path_hint;
pub mod probe;
pub mod registry;

pub use registry::{Bundle, BundleId, BundleRegistry, DetectConfig, MultilineMode, SeededPattern};
