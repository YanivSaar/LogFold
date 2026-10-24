//! Pattern folding engine: the lock-free core.
//!
//! The engine owns the [`PatternRegistry`] — a sharded hash map keyed by
//! skeleton hash. The hot path (fold → upsert) is in [`registry::fold_line`].

pub mod extractor;
pub mod fuzzy;
pub mod hasher;
pub mod pattern;
pub mod registry;
pub mod scorer;

pub use pattern::{Pattern, PatternSnapshot, VarStats};
pub use registry::{PatternRegistry, UpsertOutcome};
