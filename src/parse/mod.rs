//! Lexical analysis: raw log line → token stream → skeleton.
//!
//! The hot path for a line is:
//!
//! ```text
//!     tokenizer::classify(line, &mut tokens)
//!   → skeleton::build(&tokens, &mut skel)
//!   → engine::hasher::fnv1a(skel.as_bytes())
//! ```
//!
//! Both buffers are expected to be re-used per thread (TLS scratch) — see
//! `engine::worker` for the typical reuse pattern.

pub mod formats;
pub mod skeleton;
pub mod tokenizer;

use crate::types::TokenType;

/// A classified lexical token referencing the original line.
///
/// Keeping `text` as a borrow lets the hot path tokenize without allocating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token<'a> {
    pub ty: TokenType,
    pub text: &'a str,
}
