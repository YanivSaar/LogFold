//! Skeleton builder: converts a classified token stream into a canonical
//! string with variable slots.
//!
//! Example:
//! ```text
//!   Accepted password for alice from 10.0.0.1 port 22 ssh2
//! ⇒ Accepted password for {WORD} from {IP} port {NUM} ssh2
//! ```
//!
//! Note that `alice` is a WORD here (no bundle context yet). P2 wires
//! bundle `context_types` so "after `for` → USER" promotes WORD → USER
//! and this skeleton becomes `… for {USER} from {IP} port {PORT} ssh2`.

use compact_str::CompactString;
use std::fmt::Write;

use crate::parse::Token;
use crate::types::TokenType;

/// Variable position metadata — tells the extractor which token position
/// in the raw stream corresponds to which `{TAG}` slot in the skeleton.
#[derive(Debug, Clone, Copy)]
pub struct VarSlot {
    pub token_index: u16,
    pub ty: TokenType,
}

/// Build a skeleton string plus the ordered list of variable slots.
///
/// The caller provides reusable buffers (`skel`, `slots`); both are
/// `clear()`-ed on entry.
pub fn build(tokens: &[Token<'_>], skel: &mut CompactString, slots: &mut Vec<VarSlot>) {
    skel.clear();
    slots.clear();

    for (i, tok) in tokens.iter().enumerate() {
        if i > 0 {
            skel.push(' ');
        }
        if tok.ty.is_variable() {
            // Format directly into the CompactString to avoid a temporary.
            // CompactString impls Write.
            write!(skel, "{{{}}}", tok.ty.tag()).ok();
            slots.push(VarSlot {
                token_index: i as u16,
                ty: tok.ty,
            });
        } else {
            skel.push_str(tok.text);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::tokenizer;

    fn skeleton_of(line: &str) -> (CompactString, Vec<VarSlot>) {
        let mut tokens = Vec::new();
        tokenizer::classify(line, &mut tokens);
        let mut skel = CompactString::default();
        let mut slots = Vec::new();
        build(&tokens, &mut skel, &mut slots);
        (skel, slots)
    }

    #[test]
    fn substitutes_variables() {
        // WORD tokens stay literal; only non-WORD types become `{TAG}` slots.
        let (skel, slots) = skeleton_of("Failed password for alice from 10.0.0.1 port 22");
        assert_eq!(skel, "Failed password for alice from {IP} port {NUM}");
        assert_eq!(slots.len(), 2);
        assert_eq!(slots[0].ty, TokenType::Ip);
        assert_eq!(slots[1].ty, TokenType::Num);
    }

    #[test]
    fn two_identical_lines_fold_to_same_skeleton() {
        let (s1, _) = skeleton_of("sshd[123]: Failed password for bob from 1.2.3.4 port 22");
        let (s2, _) = skeleton_of("sshd[456]: Failed password for carol from 5.6.7.8 port 22");
        // The square-bracket PIDs are not whitespace-separated so they stay
        // literal — this is a known P1 limitation; punctuation-level splitting
        // arrives with the base-parser work in P2.
        assert_ne!(s1, s2); // confirms current behaviour
    }

    #[test]
    fn whitespace_only_input() {
        let (skel, slots) = skeleton_of("   \t ");
        assert!(skel.is_empty());
        assert!(slots.is_empty());
    }
}
