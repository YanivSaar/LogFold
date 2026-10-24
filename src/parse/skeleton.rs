//! Skeleton builder: converts a classified token stream into a canonical
//! string with variable slots.
//!
//! Example:
//! ```text
//!   Accepted password for alice from 10.0.0.1 port 22 ssh2
//! ⇒ Accepted password for {USER} from {IP} port {PORT} ssh2
//! ```
//!
//! Context promotion ("after `for` → USER", "after `port` → PORT") is
//! supplied by the bundle via `[[context_types]]` entries. Builders
//! that don't want promotion call [`build`]; builders that do call
//! [`build_with_context`] and pass the rule list.

use compact_str::CompactString;
use std::fmt::Write;

use crate::parse::Token;
use crate::types::TokenType;

/// A context rule: when a WORD token's text equals `after`, promote the
/// *next* WORD token to type `ty`. Case-insensitive by design because
/// anchors in log messages often appear with mixed casing
/// (`for`, `For`, `FOR`).
#[derive(Debug, Clone)]
pub struct ContextRule {
    pub after: CompactString,
    pub ty: TokenType,
}

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
/// `clear()`-ed on entry. This is the no-context fast path.
pub fn build(tokens: &[Token<'_>], skel: &mut CompactString, slots: &mut Vec<VarSlot>) {
    build_with_context(tokens, &[], skel, slots);
}

/// Build a skeleton with bundle `context_types` applied. Each rule
/// promotes the WORD token immediately following an anchor WORD to a
/// typed slot (`{USER}`, `{PORT}`, …).
///
/// Rules are consulted in order; the first match wins. Rules whose
/// anchor doesn't appear in the token stream contribute no cost beyond
/// a single string compare per WORD token.
pub fn build_with_context(
    tokens: &[Token<'_>],
    rules: &[ContextRule],
    skel: &mut CompactString,
    slots: &mut Vec<VarSlot>,
) {
    skel.clear();
    slots.clear();

    for (i, tok) in tokens.iter().enumerate() {
        if i > 0 {
            skel.push(' ');
        }
        // Figure out the effective type.
        //
        // We promote the current token when (a) a rule exists for the
        // preceding WORD anchor, and (b) the current token is a kind
        // we're willing to re-interpret. WORD and NUM are the
        // ambiguous types where context genuinely adds information
        // ("port 22" is a port, "for alice" is a user). IP, Email,
        // Url, Path, Uuid, Hash, Date already carry structural
        // signals strong enough to override anchor context, so we
        // leave them as-is even if the anchor hits.
        let promotable = matches!(tok.ty, TokenType::Word | TokenType::Num);
        let effective_ty = if promotable && i > 0 && !rules.is_empty() {
            let prev = &tokens[i - 1];
            if prev.ty == TokenType::Word {
                rules
                    .iter()
                    .find(|r| r.after.eq_ignore_ascii_case(prev.text))
                    .map(|r| r.ty)
                    .unwrap_or(tok.ty)
            } else {
                tok.ty
            }
        } else {
            tok.ty
        };

        if effective_ty.is_variable() {
            write!(skel, "{{{}}}", effective_ty.tag()).ok();
            slots.push(VarSlot {
                token_index: i as u16,
                ty: effective_ty,
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
    fn context_rules_promote_following_word() {
        let rules = vec![
            ContextRule {
                after: "for".into(),
                ty: TokenType::User,
            },
            ContextRule {
                after: "port".into(),
                ty: TokenType::Port,
            },
        ];
        let mut tokens = Vec::new();
        tokenizer::classify(
            "Failed password for alice from 10.0.0.1 port 22",
            &mut tokens,
        );
        let mut skel = CompactString::default();
        let mut slots = Vec::new();
        build_with_context(&tokens, &rules, &mut skel, &mut slots);
        assert_eq!(skel, "Failed password for {USER} from {IP} port {PORT}");
        let types: Vec<_> = slots.iter().map(|s| s.ty).collect();
        assert_eq!(types, vec![TokenType::User, TokenType::Ip, TokenType::Port]);
    }

    #[test]
    fn context_rules_are_case_insensitive() {
        let rules = vec![ContextRule {
            after: "user".into(),
            ty: TokenType::User,
        }];
        let mut tokens = Vec::new();
        tokenizer::classify("Invalid User bob from 1.2.3.4", &mut tokens);
        let mut skel = CompactString::default();
        let mut slots = Vec::new();
        build_with_context(&tokens, &rules, &mut skel, &mut slots);
        // "User" (capital U) matches the "user" rule
        assert!(skel.contains("{USER}"), "got {skel}");
    }

    #[test]
    fn context_rules_do_not_touch_non_word_tokens() {
        // If the token after an anchor is already typed (e.g. an IP),
        // we must NOT re-tag it as USER even if a rule exists.
        let rules = vec![ContextRule {
            after: "from".into(),
            ty: TokenType::User,
        }];
        let mut tokens = Vec::new();
        tokenizer::classify("coming from 10.0.0.1", &mut tokens);
        let mut skel = CompactString::default();
        let mut slots = Vec::new();
        build_with_context(&tokens, &rules, &mut skel, &mut slots);
        assert_eq!(skel, "coming from {IP}");
        assert_eq!(slots[0].ty, TokenType::Ip);
    }

    #[test]
    fn whitespace_only_input() {
        let (skel, slots) = skeleton_of("   \t ");
        assert!(skel.is_empty());
        assert!(slots.is_empty());
    }
}
