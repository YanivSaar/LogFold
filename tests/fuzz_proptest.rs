//! v0.12 audit: property tests on the parse hot path.
//!
//! Goal: no panic, no infinite loop, no allocation blow-up on
//! arbitrary byte input. The tokeniser and skeleton builder are
//! supposed to be total functions over `&str`, so proptest just
//! throws a lot of weird strings at them and asserts they survive.

use compact_str::CompactString;
use proptest::prelude::*;

use logfold::parse::{skeleton, tokenizer, Token};

proptest! {
    #![proptest_config(ProptestConfig {
        // Lots of cases but each one is cheap; keep runtime under a few seconds.
        cases: 2048,
        .. ProptestConfig::default()
    })]

    #[test]
    fn tokenizer_never_panics_on_any_utf8(s in "\\PC{0,4096}") {
        let mut buf = Vec::new();
        tokenizer::classify(&s, &mut buf);
        // Weak postcondition: every emitted token has a non-empty text.
        for t in &buf {
            prop_assert!(!t.text.is_empty());
        }
    }

    #[test]
    fn skeleton_build_is_total(s in "\\PC{0,4096}") {
        let mut tokens = Vec::new();
        tokenizer::classify(&s, &mut tokens);
        let mut skel = CompactString::default();
        let mut slots = Vec::new();
        skeleton::build(&tokens, &mut skel, &mut slots);
        // Weak postcondition: slot count never exceeds token count.
        prop_assert!(slots.len() <= tokens.len());
    }

    #[test]
    fn tokenizer_output_is_deterministic(s in "\\PC{0,2048}") {
        let mut a = Vec::new();
        let mut b = Vec::new();
        tokenizer::classify(&s, &mut a);
        tokenizer::classify(&s, &mut b);
        prop_assert_eq!(a.len(), b.len());
        for (ta, tb) in a.iter().zip(b.iter()) {
            prop_assert_eq!(ta.ty, tb.ty);
            prop_assert_eq!(ta.text, tb.text);
        }
    }

    #[test]
    fn skeleton_build_is_deterministic(s in "\\PC{0,2048}") {
        let mut t1: Vec<Token<'_>> = Vec::new();
        let mut t2: Vec<Token<'_>> = Vec::new();
        tokenizer::classify(&s, &mut t1);
        tokenizer::classify(&s, &mut t2);
        let mut s1 = CompactString::default();
        let mut s2 = CompactString::default();
        let mut sl1 = Vec::new();
        let mut sl2 = Vec::new();
        skeleton::build(&t1, &mut s1, &mut sl1);
        skeleton::build(&t2, &mut s2, &mut sl2);
        prop_assert_eq!(s1, s2);
        prop_assert_eq!(sl1.len(), sl2.len());
    }

    #[test]
    fn syslog_parser_never_panics(s in "\\PC{0,4096}") {
        let _ = logfold::parse::formats::syslog::parse(&s);
    }

    #[test]
    fn json_parser_never_panics(s in "\\PC{0,4096}") {
        let _ = logfold::parse::formats::json::parse(&s);
    }

    #[test]
    fn kv_parser_never_panics(s in "\\PC{0,4096}") {
        let _ = logfold::parse::formats::kv::parse(&s);
    }

    #[test]
    fn cef_parser_never_panics(s in "\\PC{0,4096}") {
        let _ = logfold::parse::formats::cef::parse(&s);
    }

    #[test]
    fn leef_parser_never_panics(s in "\\PC{0,4096}") {
        let _ = logfold::parse::formats::leef::parse(&s);
    }
}
