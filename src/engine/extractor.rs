//! Variable extraction: given a pattern and the raw token stream of a
//! matching line, update each `VarStats` entry with the concrete value
//! that occupies its slot.

use crate::engine::pattern::Pattern;
use crate::parse::skeleton::VarSlot;
use crate::parse::Token;

pub fn ingest(pattern: &Pattern, slots: &[VarSlot], tokens: &[Token<'_>]) {
    if slots.is_empty() {
        return;
    }
    let mut vars = pattern.vars.lock();
    for (slot, var) in slots.iter().zip(vars.iter_mut()) {
        let idx = slot.token_index as usize;
        if let Some(tok) = tokens.get(idx) {
            var.observe(tok.text);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::pattern::Pattern;
    use crate::parse::{skeleton, tokenizer};
    use compact_str::CompactString;

    #[test]
    fn captures_variable_values() {
        let line = "Failed password for alice from 10.0.0.1 port 22";
        let mut tokens = Vec::new();
        tokenizer::classify(line, &mut tokens);
        let mut skel = CompactString::default();
        let mut slots = Vec::new();
        skeleton::build(&tokens, &mut skel, &mut slots);

        let pat = Pattern::new(1, skel, "unknown".into(), &slots);
        ingest(&pat, &slots, &tokens);
        ingest(&pat, &slots, &tokens);

        let vars = pat.vars.lock();
        // WORD tokens are anchors, so slots are: 0 = "10.0.0.1" (IP), 1 = "22" (NUM).
        assert_eq!(vars[0].total, 2);
        assert_eq!(vars[0].exact.as_ref().unwrap().len(), 1);
        let top = vars[0].top();
        assert_eq!(top[0].0.as_str(), "10.0.0.1");
    }
}
