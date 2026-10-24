//! Fuzzy clusterer for the registry miss path.
//!
//! When a skeleton misses, we check whether a very similar skeleton
//! already exists — if so, we fold into it instead of creating a new
//! pattern. "Very similar" = token-level edit distance ≤ 2.

/// True if two skeletons differ by at most two token-level edits (replace,
/// insert, or delete). We use Levenshtein over the whitespace-split tokens
/// of each skeleton. Early-exits once the running distance exceeds 2.
pub fn is_close(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    let a_tokens: Vec<&str> = a.split_whitespace().collect();
    let b_tokens: Vec<&str> = b.split_whitespace().collect();

    // Big length delta rules out an edit distance of ≤ 2 immediately.
    let (la, lb) = (a_tokens.len(), b_tokens.len());
    if la.abs_diff(lb) > 2 {
        return false;
    }

    edit_distance_leq(a_tokens.as_slice(), b_tokens.as_slice(), 2)
}

/// Bounded token Levenshtein. Returns true if distance ≤ `max`.
///
/// Implementation: two-row dynamic programming over tokens. Early-exit if
/// the whole active row exceeds `max`.
fn edit_distance_leq(a: &[&str], b: &[&str], max: usize) -> bool {
    let max_u = max.saturating_add(1);
    let (la, lb) = (a.len(), b.len());

    let mut prev: Vec<usize> = (0..=lb).collect();
    let mut curr: Vec<usize> = vec![0; lb + 1];

    for i in 1..=la {
        curr[0] = i;
        let mut row_min = curr[0];
        for j in 1..=lb {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            let del = prev[j] + 1;
            let ins = curr[j - 1] + 1;
            let sub = prev[j - 1] + cost;
            curr[j] = del.min(ins).min(sub);
            if curr[j] < row_min {
                row_min = curr[j];
            }
        }
        if row_min >= max_u {
            return false;
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[lb] <= max
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_is_close() {
        assert!(is_close(
            "Failed password for {USER}",
            "Failed password for {USER}"
        ));
    }

    #[test]
    fn one_token_differs_is_close() {
        assert!(is_close(
            "Failed password for {USER} from {IP}",
            "Failed password for {USER} from {WORD}"
        ));
    }

    #[test]
    fn two_tokens_differ_is_close() {
        assert!(is_close(
            "Failed password for {USER} from {IP} port {NUM}",
            "Failed password for {USER} from {WORD} port {WORD}"
        ));
    }

    #[test]
    fn three_tokens_differ_is_not_close() {
        assert!(!is_close(
            "Failed password for {USER} from {IP} port {NUM}",
            "Accepted key for {WORD} from {WORD} port {WORD}"
        ));
    }

    #[test]
    fn length_delta_three_rejected() {
        assert!(!is_close("a b c", "a b c d e f"));
    }
}
