//! FNV-1a 64-bit hash. Used to key the pattern registry by skeleton.
//!
//! We don't need cryptographic strength; we need deterministic, zero-alloc,
//! and sub-nanosecond. FNV-1a fits.

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;

#[inline]
pub fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h = FNV_OFFSET;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_offset() {
        assert_eq!(fnv1a(b""), FNV_OFFSET);
    }

    #[test]
    fn is_deterministic() {
        assert_eq!(fnv1a(b"the quick brown fox"), fnv1a(b"the quick brown fox"));
    }

    #[test]
    fn distinguishes_inputs() {
        assert_ne!(fnv1a(b"foo"), fnv1a(b"bar"));
        assert_ne!(fnv1a(b"a"), fnv1a(b"b"));
    }

    #[test]
    fn length_sensitive() {
        assert_ne!(fnv1a(b"ab"), fnv1a(b"abc"));
    }
}
