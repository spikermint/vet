use std::fmt;
use std::hash::{Hash, Hasher};

use fnv::FnvHasher;

/// Secrets shorter than this are fully masked.
const FULL_MASK_THRESHOLD: usize = 12;

/// Secrets at or above this length show 4-character bookends instead of 2.
const PARTIAL_MASK_THRESHOLD: usize = 24;

/// Mask for short secrets (fully hidden).
const MASK_DOTS_8: &str = "••••••••";

/// Mask for medium/long secrets (with visible bookends).
const MASK_DOTS_12: &str = "••••••••••••";

/// A secret value with no way to retrieve the original content.
///
/// At construction, the raw value is immediately:
/// 1. Hashed into a fingerprint (for stable `FindingId` generation)
/// 2. Masked for safe display (e.g., `ghp_••••••••••••Xy4z`)
/// 3. Discarded
#[derive(Clone)]
pub struct Secret {
    masked: Box<str>,
    fingerprint: u64,
}

impl Secret {
    #[must_use]
    pub fn new(raw: &str) -> Self {
        Self {
            fingerprint: hash_raw(raw),
            masked: mask_raw(raw).into(),
        }
    }

    #[must_use]
    pub fn as_masked(&self) -> &str {
        &self.masked
    }

    #[must_use]
    pub const fn fingerprint(&self) -> u64 {
        self.fingerprint
    }

    pub(crate) fn hash_into(&self, hasher: &mut impl Hasher) {
        self.fingerprint.hash(hasher);
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secret")
            .field("masked", &self.masked)
            .finish_non_exhaustive()
    }
}

fn hash_raw(raw: &str) -> u64 {
    let mut hasher = FnvHasher::default();
    raw.hash(&mut hasher);
    hasher.finish()
}

fn mask_raw(raw: &str) -> String {
    let chars: Vec<char> = raw.chars().collect();
    let char_count = chars.len();

    if char_count < FULL_MASK_THRESHOLD {
        MASK_DOTS_8.to_string()
    } else if char_count < PARTIAL_MASK_THRESHOLD {
        // Show 2-character bookends
        let prefix: String = chars[..2].iter().collect();
        let suffix: String = chars[char_count - 2..].iter().collect();
        format!("{prefix}{MASK_DOTS_8}{suffix}")
    } else {
        // Show 4-character bookends
        let prefix: String = chars[..4].iter().collect();
        let suffix: String = chars[char_count - 4..].iter().collect();
        format!("{prefix}{MASK_DOTS_12}{suffix}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_fully_hides_secrets_under_12_chars() {
        let secret = Secret::new("abc123");
        assert_eq!(secret.as_masked(), "••••••••");
    }

    #[test]
    fn mask_shows_2char_bookends_at_exactly_12_chars() {
        let secret = Secret::new("123456789012");
        assert_eq!(secret.as_masked(), "12••••••••12");
    }

    #[test]
    fn mask_shows_2char_bookends_for_12_to_23_char_secrets() {
        let secret = Secret::new("ghp_1234567890abcd");
        assert_eq!(secret.as_masked(), "gh••••••••cd");
    }

    #[test]
    fn mask_shows_4char_bookends_for_24plus_char_secrets() {
        let secret = Secret::new("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        assert_eq!(secret.as_masked(), "ghp_••••••••••••xxxx");
    }

    #[test]
    fn mask_switches_to_4char_bookends_at_exactly_24_chars() {
        let secret = Secret::new("123456789012345678901234");
        assert_eq!(secret.as_masked(), "1234••••••••••••1234");
    }

    #[test]
    fn mask_fully_hides_empty_string() {
        let secret = Secret::new("");
        assert_eq!(secret.as_masked(), "••••••••");
    }

    #[test]
    fn fingerprint_is_deterministic_for_identical_content() {
        let s1 = Secret::new("my-secret-key");
        let s2 = Secret::new("my-secret-key");
        assert_eq!(s1.fingerprint(), s2.fingerprint());
    }

    #[test]
    fn fingerprint_differs_for_different_content() {
        let s1 = Secret::new("secret-a");
        let s2 = Secret::new("secret-b");
        assert_ne!(s1.fingerprint(), s2.fingerprint());
    }

    #[test]
    fn fingerprint_preserved_after_clone() {
        let original = Secret::new("test-secret");
        let cloned = original.clone();
        assert_eq!(original.fingerprint(), cloned.fingerprint());
        assert_eq!(original.as_masked(), cloned.as_masked());
    }

    #[test]
    fn debug_impl_shows_masked_value_only() {
        let secret = Secret::new("super-secret-value");
        let debug = format!("{:?}", secret);
        assert!(!debug.contains("super-secret-value"));
        assert!(debug.contains("Secret"));
    }
}
