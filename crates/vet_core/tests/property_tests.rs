//! Property-based tests for `vet_core`.
//!
//! These tests verify invariants that should hold for all inputs,
//! catching edge cases that hand-written tests might miss.

use proptest::prelude::*;
use vet_core::prelude::*;

proptest! {
    /// Secret masking never panics and always produces output.
    #[test]
    fn secret_masking_handles_unicode(s in ".+") {
        let secret = Secret::new(&s);
        let masked = secret.as_masked();
        prop_assert!(!masked.is_empty());
    }

    /// Masked output never contains the full original secret (if long enough).
    #[test]
    fn masked_secret_hides_middle(s in ".{24,100}") {
        let secret = Secret::new(&s);
        let masked = secret.as_masked();

        prop_assert!(
            !masked.contains(&s),
            "Masked output contains full secret"
        );
    }

    /// Same secret always produces same fingerprint.
    /// Uses `\PC*` (non-control characters) to avoid control character edge cases.
    #[test]
    fn fingerprint_is_deterministic(s in "\\PC*") {
        let secret1 = Secret::new(&s);
        let secret2 = Secret::new(&s);

        prop_assert_eq!(secret1.fingerprint(), secret2.fingerprint());
    }

    /// FindingId is always 12 hex characters.
    #[test]
    fn finding_id_is_valid_hex(
        pattern_id in "[a-z]{3,10}/[a-z]{3,20}",
        secret_value in "[a-zA-Z0-9]{4,50}"
    ) {
        let secret = Secret::new(&secret_value);
        let id = FindingId::new(&pattern_id, &secret);
        let id_str = id.as_str();

        prop_assert_eq!(id_str.len(), 12);
        prop_assert!(
            id_str.chars().all(|c| c.is_ascii_hexdigit()),
            "FindingId '{}' contains non-hex characters",
            id_str
        );
    }

    /// Span returns None for invalid byte boundaries.
    #[test]
    fn span_rejects_invalid_boundaries(
        content in "[a-zA-Z0-9 \n]{1,100}",
        start in 0usize..200usize
    ) {
        let result = Span::from_byte_range(&content, start, start);

        if start <= content.len() && content.is_char_boundary(start) {
            let Some(span) = result else {
                return Err(TestCaseError::fail("expected Some for valid boundary"));
            };
            prop_assert!(span.line >= 1);
            prop_assert!(span.column >= 1);
        } else {
            prop_assert!(result.is_none());
        }
    }
}
