/// Calculates Shannon entropy in bits per character.
///
/// Returns a value between 0.0 (completely uniform, e.g., "AAAA")
/// and ~8.0 (maximum for byte-level analysis).
///
/// Typical thresholds:
/// - < 2.5: Very low (likely placeholder like "EXAMPLE")
/// - 2.5 - 3.5: Low (possibly real, but suspicious)
/// - 3.5 - 4.5: Medium-high (likely real secret)
/// - > 4.5: High (almost certainly random/generated)
#[must_use]
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut freq = [0u32; 256];
    #[expect(
        clippy::cast_precision_loss,
        reason = "string length fits in f64 without meaningful loss"
    )]
    let len = s.len() as f64;

    for byte in s.bytes() {
        freq[byte as usize] += 1;
    }

    freq.iter()
        .copied()
        .filter(|&count| count > 0)
        .map(|count| {
            let p = f64::from(count) / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::shannon_entropy;

    #[test]
    fn shannon_entropy_of_empty_string_is_zero() {
        assert!((shannon_entropy("") - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn shannon_entropy_of_single_char_is_zero() {
        assert!((shannon_entropy("a") - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn shannon_entropy_of_repeated_char_is_zero() {
        assert!((shannon_entropy("aaaaaaaaaa") - 0.0).abs() < f64::EPSILON);
        assert!((shannon_entropy("XXXXXXXXXXXXXXXXXXXXXXXX") - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn shannon_entropy_of_two_equal_chars_is_one_bit() {
        let entropy = shannon_entropy("abababab");
        assert!((entropy - 1.0).abs() < 0.001, "Expected ~1.0, got {entropy}");
    }

    #[test]
    fn shannon_entropy_of_four_equal_chars_is_two_bits() {
        let entropy = shannon_entropy("abcdabcdabcd");
        assert!((entropy - 2.0).abs() < 0.001, "Expected ~2.0, got {entropy}");
    }

    #[test]
    fn shannon_entropy_of_full_alphanumeric_is_near_six_bits() {
        let chars: String = ('a'..='z').chain('A'..='Z').chain('0'..='9').collect();
        let entropy = shannon_entropy(&chars);
        assert!(entropy > 5.9 && entropy < 6.0, "Expected ~5.95, got {entropy}");
    }

    #[test]
    fn shannon_entropy_of_real_aws_key_exceeds_4_bits() {
        let key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let entropy = shannon_entropy(key);
        assert!(entropy > 4.0, "Real AWS key should have entropy > 4.0, got {entropy}");
    }

    #[test]
    fn shannon_entropy_of_real_github_token_exceeds_4_bits() {
        let token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890";
        let entropy = shannon_entropy(token);
        assert!(
            entropy > 4.0,
            "Real GitHub token should have entropy > 4.0, got {entropy}"
        );
    }

    #[test]
    fn shannon_entropy_of_placeholder_xxx_is_below_2_5_bits() {
        let placeholder = "ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        let entropy = shannon_entropy(placeholder);
        assert!(entropy < 2.5, "Placeholder should have entropy < 2.5, got {entropy}");
    }

    #[test]
    fn shannon_entropy_handles_unicode_without_panic() {
        let unicode = "こんにちは世界🔐🔑";
        let entropy = shannon_entropy(unicode);
        assert!(entropy > 0.0);
    }

    #[test]
    fn shannon_entropy_counts_multibyte_chars_as_bytes() {
        let accented = "éééé";
        let entropy = shannon_entropy(accented);
        assert!(
            (entropy - 1.0).abs() < 0.001,
            "Expected ~1.0 for two-byte char, got {entropy}"
        );
    }
}
