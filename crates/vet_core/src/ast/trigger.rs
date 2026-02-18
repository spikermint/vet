//! Trigger word matching with segment boundary enforcement.
//!
//! Trigger words must appear as complete segments within variable names,
//! separated by `_`, `.`, `-`, a case boundary, or at the start/end of the
//! identifier. Case boundaries include both camelCase (`dbPassword`) and
//! acronym-prefixed names (`DBPassword`, `HTTPSecret`). For example,
//! `DB_PASSWORD`, `dbPassword`, and `DBPassword` all match the `password`
//! trigger, but `passport` does not.
//!
//! Without boundaries, short trigger words produce false positives on
//! unrelated variable names: `token` matches `tokenizer`, `secret` matches
//! `secretary`, `key` matches `keyboard`/`monkey`/`turkey`, etc. Boundary
//! enforcement ensures we only match when the trigger word appears as a
//! distinct segment in the identifier.

use std::sync::Arc;

/// A group of trigger words that share a common generic pattern.
#[derive(Debug, Clone)]
pub struct TriggerWordGroup {
    /// Pattern ID for findings produced by this trigger group.
    pub pattern_id: Arc<str>,
    /// Words that activate this pattern when found in a variable name.
    pub words: Box<[Box<str>]>,
}

impl TriggerWordGroup {
    /// Creates a trigger word group from static string slices.
    #[must_use]
    pub fn from_static(pattern_id: &str, words: &[&str]) -> Self {
        Self {
            pattern_id: Arc::from(pattern_id),
            words: words.iter().map(|&w| Box::from(w)).collect(),
        }
    }
}

/// Checks whether any trigger word from the group appears as a segment-bounded
/// match within the given variable name.
///
/// A segment boundary is `_`, `.`, `-`, a case boundary, or the start/end of
/// the string. The comparison is case-insensitive.
///
/// # Examples
///
/// - `DB_PASSWORD` matches trigger `password` (preceded by `_`)
/// - `dbPassword` matches trigger `password` (case boundary: lowercase → uppercase)
/// - `DBPassword` matches trigger `password` (case boundary: acronym → word)
/// - `passport` does **not** match (no boundary before `password`)
/// - `password` matches (at start and end)
/// - `api.password.value` matches (bounded by `.`)
#[must_use]
pub fn matches_trigger(name: &str, group: &TriggerWordGroup) -> bool {
    let lower = name.to_ascii_lowercase();
    group
        .words
        .iter()
        .any(|word| contains_as_segment(&lower, name.as_bytes(), word))
}

fn is_delimiter(b: u8) -> bool {
    matches!(b, b'_' | b'.' | b'-')
}

/// Returns `true` if position `idx` starts a new word based on a case transition.
///
/// ```text
/// dbPassword    →  boundary at P  (lowercase 'b' then uppercase 'P')
/// DBPassword    →  boundary at P  (uppercase 'B' then uppercase 'P' followed by lowercase 'a')
/// HTTPSecret    →  boundary at S
/// DB            →  no boundary (all uppercase, no lowercase follower)
/// ```
///
/// Works on the original (non-lowered) bytes so case information is preserved.
fn is_case_boundary(original: &[u8], idx: usize) -> bool {
    if idx == 0 || !original[idx].is_ascii_uppercase() {
        return false;
    }

    let prev = original[idx - 1];

    // "db|Password" - lowercase followed by uppercase always starts a new word
    if prev.is_ascii_lowercase() {
        return true;
    }

    // "DB|Password" - inside a run of uppercase letters, a new word starts
    // when the current uppercase letter is followed by a lowercase letter
    // (i.e. it's the first letter of a word, not the middle of an acronym)
    prev.is_ascii_uppercase() && original.get(idx + 1).is_some_and(u8::is_ascii_lowercase)
}

fn is_segment_start(lowered: &[u8], original: &[u8], idx: usize) -> bool {
    idx == 0 || is_delimiter(lowered[idx - 1]) || is_case_boundary(original, idx)
}

fn is_segment_end(lowered: &[u8], original: &[u8], idx: usize) -> bool {
    idx == lowered.len() || is_delimiter(lowered[idx]) || is_case_boundary(original, idx)
}

fn contains_as_segment(haystack: &str, original: &[u8], needle: &str) -> bool {
    let haystack_bytes = haystack.as_bytes();
    let needle_len = needle.len();

    if needle_len > haystack_bytes.len() {
        return false;
    }

    let mut pos = 0;
    while pos + needle_len <= haystack_bytes.len() {
        if let Some(idx) = find_substr(&haystack_bytes[pos..], needle.as_bytes()) {
            let abs_idx = pos + idx;
            let end_pos = abs_idx + needle_len;

            if is_segment_start(haystack_bytes, original, abs_idx) && is_segment_end(haystack_bytes, original, end_pos)
            {
                return true;
            }
            pos = abs_idx + 1;
        } else {
            break;
        }
    }

    false
}

fn find_substr(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn password_group() -> TriggerWordGroup {
        TriggerWordGroup::from_static("generic/password-assignment", &["password", "passwd", "pwd"])
    }

    fn api_key_group() -> TriggerWordGroup {
        TriggerWordGroup::from_static(
            "generic/api-key-assignment",
            &["api_key", "apikey", "api-key", "api.key"],
        )
    }

    #[test]
    fn matches_trigger_word_at_start() {
        assert!(matches_trigger("password", &password_group()));
    }

    #[test]
    fn matches_trigger_word_with_underscore_prefix() {
        assert!(matches_trigger("DB_PASSWORD", &password_group()));
    }

    #[test]
    fn matches_trigger_word_with_dot_prefix() {
        assert!(matches_trigger("config.password", &password_group()));
    }

    #[test]
    fn matches_trigger_word_with_suffix() {
        assert!(matches_trigger("password_hash", &password_group()));
    }

    #[test]
    fn matches_trigger_word_with_prefix_and_suffix() {
        assert!(matches_trigger("db_password_encrypted", &password_group()));
    }

    #[test]
    fn rejects_trigger_word_as_substring() {
        assert!(!matches_trigger("ospassword", &password_group()));
    }

    #[test]
    fn rejects_trigger_word_embedded_without_boundary() {
        assert!(!matches_trigger("mypasswordvalue", &password_group()));
    }

    #[test]
    fn matches_case_insensitively() {
        assert!(matches_trigger("DB_PASSWORD", &password_group()));
        assert!(matches_trigger("Db_Password", &password_group()));
    }

    #[test]
    fn matches_passwd_variant() {
        assert!(matches_trigger("db_passwd", &password_group()));
    }

    #[test]
    fn matches_pwd_variant() {
        assert!(matches_trigger("admin_pwd", &password_group()));
    }

    #[test]
    fn matches_compound_trigger_with_underscore() {
        assert!(matches_trigger("MY_API_KEY", &api_key_group()));
    }

    #[test]
    fn matches_compound_trigger_with_dash() {
        assert!(matches_trigger("my-api-key", &api_key_group()));
    }

    #[test]
    fn matches_compound_trigger_with_dot() {
        assert!(matches_trigger("config.api.key", &api_key_group()));
    }

    #[test]
    fn matches_apikey_no_separator() {
        assert!(matches_trigger("apikey", &api_key_group()));
    }

    #[test]
    fn matches_camel_case_suffix() {
        assert!(matches_trigger("dbPassword", &password_group()));
    }

    #[test]
    fn matches_camel_case_middle() {
        assert!(matches_trigger("myPasswordHash", &password_group()));
    }

    #[test]
    fn matches_camel_case_start() {
        assert!(matches_trigger("PasswordHash", &password_group()));
    }

    #[test]
    fn matches_abbreviation_prefix() {
        assert!(matches_trigger("DBPassword", &password_group()));
    }

    #[test]
    fn matches_abbreviation_prefix_with_secret() {
        let group = TriggerWordGroup::from_static("generic/secret-assignment", &["secret"]);
        assert!(matches_trigger("HTTPSecret", &group));
    }

    #[test]
    fn matches_abbreviation_prefix_with_api_key() {
        assert!(matches_trigger("AWSApikey", &api_key_group()));
    }

    #[test]
    fn rejects_camel_case_without_boundary() {
        assert!(!matches_trigger("Passport", &password_group()));
    }

    #[test]
    fn rejects_empty_name() {
        assert!(!matches_trigger("", &password_group()));
    }
}
