//! `.env` file secret detection via regex.
//!
//! `.env` files use a simple `KEY=VALUE` format with no code constructs to
//! disambiguate, so a regex suffices. No AST parsing is needed.

use std::sync::LazyLock;

use regex::Regex;

use std::sync::Arc;

use super::AstFinding;
use super::trigger::TriggerWordGroup;

/// Compiled regex for extracting `KEY=VALUE` pairs from `.env` files where the
/// key contains a trigger word and the value is at least 8 characters.
static DOTENV_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    #[expect(clippy::unwrap_used, reason = "static regex is known-valid at compile time")]
    Regex::new(r"(?m)^([A-Za-z_][A-Za-z0-9_.\-]*)\s*=\s*['\x22]?([^\s#'\x22]{8,120})['\x22]?").unwrap()
});

/// Extracts generic findings from `.env` file content.
///
/// Scans every `KEY=VALUE` line and checks whether the key contains a trigger
/// word as a segment-bounded match. Values shorter than 8 characters or
/// starting with `$` (variable references) are skipped.
pub fn extract_dotenv_findings(content: &str, trigger_groups: &[TriggerWordGroup]) -> Vec<AstFinding> {
    let mut findings = Vec::new();

    for captures in DOTENV_PATTERN.captures_iter(content) {
        let (Some(key_match), Some(value_match)) = (captures.get(1), captures.get(2)) else {
            continue;
        };

        let key = key_match.as_str();
        let value = value_match.as_str();

        if value.starts_with('$') {
            continue;
        }

        for group in trigger_groups {
            if super::trigger::matches_trigger(key, group) {
                findings.push(AstFinding {
                    pattern_id: Arc::clone(&group.pattern_id),
                    variable_name: key.to_string(),
                    secret_value: value.to_string(),
                    byte_start: value_match.start(),
                    byte_end: value_match.end(),
                });
                break;
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn password_group() -> TriggerWordGroup {
        TriggerWordGroup::from_static("generic/password-assignment", &["password", "passwd", "pwd"])
    }

    fn token_group() -> TriggerWordGroup {
        TriggerWordGroup::from_static("generic/token-assignment", &["access_token", "auth_token"])
    }

    fn groups() -> Vec<TriggerWordGroup> {
        vec![password_group(), token_group()]
    }

    #[test]
    fn detects_password_in_env_file() {
        let content = "DB_PASSWORD=a8Kj2mNx9pQ4rT7v\n";
        let findings = extract_dotenv_findings(content, &groups());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pattern_id.as_ref(), "generic/password-assignment");
        assert_eq!(findings[0].secret_value, "a8Kj2mNx9pQ4rT7v");
    }

    #[test]
    fn detects_quoted_value() {
        let content = "DB_PASSWORD=\"a8Kj2mNx9pQ4rT7v\"\n";
        let findings = extract_dotenv_findings(content, &groups());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].secret_value, "a8Kj2mNx9pQ4rT7v");
    }

    #[test]
    fn detects_single_quoted_value() {
        let content = "DB_PASSWORD='a8Kj2mNx9pQ4rT7v'\n";
        let findings = extract_dotenv_findings(content, &groups());
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn skips_variable_reference() {
        let content = "DB_PASSWORD=$VAULT_SECRET\n";
        let findings = extract_dotenv_findings(content, &groups());
        assert!(findings.is_empty());
    }

    #[test]
    fn skips_short_value() {
        let content = "DB_PASSWORD=short\n";
        let findings = extract_dotenv_findings(content, &groups());
        assert!(findings.is_empty());
    }

    #[test]
    fn skips_comment_after_value() {
        let content = "DB_PASSWORD=a8Kj2mNx9pQ4rT7v # this is a comment\n";
        let findings = extract_dotenv_findings(content, &groups());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].secret_value, "a8Kj2mNx9pQ4rT7v");
    }

    #[test]
    fn skips_lines_without_trigger_word() {
        let content = "DATABASE_URL=postgresql://localhost/mydb\n";
        let findings = extract_dotenv_findings(content, &groups());
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_access_token() {
        let content = "ACCESS_TOKEN=xK9mN2pQ4rT7vB5cW3eR8yU\n";
        let findings = extract_dotenv_findings(content, &groups());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pattern_id.as_ref(), "generic/token-assignment");
    }

    #[test]
    fn handles_multiple_entries() {
        let content = "\
DB_PASSWORD=a8Kj2mNx9pQ4rT7v
APP_KEY=not_a_trigger
AUTH_TOKEN=xK9mN2pQ4rT7vB5cW3eR8yU
";
        let findings = extract_dotenv_findings(content, &groups());
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn handles_spaces_around_equals() {
        let content = "DB_PASSWORD = a8Kj2mNx9pQ4rT7v\n";
        let findings = extract_dotenv_findings(content, &groups());
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn rejects_substring_trigger() {
        let content = "OSPASSWORD=a8Kj2mNx9pQ4rT7v\n";
        let findings = extract_dotenv_findings(content, &groups());
        assert!(findings.is_empty());
    }
}
