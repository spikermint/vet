//! Types representing detected secrets.
//!
//! The central type is [`Finding`], which contains everything needed to
//! report a secret: location, pattern info, masked secret, and confidence.
//!
//! [`FindingId`] provides stable identification across file moves and refactors,
//! enabling allowlists and baselines to track findings by content rather than location.

mod secret;
mod span;

use std::fmt;
use std::hash::{Hash, Hasher};
use std::path::Path;

use fnv::FnvHasher;
pub use secret::Secret;
use serde::{Deserialize, Serialize};
pub use span::Span;

use crate::pattern::Severity;

const FINDING_ID_LENGTH: usize = 8;

/// Indicates how likely a finding is to be a real secret versus a false positive.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// The match has sufficient entropy to likely be a real secret.
    #[default]
    High,
    /// The match may be a placeholder, example, or false positive.
    Low,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::High => write!(f, "high"),
            Self::Low => write!(f, "low"),
        }
    }
}

/// Stable identifier for a finding, based on pattern ID and secret content.
///
/// The same secret detected by the same pattern will always produce the same ID,
/// regardless of file location.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct FindingId(Box<str>);

impl FindingId {
    #[must_use]
    pub fn new(pattern_id: &str, secret: &Secret) -> Self {
        let hash = hash_finding(pattern_id, secret);
        let hex = format!("{hash:016x}");
        Self(hex[..FINDING_ID_LENGTH].into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for FindingId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for FindingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FindingId({})", self.0)
    }
}

impl fmt::Display for FindingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn hash_finding(pattern_id: &str, secret: &Secret) -> u64 {
    let mut hasher = FnvHasher::default();
    pattern_id.hash(&mut hasher);
    secret.hash_into(&mut hasher);
    hasher.finish()
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub id: FindingId,
    pub path: Box<Path>,
    pub span: Span,
    pub pattern_id: Box<str>,
    pub secret: Secret,
    pub severity: Severity,
    pub masked_line: Box<str>,
    pub confidence: Confidence,
}

impl Finding {
    #[must_use]
    pub const fn line(&self) -> u32 {
        self.span.line
    }

    #[must_use]
    pub const fn column(&self) -> u32 {
        self.span.column
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}: {} [{}]",
            self.path.display(),
            self.span.line,
            self.span.column,
            self.pattern_id,
            self.severity,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::pattern::Severity;
    use crate::test_utils::make_finding;

    #[test]
    fn confidence_defaults_to_high() {
        assert_eq!(Confidence::default(), Confidence::High);
    }

    #[test]
    fn confidence_display_formats_as_lowercase() {
        assert_eq!(format!("{}", Confidence::High), "high");
        assert_eq!(format!("{}", Confidence::Low), "low");
    }

    #[test]
    fn confidence_variants_compare_correctly() {
        assert_eq!(Confidence::High, Confidence::High);
        assert_eq!(Confidence::Low, Confidence::Low);
        assert_ne!(Confidence::High, Confidence::Low);
    }

    #[test]
    fn finding_id_is_exactly_eight_hex_characters() {
        let secret = Secret::new("test-secret");
        let id = FindingId::new("test/pattern", &secret);
        assert_eq!(id.as_str().len(), 8);
    }

    #[test]
    fn finding_id_contains_only_hex_digits() {
        let secret = Secret::new("test-secret");
        let id = FindingId::new("test/pattern", &secret);
        assert!(id.as_str().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn finding_id_is_deterministic_for_same_secret() {
        let s1 = Secret::new("same-secret");
        let s2 = Secret::new("same-secret");
        let id1 = FindingId::new("test/pattern", &s1);
        let id2 = FindingId::new("test/pattern", &s2);
        assert_eq!(id1, id2);
    }

    #[test]
    fn finding_id_differs_when_secret_content_differs() {
        let s1 = Secret::new("secret-one");
        let s2 = Secret::new("secret-two");
        let id1 = FindingId::new("test/pattern", &s1);
        let id2 = FindingId::new("test/pattern", &s2);
        assert_ne!(id1, id2);
    }

    #[test]
    fn finding_id_differs_when_pattern_id_differs() {
        let secret = Secret::new("same-secret");
        let id1 = FindingId::new("pattern/one", &secret);
        let id2 = FindingId::new("pattern/two", &secret);
        assert_ne!(id1, id2);
    }

    #[test]
    fn finding_id_as_ref_returns_same_as_as_str() {
        let secret = Secret::new("test");
        let id = FindingId::new("test/pattern", &secret);
        let s: &str = id.as_ref();
        assert_eq!(s, id.as_str());
    }

    #[test]
    fn finding_id_display_shows_hex_string() {
        let secret = Secret::new("test");
        let id = FindingId::new("test/pattern", &secret);
        assert_eq!(format!("{}", id), id.as_str());
    }

    #[test]
    fn finding_id_debug_includes_type_name_and_value() {
        let secret = Secret::new("test");
        let id = FindingId::new("test/pattern", &secret);
        let debug = format!("{:?}", id);
        assert!(debug.contains("FindingId"));
        assert!(debug.contains(id.as_str()));
    }

    #[test]
    fn finding_line_returns_span_line() {
        let finding = make_finding("test/pattern", "secret");
        assert_eq!(finding.line(), finding.span.line);
    }

    #[test]
    fn finding_column_returns_span_column() {
        let finding = make_finding("test/pattern", "secret");
        assert_eq!(finding.column(), finding.span.column);
    }

    #[test]
    fn finding_display_shows_path_location_pattern_severity() {
        let secret = Secret::new("secret");
        let finding = Finding {
            id: FindingId::new("aws/key", &secret),
            path: Path::new("src/config.rs").into(),
            span: Span::new(42, 13, 100, 120),
            pattern_id: "aws/key".into(),
            secret,
            severity: Severity::Critical,
            masked_line: "masked".into(),
            confidence: Confidence::High,
        };

        let display = format!("{}", finding);
        assert!(display.contains("src/config.rs"));
        assert!(display.contains("42:13"));
        assert!(display.contains("aws/key"));
        assert!(display.contains("critical"));
    }
}
