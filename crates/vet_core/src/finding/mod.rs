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
use std::path::Path;
use std::sync::Arc;

pub use secret::Secret;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub use span::Span;

use crate::baseline::Fingerprint;
use crate::pattern::Severity;

const FINDING_ID_LENGTH: usize = 12;
const FINDING_ID_BYTES: usize = FINDING_ID_LENGTH / 2;

/// Indicates how likely a finding is to be a real secret versus a false positive.
///
/// Variants are ordered by confidence level (`Low < High`) so that filtering
/// can use a simple `>=` comparison against a minimum threshold.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// The match may be a placeholder, example, or false positive.
    Low,
    /// The match has sufficient entropy to likely be a real secret.
    #[default]
    High,
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
    /// Creates a new finding ID by hashing the pattern ID and secret content.
    #[must_use]
    pub fn new(pattern_id: &str, secret: &Secret) -> Self {
        let hash_bytes = compute_id_hash(pattern_id, secret);
        let hex = bytes_to_hex(&hash_bytes);
        Self(hex.into())
    }

    /// Returns the hex string representation of this ID.
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

fn compute_id_hash(pattern_id: &str, secret: &Secret) -> [u8; FINDING_ID_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(pattern_id.as_bytes());
    hasher.update(secret.fingerprint().to_le_bytes());
    let hash = hasher.finalize();
    #[expect(
        clippy::expect_used,
        reason = "SHA-256 always produces 32 bytes; slicing first 6 is infallible"
    )]
    hash[..FINDING_ID_BYTES].try_into().expect("SHA-256 produces 32 bytes")
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// A single detected secret in a source file.
///
/// Contains everything needed to report the finding: the matched secret
/// (masked), its source location, the pattern that triggered, and a
/// confidence level indicating whether it is likely a true positive.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Stable identifier derived from the pattern ID and secret content.
    pub id: FindingId,
    /// Path to the file where the secret was found.
    pub path: Box<Path>,
    /// Line, column, and byte offsets of the match.
    pub span: Span,
    /// Identifier of the pattern that matched (e.g. `"aws/access-key"`).
    pub pattern_id: Arc<str>,
    /// The matched secret, hashed and masked for safe handling.
    pub secret: Secret,
    /// Severity inherited from the matching pattern.
    pub severity: Severity,
    /// The source line with the secret replaced by a masked placeholder.
    pub masked_line: Box<str>,
    /// Whether the match is likely a real secret or a potential false positive.
    pub confidence: Confidence,
}

impl Finding {
    /// Returns the 1-indexed line number of the match.
    #[must_use]
    pub const fn line(&self) -> u32 {
        self.span.line
    }

    /// Returns the 1-indexed column number of the match.
    #[must_use]
    pub const fn column(&self) -> u32 {
        self.span.column
    }

    /// Computes a `Fingerprint` suitable for baseline tracking.
    ///
    /// The fingerprint is derived from the pattern ID, file path, and
    /// secret hash - so it remains stable across whitespace changes but
    /// changes if the file is renamed.
    #[must_use]
    pub fn baseline_fingerprint(&self) -> Fingerprint {
        Fingerprint::calculate(&self.pattern_id, &self.path, self.secret.hash_hex())
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
    use super::*;
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
        assert!(Confidence::Low < Confidence::High);
    }

    #[test]
    fn finding_id_is_exactly_twelve_hex_characters() {
        let secret = Secret::new("test-secret");
        let id = FindingId::new("test/pattern", &secret);
        assert_eq!(id.as_str().len(), 12);
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
        assert_eq!(format!("{id}"), id.as_str());
    }

    #[test]
    fn finding_id_debug_includes_type_name_and_value() {
        let secret = Secret::new("test");
        let id = FindingId::new("test/pattern", &secret);
        let debug = format!("{id:?}");
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

        let display = format!("{finding}");
        assert!(display.contains("src/config.rs"));
        assert!(display.contains("42:13"));
        assert!(display.contains("aws/key"));
        assert!(display.contains("critical"));
    }

    #[test]
    fn baseline_fingerprint_is_deterministic() {
        let secret = Secret::new("test-secret");
        let finding = Finding {
            id: FindingId::new("test/pattern", &secret),
            path: Path::new("test.txt").into(),
            span: Span::new(1, 1, 0, 10),
            pattern_id: "test/pattern".into(),
            secret: secret.clone(),
            severity: Severity::High,
            masked_line: "masked".into(),
            confidence: Confidence::High,
        };

        let fp1 = finding.baseline_fingerprint();
        let fp2 = finding.baseline_fingerprint();

        assert_eq!(fp1.as_str(), fp2.as_str());
    }

    #[test]
    fn baseline_fingerprint_differs_for_different_files() {
        let secret = Secret::new("same-secret");
        let finding1 = Finding {
            id: FindingId::new("test/pattern", &secret),
            path: Path::new("file1.txt").into(),
            span: Span::new(1, 1, 0, 10),
            pattern_id: "test/pattern".into(),
            secret: secret.clone(),
            severity: Severity::High,
            masked_line: "masked".into(),
            confidence: Confidence::High,
        };

        let finding2 = Finding {
            id: FindingId::new("test/pattern", &secret),
            path: Path::new("file2.txt").into(),
            span: Span::new(1, 1, 0, 10),
            pattern_id: "test/pattern".into(),
            secret: secret.clone(),
            severity: Severity::High,
            masked_line: "masked".into(),
            confidence: Confidence::High,
        };

        assert_ne!(
            finding1.baseline_fingerprint().as_str(),
            finding2.baseline_fingerprint().as_str()
        );
    }
}
