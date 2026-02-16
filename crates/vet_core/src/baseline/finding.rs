use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::fingerprint::Fingerprint;
use crate::Severity;

/// Review outcome for a baseline finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BaselineStatus {
    /// The finding was reviewed and accepted as a known secret.
    Accepted,
    /// The finding was reviewed and marked to be ignored (false positive, etc.).
    Ignored,
}

impl std::fmt::Display for BaselineStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Accepted => write!(f, "accepted"),
            Self::Ignored => write!(f, "ignored"),
        }
    }
}

/// A single acknowledged finding stored in a [`Baseline`](super::Baseline).
///
/// Records the fingerprint, review status, and enough context to display
/// a summary without needing to re-scan the original file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineFinding {
    /// Stable identifier derived from pattern ID, file path, and secret hash.
    pub fingerprint: Fingerprint,

    /// Pattern that originally matched (e.g. `"aws/access-key"`).
    pub pattern_id: String,

    /// Severity of the finding at the time it was reviewed.
    pub severity: Severity,

    /// File path where the finding was detected.
    pub file: String,

    /// SHA-256 hash of the matched secret value.
    pub secret_hash: String,

    /// Whether the finding was accepted or ignored.
    pub status: BaselineStatus,

    /// Human-readable justification provided during review.
    pub reason: String,

    /// Timestamp when the finding was reviewed.
    #[serde(with = "chrono::serde::ts_seconds")]
    pub reviewed_at: DateTime<Utc>,
}

impl BaselineFinding {
    /// Creates a new finding with `reviewed_at` set to the current time.
    #[must_use]
    pub fn new(
        fingerprint: Fingerprint,
        pattern_id: String,
        severity: Severity,
        file: String,
        secret_hash: String,
        status: BaselineStatus,
        reason: String,
    ) -> Self {
        Self {
            fingerprint,
            pattern_id,
            severity,
            file,
            secret_hash,
            status,
            reason,
            reviewed_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_finding_with_current_timestamp() {
        let before = Utc::now();
        let finding = BaselineFinding::new(
            Fingerprint::from_string("sha256:abc123"),
            "test/pattern".to_string(),
            Severity::High,
            "test.py".to_string(),
            "sha256:secret".to_string(),
            BaselineStatus::Accepted,
            "Test reason".to_string(),
        );
        let after = Utc::now();

        assert!(finding.reviewed_at >= before);
        assert!(finding.reviewed_at <= after);
    }

    #[test]
    fn fingerprint_field_is_fingerprint_type() {
        let finding = BaselineFinding::new(
            Fingerprint::from_string("sha256:test"),
            "test".to_string(),
            Severity::High,
            "test.py".to_string(),
            "sha256:secret".to_string(),
            BaselineStatus::Accepted,
            "test".to_string(),
        );

        assert_eq!(finding.fingerprint.as_str(), "sha256:test");
    }

    #[test]
    fn status_serializes_to_lowercase() {
        let json_accepted = serde_json::to_string(&BaselineStatus::Accepted).unwrap();
        let json_ignored = serde_json::to_string(&BaselineStatus::Ignored).unwrap();

        assert_eq!(json_accepted, "\"accepted\"");
        assert_eq!(json_ignored, "\"ignored\"");
    }

    #[test]
    fn status_display_shows_lowercase() {
        assert_eq!(format!("{}", BaselineStatus::Accepted), "accepted");
        assert_eq!(format!("{}", BaselineStatus::Ignored), "ignored");
    }

    #[test]
    fn finding_roundtrip_serialization() {
        let finding = BaselineFinding::new(
            Fingerprint::from_string("sha256:abc123"),
            "test/pattern".to_string(),
            Severity::High,
            "test.py".to_string(),
            "sha256:secret".to_string(),
            BaselineStatus::Accepted,
            "Test reason".to_string(),
        );

        let json = serde_json::to_string(&finding).unwrap();
        let deserialized: BaselineFinding = serde_json::from_str(&json).unwrap();

        assert_eq!(finding.fingerprint, deserialized.fingerprint);
        assert_eq!(finding.pattern_id, deserialized.pattern_id);
        assert_eq!(finding.status, deserialized.status);
    }
}
