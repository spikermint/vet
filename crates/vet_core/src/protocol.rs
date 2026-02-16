//! Editor-agnostic protocol types for LSP and tooling consumers.
//!
//! These types define the data contracts between the vet LSP server and
//! editor extensions. Each editor extension is responsible for rendering
//! these into its native UI format.

use serde::{Deserialize, Serialize};
use vet_providers::VerificationStatus;

use crate::Severity;

/// Whether a secret has been committed to git history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ExposureRisk {
    /// Secret not found in HEAD. Safe to remove before committing.
    NotInHistory,

    /// Secret exists in HEAD. Already in git history, rotation required.
    InHistory,

    /// Cannot determine (no git repo, git error, etc.). Show generic advice.
    #[default]
    Unknown,
}

/// Editor-agnostic hover content for a detected secret.
///
/// Sent via `vet/hoverData` custom LSP request. Each editor extension
/// is responsible for rendering this into its native tooltip format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HoverData {
    /// Human-readable pattern name (e.g. "AWS Secret Access Key").
    pub pattern_name: String,

    /// Detection severity.
    pub severity: Severity,

    /// Human-readable description of what the pattern matches.
    pub description: String,

    /// Live verification status, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<VerificationInfo>,

    /// Remediation guidance based on git exposure.
    pub remediation: RemediationInfo,
}

/// Verification status of a detected secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationInfo {
    /// Whether the secret is live, inactive, or inconclusive.
    pub status: VerificationStatus,

    /// Service provider name (e.g. "GitHub", "AWS").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,

    /// Additional details (e.g. "user: octocat, scopes: repo").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,

    /// Reason for inconclusive result (e.g. "rate limited").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// ISO 8601 timestamp of when verification occurred.
    /// Extensions compute relative time ("2 min ago") client-side.
    pub verified_at: String,
}

/// Remediation context based on git exposure risk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemediationInfo {
    /// Git exposure status of the secret.
    pub exposure: ExposureRisk,

    /// Remediation advice text (e.g. "Revoke or rotate the secret immediately").
    pub advice: String,
}

/// Structured data attached to each LSP diagnostic.
///
/// Extensions read this to power code actions, hover lookups,
/// and verification triggers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticData {
    /// Stable fingerprint for baseline matching.
    pub fingerprint: String,

    /// Unique finding ID for this scan session.
    pub finding_id: String,

    /// Whether this pattern supports live verification.
    pub verifiable: bool,

    /// Cached verification result, if available and not expired.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<DiagnosticVerification>,
}

/// Verification summary embedded in diagnostic data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticVerification {
    /// Whether the secret is live, inactive, or inconclusive.
    pub status: VerificationStatus,

    /// Provider name, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,

    /// Additional details from the verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,

    /// ISO 8601 timestamp of when verification occurred.
    pub verified_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposure_risk_default_is_unknown() {
        assert_eq!(ExposureRisk::default(), ExposureRisk::Unknown);
    }

    #[test]
    fn exposure_risk_serialises_to_camel_case() {
        let json = serde_json::to_string(&ExposureRisk::InHistory).unwrap();
        assert_eq!(json, "\"inHistory\"");

        let json = serde_json::to_string(&ExposureRisk::NotInHistory).unwrap();
        assert_eq!(json, "\"notInHistory\"");

        let json = serde_json::to_string(&ExposureRisk::Unknown).unwrap();
        assert_eq!(json, "\"unknown\"");
    }

    #[test]
    fn hover_data_round_trips_through_json() {
        let data = HoverData {
            pattern_name: "AWS Secret Key".to_string(),
            severity: Severity::Critical,
            description: "Matches AWS secret access keys".to_string(),
            verification: None,
            remediation: RemediationInfo {
                exposure: ExposureRisk::NotInHistory,
                advice: "Remove before committing.".to_string(),
            },
        };

        let json = serde_json::to_string(&data).unwrap();
        let parsed: HoverData = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, data);
    }

    #[test]
    fn hover_data_with_verification_round_trips() {
        let data = HoverData {
            pattern_name: "GitHub PAT".to_string(),
            severity: Severity::High,
            description: "Matches GitHub personal access tokens".to_string(),
            verification: Some(VerificationInfo {
                status: VerificationStatus::Live,
                provider: Some("GitHub".to_string()),
                details: Some("user: octocat".to_string()),
                reason: None,
                verified_at: "2025-01-01T00:00:00Z".to_string(),
            }),
            remediation: RemediationInfo {
                exposure: ExposureRisk::InHistory,
                advice: "Revoke or rotate the token.".to_string(),
            },
        };

        let json = serde_json::to_string(&data).unwrap();
        let parsed: HoverData = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, data);
    }

    #[test]
    fn diagnostic_data_round_trips_through_json() {
        let data = DiagnosticData {
            fingerprint: "sha256:abc123".to_string(),
            finding_id: "finding-1".to_string(),
            verifiable: true,
            verification: Some(DiagnosticVerification {
                status: VerificationStatus::Live,
                provider: Some("GitHub".to_string()),
                details: Some("user: test".to_string()),
                verified_at: "2025-01-01T00:00:00Z".to_string(),
            }),
        };

        let json = serde_json::to_string(&data).unwrap();
        let parsed: DiagnosticData = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, data);
    }

    #[test]
    fn diagnostic_data_omits_none_verification() {
        let data = DiagnosticData {
            fingerprint: "sha256:abc123".to_string(),
            finding_id: "finding-1".to_string(),
            verifiable: false,
            verification: None,
        };

        let json = serde_json::to_string(&data).unwrap();
        assert!(!json.contains("verification"));
    }
}
