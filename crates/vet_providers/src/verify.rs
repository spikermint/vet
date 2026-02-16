//! Secret verification types and traits.

use std::pin::Pin;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// A pinned, boxed, `Send` future used as the return type for async verification.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Errors that can occur during secret verification.
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    /// The HTTP client could not be initialised.
    #[error("failed to initialize HTTP client: {0}")]
    ClientInit(String),

    /// An HTTP request to the provider's API failed.
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// The verification request exceeded the configured timeout.
    #[error("verification timed out after {0:?}")]
    Timeout(Duration),

    /// No verifier is registered for the requested pattern.
    #[error("no verifier registered for pattern: {pattern_id}")]
    UnsupportedPattern {
        /// Identifier of the pattern that has no registered verifier.
        pattern_id: String,
    },
}

/// The outcome of verifying a detected secret against its provider's API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the secret is live, inactive, or inconclusive.
    pub status: VerificationStatus,
    /// Optional details about the service that recognised the secret.
    pub service: Option<ServiceInfo>,
    /// ISO 8601 timestamp of when verification was performed.
    pub verified_at: Box<str>,
}

/// Whether a verified secret is currently active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationStatus {
    /// The secret is active and grants access.
    #[serde(rename = "live")]
    Live,
    /// The secret has been revoked or expired.
    #[serde(rename = "inactive")]
    Inactive,
    /// Verification could not determine the secret's status.
    #[serde(rename = "inconclusive")]
    Inconclusive,
}

impl std::fmt::Display for VerificationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Live => write!(f, "live"),
            Self::Inactive => write!(f, "inactive"),
            Self::Inconclusive => write!(f, "inconclusive"),
        }
    }
}

/// Metadata about the service that recognised a verified secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    /// The provider name (e.g. `"GitHub"`), if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<Box<str>>,
    /// A human-readable summary of the verification outcome.
    pub details: Box<str>,
    /// A link to the provider's key management documentation, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documentation_url: Option<Box<str>>,
}

impl VerificationResult {
    /// Creates a result indicating the secret is live and active.
    #[must_use]
    pub fn live(service: ServiceInfo) -> Self {
        Self {
            status: VerificationStatus::Live,
            service: Some(service),
            verified_at: current_timestamp(),
        }
    }

    /// Creates a result indicating the secret is inactive (revoked or expired).
    #[must_use]
    pub fn inactive(provider: &str) -> Self {
        Self {
            status: VerificationStatus::Inactive,
            service: Some(ServiceInfo {
                provider: Some(provider.into()),
                details: "key is revoked or expired".into(),
                documentation_url: None,
            }),
            verified_at: current_timestamp(),
        }
    }

    /// Creates a result indicating verification was inconclusive.
    #[must_use]
    pub fn inconclusive(reason: &str) -> Self {
        Self {
            status: VerificationStatus::Inconclusive,
            service: Some(ServiceInfo {
                provider: None,
                details: reason.into(),
                documentation_url: None,
            }),
            verified_at: current_timestamp(),
        }
    }
}

fn current_timestamp() -> Box<str> {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
        .into_boxed_str()
}

/// Trait for providers that can verify whether a detected secret is still active.
pub trait SecretVerifier: Send + Sync {
    /// Checks the secret against the provider's API and returns a `VerificationResult`.
    fn verify<'a>(
        &'a self,
        client: &'a reqwest::Client,
        secret: &'a str,
        pattern_id: &'a str,
    ) -> BoxFuture<'a, Result<VerificationResult, VerificationError>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_status_display() {
        assert_eq!(format!("{}", VerificationStatus::Live), "live");
        assert_eq!(format!("{}", VerificationStatus::Inactive), "inactive");
        assert_eq!(format!("{}", VerificationStatus::Inconclusive), "inconclusive");
    }

    #[test]
    fn verification_result_live_has_service_info() {
        let result = VerificationResult::live(ServiceInfo {
            provider: Some("Test".into()),
            details: "test details".into(),
            documentation_url: None,
        });

        assert_eq!(result.status, VerificationStatus::Live);
        assert!(result.service.is_some());
    }

    #[test]
    fn verification_result_inactive_sets_default_details() {
        let result = VerificationResult::inactive("GitHub");

        assert_eq!(result.status, VerificationStatus::Inactive);
        let service = result.service.as_ref().unwrap();
        assert_eq!(service.provider.as_deref(), Some("GitHub"));
        assert!(service.details.contains("revoked"));
    }

    #[test]
    fn verification_result_inconclusive_has_no_provider() {
        let result = VerificationResult::inconclusive("rate limited");

        assert_eq!(result.status, VerificationStatus::Inconclusive);
        let service = result.service.as_ref().unwrap();
        assert!(service.provider.is_none());
        assert!(service.details.contains("rate limited"));
    }
}
