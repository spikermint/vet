//! Hover data generation for detected secrets.

use serde::{Deserialize, Serialize};
use tower_lsp::lsp_types::Range;
use vet_core::prelude::*;
use vet_core::protocol::{self, ExposureRisk, HoverData, RemediationInfo, VerificationInfo};
use vet_providers::{VerificationResult, VerificationStatus};

/// Response for the `vet/hoverData` custom LSP request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VetHoverResponse {
    /// Editor-agnostic hover content.
    pub data: HoverData,

    /// The range the hover applies to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<Range>,
}

/// Builds editor-agnostic hover data for a detected pattern.
#[must_use]
pub fn build_hover_data(
    pattern: &Pattern,
    exposure: ExposureRisk,
    verification: Option<&VerificationResult>,
) -> HoverData {
    HoverData {
        pattern_name: pattern.name.to_string(),
        severity: pattern.severity,
        description: pattern.description.to_string(),
        verification: verification.map(to_verification_info),
        remediation: build_remediation(pattern.remediation(), exposure),
    }
}

fn to_verification_info(result: &VerificationResult) -> VerificationInfo {
    let service = result.service.as_ref();
    let provider = service.and_then(|s| s.provider.as_deref().map(String::from));
    let details = service.map(|s| s.details.to_string()).filter(|d| !d.is_empty());

    let reason = match result.status {
        VerificationStatus::Inconclusive => details.clone(),
        _ => None,
    };

    protocol::VerificationInfo {
        status: result.status,
        provider,
        details,
        reason,
        verified_at: result.verified_at.to_string(),
    }
}

fn build_remediation(remediation_text: &str, exposure: ExposureRisk) -> RemediationInfo {
    let advice = match exposure {
        ExposureRisk::InHistory => format!("This secret is in your git history.\n\n{remediation_text}"),
        ExposureRisk::NotInHistory => {
            "Remove before committing. Use environment variables or a secrets manager instead.".to_string()
        }
        ExposureRisk::Unknown => format!(
            "Avoid committing secrets. Use environment variables or a secrets manager.\n\nIf exposed: {remediation_text}"
        ),
    };

    RemediationInfo { exposure, advice }
}

#[cfg(test)]
mod tests {
    use regex::Regex;

    use super::*;

    fn make_pattern(id: &str, name: &str, description: &str, severity: Severity) -> Pattern {
        Pattern {
            id: id.into(),
            group: Group::Custom,
            name: name.into(),
            description: description.into(),
            severity,
            regex: Regex::new(r"test").unwrap(),
            keywords: vec![].into(),
            default_enabled: true,
            min_entropy: None,
        }
    }

    #[test]
    fn hover_data_contains_pattern_name() {
        let pattern = make_pattern(
            "aws/access-key",
            "AWS Access Key ID",
            "Matches AWS access key IDs",
            Severity::High,
        );
        let data = build_hover_data(&pattern, ExposureRisk::Unknown, None);

        assert_eq!(data.pattern_name, "AWS Access Key ID");
    }

    #[test]
    fn hover_data_contains_severity() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::Critical);
        let data = build_hover_data(&pattern, ExposureRisk::Unknown, None);

        assert_eq!(data.severity, Severity::Critical);
    }

    #[test]
    fn hover_data_contains_description() {
        let pattern = make_pattern("test", "Test Pattern", "This is a test description", Severity::High);
        let data = build_hover_data(&pattern, ExposureRisk::Unknown, None);

        assert_eq!(data.description, "This is a test description");
    }

    #[test]
    fn no_verification_returns_none() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::High);
        let data = build_hover_data(&pattern, ExposureRisk::Unknown, None);

        assert!(data.verification.is_none());
    }

    #[test]
    fn in_history_shows_git_history_advice() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::High);
        let data = build_hover_data(&pattern, ExposureRisk::InHistory, None);

        assert_eq!(data.remediation.exposure, ExposureRisk::InHistory);
        assert!(data.remediation.advice.contains("git history"));
        assert!(data.remediation.advice.contains("Revoke or rotate"));
    }

    #[test]
    fn not_in_history_shows_prevention_advice() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::High);
        let data = build_hover_data(&pattern, ExposureRisk::NotInHistory, None);

        assert_eq!(data.remediation.exposure, ExposureRisk::NotInHistory);
        assert!(data.remediation.advice.contains("Remove before committing"));
        assert!(data.remediation.advice.contains("environment variables"));
    }

    #[test]
    fn unknown_exposure_shows_if_exposed_anchor() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::High);
        let data = build_hover_data(&pattern, ExposureRisk::Unknown, None);

        assert_eq!(data.remediation.exposure, ExposureRisk::Unknown);
        assert!(data.remediation.advice.contains("Avoid committing secrets"));
        assert!(data.remediation.advice.contains("If exposed:"));
        assert!(data.remediation.advice.contains("Revoke or rotate"));
    }

    #[test]
    fn verified_live_has_correct_status() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::Critical);
        let result = VerificationResult::live(vet_providers::ServiceInfo {
            provider: Some("GitHub".into()),
            details: "user: octocat".into(),
            documentation_url: None,
        });
        let data = build_hover_data(&pattern, ExposureRisk::Unknown, Some(&result));

        let verification = data.verification.unwrap();
        assert_eq!(verification.status, VerificationStatus::Live);
        assert_eq!(verification.provider.as_deref(), Some("GitHub"));
        assert_eq!(verification.details.as_deref(), Some("user: octocat"));
        assert!(verification.reason.is_none());
    }

    #[test]
    fn verified_inactive_has_correct_status() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::Critical);
        let result = VerificationResult::inactive("GitHub");
        let data = build_hover_data(&pattern, ExposureRisk::Unknown, Some(&result));

        let verification = data.verification.unwrap();
        assert_eq!(verification.status, VerificationStatus::Inactive);
        assert_eq!(verification.provider.as_deref(), Some("GitHub"));
    }

    #[test]
    fn verified_inconclusive_has_reason() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::Critical);
        let result = VerificationResult::inconclusive("rate limited");
        let data = build_hover_data(&pattern, ExposureRisk::Unknown, Some(&result));

        let verification = data.verification.unwrap();
        assert_eq!(verification.status, VerificationStatus::Inconclusive);
        assert!(verification.reason.is_some());
        assert!(verification.reason.unwrap().contains("rate limited"));
    }

    #[test]
    fn verification_has_timestamp() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::Critical);
        let result = VerificationResult::live(vet_providers::ServiceInfo {
            provider: Some("GitHub".into()),
            details: "user: octocat, scopes: repo".into(),
            documentation_url: None,
        });
        let data = build_hover_data(&pattern, ExposureRisk::Unknown, Some(&result));

        let verification = data.verification.unwrap();
        assert!(!verification.verified_at.is_empty());
    }

    #[test]
    fn verification_details_preserved() {
        let result = VerificationResult::live(vet_providers::ServiceInfo {
            provider: Some("GitHub".into()),
            details: "user: octocat, scopes: repo".into(),
            documentation_url: None,
        });
        let pattern = make_pattern("test", "Test", "Desc", Severity::Critical);
        let data = build_hover_data(&pattern, ExposureRisk::Unknown, Some(&result));

        let verification = data.verification.unwrap();
        assert_eq!(verification.details.as_deref(), Some("user: octocat, scopes: repo"));
    }
}
