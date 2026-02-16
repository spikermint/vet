//! Diagnostic generation from scan findings.
//!
//! Converts scanner findings to LSP diagnostics.

use lru::LruCache;
use tower_lsp::lsp_types::{Diagnostic, DiagnosticSeverity, DiagnosticTag, NumberOrString, Position, Range};
use vet_core::prelude::*;
use vet_core::protocol;
use vet_providers::{ProviderRegistry, VerificationStatus};

use crate::state::CachedVerification;

const SOURCE: &str = "vet";

/// References to verification state needed when building diagnostics.
pub struct DiagnosticContext<'a> {
    /// The provider registry, used to check if a pattern supports live verification.
    pub verifier_registry: Option<&'a ProviderRegistry>,
    /// The LRU cache of recent verification results.
    pub verification_cache: &'a LruCache<String, CachedVerification>,
}

/// Converts scanner findings to LSP diagnostics, enriched with verification data.
#[must_use]
pub fn findings_to_diagnostics_with_context(findings: &[Finding], context: &DiagnosticContext<'_>) -> Vec<Diagnostic> {
    findings
        .iter()
        .map(|f| finding_to_diagnostic(f, Some(context)))
        .collect()
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "span lengths are always within u32 range for single-line diagnostics"
)]
fn finding_to_diagnostic(finding: &Finding, context: Option<&DiagnosticContext<'_>>) -> Diagnostic {
    let line = finding.span.line.saturating_sub(1);
    let column = finding.span.column.saturating_sub(1);

    let range = Range {
        start: Position::new(line, column),
        end: Position::new(line, column + finding.span.len() as u32),
    };

    let tags = diagnostic_tags_for_confidence(finding.confidence);
    let fingerprint = finding.baseline_fingerprint();
    let finding_id = finding.id.as_str();

    let (verifiable, cached_verification) = context.map_or((false, None), |ctx| {
        let verifiable = ctx
            .verifier_registry
            .is_some_and(|r| r.supports_verification(&finding.pattern_id));
        let cached = ctx.verification_cache.peek(finding_id);
        (verifiable, cached)
    });

    let (severity, message) = match cached_verification {
        Some(cached) if !cached.is_expired() => {
            let (sev, msg) = format_verified_message(finding, &cached.result);
            (sev, msg)
        }
        _ => (to_lsp_severity(finding.severity), format_message(finding)),
    };

    let data = build_diagnostic_data(&fingerprint, finding_id, verifiable, cached_verification);

    Diagnostic {
        range,
        severity: Some(severity),
        code: Some(NumberOrString::String(finding.pattern_id.to_string())),
        source: Some(SOURCE.to_string()),
        message,
        tags: if tags.is_empty() { None } else { Some(tags) },
        data: Some(data),
        ..Default::default()
    }
}

#[expect(clippy::expect_used, reason = "DiagnosticData serialisation is infallible")]
fn build_diagnostic_data(
    fingerprint: &vet_core::Fingerprint,
    finding_id: &str,
    verifiable: bool,
    cached_verification: Option<&CachedVerification>,
) -> serde_json::Value {
    let verification = cached_verification.filter(|c| !c.is_expired()).map(|cached| {
        let service = cached.result.service.as_ref();
        protocol::DiagnosticVerification {
            status: cached.result.status,
            provider: service.and_then(|s| s.provider.as_deref().map(String::from)),
            details: service.map(|s| s.details.to_string()),
            verified_at: cached.result.verified_at.to_string(),
        }
    });

    let data = protocol::DiagnosticData {
        fingerprint: fingerprint.as_str().to_string(),
        finding_id: finding_id.to_string(),
        verifiable,
        verification,
    };

    serde_json::to_value(data).expect("DiagnosticData serialisation cannot fail")
}

fn format_verified_message(
    finding: &Finding,
    result: &vet_providers::VerificationResult,
) -> (DiagnosticSeverity, String) {
    let service = result.service.as_ref();
    let details = service.map_or("", |s| &s.details);

    match result.status {
        VerificationStatus::Live => {
            let pattern_id = &finding.pattern_id;
            let message = if details.is_empty() {
                format!("LIVE - {pattern_id}")
            } else {
                format!("LIVE - {pattern_id} - {details}")
            };
            (DiagnosticSeverity::ERROR, message)
        }
        VerificationStatus::Inactive => {
            let pattern_id = &finding.pattern_id;
            let message = if details.is_empty() {
                format!("Inactive - {pattern_id} - key is revoked or expired")
            } else {
                format!("Inactive - {pattern_id} - {details}")
            };
            (DiagnosticSeverity::WARNING, message)
        }
        VerificationStatus::Inconclusive => {
            let pattern_id = &finding.pattern_id;
            let message = if details.is_empty() {
                format!("Inconclusive - {pattern_id} - rate limited, try again later")
            } else {
                format!("Inconclusive - {pattern_id} - {details}")
            };
            (to_lsp_severity(finding.severity), message)
        }
    }
}

const fn to_lsp_severity(severity: Severity) -> DiagnosticSeverity {
    match severity {
        Severity::Critical | Severity::High => DiagnosticSeverity::ERROR,
        Severity::Medium => DiagnosticSeverity::WARNING,
        Severity::Low => DiagnosticSeverity::INFORMATION,
    }
}

fn format_message(finding: &Finding) -> String {
    let suffix = match finding.confidence {
        Confidence::Low => " (low confidence)",
        Confidence::High => "",
    };

    format!("Potential secret: {}{suffix}", finding.pattern_id)
}

fn diagnostic_tags_for_confidence(confidence: Confidence) -> Vec<DiagnosticTag> {
    match confidence {
        Confidence::Low => vec![DiagnosticTag::UNNECESSARY],
        Confidence::High => vec![],
    }
}

/// Filters findings, keeping only those at or above the minimum confidence level.
#[must_use]
pub fn filter_by_confidence(findings: Vec<Finding>, minimum: Confidence) -> Vec<Finding> {
    findings.into_iter().filter(|f| f.confidence >= minimum).collect()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn findings_to_diagnostics(findings: &[Finding]) -> Vec<Diagnostic> {
        findings.iter().map(|f| finding_to_diagnostic(f, None)).collect()
    }

    fn make_finding(
        pattern_id: &str,
        severity: Severity,
        confidence: Confidence,
        line: u32,
        column: u32,
        len: usize,
    ) -> Finding {
        let secret = Secret::new("test-secret");
        Finding {
            id: FindingId::new(pattern_id, &secret),
            path: Path::new("test.txt").into(),
            span: Span::new(line, column, 0, len),
            pattern_id: pattern_id.into(),
            secret,
            severity,
            masked_line: "masked".into(),
            confidence,
        }
    }

    #[test]
    fn empty_findings_returns_empty_diagnostics() {
        let diagnostics = findings_to_diagnostics(&[]);
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn converts_single_finding() {
        let finding = make_finding("test/pattern", Severity::High, Confidence::High, 10, 5, 20);
        let diagnostics = findings_to_diagnostics(&[finding]);

        assert_eq!(diagnostics.len(), 1);
    }

    #[test]
    fn converts_multiple_findings() {
        let findings = vec![
            make_finding("test/a", Severity::High, Confidence::High, 1, 1, 10),
            make_finding("test/b", Severity::Low, Confidence::Low, 5, 3, 15),
        ];
        let diagnostics = findings_to_diagnostics(&findings);

        assert_eq!(diagnostics.len(), 2);
    }

    #[test]
    fn line_is_zero_indexed() {
        let finding = make_finding("test/pattern", Severity::High, Confidence::High, 10, 5, 20);
        let diagnostics = findings_to_diagnostics(&[finding]);

        assert_eq!(diagnostics[0].range.start.line, 9);
    }

    #[test]
    fn column_is_zero_indexed() {
        let finding = make_finding("test/pattern", Severity::High, Confidence::High, 10, 5, 20);
        let diagnostics = findings_to_diagnostics(&[finding]);

        assert_eq!(diagnostics[0].range.start.character, 4);
    }

    #[test]
    fn range_end_includes_length() {
        let finding = make_finding("test/pattern", Severity::High, Confidence::High, 10, 5, 20);
        let diagnostics = findings_to_diagnostics(&[finding]);

        assert_eq!(diagnostics[0].range.end.character, 4 + 20);
    }

    #[test]
    fn critical_severity_maps_to_error() {
        let finding = make_finding("test/pattern", Severity::Critical, Confidence::High, 1, 1, 10);
        let diagnostics = findings_to_diagnostics(&[finding]);

        assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::ERROR));
    }

    #[test]
    fn high_severity_maps_to_error() {
        let finding = make_finding("test/pattern", Severity::High, Confidence::High, 1, 1, 10);
        let diagnostics = findings_to_diagnostics(&[finding]);

        assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::ERROR));
    }

    #[test]
    fn medium_severity_maps_to_warning() {
        let finding = make_finding("test/pattern", Severity::Medium, Confidence::High, 1, 1, 10);
        let diagnostics = findings_to_diagnostics(&[finding]);

        assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::WARNING));
    }

    #[test]
    fn low_severity_maps_to_information() {
        let finding = make_finding("test/pattern", Severity::Low, Confidence::High, 1, 1, 10);
        let diagnostics = findings_to_diagnostics(&[finding]);

        assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::INFORMATION));
    }

    #[test]
    fn source_is_vet() {
        let finding = make_finding("test/pattern", Severity::High, Confidence::High, 1, 1, 10);
        let diagnostics = findings_to_diagnostics(&[finding]);

        assert_eq!(diagnostics[0].source, Some("vet".to_string()));
    }

    #[test]
    fn code_is_pattern_id() {
        let finding = make_finding("aws/access-key", Severity::High, Confidence::High, 1, 1, 10);
        let diagnostics = findings_to_diagnostics(&[finding]);

        assert_eq!(
            diagnostics[0].code,
            Some(NumberOrString::String("aws/access-key".to_string()))
        );
    }

    #[test]
    fn message_includes_pattern_id() {
        let finding = make_finding("aws/access-key", Severity::High, Confidence::High, 1, 1, 10);
        let diagnostics = findings_to_diagnostics(&[finding]);

        assert!(diagnostics[0].message.contains("aws/access-key"));
    }

    #[test]
    fn low_confidence_adds_suffix_to_message() {
        let finding = make_finding("test/pattern", Severity::High, Confidence::Low, 1, 1, 10);
        let diagnostics = findings_to_diagnostics(&[finding]);

        assert!(diagnostics[0].message.contains("(low confidence)"));
    }

    #[test]
    fn high_confidence_no_suffix() {
        let finding = make_finding("test/pattern", Severity::High, Confidence::High, 1, 1, 10);
        let diagnostics = findings_to_diagnostics(&[finding]);

        assert!(!diagnostics[0].message.contains("(low confidence)"));
    }

    #[test]
    fn low_confidence_has_unnecessary_tag() {
        let finding = make_finding("test/pattern", Severity::High, Confidence::Low, 1, 1, 10);
        let diagnostics = findings_to_diagnostics(&[finding]);

        assert!(
            diagnostics[0]
                .tags
                .as_ref()
                .is_some_and(|t| t.contains(&DiagnosticTag::UNNECESSARY))
        );
    }

    #[test]
    fn high_confidence_has_no_tags() {
        let finding = make_finding("test/pattern", Severity::High, Confidence::High, 1, 1, 10);
        let diagnostics = findings_to_diagnostics(&[finding]);

        assert!(diagnostics[0].tags.is_none());
    }

    #[test]
    fn filter_by_confidence_high_minimum_keeps_only_high() {
        let findings = vec![
            make_finding("test/a", Severity::High, Confidence::High, 1, 1, 10),
            make_finding("test/b", Severity::High, Confidence::Low, 2, 1, 10),
        ];

        let filtered = filter_by_confidence(findings, Confidence::High);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].confidence, Confidence::High);
    }

    #[test]
    fn filter_by_confidence_low_minimum_keeps_all() {
        let findings = vec![
            make_finding("test/a", Severity::High, Confidence::High, 1, 1, 10),
            make_finding("test/b", Severity::High, Confidence::Low, 2, 1, 10),
        ];

        let filtered = filter_by_confidence(findings, Confidence::Low);

        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn filter_by_confidence_empty_input() {
        let filtered = filter_by_confidence(vec![], Confidence::High);
        assert!(filtered.is_empty());
    }

    #[test]
    fn filter_by_confidence_all_low_with_high_minimum() {
        let findings = vec![
            make_finding("test/a", Severity::High, Confidence::Low, 1, 1, 10),
            make_finding("test/b", Severity::High, Confidence::Low, 2, 1, 10),
        ];

        let filtered = filter_by_confidence(findings, Confidence::High);

        assert!(filtered.is_empty());
    }
}
