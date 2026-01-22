use tower_lsp::lsp_types::{Diagnostic, DiagnosticSeverity, DiagnosticTag, NumberOrString, Position, Range};
use vet_core::prelude::*;

const SOURCE: &str = "vet";

#[must_use]
pub fn findings_to_diagnostics(findings: &[Finding]) -> Vec<Diagnostic> {
    findings.iter().map(finding_to_diagnostic).collect()
}

#[allow(clippy::cast_possible_truncation)]
fn finding_to_diagnostic(finding: &Finding) -> Diagnostic {
    let line = finding.span.line.saturating_sub(1);
    let column = finding.span.column.saturating_sub(1);

    let range = Range {
        start: Position::new(line, column),
        end: Position::new(line, column + finding.span.len() as u32),
    };

    let tags = diagnostic_tags_for_confidence(finding.confidence);

    Diagnostic {
        range,
        severity: Some(to_lsp_severity(finding.severity)),
        code: Some(NumberOrString::String(finding.pattern_id.to_string())),
        source: Some(SOURCE.to_string()),
        message: format_message(finding),
        tags: if tags.is_empty() { None } else { Some(tags) },
        ..Default::default()
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

#[must_use]
pub fn filter_by_confidence(findings: Vec<Finding>, include_low_confidence: bool) -> Vec<Finding> {
    findings
        .into_iter()
        .filter(|f| include_low_confidence || f.confidence != Confidence::Low)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

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
    fn filter_by_confidence_keeps_high_when_false() {
        let findings = vec![
            make_finding("test/a", Severity::High, Confidence::High, 1, 1, 10),
            make_finding("test/b", Severity::High, Confidence::Low, 2, 1, 10),
        ];

        let filtered = filter_by_confidence(findings, false);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].confidence, Confidence::High);
    }

    #[test]
    fn filter_by_confidence_keeps_all_when_true() {
        let findings = vec![
            make_finding("test/a", Severity::High, Confidence::High, 1, 1, 10),
            make_finding("test/b", Severity::High, Confidence::Low, 2, 1, 10),
        ];

        let filtered = filter_by_confidence(findings, true);

        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn filter_by_confidence_empty_input() {
        let filtered = filter_by_confidence(vec![], false);
        assert!(filtered.is_empty());
    }

    #[test]
    fn filter_by_confidence_all_low() {
        let findings = vec![
            make_finding("test/a", Severity::High, Confidence::Low, 1, 1, 10),
            make_finding("test/b", Severity::High, Confidence::Low, 2, 1, 10),
        ];

        let filtered = filter_by_confidence(findings, false);

        assert!(filtered.is_empty());
    }
}
