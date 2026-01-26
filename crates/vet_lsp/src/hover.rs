//! Hover content generation for detected secrets.
//!
//! Provides context aware remediation guidance based on whether
//! a secret has been committed to git history.

use tower_lsp::lsp_types::{Hover, HoverContents, MarkupContent, MarkupKind, Range};
use vet_core::prelude::*;

use crate::git::ExposureRisk;

#[must_use]
pub fn pattern_hover(pattern: &Pattern, range: Range, exposure: ExposureRisk) -> Hover {
    let contents = format_pattern_markdown(pattern, exposure);

    Hover {
        contents: HoverContents::Markup(MarkupContent {
            kind: MarkupKind::Markdown,
            value: contents,
        }),
        range: Some(range),
    }
}

fn format_pattern_markdown(pattern: &Pattern, exposure: ExposureRisk) -> String {
    let mut sections = Vec::new();

    sections.push(format!("## {}", pattern.name));
    sections.push(String::new());
    sections.push(pattern.description.to_string());
    sections.push(String::new());

    sections.push(format!("**{}** severity", format_severity(pattern.severity)));
    sections.push(String::new());

    if let Some(remediation) = &pattern.remediation {
        sections.push("---".to_string());
        sections.push(String::new());
        sections.push(format_remediation(remediation, exposure));
        sections.push(String::new());
    }

    sections.push("---".to_string());
    sections.push(String::new());
    sections.push(format!("`{}`", pattern.id));

    sections.join("\n")
}

fn format_remediation(remediation: &str, exposure: ExposureRisk) -> String {
    match exposure {
        ExposureRisk::InHistory => {
            format!("**⚠️ This secret is in your git history.**\n\n{remediation}")
        }
        ExposureRisk::NotInHistory => "**Remediation**\n\n\
             Remove before committing. Use environment variables or a secrets manager."
            .to_string(),
        ExposureRisk::Unknown => {
            format!(
                "**Remediation**\n\n\
                 Avoid committing secrets. Use environment variables or a secrets manager.\n\n\
                 If exposed: {remediation}"
            )
        }
    }
}

fn format_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use regex::Regex;
    use tower_lsp::lsp_types::Position;

    use super::*;

    fn make_pattern(id: &str, name: &str, description: &str, severity: Severity, remediation: Option<&str>) -> Pattern {
        Pattern {
            id: id.into(),
            group: "test".into(),
            name: name.into(),
            description: description.into(),
            remediation: remediation.map(Into::into),
            severity,
            regex: Regex::new(r"test").unwrap(),
            keywords: vec![].into(),
            default_enabled: true,
            min_entropy: None,
        }
    }

    fn hover_markdown(hover: &Hover) -> &str {
        let HoverContents::Markup(content) = &hover.contents else {
            panic!("Expected markup content");
        };
        &content.value
    }

    #[test]
    fn hover_contains_pattern_name() {
        let pattern = make_pattern(
            "aws/access-key",
            "AWS Access Key ID",
            "Matches AWS access key IDs",
            Severity::High,
            None,
        );
        let hover = pattern_hover(&pattern, Range::default(), ExposureRisk::Unknown);

        assert!(hover_markdown(&hover).contains("## AWS Access Key ID"));
    }

    #[test]
    fn hover_contains_description() {
        let pattern = make_pattern(
            "test/pattern",
            "Test Pattern",
            "This is a test description",
            Severity::High,
            None,
        );
        let hover = pattern_hover(&pattern, Range::default(), ExposureRisk::Unknown);

        assert!(hover_markdown(&hover).contains("This is a test description"));
    }

    #[test]
    fn hover_contains_pattern_id_at_end() {
        let pattern = make_pattern(
            "aws/secret-key",
            "AWS Secret Key",
            "Description",
            Severity::Critical,
            None,
        );
        let hover = pattern_hover(&pattern, Range::default(), ExposureRisk::Unknown);
        let markdown = hover_markdown(&hover);

        assert!(markdown.contains("`aws/secret-key`"));
        assert!(markdown.ends_with("`aws/secret-key`"));
    }

    #[test]
    fn hover_critical_shows_simple_text() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::Critical, None);
        let hover = pattern_hover(&pattern, Range::default(), ExposureRisk::Unknown);

        let markdown = hover_markdown(&hover);
        assert!(markdown.contains("**Critical** severity"));
    }

    #[test]
    fn hover_high_shows_simple_text() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::High, None);
        let hover = pattern_hover(&pattern, Range::default(), ExposureRisk::Unknown);

        let markdown = hover_markdown(&hover);
        assert!(markdown.contains("**High** severity"));
        assert!(!markdown.contains(">"));
    }

    #[test]
    fn hover_medium_shows_simple_text() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::Medium, None);
        let hover = pattern_hover(&pattern, Range::default(), ExposureRisk::Unknown);

        let markdown = hover_markdown(&hover);
        assert!(markdown.contains("**Medium** severity"));
    }

    #[test]
    fn hover_low_shows_simple_text() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::Low, None);
        let hover = pattern_hover(&pattern, Range::default(), ExposureRisk::Unknown);

        let markdown = hover_markdown(&hover);
        assert!(markdown.contains("**Low** severity"));
    }

    #[test]
    fn hover_includes_remediation_when_present() {
        let pattern = make_pattern(
            "test",
            "Test",
            "Desc",
            Severity::High,
            Some("Rotate the credential immediately"),
        );
        let hover = pattern_hover(&pattern, Range::default(), ExposureRisk::Unknown);

        let markdown = hover_markdown(&hover);
        assert!(markdown.contains("**Remediation**"));
        assert!(markdown.contains("Rotate the credential immediately"));
    }

    #[test]
    fn hover_excludes_remediation_when_absent() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::High, None);
        let hover = pattern_hover(&pattern, Range::default(), ExposureRisk::Unknown);

        assert!(!hover_markdown(&hover).contains("**Remediation**"));
    }

    #[test]
    fn hover_is_markdown() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::High, None);
        let hover = pattern_hover(&pattern, Range::default(), ExposureRisk::Unknown);

        let HoverContents::Markup(content) = &hover.contents else {
            panic!("Expected markup content");
        };
        assert_eq!(content.kind, MarkupKind::Markdown);
    }

    #[test]
    fn hover_has_range() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::High, None);
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let hover = pattern_hover(&pattern, range, ExposureRisk::Unknown);

        assert_eq!(hover.range, Some(range));
    }

    #[test]
    fn hover_in_history_shows_warning() {
        let pattern = make_pattern(
            "test",
            "Test",
            "Desc",
            Severity::High,
            Some("Rotate the credential immediately"),
        );
        let hover = pattern_hover(&pattern, Range::default(), ExposureRisk::InHistory);
        let markdown = hover_markdown(&hover);

        assert!(markdown.contains("⚠️ This secret is in your git history"));
        assert!(markdown.contains("Rotate the credential immediately"));
    }

    #[test]
    fn hover_not_in_history_shows_prevention_advice() {
        let pattern = make_pattern(
            "test",
            "Test",
            "Desc",
            Severity::High,
            Some("Rotate the credential immediately"),
        );
        let hover = pattern_hover(&pattern, Range::default(), ExposureRisk::NotInHistory);
        let markdown = hover_markdown(&hover);

        assert!(markdown.contains("Remove before committing"));
        assert!(markdown.contains("environment variables"));
        assert!(!markdown.contains("Rotate the credential"));
    }

    #[test]
    fn hover_unknown_shows_generic_advice() {
        let pattern = make_pattern(
            "test",
            "Test",
            "Desc",
            Severity::High,
            Some("Rotate the credential immediately"),
        );
        let hover = pattern_hover(&pattern, Range::default(), ExposureRisk::Unknown);
        let markdown = hover_markdown(&hover);

        assert!(markdown.contains("Avoid committing secrets"));
        assert!(markdown.contains("If exposed:"));
        assert!(markdown.contains("Rotate the credential immediately"));
    }
}
