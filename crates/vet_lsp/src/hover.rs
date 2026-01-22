use tower_lsp::lsp_types::{Hover, HoverContents, MarkupContent, MarkupKind, Range};
use vet_core::prelude::*;

#[must_use]
pub fn pattern_hover(pattern: &Pattern, range: Range) -> Hover {
    let contents = format_pattern_markdown(pattern);

    Hover {
        contents: HoverContents::Markup(MarkupContent {
            kind: MarkupKind::Markdown,
            value: contents,
        }),
        range: Some(range),
    }
}

fn format_pattern_markdown(pattern: &Pattern) -> String {
    let mut lines = Vec::new();

    lines.push(format!("### {}", pattern.name));
    lines.push(String::new());

    lines.push(pattern.description.to_string());
    lines.push(String::new());

    let severity_badge = format_severity_badge(pattern.severity);
    lines.push(format!("**Severity:** {} · **ID:** `{}`", severity_badge, pattern.id));

    if let Some(remediation) = &pattern.remediation {
        lines.push(String::new());
        lines.push("---".to_string());
        lines.push(String::new());
        lines.push(format!("**Remediation:** {}", remediation));
    }

    lines.join("\n")
}

fn format_severity_badge(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "🔴 Critical",
        Severity::High => "🟠 High",
        Severity::Medium => "🟡 Medium",
        Severity::Low => "🟢 Low",
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
            Severity::Critical,
            None,
        );
        let hover = pattern_hover(&pattern, Range::default());

        assert!(hover_markdown(&hover).contains("AWS Access Key ID"));
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
        let hover = pattern_hover(&pattern, Range::default());

        assert!(hover_markdown(&hover).contains("This is a test description"));
    }

    #[test]
    fn hover_contains_pattern_id() {
        let pattern = make_pattern(
            "aws/secret-key",
            "AWS Secret Key",
            "Description",
            Severity::Critical,
            None,
        );
        let hover = pattern_hover(&pattern, Range::default());

        assert!(hover_markdown(&hover).contains("`aws/secret-key`"));
    }

    #[test]
    fn hover_contains_severity_critical() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::Critical, None);
        let hover = pattern_hover(&pattern, Range::default());

        let markdown = hover_markdown(&hover);
        assert!(markdown.contains("Critical"));
        assert!(markdown.contains("🔴"));
    }

    #[test]
    fn hover_contains_severity_high() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::High, None);
        let hover = pattern_hover(&pattern, Range::default());

        let markdown = hover_markdown(&hover);
        assert!(markdown.contains("High"));
        assert!(markdown.contains("🟠"));
    }

    #[test]
    fn hover_contains_severity_medium() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::Medium, None);
        let hover = pattern_hover(&pattern, Range::default());

        let markdown = hover_markdown(&hover);
        assert!(markdown.contains("Medium"));
        assert!(markdown.contains("🟡"));
    }

    #[test]
    fn hover_contains_severity_low() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::Low, None);
        let hover = pattern_hover(&pattern, Range::default());

        let markdown = hover_markdown(&hover);
        assert!(markdown.contains("Low"));
        assert!(markdown.contains("🟢"));
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
        let hover = pattern_hover(&pattern, Range::default());

        let markdown = hover_markdown(&hover);
        assert!(markdown.contains("Remediation"));
        assert!(markdown.contains("Rotate the credential immediately"));
    }

    #[test]
    fn hover_excludes_remediation_when_absent() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::High, None);
        let hover = pattern_hover(&pattern, Range::default());

        assert!(!hover_markdown(&hover).contains("Remediation"));
    }

    #[test]
    fn hover_is_markdown() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::High, None);
        let hover = pattern_hover(&pattern, Range::default());

        let HoverContents::Markup(content) = &hover.contents else {
            panic!("Expected markup content");
        };
        assert_eq!(content.kind, MarkupKind::Markdown);
    }

    #[test]
    fn hover_has_range() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::High, None);
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let hover = pattern_hover(&pattern, range);

        assert_eq!(hover.range, Some(range));
    }
}
