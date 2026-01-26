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
    let mut lines = Vec::new();

    lines.push(format!(
        "$(key) **{}** — {} **<span style=\"color:{};\">{}</span>**",
        pattern.name,
        severity_icon(pattern.severity),
        severity_color(pattern.severity),
        format_severity(pattern.severity),
    ));
    lines.push(String::new());

    lines.push(pattern.description.to_string());
    lines.push(String::new());
    lines.push("---".to_string());

    if let Some(remediation) = &pattern.remediation {
        lines.push(String::new());
        lines.push(format_remediation(remediation, exposure));
        lines.push(String::new());
        lines.push("---".to_string());
    }

    lines.push(String::new());
    lines.push(format!("`{}`", pattern.id));

    lines.join("\n")
}

fn format_remediation(remediation: &str, exposure: ExposureRisk) -> String {
    match exposure {
        ExposureRisk::InHistory => format_alert_in_history(remediation),
        ExposureRisk::NotInHistory => format_alert_not_in_history(),
        ExposureRisk::Unknown => format_alert_unknown(remediation),
    }
}

fn format_alert_in_history(remediation: &str) -> String {
    format_alert(
        "$(alert)",
        "{{danger}}",
        "This secret is in your git history.",
        remediation,
    )
}

fn format_alert_not_in_history() -> String {
    format_alert(
        "$(shield)",
        "{{info}}",
        "Remove before committing",
        "Use environment variables or a secrets manager instead.",
    )
}

fn format_alert_unknown(remediation: &str) -> String {
    let message = format!(
        "Avoid committing secrets. Use environment variables or a secrets manager.\n\n\
         If exposed: {remediation}"
    );

    format_alert("$(info)", "{{muted}}", "Remediation", &message)
}

fn format_alert(icon: &str, title_color: &str, title: &str, message: &str) -> String {
    let mut lines = vec![format!(
        "{icon} **<span style=\"color:{title_color};\">{title}</span>**"
    )];

    for line in message.lines() {
        if line.is_empty() {
            lines.push(String::new());
        } else {
            lines.push(format!("<span style=\"color:{{{{muted}}}};\">{line}</span>"));
        }
    }

    lines.join("\n")
}

fn severity_icon(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "$(flame)",
        Severity::High => "$(warning)",
        Severity::Medium => "$(info)",
        Severity::Low => "$(chevron-down)",
    }
}

fn severity_color(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "{{danger}}",
        Severity::High => "{{warning}}",
        Severity::Medium => "{{info}}",
        Severity::Low => "{{success}}",
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
    fn contains_pattern_name_bold() {
        let pattern = make_pattern(
            "aws/access-key",
            "AWS Access Key ID",
            "Matches AWS access key IDs",
            Severity::High,
            None,
        );
        let hover = pattern_hover(&pattern, Range::default(), ExposureRisk::Unknown);

        assert!(hover_markdown(&hover).contains("**AWS Access Key ID**"));
    }

    #[test]
    fn contains_description() {
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
    fn contains_pattern_id_at_end() {
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
    fn critical_severity_has_flame_icon_and_danger_token() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::Critical, None);
        let hover = pattern_hover(&pattern, Range::default(), ExposureRisk::Unknown);
        let markdown = hover_markdown(&hover);

        assert!(markdown.contains("$(flame)"));
        assert!(markdown.contains("{{danger}}"));
        assert!(markdown.contains("Critical"));
    }

    #[test]
    fn high_severity_has_warning_icon_and_warning_token() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::High, None);
        let hover = pattern_hover(&pattern, Range::default(), ExposureRisk::Unknown);
        let markdown = hover_markdown(&hover);

        assert!(markdown.contains("$(warning)"));
        assert!(markdown.contains("{{warning}}"));
        assert!(markdown.contains("High"));
    }

    #[test]
    fn medium_severity_has_info_icon_and_info_token() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::Medium, None);
        let hover = pattern_hover(&pattern, Range::default(), ExposureRisk::Unknown);
        let markdown = hover_markdown(&hover);

        assert!(markdown.contains("$(info)"));
        assert!(markdown.contains("{{info}}"));
        assert!(markdown.contains("Medium"));
    }

    #[test]
    fn low_severity_has_chevron_icon_and_success_token() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::Low, None);
        let hover = pattern_hover(&pattern, Range::default(), ExposureRisk::Unknown);
        let markdown = hover_markdown(&hover);

        assert!(markdown.contains("$(chevron-down)"));
        assert!(markdown.contains("{{success}}"));
        assert!(markdown.contains("Low"));
    }

    #[test]
    fn content_is_markdown_format() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::High, None);
        let hover = pattern_hover(&pattern, Range::default(), ExposureRisk::Unknown);

        let HoverContents::Markup(content) = &hover.contents else {
            panic!("Expected markup content");
        };
        assert_eq!(content.kind, MarkupKind::Markdown);
    }

    #[test]
    fn includes_provided_range() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::High, None);
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let hover = pattern_hover(&pattern, range, ExposureRisk::Unknown);

        assert_eq!(hover.range, Some(range));
    }

    #[test]
    fn in_history_shows_alert_with_danger_token() {
        let pattern = make_pattern(
            "test",
            "Test",
            "Desc",
            Severity::High,
            Some("Rotate the credential immediately"),
        );
        let hover = pattern_hover(&pattern, Range::default(), ExposureRisk::InHistory);
        let markdown = hover_markdown(&hover);

        assert!(markdown.contains("$(alert)"));
        assert!(markdown.contains("color:{{danger}};"));
        assert!(markdown.contains("git history"));
        assert!(markdown.contains("Rotate the credential immediately"));
    }

    #[test]
    fn not_in_history_shows_prevention_with_info_token() {
        let pattern = make_pattern(
            "test",
            "Test",
            "Desc",
            Severity::High,
            Some("Rotate the credential immediately"),
        );
        let hover = pattern_hover(&pattern, Range::default(), ExposureRisk::NotInHistory);
        let markdown = hover_markdown(&hover);

        assert!(markdown.contains("$(shield)"));
        assert!(markdown.contains("color:{{info}};"));
        assert!(markdown.contains("Remove before committing"));
        assert!(markdown.contains("environment variables"));
        assert!(!markdown.contains("Rotate the credential"));
    }

    #[test]
    fn unknown_exposure_shows_generic_advice() {
        let pattern = make_pattern(
            "test",
            "Test",
            "Desc",
            Severity::High,
            Some("Rotate the credential immediately"),
        );
        let hover = pattern_hover(&pattern, Range::default(), ExposureRisk::Unknown);
        let markdown = hover_markdown(&hover);

        assert!(markdown.contains("$(info)"));
        assert!(markdown.contains("Avoid committing secrets"));
        assert!(markdown.contains("If exposed:"));
        assert!(markdown.contains("Rotate the credential immediately"));
    }

    #[test]
    fn includes_key_icon_in_header() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::High, None);
        let hover = pattern_hover(&pattern, Range::default(), ExposureRisk::Unknown);

        assert!(hover_markdown(&hover).contains("$(key)"));
    }

    #[test]
    fn without_remediation_omits_alert_section() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::High, None);
        let hover = pattern_hover(&pattern, Range::default(), ExposureRisk::InHistory);
        let markdown = hover_markdown(&hover);

        assert!(!markdown.contains("$(alert)"));
        assert!(!markdown.contains("$(shield)"));
    }

    #[test]
    fn message_lines_use_muted_token() {
        let pattern = make_pattern("test", "Test", "Desc", Severity::High, Some("Fix it"));
        let hover = pattern_hover(&pattern, Range::default(), ExposureRisk::InHistory);
        let markdown = hover_markdown(&hover);

        assert!(markdown.contains("color:{{muted}};"));
    }
}
