//! Code action generation for vet diagnostics.

use std::collections::HashMap;

use tower_lsp::lsp_types::{
    CodeAction, CodeActionKind, CodeActionOrCommand, Command, Diagnostic, Position, Range, TextEdit, Url, WorkspaceEdit,
};

use crate::state::OpenDocument;
use vet_core::comment_syntax::{self, CommentSyntax};

/// Builds code actions (quick-fixes) for vet diagnostics intersecting the given range.
#[must_use]
pub fn actions_for_diagnostics(
    uri: &Url,
    range: &Range,
    diagnostics: &[Diagnostic],
    document: Option<&OpenDocument>,
) -> Vec<CodeActionOrCommand> {
    let Some(document) = document else {
        return Vec::new();
    };

    let vet_diagnostics: Vec<_> = diagnostics
        .iter()
        .filter(|d| is_vet_diagnostic(d) && ranges_intersect(&d.range, range))
        .collect();

    if vet_diagnostics.is_empty() {
        return Vec::new();
    }

    let syntax = comment_syntax::for_language(&document.language_id);
    let mut actions = Vec::new();

    for diagnostic in &vet_diagnostics {
        if let Some(syntax) = &syntax
            && let Some(action) = make_ignore_action(uri, diagnostic, syntax, &document.content)
        {
            actions.push(CodeActionOrCommand::CodeAction(action));
        }

        if let Some(action) = make_ignore_in_config_action(uri, diagnostic) {
            actions.push(CodeActionOrCommand::CodeAction(action));
        }

        if let Some(action) = make_verify_action(uri, diagnostic) {
            actions.push(CodeActionOrCommand::CodeAction(action));
        }
    }

    if let Some(syntax) = &syntax {
        let lines_with_multiple: Vec<u32> = find_lines_with_multiple_diagnostics(&vet_diagnostics);
        for line in lines_with_multiple {
            if let Some(action) = make_ignore_line_action(uri, line, syntax, &document.content) {
                actions.push(CodeActionOrCommand::CodeAction(action));
            }
        }
    }

    actions
}

fn is_vet_diagnostic(diagnostic: &Diagnostic) -> bool {
    diagnostic.source.as_ref().is_some_and(|s| s.as_str() == "vet")
}

fn ranges_intersect(a: &Range, b: &Range) -> bool {
    position_less_or_equal(a.start, b.end) && position_less_or_equal(b.start, a.end)
}

fn position_less_or_equal(a: Position, b: Position) -> bool {
    a.line < b.line || (a.line == b.line && a.character <= b.character)
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "line lengths are always within u32 range for editor content"
)]
fn make_ignore_action(uri: &Url, diagnostic: &Diagnostic, syntax: &CommentSyntax, content: &str) -> Option<CodeAction> {
    let line = diagnostic.range.start.line as usize;
    let line_content = content.lines().nth(line)?;
    let line_end = line_content.len() as u32;

    let pattern_id = match &diagnostic.code {
        Some(tower_lsp::lsp_types::NumberOrString::String(s)) => s.clone(),
        Some(tower_lsp::lsp_types::NumberOrString::Number(n)) => n.to_string(),
        None => "secret".to_string(),
    };

    let ignore_comment = syntax.format_ignore();
    let ignore_text = format!(" {ignore_comment}");
    let edit_position = Position::new(diagnostic.range.start.line, line_end);

    let mut changes = HashMap::new();
    changes.insert(
        uri.clone(),
        vec![TextEdit {
            range: Range::new(edit_position, edit_position),
            new_text: ignore_text,
        }],
    );

    Some(CodeAction {
        title: format!("Ignore {pattern_id} on this line"),
        kind: Some(CodeActionKind::QUICKFIX),
        diagnostics: Some(vec![diagnostic.clone()]),
        edit: Some(WorkspaceEdit {
            changes: Some(changes),
            ..Default::default()
        }),
        is_preferred: Some(false),
        ..Default::default()
    })
}

fn find_lines_with_multiple_diagnostics(diagnostics: &[&Diagnostic]) -> Vec<u32> {
    let mut line_counts: HashMap<u32, usize> = HashMap::new();

    for d in diagnostics {
        *line_counts.entry(d.range.start.line).or_default() += 1;
    }

    line_counts
        .into_iter()
        .filter(|(_, count)| *count > 1)
        .map(|(line, _)| line)
        .collect()
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "line lengths are always within u32 range for editor content"
)]
fn make_ignore_line_action(uri: &Url, line: u32, syntax: &CommentSyntax, content: &str) -> Option<CodeAction> {
    let line_content = content.lines().nth(line as usize)?;
    let line_end = line_content.len() as u32;

    let ignore_comment = syntax.format_ignore();
    let ignore_text = format!(" {ignore_comment}");
    let edit_position = Position::new(line, line_end);

    let mut changes = HashMap::new();
    changes.insert(
        uri.clone(),
        vec![TextEdit {
            range: Range::new(edit_position, edit_position),
            new_text: ignore_text,
        }],
    );

    Some(CodeAction {
        title: "Ignore all secrets on this line".to_string(),
        kind: Some(CodeActionKind::QUICKFIX),
        diagnostics: None,
        edit: Some(WorkspaceEdit {
            changes: Some(changes),
            ..Default::default()
        }),
        is_preferred: Some(false),
        ..Default::default()
    })
}

fn make_ignore_in_config_action(uri: &Url, diagnostic: &Diagnostic) -> Option<CodeAction> {
    let data = diagnostic.data.as_ref()?;
    let fingerprint = data.get("fingerprint")?.as_str()?;

    let pattern_id = match &diagnostic.code {
        Some(tower_lsp::lsp_types::NumberOrString::String(s)) => s.clone(),
        _ => return None,
    };

    Some(CodeAction {
        title: "Ignore in config (.vet.toml)".to_string(),
        kind: Some(CodeActionKind::QUICKFIX),
        diagnostics: Some(vec![diagnostic.clone()]),
        command: Some(Command {
            title: "Ignore in config (.vet.toml)".to_string(),
            command: "vet.ignoreInConfig".to_string(),
            arguments: Some(vec![serde_json::json!({
                "fingerprint": fingerprint,
                "patternId": pattern_id,
                "uri": uri.to_string(),
            })]),
        }),
        is_preferred: Some(false),
        ..Default::default()
    })
}

fn make_verify_action(uri: &Url, diagnostic: &Diagnostic) -> Option<CodeAction> {
    let data = diagnostic.data.as_ref()?;
    let verifiable = data.get("verifiable")?.as_bool()?;

    if !verifiable {
        return None;
    }

    let finding_id = data.get("findingId")?.as_str()?;

    let pattern_id = match &diagnostic.code {
        Some(tower_lsp::lsp_types::NumberOrString::String(s)) => s.clone(),
        _ => return None,
    };

    Some(CodeAction {
        title: "Verify if secret is live".to_string(),
        kind: Some(CodeActionKind::QUICKFIX),
        diagnostics: Some(vec![diagnostic.clone()]),
        command: Some(Command {
            title: "Verify Secret".to_string(),
            command: "vet.verifySecret".to_string(),
            arguments: Some(vec![serde_json::json!({
                "findingId": finding_id,
                "patternId": pattern_id,
                "uri": uri.to_string(),
            })]),
        }),
        is_preferred: Some(false),
        ..Default::default()
    })
}

#[cfg(test)]
#[expect(clippy::panic, reason = "tests use panic for clearer failure messages")]
mod tests {
    use tower_lsp::lsp_types::{DiagnosticSeverity, NumberOrString};

    use super::*;

    fn make_diagnostic(line: u32, start_col: u32, end_col: u32, code: &str) -> Diagnostic {
        Diagnostic {
            range: Range::new(Position::new(line, start_col), Position::new(line, end_col)),
            severity: Some(DiagnosticSeverity::ERROR),
            code: Some(NumberOrString::String(code.to_string())),
            source: Some("vet".to_string()),
            message: format!("Potential secret: {code}"),
            data: Some(serde_json::json!({
                "fingerprint": "sha256:test_fingerprint",
            })),
            ..Default::default()
        }
    }

    fn make_document(content: &str, language_id: &str) -> OpenDocument {
        OpenDocument {
            content: content.to_string(),
            language_id: language_id.into(),
        }
    }

    #[test]
    fn no_actions_without_document() {
        let uri = Url::parse("file:///test.rs").unwrap();
        let range = Range::new(Position::new(0, 0), Position::new(0, 10));
        let diagnostics = vec![make_diagnostic(0, 0, 10, "aws/secret-key")];

        let actions = actions_for_diagnostics(&uri, &range, &diagnostics, None);

        assert!(actions.is_empty());
    }

    #[test]
    fn shows_config_ignore_for_unsupported_language() {
        let uri = Url::parse("file:///test.xyz").unwrap();
        let range = Range::new(Position::new(0, 0), Position::new(0, 10));
        let diagnostics = vec![make_diagnostic(0, 0, 10, "aws/secret-key")];
        let document = make_document("some content", "unknown-language");

        let actions = actions_for_diagnostics(&uri, &range, &diagnostics, Some(&document));

        assert_eq!(actions.len(), 1);
        if let CodeActionOrCommand::CodeAction(action) = &actions[0] {
            assert_eq!(action.title, "Ignore in config (.vet.toml)");
        }
    }

    #[test]
    fn no_actions_when_no_vet_diagnostics() {
        let uri = Url::parse("file:///test.rs").unwrap();
        let range = Range::new(Position::new(0, 0), Position::new(0, 10));
        let mut diagnostic = make_diagnostic(0, 0, 10, "some-error");
        diagnostic.source = Some("other-linter".to_string());
        let document = make_document("let x = 42;", "rust");

        let actions = actions_for_diagnostics(&uri, &range, &[diagnostic], Some(&document));

        assert!(actions.is_empty());
    }

    #[test]
    fn generates_ignore_action_for_rust() {
        let uri = Url::parse("file:///test.rs").unwrap();
        let range = Range::new(Position::new(0, 0), Position::new(0, 30));
        let diagnostics = vec![make_diagnostic(0, 15, 25, "aws/access-key")];
        let document = make_document("let api_key = \"AKIAIOSFODNN7EXAMPLE\";", "rust");

        let actions = actions_for_diagnostics(&uri, &range, &diagnostics, Some(&document));

        assert_eq!(actions.len(), 2);
        if let CodeActionOrCommand::CodeAction(action) = &actions[0] {
            assert!(action.title.contains("aws/access-key"));
            assert_eq!(action.kind, Some(CodeActionKind::QUICKFIX));

            let edit = action.edit.as_ref().unwrap();
            let changes = edit.changes.as_ref().unwrap();
            let text_edits = changes.get(&uri).unwrap();
            assert_eq!(text_edits.len(), 1);
            assert!(text_edits[0].new_text.contains("// vet:ignore"));
        } else {
            panic!("Expected CodeAction");
        }
    }

    #[test]
    fn generates_ignore_action_for_python() {
        let uri = Url::parse("file:///test.py").unwrap();
        let range = Range::new(Position::new(0, 0), Position::new(0, 30));
        let diagnostics = vec![make_diagnostic(0, 10, 20, "generic/api-key")];
        let document = make_document("api_key = \"secret123\"", "python");

        let actions = actions_for_diagnostics(&uri, &range, &diagnostics, Some(&document));

        assert_eq!(actions.len(), 2);
        if let CodeActionOrCommand::CodeAction(action) = &actions[0] {
            let edit = action.edit.as_ref().unwrap();
            let changes = edit.changes.as_ref().unwrap();
            let text_edits = changes.get(&uri).unwrap();
            assert!(text_edits[0].new_text.contains("# vet:ignore"));
        } else {
            panic!("Expected CodeAction");
        }
    }

    #[test]
    fn generates_ignore_action_for_css() {
        let uri = Url::parse("file:///test.css").unwrap();
        let range = Range::new(Position::new(0, 0), Position::new(0, 30));
        let diagnostics = vec![make_diagnostic(0, 10, 20, "generic/secret")];
        let document = make_document("--api-key: \"secret\";", "css");

        let actions = actions_for_diagnostics(&uri, &range, &diagnostics, Some(&document));

        assert_eq!(actions.len(), 2);
        if let CodeActionOrCommand::CodeAction(action) = &actions[0] {
            let edit = action.edit.as_ref().unwrap();
            let changes = edit.changes.as_ref().unwrap();
            let text_edits = changes.get(&uri).unwrap();
            assert!(text_edits[0].new_text.contains("/* vet:ignore */"));
        } else {
            panic!("Expected CodeAction");
        }
    }

    #[test]
    fn edit_position_is_at_line_end() {
        let uri = Url::parse("file:///test.rs").unwrap();
        let range = Range::new(Position::new(0, 0), Position::new(0, 20));
        let diagnostics = vec![make_diagnostic(0, 5, 15, "test/pattern")];
        let content = "let x = \"secret\";";
        let document = make_document(content, "rust");

        let actions = actions_for_diagnostics(&uri, &range, &diagnostics, Some(&document));

        assert_eq!(actions.len(), 2);
        if let CodeActionOrCommand::CodeAction(action) = &actions[0] {
            let edit = action.edit.as_ref().unwrap();
            let changes = edit.changes.as_ref().unwrap();
            let text_edits = changes.get(&uri).unwrap();

            // Should insert at column 17 (end of "let x = \"secret\";")
            #[expect(clippy::cast_possible_truncation, reason = "test string is short, cannot exceed u32")]
            let expected_len = content.len() as u32;
            assert_eq!(text_edits[0].range.start.character, expected_len);
        } else {
            panic!("Expected CodeAction");
        }
    }

    #[test]
    fn multiple_diagnostics_same_line_produces_bulk_action() {
        let uri = Url::parse("file:///test.rs").unwrap();
        let range = Range::new(Position::new(0, 0), Position::new(0, 50));
        let diagnostics = vec![
            make_diagnostic(0, 5, 15, "aws/access-key"),
            make_diagnostic(0, 25, 35, "aws/secret-key"),
        ];
        let document = make_document(
            "let keys = (\"AKIAIOSFODNN7EXAMPLE\", \"wJalrXUtnFEMI/K7MDENG\");",
            "rust",
        );

        let actions = actions_for_diagnostics(&uri, &range, &diagnostics, Some(&document));

        // Should have 2 individual inline ignore actions + 2 config ignore actions + 1 bulk action
        assert_eq!(actions.len(), 5);

        let bulk_action = actions.iter().find(|a| {
            if let CodeActionOrCommand::CodeAction(action) = a {
                action.title.contains("all secrets")
            } else {
                false
            }
        });
        assert!(bulk_action.is_some());
    }

    #[test]
    fn ranges_intersect_same_range() {
        let a = Range::new(Position::new(0, 5), Position::new(0, 10));
        let b = Range::new(Position::new(0, 5), Position::new(0, 10));
        assert!(ranges_intersect(&a, &b));
    }

    #[test]
    fn ranges_intersect_overlapping() {
        let a = Range::new(Position::new(0, 5), Position::new(0, 15));
        let b = Range::new(Position::new(0, 10), Position::new(0, 20));
        assert!(ranges_intersect(&a, &b));
    }

    #[test]
    fn ranges_intersect_contained() {
        let a = Range::new(Position::new(0, 0), Position::new(0, 100));
        let b = Range::new(Position::new(0, 10), Position::new(0, 20));
        assert!(ranges_intersect(&a, &b));
    }

    #[test]
    fn ranges_do_not_intersect() {
        let a = Range::new(Position::new(0, 0), Position::new(0, 5));
        let b = Range::new(Position::new(0, 10), Position::new(0, 15));
        assert!(!ranges_intersect(&a, &b));
    }

    #[test]
    fn ranges_on_different_lines_do_not_intersect() {
        let a = Range::new(Position::new(0, 0), Position::new(0, 100));
        let b = Range::new(Position::new(1, 0), Position::new(1, 100));
        assert!(!ranges_intersect(&a, &b));
    }

    #[test]
    fn is_vet_diagnostic_true() {
        let diagnostic = make_diagnostic(0, 0, 10, "test");
        assert!(is_vet_diagnostic(&diagnostic));
    }

    #[test]
    fn is_vet_diagnostic_false_for_other_source() {
        let mut diagnostic = make_diagnostic(0, 0, 10, "test");
        diagnostic.source = Some("eslint".to_string());
        assert!(!is_vet_diagnostic(&diagnostic));
    }

    #[test]
    fn is_vet_diagnostic_false_for_no_source() {
        let mut diagnostic = make_diagnostic(0, 0, 10, "test");
        diagnostic.source = None;
        assert!(!is_vet_diagnostic(&diagnostic));
    }
}
