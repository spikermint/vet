//! Server state management.
//!
//! Maintains the runtime state of the language server including scanner,
//! workspace configuration, and open documents.

use std::collections::HashMap;
use std::path::PathBuf;

use globset::GlobSet;
use ignore::gitignore::Gitignore;
use tower_lsp::lsp_types::{Diagnostic, Url};
use vet_core::prelude::*;

#[derive(Debug, Clone)]
pub struct OpenDocument {
    pub content: String,
    pub language_id: String,
}

impl OpenDocument {
    #[must_use]
    pub fn new(content: String, language_id: String) -> Self {
        Self { content, language_id }
    }

    #[must_use]
    pub fn extract_range(&self, line: u32, start_char: u32, end_char: u32) -> Option<String> {
        let line_content = self.content.lines().nth(line as usize)?;
        let chars: Vec<char> = line_content.chars().collect();

        let start = start_char as usize;
        let end = end_char as usize;

        if start > chars.len() || end > chars.len() || start > end {
            return None;
        }

        Some(chars[start..end].iter().collect())
    }
}

pub struct ServerState {
    pub scanner: Option<Scanner>,
    pub workspace_roots: Vec<PathBuf>,
    pub config: Option<Config>,
    pub exclude_matcher: Option<GlobSet>,
    pub gitignore: Option<Gitignore>,
    pub respect_gitignore: bool,
    pub include_low_confidence_override: Option<bool>,
    pub open_documents: HashMap<Url, OpenDocument>,
    pub diagnostics: HashMap<Url, Vec<Diagnostic>>,
}

impl ServerState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            scanner: None,
            workspace_roots: Vec::new(),
            config: None,
            exclude_matcher: None,
            gitignore: None,
            respect_gitignore: true,
            include_low_confidence_override: None,
            open_documents: HashMap::new(),
            diagnostics: HashMap::new(),
        }
    }

    #[must_use]
    pub fn includes_low_confidence_findings(&self) -> bool {
        if let Some(override_val) = self.include_low_confidence_override {
            return override_val;
        }

        self.config.as_ref().is_some_and(|c| c.include_low_confidence)
    }

    #[must_use]
    pub fn primary_workspace_root(&self) -> Option<&PathBuf> {
        self.workspace_roots.first()
    }

    #[must_use]
    pub fn get_document(&self, uri: &Url) -> Option<&OpenDocument> {
        self.open_documents.get(uri)
    }

    #[must_use]
    pub fn get_diagnostics(&self, uri: &Url) -> Option<&[Diagnostic]> {
        self.diagnostics.get(uri).map(Vec::as_slice)
    }
}

impl Default for ServerState {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ServerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerState")
            .field("scanner", &self.scanner.as_ref().map(|_| "Scanner"))
            .field("workspace_roots", &self.workspace_roots)
            .field("config", &self.config)
            .field("respect_gitignore", &self.respect_gitignore)
            .field("open_documents", &self.open_documents.len())
            .field("diagnostics", &self.diagnostics.len())
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use tower_lsp::lsp_types::{DiagnosticSeverity, Position, Range};

    use super::*;

    fn make_diagnostic(line: u32, code: &str) -> Diagnostic {
        Diagnostic {
            range: Range::new(Position::new(line, 0), Position::new(line, 10)),
            severity: Some(DiagnosticSeverity::ERROR),
            code: Some(tower_lsp::lsp_types::NumberOrString::String(code.to_string())),
            source: Some("vet".to_string()),
            message: format!("Potential secret: {code}"),
            ..Default::default()
        }
    }

    #[test]
    fn default_state_respects_gitignore() {
        let state = ServerState::new();
        assert!(state.respect_gitignore);
    }

    #[test]
    fn default_state_has_no_gitignore_matcher() {
        let state = ServerState::new();
        assert!(state.gitignore.is_none());
    }

    #[test]
    fn no_config_means_no_low_confidence() {
        let state = ServerState::new();
        assert!(!state.includes_low_confidence_findings());
    }

    #[test]
    fn config_controls_low_confidence() {
        let mut state = ServerState::new();
        let config = Config {
            include_low_confidence: true,
            ..Default::default()
        };
        state.config = Some(config);

        assert!(state.includes_low_confidence_findings());
    }

    #[test]
    fn override_beats_config() {
        let mut state = ServerState::new();
        let config = Config {
            include_low_confidence: true,
            ..Default::default()
        };
        state.config = Some(config);
        state.include_low_confidence_override = Some(false);

        assert!(!state.includes_low_confidence_findings());
    }

    #[test]
    fn primary_workspace_root_returns_first() {
        let mut state = ServerState::new();
        state.workspace_roots = vec![PathBuf::from("/project-a"), PathBuf::from("/project-b")];

        assert_eq!(state.primary_workspace_root(), Some(&PathBuf::from("/project-a")));
    }

    #[test]
    fn primary_workspace_root_none_when_empty() {
        let state = ServerState::new();
        assert!(state.primary_workspace_root().is_none());
    }

    #[test]
    fn get_document_returns_none_for_missing() {
        let state = ServerState::new();
        let uri = Url::parse("file:///test.rs").unwrap();
        assert!(state.get_document(&uri).is_none());
    }

    #[test]
    fn get_document_returns_document() {
        let mut state = ServerState::new();
        let uri = Url::parse("file:///test.rs").unwrap();
        state.open_documents.insert(
            uri.clone(),
            OpenDocument::new("content".to_string(), "rust".to_string()),
        );

        let doc = state.get_document(&uri).expect("document should exist");
        assert_eq!(doc.content, "content");
        assert_eq!(doc.language_id, "rust");
    }

    #[test]
    fn get_diagnostics_returns_none_for_missing() {
        let state = ServerState::new();
        let uri = Url::parse("file:///test.rs").unwrap();
        assert!(state.get_diagnostics(&uri).is_none());
    }

    #[test]
    fn get_diagnostics_returns_diagnostics() {
        let mut state = ServerState::new();
        let uri = Url::parse("file:///test.rs").unwrap();
        let diagnostics = vec![make_diagnostic(0, "aws/access-key")];
        state.diagnostics.insert(uri.clone(), diagnostics);

        let result = state.get_diagnostics(&uri).expect("diagnostics should exist");
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn debug_format_includes_gitignore_info() {
        let state = ServerState::new();
        let debug = format!("{:?}", state);
        assert!(debug.contains("respect_gitignore"));
    }
}
