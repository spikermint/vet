//! AST-powered generic secret detection using tree-sitter.
//!
//! This module detects hardcoded secrets assigned to variables with names like
//! `password`, `secret`, `api_key`, and `token`. Unlike the regex pipeline, it
//! uses tree-sitter to parse source files into an abstract syntax tree, then
//! runs structural queries to find string literal assignments. This lowers the
//! risk of false positives because the AST structurally distinguishes string
//! literals from function calls, variable references, and comments.
//!
//! `.env` files are handled separately with a regex (no AST needed - every
//! value is a literal). Unsupported languages are skipped entirely.
//!
//! # Architecture
//!
//! ```text
//! Aho-Corasick keyword hit for generic pattern
//!   │
//!   ├─ .env file?   → regex extraction
//!   ├─ Supported source code? → tree-sitter parse → AST query → findings
//!   └─ Unsupported? → skip (no detection beats false positives)
//! ```

mod dotenv;
pub mod trigger;
mod validator;

use std::path::Path;
use std::sync::Arc;

pub use validator::SourceLanguage;

/// A generic secret finding extracted by AST or `.env` analysis.
#[derive(Debug, Clone)]
pub struct AstFinding {
    /// Pattern ID (e.g. `generic/password-assignment`).
    pub pattern_id: Arc<str>,
    /// Variable or key name that triggered the match.
    pub variable_name: String,
    /// The string literal value (potential secret).
    pub secret_value: String,
    /// Byte offset of the value start in the original content.
    pub byte_start: usize,
    /// Byte offset of the value end in the original content.
    pub byte_end: usize,
}

/// Detects the source language from a file path extension.
///
/// Returns `None` for unsupported or unrecognised extensions.
#[must_use]
pub fn detect_language(path: &Path) -> Option<SourceLanguage> {
    let ext = path.extension()?.to_str()?;
    match ext {
        "py" => Some(SourceLanguage::Python),
        "js" | "jsx" | "mjs" | "cjs" => Some(SourceLanguage::JavaScript),
        "ts" | "tsx" => Some(SourceLanguage::TypeScript),
        "go" => Some(SourceLanguage::Go),
        "rb" => Some(SourceLanguage::Ruby),
        "java" => Some(SourceLanguage::Java),
        "rs" => Some(SourceLanguage::Rust),
        _ => None,
    }
}

/// Returns `true` if the path represents a `.env` file.
///
/// Matches `.env`, `.env.local`, `.env.production`, etc.
#[must_use]
pub fn is_dotenv_file(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    file_name == ".env" || file_name.starts_with(".env.")
}

/// Extracts generic secret findings from a file.
///
/// Routes to AST parsing (source code) or regex (`.env` files) depending on
/// the file type. Returns an empty vec for unsupported file types.
#[must_use]
pub fn extract_generic_findings(
    content: &[u8],
    path: &Path,
    trigger_groups: &[trigger::TriggerWordGroup],
) -> Vec<AstFinding> {
    if is_dotenv_file(path) {
        let Ok(text) = std::str::from_utf8(content) else {
            return Vec::new();
        };
        return dotenv::extract_dotenv_findings(text, trigger_groups);
    }

    if let Some(language) = detect_language(path) {
        return validator::extract_ast_findings(content, language, trigger_groups);
    }

    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_language_python() {
        assert_eq!(detect_language(Path::new("app.py")), Some(SourceLanguage::Python));
    }

    #[test]
    fn detect_language_javascript_variants() {
        assert_eq!(detect_language(Path::new("app.js")), Some(SourceLanguage::JavaScript));
        assert_eq!(detect_language(Path::new("app.jsx")), Some(SourceLanguage::JavaScript));
        assert_eq!(detect_language(Path::new("app.mjs")), Some(SourceLanguage::JavaScript));
        assert_eq!(detect_language(Path::new("app.cjs")), Some(SourceLanguage::JavaScript));
    }

    #[test]
    fn detect_language_typescript_variants() {
        assert_eq!(detect_language(Path::new("app.ts")), Some(SourceLanguage::TypeScript));
        assert_eq!(detect_language(Path::new("app.tsx")), Some(SourceLanguage::TypeScript));
    }

    #[test]
    fn detect_language_go() {
        assert_eq!(detect_language(Path::new("main.go")), Some(SourceLanguage::Go));
    }

    #[test]
    fn detect_language_ruby() {
        assert_eq!(detect_language(Path::new("config.rb")), Some(SourceLanguage::Ruby));
    }

    #[test]
    fn detect_language_java() {
        assert_eq!(detect_language(Path::new("Config.java")), Some(SourceLanguage::Java));
    }

    #[test]
    fn detect_language_rust() {
        assert_eq!(detect_language(Path::new("main.rs")), Some(SourceLanguage::Rust));
    }

    #[test]
    fn detect_language_unsupported_returns_none() {
        assert_eq!(detect_language(Path::new("script.sh")), None);
        assert_eq!(detect_language(Path::new("style.css")), None);
        assert_eq!(detect_language(Path::new("README.md")), None);
    }

    #[test]
    fn detect_language_no_extension_returns_none() {
        assert_eq!(detect_language(Path::new("Makefile")), None);
    }

    #[test]
    fn is_dotenv_file_matches_plain_env() {
        assert!(is_dotenv_file(Path::new(".env")));
    }

    #[test]
    fn is_dotenv_file_matches_env_variants() {
        assert!(is_dotenv_file(Path::new(".env.local")));
        assert!(is_dotenv_file(Path::new(".env.production")));
        assert!(is_dotenv_file(Path::new(".env.development")));
    }

    #[test]
    fn is_dotenv_file_rejects_non_env() {
        assert!(!is_dotenv_file(Path::new("config.env")));
        assert!(!is_dotenv_file(Path::new("env")));
        assert!(!is_dotenv_file(Path::new(".envrc")));
    }

    #[test]
    fn extract_generic_findings_routes_to_dotenv() {
        let groups = vec![trigger::TriggerWordGroup::from_static(
            "generic/password-assignment",
            &["password"],
        )];
        let content = b"DB_PASSWORD=a8Kj2mNx9pQ4rT7v\n";
        let findings = extract_generic_findings(content, Path::new(".env"), &groups);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn extract_generic_findings_routes_to_ast_for_python() {
        let groups = vec![trigger::TriggerWordGroup::from_static(
            "generic/password-assignment",
            &["password"],
        )];
        let content = b"password = \"a8Kj2mNx9pQ4rT7v\"";
        let findings = extract_generic_findings(content, Path::new("config.py"), &groups);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn extract_generic_findings_skips_unsupported_language() {
        let groups = vec![trigger::TriggerWordGroup::from_static(
            "generic/password-assignment",
            &["password"],
        )];
        let content = b"password = \"a8Kj2mNx9pQ4rT7v\"";
        let findings = extract_generic_findings(content, Path::new("script.sh"), &groups);
        assert!(findings.is_empty());
    }
}
