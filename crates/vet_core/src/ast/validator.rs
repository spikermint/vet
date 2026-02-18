//! Core AST validation logic using tree-sitter.
//!
//! Parses source files with language-specific grammars and runs queries to
//! extract string literal assignments where the variable name matches a
//! trigger word.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

use tree_sitter::{Language, Parser, Query, QueryCursor, StreamingIterator as _};

use super::AstFinding;
use super::trigger::{TriggerWordGroup, matches_trigger};

/// Supported source languages for AST-based detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceLanguage {
    /// Python (.py)
    Python,
    /// `JavaScript` - `.js`, `.jsx`, `.mjs`, `.cjs`
    JavaScript,
    /// `TypeScript` - `.ts`, `.tsx`
    TypeScript,
    /// Go (.go)
    Go,
    /// Ruby (.rb)
    Ruby,
    /// Java (.java)
    Java,
    /// Rust (.rs)
    Rust,
}

impl SourceLanguage {
    /// Returns the tree-sitter `Language` for this source language.
    fn tree_sitter_language(self) -> Language {
        match self {
            Self::Python => tree_sitter_python::LANGUAGE.into(),
            Self::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Self::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Self::Go => tree_sitter_go::LANGUAGE.into(),
            Self::Ruby => tree_sitter_ruby::LANGUAGE.into(),
            Self::Java => tree_sitter_java::LANGUAGE.into(),
            Self::Rust => tree_sitter_rust::LANGUAGE.into(),
        }
    }

    /// Returns the tree-sitter query source for this language.
    fn query_source(self) -> &'static str {
        match self {
            Self::Python => include_str!("queries/python.scm"),
            Self::JavaScript => include_str!("queries/javascript.scm"),
            Self::TypeScript => include_str!("queries/typescript.scm"),
            Self::Go => include_str!("queries/go.scm"),
            Self::Ruby => include_str!("queries/ruby.scm"),
            Self::Java => include_str!("queries/java.scm"),
            Self::Rust => include_str!("queries/rust.scm"),
        }
    }
}

// Thread-local storage for tree-sitter parsers (one per language).
// `tree_sitter::Parser` is not `Send`, so each thread gets its own instance.
thread_local! {
    static PARSERS: RefCell<HashMap<SourceLanguage, Parser>> = RefCell::new(HashMap::new());
}

/// Extracts generic findings from a source file using tree-sitter AST queries.
///
/// Parses the content with the appropriate grammar, runs queries to find all
/// string literal assignments, and checks variable names against trigger words.
pub fn extract_ast_findings(
    content: &[u8],
    language: SourceLanguage,
    trigger_groups: &[TriggerWordGroup],
) -> Vec<AstFinding> {
    let ts_language = language.tree_sitter_language();

    let tree = PARSERS.with(|parsers| {
        let mut parsers = parsers.borrow_mut();
        let parser = parsers.entry(language).or_insert_with(|| {
            let mut p = Parser::new();
            #[expect(clippy::expect_used, reason = "grammar is compiled into the binary and always valid")]
            p.set_language(&ts_language)
                .expect("built-in grammar should always be loadable");
            p
        });

        parser.parse(content, None)
    });

    let Some(tree) = tree else {
        return Vec::new();
    };

    let Ok(query) = Query::new(&ts_language, language.query_source()) else {
        return Vec::new();
    };

    let Some(name_idx) = query.capture_index_for_name("name") else {
        return Vec::new();
    };
    let Some(value_idx) = query.capture_index_for_name("value") else {
        return Vec::new();
    };

    let mut cursor = QueryCursor::new();
    let mut findings = Vec::new();

    let mut matches = cursor.matches(&query, tree.root_node(), content);
    while let Some(m) = matches.next() {
        let mut name_text: Option<&str> = None;
        let mut value_text: Option<&str> = None;
        let mut value_start: usize = 0;
        let mut value_end: usize = 0;

        for capture in m.captures {
            let node = capture.node;
            let Ok(text) = std::str::from_utf8(&content[node.byte_range()]) else {
                continue;
            };

            if capture.index == name_idx {
                name_text = Some(text);
            } else if capture.index == value_idx {
                value_text = Some(text);
                value_start = node.start_byte();
                value_end = node.end_byte();
            }
        }

        let (Some(name), Some(value)) = (name_text, value_text) else {
            continue;
        };

        // Strip surrounding quotes - dict/map/hash keys capture the full
        // string node (e.g. `"password"`) while identifiers have no quotes.
        let clean_name = strip_string_quotes(name);
        let clean_value = strip_string_quotes(value);

        if clean_value.len() < 8 || clean_value.len() > 120 {
            continue;
        }

        for group in trigger_groups {
            if matches_trigger(clean_name, group) {
                findings.push(AstFinding {
                    pattern_id: Arc::clone(&group.pattern_id),
                    variable_name: clean_name.to_string(),
                    secret_value: clean_value.to_string(),
                    byte_start: value_start,
                    byte_end: value_end,
                });
                break;
            }
        }
    }

    findings
}

/// Strips matching surrounding quotes from a captured string value.
///
/// Some grammars capture the full string node including quotes (e.g. Go's
/// `interpreted_string_literal` includes the `"` delimiters). Others capture
/// only the inner content (e.g. Python's `string_content`). This function
/// handles both cases by stripping matching `"`, `'`, or `` ` `` pairs.
fn strip_string_quotes(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.len() >= 2 && matches!(bytes[0], b'"' | b'\'' | b'`') && bytes[0] == bytes[bytes.len() - 1] {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn password_group() -> TriggerWordGroup {
        TriggerWordGroup::from_static("generic/password-assignment", &["password", "passwd", "pwd"])
    }

    fn secret_group() -> TriggerWordGroup {
        TriggerWordGroup::from_static("generic/secret-assignment", &["secret", "credential"])
    }

    fn token_group() -> TriggerWordGroup {
        TriggerWordGroup::from_static(
            "generic/token-assignment",
            &["token", "access_token", "auth_token", "bearer_token", "refresh_token"],
        )
    }

    fn groups() -> Vec<TriggerWordGroup> {
        vec![password_group(), secret_group(), token_group()]
    }

    // Python tests

    #[test]
    fn python_simple_assignment_detected() {
        let code = b"password = \"a8Kj2mNx9pQ4rT7v\"";
        let findings = extract_ast_findings(code, SourceLanguage::Python, &groups());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pattern_id.as_ref(), "generic/password-assignment");
        assert_eq!(findings[0].secret_value, "a8Kj2mNx9pQ4rT7v");
    }

    #[test]
    fn python_function_call_not_detected() {
        let code = b"password = decrypt(\"a8Kj2mNx9pQ4rT7v\")";
        let findings = extract_ast_findings(code, SourceLanguage::Python, &groups());
        assert!(findings.is_empty());
    }

    #[test]
    fn python_variable_reference_not_detected() {
        let code = b"password = config.db.credential";
        let findings = extract_ast_findings(code, SourceLanguage::Python, &groups());
        assert!(findings.is_empty());
    }

    #[test]
    fn python_attribute_assignment_detected() {
        let code = b"self.password = \"a8Kj2mNx9pQ4rT7v\"";
        let findings = extract_ast_findings(code, SourceLanguage::Python, &groups());
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn python_dict_literal_detected() {
        let code = b"config = {\"password\": \"a8Kj2mNx9pQ4rT7v\"}";
        let findings = extract_ast_findings(code, SourceLanguage::Python, &groups());
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn python_keyword_argument_detected() {
        let code = b"db.connect(password=\"a8Kj2mNx9pQ4rT7v\")";
        let findings = extract_ast_findings(code, SourceLanguage::Python, &groups());
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn python_comparison_not_detected() {
        let code = b"if password == \"a8Kj2mNx9pQ4rT7v\": pass";
        let findings = extract_ast_findings(code, SourceLanguage::Python, &groups());
        assert!(findings.is_empty());
    }

    #[test]
    fn python_comment_not_detected() {
        let code = b"# password = \"a8Kj2mNx9pQ4rT7v\"";
        let findings = extract_ast_findings(code, SourceLanguage::Python, &groups());
        assert!(findings.is_empty());
    }

    #[test]
    fn python_none_assignment_not_detected() {
        let code = b"password = None";
        let findings = extract_ast_findings(code, SourceLanguage::Python, &groups());
        assert!(findings.is_empty());
    }

    #[test]
    fn python_short_value_skipped() {
        let code = b"password = \"short\"";
        let findings = extract_ast_findings(code, SourceLanguage::Python, &groups());
        assert!(findings.is_empty());
    }

    // JavaScript tests

    #[test]
    fn javascript_const_declaration_detected() {
        let code = b"const password = \"a8Kj2mNx9pQ4rT7v\";";
        let findings = extract_ast_findings(code, SourceLanguage::JavaScript, &groups());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pattern_id.as_ref(), "generic/password-assignment");
    }

    #[test]
    fn javascript_object_property_detected() {
        let code = b"const config = { password: \"a8Kj2mNx9pQ4rT7v\" };";
        let findings = extract_ast_findings(code, SourceLanguage::JavaScript, &groups());
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn javascript_function_call_not_detected() {
        let code = b"const password = decrypt(\"a8Kj2mNx9pQ4rT7v\");";
        let findings = extract_ast_findings(code, SourceLanguage::JavaScript, &groups());
        assert!(findings.is_empty());
    }

    #[test]
    fn javascript_member_assignment_detected() {
        let code = b"config.password = \"a8Kj2mNx9pQ4rT7v\";";
        let findings = extract_ast_findings(code, SourceLanguage::JavaScript, &groups());
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn javascript_camel_case_token_detected() {
        let code = b"const authToken = \"cX2mN8pQ4rT7vB5wK3eR\";";
        let findings = extract_ast_findings(code, SourceLanguage::JavaScript, &groups());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pattern_id.as_ref(), "generic/token-assignment");
    }

    #[test]
    fn javascript_camel_case_access_token_detected() {
        let code = b"const accessToken = \"fT9nR2mK7jQ4vB8wP3xL\";";
        let findings = extract_ast_findings(code, SourceLanguage::JavaScript, &groups());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pattern_id.as_ref(), "generic/token-assignment");
    }

    // Go tests

    #[test]
    fn go_short_var_declaration_detected() {
        let code = b"package main\nfunc main() {\n\tpassword := \"a8Kj2mNx9pQ4rT7v\"\n}";
        let findings = extract_ast_findings(code, SourceLanguage::Go, &groups());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].secret_value, "a8Kj2mNx9pQ4rT7v");
    }

    #[test]
    fn go_map_literal_string_key_detected() {
        let code = b"package main\nfunc main() {\n\tconfig := map[string]string{\n\t\t\"password\": \"gM4nR8vP2jL9nQ5wK3bT\",\n\t}\n}";
        let findings = extract_ast_findings(code, SourceLanguage::Go, &groups());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].variable_name, "password");
        assert_eq!(findings[0].secret_value, "gM4nR8vP2jL9nQ5wK3bT");
    }

    #[test]
    fn go_function_call_not_detected() {
        let code = b"package main\nfunc main() {\n\tpassword := decrypt(\"a8Kj2mNx9pQ4rT7v\")\n}";
        let findings = extract_ast_findings(code, SourceLanguage::Go, &groups());
        assert!(findings.is_empty());
    }

    // Rust tests

    #[test]
    fn rust_let_declaration_detected() {
        let code = b"fn main() {\n    let password = \"a8Kj2mNx9pQ4rT7v\";\n}";
        let findings = extract_ast_findings(code, SourceLanguage::Rust, &groups());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pattern_id.as_ref(), "generic/password-assignment");
    }

    #[test]
    fn rust_function_call_not_detected() {
        let code = b"fn main() {\n    let password = decrypt(\"a8Kj2mNx9pQ4rT7v\");\n}";
        let findings = extract_ast_findings(code, SourceLanguage::Rust, &groups());
        assert!(findings.is_empty());
    }

    // Java tests

    #[test]
    fn java_local_variable_detected() {
        let code = b"class Main {\n    void run() {\n        String password = \"a8Kj2mNx9pQ4rT7v\";\n    }\n}";
        let findings = extract_ast_findings(code, SourceLanguage::Java, &groups());
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn java_field_declaration_detected() {
        let code = b"class Config {\n    private String password = \"a8Kj2mNx9pQ4rT7v\";\n}";
        let findings = extract_ast_findings(code, SourceLanguage::Java, &groups());
        assert_eq!(findings.len(), 1);
    }

    // Ruby tests

    #[test]
    fn ruby_simple_assignment_detected() {
        let code = b"password = \"a8Kj2mNx9pQ4rT7v\"";
        let findings = extract_ast_findings(code, SourceLanguage::Ruby, &groups());
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ruby_hash_symbol_key_detected() {
        let code = b"config = { password: \"a8Kj2mNx9pQ4rT7v\" }";
        let findings = extract_ast_findings(code, SourceLanguage::Ruby, &groups());
        assert_eq!(findings.len(), 1);
    }

    // TypeScript tests

    #[test]
    fn typescript_const_declaration_detected() {
        let code = b"const password: string = \"a8Kj2mNx9pQ4rT7v\";";
        let findings = extract_ast_findings(code, SourceLanguage::TypeScript, &groups());
        assert_eq!(findings.len(), 1);
    }

    // Cross-language tests

    #[test]
    fn multiple_trigger_groups_produce_separate_findings() {
        let code = b"password = \"a8Kj2mNx9pQ4rT7v\"\nsecret = \"xK9mN2pQ4rT7vB5c\"";
        let findings = extract_ast_findings(code, SourceLanguage::Python, &groups());
        assert_eq!(findings.len(), 2);

        let ids: Vec<&str> = findings.iter().map(|f| f.pattern_id.as_ref()).collect();
        assert!(ids.contains(&"generic/password-assignment"));
        assert!(ids.contains(&"generic/secret-assignment"));
    }

    #[test]
    fn empty_content_returns_no_findings() {
        let findings = extract_ast_findings(b"", SourceLanguage::Python, &groups());
        assert!(findings.is_empty());
    }

    #[test]
    fn non_trigger_variable_not_detected() {
        let code = b"username = \"a8Kj2mNx9pQ4rT7v\"";
        let findings = extract_ast_findings(code, SourceLanguage::Python, &groups());
        assert!(findings.is_empty());
    }
}
