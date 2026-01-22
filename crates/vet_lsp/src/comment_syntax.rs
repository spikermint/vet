#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommentSyntax {
    Line(&'static str),
    Block(&'static str, &'static str),
}

impl CommentSyntax {
    #[must_use]
    pub fn format_ignore(&self) -> String {
        match self {
            Self::Line(prefix) => format!("{prefix} vet:ignore"),
            Self::Block(start, end) => format!("{start} vet:ignore {end}"),
        }
    }
}

#[must_use]
pub fn for_language(language_id: &str) -> Option<CommentSyntax> {
    match language_id {
        // C-style line comments
        "c" | "cpp" | "csharp" | "fsharp" | "go" | "groovy" | "java" | "javascript" | "javascriptreact" | "jsonc"
        | "kotlin" | "objective-c" | "objective-cpp" | "php" | "rust" | "scala" | "swift" | "typescript"
        | "typescriptreact" | "zig" | "dart" | "proto" | "proto3" | "v" | "odin" => Some(CommentSyntax::Line("//")),

        // Hash comments
        "coffeescript" | "dockerfile" | "elixir" | "gitignore" | "julia" | "makefile" | "nim" | "perl" | "perl6"
        | "powershell" | "python" | "r" | "ruby" | "shellscript" | "tcl" | "toml" | "yaml" | "fish" | "nix"
        | "crystal" => Some(CommentSyntax::Line("#")),

        // Double-dash comments
        "haskell" | "lua" | "sql" | "plsql" | "ada" | "elm" | "purescript" | "vhdl" => Some(CommentSyntax::Line("--")),

        // Semicolon comments
        "clojure" | "lisp" | "scheme" | "racket" | "asm" | "ini" | "properties" => Some(CommentSyntax::Line(";")),

        // Percent comments
        "bibtex" | "erlang" | "latex" | "matlab" | "tex" | "prolog" => Some(CommentSyntax::Line("%")),

        // Apostrophe comments
        "vb" | "vba" => Some(CommentSyntax::Line("'")),

        // Block comments only (no single-line syntax)
        "css" | "scss" | "less" => Some(CommentSyntax::Block("/*", "*/")),
        "html" | "xml" | "xsl" | "svg" | "vue" | "svelte" | "astro" | "markdown" => {
            Some(CommentSyntax::Block("<!--", "-->"))
        }

        // Unsupported or unknown
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_comment_format() {
        let syntax = CommentSyntax::Line("//");
        assert_eq!(syntax.format_ignore(), "// vet:ignore");
    }

    #[test]
    fn hash_comment_format() {
        let syntax = CommentSyntax::Line("#");
        assert_eq!(syntax.format_ignore(), "# vet:ignore");
    }

    #[test]
    fn block_comment_format() {
        let syntax = CommentSyntax::Block("/*", "*/");
        assert_eq!(syntax.format_ignore(), "/* vet:ignore */");
    }

    #[test]
    fn html_comment_format() {
        let syntax = CommentSyntax::Block("<!--", "-->");
        assert_eq!(syntax.format_ignore(), "<!-- vet:ignore -->");
    }

    #[test]
    fn rust_uses_double_slash() {
        assert_eq!(for_language("rust"), Some(CommentSyntax::Line("//")));
    }

    #[test]
    fn python_uses_hash() {
        assert_eq!(for_language("python"), Some(CommentSyntax::Line("#")));
    }

    #[test]
    fn sql_uses_double_dash() {
        assert_eq!(for_language("sql"), Some(CommentSyntax::Line("--")));
    }

    #[test]
    fn css_uses_block_comment() {
        assert_eq!(for_language("css"), Some(CommentSyntax::Block("/*", "*/")));
    }

    #[test]
    fn html_uses_xml_comment() {
        assert_eq!(for_language("html"), Some(CommentSyntax::Block("<!--", "-->")));
    }

    #[test]
    fn unknown_language_returns_none() {
        assert_eq!(for_language("unknown-lang-xyz"), None);
    }

    #[test]
    fn typescript_react_supported() {
        assert_eq!(for_language("typescriptreact"), Some(CommentSyntax::Line("//")));
    }

    #[test]
    fn shellscript_uses_hash() {
        assert_eq!(for_language("shellscript"), Some(CommentSyntax::Line("#")));
    }

    #[test]
    fn yaml_uses_hash() {
        assert_eq!(for_language("yaml"), Some(CommentSyntax::Line("#")));
    }

    #[test]
    fn dockerfile_uses_hash() {
        assert_eq!(for_language("dockerfile"), Some(CommentSyntax::Line("#")));
    }

    #[test]
    fn lisp_uses_semicolon() {
        assert_eq!(for_language("lisp"), Some(CommentSyntax::Line(";")));
    }

    #[test]
    fn latex_uses_percent() {
        assert_eq!(for_language("latex"), Some(CommentSyntax::Line("%")));
    }

    #[test]
    fn vb_uses_apostrophe() {
        assert_eq!(for_language("vb"), Some(CommentSyntax::Line("'")));
    }
}
