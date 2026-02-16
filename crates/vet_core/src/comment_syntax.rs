//! Language-aware comment syntax for ignore markers.
//!
//! Used by both the LSP (via language ID) and CLI (via file extension).

use std::path::Path;

/// The marker text that indicates a line should be ignored.
pub const IGNORE_MARKER: &str = "vet:ignore";

/// Comment syntax used by a programming language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommentSyntax {
    /// Single-line comment with a prefix (e.g. `//`, `#`, `--`).
    Line(&'static str),
    /// Block comment with start and end delimiters (e.g. `/*` … `*/`).
    Block(&'static str, &'static str),
}

impl CommentSyntax {
    /// Formats a `vet:ignore` marker using this language's comment syntax.
    #[must_use]
    pub fn format_ignore(&self) -> String {
        match self {
            Self::Line(prefix) => format!("{prefix} vet:ignore"),
            Self::Block(start, end) => format!("{start} vet:ignore {end}"),
        }
    }
}

/// Returns the comment syntax for a VS Code language identifier (e.g. `"rust"`, `"python"`).
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

        _ => None,
    }
}

/// Returns the comment syntax for a file path, derived from its extension.
#[must_use]
pub fn for_path(path: &Path) -> Option<CommentSyntax> {
    let ext = path.extension()?.to_str()?;
    for_extension(ext)
}

/// Returns the comment syntax for a file extension (e.g. `"rs"`, `"py"`).
#[must_use]
pub fn for_extension(ext: &str) -> Option<CommentSyntax> {
    let language_id = extension_to_language_id(ext)?;
    for_language(language_id)
}

fn extension_to_language_id(ext: &str) -> Option<&'static str> {
    match ext.to_lowercase().as_str() {
        // C-style
        "c" | "h" => Some("c"),
        "cpp" | "cc" | "cxx" | "hpp" | "hxx" | "hh" => Some("cpp"),
        "cs" => Some("csharp"),
        "fs" | "fsx" | "fsi" => Some("fsharp"),
        "go" => Some("go"),
        "groovy" | "gradle" => Some("groovy"),
        "java" => Some("java"),
        "js" | "mjs" | "cjs" => Some("javascript"),
        "jsx" => Some("javascriptreact"),
        "kt" | "kts" => Some("kotlin"),
        "m" => Some("objective-c"),
        "mm" => Some("objective-cpp"),
        "php" => Some("php"),
        "rs" => Some("rust"),
        "scala" | "sc" => Some("scala"),
        "swift" => Some("swift"),
        "ts" | "mts" | "cts" => Some("typescript"),
        "tsx" => Some("typescriptreact"),
        "zig" => Some("zig"),
        "dart" => Some("dart"),
        "proto" => Some("proto"),
        "v" => Some("v"),
        "odin" => Some("odin"),

        // Hash comments
        "coffee" => Some("coffeescript"),
        "ex" | "exs" => Some("elixir"),
        "jl" => Some("julia"),
        "nim" | "nims" => Some("nim"),
        "pl" | "pm" => Some("perl"),
        "p6" | "pm6" | "raku" => Some("perl6"),
        "ps1" | "psm1" | "psd1" => Some("powershell"),
        "py" | "pyw" | "pyi" => Some("python"),
        "r" => Some("r"),
        "rb" | "rake" | "gemspec" => Some("ruby"),
        "sh" | "bash" | "zsh" | "ksh" => Some("shellscript"),
        "tcl" => Some("tcl"),
        "toml" => Some("toml"),
        "yml" | "yaml" => Some("yaml"),
        "fish" => Some("fish"),
        "nix" => Some("nix"),
        "cr" => Some("crystal"),

        // Double-dash comments
        "hs" | "lhs" => Some("haskell"),
        "lua" => Some("lua"),
        "sql" => Some("sql"),
        "ada" | "adb" | "ads" => Some("ada"),
        "elm" => Some("elm"),
        "purs" => Some("purescript"),
        "vhd" | "vhdl" => Some("vhdl"),

        // Semicolon comments
        "clj" | "cljs" | "cljc" | "edn" => Some("clojure"),
        "lisp" | "lsp" | "cl" => Some("lisp"),
        "scm" | "ss" => Some("scheme"),
        "rkt" => Some("racket"),
        "asm" | "s" => Some("asm"),
        "ini" => Some("ini"),
        "properties" => Some("properties"),

        // Percent comments
        "bib" => Some("bibtex"),
        "erl" | "hrl" => Some("erlang"),
        "tex" | "sty" | "cls" => Some("latex"),
        "mat" => Some("matlab"),
        "pro" => Some("prolog"),

        // Apostrophe comments
        "vb" | "vbs" => Some("vb"),
        "bas" => Some("vba"),

        // Block comments only
        "css" => Some("css"),
        "scss" => Some("scss"),
        "less" => Some("less"),
        "html" | "htm" => Some("html"),
        "xml" => Some("xml"),
        "xsl" | "xslt" => Some("xsl"),
        "svg" => Some("svg"),
        "vue" => Some("vue"),
        "svelte" => Some("svelte"),
        "astro" => Some("astro"),
        "md" | "markdown" => Some("markdown"),

        // JSON with comments
        "jsonc" => Some("jsonc"),

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

    #[test]
    fn rs_extension_maps_to_rust() {
        assert_eq!(for_extension("rs"), Some(CommentSyntax::Line("//")));
    }

    #[test]
    fn py_extension_maps_to_python() {
        assert_eq!(for_extension("py"), Some(CommentSyntax::Line("#")));
    }

    #[test]
    fn ts_extension_maps_to_typescript() {
        assert_eq!(for_extension("ts"), Some(CommentSyntax::Line("//")));
    }

    #[test]
    fn css_extension_maps_to_block_comment() {
        assert_eq!(for_extension("css"), Some(CommentSyntax::Block("/*", "*/")));
    }

    #[test]
    fn html_extension_maps_to_xml_comment() {
        assert_eq!(for_extension("html"), Some(CommentSyntax::Block("<!--", "-->")));
    }

    #[test]
    fn sql_extension_maps_to_double_dash() {
        assert_eq!(for_extension("sql"), Some(CommentSyntax::Line("--")));
    }

    #[test]
    fn unknown_extension_returns_none() {
        assert_eq!(for_extension("xyz123"), None);
    }

    #[test]
    fn extension_lookup_is_case_insensitive() {
        assert_eq!(for_extension("RS"), Some(CommentSyntax::Line("//")));
        assert_eq!(for_extension("Py"), Some(CommentSyntax::Line("#")));
    }

    #[test]
    fn for_path_extracts_extension() {
        assert_eq!(for_path(Path::new("src/main.rs")), Some(CommentSyntax::Line("//")));
        assert_eq!(for_path(Path::new("config.py")), Some(CommentSyntax::Line("#")));
    }

    #[test]
    fn for_path_returns_none_for_no_extension() {
        assert_eq!(for_path(Path::new("Makefile")), None);
    }
}
