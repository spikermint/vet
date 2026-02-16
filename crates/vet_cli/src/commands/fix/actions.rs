//! Fix actions and their application logic.

use std::path::Path;

use vet_core::Finding;
use vet_core::comment_syntax::{self, IGNORE_MARKER};
use vet_core::text::{find_line_end, find_line_start};

const REDACTED_MARKER: &str = "<REDACTED>";

/// A remediation action the user can apply to a detected secret.
#[derive(Debug, Clone)]
pub enum FixAction {
    /// Replace the secret with `<REDACTED>`.
    Redact,
    /// Replace with an environment variable placeholder.
    Placeholder(String),
    /// Delete the entire line containing the secret.
    DeleteLine,
    /// Append a `vet:ignore` comment to the line.
    Ignore,
}

impl FixAction {
    /// Returns a short human-readable label for display in prompts.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Redact => "Redact",
            Self::Placeholder(_) => "Placeholder",
            Self::DeleteLine => "Delete line",
            Self::Ignore => "Ignore",
        }
    }
}

/// Outcome of applying a fix action to a document.
#[derive(Debug)]
pub struct ApplyResult {
    /// Whether the action was applied successfully.
    pub success: bool,
    /// Net byte offset change (positive = content grew, negative = shrank).
    pub bytes_changed: isize,
}

/// Applies a fix action to the document content at the finding's span.
#[must_use]
pub fn apply_action(content: &mut String, finding: &Finding, action: &FixAction, offset: isize) -> ApplyResult {
    let Some(adjusted_start) = adjust_offset(finding.span.byte_start, offset) else {
        return ApplyResult {
            success: false,
            bytes_changed: 0,
        };
    };
    let Some(adjusted_end) = adjust_offset(finding.span.byte_end, offset) else {
        return ApplyResult {
            success: false,
            bytes_changed: 0,
        };
    };

    if adjusted_start >= content.len() || adjusted_end > content.len() {
        return ApplyResult {
            success: false,
            bytes_changed: 0,
        };
    }

    let bytes_changed = match action {
        FixAction::Redact => replace_span(content, adjusted_start, adjusted_end, REDACTED_MARKER),
        FixAction::Placeholder(env_var) => {
            let replacement = format!("${{{env_var}}}");
            replace_span(content, adjusted_start, adjusted_end, &replacement)
        }
        FixAction::DeleteLine => delete_line(content, adjusted_start),
        FixAction::Ignore => append_ignore_comment(content, adjusted_start, &finding.path),
    };

    ApplyResult {
        success: true,
        bytes_changed,
    }
}

/// Derives an environment variable name from a pattern ID (e.g. `"payments/stripe-secret"` becomes `"STRIPE_SECRET"`).
#[must_use]
pub fn derive_env_var_name(pattern_id: &str) -> String {
    pattern_id
        .split('/')
        .next_back()
        .unwrap_or(pattern_id)
        .replace('-', "_")
        .to_uppercase()
}

/// Before-and-after text for previewing a fix action.
#[derive(Debug)]
pub struct PreviewLines {
    /// One-based line number of the affected line.
    pub line_number: u32,
    /// The original line content.
    pub original: String,
    /// The line content after the action would be applied.
    pub modified: String,
    /// Whether the action deletes the entire line.
    pub is_deletion: bool,
}

/// Generates a preview of what the fix action would change.
#[must_use]
pub fn generate_preview(content: &str, finding: &Finding, action: &FixAction, offset: isize) -> Option<PreviewLines> {
    let adjusted_start = adjust_offset(finding.span.byte_start, offset)?;
    let adjusted_end = adjust_offset(finding.span.byte_end, offset)?;

    if adjusted_start >= content.len() || adjusted_end > content.len() {
        return None;
    }

    let line_start = find_line_start(content, adjusted_start);
    let line_end = find_line_end(content, adjusted_start);
    let original_line = &content[line_start..line_end];

    let modified = match action {
        FixAction::Redact => {
            let (prefix, suffix) = split_around_secret(original_line, adjusted_start, adjusted_end, line_start);
            format!("{prefix}{REDACTED_MARKER}{suffix}")
        }
        FixAction::Placeholder(env_var) => {
            let (prefix, suffix) = split_around_secret(original_line, adjusted_start, adjusted_end, line_start);
            format!("{prefix}${{{env_var}}}{suffix}")
        }
        FixAction::DeleteLine => String::new(),
        FixAction::Ignore => {
            let syntax = comment_syntax::for_path(&finding.path)?;
            format!("{original_line} {}", syntax.format_ignore())
        }
    };

    Some(PreviewLines {
        line_number: finding.span.line,
        original: original_line.to_string(),
        modified,
        is_deletion: matches!(action, FixAction::DeleteLine),
    })
}

fn split_around_secret(line: &str, secret_start: usize, secret_end: usize, line_start: usize) -> (&str, &str) {
    let offset_in_line = secret_start - line_start;
    let secret_len = secret_end - secret_start;
    let end_in_line = (offset_in_line + secret_len).min(line.len());
    (&line[..offset_in_line], &line[end_in_line..])
}

fn adjust_offset(byte_pos: usize, offset: isize) -> Option<usize> {
    if offset >= 0 {
        #[expect(clippy::cast_sign_loss, reason = "offset is non-negative in this branch")]
        Some(byte_pos + offset as usize)
    } else {
        byte_pos.checked_sub(offset.unsigned_abs())
    }
}

#[expect(clippy::cast_possible_wrap, reason = "span lengths are far below isize::MAX")]
fn replace_span(content: &mut String, start: usize, end: usize, replacement: &str) -> isize {
    let old_len = end - start;
    let new_len = replacement.len();
    content.replace_range(start..end, replacement);
    new_len as isize - old_len as isize
}

fn delete_line(content: &mut String, byte_pos: usize) -> isize {
    let line_start = find_line_start(content, byte_pos);
    let line_end = find_line_end(content, byte_pos);

    let delete_end = if line_end < content.len() && content.as_bytes().get(line_end) == Some(&b'\n') {
        line_end + 1
    } else {
        line_end
    };

    let deleted_len = delete_end - line_start;
    content.replace_range(line_start..delete_end, "");
    #[expect(clippy::cast_possible_wrap, reason = "line lengths are far below isize::MAX")]
    -(deleted_len as isize)
}

fn append_ignore_comment(content: &mut String, byte_pos: usize, path: &Path) -> isize {
    let Some(syntax) = comment_syntax::for_path(path) else {
        return 0;
    };

    let line_start = find_line_start(content, byte_pos);
    let line_end = find_line_end(content, byte_pos);

    let line = &content[line_start..line_end];
    if line.contains(IGNORE_MARKER) {
        return 0;
    }

    let comment = format!(" {}", syntax.format_ignore());
    let comment_len = comment.len();

    content.insert_str(line_end, &comment);
    #[expect(clippy::cast_possible_wrap, reason = "comment length is far below isize::MAX")]
    {
        comment_len as isize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_env_var_name_extracts_after_slash() {
        assert_eq!(derive_env_var_name("payments/stripe-secret"), "STRIPE_SECRET");
    }

    #[test]
    fn derive_env_var_name_converts_hyphens() {
        assert_eq!(derive_env_var_name("ai/openai-api-key"), "OPENAI_API_KEY");
    }

    #[test]
    fn derive_env_var_name_handles_no_slash() {
        assert_eq!(derive_env_var_name("simple-pattern"), "SIMPLE_PATTERN");
    }

    #[test]
    fn replace_span_shorter_replacement() {
        let mut content = String::from("key = sk_live_abc123xyz");
        let offset = replace_span(&mut content, 6, 23, REDACTED_MARKER);
        assert_eq!(content, "key = <REDACTED>");
        assert_eq!(offset, -7);
    }

    #[test]
    fn replace_span_longer_replacement() {
        let mut content = String::from("x = A");
        let offset = replace_span(&mut content, 4, 5, "MUCH_LONGER");
        assert_eq!(content, "x = MUCH_LONGER");
        assert_eq!(offset, 10);
    }

    #[test]
    fn delete_line_middle_of_file() {
        let mut content = String::from("line1\nsecret_here\nline3");
        let offset = delete_line(&mut content, 10);
        assert_eq!(content, "line1\nline3");
        assert_eq!(offset, -12);
    }

    #[test]
    fn delete_line_last_line_no_newline() {
        let mut content = String::from("line1\nlast_line");
        let offset = delete_line(&mut content, 10);
        assert_eq!(content, "line1\n");
        assert_eq!(offset, -9);
    }

    #[test]
    fn append_ignore_comment_rust_file() {
        let mut content = String::from("let key = secret;");
        let path = Path::new("test.rs");
        let offset = append_ignore_comment(&mut content, 10, path);
        assert_eq!(content, "let key = secret; // vet:ignore");
        assert_eq!(offset, 14);
    }

    #[test]
    fn append_ignore_comment_python_file() {
        let mut content = String::from("key = secret");
        let path = Path::new("test.py");
        let offset = append_ignore_comment(&mut content, 6, path);
        assert_eq!(content, "key = secret # vet:ignore");
        assert_eq!(offset, 13);
    }

    #[test]
    fn append_ignore_comment_skips_if_present() {
        let mut content = String::from("key = secret // vet:ignore");
        let path = Path::new("test.rs");
        let offset = append_ignore_comment(&mut content, 6, path);
        assert_eq!(content, "key = secret // vet:ignore");
        assert_eq!(offset, 0);
    }

    #[test]
    fn append_ignore_comment_unknown_extension_returns_zero() {
        let mut content = String::from("key = secret");
        let path = Path::new("test.unknownext");
        let offset = append_ignore_comment(&mut content, 6, path);
        assert_eq!(content, "key = secret");
        assert_eq!(offset, 0);
    }

    #[test]
    fn adjust_offset_positive() {
        assert_eq!(adjust_offset(10, 5), Some(15));
    }

    #[test]
    fn adjust_offset_negative() {
        assert_eq!(adjust_offset(10, -3), Some(7));
    }

    #[test]
    fn adjust_offset_underflow_returns_none() {
        assert_eq!(adjust_offset(5, -10), None);
    }
}
