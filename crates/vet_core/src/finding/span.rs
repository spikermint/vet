use std::fmt;

use crate::text::find_line_start;

/// Source location of a finding, with 1-indexed line/column and byte offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    /// 1-indexed line number within the file.
    pub line: u32,
    /// 1-indexed column number (in characters, not bytes).
    pub column: u32,
    /// Byte offset of the first character of the match.
    pub byte_start: usize,
    /// Byte offset one past the last character of the match.
    pub byte_end: usize,
}

impl Span {
    /// Creates a span from pre-computed line, column, and byte offsets.
    #[must_use]
    pub const fn new(line: u32, column: u32, byte_start: usize, byte_end: usize) -> Self {
        Self {
            line,
            column,
            byte_start,
            byte_end,
        }
    }

    /// Derives line and column numbers from byte offsets into `content`.
    ///
    /// Returns `None` if either offset is out of bounds or not on a UTF-8
    /// character boundary.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "line/column counts in source files fit in u32"
    )]
    #[must_use]
    pub fn from_byte_range(content: &str, byte_start: usize, byte_end: usize) -> Option<Self> {
        if byte_start > content.len()
            || byte_end > content.len()
            || !content.is_char_boundary(byte_start)
            || !content.is_char_boundary(byte_end)
        {
            return None;
        }

        let before_match = &content[..byte_start];
        let line = before_match.chars().filter(|&c| c == '\n').count() as u32 + 1;
        let line_start = find_line_start(content, byte_start);
        let column = content[line_start..byte_start].chars().count() as u32 + 1;

        Some(Self {
            line,
            column,
            byte_start,
            byte_end,
        })
    }

    /// Returns the byte length of the matched region.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.byte_end - self.byte_start
    }

    /// Returns `true` if the span covers zero bytes.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.byte_start == self.byte_end
    }
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.line, self.column)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_byte_range_at_start_returns_line1_column1() {
        let content = "secret";
        let span = Span::from_byte_range(content, 0, 6).unwrap();
        assert_eq!(span.line, 1);
        assert_eq!(span.column, 1);
    }

    #[test]
    fn from_byte_range_mid_line_calculates_correct_column() {
        let content = "key = SECRET";
        let span = Span::from_byte_range(content, 6, 12).unwrap();
        assert_eq!(span.line, 1);
        assert_eq!(span.column, 7);
    }

    #[test]
    fn from_byte_range_after_newline_returns_line2() {
        let content = "line1\nSECRET";
        let span = Span::from_byte_range(content, 6, 12).unwrap();
        assert_eq!(span.line, 2);
        assert_eq!(span.column, 1);
    }

    #[test]
    fn from_byte_range_calculates_line_and_column_correctly() {
        let content = "line1\nline2\nkey = SECRET";
        let span = Span::from_byte_range(content, 18, 24).unwrap();
        assert_eq!(span.line, 3);
        assert_eq!(span.column, 7);
    }

    #[test]
    fn from_byte_range_handles_crlf_newlines() {
        let content = "line1\r\nSECRET";
        let span = Span::from_byte_range(content, 7, 13).unwrap();
        assert_eq!(span.line, 2);
        assert_eq!(span.column, 1);
    }

    #[test]
    fn from_byte_range_counts_characters_not_bytes_for_column() {
        let content = "éé = SECRET";
        let span = Span::from_byte_range(content, 7, 13).unwrap();
        assert_eq!(span.line, 1);
        assert_eq!(span.column, 6);
    }

    #[test]
    fn from_byte_range_handles_empty_content() {
        let span = Span::from_byte_range("", 0, 0).unwrap();
        assert_eq!(span.line, 1);
        assert_eq!(span.column, 1);
    }

    #[test]
    fn from_byte_range_at_end_of_line() {
        let content = "SECRET\nnext";
        let span = Span::from_byte_range(content, 0, 6).unwrap();
        assert_eq!(span.line, 1);
        assert_eq!(span.column, 1);
        assert_eq!(span.len(), 6);
    }

    #[test]
    fn len_returns_byte_length() {
        let span = Span::new(1, 1, 10, 25);
        assert_eq!(span.len(), 15);
    }

    #[test]
    fn is_empty_returns_true_for_zero_length() {
        let span = Span::new(1, 1, 5, 5);
        assert!(span.is_empty());
    }

    #[test]
    fn is_empty_returns_false_when_has_length() {
        let span = Span::new(1, 1, 5, 10);
        assert!(!span.is_empty());
    }

    #[test]
    fn display_formats_as_line_colon_column() {
        let span = Span::new(42, 13, 0, 10);
        assert_eq!(format!("{span}"), "42:13");
    }

    #[test]
    fn byte_offsets_are_preserved() {
        let content = "some content here";
        let span = Span::from_byte_range(content, 5, 12).unwrap();
        assert_eq!(span.byte_start, 5);
        assert_eq!(span.byte_end, 12);
    }
}
