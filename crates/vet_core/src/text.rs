/// Returns the byte offset of the start of the line containing `offset`.
#[must_use]
pub fn find_line_start(content: &str, offset: usize) -> usize {
    content[..offset].rfind('\n').map_or(0, |i| i + 1)
}

/// Returns the byte offset of the next newline after `offset`, or the end
/// of `content` if there is no trailing newline.
#[must_use]
pub fn find_line_end(content: &str, offset: usize) -> usize {
    content[offset..].find('\n').map_or(content.len(), |i| offset + i)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_line_start_at_beginning_returns_zero() {
        assert_eq!(find_line_start("hello", 0), 0);
        assert_eq!(find_line_start("hello", 3), 0);
    }

    #[test]
    fn find_line_start_on_second_line_returns_position_after_newline() {
        let content = "line1\nline2";
        assert_eq!(find_line_start(content, 6), 6);
        assert_eq!(find_line_start(content, 8), 6);
    }

    #[test]
    fn find_line_start_on_third_line() {
        let content = "line1\nline2\nline3";
        assert_eq!(find_line_start(content, 12), 12);
        assert_eq!(find_line_start(content, 15), 12);
    }

    #[test]
    fn find_line_start_at_newline_returns_start_of_current_line() {
        let content = "line1\nline2";
        assert_eq!(find_line_start(content, 5), 0);
    }

    #[test]
    fn find_line_start_handles_empty_line() {
        let content = "line1\n\nline3";
        assert_eq!(find_line_start(content, 6), 6);
        assert_eq!(find_line_start(content, 7), 7);
    }

    #[test]
    fn find_line_start_handles_crlf() {
        let content = "line1\r\nline2";
        assert_eq!(find_line_start(content, 7), 7);
    }

    #[test]
    fn find_line_end_on_single_line_returns_content_length() {
        let content = "hello";
        assert_eq!(find_line_end(content, 0), 5);
        assert_eq!(find_line_end(content, 3), 5);
    }

    #[test]
    fn find_line_end_on_first_line_stops_at_newline() {
        let content = "line1\nline2";
        assert_eq!(find_line_end(content, 0), 5);
        assert_eq!(find_line_end(content, 3), 5);
    }

    #[test]
    fn find_line_end_on_second_line_returns_content_length() {
        let content = "line1\nline2";
        assert_eq!(find_line_end(content, 6), 11);
    }

    #[test]
    fn find_line_end_at_newline_returns_newline_position() {
        let content = "line1\nline2";
        assert_eq!(find_line_end(content, 5), 5);
    }

    #[test]
    fn find_line_end_handles_empty_line() {
        let content = "line1\n\nline3";
        assert_eq!(find_line_end(content, 6), 6);
    }

    #[test]
    fn find_line_end_on_last_line_without_trailing_newline() {
        let content = "line1\nline2";
        assert_eq!(find_line_end(content, 6), 11);
    }

    #[test]
    fn find_line_end_handles_trailing_newline() {
        let content = "line1\n";
        assert_eq!(find_line_end(content, 0), 5);
    }

    #[test]
    fn find_line_start_and_end_handle_empty_content() {
        assert_eq!(find_line_start("", 0), 0);
        assert_eq!(find_line_end("", 0), 0);
    }

    #[test]
    fn find_line_start_and_end_handle_single_newline() {
        let content = "\n";
        assert_eq!(find_line_start(content, 0), 0);
        assert_eq!(find_line_end(content, 0), 0);
        assert_eq!(find_line_start(content, 1), 1);
        assert_eq!(find_line_end(content, 1), 1);
    }

    #[test]
    fn find_line_start_and_end_handle_consecutive_newlines() {
        let content = "\n\n\n";
        assert_eq!(find_line_start(content, 0), 0);
        assert_eq!(find_line_start(content, 1), 1);
        assert_eq!(find_line_start(content, 2), 2);
        assert_eq!(find_line_end(content, 0), 0);
        assert_eq!(find_line_end(content, 1), 1);
        assert_eq!(find_line_end(content, 2), 2);
    }
}
