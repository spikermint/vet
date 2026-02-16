//! File collection and reading utilities.
//!
//! Handles walking directories with gitignore support, applying exclude
//! patterns, and reading text files with size limits.

use std::io::Read;
use std::path::{Path, PathBuf};

use ignore::WalkBuilder;
use ignore::overrides::OverrideBuilder;
use vet_core::binary::{has_binary_extension, is_binary_bytes};

const CONTEXT_LINES_BEFORE: usize = 1;
const CONTEXT_LINES_AFTER: usize = 1;

/// Walks the given paths, collecting scannable text files while honouring
/// exclude globs, gitignore rules, and binary-extension filtering.
#[must_use]
pub fn collect_files(paths: &[PathBuf], excludes: &[String], respect_gitignore: bool) -> Vec<PathBuf> {
    let mut files = Vec::new();

    for path in paths {
        if path.is_file() {
            if !has_binary_extension(path) {
                files.push(path.clone());
            }
            continue;
        }

        let overrides = build_overrides(path, excludes);
        let walker = build_walker(path, overrides, respect_gitignore);

        let (tx, rx) = std::sync::mpsc::channel();
        walker.run(|| {
            let tx = tx.clone();
            Box::new(move |result| {
                if let Ok(entry) = result
                    && is_scannable_file(&entry)
                {
                    let _ = tx.send(entry.into_path());
                }
                ignore::WalkState::Continue
            })
        });
        drop(tx);
        files.extend(rx);
    }

    files
}

fn is_scannable_file(entry: &ignore::DirEntry) -> bool {
    entry.file_type().is_some_and(|ft| ft.is_file()) && !has_binary_extension(entry.path())
}

/// Files at or above this size are memory-mapped instead of heap-read.
const MMAP_THRESHOLD: u64 = 32 * 1024;

/// Reads a file as UTF-8 text, returning `None` if it exceeds `max_size`,
/// does not exist, or contains binary content.
///
/// Small files (< 32 KB) are read with a single `read` syscall.
/// Large files are memory-mapped so the OS page cache is used directly,
/// avoiding a heap copy until we confirm the file is text.
#[must_use]
pub fn read_text_file(path: &Path, max_size: Option<u64>) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    let len = metadata.len();

    if let Some(max) = max_size
        && len > max
    {
        return None;
    }

    if len >= MMAP_THRESHOLD {
        read_large_file_mmap(&file, len)
    } else {
        read_small_file(&mut file, len)
    }
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "files above max_size are already rejected; remaining sizes fit in usize"
)]
fn read_small_file(file: &mut std::fs::File, len: u64) -> Option<String> {
    let mut bytes = Vec::with_capacity(len as usize);
    file.read_to_end(&mut bytes).ok()?;
    if is_binary_bytes(&bytes) {
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn read_large_file_mmap(file: &std::fs::File, _len: u64) -> Option<String> {
    // SAFETY: The map is read-only and dropped before this function returns.
    // Concurrent file truncation could cause SIGBUS, but this is the same
    // risk `git` and `ripgrep` accept for mmap-based file reading.
    #[expect(unsafe_code, reason = "mmap requires unsafe; lifetime is scoped to this function")]
    let mmap = unsafe { memmap2::Mmap::map(file) }.ok()?;

    if is_binary_bytes(&mmap) {
        return None;
    }

    std::str::from_utf8(&mmap).ok().map(String::from)
}

#[expect(
    clippy::expect_used,
    reason = "pattern format is validated by caller; programmer error if invalid"
)]
fn build_overrides(path: &Path, excludes: &[String]) -> ignore::overrides::Override {
    let mut builder = OverrideBuilder::new(path);

    for pattern in excludes {
        builder.add(&format!("!{pattern}")).expect("invalid exclude pattern");
    }

    builder.build().expect("failed to build overrides")
}

fn build_walker(path: &Path, overrides: ignore::overrides::Override, respect_gitignore: bool) -> ignore::WalkParallel {
    WalkBuilder::new(path)
        .hidden(false)
        .git_ignore(respect_gitignore)
        .git_global(respect_gitignore)
        .git_exclude(respect_gitignore)
        .overrides(overrides)
        .build_parallel()
}

/// A single line of source code displayed alongside a finding.
#[derive(Debug, Clone)]
pub struct ContextLine {
    /// One-based line number in the original file.
    pub line_number: usize,
    /// The line text (masked if the line contains a secret).
    pub content: String,
    /// Whether this line is the primary finding line.
    pub is_finding: bool,
}

/// Extracts context lines around a finding, substituting masked content for
/// any lines that contain secrets.
#[must_use]
pub fn get_context_lines(
    content: &str,
    finding_line: usize,
    masked_line_content: &str,
    other_masked_lines: &[(usize, &str)],
) -> Vec<ContextLine> {
    let lines: Vec<&str> = content.lines().collect();
    let range = calculate_context_range(finding_line, lines.len());

    range
        .map(|i| build_context_line(i, finding_line, &lines, masked_line_content, other_masked_lines))
        .collect()
}

fn calculate_context_range(finding_line: usize, total_lines: usize) -> std::ops::Range<usize> {
    let finding_index = finding_line.saturating_sub(1);

    let start = finding_index.saturating_sub(CONTEXT_LINES_BEFORE);
    let end = (finding_index + CONTEXT_LINES_AFTER + 1).min(total_lines);

    start..end
}

fn build_context_line(
    index: usize,
    finding_line: usize,
    lines: &[&str],
    masked_line_content: &str,
    other_masked_lines: &[(usize, &str)],
) -> ContextLine {
    let line_number = index + 1;
    let is_finding = line_number == finding_line;

    let content = if is_finding {
        masked_line_content.to_string()
    } else if let Some((_, masked)) = other_masked_lines.iter().find(|(ln, _)| *ln == line_number) {
        (*masked).to_string()
    } else {
        lines.get(index).copied().unwrap_or("").to_string()
    };

    ContextLine {
        line_number,
        content,
        is_finding,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::{NamedTempFile, TempDir};

    use super::*;

    #[test]
    fn read_text_file_success() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "hello world").unwrap();

        let content = read_text_file(file.path(), None);

        assert!(content.is_some());
        assert!(content.unwrap().contains("hello world"));
    }

    #[test]
    fn read_text_file_nonexistent() {
        let content = read_text_file(Path::new("/nonexistent/file.txt"), None);
        assert!(content.is_none());
    }

    #[test]
    fn read_text_file_within_size_limit() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "small content").unwrap();

        let content = read_text_file(file.path(), Some(1000));

        assert!(content.is_some());
    }

    #[test]
    fn read_text_file_exceeds_size_limit() {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "{}", "x".repeat(1000)).unwrap();

        let content = read_text_file(file.path(), Some(500));

        assert!(content.is_none());
    }

    #[test]
    fn read_text_file_exactly_at_limit() {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "{}", "x".repeat(100)).unwrap();

        let content = read_text_file(file.path(), Some(100));

        assert!(content.is_some());
    }

    #[test]
    fn read_text_file_rejects_binary_content() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"text\x00binary").unwrap();

        let content = read_text_file(file.path(), None);

        assert!(content.is_none());
    }

    #[test]
    fn get_context_lines_single_line_file() {
        let content = "secret = TOKEN_ABC";
        let lines = get_context_lines(content, 1, "secret = ********", &[]);

        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].line_number, 1);
        assert!(lines[0].is_finding);
        assert_eq!(lines[0].content, "secret = ********");
    }

    #[test]
    fn get_context_lines_with_before_context() {
        let content = "line1\nline2\nsecret = TOKEN";
        let lines = get_context_lines(content, 3, "secret = ********", &[]);

        assert!(lines.iter().any(|l| l.line_number == 2));
        assert!(lines.iter().any(|l| l.line_number == 3 && l.is_finding));
    }

    #[test]
    fn get_context_lines_with_after_context() {
        let content = "secret = TOKEN\nline2\nline3";
        let lines = get_context_lines(content, 1, "secret = ********", &[]);

        assert!(lines.iter().any(|l| l.line_number == 1 && l.is_finding));
        assert!(lines.iter().any(|l| l.line_number == 2));
    }

    #[test]
    fn get_context_lines_middle_of_file() {
        let content = "line1\nline2\nsecret = TOKEN\nline4\nline5";
        let lines = get_context_lines(content, 3, "secret = ********", &[]);

        assert!(lines.len() >= 3);
        assert!(lines.iter().any(|l| l.line_number == 2 && !l.is_finding));
        assert!(lines.iter().any(|l| l.line_number == 3 && l.is_finding));
        assert!(lines.iter().any(|l| l.line_number == 4 && !l.is_finding));
    }

    #[test]
    fn get_context_lines_uses_masked_content_for_finding() {
        let content = "before\nSECRET_TOKEN\nafter";
        let lines = get_context_lines(content, 2, "********", &[]);

        let finding_line = lines.iter().find(|l| l.is_finding).unwrap();
        assert_eq!(finding_line.content, "********");
    }

    #[test]
    fn get_context_lines_preserves_original_for_non_findings() {
        let content = "original line\nsecret = TOKEN";
        let lines = get_context_lines(content, 2, "secret = ********", &[]);

        let context_line = lines.iter().find(|l| l.line_number == 1).unwrap();
        assert_eq!(context_line.content, "original line");
        assert!(!context_line.is_finding);
    }

    #[test]
    fn collect_files_single_text_file() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("test.rs");
        std::fs::write(&file, "fn main() {}").unwrap();

        let files = collect_files(&[dir.path().to_path_buf()], &[], true);

        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("test.rs"));
    }

    #[test]
    fn collect_files_skips_binary_extensions() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("code.rs"), "fn main() {}").unwrap();
        std::fs::write(dir.path().join("image.png"), "fake png").unwrap();

        let files = collect_files(&[dir.path().to_path_buf()], &[], true);

        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("code.rs"));
    }

    #[test]
    fn collect_files_with_exclude_pattern() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("src");
        let vendor = dir.path().join("vendor");
        std::fs::create_dir(&src).unwrap();
        std::fs::create_dir(&vendor).unwrap();
        std::fs::write(src.join("main.rs"), "fn main() {}").unwrap();
        std::fs::write(vendor.join("lib.rs"), "// vendored").unwrap();

        let excludes = vec!["vendor/**".to_string()];
        let files = collect_files(&[dir.path().to_path_buf()], &excludes, true);

        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("main.rs"));
    }

    #[test]
    fn collect_files_direct_file_path() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "content").unwrap();

        let files = collect_files(&[file.path().to_path_buf()], &[], true);

        assert_eq!(files.len(), 1);
    }

    #[test]
    fn collect_files_direct_binary_file_skipped() {
        let dir = TempDir::new().unwrap();
        let binary = dir.path().join("image.png");
        std::fs::write(&binary, "fake png").unwrap();

        let files = collect_files(&[binary], &[], true);

        assert!(files.is_empty());
    }

    #[test]
    fn collect_files_empty_directory() {
        let dir = TempDir::new().unwrap();

        let files = collect_files(&[dir.path().to_path_buf()], &[], true);

        assert!(files.is_empty());
    }

    #[test]
    fn collect_files_nested_directories() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("a").join("b").join("c");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("deep.rs"), "// deep").unwrap();

        let files = collect_files(&[dir.path().to_path_buf()], &[], true);

        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("deep.rs"));
    }

    #[test]
    fn get_context_lines_masks_other_findings() {
        let source = "line1\nSECRET_ONE\nSECRET_TWO\nline4";
        let other_masked = vec![(2, "********")];
        let context = get_context_lines(source, 3, "********", &other_masked);

        let second_line = context.iter().find(|l| l.line_number == 2).unwrap();
        assert_eq!(second_line.content, "********");
        assert!(!second_line.is_finding);
    }
}
