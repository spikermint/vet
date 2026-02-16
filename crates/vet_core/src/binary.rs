//! Binary file detection utilities.

use std::path::Path;

/// Number of bytes to check for null bytes when detecting binary content.
/// Matches how git handles this as binary files almost always have nulls in headers.
const BINARY_CHECK_BYTES: usize = 8000;

/// File extensions that are always treated as binary, regardless of content.
const BINARY_EXTENSIONS: &[&str] = &[
    "o", "obj", "a", "so", "dylib", "dll", "exe", "pyc", "pyo", "class", "rlib", "rmeta", // Compiled code
    "png", "jpg", "jpeg", "gif", "ico", "webp", "bmp", "tiff", "tif", "heic", "heif", "avif", // Images
    "mp3", "mp4", "wav", "avi", "mov", "flac", "ogg", "webm", "mkv", "m4a", // Audio/Video
    "zip", "tar", "gz", "bz2", "xz", "7z", "rar", "zst", // Archives
    "ttf", "otf", "woff", "woff2", "eot", // Fonts
    "wasm", "bin", "dat", "pak", "bundle", // Other binary
];

/// Returns `true` if the file extension is in the known binary list.
///
/// The check is case-insensitive.
#[must_use]
pub fn has_binary_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| BINARY_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()))
}

/// Returns `true` if the first [`BINARY_CHECK_BYTES`] of `content` contain
/// a null byte, which strongly indicates binary data.
#[must_use]
pub fn is_binary_content(content: &str) -> bool {
    is_binary_bytes(content.as_bytes())
}

/// Returns `true` if the first [`BINARY_CHECK_BYTES`] of `bytes` contain
/// a null byte, which strongly indicates binary data.
#[must_use]
pub fn is_binary_bytes(bytes: &[u8]) -> bool {
    let check_len = bytes.len().min(BINARY_CHECK_BYTES);
    bytes[..check_len].contains(&0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_binary_extension_detects_images() {
        assert!(has_binary_extension(Path::new("photo.png")));
        assert!(has_binary_extension(Path::new("image.jpg")));
        assert!(has_binary_extension(Path::new("icon.gif")));
        assert!(has_binary_extension(Path::new("banner.webp")));
    }

    #[test]
    fn has_binary_extension_detects_compiled_code() {
        assert!(has_binary_extension(Path::new("main.o")));
        assert!(has_binary_extension(Path::new("lib.so")));
        assert!(has_binary_extension(Path::new("app.exe")));
        assert!(has_binary_extension(Path::new("module.pyc")));
    }

    #[test]
    fn has_binary_extension_detects_archives() {
        assert!(has_binary_extension(Path::new("archive.zip")));
        assert!(has_binary_extension(Path::new("backup.tar")));
        assert!(has_binary_extension(Path::new("data.gz")));
    }

    #[test]
    fn has_binary_extension_is_case_insensitive() {
        assert!(has_binary_extension(Path::new("IMAGE.PNG")));
        assert!(has_binary_extension(Path::new("Photo.JPG")));
        assert!(has_binary_extension(Path::new("Archive.ZIP")));
    }

    #[test]
    fn has_binary_extension_allows_text_files() {
        assert!(!has_binary_extension(Path::new("main.rs")));
        assert!(!has_binary_extension(Path::new("config.toml")));
        assert!(!has_binary_extension(Path::new("README.md")));
        assert!(!has_binary_extension(Path::new("script.js")));
    }

    #[test]
    fn has_binary_extension_allows_no_extension() {
        assert!(!has_binary_extension(Path::new("Makefile")));
        assert!(!has_binary_extension(Path::new("Dockerfile")));
        assert!(!has_binary_extension(Path::new(".gitignore")));
    }

    #[test]
    fn has_binary_extension_handles_hidden_files() {
        assert!(!has_binary_extension(Path::new(".env")));
        assert!(has_binary_extension(Path::new(".cache.png")));
    }

    #[test]
    fn is_binary_content_detects_null_bytes() {
        assert!(is_binary_content("hello\0world"));
        assert!(is_binary_content("\0binary"));
    }

    #[test]
    fn is_binary_content_allows_text() {
        assert!(!is_binary_content("hello world"));
        assert!(!is_binary_content("line1\nline2\nline3"));
        assert!(!is_binary_content(""));
    }

    #[test]
    fn is_binary_content_checks_limited_bytes() {
        // Create content with null byte after the check limit
        let mut content = "a".repeat(BINARY_CHECK_BYTES + 100);
        content.push('\0');
        assert!(!is_binary_content(&content));
    }
}
