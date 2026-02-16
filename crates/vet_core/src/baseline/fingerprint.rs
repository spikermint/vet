use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Content-based identifier for a finding in the baseline.
///
/// Computed as `sha256(<pattern_id>:<normalised_path>:<secret_hash>)`, so the
/// same secret in the same file always produces the same fingerprint regardless
/// of line number or surrounding whitespace.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Fingerprint {
    /// The `sha256:<hex>` string representation.
    value: Box<str>,
}

impl Fingerprint {
    /// Computes a fingerprint from a pattern ID, file path, and secret hash.
    ///
    /// The file path is normalised (forward slashes, leading `./` stripped)
    /// so fingerprints are consistent across platforms.
    #[inline]
    #[must_use]
    pub fn calculate(pattern_id: &str, file_path: &Path, secret_hash: &str) -> Self {
        let normalized_path = normalise_path(file_path);
        let input = format!("{pattern_id}:{normalized_path}:{secret_hash}");

        let hash = Sha256::digest(input.as_bytes());
        let hex = hex::encode(hash);

        Self {
            value: format!("sha256:{hex}").into(),
        }
    }

    /// Creates a fingerprint from an existing string (e.g. loaded from JSON).
    #[inline]
    #[must_use]
    pub fn from_string(value: &str) -> Self {
        Self { value: value.into() }
    }

    /// Returns the fingerprint as a string slice.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl AsRef<str> for Fingerprint {
    fn as_ref(&self) -> &str {
        &self.value
    }
}

fn normalise_path(path: &Path) -> String {
    let path_str = path.to_string_lossy();

    path_str.replace('\\', "/").trim_start_matches("./").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calculate_produces_deterministic_output() {
        let fp1 = Fingerprint::calculate("aws/access-key-id", Path::new("src/config.py"), "sha256:abc123");
        let fp2 = Fingerprint::calculate("aws/access-key-id", Path::new("src/config.py"), "sha256:abc123");

        assert_eq!(fp1, fp2);
    }

    #[test]
    fn different_files_produce_different_fingerprints() {
        let fp1 = Fingerprint::calculate("aws/access-key-id", Path::new("src/config.py"), "sha256:abc123");
        let fp2 = Fingerprint::calculate("aws/access-key-id", Path::new("src/other.py"), "sha256:abc123");

        assert_ne!(fp1, fp2);
    }

    #[test]
    fn different_patterns_produce_different_fingerprints() {
        let fp1 = Fingerprint::calculate("aws/access-key-id", Path::new("src/config.py"), "sha256:abc123");
        let fp2 = Fingerprint::calculate("aws/secret-access-key", Path::new("src/config.py"), "sha256:abc123");

        assert_ne!(fp1, fp2);
    }

    #[test]
    fn different_secret_hashes_produce_different_fingerprints() {
        let fp1 = Fingerprint::calculate("aws/access-key-id", Path::new("src/config.py"), "sha256:abc123");
        let fp2 = Fingerprint::calculate("aws/access-key-id", Path::new("src/config.py"), "sha256:def456");

        assert_ne!(fp1, fp2);
    }

    #[test]
    fn normalizes_windows_paths() {
        let fp1 = Fingerprint::calculate("test", Path::new("src\\config.py"), "sha256:abc");
        let fp2 = Fingerprint::calculate("test", Path::new("src/config.py"), "sha256:abc");

        assert_eq!(fp1, fp2);
    }

    #[test]
    fn strips_leading_dot_slash() {
        let fp1 = Fingerprint::calculate("test", Path::new("./src/config.py"), "sha256:abc");
        let fp2 = Fingerprint::calculate("test", Path::new("src/config.py"), "sha256:abc");

        assert_eq!(fp1, fp2);
    }

    #[test]
    fn fingerprint_starts_with_sha256_prefix() {
        let fp = Fingerprint::calculate("test", Path::new("file.txt"), "sha256:abc");

        assert!(fp.as_str().starts_with("sha256:"));
    }

    #[test]
    fn fingerprint_has_correct_length() {
        let fp = Fingerprint::calculate("test", Path::new("file.txt"), "sha256:abc");

        assert_eq!(fp.as_str().len(), 71);
    }

    #[test]
    fn from_string_preserves_value() {
        let original = "sha256:abc123def456";
        let fp = Fingerprint::from_string(original);

        assert_eq!(fp.as_str(), original);
    }

    #[test]
    fn display_shows_fingerprint_value() {
        let fp = Fingerprint::from_string("sha256:test123");

        assert_eq!(format!("{fp}"), "sha256:test123");
    }

    #[test]
    fn as_ref_returns_same_as_as_str() {
        let fp = Fingerprint::from_string("sha256:test");
        let s: &str = fp.as_ref();

        assert_eq!(s, fp.as_str());
    }

    #[test]
    fn serializes_as_plain_string() {
        let fp = Fingerprint::from_string("sha256:abc123");
        let json = serde_json::to_string(&fp).unwrap();

        assert_eq!(json, "\"sha256:abc123\"");
    }

    #[test]
    fn deserializes_from_plain_string() {
        let json = "\"sha256:abc123\"";
        let fp: Fingerprint = serde_json::from_str(json).unwrap();

        assert_eq!(fp.as_str(), "sha256:abc123");
    }

    #[test]
    fn serde_roundtrip_preserves_value() {
        let original = Fingerprint::from_string("sha256:test123");
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: Fingerprint = serde_json::from_str(&json).unwrap();

        assert_eq!(original, deserialized);
    }
}
