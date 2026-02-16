use std::fs;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::error::BaselineError;
use super::finding::BaselineFinding;
use super::fingerprint::Fingerprint;

/// Schema version of the baseline JSON format.
const CURRENT_VERSION: &str = "1";

/// Persistent record of acknowledged findings, serialised as JSON.
///
/// A baseline tracks which secrets have been reviewed so they are not
/// reported again on subsequent scans. Each finding is identified by a
/// `Fingerprint` derived from the pattern, file path, and secret hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    /// Schema version string (currently `"1"`).
    pub version: String,

    /// Timestamp when the baseline was first created.
    #[serde(with = "chrono::serde::ts_seconds")]
    pub created_at: DateTime<Utc>,

    /// Timestamp of the most recent save.
    #[serde(with = "chrono::serde::ts_seconds")]
    pub updated_at: DateTime<Utc>,

    /// Version of `vet` that last wrote this file.
    pub vet_version: String,

    /// The acknowledged findings stored in this baseline.
    pub findings: Vec<BaselineFinding>,
}

impl Baseline {
    /// Creates an empty baseline with the current timestamp and version.
    #[must_use]
    pub fn new() -> Self {
        let now = Utc::now();

        Self {
            version: CURRENT_VERSION.to_string(),
            created_at: now,
            updated_at: now,
            vet_version: env!("CARGO_PKG_VERSION").to_string(),
            findings: Vec::new(),
        }
    }

    /// Loads a baseline from a JSON file on disk.
    ///
    /// Returns `BaselineError::NotFound` if the file does not exist, or
    /// `BaselineError::UnsupportedVersion` if the schema version is unrecognised.
    pub fn load(path: &Path) -> Result<Self, BaselineError> {
        if !path.exists() {
            return Err(BaselineError::NotFound {
                path: path.to_path_buf(),
            });
        }

        let content = fs::read_to_string(path).map_err(|e| BaselineError::Read {
            path: path.to_path_buf(),
            source: e,
        })?;

        let baseline: Self = serde_json::from_str(&content).map_err(|e| BaselineError::Parse {
            path: path.to_path_buf(),
            source: e,
        })?;

        if baseline.version != CURRENT_VERSION {
            return Err(BaselineError::UnsupportedVersion {
                version: baseline.version,
            });
        }

        Ok(baseline)
    }

    /// Atomically writes this baseline to a JSON file, updating `updated_at`.
    pub fn save(&mut self, path: &Path) -> Result<(), BaselineError> {
        self.updated_at = Utc::now();
        self.vet_version = env!("CARGO_PKG_VERSION").to_string();

        let json = serde_json::to_string_pretty(self).map_err(|e| BaselineError::Parse {
            path: path.to_path_buf(),
            source: e,
        })?;

        crate::fs_util::atomic_write(path, &json).map_err(|e| BaselineError::Write {
            path: path.to_path_buf(),
            source: e,
        })?;

        Ok(())
    }

    /// Adds or replaces a finding. If a finding with the same fingerprint
    /// already exists, it is removed before the new one is inserted.
    pub fn add_finding(&mut self, finding: BaselineFinding) {
        self.findings.retain(|f| f.fingerprint != finding.fingerprint);
        self.findings.push(finding);
    }

    /// Returns `true` if any finding matches the given fingerprint.
    #[must_use]
    pub fn contains_fingerprint(&self, fingerprint: &Fingerprint) -> bool {
        self.findings.iter().any(|f| &f.fingerprint == fingerprint)
    }

    /// Looks up a finding by its fingerprint.
    #[must_use]
    pub fn get_finding(&self, fingerprint: &Fingerprint) -> Option<&BaselineFinding> {
        self.findings.iter().find(|f| &f.fingerprint == fingerprint)
    }

    /// Returns the number of findings in the baseline.
    #[must_use]
    pub fn len(&self) -> usize {
        self.findings.len()
    }

    /// Returns `true` if the baseline contains no findings.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }
}

impl Default for Baseline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::Severity;
    use crate::baseline::BaselineStatus;

    fn create_test_finding(fingerprint: &str) -> BaselineFinding {
        BaselineFinding::new(
            Fingerprint::from_string(fingerprint),
            "test/pattern".to_string(),
            Severity::High,
            "test.py".to_string(),
            "sha256:secret".to_string(),
            BaselineStatus::Accepted,
            "Test reason".to_string(),
        )
    }

    #[test]
    fn new_baseline_has_version_1() {
        let baseline = Baseline::new();

        assert_eq!(baseline.version, "1");
    }

    #[test]
    fn new_baseline_has_empty_findings() {
        let baseline = Baseline::new();

        assert!(baseline.findings.is_empty());
        assert!(baseline.is_empty());
        assert_eq!(baseline.len(), 0);
    }

    #[test]
    fn new_baseline_has_current_timestamp() {
        let before = Utc::now();
        let baseline = Baseline::new();
        let after = Utc::now();

        assert!(baseline.created_at >= before);
        assert!(baseline.created_at <= after);
        assert_eq!(baseline.created_at, baseline.updated_at);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("baseline.json");

        let mut baseline = Baseline::new();
        baseline.add_finding(create_test_finding("sha256:abc123"));

        baseline.save(&path).unwrap();

        let loaded = Baseline::load(&path).unwrap();

        assert_eq!(loaded.version, "1");
        assert_eq!(loaded.findings.len(), 1);
        assert_eq!(loaded.findings[0].fingerprint.as_str(), "sha256:abc123");
    }

    #[test]
    fn save_updates_timestamp() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("baseline.json");

        let mut baseline = Baseline::new();
        let original_updated_at = baseline.updated_at;

        std::thread::sleep(std::time::Duration::from_millis(10));

        baseline.save(&path).unwrap();

        assert!(baseline.updated_at > original_updated_at);
    }

    #[test]
    fn load_missing_file_returns_not_found() {
        let result = Baseline::load(Path::new("/nonexistent/path.json"));

        assert!(matches!(result, Err(BaselineError::NotFound { .. })));
    }

    #[test]
    fn load_invalid_json_returns_parse_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("invalid.json");
        fs::write(&path, "not valid json").unwrap();

        let result = Baseline::load(&path);

        assert!(matches!(result, Err(BaselineError::Parse { .. })));
    }

    #[test]
    fn load_wrong_version_returns_unsupported_version() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("old.json");
        fs::write(
            &path,
            r#"{"version": "0.5", "created_at": 0, "updated_at": 0, "vet_version": "0.1.0", "findings": []}"#,
        )
        .unwrap();

        let result = Baseline::load(&path);

        assert!(matches!(
            result,
            Err(BaselineError::UnsupportedVersion { version }) if version == "0.5"
        ));
    }

    #[test]
    fn add_finding_appends_new_finding() {
        let mut baseline = Baseline::new();

        baseline.add_finding(create_test_finding("sha256:abc"));

        assert_eq!(baseline.findings.len(), 1);
    }

    #[test]
    fn add_finding_replaces_existing_with_same_fingerprint() {
        let mut baseline = Baseline::new();

        baseline.add_finding(create_test_finding("sha256:abc"));
        baseline.add_finding(create_test_finding("sha256:abc"));

        assert_eq!(baseline.findings.len(), 1);
    }

    #[test]
    fn contains_fingerprint_returns_true_for_existing() {
        let mut baseline = Baseline::new();
        baseline.add_finding(create_test_finding("sha256:abc"));

        assert!(baseline.contains_fingerprint(&Fingerprint::from_string("sha256:abc")));
    }

    #[test]
    fn contains_fingerprint_returns_false_for_missing() {
        let baseline = Baseline::new();

        assert!(!baseline.contains_fingerprint(&Fingerprint::from_string("sha256:xyz")));
    }

    #[test]
    fn get_finding_returns_some_for_existing() {
        let mut baseline = Baseline::new();
        baseline.add_finding(create_test_finding("sha256:abc"));

        let finding = baseline.get_finding(&Fingerprint::from_string("sha256:abc"));

        assert!(finding.is_some());
        assert_eq!(finding.unwrap().fingerprint.as_str(), "sha256:abc");
    }

    #[test]
    fn get_finding_returns_none_for_missing() {
        let baseline = Baseline::new();

        let finding = baseline.get_finding(&Fingerprint::from_string("sha256:xyz"));

        assert!(finding.is_none());
    }

    #[test]
    fn len_returns_number_of_findings() {
        let mut baseline = Baseline::new();

        assert_eq!(baseline.len(), 0);

        baseline.add_finding(create_test_finding("sha256:one"));
        assert_eq!(baseline.len(), 1);

        baseline.add_finding(create_test_finding("sha256:two"));
        assert_eq!(baseline.len(), 2);
    }

    #[test]
    fn is_empty_reflects_findings_presence() {
        let mut baseline = Baseline::new();

        assert!(baseline.is_empty());

        baseline.add_finding(create_test_finding("sha256:test"));
        assert!(!baseline.is_empty());
    }

    #[test]
    fn default_creates_empty_baseline() {
        let baseline = Baseline::default();

        assert_eq!(baseline.version, "1");
        assert!(baseline.is_empty());
    }
}
