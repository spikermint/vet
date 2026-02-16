use std::path::{Path, PathBuf};

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::error::PatternError;
use crate::finding::Confidence;
use crate::pattern::{Group, Pattern, Severity};

/// A finding that the user has explicitly acknowledged and suppressed.
///
/// Stored in the `[[ignore]]` array of `.vet.toml`. Each entry records enough
/// context to re-identify the finding and explain why it was suppressed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigIgnore {
    /// SHA-256 fingerprint of the suppressed secret.
    pub fingerprint: String,
    /// Pattern that originally matched (e.g. `"aws/access-key"`).
    pub pattern_id: String,
    /// File path where the finding was detected.
    pub file: String,
    /// Human-readable justification for suppressing the finding.
    pub reason: String,
}

/// Project-level configuration loaded from `.vet.toml`.
///
/// Controls which patterns are enabled, severity thresholds, file exclusions,
/// custom patterns, and inline suppressions. All fields are optional and
/// default to permissive values (scan everything, no threshold).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// Minimum severity level to report. Findings below this are filtered out.
    #[serde(default)]
    pub severity: Option<Severity>,

    /// Glob patterns for file paths to exclude from scanning.
    #[serde(default)]
    pub exclude_paths: Vec<String>,

    /// Maximum file size in bytes. Files larger than this are skipped.
    #[serde(default)]
    pub max_file_size: Option<u64>,

    /// Minimum confidence level for reported findings.
    ///
    /// Findings below this threshold are filtered out. Defaults to `High`,
    /// meaning only high-confidence matches are shown unless lowered.
    #[serde(default)]
    pub minimum_confidence: Confidence,

    /// User-defined secret detection patterns.
    #[serde(default)]
    pub patterns: Vec<CustomPattern>,

    /// Built-in pattern IDs to disable (e.g. `"generic/base64"`).
    #[serde(default)]
    pub disabled_patterns: Vec<String>,

    /// Path to the baseline file, relative to the config file.
    #[serde(default)]
    pub baseline_path: Option<String>,

    /// Findings that have been explicitly acknowledged and suppressed.
    #[serde(default, rename = "ignore")]
    pub ignores: Vec<ConfigIgnore>,
}

/// A user-defined secret detection pattern declared in `.vet.toml`.
///
/// Custom patterns are compiled into `Pattern` instances at startup and
/// participate in scanning alongside the built-in providers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomPattern {
    /// Unique identifier, conventionally prefixed with `"custom/"`.
    pub id: String,
    /// Human-readable name shown in diagnostics.
    pub name: String,
    /// Regular expression used to match secrets in source text.
    pub regex: String,
    /// Severity assigned to findings from this pattern.
    pub severity: Severity,
    /// Optional longer description. Falls back to `name` if absent.
    #[serde(default)]
    pub description: Option<String>,
    /// Aho-Corasick pre-filter keywords. If non-empty, the pattern is only
    /// tested against lines that contain at least one keyword.
    #[serde(default)]
    pub keywords: Vec<String>,
    /// Minimum Shannon entropy for a match to be classified as high confidence.
    #[serde(default)]
    pub min_entropy: Option<f64>,
}

impl CustomPattern {
    /// Compiles this definition into a `Pattern` ready for scanning.
    ///
    /// Returns `PatternError::InvalidRegex` if the regex is malformed.
    pub fn compile(&self) -> Result<Pattern, PatternError> {
        let regex = Regex::new(&self.regex).map_err(|source| PatternError::InvalidRegex {
            id: self.id.clone(),
            source,
        })?;

        Ok(Pattern {
            id: self.id.clone().into(),
            group: Group::Custom,
            name: self.name.clone().into(),
            description: self.description.clone().unwrap_or_else(|| self.name.clone()).into(),
            severity: self.severity,
            regex,
            keywords: self.keywords.iter().map(|s| s.as_str().into()).collect(),
            default_enabled: true,
            min_entropy: self.min_entropy,
        })
    }
}

impl Config {
    /// Creates a default configuration with no overrides.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads configuration from a `.vet.toml` file.
    ///
    /// Returns the default configuration if the file does not exist.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Ok(Self::new());
        }

        let content = read_file(path)?;
        parse_toml(path, &content)
    }

    /// Parses configuration from a TOML string.
    pub fn from_toml(content: &str) -> Result<Self, ConfigError> {
        toml::from_str(content).map_err(|source| ConfigError::Parse {
            path: PathBuf::from("<inline>"),
            source,
        })
    }

    /// Atomically writes this configuration to a `.vet.toml` file.
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        let content = serialise_toml(self)?;
        write_file(path, &content)
    }

    /// Serialises this configuration to a pretty-printed TOML string.
    pub fn to_toml(&self) -> Result<String, ConfigError> {
        serialise_toml(self)
    }

    /// Compiles all user-defined patterns into `Pattern` instances.
    ///
    /// Fails on the first pattern whose regex is invalid.
    pub fn compile_custom_patterns(&self) -> Result<Vec<Pattern>, PatternError> {
        self.patterns.iter().map(CustomPattern::compile).collect()
    }
}

fn read_file(path: &Path) -> Result<String, ConfigError> {
    std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })
}

fn write_file(path: &Path, content: &str) -> Result<(), ConfigError> {
    crate::fs_util::atomic_write(path, content).map_err(|source| ConfigError::Write {
        path: path.to_path_buf(),
        source,
    })
}

fn parse_toml(path: &Path, content: &str) -> Result<Config, ConfigError> {
    toml::from_str(content).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

fn serialise_toml(config: &Config) -> Result<String, ConfigError> {
    toml::to_string_pretty(config).map_err(|source| ConfigError::Serialize { source })
}

/// Errors that can occur when reading, parsing, serialising, or writing
/// a `.vet.toml` configuration file.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The config file could not be read from disk.
    #[error("failed to read config '{path}': {source}")]
    Read {
        /// Path to the config file that could not be read.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The config file contained invalid TOML or unexpected values.
    #[error("failed to parse config '{path}': {source}")]
    Parse {
        /// Path to the config file that could not be parsed.
        path: PathBuf,
        /// The underlying TOML deserialization error.
        #[source]
        source: toml::de::Error,
    },

    /// The in-memory configuration could not be serialised to TOML.
    #[error("failed to serialise config: {source}")]
    Serialize {
        /// The underlying TOML serialization error.
        #[source]
        source: toml::ser::Error,
    },

    /// The config file could not be written to disk.
    #[error("failed to write config '{path}': {source}")]
    Write {
        /// Path to the config file that could not be written.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

impl ConfigError {
    /// Returns the file path associated with this error, if any.
    ///
    /// `ConfigError::Serialize` errors have no associated path.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Read { path, .. } | Self::Parse { path, .. } | Self::Write { path, .. } => Some(path),
            Self::Serialize { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use serde::ser::Error;
    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn config_default_initialises_with_none_severity_and_empty_collections() {
        let config = Config::default();
        assert!(config.severity.is_none());
        assert!(config.exclude_paths.is_empty());
        assert!(config.max_file_size.is_none());
        assert_eq!(config.minimum_confidence, Confidence::High);
        assert!(config.patterns.is_empty());
        assert!(config.disabled_patterns.is_empty());
        assert!(config.baseline_path.is_none());
        assert!(config.ignores.is_empty());
    }

    #[test]
    fn config_new_is_identical_to_default() {
        let new = Config::new();
        let default = Config::default();
        assert_eq!(new.severity, default.severity);
        assert_eq!(new.exclude_paths, default.exclude_paths);
    }

    #[test]
    fn from_toml_parses_severity_only_config() {
        let toml = r#"severity = "high""#;
        let config = Config::from_toml(toml).unwrap();
        assert_eq!(config.severity, Some(Severity::High));
    }

    #[test]
    fn from_toml_parses_all_four_severity_levels() {
        for (toml, expected) in [
            (r#"severity = "low""#, Severity::Low),
            (r#"severity = "medium""#, Severity::Medium),
            (r#"severity = "high""#, Severity::High),
            (r#"severity = "critical""#, Severity::Critical),
        ] {
            let config = Config::from_toml(toml).unwrap();
            assert_eq!(config.severity, Some(expected));
        }
    }

    #[test]
    fn from_toml_parses_exclude_paths_array() {
        let toml = r#"exclude_paths = ["node_modules/**", "vendor/**", "*.test.js"]"#;
        let config = Config::from_toml(toml).unwrap();
        assert_eq!(config.exclude_paths.len(), 3);
        assert!(config.exclude_paths.contains(&"node_modules/**".to_string()));
    }

    #[test]
    fn from_toml_parses_max_file_size_in_bytes() {
        let toml = "max_file_size = 1048576";
        let config = Config::from_toml(toml).unwrap();
        assert_eq!(config.max_file_size, Some(1_048_576));
    }

    #[test]
    fn from_toml_parses_minimum_confidence() {
        let toml = r#"minimum_confidence = "low""#;
        let config = Config::from_toml(toml).unwrap();
        assert_eq!(config.minimum_confidence, Confidence::Low);
    }

    #[test]
    fn from_toml_parses_disabled_patterns_list() {
        let toml = r#"disabled_patterns = ["generic/base64", "generic/password-assignment"]"#;
        let config = Config::from_toml(toml).unwrap();
        assert_eq!(config.disabled_patterns.len(), 2);
    }

    #[test]
    fn from_toml_parses_minimal_custom_pattern() {
        let toml = r#"
            [[patterns]]
            id = "custom/my-token"
            name = "My Custom Token"
            regex = 'MY_TOKEN_[A-Z0-9]{32}'
            severity = "high"
        "#;
        let config = Config::from_toml(toml).unwrap();
        assert_eq!(config.patterns.len(), 1);
        assert_eq!(config.patterns[0].id, "custom/my-token");
        assert_eq!(config.patterns[0].severity, Severity::High);
    }

    #[test]
    fn from_toml_parses_custom_pattern_with_optional_fields() {
        let toml = r#"
            [[patterns]]
            id = "custom/full"
            name = "Full Pattern"
            regex = 'FULL_[A-Z]{16}'
            severity = "critical"
            description = "A fully specified pattern"
            keywords = ["FULL_"]
            min_entropy = 3.5
        "#;
        let config = Config::from_toml(toml).unwrap();
        let pattern = &config.patterns[0];
        assert_eq!(pattern.description, Some("A fully specified pattern".to_string()));
        assert_eq!(pattern.keywords, vec!["FULL_"]);
        assert_eq!(pattern.min_entropy, Some(3.5));
    }

    #[test]
    fn from_toml_parses_multiple_custom_patterns_in_order() {
        let toml = r#"
            [[patterns]]
            id = "custom/first"
            name = "First"
            regex = 'FIRST_[A-Z]{8}'
            severity = "low"

            [[patterns]]
            id = "custom/second"
            name = "Second"
            regex = 'SECOND_[A-Z]{8}'
            severity = "high"
        "#;
        let config = Config::from_toml(toml).unwrap();
        assert_eq!(config.patterns.len(), 2);
    }

    #[test]
    fn from_toml_parses_complete_config_with_all_fields() {
        let toml = r#"
            severity = "medium"
            max_file_size = 2097152
            exclude_paths = ["target/**"]
            minimum_confidence = "low"
            disabled_patterns = ["generic/base64"]

            [[patterns]]
            id = "custom/test"
            name = "Test"
            regex = 'TEST_[0-9]{8}'
            severity = "high"
        "#;
        let config = Config::from_toml(toml).unwrap();
        assert_eq!(config.severity, Some(Severity::Medium));
        assert_eq!(config.max_file_size, Some(2_097_152));
        assert_eq!(config.exclude_paths, vec!["target/**"]);
        assert_eq!(config.minimum_confidence, Confidence::Low);
        assert_eq!(config.disabled_patterns, vec!["generic/base64"]);
        assert_eq!(config.patterns.len(), 1);
    }

    #[test]
    fn from_toml_returns_defaults_for_empty_string() {
        let config = Config::from_toml("").unwrap();
        assert!(config.severity.is_none());
        assert!(config.patterns.is_empty());
    }

    #[test]
    fn from_toml_rejects_malformed_toml_syntax() {
        let result = Config::from_toml("this is { not valid toml");
        assert!(result.is_err());
    }

    #[test]
    fn from_toml_rejects_unknown_severity_value() {
        let result = Config::from_toml(r#"severity = "extreme""#);
        assert!(result.is_err());
    }

    #[test]
    fn load_returns_default_config_when_file_not_found() {
        let config = Config::load(Path::new("/nonexistent/path/.vet.toml")).unwrap();
        assert!(config.severity.is_none());
    }

    #[test]
    fn load_parses_existing_config_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"severity = "critical""#).unwrap();

        let config = Config::load(file.path()).unwrap();
        assert_eq!(config.severity, Some(Severity::Critical));
    }

    #[test]
    fn custom_pattern_compile_succeeds_with_valid_regex() {
        let pattern = CustomPattern {
            id: "test/valid".into(),
            name: "Valid Pattern".into(),
            regex: r"TEST_[A-Z]{8}".into(),
            severity: Severity::High,
            description: None,
            keywords: vec![],
            min_entropy: None,
        };
        let compiled = pattern.compile().unwrap();
        assert!(compiled.regex.is_match("TEST_ABCDEFGH"));
        assert!(!compiled.regex.is_match("TEST_abc"));
    }

    #[test]
    fn custom_pattern_compile_fails_with_unclosed_bracket() {
        let pattern = CustomPattern {
            id: "test/invalid".into(),
            name: "Invalid".into(),
            regex: r"[unclosed".into(),
            severity: Severity::Low,
            description: None,
            keywords: vec![],
            min_entropy: None,
        };
        let result = pattern.compile();
        assert!(result.is_err());
    }

    #[test]
    fn custom_pattern_compile_uses_name_when_description_absent() {
        let pattern = CustomPattern {
            id: "test/desc".into(),
            name: "My Pattern Name".into(),
            regex: r"X".into(),
            severity: Severity::Low,
            description: None,
            keywords: vec![],
            min_entropy: None,
        };
        let compiled = pattern.compile().unwrap();
        assert_eq!(compiled.description.as_ref(), "My Pattern Name");
    }

    #[test]
    fn custom_pattern_compile_preserves_explicit_description() {
        let pattern = CustomPattern {
            id: "test/desc".into(),
            name: "Name".into(),
            regex: r"X".into(),
            severity: Severity::Low,
            description: Some("Explicit description".into()),
            keywords: vec![],
            min_entropy: None,
        };
        let compiled = pattern.compile().unwrap();
        assert_eq!(compiled.description.as_ref(), "Explicit description");
    }

    #[test]
    fn custom_pattern_compile_assigns_custom_group() {
        let pattern = CustomPattern {
            id: "test/group".into(),
            name: "Test".into(),
            regex: r"X".into(),
            severity: Severity::Low,
            description: None,
            keywords: vec![],
            min_entropy: None,
        };
        let compiled = pattern.compile().unwrap();
        assert_eq!(compiled.group, Group::Custom);
    }

    #[test]
    fn compile_custom_patterns_returns_empty_vec_for_no_patterns() {
        let config = Config::default();
        let patterns = config.compile_custom_patterns().unwrap();
        assert!(patterns.is_empty());
    }

    #[test]
    fn compile_custom_patterns_compiles_all_patterns() {
        let config = Config::from_toml(
            r#"
            [[patterns]]
            id = "a"
            name = "A"
            regex = 'A'
            severity = "low"

            [[patterns]]
            id = "b"
            name = "B"
            regex = 'B'
            severity = "high"
        "#,
        )
        .unwrap();

        let patterns = config.compile_custom_patterns().unwrap();
        assert_eq!(patterns.len(), 2);
    }

    #[test]
    fn compile_custom_patterns_fails_fast_on_invalid_regex() {
        let config = Config::from_toml(
            r#"
            [[patterns]]
            id = "valid"
            name = "Valid"
            regex = 'OK'
            severity = "low"

            [[patterns]]
            id = "invalid"
            name = "Invalid"
            regex = '[broken'
            severity = "low"
        "#,
        )
        .unwrap();

        let result = config.compile_custom_patterns();
        assert!(result.is_err());
    }

    #[test]
    fn config_survives_serialise_deserialise_roundtrip() {
        let original = Config {
            severity: Some(Severity::High),
            exclude_paths: vec!["test/**".into()],
            max_file_size: Some(500_000),
            minimum_confidence: Confidence::Low,
            patterns: vec![],
            disabled_patterns: vec!["x".into()],
            baseline_path: Some(".vet-baseline.json".into()),
            ignores: vec![ConfigIgnore {
                fingerprint: "sha256:abc123".into(),
                pattern_id: "aws/access-key".into(),
                file: "src/test.py".into(),
                reason: "test".into(),
            }],
        };

        let toml = original.to_toml().unwrap();
        let restored = Config::from_toml(&toml).unwrap();

        assert_eq!(restored.severity, original.severity);
        assert_eq!(restored.exclude_paths, original.exclude_paths);
        assert_eq!(restored.max_file_size, original.max_file_size);
        assert_eq!(restored.minimum_confidence, original.minimum_confidence);
        assert_eq!(restored.disabled_patterns, original.disabled_patterns);
        assert_eq!(restored.baseline_path, original.baseline_path);
        assert_eq!(restored.ignores.len(), 1);
        assert_eq!(restored.ignores[0].fingerprint, "sha256:abc123");
    }

    #[test]
    fn config_error_includes_path_in_display() {
        let error = ConfigError::Read {
            path: PathBuf::from("/etc/vet.toml"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "file not found"),
        };
        let message = error.to_string();
        assert!(message.contains("/etc/vet.toml"));
    }

    #[test]
    fn config_error_path_returns_path_for_read_error() {
        let error = ConfigError::Read {
            path: PathBuf::from("/test/path"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
        };
        assert_eq!(error.path(), Some(Path::new("/test/path")));
    }

    #[test]
    fn config_error_path_returns_none_for_serialize_error() {
        let error = ConfigError::Serialize {
            source: toml::ser::Error::custom("test"),
        };
        assert!(error.path().is_none());
    }
}
