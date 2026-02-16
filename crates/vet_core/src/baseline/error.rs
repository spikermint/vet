use std::path::PathBuf;

use thiserror::Error;

/// Errors that can occur when loading, saving, or parsing a baseline file.
#[derive(Debug, Error)]
pub enum BaselineError {
    /// The baseline file does not exist at the expected path.
    #[error("baseline file not found: {path}")]
    NotFound {
        /// Path where the baseline file was expected.
        path: PathBuf,
    },

    /// The baseline file exists but its structure is invalid.
    #[error("invalid baseline file: {path}")]
    Invalid {
        /// Path to the invalid baseline file.
        path: PathBuf,
    },

    /// The baseline file declares a version this build does not support.
    #[error("unsupported baseline version: {version}")]
    UnsupportedVersion {
        /// The unsupported version string found in the file.
        version: String,
    },

    /// The baseline file could not be read from disk.
    #[error("failed to read baseline file '{path}': {source}")]
    Read {
        /// Path to the file that could not be read.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The baseline file could not be written to disk.
    #[error("failed to write baseline file '{path}': {source}")]
    Write {
        /// Path to the file that could not be written.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The baseline file contained invalid JSON.
    #[error("failed to parse baseline file '{path}': {source}")]
    Parse {
        /// Path to the file that could not be parsed.
        path: PathBuf,
        /// The underlying JSON parse error.
        #[source]
        source: serde_json::Error,
    },
}
