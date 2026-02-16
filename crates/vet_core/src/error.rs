use thiserror::Error;

/// Errors that can occur when compiling a secret detection pattern.
#[derive(Debug, Error)]
pub enum PatternError {
    /// The pattern's regular expression failed to compile.
    #[error("invalid regex in pattern '{id}': {source}")]
    InvalidRegex {
        /// Identifier of the pattern that failed (e.g. `"aws/access-key"`).
        id: String,
        /// The underlying regex compilation error.
        #[source]
        source: regex::Error,
    },
}

/// Top-level error type for the vet scanning pipeline.
///
/// Unifies errors from pattern compilation, configuration loading, and
/// baseline operations into a single type for callers that orchestrate
/// the full workflow.
#[derive(Debug, Error)]
pub enum VetError {
    /// A pattern failed to compile.
    #[error(transparent)]
    Pattern(#[from] PatternError),

    /// Configuration could not be read, parsed, or written.
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),

    /// A baseline file could not be loaded or saved.
    #[error(transparent)]
    Baseline(#[from] crate::baseline::BaselineError),
}
