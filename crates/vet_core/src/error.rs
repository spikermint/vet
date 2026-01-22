use thiserror::Error;

#[derive(Debug, Error)]
pub enum PatternError {
    #[error("invalid regex in pattern '{id}': {source}")]
    InvalidRegex {
        id: String,
        #[source]
        source: regex::Error,
    },
}

#[derive(Debug, Error)]
pub enum VetError {
    #[error(transparent)]
    Pattern(#[from] PatternError),

    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
}
