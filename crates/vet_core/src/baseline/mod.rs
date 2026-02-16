//! Baseline support for tracking acknowledged findings.

mod error;
mod file;
mod finding;
mod fingerprint;
mod matcher;

pub use error::BaselineError;
pub use file::Baseline;
pub use finding::{BaselineFinding, BaselineStatus};
pub use fingerprint::Fingerprint;
pub use matcher::IgnoreMatcher;
