//! Convenience re-exports of the most commonly used types.

pub use crate::baseline::{Baseline, BaselineError, BaselineFinding, BaselineStatus, Fingerprint, IgnoreMatcher};
pub use crate::config::{Config, ConfigError};
pub use crate::error::{PatternError, VetError};
pub use crate::finding::{Confidence, Finding, FindingId, Secret, Span};
pub use crate::pattern::{DetectionStrategy, Group, Pattern, PatternRegistry, Severity};
pub use crate::scanner::Scanner;
