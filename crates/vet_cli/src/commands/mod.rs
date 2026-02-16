//! CLI command handlers.

/// Baseline management for tracking acknowledged secrets.
pub mod baseline;
/// Interactive remediation of detected secrets.
pub mod fix;
/// Git history scanning for secrets in past commits.
pub mod history;
/// Git pre-commit hook installation and execution.
pub mod hook;
/// Project initialisation and `.vet.toml` creation.
pub mod init;
/// Pattern listing and inspection.
pub mod patterns;
/// File and directory scanning for secrets.
pub mod scan;

/// Convenience alias for command return types.
pub type Result<T = ()> = anyhow::Result<T>;
