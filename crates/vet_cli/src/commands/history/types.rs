//! Types for history scanning.

use std::path::PathBuf;
use std::sync::Arc;

use crate::git::CommitInfo;

/// Options controlling which commits to include in a history scan.
#[derive(Debug, Clone)]
pub struct HistoryOptions {
    /// Maximum number of commits to scan.
    pub limit: Option<usize>,
    /// Start scanning from this ref.
    pub since: Option<String>,
    /// Stop scanning at this ref.
    pub until: String,
    /// Branch to scan.
    pub branch: Option<String>,
    /// Follow only the first parent of merge commits.
    pub first_parent: bool,
    /// Scan all branches and refs.
    pub all: bool,
}

/// A single occurrence of a secret in a specific commit.
#[derive(Debug, Clone)]
pub struct SecretOccurrence {
    /// The commit where this occurrence was found.
    pub commit: Arc<CommitInfo>,
    /// File path within the commit tree.
    pub path: PathBuf,
    /// One-based line number.
    pub line: u32,
    /// One-based column number.
    pub column: u32,
    /// The masked line content for display.
    pub line_content: String,
}

/// A secret found across git history, with its introduction point and all occurrences.
#[derive(Debug)]
pub struct HistoryFinding {
    /// The underlying finding from the scanner.
    pub finding: vet_core::Finding,
    /// The earliest commit where this secret appeared.
    pub introduced_in: SecretOccurrence,
    /// All commits containing this secret.
    pub occurrences: Vec<SecretOccurrence>,
    /// Total number of occurrences across all commits.
    pub occurrence_count: usize,
}

/// Results from a complete history scan.
#[derive(Debug)]
pub struct HistoryScanResult {
    /// Unique secrets found across the scanned commits.
    pub findings: Vec<HistoryFinding>,
    /// Total number of commits that were scanned.
    pub commits_scanned: usize,
}
