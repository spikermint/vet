//! Types for history scanning.

use std::path::PathBuf;
use std::sync::Arc;

use crate::git::CommitInfo;

#[derive(Debug, Clone)]
pub struct HistoryOptions {
    pub limit: Option<usize>,
    pub since: Option<String>,
    pub until: String,
    pub branch: Option<String>,
    pub first_parent: bool,
    pub all: bool,
}

#[derive(Debug, Clone)]
pub struct SecretOccurrence {
    pub commit: Arc<CommitInfo>,
    pub path: PathBuf,
    pub line: u32,
    pub column: u32,
    pub line_content: String,
}

#[derive(Debug)]
pub struct HistoryFinding {
    pub finding: vet_core::Finding,
    pub introduced_in: SecretOccurrence,
    pub occurrences: Vec<SecretOccurrence>,
    pub occurrence_count: usize,
}

#[derive(Debug)]
pub struct HistoryScanResult {
    pub findings: Vec<HistoryFinding>,
    pub commits_scanned: usize,
}
