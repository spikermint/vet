//! Git object types used throughout the CLI.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use gix::bstr::ByteSlice as _;

const SHORT_HASH_LENGTH: usize = 7;

/// Wrapper around a raw git object ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectId(pub(super) gix::ObjectId);

impl ObjectId {
    pub(super) fn from_raw(oid: gix::ObjectId) -> Self {
        Self(oid)
    }

    pub(super) fn into_raw(self) -> gix::ObjectId {
        self.0
    }
}

/// A file that was added, modified, or rewritten in a commit.
#[derive(Debug, Clone)]
pub struct ChangedFile {
    /// Relative path within the repository.
    pub path: PathBuf,
    /// Object ID of the file blob at this commit.
    pub blob_id: ObjectId,
}

/// Metadata extracted from a git commit for display purposes.
#[derive(Debug, Clone)]
pub struct CommitInfo {
    /// Full hex SHA-1 hash.
    pub hash: String,
    /// Abbreviated hash (first 7 characters).
    pub short_hash: String,
    /// Author name from the commit signature.
    pub author_name: String,
    /// Author email from the commit signature.
    pub author_email: String,
    /// Commit timestamp in UTC.
    pub date: DateTime<Utc>,
    /// First line of the commit message.
    pub message: String,
}

impl CommitInfo {
    pub(super) fn from_gix_commit(commit: &gix::Commit<'_>) -> Self {
        let hash = commit.id().to_string();
        let short_hash = hash.get(..SHORT_HASH_LENGTH).unwrap_or(&hash).to_string();

        let (author_name, author_email) = commit.author().map_or_else(
            |_| ("unknown".to_string(), "unknown".to_string()),
            |sig| (sig.name.to_string(), sig.email.to_string()),
        );

        let date = commit
            .time()
            .ok()
            .and_then(|t| DateTime::from_timestamp(t.seconds, 0))
            .unwrap_or_default();

        let message = extract_first_line(commit);

        Self {
            hash,
            short_hash,
            author_name,
            author_email,
            date,
            message,
        }
    }
}

fn extract_first_line(commit: &gix::Commit<'_>) -> String {
    commit
        .message_raw()
        .map(|m| {
            m.lines()
                .next()
                .map(|line| String::from_utf8_lossy(line).into_owned())
                .unwrap_or_default()
        })
        .unwrap_or_default()
}
