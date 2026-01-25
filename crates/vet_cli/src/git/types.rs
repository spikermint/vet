//! Git object types used throughout the CLI.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use gix::bstr::ByteSlice as _;

const SHORT_HASH_LENGTH: usize = 7;

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

#[derive(Debug, Clone)]
pub struct ChangedFile {
    pub path: PathBuf,
    pub blob_id: ObjectId,
}

#[derive(Debug, Clone)]
pub struct CommitInfo {
    pub hash: String,
    pub short_hash: String,
    pub author_name: String,
    pub author_email: String,
    pub date: DateTime<Utc>,
    pub message: String,
}

impl CommitInfo {
    pub(super) fn from_gix_commit(commit: &gix::Commit<'_>) -> Self {
        let hash = commit.id().to_string();
        let short_hash = hash.get(..SHORT_HASH_LENGTH).unwrap_or(&hash).to_string();

        let (author_name, author_email) = commit
            .author()
            .map(|sig| (sig.name.to_string(), sig.email.to_string()))
            .unwrap_or_else(|_| ("unknown".to_string(), "unknown".to_string()));

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
