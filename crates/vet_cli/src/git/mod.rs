//! Git repository access for secret scanning.

mod local;
mod types;

use std::path::{Path, PathBuf};

use gix::ThreadSafeRepository;

pub use self::local::LocalRepo;
pub use self::types::{CommitInfo, ObjectId};
use crate::commands::history::HistoryOptions;

/// Default object cache size for tree diffs (64 MB).
const DEFAULT_CACHE_SIZE: usize = 64 * 1024 * 1024;

/// Thread-safe handle to a discovered git repository.
#[derive(Debug)]
pub struct Repo {
    /// The underlying `gix` thread-safe repository.
    inner: ThreadSafeRepository,
    /// Object cache size computed from the repository index.
    cache_size: usize,
}

impl Repo {
    /// Discovers and opens a git repository at or above the given path.
    #[must_use]
    pub fn discover(path: &Path) -> Option<Self> {
        let mut repo = gix::discover(path).ok()?;
        let cache_size = compute_cache_size(&repo);
        configure_cache(&mut repo, cache_size);
        let inner = repo.into_sync();
        Some(Self { inner, cache_size })
    }

    /// Opens the repository containing the current working directory.
    #[must_use]
    pub fn open_cwd() -> Option<Self> {
        Self::discover(&std::env::current_dir().ok()?)
    }

    /// Creates a thread-local repository handle for use within a rayon task.
    #[must_use]
    pub fn thread_local(&self) -> LocalRepo {
        let mut repo = self.inner.to_thread_local();
        configure_cache(&mut repo, self.cache_size);
        LocalRepo { inner: repo }
    }

    /// Returns `true` if this is a shallow clone with truncated history.
    #[must_use]
    pub fn is_shallow(&self) -> bool {
        self.inner.to_thread_local().is_shallow()
    }

    /// Collects commit object IDs matching the given history options.
    pub fn collect_commits(&self, opts: &HistoryOptions) -> anyhow::Result<Vec<ObjectId>> {
        self.thread_local().collect_commits(opts)
    }
}

fn compute_cache_size(repo: &gix::Repository) -> usize {
    repo.index_or_empty()
        .map(|idx| repo.compute_object_cache_size_for_tree_diffs(&idx))
        .unwrap_or(DEFAULT_CACHE_SIZE)
}

fn configure_cache(repo: &mut gix::Repository, size: usize) {
    repo.object_cache_size_if_unset(size);
}

/// Returns `true` if the current working directory is inside a git repository.
#[must_use]
pub fn in_repo() -> bool {
    Repo::open_cwd().is_some()
}

/// Returns the list of staged file paths, or `None` if not in a repository.
#[must_use]
pub fn staged_files() -> Option<Vec<PathBuf>> {
    Repo::open_cwd().map(|repo| repo.thread_local().staged_files())
}

/// Reads the staged (index) content of a file as UTF-8 text.
#[must_use]
pub fn staged_content(path: &Path) -> Option<String> {
    Repo::open_cwd()?.thread_local().staged_content(path)
}
