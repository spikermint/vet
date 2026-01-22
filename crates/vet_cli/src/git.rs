use std::path::{Path, PathBuf};

use git2::{DiffOptions, Repository};

pub struct Repo {
    inner: Repository,
}

impl Repo {
    pub fn discover(path: &Path) -> Option<Self> {
        Repository::discover(path).ok().map(|inner| Self { inner })
    }

    pub fn open_cwd() -> Option<Self> {
        let cwd = std::env::current_dir().ok()?;
        Self::discover(&cwd)
    }

    pub fn staged_files(&self) -> Vec<PathBuf> {
        let head_tree = self.inner.head().ok().and_then(|h| h.peel_to_tree().ok());

        let mut opts = DiffOptions::new();
        opts.include_untracked(false);

        let diff = self
            .inner
            .diff_tree_to_index(head_tree.as_ref(), None, Some(&mut opts))
            .ok();

        let Some(diff) = diff else {
            return Vec::new();
        };

        let mut files = Vec::new();

        for delta in diff.deltas() {
            if let Some(path) = delta.new_file().path() {
                files.push(path.to_path_buf());
            }
        }

        files
    }

    pub fn staged_content(&self, path: &Path) -> Option<String> {
        let index = self.inner.index().ok()?;
        let entry = index.get_path(path, 0)?;
        let blob = self.inner.find_blob(entry.id).ok()?;

        if blob.is_binary() {
            return None;
        }

        String::from_utf8(blob.content().to_vec()).ok()
    }
}

pub fn staged_files() -> Option<Vec<PathBuf>> {
    Repo::open_cwd().map(|repo| repo.staged_files())
}

pub fn staged_content(path: &Path) -> Option<String> {
    Repo::open_cwd()?.staged_content(path)
}

pub fn in_repo() -> bool {
    Repo::open_cwd().is_some()
}
