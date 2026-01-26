//! Git integration for determining secret exposure status.
//!
//! Checks whether a detected secret exists in the committed history (HEAD)
//! to provide context aware remediation guidance.

use std::path::Path;

use gix::bstr::ByteSlice as _;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExposureRisk {
    /// Secret not found in HEAD. Safe to remove before committing.
    NotInHistory,

    /// Secret exists in HEAD. Already in git history, rotation required.
    InHistory,

    /// Cannot determine (no git repo, git error, etc.). Show generic advice.
    #[default]
    Unknown,
}

pub struct GitContext {
    repo: gix::Repository,
}

impl GitContext {
    pub fn discover(path: &Path) -> Option<Self> {
        gix::discover(path).ok().map(|repo| Self { repo })
    }

    pub fn check_secret_exposure(&self, file_path: &Path, secret: &str) -> ExposureRisk {
        let Some(relative_path) = self.make_relative(file_path) else {
            return ExposureRisk::Unknown;
        };

        let Some(head_content) = self.read_file_from_head(&relative_path) else {
            return ExposureRisk::NotInHistory;
        };

        if head_content.contains(secret) {
            ExposureRisk::InHistory
        } else {
            ExposureRisk::NotInHistory
        }
    }

    fn make_relative(&self, file_path: &Path) -> Option<String> {
        let workdir = self.repo.workdir()?;
        let relative = file_path.strip_prefix(workdir).ok()?;
        Some(relative.to_string_lossy().into_owned())
    }

    fn read_file_from_head(&self, relative_path: &str) -> Option<String> {
        let head = self.repo.head_commit().ok()?;
        let tree = head.tree().ok()?;

        let entry = tree.lookup_entry_by_path(relative_path).ok().flatten()?;

        let object = entry.object().ok()?;
        let blob = object.try_into_blob().ok()?;

        blob.data.to_str().ok().map(ToString::to_string)
    }
}

impl std::fmt::Debug for GitContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitContext")
            .field("workdir", &self.repo.workdir())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::Command;

    use tempfile::TempDir;

    use super::*;

    fn init_git_repo(dir: &TempDir) {
        Command::new("git")
            .args(["init"])
            .current_dir(dir.path())
            .output()
            .expect("git init failed");

        Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(dir.path())
            .output()
            .expect("git config email failed");

        Command::new("git")
            .args(["config", "user.name", "Test User"])
            .current_dir(dir.path())
            .output()
            .expect("git config name failed");
    }

    fn commit_file(dir: &TempDir, filename: &str, content: &str) {
        fs::write(dir.path().join(filename), content).expect("write failed");

        Command::new("git")
            .args(["add", filename])
            .current_dir(dir.path())
            .output()
            .expect("git add failed");

        Command::new("git")
            .args(["commit", "-m", "commit"])
            .current_dir(dir.path())
            .output()
            .expect("git commit failed");
    }

    #[test]
    fn discover_returns_none_outside_git_repo() {
        let dir = TempDir::new().unwrap();
        let context = GitContext::discover(dir.path());
        assert!(context.is_none());
    }

    #[test]
    fn discover_returns_context_in_git_repo() {
        let dir = TempDir::new().unwrap();
        init_git_repo(&dir);
        commit_file(&dir, "initial.txt", "init");

        let context = GitContext::discover(dir.path());
        assert!(context.is_some());
    }

    #[test]
    fn secret_not_in_history_for_new_file() {
        let dir = TempDir::new().unwrap();
        init_git_repo(&dir);
        commit_file(&dir, "initial.txt", "init");

        let new_file = dir.path().join("new.txt");
        fs::write(&new_file, "SECRET_TOKEN").unwrap();

        let context = GitContext::discover(dir.path()).unwrap();
        let risk = context.check_secret_exposure(&new_file, "SECRET_TOKEN");

        assert_eq!(risk, ExposureRisk::NotInHistory);
    }

    #[test]
    fn secret_in_history_when_committed() {
        let dir = TempDir::new().unwrap();
        init_git_repo(&dir);
        commit_file(&dir, "config.txt", "api_key = SECRET_TOKEN");

        let file_path = dir.path().join("config.txt");
        let context = GitContext::discover(dir.path()).unwrap();
        let risk = context.check_secret_exposure(&file_path, "SECRET_TOKEN");

        assert_eq!(risk, ExposureRisk::InHistory);
    }

    #[test]
    fn new_secret_in_existing_file_not_in_history() {
        let dir = TempDir::new().unwrap();
        init_git_repo(&dir);
        commit_file(&dir, "config.txt", "old_content");

        let file_path = dir.path().join("config.txt");
        fs::write(&file_path, "old_content\nNEW_SECRET").unwrap();

        let context = GitContext::discover(dir.path()).unwrap();
        let risk = context.check_secret_exposure(&file_path, "NEW_SECRET");

        assert_eq!(risk, ExposureRisk::NotInHistory);
    }

    #[test]
    fn modified_secret_not_in_history() {
        let dir = TempDir::new().unwrap();
        init_git_repo(&dir);
        commit_file(&dir, "config.txt", "key = sk_live_abc123");

        let file_path = dir.path().join("config.txt");
        fs::write(&file_path, "key = sk_live_xyz789").unwrap();

        let context = GitContext::discover(dir.path()).unwrap();
        let risk = context.check_secret_exposure(&file_path, "sk_live_xyz789");

        assert_eq!(risk, ExposureRisk::NotInHistory);
    }
}
