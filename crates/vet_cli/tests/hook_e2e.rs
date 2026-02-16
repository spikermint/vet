//! End-to-end tests for the `vet hook` command.

#![expect(clippy::expect_used, reason = "tests use expect for clearer failure messages")]

use std::fs;

use assert_cmd::Command;
use tempfile::TempDir;

fn vet() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vet"))
}

fn init_git_repo(dir: &TempDir) {
    std::process::Command::new("git")
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .expect("git init failed");
}

#[test]
fn install_requires_git_repo() {
    let dir = TempDir::new().unwrap();

    vet()
        .args(["hook", "install"])
        .current_dir(dir.path())
        .assert()
        .failure();
}

#[test]
#[cfg(unix)]
fn install_creates_executable_pre_commit() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    init_git_repo(&dir);

    vet()
        .args(["hook", "install"])
        .current_dir(dir.path())
        .assert()
        .success();

    let hook_path = dir.path().join(".git/hooks/pre-commit");
    assert!(hook_path.exists());

    let content = fs::read_to_string(&hook_path).unwrap();
    assert!(content.contains("vet"));

    let metadata = fs::metadata(&hook_path).unwrap();
    let permissions = metadata.permissions();
    assert!(permissions.mode() & 0o111 != 0, "hook should be executable");
}

#[test]
fn install_twice_is_idempotent() {
    let dir = TempDir::new().unwrap();
    init_git_repo(&dir);

    vet()
        .args(["hook", "install"])
        .current_dir(dir.path())
        .assert()
        .success();

    vet()
        .args(["hook", "install"])
        .current_dir(dir.path())
        .assert()
        .success();

    let hook_path = dir.path().join(".git/hooks/pre-commit");
    assert!(hook_path.exists());
}

#[test]
fn uninstall_removes_hook() {
    let dir = TempDir::new().unwrap();
    init_git_repo(&dir);

    vet()
        .args(["hook", "install"])
        .current_dir(dir.path())
        .assert()
        .success();

    vet()
        .args(["hook", "uninstall"])
        .current_dir(dir.path())
        .assert()
        .success();

    let hook_path = dir.path().join(".git/hooks/pre-commit");
    if hook_path.exists() {
        let content = fs::read_to_string(&hook_path).unwrap();
        assert!(!content.contains("vet"), "hook should not contain vet");
    }
}

#[test]
fn status_shows_no_hook_when_none_installed() {
    let dir = TempDir::new().unwrap();
    init_git_repo(&dir);

    vet().args(["hook"]).current_dir(dir.path()).assert().success();
}

#[test]
fn status_shows_installed_when_present() {
    let dir = TempDir::new().unwrap();
    init_git_repo(&dir);

    vet()
        .args(["hook", "install"])
        .current_dir(dir.path())
        .assert()
        .success();

    vet().args(["hook"]).current_dir(dir.path()).assert().success();
}
