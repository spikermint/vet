//! End-to-end tests for the `vet history` command.

#![expect(clippy::expect_used, reason = "tests use expect for clearer failure messages")]

use std::fs;
use std::process::Command as StdCommand;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn vet() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vet"))
}

fn init_git_repo(dir: &TempDir) {
    StdCommand::new("git")
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .expect("git init failed");

    StdCommand::new("git")
        .args(["config", "user.email", "test@test.com"])
        .current_dir(dir.path())
        .output()
        .expect("git config email failed");

    StdCommand::new("git")
        .args(["config", "user.name", "Test User"])
        .current_dir(dir.path())
        .output()
        .expect("git config name failed");
}

fn commit(dir: &TempDir, file: &str, content: &str, msg: &str) {
    fs::write(dir.path().join(file), content).expect("write failed");

    StdCommand::new("git")
        .args(["add", file])
        .current_dir(dir.path())
        .output()
        .expect("git add failed");

    StdCommand::new("git")
        .args(["commit", "-m", msg])
        .current_dir(dir.path())
        .output()
        .expect("git commit failed");
}

#[test]
fn history_finds_secret_in_current_commit() {
    let dir = TempDir::new().unwrap();
    init_git_repo(&dir);

    commit(
        &dir,
        "secret.env",
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
        "Add secret",
    );

    vet()
        .args(["history"])
        .current_dir(dir.path())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("ghp_"));
}

#[test]
fn history_finds_deleted_secret() {
    let dir = TempDir::new().unwrap();
    init_git_repo(&dir);

    commit(
        &dir,
        "secret.env",
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
        "Add secret",
    );

    commit(&dir, "secret.env", "GITHUB_TOKEN=redacted", "Remove secret");

    // Secret no longer in HEAD, but should be found in history
    vet()
        .args(["history"])
        .current_dir(dir.path())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("ghp_"));
}

#[test]
fn history_no_secrets_returns_success() {
    let dir = TempDir::new().unwrap();
    init_git_repo(&dir);

    commit(&dir, "clean.txt", "nothing secret here", "Clean commit");

    vet()
        .args(["history"])
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("No secrets"));
}

#[test]
fn history_limit_flag() {
    let dir = TempDir::new().unwrap();
    init_git_repo(&dir);

    commit(
        &dir,
        "secret.env",
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
        "Add secret",
    );

    commit(&dir, "clean.txt", "clean content", "Clean commit");

    // Only scan last commit (which is clean)
    vet()
        .args(["history", "-n", "1"])
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("No secrets"));
}

#[test]
fn history_json_output() {
    let dir = TempDir::new().unwrap();
    init_git_repo(&dir);

    commit(
        &dir,
        "secret.env",
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
        "Add secret",
    );

    let output = vet()
        .args(["history", "--format=json"])
        .current_dir(dir.path())
        .output()
        .expect("failed to run");

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("invalid json");

    assert_eq!(json["scan_type"], "history");
    assert!(!json["findings"].as_array().unwrap().is_empty());
    assert!(json["findings"][0]["introduced_in"]["commit"]["hash"].is_string());
}

#[test]
fn history_sarif_output() {
    let dir = TempDir::new().unwrap();
    init_git_repo(&dir);

    commit(
        &dir,
        "secret.env",
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
        "Add secret",
    );

    let output = vet()
        .args(["history", "--format=sarif"])
        .current_dir(dir.path())
        .output()
        .expect("failed to run");

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("invalid json");

    assert_eq!(json["version"], "2.1.0");
    assert!(!json["runs"][0]["results"].as_array().unwrap().is_empty());
}

#[test]
fn history_exit_zero_flag() {
    let dir = TempDir::new().unwrap();
    init_git_repo(&dir);

    commit(
        &dir,
        "secret.env",
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
        "Add secret",
    );

    vet()
        .args(["history", "--exit-zero"])
        .current_dir(dir.path())
        .assert()
        .success();
}

#[test]
fn history_requires_git_repo() {
    let dir = TempDir::new().unwrap();
    // No git init

    vet()
        .args(["history"])
        .current_dir(dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("not a git repository"));
}

#[test]
fn history_output_to_file() {
    let dir = TempDir::new().unwrap();
    init_git_repo(&dir);

    commit(
        &dir,
        "secret.env",
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
        "Add secret",
    );

    let output_path = dir.path().join("report.json");

    vet()
        .args(["history", "--format=json", "-o", output_path.to_str().unwrap()])
        .current_dir(dir.path())
        .assert()
        .code(1);

    assert!(output_path.exists());
    let content = fs::read_to_string(&output_path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).expect("invalid json");
    assert_eq!(json["scan_type"], "history");
}

#[test]
fn history_all_flag_shows_multiple_occurrences() {
    let dir = TempDir::new().unwrap();
    init_git_repo(&dir);

    // Same secret in two commits
    commit(
        &dir,
        "secret.env",
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
        "Add secret",
    );

    commit(
        &dir,
        "secret.env",
        "# comment\nGITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
        "Modify file",
    );

    // With --all, should show "introduced" marker
    vet()
        .args(["history", "--all"])
        .current_dir(dir.path())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("introduced"));
}
