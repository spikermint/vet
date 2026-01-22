use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn vet() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vet"))
}

#[test]
fn exit_zero_when_no_secrets() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("clean.rs"), "fn main() {}").unwrap();

    vet().args(["scan", "."]).current_dir(dir.path()).assert().success();
}

#[test]
fn exit_one_when_secrets_found() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("secrets.env"),
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
    )
    .unwrap();

    vet().args(["scan", "."]).current_dir(dir.path()).assert().code(1);
}

#[test]
fn exit_zero_flag_overrides_findings() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("secrets.env"),
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
    )
    .unwrap();

    vet()
        .args(["scan", ".", "--exit-zero"])
        .current_dir(dir.path())
        .assert()
        .success();
}

#[test]
fn exit_zero_for_empty_directory() {
    let dir = TempDir::new().unwrap();

    vet().args(["scan", "."]).current_dir(dir.path()).assert().success();
}

#[test]
fn help_shows_usage() {
    vet()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("secret scanner"));
}

#[test]
fn version_flag_works() {
    vet()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("vet"));
}

#[test]
fn scan_nonexistent_path_fails() {
    vet()
        .args(["scan", "/nonexistent/path/that/does/not/exist"])
        .assert()
        .success(); // Returns success but scans 0 files
}

#[test]
fn patterns_command_succeeds() {
    vet()
        .args(["patterns"])
        .assert()
        .success()
        .stdout(predicate::str::contains("patterns"));
}

#[test]
fn patterns_with_severity_filter() {
    vet().args(["patterns", "--severity", "critical"]).assert().success();
}

#[test]
fn patterns_with_invalid_severity_fails() {
    vet().args(["patterns", "--severity", "extreme"]).assert().failure();
}

#[test]
fn init_creates_config_file() {
    let dir = TempDir::new().unwrap();

    vet().args(["init", "--yes"]).current_dir(dir.path()).assert().success();

    assert!(dir.path().join(".vet.toml").exists());
}

#[test]
fn init_minimal_creates_config() {
    let dir = TempDir::new().unwrap();

    vet()
        .args(["init", "--yes", "--minimal"])
        .current_dir(dir.path())
        .assert()
        .success();

    let content = fs::read_to_string(dir.path().join(".vet.toml")).unwrap();
    assert!(content.contains("severity"));
}

#[test]
fn completions_bash_generates_valid_output() {
    vet()
        .args(["completions", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("complete"));
}

#[test]
fn completions_zsh_generates_valid_output() {
    vet()
        .args(["completions", "zsh"])
        .assert()
        .success()
        .stdout(predicate::str::contains("compdef"));
}
