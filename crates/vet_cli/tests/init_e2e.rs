//! End-to-end tests for the `vet init` command.

use std::fs;

use assert_cmd::Command;
use insta::assert_snapshot;
use tempfile::TempDir;

fn vet() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vet"))
}

#[test]
fn creates_config_file() {
    let dir = TempDir::new().unwrap();

    vet().args(["init", "--yes"]).current_dir(dir.path()).assert().success();

    assert!(dir.path().join(".vet.toml").exists());
}

#[test]
fn minimal_flag_creates_config() {
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
fn minimal_config_content_snapshot() {
    let dir = TempDir::new().unwrap();

    vet()
        .args(["init", "--yes", "--minimal"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let config = fs::read_to_string(dir.path().join(".vet.toml")).unwrap();
    assert_snapshot!("init_minimal_config", config);
}

#[test]
fn init_then_scan_clean() {
    let dir = TempDir::new().unwrap();

    vet().args(["init", "--yes"]).current_dir(dir.path()).assert().success();

    assert!(dir.path().join(".vet.toml").exists());

    fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();

    vet().args(["scan", "."]).current_dir(dir.path()).assert().success();
}

#[test]
fn init_then_scan_finds_secret() {
    let dir = TempDir::new().unwrap();

    vet().args(["init", "--yes"]).current_dir(dir.path()).assert().success();

    fs::write(
        dir.path().join("config.env"),
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
    )
    .unwrap();

    vet().args(["scan", "."]).current_dir(dir.path()).assert().code(1);
}

#[test]
fn output_flag_specifies_path() {
    let dir = TempDir::new().unwrap();
    let custom_path = dir.path().join("custom-config.toml");

    vet()
        .args(["init", "--yes", "--output", custom_path.to_str().unwrap()])
        .current_dir(dir.path())
        .assert()
        .success();

    assert!(custom_path.exists());
    assert!(!dir.path().join(".vet.toml").exists());
}
