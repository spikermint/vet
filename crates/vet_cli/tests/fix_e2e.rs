//! End-to-end tests for the `vet fix` command.

use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn vet() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vet"))
}

#[test]
fn help_shows_usage() {
    vet()
        .args(["fix", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("dry-run"))
        .stdout(predicate::str::contains("severity"));
}

#[test]
fn no_secrets_shows_success() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("clean.rs"), "fn main() {}").unwrap();

    vet()
        .args(["fix", "."])
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("no secrets"));
}

#[test]
fn no_files_shows_warning() {
    let dir = TempDir::new().unwrap();

    vet()
        .args(["fix", "."])
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("no files"));
}

#[test]
fn exclude_pattern_works() {
    let dir = TempDir::new().unwrap();

    let vendor = dir.path().join("vendor");
    fs::create_dir(&vendor).unwrap();
    fs::write(vendor.join("secret.rs"), r#"let k = "sk_live_abc123def456ghi789";"#).unwrap();

    vet()
        .args(["fix", ".", "--exclude", "vendor/**"])
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("no files").or(predicate::str::contains("no secrets")));
}

#[test]
fn severity_filter_works() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("test.rs"), "fn main() {}").unwrap();

    vet()
        .args(["fix", ".", "--severity", "critical"])
        .current_dir(dir.path())
        .assert()
        .success();
}

#[test]
fn dry_run_flag_accepted() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("clean.rs"), "fn main() {}").unwrap();

    vet()
        .args(["fix", ".", "--dry-run"])
        .current_dir(dir.path())
        .assert()
        .success();
}

#[test]
fn config_file_flag_accepted() {
    let dir = TempDir::new().unwrap();

    fs::write(dir.path().join("custom.toml"), r#"severity = "high""#).unwrap();
    fs::write(dir.path().join("clean.rs"), "fn main() {}").unwrap();

    vet()
        .args(["fix", ".", "--config", "custom.toml"])
        .current_dir(dir.path())
        .assert()
        .success();
}

#[test]
fn skip_gitignore_flag_accepted() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("clean.rs"), "fn main() {}").unwrap();

    vet()
        .args(["fix", ".", "--skip-gitignore"])
        .current_dir(dir.path())
        .assert()
        .success();
}

#[test]
fn max_file_size_flag_accepted() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("clean.rs"), "fn main() {}").unwrap();

    vet()
        .args(["fix", ".", "--max-file-size", "1000000"])
        .current_dir(dir.path())
        .assert()
        .success();
}

#[test]
fn alias_f_works() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("clean.rs"), "fn main() {}").unwrap();

    vet()
        .args(["f", "."])
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("no secrets"));
}
