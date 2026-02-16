//! End-to-end tests for global CLI behaviour (help, version, etc.).

use assert_cmd::Command;
use predicates::prelude::*;

fn vet() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vet"))
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
fn help_lists_commands() {
    vet()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("scan"))
        .stdout(predicate::str::contains("fix"))
        .stdout(predicate::str::contains("init"))
        .stdout(predicate::str::contains("history"))
        .stdout(predicate::str::contains("patterns"));
}

#[test]
fn version_flag() {
    vet()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("vet"));
}

#[test]
fn version_format() {
    let output = vet().arg("--version").output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("vet") && stdout.chars().any(|c| c.is_ascii_digit()),
        "version should contain 'vet' and a version number"
    );
}

#[test]
fn no_args_shows_help() {
    vet().assert().failure().stderr(predicate::str::contains("Usage"));
}

#[test]
fn invalid_command_fails() {
    vet().arg("invalid-command").assert().failure();
}
