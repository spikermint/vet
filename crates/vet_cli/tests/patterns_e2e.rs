//! End-to-end tests for the `vet patterns` command.

use assert_cmd::Command;
use predicates::prelude::*;

fn vet() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vet"))
}

#[test]
fn patterns_succeeds() {
    vet()
        .args(["patterns"])
        .assert()
        .success()
        .stdout(predicate::str::contains("patterns"));
}

#[test]
fn patterns_lists_known_patterns() {
    let output = vet().args(["patterns"]).output().unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("github") || stdout.contains("aws") || stdout.contains("stripe"));
}

#[test]
fn severity_filter_critical() {
    vet().args(["patterns", "--severity", "critical"]).assert().success();
}

#[test]
fn severity_filter_high() {
    vet().args(["patterns", "--severity", "high"]).assert().success();
}

#[test]
fn severity_filter_medium() {
    vet().args(["patterns", "--severity", "medium"]).assert().success();
}

#[test]
fn severity_filter_low() {
    vet().args(["patterns", "--severity", "low"]).assert().success();
}

#[test]
fn invalid_severity_fails() {
    vet().args(["patterns", "--severity", "extreme"]).assert().failure();
}

#[test]
fn group_filter() {
    vet().args(["patterns", "--group", "vcs"]).assert().success();
}

#[test]
fn verbose_shows_more_details() {
    let normal = vet().args(["patterns"]).output().unwrap();
    let verbose = vet().args(["patterns", "--verbose"]).output().unwrap();

    let normal_len = normal.stdout.len();
    let verbose_len = verbose.stdout.len();

    assert!(
        verbose_len >= normal_len,
        "verbose should show at least as much as normal"
    );
}
