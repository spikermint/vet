//! End-to-end tests for the `vet completions` command.

use assert_cmd::Command;
use predicates::prelude::*;

fn vet() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vet"))
}

#[test]
fn bash_completions() {
    vet()
        .args(["completions", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("complete"));
}

#[test]
fn zsh_completions() {
    vet()
        .args(["completions", "zsh"])
        .assert()
        .success()
        .stdout(predicate::str::contains("compdef"));
}

#[test]
fn fish_completions() {
    vet()
        .args(["completions", "fish"])
        .assert()
        .success()
        .stdout(predicate::str::contains("complete"));
}

#[test]
fn powershell_completions() {
    vet().args(["completions", "powershell"]).assert().success();
}

#[test]
fn elvish_completions() {
    vet().args(["completions", "elvish"]).assert().success();
}

#[test]
fn invalid_shell_fails() {
    vet().args(["completions", "invalid-shell"]).assert().failure();
}
