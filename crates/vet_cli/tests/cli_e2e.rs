#![allow(clippy::expect_used)]

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
fn workflow_init_then_scan() {
    let dir = TempDir::new().unwrap();

    // Initialise config
    vet().args(["init", "--yes"]).current_dir(dir.path()).assert().success();

    assert!(dir.path().join(".vet.toml").exists());

    // Create a clean file
    fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();

    // Scan should use the config
    vet().args(["scan", "."]).current_dir(dir.path()).assert().success();
}

#[test]
fn workflow_init_then_scan_finds_secret() {
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
fn workflow_config_exclude_paths() {
    let dir = TempDir::new().unwrap();

    // Create config with exclusion
    fs::write(
        dir.path().join(".vet.toml"),
        r#"
exclude_paths = ["secrets/**"]
"#,
    )
    .unwrap();

    // Put secret in excluded directory
    let secrets_dir = dir.path().join("secrets");
    fs::create_dir(&secrets_dir).unwrap();
    fs::write(
        secrets_dir.join("api.env"),
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
    )
    .unwrap();

    // Should pass because secrets/ is excluded
    vet().args(["scan", "."]).current_dir(dir.path()).assert().success();
}

#[test]
fn workflow_config_severity_threshold() {
    let dir = TempDir::new().unwrap();

    // Create config with high severity threshold
    fs::write(
        dir.path().join(".vet.toml"),
        r#"
severity = "critical"
"#,
    )
    .unwrap();

    // Create file with a high-severity secret
    fs::write(
        dir.path().join("config.env"),
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
    )
    .unwrap();

    // GitHub tokens are critical, should still be found
    vet().args(["scan", "."]).current_dir(dir.path()).assert().code(1);
}

#[test]
fn workflow_cli_args_override_config() {
    let dir = TempDir::new().unwrap();

    // Config says scan everything
    fs::write(
        dir.path().join(".vet.toml"),
        r#"
severity = "low"
"#,
    )
    .unwrap();

    fs::write(
        dir.path().join("secret.env"),
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
    )
    .unwrap();

    // CLI --exclude should override
    vet()
        .args(["scan", ".", "--exclude", "*.env"])
        .current_dir(dir.path())
        .assert()
        .success();
}

#[test]
#[cfg(unix)]
fn workflow_hook_install_creates_pre_commit() {
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

    // Check it's executable
    let metadata = fs::metadata(&hook_path).unwrap();
    let permissions = metadata.permissions();
    assert!(permissions.mode() & 0o111 != 0);
}

#[test]
fn workflow_hook_install_twice_is_idempotent() {
    let dir = TempDir::new().unwrap();
    init_git_repo(&dir);

    vet()
        .args(["hook", "install"])
        .current_dir(dir.path())
        .assert()
        .success();

    // Second install should also succeed
    vet()
        .args(["hook", "install"])
        .current_dir(dir.path())
        .assert()
        .success();

    let hook_path = dir.path().join(".git/hooks/pre-commit");
    assert!(hook_path.exists());
}

#[test]
fn workflow_hook_uninstall() {
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
    // Hook should be removed or no longer contain vet
    if hook_path.exists() {
        let content = fs::read_to_string(&hook_path).unwrap();
        assert!(!content.contains("vet"));
    }
}

#[test]
fn workflow_hook_install_no_git_repo_fails() {
    let dir = TempDir::new().unwrap();

    vet()
        .args(["hook", "install"])
        .current_dir(dir.path())
        .assert()
        .failure();
}

#[test]
fn workflow_custom_pattern() {
    let dir = TempDir::new().unwrap();

    fs::write(
        dir.path().join(".vet.toml"),
        r#"
[[patterns]]
id = "custom/my-token"
name = "My Custom Token"
regex = 'MYAPP_[A-Z0-9]{16}'
severity = "high"
keywords = ["MYAPP_"]
"#,
    )
    .unwrap();

    fs::write(dir.path().join("config.txt"), "token = MYAPP_ABCD1234EFGH5678").unwrap();

    vet().args(["scan", "."]).current_dir(dir.path()).assert().code(1);
}

#[test]
fn workflow_disabled_pattern() {
    let dir = TempDir::new().unwrap();

    fs::write(
        dir.path().join(".vet.toml"),
        r#"
disabled_patterns = ["vcs/github-pat"]
"#,
    )
    .unwrap();

    fs::write(
        dir.path().join("secret.env"),
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
    )
    .unwrap();

    // Should pass because the pattern is disabled
    vet().args(["scan", "."]).current_dir(dir.path()).assert().success();
}

#[test]
fn workflow_inline_ignore() {
    let dir = TempDir::new().unwrap();

    fs::write(
        dir.path().join("config.env"),
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890 # vet:ignore",
    )
    .unwrap();

    vet().args(["scan", "."]).current_dir(dir.path()).assert().success();
}

#[test]
fn workflow_multiple_output_formats() {
    let dir = TempDir::new().unwrap();

    fs::write(
        dir.path().join("secret.env"),
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
    )
    .unwrap();

    // JSON output
    let json_out = dir.path().join("results.json");
    vet()
        .args(["scan", ".", "--format", "json", "--output", json_out.to_str().unwrap()])
        .current_dir(dir.path())
        .assert()
        .code(1);
    assert!(json_out.exists());

    // SARIF output
    let sarif_out = dir.path().join("results.sarif");
    vet()
        .args([
            "scan",
            ".",
            "--format",
            "sarif",
            "--output",
            sarif_out.to_str().unwrap(),
        ])
        .current_dir(dir.path())
        .assert()
        .code(1);
    assert!(sarif_out.exists());

    // Verify both are valid JSON
    let json_content = fs::read_to_string(&json_out).unwrap();
    let sarif_content = fs::read_to_string(&sarif_out).unwrap();
    assert!(serde_json::from_str::<serde_json::Value>(&json_content).is_ok());
    assert!(serde_json::from_str::<serde_json::Value>(&sarif_content).is_ok());
}

#[test]
fn workflow_respects_gitignore() {
    let dir = TempDir::new().unwrap();
    init_git_repo(&dir);

    fs::write(dir.path().join(".gitignore"), "ignored/\n").unwrap();

    let ignored_dir = dir.path().join("ignored");
    fs::create_dir(&ignored_dir).unwrap();
    fs::write(
        ignored_dir.join("secret.env"),
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
    )
    .unwrap();

    // Respects .gitignore by default
    vet().args(["scan", "."]).current_dir(dir.path()).assert().success();

    vet()
        .args(["scan", ".", "--use-gitignore=false"])
        .current_dir(dir.path())
        .assert()
        .code(1);
}

#[test]
fn workflow_scan_specific_file() {
    let dir = TempDir::new().unwrap();

    fs::write(dir.path().join("clean.rs"), "fn main() {}").unwrap();

    fs::write(
        dir.path().join("secret.env"),
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
    )
    .unwrap();

    // Scanning only clean.rs should pass
    vet()
        .args(["scan", "clean.rs"])
        .current_dir(dir.path())
        .assert()
        .success();

    // Scanning secret.env should fail
    vet()
        .args(["scan", "secret.env"])
        .current_dir(dir.path())
        .assert()
        .code(1);
}

#[test]
fn workflow_scan_multiple_paths() {
    let dir = TempDir::new().unwrap();

    let src = dir.path().join("src");
    let tests = dir.path().join("tests");
    fs::create_dir(&src).unwrap();
    fs::create_dir(&tests).unwrap();

    fs::write(src.join("main.rs"), "fn main() {}").unwrap();
    fs::write(tests.join("test.rs"), "fn test() {}").unwrap();

    vet()
        .args(["scan", "src", "tests"])
        .current_dir(dir.path())
        .assert()
        .success();
}
