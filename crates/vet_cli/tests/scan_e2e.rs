//! End-to-end tests for the `vet scan` command.

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
fn scan_nonexistent_path_succeeds_with_zero_files() {
    vet()
        .args(["scan", "/nonexistent/path/that/does/not/exist"])
        .assert()
        .success();
}

#[test]
fn scan_specific_file() {
    let dir = TempDir::new().unwrap();

    fs::write(dir.path().join("clean.rs"), "fn main() {}").unwrap();
    fs::write(
        dir.path().join("secret.env"),
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
    )
    .unwrap();

    vet()
        .args(["scan", "clean.rs"])
        .current_dir(dir.path())
        .assert()
        .success();

    vet()
        .args(["scan", "secret.env"])
        .current_dir(dir.path())
        .assert()
        .code(1);
}

#[test]
fn scan_multiple_paths() {
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

#[test]
fn config_exclude_paths() {
    let dir = TempDir::new().unwrap();

    fs::write(
        dir.path().join(".vet.toml"),
        r#"
exclude_paths = ["secrets/**"]
"#,
    )
    .unwrap();

    let secrets_dir = dir.path().join("secrets");
    fs::create_dir(&secrets_dir).unwrap();
    fs::write(
        secrets_dir.join("api.env"),
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
    )
    .unwrap();

    vet().args(["scan", "."]).current_dir(dir.path()).assert().success();
}

#[test]
fn config_severity_threshold() {
    let dir = TempDir::new().unwrap();

    fs::write(
        dir.path().join(".vet.toml"),
        r#"
severity = "critical"
"#,
    )
    .unwrap();

    fs::write(
        dir.path().join("config.env"),
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
    )
    .unwrap();

    vet().args(["scan", "."]).current_dir(dir.path()).assert().code(1);
}

#[test]
fn cli_args_override_config() {
    let dir = TempDir::new().unwrap();

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

    vet()
        .args(["scan", ".", "--exclude", "*.env"])
        .current_dir(dir.path())
        .assert()
        .success();
}

#[test]
fn custom_pattern_detection() {
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
fn disabled_pattern() {
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

    vet().args(["scan", "."]).current_dir(dir.path()).assert().success();
}

#[test]
fn inline_ignore_marker() {
    let dir = TempDir::new().unwrap();

    fs::write(
        dir.path().join("config.env"),
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890 # vet:ignore",
    )
    .unwrap();

    vet().args(["scan", "."]).current_dir(dir.path()).assert().success();
}

#[test]
fn respects_gitignore_by_default() {
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

    vet().args(["scan", "."]).current_dir(dir.path()).assert().success();
}

#[test]
fn skip_gitignore_scans_ignored_files() {
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

    vet()
        .args(["scan", ".", "--skip-gitignore"])
        .current_dir(dir.path())
        .assert()
        .code(1);
}

#[test]
fn json_format_is_valid() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("test.env"),
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
    )
    .unwrap();

    let output = vet()
        .args(["scan", ".", "--format", "json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON output");
    assert!(json.is_array());
    assert!(!json.as_array().unwrap().is_empty());
}

#[test]
fn sarif_format_is_valid() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("test.env"),
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
    )
    .unwrap();

    let output = vet()
        .args(["scan", ".", "--format", "sarif"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let sarif: serde_json::Value = serde_json::from_str(&stdout).expect("invalid SARIF output");

    assert_eq!(sarif["$schema"], "https://json.schemastore.org/sarif-2.1.0.json");
    assert_eq!(sarif["version"], "2.1.0");
    assert!(sarif["runs"].as_array().is_some());
}

#[test]
fn sarif_includes_tool_info() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("clean.rs"), "fn main() {}").unwrap();

    let output = vet()
        .args(["scan", ".", "--format", "sarif"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let sarif: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    let tool = &sarif["runs"][0]["tool"]["driver"];
    assert_eq!(tool["name"], "vet");
    assert!(tool.get("rules").is_some());
}

#[test]
fn text_output_clean_shows_success() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("clean.rs"), "fn main() {}").unwrap();

    let output = vet().args(["scan", "."]).current_dir(dir.path()).output().unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("✓") || stdout.contains("No secrets"));
}

#[test]
fn text_output_with_finding_shows_details() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("leak.env"),
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
    )
    .unwrap();

    let output = vet().args(["scan", "."]).current_dir(dir.path()).output().unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("leak.env") || stdout.contains("github") || stdout.contains("secret"),
        "Expected finding output, got: {stdout}"
    );
}

#[test]
fn output_to_file() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("test.env"),
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
    )
    .unwrap();

    let output_file = dir.path().join("results.json");

    vet()
        .args([
            "scan",
            ".",
            "--format",
            "json",
            "--output",
            output_file.to_str().unwrap(),
        ])
        .current_dir(dir.path())
        .assert()
        .code(1);

    assert!(output_file.exists());
    let content = fs::read_to_string(&output_file).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert!(!json.as_array().unwrap().is_empty());
}

#[test]
fn multiple_output_formats_to_file() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("secret.env"),
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
    )
    .unwrap();

    let json_out = dir.path().join("results.json");
    vet()
        .args(["scan", ".", "--format", "json", "--output", json_out.to_str().unwrap()])
        .current_dir(dir.path())
        .assert()
        .code(1);
    assert!(json_out.exists());

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

    let json_content = fs::read_to_string(&json_out).unwrap();
    let sarif_content = fs::read_to_string(&sarif_out).unwrap();
    assert!(serde_json::from_str::<serde_json::Value>(&json_content).is_ok());
    assert!(serde_json::from_str::<serde_json::Value>(&sarif_content).is_ok());
}

#[test]
fn verify_flag_is_accepted() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("clean.rs"), "fn main() {}").unwrap();

    vet()
        .args(["scan", ".", "--verify"])
        .current_dir(dir.path())
        .assert()
        .success();
}

#[test]
fn verify_flag_with_no_findings_succeeds() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("clean.rs"), "fn main() {}").unwrap();

    let output = vet()
        .args(["scan", ".", "--verify", "--format", "json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert!(json.as_array().unwrap().is_empty());
}

#[test]
fn json_output_includes_verification_field_when_verify_flag() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("test.env"),
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
    )
    .unwrap();

    let output = vet()
        .args(["scan", ".", "--format", "json", "--verify"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    let findings = json.as_array().expect("should be array");
    assert!(!findings.is_empty(), "should have findings");

    // All findings should have a verification field (may be null for network errors)
    for finding in findings {
        assert!(
            finding.get("verification").is_some(),
            "finding should have verification field: {finding}"
        );
    }
}

#[test]
fn sarif_output_includes_verification_properties_when_verify_flag() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("test.env"),
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
    )
    .unwrap();

    let output = vet()
        .args(["scan", ".", "--format", "sarif", "--verify"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let sarif: serde_json::Value = serde_json::from_str(&stdout).expect("valid SARIF");

    let results = sarif["runs"][0]["results"].as_array().expect("should have results");
    assert!(!results.is_empty(), "should have results");

    // All results should have properties with verification status
    for result in results {
        let properties = result.get("properties");
        assert!(properties.is_some(), "result should have properties: {result}");
        assert!(
            properties.unwrap().get("verificationStatus").is_some(),
            "properties should have verificationStatus: {result}"
        );
    }
}

#[test]
fn verify_flag_works_with_exit_zero() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("test.env"),
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
    )
    .unwrap();

    vet()
        .args(["scan", ".", "--verify", "--exit-zero"])
        .current_dir(dir.path())
        .assert()
        .success();
}
