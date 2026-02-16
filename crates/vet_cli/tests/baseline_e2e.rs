//! End-to-end tests for the `vet baseline` command.

#![expect(clippy::unwrap_used, reason = "tests use expect/unwrap for clearer failure messages")]

use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn vet() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vet"))
}

fn create_test_secret_file(dir: &TempDir, filename: &str) {
    fs::write(
        dir.path().join(filename),
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
    )
    .unwrap();
}

fn create_baseline_with_secret(dir: &TempDir) {
    create_test_secret_file(dir, "secret.env");

    vet()
        .args([
            "baseline",
            ".",
            "-o",
            ".vet-baseline.json",
            "--accept-all",
            "--reason",
            "Test baseline",
        ])
        .current_dir(dir.path())
        .assert()
        .success();
}

#[test]
fn baseline_creates_file_when_none_exists() {
    let dir = TempDir::new().unwrap();
    create_test_secret_file(&dir, "secret.env");

    vet()
        .args([
            "baseline",
            ".",
            "-o",
            ".vet-baseline.json",
            "--accept-all",
            "--reason",
            "Initial baseline for testing",
        ])
        .current_dir(dir.path())
        .assert()
        .success();

    let baseline_path = dir.path().join(".vet-baseline.json");
    assert!(baseline_path.exists(), "baseline file should be created");

    let content = fs::read_to_string(&baseline_path).unwrap();
    assert!(content.contains("\"version\": \"1\""));
    assert!(content.contains("Initial baseline for testing"));
}

#[test]
fn baseline_creates_empty_file_when_no_secrets() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("clean.rs"), "fn main() {}").unwrap();

    vet()
        .args(["baseline", ".", "-o", ".vet-baseline.json"])
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("no new findings"));

    let baseline_path = dir.path().join(".vet-baseline.json");
    assert!(baseline_path.exists());

    let content = fs::read_to_string(&baseline_path).unwrap();
    let baseline: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(baseline["findings"].as_array().unwrap().len(), 0);
}

#[test]
fn baseline_updates_existing_file() {
    let dir = TempDir::new().unwrap();
    create_baseline_with_secret(&dir);

    let baseline_path = dir.path().join(".vet-baseline.json");
    let content_before = fs::read_to_string(&baseline_path).unwrap();
    let baseline_before: serde_json::Value = serde_json::from_str(&content_before).unwrap();
    let findings_before = baseline_before["findings"].as_array().unwrap().len();

    create_test_secret_file(&dir, "secret2.env");

    vet()
        .args([
            "baseline",
            ".",
            "-o",
            ".vet-baseline.json",
            "--accept-all",
            "--reason",
            "Added new secret",
        ])
        .current_dir(dir.path())
        .assert()
        .success();

    let content_after = fs::read_to_string(&baseline_path).unwrap();
    let baseline_after: serde_json::Value = serde_json::from_str(&content_after).unwrap();
    let findings_after = baseline_after["findings"].as_array().unwrap().len();

    assert_eq!(findings_after, findings_before + 1, "should have one more finding");
}

#[test]
fn baseline_with_custom_output_path() {
    let dir = TempDir::new().unwrap();
    create_test_secret_file(&dir, "secret.env");

    vet()
        .args([
            "baseline",
            ".",
            "-o",
            "custom-baseline.json",
            "--accept-all",
            "--reason",
            "Custom path test",
        ])
        .current_dir(dir.path())
        .assert()
        .success();

    let custom_path = dir.path().join("custom-baseline.json");
    assert!(custom_path.exists());
}

#[test]
fn baseline_with_severity_filter() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("secrets.env"),
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890\nAPI_KEY=test123",
    )
    .unwrap();

    vet()
        .args([
            "baseline",
            ".",
            "-o",
            ".vet-baseline.json",
            "--severity",
            "high",
            "--accept-all",
            "--reason",
            "Only high severity",
        ])
        .current_dir(dir.path())
        .assert()
        .success();

    let baseline_path = dir.path().join(".vet-baseline.json");
    let content = fs::read_to_string(&baseline_path).unwrap();
    let baseline: serde_json::Value = serde_json::from_str(&content).unwrap();

    let findings = baseline["findings"].as_array().unwrap();
    for finding in findings {
        let severity = finding["severity"].as_str().unwrap();
        assert!(
            severity == "high" || severity == "critical",
            "all findings should be high or critical severity"
        );
    }
}

#[test]
fn baseline_with_exclude_pattern() {
    let dir = TempDir::new().unwrap();
    create_test_secret_file(&dir, "secret.env");
    create_test_secret_file(&dir, "excluded.env");

    vet()
        .args([
            "baseline",
            ".",
            "-o",
            ".vet-baseline.json",
            "--exclude",
            "excluded.*",
            "--accept-all",
            "--reason",
            "Exclude test",
        ])
        .current_dir(dir.path())
        .assert()
        .success();

    let baseline_path = dir.path().join(".vet-baseline.json");
    let content = fs::read_to_string(&baseline_path).unwrap();
    let baseline: serde_json::Value = serde_json::from_str(&content).unwrap();

    let findings = baseline["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "should only have one finding");
    assert!(!findings[0]["file"].as_str().unwrap().contains("excluded"));
}

#[test]
fn baseline_stats_displays_summary() {
    let dir = TempDir::new().unwrap();
    create_baseline_with_secret(&dir);

    vet()
        .args(["baseline", "stats", "-b", ".vet-baseline.json"])
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Baseline:"))
        .stdout(predicate::str::contains("Created:"))
        .stdout(predicate::str::contains("Findings:"))
        .stdout(predicate::str::contains("By Status:"))
        .stdout(predicate::str::contains("accepted"));
}

#[test]
fn baseline_stats_json_format() {
    let dir = TempDir::new().unwrap();
    create_baseline_with_secret(&dir);

    let output = vet()
        .args(["baseline", "stats", "-b", ".vet-baseline.json", "--json"])
        .current_dir(dir.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json_str = String::from_utf8(output).unwrap();
    let stats: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    assert!(stats.get("total").is_some());
    assert!(stats.get("accepted").is_some());
    assert!(stats.get("ignored").is_some());
    assert!(stats.get("by_severity").is_some());
    assert!(stats.get("by_pattern").is_some());
}

#[test]
fn baseline_stats_missing_file_errors() {
    let dir = TempDir::new().unwrap();

    vet()
        .args(["baseline", "stats", "-b", "nonexistent.json"])
        .current_dir(dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to load baseline"));
}

#[test]
fn scan_filters_baseline_findings() {
    let dir = TempDir::new().unwrap();
    create_baseline_with_secret(&dir);

    vet()
        .args(["scan", ".", "--baseline", ".vet-baseline.json"])
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("in baseline").or(predicate::str::contains("0 new")));
}

#[test]
fn scan_detects_new_secrets_with_baseline() {
    let dir = TempDir::new().unwrap();
    create_baseline_with_secret(&dir);

    create_test_secret_file(&dir, "new-secret.env");

    vet()
        .args(["scan", ".", "--baseline", ".vet-baseline.json"])
        .current_dir(dir.path())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("new-secret.env"));
}

#[test]
fn scan_with_baseline_and_allow_new_flag() {
    let dir = TempDir::new().unwrap();
    create_baseline_with_secret(&dir);

    create_test_secret_file(&dir, "new-secret.env");

    vet()
        .args(["scan", ".", "--baseline", ".vet-baseline.json", "--allow-new"])
        .current_dir(dir.path())
        .assert()
        .success();
}

#[test]
fn scan_errors_when_baseline_file_missing() {
    let dir = TempDir::new().unwrap();
    create_test_secret_file(&dir, "secret.env");

    vet()
        .args(["scan", ".", "--baseline", "nonexistent.json"])
        .current_dir(dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("baseline file not found"));
}

#[test]
fn scan_uses_config_baseline_path() {
    let dir = TempDir::new().unwrap();
    create_test_secret_file(&dir, "secret.env");

    fs::write(dir.path().join(".vet.toml"), r#"baseline_path = ".vet-baseline.json""#).unwrap();

    vet()
        .args(["baseline", ".", "--accept-all", "--reason", "Config test"])
        .current_dir(dir.path())
        .assert()
        .success();

    vet().args(["scan", "."]).current_dir(dir.path()).assert().success();
}

#[test]
fn scan_with_config_ignores() {
    let dir = TempDir::new().unwrap();
    create_test_secret_file(&dir, "secret.env");

    // First, create a baseline to get the fingerprint
    vet()
        .args([
            "baseline",
            ".",
            "-o",
            ".vet-baseline.json",
            "--accept-all",
            "--reason",
            "Get fingerprint",
        ])
        .current_dir(dir.path())
        .assert()
        .success();

    let baseline_content = fs::read_to_string(dir.path().join(".vet-baseline.json")).unwrap();
    let baseline: serde_json::Value = serde_json::from_str(&baseline_content).unwrap();
    let fingerprint = baseline["findings"][0]["fingerprint"].as_str().unwrap();

    // Remove baseline file
    fs::remove_file(dir.path().join(".vet-baseline.json")).unwrap();

    // Create config with ignore
    fs::write(
        dir.path().join(".vet.toml"),
        format!(
            r#"
[[ignore]]
fingerprint = "{fingerprint}"
pattern_id = "vcs/github-pat"
file = "secret.env"
reason = "Test fixture"
"#
        ),
    )
    .unwrap();

    // Scan should now succeed because the finding is in config ignores
    vet().args(["scan", "."]).current_dir(dir.path()).assert().success();
}

#[test]
fn baseline_fingerprint_is_stable() {
    let dir = TempDir::new().unwrap();
    create_test_secret_file(&dir, "secret.env");

    vet()
        .args([
            "baseline",
            ".",
            "-o",
            "baseline1.json",
            "--accept-all",
            "--reason",
            "First",
        ])
        .current_dir(dir.path())
        .assert()
        .success();

    let _ = fs::remove_file(dir.path().join(".vet-baseline.json"));

    vet()
        .args([
            "baseline",
            ".",
            "-o",
            "baseline2.json",
            "--accept-all",
            "--reason",
            "Second",
        ])
        .current_dir(dir.path())
        .assert()
        .success();

    let content1 = fs::read_to_string(dir.path().join("baseline1.json")).unwrap();
    let content2 = fs::read_to_string(dir.path().join("baseline2.json")).unwrap();

    let baseline1: serde_json::Value = serde_json::from_str(&content1).unwrap();
    let baseline2: serde_json::Value = serde_json::from_str(&content2).unwrap();

    let fingerprint1 = baseline1["findings"][0]["fingerprint"].as_str().unwrap();
    let fingerprint2 = baseline2["findings"][0]["fingerprint"].as_str().unwrap();

    assert_eq!(
        fingerprint1, fingerprint2,
        "fingerprints should be identical for same secret in same file"
    );
}

#[test]
fn baseline_different_files_different_fingerprints() {
    let dir = TempDir::new().unwrap();
    create_test_secret_file(&dir, "secret1.env");
    create_test_secret_file(&dir, "secret2.env");

    vet()
        .args([
            "baseline",
            ".",
            "-o",
            ".vet-baseline.json",
            "--accept-all",
            "--reason",
            "Multi-file test",
        ])
        .current_dir(dir.path())
        .assert()
        .success();

    let content = fs::read_to_string(dir.path().join(".vet-baseline.json")).unwrap();
    let baseline: serde_json::Value = serde_json::from_str(&content).unwrap();

    let findings = baseline["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 2);

    let fp1 = findings[0]["fingerprint"].as_str().unwrap();
    let fp2 = findings[1]["fingerprint"].as_str().unwrap();

    assert_ne!(
        fp1, fp2,
        "same secret in different files should have different fingerprints"
    );
}

#[test]
fn baseline_validates_json_structure() {
    let dir = TempDir::new().unwrap();

    fs::write(dir.path().join(".vet-baseline.json"), "invalid json content").unwrap();

    vet()
        .args(["baseline", "stats", "-b", ".vet-baseline.json"])
        .current_dir(dir.path())
        .assert()
        .failure();
}

#[test]
fn baseline_rejects_wrong_version() {
    let dir = TempDir::new().unwrap();

    fs::write(
        dir.path().join(".vet-baseline.json"),
        r#"{
            "version": "0.5",
            "created_at": 0,
            "updated_at": 0,
            "vet_version": "0.1.0",
            "findings": []
        }"#,
    )
    .unwrap();

    vet()
        .args(["baseline", "stats", "-b", ".vet-baseline.json"])
        .current_dir(dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("unsupported baseline version"));
}

#[test]
fn baseline_handles_empty_directory() {
    let dir = TempDir::new().unwrap();

    vet()
        .args([
            "baseline",
            ".",
            "-o",
            ".vet-baseline.json",
            "--accept-all",
            "--reason",
            "Empty dir test",
        ])
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("no new findings"));
}

#[test]
fn baseline_with_minimum_confidence_flag() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("maybe-secret.txt"), "password=test123").unwrap();

    vet()
        .args([
            "baseline",
            ".",
            "-o",
            "baseline-low.json",
            "--minimum-confidence",
            "low",
            "--accept-all",
            "--reason",
            "Include low confidence",
        ])
        .current_dir(dir.path())
        .assert()
        .success();

    vet()
        .args([
            "baseline",
            ".",
            "-o",
            "baseline-high.json",
            "--accept-all",
            "--reason",
            "Only high confidence",
        ])
        .current_dir(dir.path())
        .assert()
        .success();

    let low_content = fs::read_to_string(dir.path().join("baseline-low.json")).unwrap();
    let high_content = fs::read_to_string(dir.path().join("baseline-high.json")).unwrap();

    let low_baseline: serde_json::Value = serde_json::from_str(&low_content).unwrap();
    let high_baseline: serde_json::Value = serde_json::from_str(&high_content).unwrap();

    let low_count = low_baseline["findings"].as_array().unwrap().len();
    let high_count = high_baseline["findings"].as_array().unwrap().len();

    assert!(
        low_count >= high_count,
        "low confidence mode should include at least as many findings"
    );
}
