use std::fs;

use assert_cmd::Command;
use insta::assert_snapshot;
use tempfile::TempDir;

fn vet() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vet"))
}

#[test]
fn snapshot_json_output_single_finding() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("secret.env"), "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE").unwrap();

    let output = vet()
        .args(["scan", ".", "--format", "json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(json.as_array().unwrap().len(), 1);
    assert!(json[0]["pattern_id"].as_str().unwrap().contains("aws"));
}

#[test]
fn snapshot_json_output_no_findings() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("clean.rs"), "fn main() {}").unwrap();

    let output = vet()
        .args(["scan", ".", "--format", "json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_snapshot!("json_no_findings", stdout.trim());
}

#[test]
fn snapshot_json_structure() {
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
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    let finding = &json[0];
    assert!(finding.get("id").is_some());
    assert!(finding.get("path").is_some());
    assert!(finding.get("line").is_some());
    assert!(finding.get("column").is_some());
    assert!(finding.get("pattern_id").is_some());
    assert!(finding.get("severity").is_some());
    assert!(finding.get("confidence").is_some());
    assert!(finding.get("secret_masked").is_some());
}

#[test]
fn snapshot_sarif_output() {
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
    let sarif: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(sarif["$schema"], "https://json.schemastore.org/sarif-2.1.0.json");
    assert_eq!(sarif["version"], "2.1.0");
    assert!(sarif["runs"].as_array().is_some());
}

#[test]
fn snapshot_sarif_has_tool_info() {
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
fn snapshot_text_output_clean() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("clean.rs"), "fn main() {}").unwrap();

    let output = vet().args(["scan", "."]).current_dir(dir.path()).output().unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("✓") || stdout.contains("0 findings"));
}

#[test]
fn snapshot_text_output_with_finding() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("leak.env"),
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
    )
    .unwrap();

    let output = vet().args(["scan", "."]).current_dir(dir.path()).output().unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("leak.env") || stdout.contains("github") || stdout.contains("1 finding"),
        "Expected finding output, got: {stdout}"
    );
}

#[test]
fn snapshot_patterns_list() {
    let output = vet().args(["patterns"]).output().unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("github") || stdout.contains("aws") || stdout.contains("patterns"));
}

#[test]
fn snapshot_init_config_content() {
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
