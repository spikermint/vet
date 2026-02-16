//! Configuration and hook file templates.

use std::path::Path;

use anyhow::Context as _;

/// Default minimum severity for generated configurations.
pub const DEFAULT_SEVERITY: &str = "low";
/// Default maximum file size in bytes (1 MB).
pub const DEFAULT_MAX_FILE_SIZE: u64 = 1_048_576;
/// Path to the git hooks directory.
pub const GIT_HOOKS_DIR: &str = ".git/hooks";
/// Path to the git pre-commit hook file.
pub const PRECOMMIT_HOOK_PATH: &str = ".git/hooks/pre-commit";
/// Marker comment identifying hooks managed by vet.
pub const VET_HOOK_MARKER: &str = "# vet-managed";

/// Shell script template for the vet-managed pre-commit hook.
pub const HOOK_SCRIPT: &str = r"#!/bin/sh
# vet-managed
set -e
vet scan --staged
";

/// Generates the `.vet.toml` configuration file content.
#[must_use]
pub fn build_config(severity: &str, excludes: &[&str], minimal: bool) -> String {
    if minimal {
        build_minimal_config(severity, excludes)
    } else {
        build_full_config(severity, excludes)
    }
}

fn build_minimal_config(severity: &str, excludes: &[&str]) -> String {
    use std::fmt::Write as _;

    let mut cfg = format!(
        "severity = \"{severity}\"\n\
         max_file_size = {DEFAULT_MAX_FILE_SIZE}\n"
    );

    if !excludes.is_empty() {
        cfg.push_str("exclude_paths = [\n");
        for ex in excludes {
            let _ = writeln!(cfg, "  \"{ex}\",");
        }
        cfg.push_str("]\n");
    }

    cfg
}

fn build_full_config(severity: &str, excludes: &[&str]) -> String {
    let excludes_section = if excludes.is_empty() {
        "# exclude_paths = [\"\"]".into()
    } else {
        let items: Vec<_> = excludes.iter().map(|e| format!("  \"{e}\"")).collect();
        format!("exclude_paths = [\n{},\n]", items.join(",\n"))
    };

    format!(
        r#"# .vet.toml

severity = "{severity}"
max_file_size = {DEFAULT_MAX_FILE_SIZE}

{excludes_section}

# minimum_confidence = "high"
# disabled_patterns = []

# [[patterns]]
# id = "custom-key"
# name = "Custom Key"
# regex = 'CUSTOM_[A-Z0-9]{{32}}'
# severity = "high"
"#
    )
}

/// Writes configuration content to the given file path.
pub fn write_config(path: &Path, content: &str) -> anyhow::Result<()> {
    std::fs::write(path, content).context("creating config file")
}

/// Creates the git pre-commit hook file and makes it executable.
pub fn install_hook() -> anyhow::Result<()> {
    let hooks_dir = Path::new(GIT_HOOKS_DIR);

    if !hooks_dir.exists() {
        std::fs::create_dir_all(hooks_dir)?;
    }

    std::fs::write(PRECOMMIT_HOOK_PATH, HOOK_SCRIPT)?;
    make_executable(Path::new(PRECOMMIT_HOOK_PATH))?;

    Ok(())
}

#[cfg(unix)]
fn make_executable(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)?;

    Ok(())
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}
