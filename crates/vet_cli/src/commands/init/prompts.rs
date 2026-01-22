//! Interactive prompts for init command.

use std::path::Path;

use anyhow::Context as _;
use console::style;
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, Select};

use super::detection::{collect_excludes, detect_projects};
use super::templates::{PRECOMMIT_HOOK_PATH, VET_HOOK_MARKER};
use crate::git;
use crate::ui::colors;

const SEVERITY_OPTIONS: &[&str] = &["low", "medium", "high", "critical"];

pub struct PromptResults {
    pub severity: &'static str,
    pub excludes: Vec<&'static str>,
    pub install_hook: bool,
}

pub fn collect_interactive() -> anyhow::Result<PromptResults> {
    let excludes = prompt_project_excludes()?;
    let severity = prompt_severity()?;
    let install_hook = prompt_hook_install()?;

    Ok(PromptResults {
        severity,
        excludes,
        install_hook,
    })
}

pub fn confirm_overwrite() -> bool {
    Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Overwrite?")
        .default(false)
        .interact()
        .unwrap_or(false)
}

fn prompt_project_excludes() -> anyhow::Result<Vec<&'static str>> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let detected = detect_projects(&cwd);

    if detected.is_empty() {
        return Ok(Vec::new());
    }

    let excludes = collect_excludes(&detected);
    print_detected_projects(&detected, &excludes);

    println!();

    let include = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Add suggested excludes?")
        .default(true)
        .interact()
        .unwrap_or(true);

    if include { Ok(excludes) } else { Ok(Vec::new()) }
}

fn print_detected_projects(projects: &[&super::detection::ProjectType], excludes: &[&str]) {
    let names: Vec<_> = projects.iter().map(|p| p.name).collect();

    println!(
        "{} {} {}",
        colors::warning().apply_to("●"),
        colors::muted().apply_to("detected"),
        style(names.join(", ")).bold()
    );

    println!(
        "{} {} {}",
        colors::warning().apply_to("●"),
        colors::muted().apply_to("excludes"),
        format_excludes_preview(excludes)
    );
}

fn format_excludes_preview(excludes: &[&str]) -> String {
    const MAX_DISPLAY: usize = 3;

    if excludes.len() <= MAX_DISPLAY {
        excludes.join(" ")
    } else {
        let shown: Vec<_> = excludes.iter().take(MAX_DISPLAY).copied().collect();
        let remaining = excludes.len() - MAX_DISPLAY;

        format!(
            "{} {}",
            shown.join(" "),
            colors::muted().apply_to(format!("+{remaining}"))
        )
    }
}

fn prompt_severity() -> anyhow::Result<&'static str> {
    let selected = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Minimum severity?")
        .items(SEVERITY_OPTIONS)
        .default(0)
        .interact()
        .context("severity selection")?;

    Ok(SEVERITY_OPTIONS[selected])
}

fn prompt_hook_install() -> anyhow::Result<bool> {
    if !git::in_repo() {
        return Ok(false);
    }

    let hook_path = Path::new(PRECOMMIT_HOOK_PATH);

    if hook_path.exists() {
        let content = std::fs::read_to_string(hook_path).unwrap_or_default();

        if content.contains(VET_HOOK_MARKER) {
            println!(
                "{} {}",
                colors::success().apply_to("✓"),
                colors::muted().apply_to("pre-commit already installed")
            );
            return Ok(false);
        }

        if !content.is_empty() {
            println!(
                "{} {}",
                colors::muted().apply_to("○"),
                colors::muted().apply_to("pre-commit skipped (external hook exists)")
            );
            return Ok(false);
        }
    }

    let install = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Install pre-commit hook?")
        .default(true)
        .interact()
        .unwrap_or(false);

    Ok(install)
}
