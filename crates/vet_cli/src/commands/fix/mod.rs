//! Fix command - interactively fix detected secrets.

mod actions;
mod prompts;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use vet_core::fs_util::atomic_write;
use vet_core::prelude::*;

use self::actions::{FixAction, apply_action};
use crate::CONFIG_FILENAME;
use crate::files::{collect_files, read_text_file};
use crate::scanning::{build_scanner, load_patterns};
use crate::ui::{colors, indicators, pluralise_word, print_command_header};

#[derive(Default)]
struct FixStats {
    redacted: usize,
    placeholders: usize,
    deleted: usize,
    ignored: usize,
    skipped: usize,
    files_modified: usize,
}

/// Executes the `vet fix` command.
pub fn run(
    paths: &[PathBuf],
    config_path: Option<&Path>,
    severity: Option<Severity>,
    exclude: &[String],
    skip_gitignore: bool,
    dry_run: bool,
    max_file_size: Option<u64>,
) -> anyhow::Result<()> {
    print_command_header("fix");

    let config_path = config_path.unwrap_or(Path::new(CONFIG_FILENAME));
    let config = Config::load(config_path).context("loading config")?;

    let registry = load_patterns(&config)?;
    let severity = severity.or(config.severity);
    let scanner = build_scanner(registry, severity);
    let max_file_size = max_file_size.or(config.max_file_size);

    let excludes: Vec<String> = config.exclude_paths.iter().chain(exclude.iter()).cloned().collect();

    let files = collect_files(paths, &excludes, !skip_gitignore);

    if files.is_empty() {
        println!("{} no files to scan", colors::warning().apply_to(indicators::WARNING));
        return Ok(());
    }

    let findings_by_file = scan_files(&scanner, &files, max_file_size);

    let total_findings: usize = findings_by_file.values().map(Vec::len).sum();
    if total_findings == 0 {
        println!("{} no secrets found", colors::success().apply_to(indicators::SUCCESS));
        return Ok(());
    }

    println!(
        "{} {} {} in {} {}",
        colors::info().apply_to(indicators::INFO),
        total_findings,
        pluralise_word(total_findings, "secret", "secrets"),
        findings_by_file.len(),
        pluralise_word(findings_by_file.len(), "file", "files"),
    );

    if dry_run {
        println!(
            "  {}",
            colors::muted().apply_to("(dry run - no files will be modified)")
        );
    }

    let stats = process_files(findings_by_file, total_findings, dry_run)?;

    print_summary(&stats, dry_run);

    Ok(())
}

fn scan_files(scanner: &Scanner, files: &[PathBuf], max_file_size: Option<u64>) -> HashMap<PathBuf, Vec<Finding>> {
    let mut findings_by_file: HashMap<PathBuf, Vec<Finding>> = HashMap::new();

    for path in files {
        let Some(content) = read_text_file(path, max_file_size) else {
            continue;
        };

        let findings = scanner.scan_content(&content, path);
        if !findings.is_empty() {
            findings_by_file.insert(path.clone(), findings);
        }
    }

    findings_by_file
}

fn process_files(
    findings_by_file: HashMap<PathBuf, Vec<Finding>>,
    total_findings: usize,
    dry_run: bool,
) -> anyhow::Result<FixStats> {
    let mut stats = FixStats::default();
    let mut finding_index = 0;

    let mut sorted_files: Vec<_> = findings_by_file.into_iter().collect();
    sorted_files.sort_by(|(a, _), (b, _)| a.cmp(b));

    for (path, findings) in sorted_files {
        let modified = process_single_file(&path, findings, &mut stats, &mut finding_index, total_findings, dry_run)?;

        if modified && !dry_run {
            stats.files_modified += 1;
        }
    }

    Ok(stats)
}

fn process_single_file(
    path: &Path,
    findings: Vec<Finding>,
    stats: &mut FixStats,
    finding_index: &mut usize,
    total_findings: usize,
    dry_run: bool,
) -> anyhow::Result<bool> {
    let Some(mut content) = read_text_file(path, None) else {
        return Ok(false);
    };

    let mut offset: isize = 0;
    let mut file_modified = false;

    let mut sorted_findings = findings;
    sorted_findings.sort_by_key(|f| f.span.byte_start);

    for finding in &sorted_findings {
        *finding_index += 1;

        let action = prompts::prompt_for_action(
            path,
            finding,
            &sorted_findings,
            *finding_index,
            total_findings,
            &content,
            offset,
        )?;

        let Some(action) = action else {
            stats.skipped += 1;
            continue;
        };

        let result = apply_action(&mut content, finding, &action, offset);

        if result.success {
            offset += result.bytes_changed;
            file_modified = true;

            match action {
                FixAction::Redact => stats.redacted += 1,
                FixAction::Placeholder(_) => stats.placeholders += 1,
                FixAction::DeleteLine => stats.deleted += 1,
                FixAction::Ignore => stats.ignored += 1,
            }
        }
    }

    if file_modified && !dry_run {
        atomic_write(path, &content).with_context(|| format!("failed to write {}", path.display()))?;
    }

    Ok(file_modified)
}

fn print_summary(stats: &FixStats, dry_run: bool) {
    println!();
    println!("{}", colors::muted().apply_to("─".repeat(60)));

    let mut parts = Vec::new();

    if stats.redacted > 0 {
        parts.push(format!("{} redacted", stats.redacted));
    }
    if stats.placeholders > 0 {
        parts.push(format!(
            "{} {}",
            stats.placeholders,
            pluralise_word(stats.placeholders, "placeholder", "placeholders")
        ));
    }
    if stats.deleted > 0 {
        parts.push(format!("{} deleted", stats.deleted));
    }
    if stats.ignored > 0 {
        parts.push(format!("{} ignored", stats.ignored));
    }
    if stats.skipped > 0 {
        parts.push(format!("{} skipped", stats.skipped));
    }

    let actions_taken = stats.redacted + stats.placeholders + stats.deleted + stats.ignored;

    if actions_taken == 0 {
        println!("{} no changes made", colors::muted().apply_to("○"));
    } else if dry_run {
        println!(
            "{} {} (dry run)",
            colors::info().apply_to(indicators::INFO),
            parts.join(", ")
        );
    } else {
        println!(
            "{} {} · {} {} modified",
            colors::success().apply_to(indicators::SUCCESS),
            parts.join(", "),
            stats.files_modified,
            pluralise_word(stats.files_modified, "file", "files")
        );
    }

    println!();
}
