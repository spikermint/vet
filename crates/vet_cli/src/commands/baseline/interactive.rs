//! Interactive baseline review - walks the user through each finding.

use std::path::{Path, PathBuf};

use anyhow::Result;
use console::style;
use dialoguer::{Input, Select, theme::ColorfulTheme};
use vet_core::prelude::*;

use crate::files::{collect_files, read_text_file};
use crate::scanning::{build_scanner, load_patterns};
use crate::ui::{colors, indicators};
use crate::{BaselineArgs, CONFIG_FILENAME};

/// Scans the project, filters out already-baselined findings, and walks the
/// user through an interactive accept/ignore/skip review for each new finding.
pub fn run(args: &BaselineArgs) -> Result<()> {
    let config_path = args.config.as_deref().unwrap_or_else(|| Path::new(CONFIG_FILENAME));
    let config = Config::load(config_path)?;

    let new_findings = scan_and_filter_findings(args, &config)?;
    let mut baseline = load_or_create_baseline(&args.output)?;

    if new_findings.is_empty() {
        println!(
            "{} no new findings to add",
            colors::success().apply_to(indicators::SUCCESS)
        );

        // Save baseline even if empty, so stats command works
        if !args.output.exists() {
            baseline.save(&args.output)?;
            println!(
                "{} baseline saved to {}",
                colors::info().apply_to(indicators::INFO),
                args.output.display()
            );
        }

        return Ok(());
    }
    let (added_count, skipped_count) = review_findings_interactively(&new_findings, &mut baseline, args)?;

    if added_count > 0 {
        save_baseline_with_summary(&mut baseline, &args.output, added_count)?;
    }

    if skipped_count > 0 {
        println!("{} {} {}", style("○").dim(), skipped_count, style("skipped").dim());
    }

    Ok(())
}

fn scan_and_filter_findings(args: &BaselineArgs, config: &Config) -> Result<Vec<Finding>> {
    let registry = load_patterns(config)?;
    let severity = args.severity.or(config.severity);
    let scanner = build_scanner(registry, severity);

    let excludes: Vec<String> = config
        .exclude_paths
        .iter()
        .chain(args.exclude.iter())
        .cloned()
        .collect();
    let files = collect_files(&args.paths, &excludes, true);

    if files.is_empty() {
        println!("{} no files to scan", colors::warning().apply_to(indicators::WARNING));
        return Ok(Vec::new());
    }

    println!("{} scanning for secrets...", colors::info().apply_to(indicators::INFO));
    let all_findings = scan_files(&scanner, &files, config.max_file_size);

    if all_findings.is_empty() {
        println!("{} no secrets found", colors::success().apply_to(indicators::SUCCESS));
        return Ok(Vec::new());
    }

    let baseline = if args.output.exists() {
        Baseline::load(&args.output)?
    } else {
        Baseline::new()
    };

    let baseline_matcher = IgnoreMatcher::new(Some(&baseline), &config.ignores);
    let minimum_confidence = args.minimum_confidence.unwrap_or(config.minimum_confidence);

    let new_findings: Vec<_> = all_findings
        .into_iter()
        .filter(|f: &Finding| !baseline_matcher.is_ignored(&f.baseline_fingerprint()))
        .filter(|f| f.confidence >= minimum_confidence)
        .collect();

    Ok(new_findings)
}

fn load_or_create_baseline(output_path: &Path) -> Result<Baseline> {
    if output_path.exists() {
        println!(
            "{} loading existing baseline from {}",
            colors::info().apply_to(indicators::INFO),
            output_path.display()
        );
        Ok(Baseline::load(output_path)?)
    } else {
        println!("{} creating new baseline", colors::info().apply_to(indicators::INFO));
        Ok(Baseline::new())
    }
}

fn review_findings_interactively(
    new_findings: &[Finding],
    baseline: &mut Baseline,
    args: &BaselineArgs,
) -> Result<(usize, usize)> {
    let action_verb = if args.accept_all { "found" } else { "to review" };
    println!(
        "\n{} {} new {} {}\n",
        colors::accent().apply_to("●"),
        new_findings.len(),
        if new_findings.len() == 1 { "finding" } else { "findings" },
        action_verb
    );

    let mut added_count = 0;
    let mut skipped_count = 0;

    for (idx, finding) in new_findings.iter().enumerate() {
        display_finding_details(idx, new_findings.len(), finding);

        let action = if args.accept_all {
            Action::Accept
        } else {
            prompt_for_action()?
        };

        match action {
            Action::Accept => {
                let reason = get_reason_for_action(args, "Why are you accepting this finding?")?;
                add_finding_to_baseline(baseline, finding, BaselineStatus::Accepted, reason);
                added_count += 1;
                println!("{}\n", colors::success().apply_to("✓ Added to baseline"));
            }
            Action::Ignore => {
                let reason = prompt_for_reason("Why are you ignoring this finding?")?;
                add_finding_to_baseline(baseline, finding, BaselineStatus::Ignored, reason);
                added_count += 1;
                println!("{}\n", colors::success().apply_to("✓ Ignored in baseline"));
            }
            Action::Skip => {
                skipped_count += 1;
                println!("{}\n", style("○ Skipped").dim());
            }
            Action::Quit => {
                println!();
                break;
            }
        }
    }

    Ok((added_count, skipped_count))
}

fn display_finding_details(idx: usize, total: usize, finding: &Finding) {
    println!(
        "{} {}/{} {}",
        style("►").bold(),
        idx + 1,
        total,
        style(&finding.pattern_id).cyan()
    );
    println!(
        "  {} {}:{}:{}",
        style("Location:").dim(),
        finding.path.display(),
        finding.line(),
        finding.column()
    );
    println!("  {} {}", style("Severity:").dim(), format_severity(finding.severity));
    println!();
    println!("  {}", finding.masked_line.trim());
    println!();
}

fn get_reason_for_action(args: &BaselineArgs, prompt: &str) -> Result<String> {
    if let Some(ref default_reason) = args.reason {
        Ok(default_reason.clone())
    } else {
        prompt_for_reason(prompt)
    }
}

fn add_finding_to_baseline(baseline: &mut Baseline, finding: &Finding, status: BaselineStatus, reason: String) {
    let baseline_finding = BaselineFinding::new(
        finding.baseline_fingerprint(),
        finding.pattern_id.to_string(),
        finding.severity,
        finding.path.to_string_lossy().to_string(),
        finding.secret.hash_hex().to_string(),
        status,
        reason,
    );

    baseline.add_finding(baseline_finding);
}

fn save_baseline_with_summary(baseline: &mut Baseline, output_path: &Path, added_count: usize) -> Result<()> {
    println!(
        "{} saving baseline to {}",
        colors::info().apply_to(indicators::INFO),
        output_path.display()
    );
    baseline.save(output_path)?;
    println!(
        "\n{} Added {} {} to baseline",
        colors::success().apply_to("✓"),
        added_count,
        if added_count == 1 { "finding" } else { "findings" }
    );
    Ok(())
}

fn scan_files(scanner: &Scanner, files: &[PathBuf], max_file_size: Option<u64>) -> Vec<Finding> {
    let mut all_findings = Vec::new();

    for path in files {
        let Some(content) = read_text_file(path, max_file_size) else {
            continue;
        };

        let findings = scanner.scan_content(&content, path);
        all_findings.extend(findings);
    }

    all_findings
}

enum Action {
    Accept,
    Ignore,
    Skip,
    Quit,
}

fn prompt_for_action() -> Result<Action> {
    let theme = ColorfulTheme::default();
    let options = vec!["Accept", "Ignore", "Skip", "Quit"];

    let selection = Select::with_theme(&theme)
        .with_prompt("What would you like to do?")
        .items(&options)
        .default(0)
        .interact()?;

    Ok(match selection {
        0 => Action::Accept,
        1 => Action::Ignore,
        3 => Action::Quit,
        _ => Action::Skip,
    })
}

fn prompt_for_reason(prompt: &str) -> Result<String> {
    let theme = ColorfulTheme::default();

    let reason: String = Input::with_theme(&theme)
        .with_prompt(prompt)
        .allow_empty(false)
        .interact_text()?;

    Ok(reason)
}

fn format_severity(severity: Severity) -> String {
    match severity {
        Severity::Critical => style(severity.to_string()).red().bold().to_string(),
        Severity::High => style(severity.to_string()).red().to_string(),
        Severity::Medium => style(severity.to_string()).yellow().to_string(),
        Severity::Low => style(severity.to_string()).dim().to_string(),
    }
}
