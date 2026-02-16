//! Baseline stats - displays summary statistics for a baseline file.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::Local;
use console::style;
use vet_core::prelude::*;

use crate::BaselineStatsArgs;

const TOP_PATTERNS_DISPLAY_LIMIT: usize = 10;
const PROGRESS_BAR_WIDTH: usize = 20;

/// Loads a baseline file and prints summary statistics (counts by status,
/// severity, and pattern) in text or JSON format.
pub fn run(args: &BaselineStatsArgs) -> Result<()> {
    let baseline_path = args
        .baseline
        .as_deref()
        .unwrap_or_else(|| Path::new(".vet-baseline.json"));

    let baseline = Baseline::load(baseline_path)
        .with_context(|| format!("failed to load baseline from {}", baseline_path.display()))?;

    if args.json {
        print_json_stats(&baseline)?;
    } else {
        print_text_stats(&baseline, baseline_path);
    }

    Ok(())
}

fn print_text_stats(baseline: &Baseline, baseline_path: &Path) {
    let total = baseline.len();
    let (accepted_count, ignored_count) = count_by_status(baseline);

    let created_local = baseline.created_at.with_timezone(&Local);
    let updated_local = baseline.updated_at.with_timezone(&Local);

    println!("{}: {}", style("Baseline").dim(), baseline_path.display());
    println!(
        "{}:  {}",
        style("Created").dim(),
        created_local.format("%Y-%m-%d %H:%M:%S")
    );
    println!(
        "{}:  {}",
        style("Updated").dim(),
        updated_local.format("%Y-%m-%d %H:%M:%S")
    );
    println!();

    println!("{}: {} total", style("Findings").bold(), total);

    if total > 0 {
        println!();

        // By Status with progress bars
        println!("{}:", style("By Status").bold());
        print_status_bar("accepted", accepted_count, total);
        print_status_bar("ignored", ignored_count, total);
        println!();

        // By Severity with progress bars
        let severity_counts = count_by_severity(baseline);
        println!("{}:", style("By Severity").bold());
        for severity in &[Severity::Critical, Severity::High, Severity::Medium, Severity::Low] {
            let count = severity_counts.get(severity).copied().unwrap_or(0);
            if count > 0 {
                let severity_str = severity.to_string();
                print_severity_bar(&severity_str, count, total, *severity);
            }
        }
        println!();
    } else {
        println!();
    }

    // By Pattern
    let pattern_counts = count_by_pattern(baseline);
    if !pattern_counts.is_empty() {
        println!("{}:", style("By Pattern").bold());
        let mut sorted_patterns: Vec<_> = pattern_counts.iter().collect();
        sorted_patterns.sort_by(|a, b| b.1.cmp(a.1));

        // Find longest pattern name for alignment
        let max_width = sorted_patterns
            .iter()
            .take(TOP_PATTERNS_DISPLAY_LIMIT)
            .map(|(pattern, _)| pattern.len())
            .max()
            .unwrap_or(30);

        for (pattern, count) in sorted_patterns.iter().take(TOP_PATTERNS_DISPLAY_LIMIT) {
            println!("  {pattern:<max_width$} {count}");
        }
        println!();
    }

    // Oldest and Newest
    if let Some((oldest, newest)) = find_oldest_and_newest(baseline) {
        let oldest_local = oldest.reviewed_at.with_timezone(&Local);
        let newest_local = newest.reviewed_at.with_timezone(&Local);

        println!(
            "{}: {} ({} in {})",
            style("Oldest").dim(),
            oldest_local.format("%Y-%m-%d"),
            oldest.pattern_id,
            oldest.file
        );
        println!(
            "{}: {} ({} in {})",
            style("Newest").dim(),
            newest_local.format("%Y-%m-%d"),
            newest.pattern_id,
            newest.file
        );
    }
}

fn print_status_bar(label: &str, count: usize, total: usize) {
    let percentage = if total > 0 { (count * 100) / total } else { 0 };
    let bar_length = PROGRESS_BAR_WIDTH;
    let filled = (count * bar_length) / total.max(1);

    let filled_bar = "█".repeat(filled);
    let empty_bar = "▒".repeat(bar_length - filled);

    println!("  {label:<10} {count}  {filled_bar}{empty_bar}  {percentage:>3}%");
}

fn print_severity_bar(label: &str, count: usize, total: usize, severity: Severity) {
    let percentage = if total > 0 { (count * 100) / total } else { 0 };
    let bar_length = PROGRESS_BAR_WIDTH;
    let filled = (count * bar_length) / total.max(1);

    let filled_bar = "█".repeat(filled);
    let empty_bar = "▒".repeat(bar_length - filled);

    let colored_label = match severity {
        Severity::Critical => style(label).red().bold(),
        Severity::High => style(label).red(),
        Severity::Medium => style(label).yellow(),
        Severity::Low => style(label).dim(),
    };

    println!("  {colored_label:<10} {count}  {filled_bar}{empty_bar}  {percentage:>3}%");
}

fn find_oldest_and_newest(baseline: &Baseline) -> Option<(&BaselineFinding, &BaselineFinding)> {
    if baseline.findings.is_empty() {
        return None;
    }

    let mut oldest = &baseline.findings[0];
    let mut newest = &baseline.findings[0];

    for finding in &baseline.findings {
        if finding.reviewed_at < oldest.reviewed_at {
            oldest = finding;
        }
        if finding.reviewed_at > newest.reviewed_at {
            newest = finding;
        }
    }

    Some((oldest, newest))
}

fn print_json_stats(baseline: &Baseline) -> Result<()> {
    let (accepted_count, ignored_count) = count_by_status(baseline);
    let severity_counts = count_by_severity(baseline);
    let pattern_counts = count_by_pattern(baseline);

    let stats = serde_json::json!({
        "total": baseline.len(),
        "accepted": accepted_count,
        "ignored": ignored_count,
        "by_severity": {
            "critical": severity_counts.get(&Severity::Critical).copied().unwrap_or(0),
            "high": severity_counts.get(&Severity::High).copied().unwrap_or(0),
            "medium": severity_counts.get(&Severity::Medium).copied().unwrap_or(0),
            "low": severity_counts.get(&Severity::Low).copied().unwrap_or(0),
        },
        "by_pattern": pattern_counts,
        "created_at": baseline.created_at.to_rfc3339(),
        "updated_at": baseline.updated_at.to_rfc3339(),
        "vet_version": baseline.vet_version,
    });

    println!("{}", serde_json::to_string_pretty(&stats)?);
    Ok(())
}

fn count_by_status(baseline: &Baseline) -> (usize, usize) {
    let mut accepted = 0;
    let mut ignored = 0;

    for finding in &baseline.findings {
        match finding.status {
            BaselineStatus::Accepted => accepted += 1,
            BaselineStatus::Ignored => ignored += 1,
        }
    }

    (accepted, ignored)
}

fn count_by_severity(baseline: &Baseline) -> HashMap<Severity, usize> {
    let mut counts = HashMap::new();

    for finding in &baseline.findings {
        *counts.entry(finding.severity).or_insert(0) += 1;
    }

    counts
}

fn count_by_pattern(baseline: &Baseline) -> HashMap<String, usize> {
    let mut counts = HashMap::new();

    for finding in &baseline.findings {
        *counts.entry(finding.pattern_id.clone()).or_insert(0) += 1;
    }

    counts
}
