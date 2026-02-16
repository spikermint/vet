//! Patterns command - lists available detection patterns.

use std::collections::HashMap;

use console::style;
use vet_core::prelude::*;

use crate::ui::{colors, indicators, print_command_header, severity_indicator, severity_style, truncate_with_ellipsis};

const NAME_TRUNCATE_WIDTH: usize = 35;
const DESCRIPTION_WIDTH: usize = 60;

const SEVERITY_ORDER: [Severity; 4] = [Severity::Critical, Severity::High, Severity::Medium, Severity::Low];

/// Lists built-in detection patterns, optionally filtered by group or severity.
pub fn run(group_filter: Option<&str>, severity_filter: Option<&str>, verbose: bool) -> super::Result {
    print_command_header("patterns");

    let registry = PatternRegistry::builtin()?;
    let severity = parse_severity_filter(severity_filter)?;
    let patterns = filter_patterns(registry.patterns(), group_filter, severity);

    if patterns.is_empty() {
        print_no_matches(group_filter, severity_filter);
        return Ok(());
    }

    print_count(patterns.len());

    if verbose {
        print_verbose(&patterns);
    } else {
        print_table(&patterns);
    }

    Ok(())
}

fn parse_severity_filter(s: Option<&str>) -> super::Result<Option<Severity>> {
    s.map(parse_severity).transpose()
}

fn parse_severity(s: &str) -> super::Result<Severity> {
    match s.to_lowercase().as_str() {
        "critical" => Ok(Severity::Critical),
        "high" => Ok(Severity::High),
        "medium" => Ok(Severity::Medium),
        "low" => Ok(Severity::Low),
        _ => anyhow::bail!("invalid severity '{s}' - use: critical, high, medium, low"),
    }
}

fn filter_patterns<'a>(patterns: &'a [Pattern], group: Option<&str>, severity: Option<Severity>) -> Vec<&'a Pattern> {
    patterns
        .iter()
        .filter(|p| matches_group(p, group) && matches_severity(p, severity))
        .collect()
}

fn matches_group(pattern: &Pattern, filter: Option<&str>) -> bool {
    filter.is_none_or(|g| pattern.group.as_str().eq_ignore_ascii_case(g))
}

fn matches_severity(pattern: &Pattern, filter: Option<Severity>) -> bool {
    filter.is_none_or(|s| pattern.severity == s)
}

fn print_count(count: usize) {
    println!("{}", colors::muted().apply_to(format!("{count} patterns")));
}

fn print_no_matches(group: Option<&str>, severity: Option<&str>) {
    let mut filters = Vec::new();
    if let Some(g) = group {
        filters.push(format!("--group {g}"));
    }
    if let Some(s) = severity {
        filters.push(format!("--severity {s}"));
    }

    if filters.is_empty() {
        println!(
            "{} {}",
            colors::muted().apply_to("○"),
            colors::secondary().apply_to("no patterns")
        );
    } else {
        println!(
            "{} {} {}",
            colors::muted().apply_to("○"),
            colors::secondary().apply_to("no patterns match"),
            colors::emphasis().apply_to(filters.join(" "))
        );
    }
}

fn print_table(patterns: &[&Pattern]) {
    let grouped = group_by_severity_and_group(patterns);

    for severity in SEVERITY_ORDER {
        if let Some(groups) = grouped.get(&severity) {
            print_severity_section(severity, groups);
        }
    }
}

fn group_by_severity_and_group<'a>(patterns: &[&'a Pattern]) -> HashMap<Severity, HashMap<&'a str, Vec<&'a Pattern>>> {
    let mut result: HashMap<Severity, HashMap<&str, Vec<&Pattern>>> = HashMap::new();

    for pattern in patterns {
        result
            .entry(pattern.severity)
            .or_default()
            .entry(pattern.group.as_str())
            .or_default()
            .push(pattern);
    }

    result
}

fn print_severity_section(severity: Severity, groups: &HashMap<&str, Vec<&Pattern>>) {
    let sev_style = severity_style(severity);
    let label = severity.to_string();
    let count: usize = groups.values().map(Vec::len).sum();

    println!();
    println!(
        "{} {}",
        sev_style.apply_to(label),
        colors::muted().apply_to(format!("({count})"))
    );

    let mut group_names: Vec<_> = groups.keys().collect();
    group_names.sort();

    for group_name in group_names {
        print_group(group_name, &groups[group_name]);
    }
}

fn print_group(name: &str, patterns: &[&Pattern]) {
    println!();
    println!("{}", style(name).bold());

    for pattern in patterns {
        print_pattern_row(pattern);
    }
}

fn print_pattern_row(pattern: &Pattern) {
    println!(
        "  {}  {}",
        colors::accent().apply_to(&pattern.id),
        colors::secondary().apply_to(truncate_with_ellipsis(&pattern.name, NAME_TRUNCATE_WIDTH))
    );
}

fn print_verbose(patterns: &[&Pattern]) {
    for pattern in patterns {
        print_pattern_detail(pattern);
    }
}

fn print_pattern_detail(pattern: &Pattern) {
    let sev_style = severity_style(pattern.severity);
    let severity_label = pattern.severity.to_string();

    println!();
    println!(
        "{} {} {} {} {} {}",
        severity_indicator(pattern.severity),
        style(&pattern.id).bold(),
        colors::muted().apply_to("·"),
        sev_style.apply_to(&severity_label),
        colors::muted().apply_to("·"),
        colors::muted().apply_to(pattern.group.as_str())
    );

    for line in wrap_text(&pattern.description, DESCRIPTION_WIDTH) {
        println!("  {}", colors::secondary().apply_to(&line));
    }

    let remediation = pattern.remediation();
    let first_line = remediation.lines().next().unwrap_or(remediation);
    let trimmed = first_line.trim_start_matches(|c: char| c.is_ascii_digit() || c == '.' || c == ' ');
    println!(
        "  {} {}",
        colors::info().apply_to(indicators::INFO),
        colors::secondary().apply_to(trimmed)
    );
}

fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.is_empty() {
            current_line = word.to_string();
        } else if current_line.len() + 1 + word.len() <= width {
            current_line.push(' ');
            current_line.push_str(word);
        } else {
            lines.push(current_line);
            current_line = word.to_string();
        }
    }

    if !current_line.is_empty() {
        lines.push(current_line);
    }

    lines
}
