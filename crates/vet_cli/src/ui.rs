//! UI helpers for consistent output formatting.

use std::time::Duration;

use console::Style;
use indicatif::{ProgressBar, ProgressStyle};
use vet_core::prelude::*;

pub mod indicators {
    pub const ERROR: &str = "✖";

    pub const WARNING: &str = "⚠";

    pub const INFO: &str = "ℹ";

    pub const SUCCESS: &str = "✓";

    pub const ADDED: &str = "+";
}

pub mod colors {
    use console::Style;

    pub const fn error() -> Style {
        Style::new().red()
    }

    pub const fn warning() -> Style {
        Style::new().yellow()
    }

    pub const fn info() -> Style {
        Style::new().cyan()
    }

    pub const fn success() -> Style {
        Style::new().green()
    }

    pub const fn primary() -> Style {
        Style::new().white().bold()
    }

    pub const fn secondary() -> Style {
        Style::new().color256(252)
    }

    pub const fn muted() -> Style {
        Style::new().color256(243)
    }

    pub const fn accent() -> Style {
        Style::new().cyan()
    }

    pub const fn emphasis() -> Style {
        Style::new().white()
    }

    pub const fn line_number() -> Style {
        Style::new().color256(243)
    }

    pub const fn code() -> Style {
        Style::new().color256(252)
    }
}

pub mod exit {
    pub const FINDINGS: i32 = 1;
    pub const ERROR: i32 = 2;
}

const SEVERITY_CRITICAL_COLOR: u8 = 196;
const SEVERITY_HIGH_COLOR: u8 = 208;
const SEVERITY_MEDIUM_COLOR: u8 = 220;
const SEVERITY_LOW_COLOR: u8 = 75;

pub const fn severity_style(severity: Severity) -> Style {
    match severity {
        Severity::Critical => Style::new().color256(SEVERITY_CRITICAL_COLOR).bold(),
        Severity::High => Style::new().color256(SEVERITY_HIGH_COLOR),
        Severity::Medium => Style::new().color256(SEVERITY_MEDIUM_COLOR),
        Severity::Low => Style::new().color256(SEVERITY_LOW_COLOR),
    }
}

#[must_use]
pub fn severity_indicator(severity: Severity) -> String {
    severity_style(severity).apply_to(indicators::ERROR).to_string()
}

pub fn print_command_header(command: &str) {
    println!();
    println!(
        "{} {}",
        colors::accent().bold().apply_to("vet"),
        colors::muted().apply_to(command)
    );
    println!();
}

pub fn print_hint(command: &str, description: &str) {
    const CMD_WIDTH: usize = 28;

    println!(
        "  {}  {}",
        colors::accent().apply_to(format!("{command:<CMD_WIDTH$}")),
        colors::muted().apply_to(description)
    );
}

pub fn print_error(message: &str) {
    eprintln!(
        "{} {}",
        colors::error().apply_to(indicators::ERROR),
        colors::secondary().apply_to(message)
    );
}

pub fn print_warning(message: &str) {
    eprintln!(
        "{} {}",
        colors::warning().apply_to(indicators::WARNING),
        colors::secondary().apply_to(message)
    );
}

pub fn print_info(message: &str) {
    println!(
        "{} {}",
        colors::info().apply_to(indicators::INFO),
        colors::secondary().apply_to(message)
    );
}

#[must_use]
pub const fn pluralise_word<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

#[must_use]
pub fn truncate_with_ellipsis(s: &str, max_chars: usize) -> String {
    let char_count = s.chars().count();
    if char_count <= max_chars {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max_chars - 1).collect();
        format!("{truncated}…")
    }
}

const PROGRESS_TICK_MS: u64 = 100;

#[must_use]
pub fn create_file_progress(total: usize) -> ProgressBar {
    let pb = ProgressBar::new(total as u64);

    #[allow(clippy::expect_used)] // Static template string; failure is a programmer error
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{bar:40.cyan/243} {percent:>3}% {pos}/{len} files ({elapsed} elapsed)")
            .expect("invalid progress template")
            .progress_chars("━━╸"),
    );

    pb.enable_steady_tick(Duration::from_millis(PROGRESS_TICK_MS));
    pb
}

#[must_use]
pub fn create_commit_progress(total: usize) -> ProgressBar {
    let pb = ProgressBar::new(total as u64);

    #[allow(clippy::expect_used)] // Static template string; failure is a programmer error
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{bar:40.cyan/243} {percent:>3}% {pos}/{len} commits ({elapsed} elapsed)")
            .expect("invalid progress template")
            .progress_chars("━━╸"),
    );

    pb.enable_steady_tick(Duration::from_millis(PROGRESS_TICK_MS));
    pb
}

#[derive(Debug, Default)]
struct SeverityCounts {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
}

impl SeverityCounts {
    const fn increment(&mut self, severity: Severity) {
        match severity {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
        }
    }
}

pub fn build_severity_summary<T, F>(items: &[T], get_severity: F) -> String
where
    F: Fn(&T) -> Severity,
{
    let counts = count_severities(items, get_severity);
    format_severity_counts(&counts)
}

fn count_severities<T, F>(items: &[T], get_severity: F) -> SeverityCounts
where
    F: Fn(&T) -> Severity,
{
    let mut counts = SeverityCounts::default();
    for item in items {
        counts.increment(get_severity(item));
    }
    counts
}

fn format_severity_counts(counts: &SeverityCounts) -> String {
    let mut parts = Vec::with_capacity(4);

    if counts.critical > 0 {
        parts.push(format_count(counts.critical, "critical", Severity::Critical));
    }
    if counts.high > 0 {
        parts.push(format_count(counts.high, "high", Severity::High));
    }
    if counts.medium > 0 {
        parts.push(format_count(counts.medium, "medium", Severity::Medium));
    }
    if counts.low > 0 {
        parts.push(format_count(counts.low, "low", Severity::Low));
    }

    parts.join(" · ")
}

fn format_count(count: usize, label: &str, severity: Severity) -> String {
    format!(
        "{} {} {}",
        severity_indicator(severity),
        colors::secondary().apply_to(count),
        colors::muted().apply_to(label)
    )
}

const MICROSECOND_NS: u128 = 1_000;
const MILLISECOND_NS: u128 = 1_000_000;
const SECOND_NS: u128 = 1_000_000_000;

#[allow(clippy::cast_precision_loss)]
pub fn format_duration(d: Duration) -> String {
    let nanos = d.as_nanos();

    if nanos < MICROSECOND_NS {
        format!("{nanos}ns")
    } else if nanos < MILLISECOND_NS {
        format!("{:.1}µs", nanos as f64 / MICROSECOND_NS as f64)
    } else if nanos < SECOND_NS {
        format!("{:.1}ms", nanos as f64 / MILLISECOND_NS as f64)
    } else {
        format!("{:.2}s", d.as_secs_f64())
    }
}

pub fn clap_styles() -> clap::builder::Styles {
    use clap::builder::styling::{AnsiColor, Effects, Style};

    clap::builder::Styles::styled()
        .header(
            Style::new()
                .fg_color(Some(AnsiColor::Cyan.into()))
                .effects(Effects::BOLD),
        )
        .usage(
            Style::new()
                .fg_color(Some(AnsiColor::Cyan.into()))
                .effects(Effects::BOLD),
        )
        .literal(Style::new().fg_color(Some(AnsiColor::Cyan.into())))
        .placeholder(Style::new().fg_color(Some(AnsiColor::BrightBlack.into())))
        .valid(Style::new().fg_color(Some(AnsiColor::Green.into())))
        .invalid(Style::new().fg_color(Some(AnsiColor::Red.into())))
        .error(
            Style::new()
                .fg_color(Some(AnsiColor::Red.into()))
                .effects(Effects::BOLD),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_indicators_are_single_chars() {
        assert_eq!(indicators::ERROR.chars().count(), 1);
        assert_eq!(indicators::WARNING.chars().count(), 1);
        assert_eq!(indicators::INFO.chars().count(), 1);
        assert_eq!(indicators::SUCCESS.chars().count(), 1);
        assert_eq!(indicators::ADDED.chars().count(), 1);
    }

    #[test]
    fn test_pluralise_word() {
        assert_eq!(pluralise_word(0, "secret", "secrets"), "secrets");
        assert_eq!(pluralise_word(1, "secret", "secrets"), "secret");
        assert_eq!(pluralise_word(2, "secret", "secrets"), "secrets");
    }

    #[test]
    fn test_truncate_with_ellipsis() {
        assert_eq!(truncate_with_ellipsis("short", 10), "short");
        assert_eq!(truncate_with_ellipsis("longer text", 6), "longe…");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_nanos(500)), "500ns");
        assert_eq!(format_duration(Duration::from_micros(500)), "500.0µs");
        assert_eq!(format_duration(Duration::from_millis(500)), "500.0ms");
        assert_eq!(format_duration(Duration::from_secs(2)), "2.00s");
    }
}
