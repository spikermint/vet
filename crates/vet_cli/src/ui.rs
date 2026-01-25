//! UI helpers for consistent output formatting.

use std::time::Duration;

use console::Style;
use indicatif::{ProgressBar, ProgressStyle};
use vet_core::prelude::*;

pub mod colors {
    use console::Style;

    const MUTED_GRAY: u8 = 245;

    pub const fn muted() -> Style {
        Style::new().color256(MUTED_GRAY)
    }

    pub const fn success() -> Style {
        Style::new().green()
    }

    pub const fn warning() -> Style {
        Style::new().yellow()
    }

    pub const fn error() -> Style {
        Style::new().red()
    }

    pub const fn accent() -> Style {
        Style::new().cyan()
    }

    pub const fn emphasis() -> Style {
        Style::new().white()
    }
}

pub mod exit {
    pub const FINDINGS: i32 = 1;
    pub const ERROR: i32 = 2;
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
        colors::error().apply_to("✗"),
        colors::muted().apply_to(message)
    );
}

pub fn print_warning(message: &str) {
    eprintln!(
        "{} {}",
        colors::warning().apply_to("⚠"),
        colors::muted().apply_to(message)
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
            .template("{bar:40.cyan/dim} {percent:>3}% {pos}/{len} files ({elapsed} elapsed)")
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
            .template("{bar:40.cyan/dim} {percent:>3}% {pos}/{len} commits ({elapsed} elapsed)")
            .expect("invalid progress template")
            .progress_chars("━━╸"),
    );

    pb.enable_steady_tick(Duration::from_millis(PROGRESS_TICK_MS));
    pb
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
    severity_style(severity)
        .apply_to(format!("{count} {label}"))
        .to_string()
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
                .fg_color(Some(AnsiColor::Magenta.into()))
                .effects(Effects::BOLD),
        )
        .usage(
            Style::new()
                .fg_color(Some(AnsiColor::Magenta.into()))
                .effects(Effects::BOLD),
        )
        .literal(Style::new().fg_color(Some(AnsiColor::Cyan.into())))
        .placeholder(Style::new().fg_color(Some(AnsiColor::Green.into())))
        .valid(Style::new().fg_color(Some(AnsiColor::Green.into())))
        .invalid(Style::new().fg_color(Some(AnsiColor::Red.into())))
        .error(
            Style::new()
                .fg_color(Some(AnsiColor::Red.into()))
                .effects(Effects::BOLD),
        )
}
