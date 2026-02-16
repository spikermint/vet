//! UI helpers for consistent output formatting.

use std::time::Duration;

use console::Style;
use indicatif::{ProgressBar, ProgressStyle};
use vet_core::prelude::*;

/// Single-character Unicode glyphs used as status indicators.
pub mod indicators {
    /// Error indicator (✖).
    pub const ERROR: &str = "✖";
    /// Warning indicator (⚠).
    pub const WARNING: &str = "⚠";
    /// Informational indicator (ℹ).
    pub const INFO: &str = "ℹ";
    /// Success indicator (✓).
    pub const SUCCESS: &str = "✓";
    /// Addition indicator (+).
    pub const ADDED: &str = "+";
}

/// Semantic colour palette for terminal output.
pub mod colors {
    use console::Style;

    /// Red - errors and critical findings.
    pub const fn error() -> Style {
        Style::new().red()
    }

    /// Yellow - warnings and low-confidence findings.
    pub const fn warning() -> Style {
        Style::new().yellow()
    }

    /// Cyan - informational messages.
    pub const fn info() -> Style {
        Style::new().cyan()
    }

    /// Green - success messages.
    pub const fn success() -> Style {
        Style::new().green()
    }

    /// White bold - primary/headline text.
    pub const fn primary() -> Style {
        Style::new().white().bold()
    }

    /// Light grey - secondary descriptive text.
    pub const fn secondary() -> Style {
        Style::new().color256(252)
    }

    /// Dark grey - muted/contextual text.
    pub const fn muted() -> Style {
        Style::new().color256(243)
    }

    /// Cyan - accent highlights (pattern IDs, commands).
    pub const fn accent() -> Style {
        Style::new().cyan()
    }

    /// White - emphasised inline text.
    pub const fn emphasis() -> Style {
        Style::new().white()
    }

    /// Dark grey - gutter line numbers.
    pub const fn line_number() -> Style {
        Style::new().color256(243)
    }

    /// Light grey - source code lines.
    pub const fn code() -> Style {
        Style::new().color256(252)
    }
}

/// Process exit codes.
pub mod exit {
    /// Secrets were found.
    pub const FINDINGS: i32 = 1;
    /// An unrecoverable error occurred.
    pub const ERROR: i32 = 2;
}

const SEVERITY_CRITICAL_COLOR: u8 = 196;
const SEVERITY_HIGH_COLOR: u8 = 208;
const SEVERITY_MEDIUM_COLOR: u8 = 220;
const SEVERITY_LOW_COLOR: u8 = 75;

/// Column width reserved for line numbers in code frames.
pub const LINE_NUMBER_WIDTH: usize = 4;

/// Returns the terminal colour style for a given severity level.
pub const fn severity_style(severity: Severity) -> Style {
    match severity {
        Severity::Critical => Style::new().color256(SEVERITY_CRITICAL_COLOR).bold(),
        Severity::High => Style::new().color256(SEVERITY_HIGH_COLOR),
        Severity::Medium => Style::new().color256(SEVERITY_MEDIUM_COLOR),
        Severity::Low => Style::new().color256(SEVERITY_LOW_COLOR),
    }
}

/// Returns a severity-coloured error indicator glyph.
#[must_use]
pub fn severity_indicator(severity: Severity) -> String {
    severity_style(severity).apply_to(indicators::ERROR).to_string()
}

/// Prints a styled `vet <command>` header with surrounding blank lines.
pub fn print_command_header(command: &str) {
    println!();
    println!(
        "{} {}",
        colors::accent().bold().apply_to("vet"),
        colors::muted().apply_to(command)
    );
    println!();
}

/// Prints a command hint line (`command  description`).
pub fn print_hint(command: &str, description: &str) {
    const CMD_WIDTH: usize = 28;

    println!(
        "  {}  {}",
        colors::accent().apply_to(format!("{command:<CMD_WIDTH$}")),
        colors::muted().apply_to(description)
    );
}

/// Prints a red error message to stderr.
pub fn print_error(message: &str) {
    eprintln!(
        "{} {}",
        colors::error().apply_to(indicators::ERROR),
        colors::secondary().apply_to(message)
    );
}

/// Prints a yellow warning message to stderr.
pub fn print_warning(message: &str) {
    eprintln!(
        "{} {}",
        colors::warning().apply_to(indicators::WARNING),
        colors::secondary().apply_to(message)
    );
}

/// Prints a cyan informational message to stdout.
pub fn print_info(message: &str) {
    println!(
        "{} {}",
        colors::info().apply_to(indicators::INFO),
        colors::secondary().apply_to(message)
    );
}

/// Returns `singular` when `count` is 1, otherwise `plural`.
#[must_use]
pub const fn pluralise_word<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

/// Truncates a string to `max_chars`, appending an ellipsis if shortened.
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

/// Creates a progress bar for file scanning with the given total file count.
#[must_use]
pub fn create_file_progress(total: usize) -> ProgressBar {
    let pb = ProgressBar::new(total as u64);

    #[expect(
        clippy::expect_used,
        reason = "static template string; failure is a programmer error"
    )]
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{bar:40.cyan/243} {percent:>3}% {pos}/{len} files ({elapsed} elapsed)")
            .expect("invalid progress template")
            .progress_chars("━━╸"),
    );

    pb.enable_steady_tick(Duration::from_millis(PROGRESS_TICK_MS));
    pb
}

/// Creates a progress bar for commit scanning with the given total commit count.
#[must_use]
pub fn create_commit_progress(total: usize) -> ProgressBar {
    let pb = ProgressBar::new(total as u64);

    #[expect(
        clippy::expect_used,
        reason = "static template string; failure is a programmer error"
    )]
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

/// Builds a one-line severity breakdown string (e.g. "✖ 2 critical · ✖ 1 high").
#[must_use]
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

/// Formats a duration as a human-readable string with the most appropriate
/// unit (ns, µs, ms, or s).
#[expect(
    clippy::cast_precision_loss,
    reason = "nanosecond-to-float conversion is display-only; precision loss is acceptable"
)]
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

/// Returns the shared clap colour theme used by all CLI subcommands.
#[must_use]
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
