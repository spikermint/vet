//! Text output formatting for scan results.

use std::collections::HashMap;
use std::io::Write;

use console::style;
use vet_core::prelude::*;
use vet_providers::VerificationStatus;

use super::{OutputContext, VerificationMap};
use crate::commands::scan::runner::ContentCache;
use crate::files::get_context_lines;
use crate::ui::{
    LINE_NUMBER_WIDTH, build_severity_summary, colors, format_duration, indicators, pluralise_word, severity_indicator,
    severity_style,
};

const INDENT: usize = 2;
const ICON_WIDTH: usize = 1;
const STATUS_WIDTH: usize = 9;
const PATTERN_WIDTH: usize = 30;
const COLUMN_GAP: usize = 1;
const LOCATION_GAP: usize = 2;

/// Renders scan findings as styled, human-readable text to the given writer.
pub fn write(ctx: &OutputContext, writer: &mut dyn Write, strip_colors: bool, verbose: u8) -> anyhow::Result<()> {
    let pattern_index = index_patterns_by_id(ctx.patterns);

    for finding in ctx.findings {
        write_finding(
            finding,
            ctx.findings,
            &pattern_index,
            ctx.content_cache,
            ctx.verifications,
            writer,
            strip_colors,
        )?;
    }

    if let Some(verifications) = ctx.verifications {
        write_verification_summary(ctx.findings, verifications, writer, strip_colors)?;
    }

    write_summary(ctx, writer, strip_colors, verbose)
}

fn index_patterns_by_id(patterns: &[Pattern]) -> HashMap<&str, &Pattern> {
    patterns.iter().map(|p| (p.id.as_ref(), p)).collect()
}

fn write_finding(
    finding: &Finding,
    all_findings: &[Finding],
    pattern_index: &HashMap<&str, &Pattern>,
    content_cache: &ContentCache,
    verifications: Option<&VerificationMap>,
    writer: &mut dyn Write,
    strip_colors: bool,
) -> anyhow::Result<()> {
    let pattern = pattern_index.get(finding.pattern_id.as_ref());
    let verification = verifications.and_then(|v| v.get(finding.id.as_str()));

    write_finding_header(finding, pattern, writer, strip_colors)?;
    write_code_frame(finding, all_findings, content_cache, writer, strip_colors)?;
    write_verification_status(verification, writer, strip_colors)?;
    write_remediation_hint(pattern, writer, strip_colors)?;

    writeln!(writer)?;
    Ok(())
}

fn write_finding_header(
    finding: &Finding,
    pattern: Option<&&Pattern>,
    writer: &mut dyn Write,
    strip_colors: bool,
) -> anyhow::Result<()> {
    let sev_style = severity_style(finding.severity);
    let severity_label = finding.severity.to_string();
    let description = pattern.map_or("Secret detected", |p| &p.name);

    let is_low_confidence = finding.confidence == Confidence::Low;

    let indicator = if is_low_confidence {
        colors::warning().apply_to(indicators::WARNING).to_string()
    } else {
        severity_indicator(finding.severity)
    };

    let confidence_suffix = if is_low_confidence {
        format!(
            " {} {}",
            colors::muted().apply_to("·"),
            colors::warning().apply_to("low confidence")
        )
    } else {
        String::new()
    };

    write_line(
        writer,
        format_args!(
            "{} {} {} {}{}",
            indicator,
            style(description).bold(),
            colors::muted().apply_to("·"),
            sev_style.apply_to(&severity_label),
            confidence_suffix,
        ),
        strip_colors,
    )?;

    let location = format!(
        "{}:{}:{}",
        finding.path.display(),
        finding.span.line,
        finding.span.column
    );

    write_line(
        writer,
        format_args!("  {}", colors::secondary().apply_to(&location)),
        strip_colors,
    )?;

    writeln!(writer)?;
    Ok(())
}

fn write_code_frame(
    finding: &Finding,
    all_findings: &[Finding],
    content_cache: &ContentCache,
    writer: &mut dyn Write,
    strip_colors: bool,
) -> anyhow::Result<()> {
    let content = content_cache.get(finding.path.as_ref()).map_or("", String::as_str);

    let other_masked_lines: Vec<(usize, &str)> = all_findings
        .iter()
        .filter(|f| f.path == finding.path && f.span.line != finding.span.line)
        .map(|f| (f.span.line as usize, f.masked_line.as_ref()))
        .collect();

    let context_lines = get_context_lines(
        content,
        finding.span.line as usize,
        &finding.masked_line,
        &other_masked_lines,
    );

    for ctx in &context_lines {
        if ctx.is_finding {
            write_finding_line(ctx, finding, writer, strip_colors)?;
        } else {
            write_context_line(ctx, writer, strip_colors)?;
        }
    }

    Ok(())
}

fn write_finding_line(
    ctx: &crate::files::ContextLine,
    finding: &Finding,
    writer: &mut dyn Write,
    strip_colors: bool,
) -> anyhow::Result<()> {
    let line_num = format!("{:>LINE_NUMBER_WIDTH$}", ctx.line_number);

    write_line(
        writer,
        format_args!(
            "{} {} {}",
            style(&line_num).bold(),
            colors::muted().apply_to("│"),
            ctx.content
        ),
        strip_colors,
    )?;

    write_underline(finding, writer, strip_colors)
}

fn write_underline(finding: &Finding, writer: &mut dyn Write, strip_colors: bool) -> anyhow::Result<()> {
    let underline_style = if finding.confidence == Confidence::Low {
        colors::warning()
    } else {
        severity_style(finding.severity)
    };

    let underline_start = finding.span.column.saturating_sub(1) as usize;
    let underline_len = finding.secret.as_masked().chars().count();

    let padding = " ".repeat(LINE_NUMBER_WIDTH + 3 + underline_start);

    write_line(
        writer,
        format_args!("{}{}", padding, underline_style.apply_to("^".repeat(underline_len))),
        strip_colors,
    )
}

fn write_context_line(
    ctx: &crate::files::ContextLine,
    writer: &mut dyn Write,
    strip_colors: bool,
) -> anyhow::Result<()> {
    let line_num = format!("{:>LINE_NUMBER_WIDTH$}", ctx.line_number);

    write_line(
        writer,
        format_args!(
            "{} {} {}",
            colors::line_number().apply_to(&line_num),
            colors::muted().apply_to("│"),
            colors::code().apply_to(&ctx.content)
        ),
        strip_colors,
    )
}

fn write_verification_status(
    verification: Option<&vet_providers::VerificationResult>,
    writer: &mut dyn Write,
    strip_colors: bool,
) -> anyhow::Result<()> {
    let Some(v) = verification else {
        return Ok(());
    };

    let service = v.service.as_ref();
    let details = service.map_or("", |s| s.details.as_ref());

    writeln!(writer)?;

    match v.status {
        VerificationStatus::Live => {
            let message = if details.is_empty() {
                "secret is active".to_string()
            } else {
                details.to_string()
            };
            write_line(
                writer,
                format_args!(
                    "  {} {} {} {}",
                    colors::error().apply_to(indicators::ERROR),
                    colors::error().bold().apply_to("LIVE"),
                    colors::muted().apply_to("-"),
                    colors::secondary().apply_to(message)
                ),
                strip_colors,
            )
        }
        VerificationStatus::Inactive => {
            let message = if details.is_empty() {
                "key is revoked or expired".to_string()
            } else {
                details.to_string()
            };
            write_line(
                writer,
                format_args!(
                    "  {} {} {} {}",
                    colors::success().apply_to(indicators::SUCCESS),
                    colors::success().apply_to("inactive"),
                    colors::muted().apply_to("-"),
                    colors::secondary().apply_to(message)
                ),
                strip_colors,
            )
        }
        VerificationStatus::Inconclusive => {
            let message = if details.is_empty() {
                "rate limited, try again later".to_string()
            } else {
                details.to_string()
            };
            write_line(
                writer,
                format_args!(
                    "  {} {} {} {}",
                    colors::warning().apply_to(indicators::WARNING),
                    colors::warning().apply_to("inconclusive"),
                    colors::muted().apply_to("-"),
                    colors::secondary().apply_to(message)
                ),
                strip_colors,
            )
        }
    }
}

fn write_remediation_hint(
    pattern: Option<&&Pattern>,
    writer: &mut dyn Write,
    strip_colors: bool,
) -> anyhow::Result<()> {
    let Some(pattern) = pattern else {
        return Ok(());
    };

    let remediation = pattern.remediation();
    let first_line = remediation.lines().next().unwrap_or(remediation);
    let trimmed = first_line.trim_start_matches(|c: char| c.is_ascii_digit() || c == '.' || c == ' ');

    writeln!(writer)?;
    write_line(
        writer,
        format_args!(
            "  {} {}",
            colors::info().apply_to(indicators::INFO),
            colors::secondary().apply_to(trimmed)
        ),
        strip_colors,
    )
}

fn write_verification_summary(
    findings: &[Finding],
    verifications: &VerificationMap,
    writer: &mut dyn Write,
    strip_colors: bool,
) -> anyhow::Result<()> {
    if verifications.is_empty() && findings.is_empty() {
        return Ok(());
    }

    let counts = count_verification_statuses(findings, verifications);
    let separator = build_verification_separator(findings);

    write_line(
        writer,
        format_args!("{}", colors::muted().apply_to(&separator)),
        strip_colors,
    )?;

    let header = build_verification_header(findings.len(), &counts);
    write_line(
        writer,
        format_args!(
            "  {} {} {}",
            colors::accent().bold().apply_to("verification"),
            colors::muted().apply_to("·"),
            colors::muted().apply_to(header)
        ),
        strip_colors,
    )?;
    writeln!(writer)?;

    for finding in findings {
        if let Some(v) = verifications.get(finding.id.as_str()) {
            write_verified_row(finding, v.status, writer, strip_colors)?;
        }
    }

    for finding in findings {
        if !verifications.contains_key(finding.id.as_str()) {
            write_skipped_row(finding, writer, strip_colors)?;
        }
    }

    write_line(
        writer,
        format_args!("{}", colors::muted().apply_to(&separator)),
        strip_colors,
    )?;

    Ok(())
}

fn build_verification_separator(findings: &[Finding]) -> String {
    let max_location_len = findings
        .iter()
        .map(|f| format!("{}:{}", f.path.display(), f.span.line).len())
        .max()
        .unwrap_or(0);

    let row_width =
        INDENT + ICON_WIDTH + COLUMN_GAP + STATUS_WIDTH + COLUMN_GAP + PATTERN_WIDTH + LOCATION_GAP + max_location_len;
    "─".repeat(row_width)
}

fn build_verification_header(total_count: usize, counts: &VerificationCounts) -> String {
    let secret_word = if total_count == 1 { "secret" } else { "secrets" };
    let mut parts = vec![format!("{total_count} {secret_word}")];

    if counts.live > 0 {
        parts.push(format!("{} live", counts.live));
    }
    if counts.inactive > 0 {
        parts.push(format!("{} inactive", counts.inactive));
    }
    if counts.skipped > 0 {
        parts.push(format!("{} skipped", counts.skipped));
    }

    parts.join(" · ")
}

fn write_verified_row(
    finding: &Finding,
    status: VerificationStatus,
    writer: &mut dyn Write,
    strip_colors: bool,
) -> anyhow::Result<()> {
    let location = format!("{}:{}", finding.path.display(), finding.span.line);
    let pattern_display = truncate_pattern(&finding.pattern_id, PATTERN_WIDTH);

    let (icon, status_text, pattern_style) = match status {
        VerificationStatus::Live => (
            colors::error().apply_to(indicators::ERROR),
            colors::error().bold().apply_to("LIVE"),
            colors::primary().apply_to(&pattern_display),
        ),
        VerificationStatus::Inactive => (
            colors::success().apply_to(indicators::SUCCESS),
            colors::success().apply_to("inactive"),
            colors::secondary().apply_to(&pattern_display),
        ),
        VerificationStatus::Inconclusive => (
            colors::warning().apply_to(indicators::WARNING),
            colors::warning().apply_to("inconclusive"),
            colors::secondary().apply_to(&pattern_display),
        ),
    };

    write_line(
        writer,
        format_args!(
            "  {} {:<9} {:<30}  {}",
            icon,
            status_text,
            pattern_style,
            colors::muted().apply_to(&location)
        ),
        strip_colors,
    )
}

fn write_skipped_row(finding: &Finding, writer: &mut dyn Write, strip_colors: bool) -> anyhow::Result<()> {
    let location = format!("{}:{}", finding.path.display(), finding.span.line);
    let pattern_display = truncate_pattern(&finding.pattern_id, PATTERN_WIDTH);

    write_line(
        writer,
        format_args!(
            "  {} {:<9} {:<30}  {}",
            colors::muted().apply_to("─"),
            colors::muted().apply_to("skipped"),
            colors::muted().apply_to(&pattern_display),
            colors::muted().apply_to(&location)
        ),
        strip_colors,
    )
}

fn truncate_pattern(pattern_id: &str, max_len: usize) -> String {
    if pattern_id.len() <= max_len {
        pattern_id.to_string()
    } else {
        format!("{}…", &pattern_id[..max_len - 1])
    }
}

fn write_summary(ctx: &OutputContext, writer: &mut dyn Write, strip_colors: bool, verbose: u8) -> anyhow::Result<()> {
    let files = format!("{} files", ctx.stats.file_count);
    let time = format_duration(ctx.stats.elapsed);

    let verification_counts = ctx.verifications.map(|v| count_verification_statuses(ctx.findings, v));

    if ctx.findings.is_empty() {
        write_clean_summary(&files, &time, ctx.stats.baseline_count, writer, strip_colors)?;
    } else {
        write_findings_summary(
            ctx.findings,
            &files,
            &time,
            ctx.stats.baseline_count,
            verification_counts.as_ref(),
            writer,
            strip_colors,
        )?;
    }

    if verbose > 0 && ctx.stats.filtered_count > 0 {
        writeln!(writer)?;
        write_line(
            writer,
            format_args!(
                "  {}",
                colors::muted().apply_to(format!(
                    "{} total · {} filtered (low confidence)",
                    ctx.stats.total_findings, ctx.stats.filtered_count
                ))
            ),
            strip_colors,
        )?;
    }

    Ok(())
}

fn write_clean_summary(
    files: &str,
    time: &str,
    baseline_count: usize,
    writer: &mut dyn Write,
    strip_colors: bool,
) -> anyhow::Result<()> {
    let message = if baseline_count > 0 {
        let word = pluralise_word(baseline_count, "finding", "findings");
        format!("No new secrets found ({baseline_count} {word} in baseline)")
    } else {
        "No secrets found".to_string()
    };

    write_line(
        writer,
        format_args!(
            "{} {} {} {}",
            colors::success().apply_to(indicators::SUCCESS),
            colors::primary().apply_to(message),
            colors::muted().apply_to("·"),
            colors::muted().apply_to(format!("{files} ({time})"))
        ),
        strip_colors,
    )
}

struct VerificationCounts {
    live: usize,
    inactive: usize,
    inconclusive: usize,
    skipped: usize,
}

fn count_verification_statuses(findings: &[Finding], verifications: &VerificationMap) -> VerificationCounts {
    let mut counts = VerificationCounts {
        live: 0,
        inactive: 0,
        inconclusive: 0,
        skipped: 0,
    };

    for finding in findings {
        match verifications.get(finding.id.as_str()) {
            Some(result) => match result.status {
                VerificationStatus::Live => counts.live += 1,
                VerificationStatus::Inactive => counts.inactive += 1,
                VerificationStatus::Inconclusive => counts.inconclusive += 1,
            },
            None => counts.skipped += 1,
        }
    }

    counts
}

fn write_findings_summary(
    findings: &[Finding],
    files: &str,
    time: &str,
    baseline_count: usize,
    verification_counts: Option<&VerificationCounts>,
    writer: &mut dyn Write,
    strip_colors: bool,
) -> anyhow::Result<()> {
    let count = findings.len();
    let word = pluralise_word(count, "secret", "secrets");
    let severity_summary = build_severity_summary(findings, |f| f.severity);

    let message = if baseline_count > 0 {
        let baseline_word = pluralise_word(baseline_count, "finding", "findings");
        format!("{count} new {word} found ({baseline_count} {baseline_word} in baseline)")
    } else {
        format!("{count} {word} found")
    };

    let verification_summary = match verification_counts {
        Some(counts) => {
            let mut parts = Vec::new();
            if counts.live > 0 {
                parts.push(format!(
                    "{} {}",
                    colors::error().bold().apply_to(counts.live),
                    colors::error().bold().apply_to("live")
                ));
            }
            if counts.inactive > 0 {
                parts.push(format!(
                    "{} {}",
                    colors::success().apply_to(counts.inactive),
                    colors::success().apply_to("inactive")
                ));
            }
            if counts.inconclusive > 0 {
                parts.push(format!(
                    "{} {}",
                    colors::warning().apply_to(counts.inconclusive),
                    colors::warning().apply_to("inconclusive")
                ));
            }
            if parts.is_empty() {
                String::new()
            } else {
                format!(
                    "{} {} ",
                    parts.join(&format!(" {} ", colors::muted().apply_to("·"))),
                    colors::muted().apply_to("·")
                )
            }
        }
        None => String::new(),
    };

    write_line(
        writer,
        format_args!(
            "{} {} {} {} {} {}{}",
            colors::error().apply_to(indicators::ERROR),
            colors::primary().apply_to(message),
            colors::muted().apply_to("·"),
            severity_summary,
            colors::muted().apply_to("·"),
            verification_summary,
            colors::muted().apply_to(format!("{files} ({time})"))
        ),
        strip_colors,
    )
}

fn write_line(writer: &mut dyn Write, args: std::fmt::Arguments<'_>, strip_colors: bool) -> anyhow::Result<()> {
    if strip_colors {
        let s = args.to_string();
        let stripped = console::strip_ansi_codes(&s);
        writeln!(writer, "{stripped}")?;
    } else {
        writeln!(writer, "{args}")?;
    }
    Ok(())
}
