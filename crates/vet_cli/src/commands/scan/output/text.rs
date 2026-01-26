//! Text output formatting for scan results.

use std::collections::HashMap;
use std::io::Write;

use console::style;
use vet_core::prelude::*;

use super::OutputContext;
use crate::commands::scan::runner::ContentCache;
use crate::files::get_context_lines;
use crate::ui::{
    build_severity_summary, colors, format_duration, indicators, pluralise_word, severity_indicator, severity_style,
};

const LINE_NUMBER_WIDTH: usize = 4;

pub fn write(ctx: &OutputContext, writer: &mut dyn Write, strip_colors: bool, verbose: u8) -> anyhow::Result<()> {
    let pattern_index = index_patterns_by_id(ctx.patterns);

    for finding in ctx.findings {
        write_finding(
            finding,
            ctx.findings,
            &pattern_index,
            ctx.content_cache,
            writer,
            strip_colors,
        )?;
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
    writer: &mut dyn Write,
    strip_colors: bool,
) -> anyhow::Result<()> {
    let pattern = pattern_index.get(finding.pattern_id.as_ref());

    write_finding_header(finding, pattern, writer, strip_colors)?;
    write_code_frame(finding, all_findings, content_cache, writer, strip_colors)?;
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

fn write_remediation_hint(
    pattern: Option<&&Pattern>,
    writer: &mut dyn Write,
    strip_colors: bool,
) -> anyhow::Result<()> {
    let Some(pattern) = pattern else {
        return Ok(());
    };

    let Some(remediation) = &pattern.remediation else {
        return Ok(());
    };

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

fn write_summary(ctx: &OutputContext, writer: &mut dyn Write, strip_colors: bool, verbose: u8) -> anyhow::Result<()> {
    let files = format!("{} files", ctx.stats.file_count);
    let time = format_duration(ctx.stats.elapsed);

    if ctx.findings.is_empty() {
        write_clean_summary(&files, &time, writer, strip_colors)?;
    } else {
        write_findings_summary(ctx.findings, &files, &time, writer, strip_colors)?;
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

fn write_clean_summary(files: &str, time: &str, writer: &mut dyn Write, strip_colors: bool) -> anyhow::Result<()> {
    write_line(
        writer,
        format_args!(
            "{} {} {} {}",
            colors::success().apply_to(indicators::SUCCESS),
            colors::primary().apply_to("No secrets found"),
            colors::muted().apply_to("·"),
            colors::muted().apply_to(format!("{files} ({time})"))
        ),
        strip_colors,
    )
}

fn write_findings_summary(
    findings: &[Finding],
    files: &str,
    time: &str,
    writer: &mut dyn Write,
    strip_colors: bool,
) -> anyhow::Result<()> {
    let count = findings.len();
    let word = pluralise_word(count, "secret", "secrets");
    let severity_summary = build_severity_summary(findings, |f| f.severity);

    write_line(
        writer,
        format_args!(
            "{} {} {} {} {} {}",
            colors::error().apply_to(indicators::ERROR),
            colors::primary().apply_to(format!("{count} {word} found")),
            colors::muted().apply_to("·"),
            severity_summary,
            colors::muted().apply_to("·"),
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
