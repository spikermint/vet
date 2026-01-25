//! Text output formatting for history scan results.

use std::io::Write;

use chrono::Local;
use console::style;
use vet_core::prelude::*;

use super::OutputContext;
use crate::commands::history::HistoryFinding;
use crate::ui::{self, colors, format_duration, truncate_with_ellipsis};

pub fn write(ctx: &OutputContext, writer: &mut dyn Write) -> anyhow::Result<()> {
    if ctx.findings.is_empty() {
        writeln!(writer)?;
        write_summary(ctx, writer)?;
        writeln!(writer)?;
        return Ok(());
    }

    writeln!(writer)?;

    if ctx.all {
        for finding in ctx.findings {
            write_finding_grouped(finding, ctx.patterns, writer)?;
        }
    } else {
        for finding in ctx.findings {
            write_finding(finding, ctx.patterns, writer)?;
        }
    }

    write_summary(ctx, writer)?;
    writeln!(writer)?;

    Ok(())
}

fn write_finding(finding: &HistoryFinding, patterns: &[Pattern], writer: &mut dyn Write) -> anyhow::Result<()> {
    let pattern_name = find_pattern_name(patterns, &finding.finding.pattern_id);
    let severity = finding.finding.severity.to_string().to_lowercase();
    let commit = &finding.introduced_in.commit;

    writeln!(
        writer,
        "{} {} {} {}",
        ui::severity_style(finding.finding.severity).apply_to("●"),
        style(pattern_name).bold(),
        colors::muted().apply_to("·"),
        ui::severity_style(finding.finding.severity).apply_to(&severity),
    )?;

    writeln!(
        writer,
        "  {} {}",
        colors::emphasis().apply_to(&commit.short_hash),
        truncate_with_ellipsis(&commit.message, 50),
    )?;

    writeln!(
        writer,
        "  {} {} {}",
        commit.date.with_timezone(&Local).format("%Y-%m-%d"),
        colors::muted().apply_to("·"),
        colors::muted().apply_to(&commit.author_email),
    )?;

    writeln!(
        writer,
        "  {} {}:{}",
        colors::muted().apply_to("└─"),
        finding.introduced_in.path.display(),
        finding.introduced_in.line,
    )?;

    writeln!(
        writer,
        "     {}",
        colors::muted().apply_to(&finding.finding.masked_line)
    )?;

    writeln!(writer)?;
    Ok(())
}

fn write_finding_grouped(finding: &HistoryFinding, patterns: &[Pattern], writer: &mut dyn Write) -> anyhow::Result<()> {
    let pattern_name = find_pattern_name(patterns, &finding.finding.pattern_id);
    let severity = finding.finding.severity.to_string().to_lowercase();

    let occurrence_word = ui::pluralise_word(finding.occurrence_count, "occurrence", "occurrences");
    let occurrence_text = format!("{} {}", finding.occurrence_count, occurrence_word);

    writeln!(
        writer,
        "{} {} {} {} {} {}",
        ui::severity_style(finding.finding.severity).apply_to("●"),
        style(pattern_name).bold(),
        colors::muted().apply_to("·"),
        ui::severity_style(finding.finding.severity).apply_to(&severity),
        colors::muted().apply_to("·"),
        colors::muted().apply_to(&occurrence_text),
    )?;

    writeln!(writer, "  {}", colors::muted().apply_to(&finding.finding.masked_line))?;

    let mut all = vec![&finding.introduced_in];
    all.extend(finding.occurrences.iter());
    all.sort_by_key(|occ| occ.commit.date);
    all.dedup_by(|a, b| a.commit.hash == b.commit.hash);

    let count = all.len();
    for (i, occ) in all.iter().enumerate() {
        let is_last = i == count - 1;
        let prefix = if is_last { "└─" } else { "├─" };

        let is_introduced = occ.commit.hash == finding.introduced_in.commit.hash;
        let marker = if is_introduced {
            format!(" {}", colors::muted().apply_to("(introduced)"))
        } else {
            String::new()
        };

        writeln!(
            writer,
            "  {} {} {}:{} {} {}{}",
            colors::muted().apply_to(prefix),
            colors::emphasis().apply_to(&occ.commit.short_hash),
            occ.path.display(),
            occ.line,
            colors::muted().apply_to("·"),
            occ.commit.date.with_timezone(&Local).format("%Y-%m-%d"),
            marker,
        )?;
    }

    writeln!(writer)?;
    Ok(())
}

fn write_summary(ctx: &OutputContext, writer: &mut dyn Write) -> anyhow::Result<()> {
    let commits = format!("{} commits", ctx.stats.commits_scanned);
    let timing = format!("({})", format_duration(ctx.stats.elapsed));

    if ctx.findings.is_empty() {
        writeln!(
            writer,
            "{} {} {} {} {}",
            colors::success().apply_to("✓"),
            colors::muted().apply_to("no secrets"),
            colors::muted().apply_to("·"),
            colors::muted().apply_to(&commits),
            colors::muted().apply_to(&timing),
        )?;
        return Ok(());
    }

    let count = ctx.findings.len();
    let secrets_word = if count == 1 { "secret" } else { "secrets" };
    let severity_summary = ui::build_severity_summary(ctx.findings, |f| f.finding.severity);

    let occurrence_part = if ctx.stats.total_occurrences > count {
        format!(
            "{} {} ",
            colors::muted().apply_to(format!("{} total occurrences", ctx.stats.total_occurrences)),
            colors::muted().apply_to("·"),
        )
    } else {
        String::new()
    };

    writeln!(
        writer,
        "{} {} {} {}{} {} {} {}",
        colors::error().apply_to("●"),
        style(format!("{count} {secrets_word}")).bold(),
        colors::muted().apply_to("·"),
        occurrence_part,
        severity_summary,
        colors::muted().apply_to("·"),
        colors::muted().apply_to(&commits),
        colors::muted().apply_to(&timing),
    )?;

    Ok(())
}

fn find_pattern_name<'a>(patterns: &'a [Pattern], pattern_id: &'a str) -> &'a str {
    patterns
        .iter()
        .find(|p| p.id.as_ref() == pattern_id)
        .map(|p| p.name.as_ref())
        .unwrap_or(pattern_id)
}
