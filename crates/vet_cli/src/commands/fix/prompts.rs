//! Interactive prompts for the fix command.

use std::path::Path;

use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, Select};
use vet_core::Finding;
use vet_core::comment_syntax;

use super::actions::{self, FixAction, PreviewLines};
use crate::files::get_context_lines;
use crate::ui::{LINE_NUMBER_WIDTH, colors, indicators, severity_style};

/// Displays a finding and prompts the user to choose a fix action.
pub fn prompt_for_action(
    path: &Path,
    finding: &Finding,
    all_file_findings: &[Finding],
    index: usize,
    total: usize,
    content: &str,
    offset: isize,
) -> anyhow::Result<Option<FixAction>> {
    print_finding_header(path, finding, index, total);
    print_code_context(content, finding, all_file_findings);

    let env_var_name = actions::derive_env_var_name(&finding.pattern_id);
    let comment_syntax = comment_syntax::for_path(path);

    let action = select_action(&env_var_name, comment_syntax.as_ref())?;

    let Some(action) = action else {
        print_skipped();
        return Ok(None);
    };

    if let Some(preview) = actions::generate_preview(content, finding, &action, offset) {
        print_preview(&preview);

        if !confirm_action()? {
            print_skipped();
            return Ok(None);
        }
    }

    print_applied(&action);
    Ok(Some(action))
}

fn print_finding_header(path: &Path, finding: &Finding, index: usize, total: usize) {
    println!();
    println!("{}", colors::muted().apply_to("─".repeat(60)));
    println!(
        "{} {}",
        colors::muted().apply_to(format!("[{index}/{total}]")),
        colors::primary().apply_to(&*finding.pattern_id),
    );
    println!("{}", colors::muted().apply_to("─".repeat(60)));

    let severity_label = finding.severity.to_string();
    let sev_style = severity_style(finding.severity);

    println!(
        "{} {} {}:{}",
        sev_style.apply_to(&severity_label),
        colors::muted().apply_to("·"),
        colors::secondary().apply_to(path.display().to_string()),
        colors::secondary().apply_to(finding.span.line.to_string()),
    );
    println!();
}

fn print_code_context(content: &str, finding: &Finding, all_file_findings: &[Finding]) {
    let other_masked_lines: Vec<(usize, &str)> = all_file_findings
        .iter()
        .filter(|f| f.span.line != finding.span.line)
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
            print_finding_line(ctx.line_number, &ctx.content);
        } else {
            print_context_line(ctx.line_number, &ctx.content);
        }
    }

    println!();
}

fn print_finding_line(line_number: usize, content: &str) {
    println!(
        "  {} {} {}",
        colors::primary().apply_to(format!("{line_number:>LINE_NUMBER_WIDTH$}")),
        colors::muted().apply_to("│"),
        content,
    );
}

fn print_context_line(line_number: usize, content: &str) {
    println!(
        "  {} {} {}",
        colors::muted().apply_to(format!("{line_number:>LINE_NUMBER_WIDTH$}")),
        colors::muted().apply_to("│"),
        colors::muted().apply_to(content),
    );
}

fn select_action(
    env_var_name: &str,
    comment_syntax: Option<&comment_syntax::CommentSyntax>,
) -> anyhow::Result<Option<FixAction>> {
    let mut items = vec![
        "Redact       → <REDACTED>".to_string(),
        format!("Placeholder  → ${{{env_var_name}}}"),
        "Delete line  → remove entire line".to_string(),
    ];

    if let Some(syntax) = comment_syntax {
        let formatted_ignore = syntax.format_ignore();
        items.push(format!("Ignore       → {formatted_ignore}"));
    }

    items.push("Skip         → no change".to_string());

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Action")
        .items(&items)
        .default(0)
        .interact()?;

    let action = if comment_syntax.is_some() {
        match selection {
            0 => Some(FixAction::Redact),
            1 => Some(FixAction::Placeholder(env_var_name.to_string())),
            2 => Some(FixAction::DeleteLine),
            3 => Some(FixAction::Ignore),
            _ => None,
        }
    } else {
        match selection {
            0 => Some(FixAction::Redact),
            1 => Some(FixAction::Placeholder(env_var_name.to_string())),
            2 => Some(FixAction::DeleteLine),
            _ => None,
        }
    };

    Ok(action)
}

fn print_preview(preview: &PreviewLines) {
    println!();

    if preview.is_deletion {
        println!(
            "  {} {} {}",
            colors::error().apply_to("-"),
            colors::muted().apply_to(format!("{:>LINE_NUMBER_WIDTH$}", preview.line_number)),
            colors::error().apply_to(&preview.original),
        );
    } else {
        println!(
            "  {} {} {}",
            colors::error().apply_to("-"),
            colors::muted().apply_to(format!("{:>LINE_NUMBER_WIDTH$}", preview.line_number)),
            colors::error().apply_to(&preview.original),
        );
        println!(
            "  {} {} {}",
            colors::success().apply_to("+"),
            colors::muted().apply_to(format!("{:>LINE_NUMBER_WIDTH$}", preview.line_number)),
            colors::success().apply_to(&preview.modified),
        );
    }

    println!();
}

fn confirm_action() -> anyhow::Result<bool> {
    let confirmed = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Apply?")
        .default(true)
        .interact()?;

    Ok(confirmed)
}

fn print_skipped() {
    println!(
        "  {} {}",
        colors::muted().apply_to("○"),
        colors::secondary().apply_to("skipped")
    );
}

fn print_applied(action: &FixAction) {
    println!(
        "  {} {}",
        colors::success().apply_to(indicators::SUCCESS),
        colors::secondary().apply_to(format!("{} applied", action.label().to_lowercase()))
    );
}
