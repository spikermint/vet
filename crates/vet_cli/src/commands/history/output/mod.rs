//! Output formatting for history scan results.

mod json;
mod sarif;
mod text;

use std::fs::File;
use std::io::BufWriter;
use std::time::Duration;

use anyhow::Context as _;
use vet_core::prelude::*;

use super::HistoryFinding;
use crate::{HistoryArgs, OutputFormat};

/// Aggregate statistics for a completed history scan.
#[derive(Debug)]
pub struct HistoryStats {
    /// Number of commits scanned.
    pub commits_scanned: usize,
    /// Number of unique secrets found.
    pub secrets_found: usize,
    /// Total occurrences across all commits.
    pub total_occurrences: usize,
    /// Wall-clock time for the scan.
    pub elapsed: Duration,
}

/// Everything needed to render history output in any format.
#[derive(Debug)]
pub struct OutputContext<'a> {
    /// Findings to include in the output.
    pub findings: &'a [HistoryFinding],
    /// All loaded patterns (for metadata lookup).
    pub patterns: &'a [Pattern],
    /// Scan statistics for the summary.
    pub stats: HistoryStats,
    /// Whether `--all` was passed (affects ref display).
    pub all: bool,
}

/// Writes history output to a file or stdout in the requested format.
pub fn write_output(args: &HistoryArgs, ctx: &OutputContext) -> anyhow::Result<()> {
    if let Some(path) = &args.output {
        let file = File::create(path).with_context(|| format!("failed to create output file: {}", path.display()))?;
        let mut writer = BufWriter::new(file);
        write_format(args.format, ctx, &mut writer)
    } else {
        let stdout = std::io::stdout();
        let mut writer = stdout.lock();
        write_format(args.format, ctx, &mut writer)
    }
}

fn write_format(format: OutputFormat, ctx: &OutputContext, writer: &mut dyn std::io::Write) -> anyhow::Result<()> {
    match format {
        OutputFormat::Text => text::write(ctx, writer),
        OutputFormat::Json => json::write(ctx, writer),
        OutputFormat::Sarif => sarif::write(ctx, writer),
    }
}
