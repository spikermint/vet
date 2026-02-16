//! Output formatting for scan results.

mod json;
mod sarif;
mod text;

use std::collections::HashMap;
use std::fs::File;
use std::io::BufWriter;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context as _;
use vet_core::prelude::*;
use vet_providers::VerificationResult;

use super::runner::ContentCache;
use crate::{OutputFormat, ScanArgs};

/// Maps finding IDs to their verification results.
pub type VerificationMap = HashMap<String, VerificationResult>;

/// Aggregate statistics for a completed scan.
#[derive(Debug)]
pub struct ScanStats {
    /// Number of files scanned.
    pub file_count: usize,
    /// Wall-clock time for the entire scan.
    pub elapsed: Duration,
    /// Total findings before any filtering.
    pub total_findings: usize,
    /// Findings removed by confidence or severity filters.
    pub filtered_count: usize,
    /// Findings suppressed by the baseline.
    pub baseline_count: usize,
}

/// Everything needed to render scan output in any format.
#[derive(Debug)]
pub struct OutputContext<'a> {
    /// Findings to include in the output.
    pub findings: &'a [Finding],
    /// All loaded detection patterns (for metadata lookup).
    pub patterns: &'a [Pattern],
    /// Cached file content for context line display.
    pub content_cache: &'a ContentCache,
    /// Scan statistics for the summary line.
    pub stats: ScanStats,
    /// Verification results, if verification was requested.
    pub verifications: Option<&'a VerificationMap>,
}

/// Writes scan output to a file or stdout in the requested format.
pub fn write_output(args: &ScanArgs, ctx: &OutputContext) -> anyhow::Result<()> {
    match &args.output {
        Some(path) => write_to_file(path, args.format, ctx),
        None => write_to_stdout(args.format, args.verbose, ctx),
    }
}

fn write_to_file(path: &PathBuf, format: OutputFormat, ctx: &OutputContext) -> anyhow::Result<()> {
    let file = File::create(path).with_context(|| format!("failed to create output file: {}", path.display()))?;
    let mut writer = BufWriter::new(file);

    match format {
        OutputFormat::Text => text::write(ctx, &mut writer, true, 0),
        OutputFormat::Json => json::write(ctx.findings, ctx.verifications, &mut writer),
        OutputFormat::Sarif => sarif::write(ctx.findings, ctx.patterns, ctx.verifications, &mut writer),
    }
}

fn write_to_stdout(format: OutputFormat, verbose: u8, ctx: &OutputContext) -> anyhow::Result<()> {
    let mut stdout = std::io::stdout().lock();

    match format {
        OutputFormat::Text => text::write(ctx, &mut stdout, false, verbose),
        OutputFormat::Json => json::write(ctx.findings, ctx.verifications, &mut stdout),
        OutputFormat::Sarif => sarif::write(ctx.findings, ctx.patterns, ctx.verifications, &mut stdout),
    }
}
