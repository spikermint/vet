//! Output formatting for scan results.

mod json;
mod sarif;
mod text;

use std::fs::File;
use std::io::BufWriter;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context as _;
use vet_core::prelude::*;

use super::runner::ContentCache;
use crate::{OutputFormat, ScanArgs};

pub struct ScanStats {
    pub file_count: usize,
    pub elapsed: Duration,
    pub total_findings: usize,
    pub filtered_count: usize,
}

pub struct OutputContext<'a> {
    pub findings: &'a [Finding],
    pub patterns: &'a [Pattern],
    pub content_cache: &'a ContentCache,
    pub stats: ScanStats,
}

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
        OutputFormat::Json => json::write(ctx.findings, &mut writer),
        OutputFormat::Sarif => sarif::write(ctx.findings, ctx.patterns, &mut writer),
    }
}

fn write_to_stdout(format: OutputFormat, verbose: u8, ctx: &OutputContext) -> anyhow::Result<()> {
    let mut stdout = std::io::stdout().lock();

    match format {
        OutputFormat::Text => text::write(ctx, &mut stdout, false, verbose),
        OutputFormat::Json => json::write(ctx.findings, &mut stdout),
        OutputFormat::Sarif => sarif::write(ctx.findings, ctx.patterns, &mut stdout),
    }
}
