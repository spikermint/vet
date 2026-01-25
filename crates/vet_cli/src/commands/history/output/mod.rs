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

pub struct HistoryStats {
    pub commits_scanned: usize,
    pub secrets_found: usize,
    pub total_occurrences: usize,
    pub elapsed: Duration,
}

pub struct OutputContext<'a> {
    pub findings: &'a [HistoryFinding],
    pub patterns: &'a [Pattern],
    pub stats: HistoryStats,
    pub all: bool,
}

pub fn write_output(args: &HistoryArgs, ctx: &OutputContext) -> anyhow::Result<()> {
    match &args.output {
        Some(path) => {
            let file =
                File::create(path).with_context(|| format!("failed to create output file: {}", path.display()))?;
            let mut writer = BufWriter::new(file);
            write_format(args.format, ctx, &mut writer)
        }
        None => {
            let stdout = std::io::stdout();
            let mut writer = stdout.lock();
            write_format(args.format, ctx, &mut writer)
        }
    }
}

fn write_format(format: OutputFormat, ctx: &OutputContext, writer: &mut dyn std::io::Write) -> anyhow::Result<()> {
    match format {
        OutputFormat::Text => text::write(ctx, writer),
        OutputFormat::Json => json::write(ctx, writer),
        OutputFormat::Sarif => sarif::write(ctx, writer),
    }
}
