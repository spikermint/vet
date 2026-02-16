//! JSON output formatting for history scan results.

use std::io::Write;

use serde::Serialize;

use super::OutputContext;
use crate::commands::history::{CommitInfo, HistoryFinding, SecretOccurrence};

#[derive(Serialize)]
struct JsonReport {
    version: &'static str,
    scan_type: &'static str,
    metadata: JsonMetadata,
    summary: JsonSummary,
    findings: Vec<JsonFinding>,
}

#[derive(Serialize)]
struct JsonMetadata {
    commits_scanned: usize,
    duration_ms: u64,
}

#[derive(Serialize)]
struct JsonSummary {
    secrets_found: usize,
    total_occurrences: usize,
    by_severity: JsonSeverityCounts,
}

#[derive(Serialize)]
struct JsonSeverityCounts {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
}

#[derive(Serialize)]
struct JsonFinding {
    id: String,
    pattern_id: String,
    severity: String,
    confidence: String,
    secret_masked: String,
    introduced_in: JsonOccurrence,
    occurrences: Vec<JsonOccurrence>,
    occurrence_count: usize,
}

#[derive(Serialize)]
struct JsonOccurrence {
    commit: JsonCommit,
    location: JsonLocation,
    line_content: String,
}

#[derive(Serialize)]
struct JsonCommit {
    hash: String,
    short_hash: String,
    author_name: String,
    author_email: String,
    date: String,
    message: String,
}

#[derive(Serialize)]
struct JsonLocation {
    path: String,
    line: u32,
    column: u32,
}

const VERSION: &str = "1.0";
const SCAN_TYPE: &str = "history";

/// Serialises history scan findings as a pretty-printed JSON report.
pub fn write(ctx: &OutputContext, writer: &mut dyn Write) -> anyhow::Result<()> {
    let report = build_report(ctx);
    serde_json::to_writer_pretty(&mut *writer, &report)?;
    writeln!(writer)?;
    Ok(())
}

fn build_report(ctx: &OutputContext) -> JsonReport {
    JsonReport {
        version: VERSION,
        scan_type: SCAN_TYPE,
        metadata: JsonMetadata {
            commits_scanned: ctx.stats.commits_scanned,
            duration_ms: u64::try_from(ctx.stats.elapsed.as_millis()).unwrap_or(u64::MAX),
        },
        summary: JsonSummary {
            secrets_found: ctx.stats.secrets_found,
            total_occurrences: ctx.stats.total_occurrences,
            by_severity: count_severities(ctx.findings),
        },
        findings: ctx.findings.iter().map(convert_finding).collect(),
    }
}

fn count_severities(findings: &[HistoryFinding]) -> JsonSeverityCounts {
    let mut counts = JsonSeverityCounts {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
    };

    for f in findings {
        match f.finding.severity {
            vet_core::Severity::Critical => counts.critical += 1,
            vet_core::Severity::High => counts.high += 1,
            vet_core::Severity::Medium => counts.medium += 1,
            vet_core::Severity::Low => counts.low += 1,
        }
    }

    counts
}

fn convert_finding(f: &HistoryFinding) -> JsonFinding {
    JsonFinding {
        id: f.finding.id.to_string(),
        pattern_id: f.finding.pattern_id.to_string(),
        severity: f.finding.severity.to_string().to_lowercase(),
        confidence: f.finding.confidence.to_string(),
        secret_masked: f.finding.secret.as_masked().to_string(),
        introduced_in: convert_occurrence(&f.introduced_in),
        occurrences: f.occurrences.iter().map(convert_occurrence).collect(),
        occurrence_count: f.occurrence_count,
    }
}

fn convert_occurrence(occ: &SecretOccurrence) -> JsonOccurrence {
    JsonOccurrence {
        commit: convert_commit(&occ.commit),
        location: JsonLocation {
            path: occ.path.display().to_string(),
            line: occ.line,
            column: occ.column,
        },
        line_content: occ.line_content.clone(),
    }
}

fn convert_commit(commit: &CommitInfo) -> JsonCommit {
    JsonCommit {
        hash: commit.hash.clone(),
        short_hash: commit.short_hash.clone(),
        author_name: commit.author_name.clone(),
        author_email: commit.author_email.clone(),
        date: commit.date.to_rfc3339(),
        message: commit.message.clone(),
    }
}
