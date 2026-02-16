//! SARIF output formatting for history scan results.

use std::io::Write;

use serde::Serialize;
use vet_core::prelude::*;

use super::OutputContext;
use crate::commands::history::HistoryFinding;

const SARIF_VERSION: &str = "2.1.0";
const SARIF_SCHEMA: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
const TOOL_NAME: &str = "vet";
const TOOL_URI: &str = "https://github.com/spikermint/vet";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifReport {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifDriver {
    name: &'static str,
    information_uri: &'static str,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRule {
    id: String,
    name: String,
    short_description: SarifMessage,
    full_description: SarifMessage,
    default_configuration: SarifRuleConfig,
    properties: SarifRuleProperties,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRuleConfig {
    level: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRuleProperties {
    severity: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: String,
    level: &'static str,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    fingerprints: SarifFingerprints,
    properties: SarifResultProperties,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRegion {
    start_line: u32,
    start_column: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifFingerprints {
    #[serde(rename = "secret/v1")]
    secret_v1: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResultProperties {
    scan_type: &'static str,
    commit: SarifCommitInfo,
    occurrence_count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifCommitInfo {
    hash: String,
    short_hash: String,
    date: String,
    author: String,
    message: String,
}

/// Serialises history scan findings as a SARIF v2.1.0 report.
pub fn write(ctx: &OutputContext, writer: &mut dyn Write) -> anyhow::Result<()> {
    let report = build_report(ctx);
    serde_json::to_writer_pretty(&mut *writer, &report)?;
    writeln!(writer)?;
    Ok(())
}

fn build_report(ctx: &OutputContext) -> SarifReport {
    SarifReport {
        schema: SARIF_SCHEMA,
        version: SARIF_VERSION,
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: TOOL_NAME,
                    information_uri: TOOL_URI,
                    rules: build_rules(ctx.findings, ctx.patterns),
                },
            },
            results: ctx.findings.iter().map(|f| convert_result(f, ctx.patterns)).collect(),
        }],
    }
}

fn build_rules(findings: &[HistoryFinding], patterns: &[Pattern]) -> Vec<SarifRule> {
    patterns
        .iter()
        .filter(|p| findings.iter().any(|f| f.finding.pattern_id.as_ref() == p.id.as_ref()))
        .map(convert_rule)
        .collect()
}

fn convert_rule(pattern: &Pattern) -> SarifRule {
    SarifRule {
        id: pattern.id.to_string(),
        name: pattern.name.to_string(),
        short_description: SarifMessage {
            text: pattern.name.to_string(),
        },
        full_description: SarifMessage {
            text: pattern.description.to_string(),
        },
        default_configuration: SarifRuleConfig {
            level: severity_to_level(pattern.severity),
        },
        properties: SarifRuleProperties {
            severity: pattern.severity.to_string().to_lowercase(),
        },
    }
}

fn convert_result(finding: &HistoryFinding, patterns: &[Pattern]) -> SarifResult {
    let pattern_name = patterns
        .iter()
        .find(|p| p.id.as_ref() == finding.finding.pattern_id.as_ref())
        .map_or(finding.finding.pattern_id.as_ref(), |p| p.name.as_ref());

    SarifResult {
        rule_id: finding.finding.pattern_id.to_string(),
        level: severity_to_level(finding.finding.severity),
        message: SarifMessage {
            text: format!("{pattern_name} detected in git history"),
        },
        locations: vec![SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation {
                    uri: finding.introduced_in.path.display().to_string(),
                },
                region: SarifRegion {
                    start_line: finding.introduced_in.line,
                    start_column: finding.introduced_in.column,
                },
            },
        }],
        fingerprints: SarifFingerprints {
            secret_v1: finding.finding.id.to_string(),
        },
        properties: SarifResultProperties {
            scan_type: "history",
            commit: SarifCommitInfo {
                hash: finding.introduced_in.commit.hash.clone(),
                short_hash: finding.introduced_in.commit.short_hash.clone(),
                date: finding.introduced_in.commit.date.to_rfc3339(),
                author: finding.introduced_in.commit.author_email.clone(),
                message: finding.introduced_in.commit.message.clone(),
            },
            occurrence_count: finding.occurrence_count,
        },
    }
}

fn severity_to_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}
