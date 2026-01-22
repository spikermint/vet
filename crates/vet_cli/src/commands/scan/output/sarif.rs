use std::io::Write;

use serde::Serialize;
use vet_core::prelude::*;

const SARIF_VERSION: &str = "2.1.0";
const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const TOOL_NAME: &str = "vet";

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
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRule {
    id: String,
    name: String,
    short_description: SarifMessage,
    default_configuration: SarifRuleConfig,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRuleConfig {
    level: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: String,
    level: &'static str,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
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

pub fn write(findings: &[Finding], patterns: &[Pattern], writer: &mut dyn Write) -> anyhow::Result<()> {
    let rules = build_rules(patterns);
    let results = build_results(findings);

    let report = SarifReport {
        schema: SARIF_SCHEMA,
        version: SARIF_VERSION,
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver { name: TOOL_NAME, rules },
            },
            results,
        }],
    };

    serde_json::to_writer_pretty(&mut *writer, &report)?;
    writeln!(writer)?;
    Ok(())
}

fn build_rules(patterns: &[Pattern]) -> Vec<SarifRule> {
    patterns
        .iter()
        .map(|p| SarifRule {
            id: p.id.to_string(),
            name: p.name.to_string(),
            short_description: SarifMessage {
                text: p.description.to_string(),
            },
            default_configuration: SarifRuleConfig {
                level: severity_to_level(p.severity),
            },
        })
        .collect()
}

fn build_results(findings: &[Finding]) -> Vec<SarifResult> {
    findings
        .iter()
        .map(|f| SarifResult {
            rule_id: f.pattern_id.to_string(),
            level: severity_to_level(f.severity),
            message: SarifMessage {
                text: format!("Potential secret detected: {}", f.pattern_id),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: f.path.display().to_string(),
                    },
                    region: SarifRegion {
                        start_line: f.span.line,
                        start_column: f.span.column,
                    },
                },
            }],
        })
        .collect()
}

const fn severity_to_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}
