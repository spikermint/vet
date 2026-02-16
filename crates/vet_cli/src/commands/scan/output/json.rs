//! JSON output formatter for scan findings.

use std::io::Write;

use serde::Serialize;
use vet_core::prelude::*;

use super::VerificationMap;

#[derive(Serialize)]
struct JsonFinding {
    id: String,
    path: String,
    line: u32,
    column: u32,
    pattern_id: String,
    severity: String,
    confidence: String,
    secret_masked: String,
    fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    verification: Option<JsonVerification>,
}

#[derive(Serialize)]
struct JsonVerification {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_at: Option<String>,
}

fn to_json_finding(f: &Finding, verifications: Option<&VerificationMap>) -> JsonFinding {
    let verification = verifications
        .and_then(|v| v.get(f.id.as_str()))
        .map(|v| JsonVerification {
            status: v.status.to_string(),
            provider: v
                .service
                .as_ref()
                .and_then(|s| s.provider.as_ref().map(ToString::to_string)),
            details: v.service.as_ref().map(|s| s.details.to_string()),
            verified_at: Some(v.verified_at.to_string()),
        });

    JsonFinding {
        id: f.id.to_string(),
        path: f.path.display().to_string(),
        line: f.span.line,
        column: f.span.column,
        pattern_id: f.pattern_id.to_string(),
        severity: f.severity.to_string(),
        confidence: f.confidence.to_string(),
        secret_masked: f.secret.as_masked().to_string(),
        fingerprint: f.baseline_fingerprint().as_str().to_string(),
        verification,
    }
}

/// Serialises scan findings as a pretty-printed JSON array to the given writer.
pub fn write(
    findings: &[Finding],
    verifications: Option<&VerificationMap>,
    writer: &mut dyn Write,
) -> anyhow::Result<()> {
    let json_findings: Vec<JsonFinding> = findings.iter().map(|f| to_json_finding(f, verifications)).collect();
    serde_json::to_writer_pretty(&mut *writer, &json_findings)?;
    writeln!(writer)?;
    Ok(())
}
