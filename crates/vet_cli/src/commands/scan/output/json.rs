use std::io::Write;

use serde::Serialize;
use vet_core::prelude::*;

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
}

impl From<&Finding> for JsonFinding {
    fn from(f: &Finding) -> Self {
        Self {
            id: f.id.to_string(),
            path: f.path.display().to_string(),
            line: f.span.line,
            column: f.span.column,
            pattern_id: f.pattern_id.to_string(),
            severity: f.severity.to_string(),
            confidence: f.confidence.to_string(),
            secret_masked: f.secret.as_masked().to_string(),
        }
    }
}

pub fn write(findings: &[Finding], writer: &mut dyn Write) -> anyhow::Result<()> {
    let json_findings: Vec<JsonFinding> = findings.iter().map(JsonFinding::from).collect();
    serde_json::to_writer_pretty(&mut *writer, &json_findings)?;
    writeln!(writer)?;
    Ok(())
}
