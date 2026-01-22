use std::collections::HashMap;

use regex::Regex;
use serde::Deserialize;

use super::{Pattern, Severity};
use crate::error::PatternError;

const PATTERNS_TOML: &str = include_str!("patterns.toml");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PatternsFile {
    #[serde(default)]
    groups: HashMap<String, GroupDef>,
    patterns: Vec<PatternDef>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupDef {
    #[serde(rename = "name")]
    _name: String,
    remediation: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PatternDef {
    id: String,
    group: String,
    name: String,
    description: String,
    remediation: Option<String>,
    severity: Severity,
    regex: String,
    keywords: Vec<String>,
    default_enabled: bool,
    min_entropy: Option<f64>,
}

impl PatternDef {
    fn compile(self, groups: &HashMap<String, GroupDef>) -> Result<Pattern, PatternError> {
        let regex = self.compile_regex()?;

        let remediation = self
            .remediation
            .or_else(|| groups.get(&self.group).map(|g| g.remediation.clone()));

        Ok(Pattern {
            id: self.id.into(),
            group: self.group.into(),
            name: self.name.into(),
            description: self.description.into(),
            remediation: remediation.map(Into::into),
            severity: self.severity,
            regex,
            keywords: self.keywords.into_iter().map(Into::into).collect(),
            default_enabled: self.default_enabled,
            min_entropy: self.min_entropy,
        })
    }

    fn compile_regex(&self) -> Result<Regex, PatternError> {
        Regex::new(&self.regex).map_err(|source| PatternError::InvalidRegex {
            id: self.id.clone(),
            source,
        })
    }
}

pub fn load_builtin_patterns() -> Result<Vec<Pattern>, PatternError> {
    let file: PatternsFile = parse_patterns_file();
    file.patterns.into_iter().map(|p| p.compile(&file.groups)).collect()
}

/// Parses the embedded patterns file.
///
/// # Panics
///
/// Panics if the embedded `patterns.toml` is malformed. This is caught
/// at compile time by tests, so panics indicate a build/packaging error.
#[allow(clippy::expect_used)]
fn parse_patterns_file() -> PatternsFile {
    toml::from_str(PATTERNS_TOML).expect("embedded patterns.toml is invalid")
}
