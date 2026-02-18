//! Test utilities for `vet_core` (compiled only during testing).

use std::path::Path;

use regex::Regex;

use crate::finding::{Confidence, Finding, FindingId, Secret, Span};
use crate::pattern::{DetectionStrategy, Group, Pattern, Severity};

fn base_pattern(id: &str, regex: &str) -> Pattern {
    Pattern {
        id: id.into(),
        group: Group::Auth,
        name: "Test Pattern".into(),
        description: "Test".into(),
        severity: Severity::High,
        regex: Regex::new(regex).unwrap(),
        keywords: vec![].into(),
        default_enabled: true,
        min_entropy: None,
        strategy: DetectionStrategy::Regex,
    }
}

pub fn make_pattern(id: &str, regex: &str, keywords: &[&str]) -> Pattern {
    Pattern {
        keywords: keywords.iter().map(|&s| s.into()).collect(),
        ..base_pattern(id, regex)
    }
}

pub fn make_pattern_with_entropy(id: &str, regex: &str, min_entropy: f64) -> Pattern {
    Pattern {
        min_entropy: Some(min_entropy),
        ..base_pattern(id, regex)
    }
}

pub fn make_pattern_with_severity(id: &str, regex: &str, severity: Severity) -> Pattern {
    Pattern {
        severity,
        ..base_pattern(id, regex)
    }
}

pub fn make_finding(pattern_id: &str, secret_value: &str) -> Finding {
    let secret = Secret::new(secret_value);
    Finding {
        id: FindingId::new(pattern_id, &secret),
        path: Path::new("test.txt").into(),
        span: Span::new(1, 1, 0, 10),
        pattern_id: pattern_id.into(),
        secret,
        severity: Severity::High,
        masked_line: "masked content".into(),
        confidence: Confidence::High,
    }
}
