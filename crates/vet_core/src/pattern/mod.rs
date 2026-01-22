//! Pattern definitions and registry for secret detection.

mod builtin;

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use aho_corasick::AhoCorasick;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::error::PatternError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const ALL: [Self; 4] = [Self::Low, Self::Medium, Self::High, Self::Critical];
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        write!(f, "{s}")
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(format!("invalid severity: {s}")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Pattern {
    pub id: Box<str>,
    pub group: Box<str>,
    pub name: Box<str>,
    pub description: Box<str>,
    pub remediation: Option<Box<str>>,
    pub severity: Severity,
    pub regex: Regex,
    pub keywords: Box<[Box<str>]>,
    pub default_enabled: bool,
    pub min_entropy: Option<f64>,
}

pub struct PatternRegistry {
    patterns: Vec<Pattern>,
    keyword_automaton: Option<AhoCorasick>,
    keyword_to_patterns: Vec<Vec<usize>>,
    patterns_without_keywords: Vec<usize>,
}

impl fmt::Debug for PatternRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PatternRegistry")
            .field("patterns", &self.patterns.len())
            .field("patterns_without_keywords", &self.patterns_without_keywords.len())
            .finish_non_exhaustive()
    }
}

impl PatternRegistry {
    pub fn builtin() -> Result<Self, PatternError> {
        let patterns = builtin::load_builtin_patterns()?;
        Ok(Self::new(patterns))
    }

    #[must_use]
    pub fn new(patterns: Vec<Pattern>) -> Self {
        let keyword_index = build_keyword_index(&patterns);
        let keyword_automaton = build_automaton(&keyword_index.keywords);

        Self {
            patterns,
            keyword_automaton,
            keyword_to_patterns: keyword_index.keyword_to_patterns,
            patterns_without_keywords: keyword_index.patterns_without_keywords,
        }
    }

    #[must_use]
    pub fn into_patterns(self) -> Vec<Pattern> {
        self.patterns
    }

    #[must_use]
    pub fn patterns(&self) -> &[Pattern] {
        &self.patterns
    }

    pub fn enabled_patterns(&self) -> impl Iterator<Item = &Pattern> {
        self.patterns.iter().filter(|p| p.default_enabled)
    }

    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Pattern> {
        self.patterns.iter().find(|p| p.id.as_ref() == id)
    }

    #[must_use]
    pub fn get_by_index(&self, idx: usize) -> Option<&Pattern> {
        self.patterns.get(idx)
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.patterns.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    #[must_use]
    pub(crate) const fn keyword_automaton(&self) -> Option<&AhoCorasick> {
        self.keyword_automaton.as_ref()
    }

    #[must_use]
    pub(crate) fn keyword_to_patterns(&self) -> &[Vec<usize>] {
        &self.keyword_to_patterns
    }

    #[must_use]
    pub(crate) fn patterns_without_keywords(&self) -> &[usize] {
        &self.patterns_without_keywords
    }
}

struct KeywordIndex {
    keywords: Vec<String>,
    keyword_to_patterns: Vec<Vec<usize>>,
    patterns_without_keywords: Vec<usize>,
}

fn build_keyword_index(patterns: &[Pattern]) -> KeywordIndex {
    let mut keywords = Vec::new();
    let mut keyword_to_patterns = Vec::new();
    let mut patterns_without_keywords = Vec::new();
    let mut keyword_positions: HashMap<String, usize> = HashMap::new();

    for (pattern_idx, pattern) in patterns.iter().enumerate() {
        if !pattern.default_enabled {
            continue;
        }

        if pattern.keywords.is_empty() {
            patterns_without_keywords.push(pattern_idx);
        } else {
            index_pattern_keywords(
                pattern_idx,
                pattern,
                &mut keywords,
                &mut keyword_to_patterns,
                &mut keyword_positions,
            );
        }
    }

    KeywordIndex {
        keywords,
        keyword_to_patterns,
        patterns_without_keywords,
    }
}

fn index_pattern_keywords(
    pattern_idx: usize,
    pattern: &Pattern,
    keywords: &mut Vec<String>,
    keyword_to_patterns: &mut Vec<Vec<usize>>,
    keyword_positions: &mut HashMap<String, usize>,
) {
    for keyword in &pattern.keywords {
        let keyword_str = keyword.to_string();

        if let Some(&existing_idx) = keyword_positions.get(&keyword_str) {
            keyword_to_patterns[existing_idx].push(pattern_idx);
        } else {
            let new_idx = keywords.len();
            keyword_positions.insert(keyword_str.clone(), new_idx);
            keywords.push(keyword_str);
            keyword_to_patterns.push(vec![pattern_idx]);
        }
    }
}

fn build_automaton(keywords: &[String]) -> Option<AhoCorasick> {
    if keywords.is_empty() {
        return None;
    }

    AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .match_kind(aho_corasick::MatchKind::LeftmostLongest)
        .build(keywords)
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::make_pattern;

    const TEST_REGEX: &str = r"TEST_[A-Z]{8}";

    #[test]
    fn severity_orders_low_medium_high_critical() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn severity_display_formats_as_lowercase_string() {
        assert_eq!(format!("{}", Severity::Low), "low");
        assert_eq!(format!("{}", Severity::Medium), "medium");
        assert_eq!(format!("{}", Severity::High), "high");
        assert_eq!(format!("{}", Severity::Critical), "critical");
    }

    #[test]
    fn severity_from_str_parses_lowercase_values() {
        assert_eq!(Severity::from_str("low"), Ok(Severity::Low));
        assert_eq!(Severity::from_str("medium"), Ok(Severity::Medium));
        assert_eq!(Severity::from_str("high"), Ok(Severity::High));
        assert_eq!(Severity::from_str("critical"), Ok(Severity::Critical));
    }

    #[test]
    fn severity_from_str_is_case_insensitive() {
        assert_eq!(Severity::from_str("LOW"), Ok(Severity::Low));
        assert_eq!(Severity::from_str("High"), Ok(Severity::High));
        assert_eq!(Severity::from_str("CRITICAL"), Ok(Severity::Critical));
    }

    #[test]
    fn severity_from_str_rejects_unknown_values() {
        assert!(Severity::from_str("extreme").is_err());
        assert!(Severity::from_str("").is_err());
        assert!(Severity::from_str("hi").is_err());
    }

    #[test]
    fn severity_all_contains_all_four_variants() {
        assert_eq!(Severity::ALL.len(), 4);
        assert!(Severity::ALL.contains(&Severity::Low));
        assert!(Severity::ALL.contains(&Severity::Critical));
    }

    #[test]
    fn builtin_loads_more_than_40_patterns() {
        let registry = PatternRegistry::builtin().unwrap();
        assert!(registry.len() > 40);
    }

    #[test]
    fn builtin_patterns_all_have_id_name_description_group() {
        let registry = PatternRegistry::builtin().unwrap();
        for pattern in registry.patterns() {
            assert!(!pattern.id.is_empty());
            assert!(!pattern.name.is_empty());
            assert!(!pattern.description.is_empty());
            assert!(!pattern.group.is_empty());
        }
    }

    #[test]
    fn registry_new_with_empty_vec_is_empty() {
        let registry = PatternRegistry::new(vec![]);
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn registry_len_and_is_empty_reflect_pattern_count() {
        let pattern = make_pattern("test/one", TEST_REGEX, &["keyword"]);
        let registry = PatternRegistry::new(vec![pattern]);
        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn registry_get_finds_pattern_by_exact_id() {
        let registry = PatternRegistry::builtin().unwrap();
        let pattern = registry.get("vcs/github-pat");
        assert!(pattern.is_some());
        assert_eq!(pattern.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn registry_get_returns_none_for_unknown_id() {
        let registry = PatternRegistry::builtin().unwrap();
        assert!(registry.get("nonexistent/pattern").is_none());
    }

    #[test]
    fn registry_get_by_index_returns_patterns_in_order() {
        let p1 = make_pattern("test/first", TEST_REGEX, &[]);
        let p2 = make_pattern("test/second", TEST_REGEX, &[]);
        let registry = PatternRegistry::new(vec![p1, p2]);

        assert_eq!(registry.get_by_index(0).unwrap().id.as_ref(), "test/first");
        assert_eq!(registry.get_by_index(1).unwrap().id.as_ref(), "test/second");
    }

    #[test]
    fn registry_patterns_returns_all_patterns_as_slice() {
        let p1 = make_pattern("test/a", TEST_REGEX, &[]);
        let p2 = make_pattern("test/b", TEST_REGEX, &[]);
        let registry = PatternRegistry::new(vec![p1, p2]);

        let patterns = registry.patterns();
        assert_eq!(patterns.len(), 2);
    }

    #[test]
    fn registry_into_patterns_consumes_and_returns_vec() {
        let p1 = make_pattern("test/a", TEST_REGEX, &[]);
        let registry = PatternRegistry::new(vec![p1]);

        let patterns = registry.into_patterns();
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].id.as_ref(), "test/a");
    }

    #[test]
    fn registry_enabled_patterns_excludes_disabled_patterns() {
        let mut enabled = make_pattern("test/enabled", TEST_REGEX, &[]);
        enabled.default_enabled = true;

        let mut disabled = make_pattern("test/disabled", TEST_REGEX, &[]);
        disabled.default_enabled = false;

        let registry = PatternRegistry::new(vec![enabled, disabled]);
        let enabled_patterns: Vec<_> = registry.enabled_patterns().collect();

        assert_eq!(enabled_patterns.len(), 1);
        assert_eq!(enabled_patterns[0].id.as_ref(), "test/enabled");
    }

    #[test]
    fn registry_builds_keyword_automaton_for_patterns_with_keywords() {
        let p1 = make_pattern("test/with-kw", TEST_REGEX, &["ghp_", "github"]);
        let p2 = make_pattern("test/no-kw", TEST_REGEX, &[]);
        let registry = PatternRegistry::new(vec![p1, p2]);

        assert!(registry.keyword_automaton().is_some());
        assert_eq!(registry.patterns_without_keywords().len(), 1);
    }

    #[test]
    fn registry_tracks_patterns_without_keywords_separately() {
        let p1 = make_pattern("test/no-kw-1", TEST_REGEX, &[]);
        let p2 = make_pattern("test/no-kw-2", TEST_REGEX, &[]);
        let registry = PatternRegistry::new(vec![p1, p2]);

        assert!(registry.keyword_automaton().is_none());
        assert_eq!(registry.patterns_without_keywords().len(), 2);
    }

    #[test]
    fn registry_maps_shared_keywords_to_multiple_patterns() {
        let p1 = make_pattern("test/github", TEST_REGEX, &["ghp_"]);
        let p2 = make_pattern("test/also-github", TEST_REGEX, &["ghp_"]);
        let registry = PatternRegistry::new(vec![p1, p2]);

        let mapping = registry.keyword_to_patterns();
        assert_eq!(mapping.len(), 1);
        assert_eq!(mapping[0].len(), 2);
    }

    #[test]
    fn registry_excludes_disabled_patterns_from_keyword_index() {
        let mut disabled = make_pattern("test/disabled", TEST_REGEX, &["secret_"]);
        disabled.default_enabled = false;

        let registry = PatternRegistry::new(vec![disabled]);

        assert!(registry.keyword_automaton().is_none());
        assert!(registry.patterns_without_keywords().is_empty());
    }

    #[test]
    fn registry_debug_impl_shows_pattern_count() {
        let registry = PatternRegistry::new(vec![]);
        let debug = format!("{:?}", registry);
        assert!(debug.contains("PatternRegistry"));
        assert!(debug.contains("patterns"));
    }
}
