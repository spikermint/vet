//! Pattern definitions and registry for secret detection.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use aho_corasick::AhoCorasick;
use regex::Regex;

use crate::error::PatternError;

pub use vet_providers::{DetectionStrategy, Group, Severity};

/// A compiled secret detection pattern ready for scanning.
///
/// Each pattern combines a regular expression with metadata used for
/// reporting (severity, description) and performance optimisation (keywords
/// for Aho-Corasick pre-filtering, entropy thresholds).
#[derive(Debug, Clone)]
pub struct Pattern {
    /// Unique identifier in `"group/name"` format (e.g. `"aws/access-key"`).
    pub id: Arc<str>,
    /// Provider group this pattern belongs to.
    pub group: Group,
    /// Short human-readable name shown in diagnostics.
    pub name: Box<str>,
    /// Longer description of what the pattern detects.
    pub description: Box<str>,
    /// Severity assigned to findings from this pattern.
    pub severity: Severity,
    /// Compiled regular expression that matches the secret.
    pub regex: Regex,
    /// Case-insensitive keywords for Aho-Corasick pre-filtering. If non-empty,
    /// the pattern is only tested against content that contains at least one keyword.
    pub keywords: Box<[Box<str>]>,
    /// Whether the pattern is active by default. Disabled patterns must be
    /// explicitly opted in via configuration.
    pub default_enabled: bool,
    /// Minimum Shannon entropy for a match to be classified as high confidence.
    /// When `None`, all matches are treated as high confidence.
    pub min_entropy: Option<f64>,
    /// How this pattern detects secrets (regex or AST-based).
    pub strategy: DetectionStrategy,
}

impl Pattern {
    fn from_def(def: &vet_providers::PatternDef) -> Result<Self, PatternError> {
        let regex = Regex::new(def.regex).map_err(|source| PatternError::InvalidRegex {
            id: def.id.to_string(),
            source,
        })?;

        Ok(Self {
            id: Arc::from(def.id),
            group: def.group,
            name: def.name.into(),
            description: def.description.into(),
            severity: def.severity,
            regex,
            keywords: def.keywords.iter().map(|&k| k.into()).collect(),
            default_enabled: def.default_enabled,
            min_entropy: def.min_entropy,
            strategy: def.strategy,
        })
    }

    /// Returns the remediation guidance for this pattern's provider group.
    #[must_use]
    pub fn remediation(&self) -> &'static str {
        self.group.remediation()
    }
}

/// Indexed collection of `Pattern`s with Aho-Corasick pre-filtering.
///
/// The registry builds a keyword automaton at construction time so that the
/// scanner can cheaply determine which patterns to evaluate for a given
/// piece of content.
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
    /// Creates a registry containing all built-in provider patterns.
    pub fn builtin() -> Result<Self, PatternError> {
        let provider_registry = vet_providers::ProviderRegistry::builtin();
        let patterns = provider_registry
            .all_patterns()
            .map(Pattern::from_def)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::new(patterns))
    }

    /// Creates a registry from a list of patterns, building the keyword index.
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

    /// Consumes the registry and returns the underlying pattern list.
    #[must_use]
    pub fn into_patterns(self) -> Vec<Pattern> {
        self.patterns
    }

    /// Returns all patterns as a slice.
    #[must_use]
    pub fn patterns(&self) -> &[Pattern] {
        &self.patterns
    }

    /// Returns an iterator over patterns that are enabled by default.
    pub fn enabled_patterns(&self) -> impl Iterator<Item = &Pattern> {
        self.patterns.iter().filter(|p| p.default_enabled)
    }

    /// Looks up a pattern by its ID string (e.g. `"aws/access-key"`).
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Pattern> {
        self.patterns.iter().find(|p| p.id.as_ref() == id)
    }

    /// Looks up a pattern by its positional index in the registry.
    #[must_use]
    pub fn get_by_index(&self, idx: usize) -> Option<&Pattern> {
        self.patterns.get(idx)
    }

    /// Returns the total number of patterns (both enabled and disabled).
    #[must_use]
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    /// Returns `true` if the registry contains no patterns.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Returns the Aho-Corasick automaton built from pattern keywords, if any
    /// keywords were registered.
    #[must_use]
    pub(crate) fn keyword_automaton(&self) -> Option<&AhoCorasick> {
        self.keyword_automaton.as_ref()
    }

    /// Maps each keyword index to the pattern indices that declared it.
    #[must_use]
    pub(crate) fn keyword_to_patterns(&self) -> &[Vec<usize>] {
        &self.keyword_to_patterns
    }

    /// Returns indices of patterns that have no keywords and must be tested
    /// against all content unconditionally.
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
    fn builtin_loads_more_than_40_patterns() {
        let registry = PatternRegistry::builtin().unwrap();
        assert!(registry.len() > 40);
    }

    #[test]
    fn builtin_patterns_all_have_id_name_description() {
        let registry = PatternRegistry::builtin().unwrap();
        for pattern in registry.patterns() {
            assert!(!pattern.id.is_empty());
            assert!(!pattern.name.is_empty());
            assert!(!pattern.description.is_empty());
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
        let debug = format!("{registry:?}");
        assert!(debug.contains("PatternRegistry"));
        assert!(debug.contains("patterns"));
    }

    #[test]
    fn pattern_remediation_returns_group_remediation() {
        let registry = PatternRegistry::builtin().unwrap();
        let pattern = registry.get("vcs/github-pat").unwrap();
        assert!(!pattern.remediation().is_empty());
    }
}
