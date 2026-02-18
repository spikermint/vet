//! Secret scanning engine.

use std::path::Path;
use std::sync::Arc;

#[cfg(feature = "tracing")]
use tracing::{debug, trace};

use crate::binary::is_binary_content;
use crate::comment_syntax::IGNORE_MARKER;
use crate::entropy::shannon_entropy;
use crate::finding::{Confidence, Finding, FindingId, Secret, Span};
use crate::pattern::{DetectionStrategy, Group, Pattern, PatternRegistry, Severity};
use crate::text::{find_line_end, find_line_start};

/// Secret scanning engine that matches file content against a `PatternRegistry`.
///
/// The scanner uses Aho-Corasick keyword pre-filtering to skip patterns whose
/// keywords are absent from the content, then runs full regex matching only on
/// the patterns that could plausibly match. Binary files are detected and
/// skipped automatically.
pub struct Scanner {
    registry: PatternRegistry,
    severity_threshold: Option<Severity>,
}

impl std::fmt::Debug for Scanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scanner")
            .field("patterns", &self.registry.len())
            .finish_non_exhaustive()
    }
}

impl Scanner {
    /// Creates a scanner with no severity threshold (all severities reported).
    #[must_use]
    pub const fn new(registry: PatternRegistry) -> Self {
        Self {
            registry,
            severity_threshold: None,
        }
    }

    /// Sets a minimum severity threshold. Patterns below this level are skipped.
    #[must_use]
    pub const fn with_severity_threshold(mut self, severity: Severity) -> Self {
        self.severity_threshold = Some(severity);
        self
    }

    /// Returns the total number of patterns in the registry.
    #[must_use]
    pub fn pattern_count(&self) -> usize {
        self.registry.len()
    }

    /// Looks up a pattern by its ID string.
    #[must_use]
    pub fn get_pattern(&self, id: &str) -> Option<&Pattern> {
        self.registry.get(id)
    }

    /// Scans `content` for secrets and returns all findings.
    ///
    /// Binary content is detected and skipped. Lines containing a
    /// `vet:ignore` marker are excluded from results. When a secret matches
    /// both a generic and a service-specific pattern, only the specific
    /// finding is kept.
    #[must_use]
    pub fn scan_content(&self, content: &str, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        self.scan_content_into(content, path, &mut findings);
        dedup_generic_findings(&mut findings);
        findings
    }

    /// Scans `content` for secrets, appending results to an existing vector.
    ///
    /// This is useful when scanning multiple files into a shared collection
    /// without re-allocating on each call.
    pub fn scan_content_into(&self, content: &str, path: &Path, findings: &mut Vec<Finding>) {
        if is_binary_content(content) {
            #[cfg(feature = "tracing")]
            debug!("skipping binary file");
            return;
        }

        let patterns_to_check = self.select_patterns_to_run(content);

        #[cfg(feature = "tracing")]
        {
            let active_count = patterns_to_check.iter().filter(|&&b| b).count();
            trace!(patterns_checked = active_count, size = content.len(), "scanning");
        }

        self.run_patterns_into(content, path, &patterns_to_check, findings);

        self.run_ast_patterns_into(content, path, &patterns_to_check, findings);
    }

    fn select_patterns_to_run(&self, content: &str) -> Vec<bool> {
        let mut should_run = vec![false; self.registry.len()];

        for &idx in self.registry.patterns_without_keywords() {
            should_run[idx] = true;
        }

        if let Some(automaton) = self.registry.keyword_automaton() {
            for mat in automaton.find_iter(content) {
                let keyword_idx = mat.pattern().as_usize();
                for &pattern_idx in &self.registry.keyword_to_patterns()[keyword_idx] {
                    should_run[pattern_idx] = true;
                }
            }
        }

        should_run
    }

    fn run_patterns_into(&self, content: &str, path: &Path, patterns_to_check: &[bool], findings: &mut Vec<Finding>) {
        for (idx, &should_check) in patterns_to_check.iter().enumerate() {
            if !should_check {
                continue;
            }

            let Some(pattern) = self.registry.get_by_index(idx) else {
                continue;
            };

            if !self.should_run_pattern(pattern) {
                continue;
            }

            if pattern.strategy == DetectionStrategy::AstAssignment {
                continue;
            }

            scan_with_pattern_into(content, path, pattern, findings);
        }
    }

    /// Runs AST-based patterns whose keywords were triggered.
    ///
    /// Collects all active `AstAssignment` patterns, builds trigger word groups,
    /// and dispatches to the AST module for extraction.
    fn run_ast_patterns_into(
        &self,
        content: &str,
        path: &Path,
        patterns_to_check: &[bool],
        findings: &mut Vec<Finding>,
    ) {
        use crate::ast;
        use crate::ast::trigger::TriggerWordGroup;

        let mut trigger_groups: Vec<(TriggerWordGroup, usize)> = Vec::new();

        for (idx, &should_check) in patterns_to_check.iter().enumerate() {
            if !should_check {
                continue;
            }

            let Some(pattern) = self.registry.get_by_index(idx) else {
                continue;
            };

            if !self.should_run_pattern(pattern) {
                continue;
            }

            if pattern.strategy != DetectionStrategy::AstAssignment {
                continue;
            }

            let group = TriggerWordGroup {
                pattern_id: Arc::clone(&pattern.id),
                words: pattern.keywords.clone(),
            };

            trigger_groups.push((group, idx));
        }

        if trigger_groups.is_empty() {
            return;
        }

        let groups: Vec<TriggerWordGroup> = trigger_groups.iter().map(|(g, _)| g.clone()).collect();
        let ast_findings = ast::extract_generic_findings(content.as_bytes(), path, &groups);

        for ast_finding in ast_findings {
            if is_line_ignored(content, ast_finding.byte_start) {
                continue;
            }

            let confidence = determine_confidence(&ast_finding.secret_value, Some(4.0));

            let Some(matching_pattern) = trigger_groups
                .iter()
                .find(|(g, _)| g.pattern_id == ast_finding.pattern_id)
                .and_then(|(_, idx)| self.registry.get_by_index(*idx))
            else {
                continue;
            };

            let finding = create_finding(
                content,
                path,
                matching_pattern,
                ast_finding.byte_start,
                ast_finding.byte_end,
                confidence,
            );

            #[cfg(feature = "tracing")]
            trace!(
                pattern_id = %matching_pattern.id,
                variable = %ast_finding.variable_name,
                line = finding.span.line,
                "ast match"
            );

            findings.push(finding);
        }
    }

    fn should_run_pattern(&self, pattern: &Pattern) -> bool {
        if !pattern.default_enabled {
            return false;
        }

        if let Some(threshold) = self.severity_threshold
            && pattern.severity < threshold
        {
            return false;
        }

        true
    }
}

fn scan_with_pattern_into(content: &str, path: &Path, pattern: &Pattern, findings: &mut Vec<Finding>) {
    for mat in pattern.regex.find_iter(content) {
        if is_line_ignored(content, mat.start()) {
            continue;
        }

        let matched_text = &content[mat.start()..mat.end()];
        let confidence = determine_confidence(matched_text, pattern.min_entropy);
        let finding = create_finding(content, path, pattern, mat.start(), mat.end(), confidence);

        #[cfg(feature = "tracing")]
        trace!(pattern_id = %pattern.id, line = finding.span.line, "match");

        findings.push(finding);
    }
}

fn determine_confidence(matched_text: &str, min_entropy: Option<f64>) -> Confidence {
    match min_entropy {
        Some(threshold) if shannon_entropy(matched_text) >= threshold => Confidence::High,
        Some(_) => Confidence::Low,
        None => Confidence::High,
    }
}

fn create_finding(
    content: &str,
    path: &Path,
    pattern: &Pattern,
    byte_start: usize,
    byte_end: usize,
    confidence: Confidence,
) -> Finding {
    let matched_text = &content[byte_start..byte_end];
    let secret = Secret::new(matched_text);
    // Regex match indices are always valid UTF-8 boundaries because
    // the regex crate operates on valid &str and returns character-aligned offsets.
    #[expect(
        clippy::expect_used,
        reason = "regex match indices are always valid UTF-8 boundaries"
    )]
    let span = Span::from_byte_range(content, byte_start, byte_end)
        .expect("regex match indices are always valid UTF-8 boundaries");
    let masked_line = mask_line(content, byte_start, byte_end, &secret);

    Finding {
        id: FindingId::new(&pattern.id, &secret),
        path: path.into(),
        span,
        pattern_id: Arc::clone(&pattern.id),
        secret,
        severity: pattern.severity,
        masked_line,
        confidence,
    }
}

fn mask_line(content: &str, byte_start: usize, byte_end: usize, secret: &Secret) -> Box<str> {
    let line_start = find_line_start(content, byte_start);
    let line_end = find_line_end(content, byte_start);
    let line = &content[line_start..line_end];

    let secret_offset = byte_start - line_start;
    let secret_len = byte_end - byte_start;
    let end_in_line = (secret_offset + secret_len).min(line.len());

    format!(
        "{}{}{}",
        &line[..secret_offset],
        secret.as_masked(),
        &line[end_in_line..]
    )
    .into()
}

fn is_line_ignored(content: &str, byte_offset: usize) -> bool {
    let line_start = find_line_start(content, byte_offset);
    let line_end = find_line_end(content, byte_offset);
    content[line_start..line_end].contains(IGNORE_MARKER)
}

fn ranges_overlap(a: &Span, b: &Span) -> bool {
    a.byte_start < b.byte_end && b.byte_start < a.byte_end
}

/// Removes generic findings that overlap with a more specific finding.
///
/// When a secret matches both a generic pattern (e.g. `generic/password-assignment`)
/// and a service-specific pattern (e.g. `payments/stripe-live-secret-key`), the
/// specific pattern provides better context and should take precedence.
pub fn dedup_generic_findings(findings: &mut Vec<Finding>) {
    if findings.len() < 2 {
        return;
    }

    let generic_prefix = Group::Generic.as_str();

    let has_generic = findings.iter().any(|f| f.pattern_id.starts_with(generic_prefix));
    if !has_generic {
        return;
    }

    let has_specific = findings.iter().any(|f| !f.pattern_id.starts_with(generic_prefix));
    if !has_specific {
        return;
    }

    let specific_spans: Vec<Span> = findings
        .iter()
        .filter(|f| !f.pattern_id.starts_with(generic_prefix))
        .map(|f| f.span)
        .collect();

    findings.retain(|f| {
        if !f.pattern_id.starts_with(generic_prefix) {
            return true;
        }
        !specific_spans.iter().any(|sp| ranges_overlap(&f.span, sp))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{make_finding, make_pattern, make_pattern_with_entropy, make_pattern_with_severity};

    fn scanner_with_patterns(patterns: Vec<Pattern>) -> Scanner {
        Scanner::new(PatternRegistry::new(patterns))
    }

    #[test]
    fn scan_content_detects_single_pattern_match() {
        let pattern = make_pattern("test/token", r"TOKEN_[A-Z]{8}", &[]);
        let scanner = scanner_with_patterns(vec![pattern]);

        let findings = scanner.scan_content("my TOKEN_ABCDEFGH here", Path::new("test.txt"));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pattern_id.as_ref(), "test/token");
    }

    #[test]
    fn scan_content_returns_empty_when_no_patterns_match() {
        let pattern = make_pattern("test/token", r"TOKEN_[A-Z]{8}", &[]);
        let scanner = scanner_with_patterns(vec![pattern]);

        let findings = scanner.scan_content("nothing here", Path::new("test.txt"));

        assert!(findings.is_empty());
    }

    #[test]
    fn scan_content_detects_multiple_matches_of_same_pattern() {
        let pattern = make_pattern("test/token", r"TOKEN_[A-Z]{8}", &[]);
        let scanner = scanner_with_patterns(vec![pattern]);

        let content = "first TOKEN_AAAAAAAA then TOKEN_BBBBBBBB";
        let findings = scanner.scan_content(content, Path::new("test.txt"));

        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn scan_content_detects_matches_from_different_patterns() {
        let p1 = make_pattern("test/token-a", r"TOKEN_A_[A-Z]{4}", &[]);
        let p2 = make_pattern("test/token-b", r"TOKEN_B_[A-Z]{4}", &[]);
        let scanner = scanner_with_patterns(vec![p1, p2]);

        let content = "has TOKEN_A_XXXX and TOKEN_B_YYYY";
        let findings = scanner.scan_content(content, Path::new("test.txt"));

        assert_eq!(findings.len(), 2);
        let ids: Vec<_> = findings.iter().map(|f| f.pattern_id.as_ref()).collect();
        assert!(ids.contains(&"test/token-a"));
        assert!(ids.contains(&"test/token-b"));
    }

    #[test]
    fn scan_content_skips_files_with_null_bytes() {
        let pattern = make_pattern("test/token", r"TOKEN_[A-Z]{8}", &[]);
        let scanner = scanner_with_patterns(vec![pattern]);

        let mut content = String::from("TOKEN_ABCDEFGH");
        content.push('\0');
        let findings = scanner.scan_content(&content, Path::new("test.bin"));

        assert!(findings.is_empty());
    }

    #[test]
    fn scan_content_only_checks_first_8000_bytes_for_binary() {
        let pattern = make_pattern("test/token", r"TOKEN_[A-Z]{8}", &[]);
        let scanner = scanner_with_patterns(vec![pattern]);

        let mut content = "TOKEN_ABCDEFGH".to_string();
        content.push_str(&" ".repeat(8000));
        content.push('\0');

        let findings = scanner.scan_content(&content, Path::new("test.txt"));

        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn scan_content_skips_lines_with_vet_ignore_comment() {
        let pattern = make_pattern("test/token", r"TOKEN_[A-Z]{8}", &[]);
        let scanner = scanner_with_patterns(vec![pattern]);

        let content = "secret = TOKEN_ABCDEFGH // vet:ignore";
        let findings = scanner.scan_content(content, Path::new("test.txt"));

        assert!(findings.is_empty());
    }

    #[test]
    fn scan_content_ignore_marker_does_not_affect_other_lines() {
        let pattern = make_pattern("test/token", r"TOKEN_[A-Z]{8}", &[]);
        let scanner = scanner_with_patterns(vec![pattern]);

        let content = "TOKEN_AAAAAAAA\nTOKEN_BBBBBBBB // vet:ignore\nTOKEN_CCCCCCCC";
        let findings = scanner.scan_content(content, Path::new("test.txt"));

        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn scan_content_ignore_marker_works_anywhere_on_line() {
        let pattern = make_pattern("test/token", r"TOKEN_[A-Z]{8}", &[]);
        let scanner = scanner_with_patterns(vec![pattern]);

        let findings = scanner.scan_content("vet:ignore TOKEN_ABCDEFGH", Path::new("test.txt"));
        assert!(findings.is_empty());

        let findings = scanner.scan_content("TOKEN_ABCDEFGH vet:ignore", Path::new("test.txt"));
        assert!(findings.is_empty());
    }

    #[test]
    fn with_severity_threshold_excludes_patterns_below_threshold() {
        let low = make_pattern_with_severity("test/low", r"LOW", Severity::Low);
        let high = make_pattern_with_severity("test/high", r"HIGH", Severity::High);
        let scanner = scanner_with_patterns(vec![low, high]).with_severity_threshold(Severity::High);

        let content = "LOW and HIGH";
        let findings = scanner.scan_content(content, Path::new("test.txt"));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pattern_id.as_ref(), "test/high");
    }

    #[test]
    fn with_severity_threshold_includes_patterns_at_threshold() {
        let med = make_pattern_with_severity("test/med", r"MEDIUM", Severity::Medium);
        let scanner = scanner_with_patterns(vec![med]).with_severity_threshold(Severity::Medium);

        let findings = scanner.scan_content("MEDIUM", Path::new("test.txt"));

        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn with_severity_threshold_includes_patterns_above_threshold() {
        let crit = make_pattern_with_severity("test/crit", r"CRITICAL", Severity::Critical);
        let scanner = scanner_with_patterns(vec![crit]).with_severity_threshold(Severity::Low);

        let findings = scanner.scan_content("CRITICAL", Path::new("test.txt"));

        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn scan_content_marks_high_entropy_as_high_confidence() {
        let pattern = make_pattern_with_entropy("test/key", r"KEY_[A-Za-z0-9]{20}", 3.5);
        let scanner = scanner_with_patterns(vec![pattern]);

        let content = "KEY_aBcDeFgHiJkLmNoPqRsT";
        let findings = scanner.scan_content(content, Path::new("test.txt"));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, Confidence::High);
    }

    #[test]
    fn scan_content_marks_low_entropy_as_low_confidence() {
        let pattern = make_pattern_with_entropy("test/key", r"KEY_[A-Z]{20}", 3.5);
        let scanner = scanner_with_patterns(vec![pattern]);

        let content = "KEY_XXXXXXXXXXXXXXXXXXXX";
        let findings = scanner.scan_content(content, Path::new("test.txt"));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, Confidence::Low);
    }

    #[test]
    fn scan_content_defaults_to_high_confidence_without_entropy_threshold() {
        let pattern = make_pattern("test/key", r"KEY_[A-Z]{8}", &[]);
        let scanner = scanner_with_patterns(vec![pattern]);

        let content = "KEY_XXXXXXXX";
        let findings = scanner.scan_content(content, Path::new("test.txt"));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, Confidence::High);
    }

    #[test]
    fn scan_content_skips_patterns_whose_keywords_are_absent() {
        let with_kw = make_pattern("test/with-kw", r"ghp_[a-z]{10}", &["ghp_"]);
        let no_kw = make_pattern("test/no-kw", r"SECRET_[A-Z]{4}", &[]);
        let scanner = scanner_with_patterns(vec![with_kw, no_kw]);

        let content = "has SECRET_XXXX but no github token";
        let findings = scanner.scan_content(content, Path::new("test.txt"));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pattern_id.as_ref(), "test/no-kw");
    }

    #[test]
    fn scan_content_runs_pattern_when_keyword_present() {
        let pattern = make_pattern("test/github", r"ghp_[a-z]{10}", &["ghp_"]);
        let scanner = scanner_with_patterns(vec![pattern]);

        let content = "token = ghp_abcdefghij";
        let findings = scanner.scan_content(content, Path::new("test.txt"));

        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn scan_content_finding_has_accurate_line_and_column() {
        let pattern = make_pattern("test/token", r"TOKEN", &[]);
        let scanner = scanner_with_patterns(vec![pattern]);

        let content = "line1\nkey = TOKEN\nline3";
        let findings = scanner.scan_content(content, Path::new("test.txt"));

        assert_eq!(findings[0].span.line, 2);
        assert_eq!(findings[0].span.column, 7);
    }

    #[test]
    fn scan_content_finding_preserves_file_path() {
        let pattern = make_pattern("test/token", r"TOKEN", &[]);
        let scanner = scanner_with_patterns(vec![pattern]);

        let findings = scanner.scan_content("TOKEN", Path::new("src/config.rs"));

        assert_eq!(findings[0].path.as_ref(), Path::new("src/config.rs"));
    }

    #[test]
    fn scan_content_finding_masks_secret_in_line_content() {
        let pattern = make_pattern("test/token", r"SECRET_[A-Z]{8}", &[]);
        let scanner = scanner_with_patterns(vec![pattern]);

        let content = "key = SECRET_ABCDEFGH";
        let findings = scanner.scan_content(content, Path::new("test.txt"));

        assert!(!findings[0].masked_line.contains("ABCDEFGH"));
        assert_eq!(findings[0].masked_line.as_ref(), "key = SE••••••••GH");
        assert!(findings[0].masked_line.contains("key = "));
    }

    #[test]
    fn pattern_count_reflects_registry_size() {
        let p1 = make_pattern("test/a", r"A", &[]);
        let p2 = make_pattern("test/b", r"B", &[]);
        let scanner = scanner_with_patterns(vec![p1, p2]);

        assert_eq!(scanner.pattern_count(), 2);
    }

    #[test]
    fn debug_impl_shows_scanner_with_pattern_count() {
        let scanner = scanner_with_patterns(vec![]);
        let debug = format!("{scanner:?}");
        assert!(debug.contains("Scanner"));
        assert!(debug.contains("patterns"));
    }

    #[test]
    fn scan_content_ignores_disabled_patterns() {
        let mut pattern = make_pattern("test/disabled", r"DISABLED", &[]);
        pattern.default_enabled = false;
        let scanner = scanner_with_patterns(vec![pattern]);

        let findings = scanner.scan_content("DISABLED", Path::new("test.txt"));

        assert!(findings.is_empty());
    }

    #[test]
    fn scan_content_returns_empty_for_empty_input() {
        let pattern = make_pattern("test/token", r"TOKEN", &[]);
        let scanner = scanner_with_patterns(vec![pattern]);

        let findings = scanner.scan_content("", Path::new("test.txt"));

        assert!(findings.is_empty());
    }

    #[test]
    fn builtin_patterns_detect_github_personal_access_token() {
        let registry = PatternRegistry::builtin().unwrap();
        let scanner = Scanner::new(registry);

        let content = "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890";
        let findings = scanner.scan_content(content, Path::new("env"));

        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.pattern_id.contains("github")));
    }

    #[test]
    fn builtin_patterns_detect_aws_access_key_id() {
        let registry = PatternRegistry::builtin().unwrap();
        let scanner = Scanner::new(registry);

        let content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let findings = scanner.scan_content(content, Path::new("env"));

        assert!(!findings.is_empty());
    }

    #[test]
    fn scan_content_into_appends_to_existing_vec() {
        let pattern = make_pattern("test/token", r"TOKEN_[A-Z]{4}", &[]);
        let scanner = scanner_with_patterns(vec![pattern]);

        let mut findings = Vec::new();

        scanner.scan_content_into("TOKEN_AAAA", Path::new("a.txt"), &mut findings);
        assert_eq!(findings.len(), 1);

        scanner.scan_content_into("TOKEN_BBBB", Path::new("b.txt"), &mut findings);
        assert_eq!(findings.len(), 2);

        scanner.scan_content_into("no match", Path::new("c.txt"), &mut findings);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn scan_content_into_preserves_existing_findings() {
        let pattern = make_pattern("test/token", r"TOKEN", &[]);
        let scanner = scanner_with_patterns(vec![pattern]);

        let mut findings = vec![make_finding("existing/pattern", "existing")];

        scanner.scan_content_into("has TOKEN here", Path::new("test.txt"), &mut findings);

        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].pattern_id.as_ref(), "existing/pattern");
        assert_eq!(findings[1].pattern_id.as_ref(), "test/token");
    }

    #[test]
    fn scan_content_into_skips_binary_without_modifying_vec() {
        let pattern = make_pattern("test/token", r"TOKEN", &[]);
        let scanner = scanner_with_patterns(vec![pattern]);

        let mut findings = Vec::new();
        scanner.scan_content_into("TOKEN\x00binary", Path::new("test.bin"), &mut findings);

        assert!(findings.is_empty());
    }

    #[test]
    fn scan_content_into_handles_multiple_patterns() {
        let p1 = make_pattern("test/a", r"AAA", &[]);
        let p2 = make_pattern("test/b", r"BBB", &[]);
        let scanner = scanner_with_patterns(vec![p1, p2]);

        let mut findings = Vec::new();
        scanner.scan_content_into("AAA and BBB", Path::new("test.txt"), &mut findings);

        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn scan_content_into_respects_severity_threshold() {
        let low = make_pattern_with_severity("test/low", r"LOW", Severity::Low);
        let high = make_pattern_with_severity("test/high", r"HIGH", Severity::High);
        let scanner = scanner_with_patterns(vec![low, high]).with_severity_threshold(Severity::High);

        let mut findings = Vec::new();
        scanner.scan_content_into("LOW and HIGH", Path::new("test.txt"), &mut findings);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pattern_id.as_ref(), "test/high");
    }

    #[test]
    fn dedup_removes_generic_finding_when_specific_overlaps() {
        let specific = make_finding_at("cloud/stripe-key", "sk_live_abc", 10, 25);
        let generic = make_finding_at("generic/secret-assignment", "sk_live_abc", 10, 25);
        let mut findings = vec![generic, specific];

        dedup_generic_findings(&mut findings);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pattern_id.as_ref(), "cloud/stripe-key");
    }

    #[test]
    fn dedup_keeps_both_when_no_overlap() {
        let specific = make_finding_at("cloud/stripe-key", "sk_live_abc", 10, 25);
        let generic = make_finding_at("generic/password-assignment", "mypassword1", 50, 70);
        let mut findings = vec![specific, generic];

        dedup_generic_findings(&mut findings);

        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn dedup_preserves_all_when_no_generic() {
        let f1 = make_finding_at("cloud/aws-key", "AKIAIOSFODNN", 0, 20);
        let f2 = make_finding_at("cloud/stripe-key", "sk_live_abc", 30, 45);
        let mut findings = vec![f1, f2];

        dedup_generic_findings(&mut findings);

        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn dedup_preserves_all_when_only_generic() {
        let f1 = make_finding_at("generic/password-assignment", "password1", 0, 10);
        let f2 = make_finding_at("generic/secret-assignment", "secret123", 20, 35);
        let mut findings = vec![f1, f2];

        dedup_generic_findings(&mut findings);

        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn dedup_handles_empty_findings() {
        let mut findings: Vec<Finding> = Vec::new();
        dedup_generic_findings(&mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn dedup_handles_single_finding() {
        let mut findings = vec![make_finding_at("generic/password-assignment", "pw", 0, 10)];
        dedup_generic_findings(&mut findings);
        assert_eq!(findings.len(), 1);
    }

    fn make_finding_at(pattern_id: &str, secret_text: &str, byte_start: usize, byte_end: usize) -> Finding {
        let secret = Secret::new(secret_text);
        Finding {
            id: FindingId::new(pattern_id, &secret),
            path: Path::new("test.txt").into(),
            span: Span::new(1, 1, byte_start, byte_end),
            pattern_id: pattern_id.into(),
            secret,
            severity: Severity::High,
            masked_line: "masked".into(),
            confidence: Confidence::High,
        }
    }
}
