use std::collections::HashSet;

use super::file::Baseline;
use super::fingerprint::Fingerprint;
use crate::config::ConfigIgnore;

/// Fast lookup for fingerprints that should be suppressed.
///
/// Merges fingerprints from both a [`Baseline`] file and inline
/// [`ConfigIgnore`] entries into a single `HashSet` for O(1) checks.
#[derive(Debug)]
pub struct IgnoreMatcher {
    fingerprints: HashSet<Box<str>>,
}

impl IgnoreMatcher {
    /// Builds a matcher from an optional baseline and a slice of config ignores.
    ///
    /// Duplicate fingerprints across both sources are deduplicated.
    #[must_use]
    pub fn new(baseline: Option<&Baseline>, config_ignores: &[ConfigIgnore]) -> Self {
        let mut fingerprints = HashSet::new();

        if let Some(baseline) = baseline {
            for finding in &baseline.findings {
                fingerprints.insert(finding.fingerprint.as_str().into());
            }
        }

        for ignore in config_ignores {
            fingerprints.insert(ignore.fingerprint.as_str().into());
        }

        Self { fingerprints }
    }

    /// Returns `true` if the given fingerprint should be suppressed.
    #[must_use]
    pub fn is_ignored(&self, fingerprint: &Fingerprint) -> bool {
        self.fingerprints.contains(fingerprint.as_str())
    }

    /// Returns the total number of unique suppressed fingerprints.
    #[must_use]
    pub fn len(&self) -> usize {
        self.fingerprints.len()
    }

    /// Returns `true` if no fingerprints are suppressed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Severity;
    use crate::baseline::{BaselineFinding, BaselineStatus};

    fn create_baseline_with_fingerprints(fingerprints: &[&str]) -> Baseline {
        let mut baseline = Baseline::new();
        for fp in fingerprints {
            baseline.add_finding(BaselineFinding::new(
                Fingerprint::from_string(fp),
                "test".to_string(),
                Severity::High,
                "test.py".to_string(),
                "sha256:secret".to_string(),
                BaselineStatus::Accepted,
                "test".to_string(),
            ));
        }
        baseline
    }

    #[test]
    fn empty_matcher_ignores_nothing() {
        let matcher = IgnoreMatcher::new(None, &[]);

        assert!(!matcher.is_ignored(&Fingerprint::from_string("sha256:abc")));
        assert!(matcher.is_empty());
        assert_eq!(matcher.len(), 0);
    }

    #[test]
    fn matcher_finds_baseline_fingerprints() {
        let baseline = create_baseline_with_fingerprints(&["sha256:abc", "sha256:def"]);
        let matcher = IgnoreMatcher::new(Some(&baseline), &[]);

        assert!(matcher.is_ignored(&Fingerprint::from_string("sha256:abc")));
        assert!(matcher.is_ignored(&Fingerprint::from_string("sha256:def")));
        assert!(!matcher.is_ignored(&Fingerprint::from_string("sha256:xyz")));
        assert_eq!(matcher.len(), 2);
    }

    #[test]
    fn matcher_finds_config_ignores() {
        let ignores = vec![ConfigIgnore {
            fingerprint: "sha256:config1".to_string(),
            pattern_id: "test/pattern".to_string(),
            file: "test.py".to_string(),
            reason: "test".to_string(),
        }];
        let matcher = IgnoreMatcher::new(None, &ignores);

        assert!(matcher.is_ignored(&Fingerprint::from_string("sha256:config1")));
        assert!(!matcher.is_ignored(&Fingerprint::from_string("sha256:other")));
        assert_eq!(matcher.len(), 1);
    }

    #[test]
    fn matcher_merges_baseline_and_config() {
        let baseline = create_baseline_with_fingerprints(&["sha256:baseline"]);
        let ignores = vec![ConfigIgnore {
            fingerprint: "sha256:config".to_string(),
            pattern_id: "test/pattern".to_string(),
            file: "test.py".to_string(),
            reason: "test".to_string(),
        }];
        let matcher = IgnoreMatcher::new(Some(&baseline), &ignores);

        assert!(matcher.is_ignored(&Fingerprint::from_string("sha256:baseline")));
        assert!(matcher.is_ignored(&Fingerprint::from_string("sha256:config")));
        assert_eq!(matcher.len(), 2);
    }

    #[test]
    fn matcher_deduplicates_fingerprints() {
        let baseline = create_baseline_with_fingerprints(&["sha256:same"]);
        let ignores = vec![ConfigIgnore {
            fingerprint: "sha256:same".to_string(),
            pattern_id: "test/pattern".to_string(),
            file: "test.py".to_string(),
            reason: "test".to_string(),
        }];
        let matcher = IgnoreMatcher::new(Some(&baseline), &ignores);

        assert_eq!(matcher.len(), 1);
    }

    #[test]
    fn matcher_handles_empty_baseline() {
        let baseline = Baseline::new();
        let matcher = IgnoreMatcher::new(Some(&baseline), &[]);

        assert!(matcher.is_empty());
    }

    #[test]
    fn matcher_handles_empty_config_ignores() {
        let baseline = create_baseline_with_fingerprints(&["sha256:test"]);
        let matcher = IgnoreMatcher::new(Some(&baseline), &[]);

        assert_eq!(matcher.len(), 1);
    }

    #[test]
    fn is_empty_reflects_matcher_state() {
        let empty_matcher = IgnoreMatcher::new(None, &[]);
        assert!(empty_matcher.is_empty());

        let baseline = create_baseline_with_fingerprints(&["sha256:test"]);
        let non_empty_matcher = IgnoreMatcher::new(Some(&baseline), &[]);
        assert!(!non_empty_matcher.is_empty());
    }
}
