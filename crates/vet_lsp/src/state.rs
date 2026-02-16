//! Server state management.
//!
//! Maintains the runtime state of the language server including scanner,
//! workspace configuration, and open documents.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::time::Instant;

use globset::GlobSet;
use ignore::gitignore::Gitignore;
use lru::LruCache;
use tower_lsp::lsp_types::{Diagnostic, Url};
use vet_core::prelude::*;
use vet_providers::{ProviderRegistry, VerificationResult};

const MAX_CACHE_ENTRIES: usize = 512;
const PENDING_TIMEOUT_SECS: u64 = 60;

/// A document currently open in the editor.
#[derive(Debug, Clone)]
pub struct OpenDocument {
    /// The full text content of the document.
    pub content: String,
    /// The VS Code language identifier (e.g. `"rust"`, `"python"`).
    pub language_id: Box<str>,
}

impl OpenDocument {
    /// Creates a new document from its content and language identifier.
    #[must_use]
    pub fn new(content: String, language_id: String) -> Self {
        Self {
            content,
            language_id: language_id.into_boxed_str(),
        }
    }

    /// Extracts text from a single line between character offsets.
    #[must_use]
    pub fn extract_range(&self, line: u32, start_char: u32, end_char: u32) -> Option<String> {
        let line_content = self.content.lines().nth(line as usize)?;
        let chars: Vec<char> = line_content.chars().collect();

        let start = start_char as usize;
        let end = end_char as usize;

        if start > chars.len() || end > chars.len() || start > end {
            return None;
        }

        Some(chars[start..end].iter().collect())
    }
}

/// A cached verification result with its insertion timestamp.
pub struct CachedVerification {
    /// The verification outcome from the provider's API.
    pub result: VerificationResult,
    /// When this entry was inserted into the cache.
    pub cached_at: Instant,
}

impl CachedVerification {
    /// Time-to-live for cached entries in seconds (5 minutes).
    pub const CACHE_TTL_SECS: u64 = 300; // 5 mins

    /// Wraps a verification result with the current timestamp.
    #[must_use]
    pub fn new(result: VerificationResult) -> Self {
        Self {
            result,
            cached_at: Instant::now(),
        }
    }

    /// Returns `true` if this entry has exceeded the cache TTL.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.cached_at.elapsed().as_secs() >= Self::CACHE_TTL_SECS
    }
}

/// Tracks a verification request that is currently in flight.
pub struct PendingVerification {
    /// When the verification request was initiated.
    pub started_at: Instant,
}

/// Groups the provider registry, result cache, and pending request tracking.
pub struct VerificationState {
    /// The provider registry for live verification, if initialised.
    pub registry: Option<ProviderRegistry>,
    /// LRU cache of recent verification results keyed by finding ID.
    pub cache: LruCache<String, CachedVerification>,
    /// In-flight verification requests keyed by finding ID.
    pub pending: HashMap<String, PendingVerification>,
}

impl VerificationState {
    /// Creates empty verification state with no registry or cached results.
    #[must_use]
    pub fn new() -> Self {
        Self {
            registry: None,
            cache: LruCache::new(NonZeroUsize::new(MAX_CACHE_ENTRIES).unwrap_or(NonZeroUsize::MIN)),
            pending: HashMap::new(),
        }
    }

    /// Returns `true` if a non-timed-out verification is in progress for this finding.
    #[must_use]
    pub fn is_pending(&self, finding_id: &str) -> bool {
        self.pending
            .get(finding_id)
            .is_some_and(|p| p.started_at.elapsed().as_secs() < PENDING_TIMEOUT_SECS)
    }

    /// Marks a finding as having a verification in progress.
    ///
    /// Returns `true` if the finding was newly marked, or `false` if a
    /// non-timed-out verification is already pending for it.
    pub fn mark_pending(&mut self, finding_id: String) -> bool {
        if self.is_pending(&finding_id) {
            return false;
        }

        self.pending.insert(
            finding_id,
            PendingVerification {
                started_at: Instant::now(),
            },
        );
        true
    }

    /// Removes the pending marker for a finding without caching a result.
    pub fn clear_pending(&mut self, finding_id: &str) {
        self.pending.remove(finding_id);
    }

    /// Stores a verification result in the cache and clears the pending marker.
    pub fn insert_result(&mut self, finding_id: &str, result: VerificationResult) {
        self.cache.put(finding_id.to_string(), CachedVerification::new(result));
        self.pending.remove(finding_id);
    }

    /// Returns the cached result for a finding if it exists and has not expired.
    #[must_use]
    pub fn get_cached(&self, finding_id: &str) -> Option<&CachedVerification> {
        self.cache.peek(finding_id).filter(|c| !c.is_expired())
    }
}

impl Default for VerificationState {
    fn default() -> Self {
        Self::new()
    }
}

/// Runtime state shared across all LSP request handlers.
pub struct ServerState {
    /// The compiled secret scanner, initialised on workspace open.
    pub scanner: Option<Scanner>,
    /// Root directories of the open workspace folders.
    pub workspace_roots: Vec<PathBuf>,
    /// Parsed `.vet.toml` configuration, if present.
    pub config: Option<Config>,
    /// Glob matcher for user-configured file exclusions.
    pub exclude_matcher: Option<GlobSet>,
    /// Compiled gitignore rules from the workspace root.
    pub gitignore: Option<Gitignore>,
    /// Whether to honour `.gitignore` when deciding which files to scan.
    pub respect_gitignore: bool,
    /// Editor-level override for the minimum confidence threshold.
    pub minimum_confidence_override: Option<Confidence>,
    /// Acknowledged-secrets baseline loaded from `.vet-baseline.json`.
    pub baseline: Option<Baseline>,
    /// Combined ignore matcher merging gitignore and glob exclusions.
    pub ignore_matcher: Option<IgnoreMatcher>,
    /// Documents currently open in the editor, keyed by URI.
    pub open_documents: HashMap<Url, OpenDocument>,
    /// Published diagnostics per document URI.
    pub diagnostics: HashMap<Url, Vec<Diagnostic>>,
    /// Live verification state (registry, cache, and pending requests).
    pub verification: VerificationState,
}

impl ServerState {
    /// Creates a default server state with no scanner or configuration loaded.
    #[must_use]
    pub fn new() -> Self {
        Self {
            scanner: None,
            workspace_roots: Vec::new(),
            config: None,
            exclude_matcher: None,
            gitignore: None,
            respect_gitignore: true,
            minimum_confidence_override: None,
            baseline: None,
            ignore_matcher: None,
            open_documents: HashMap::new(),
            diagnostics: HashMap::new(),
            verification: VerificationState::new(),
        }
    }

    /// Returns the minimum confidence level for reported findings.
    ///
    /// The editor-level override takes precedence over the config file setting.
    /// Defaults to `High` when neither is set.
    #[must_use]
    pub fn minimum_confidence(&self) -> Confidence {
        if let Some(override_val) = self.minimum_confidence_override {
            return override_val;
        }

        self.config.as_ref().map_or(Confidence::High, |c| c.minimum_confidence)
    }

    /// Returns the first workspace root, used as the primary project directory.
    #[must_use]
    pub fn primary_workspace_root(&self) -> Option<&PathBuf> {
        self.workspace_roots.first()
    }

    /// Returns the open document for the given URI, if tracked.
    #[must_use]
    pub fn get_document(&self, uri: &Url) -> Option<&OpenDocument> {
        self.open_documents.get(uri)
    }

    /// Returns the published diagnostics for the given URI, if any.
    #[must_use]
    pub fn get_diagnostics(&self, uri: &Url) -> Option<&[Diagnostic]> {
        self.diagnostics.get(uri).map(Vec::as_slice)
    }
}

impl Default for ServerState {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ServerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerState")
            .field("scanner", &self.scanner.as_ref().map(|_| "Scanner"))
            .field("workspace_roots", &self.workspace_roots)
            .field("config", &self.config)
            .field("respect_gitignore", &self.respect_gitignore)
            .field("open_documents", &self.open_documents.len())
            .field("diagnostics", &self.diagnostics.len())
            .field("verification_registry", &self.verification.registry)
            .field("verification_cache", &self.verification.cache.len())
            .field("verification_pending", &self.verification.pending.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests use expect for clearer failure messages")]
mod tests {
    use tower_lsp::lsp_types::{DiagnosticSeverity, Position, Range};
    use vet_providers::{ServiceInfo, VerificationStatus};

    use super::*;

    fn make_diagnostic(line: u32, code: &str) -> Diagnostic {
        Diagnostic {
            range: Range::new(Position::new(line, 0), Position::new(line, 10)),
            severity: Some(DiagnosticSeverity::ERROR),
            code: Some(tower_lsp::lsp_types::NumberOrString::String(code.to_string())),
            source: Some("vet".to_string()),
            message: format!("Potential secret: {code}"),
            ..Default::default()
        }
    }

    #[test]
    fn default_state_respects_gitignore() {
        let state = ServerState::new();
        assert!(state.respect_gitignore);
    }

    #[test]
    fn default_state_has_no_gitignore_matcher() {
        let state = ServerState::new();
        assert!(state.gitignore.is_none());
    }

    #[test]
    fn no_config_defaults_to_high_confidence() {
        let state = ServerState::new();
        assert_eq!(state.minimum_confidence(), Confidence::High);
    }

    #[test]
    fn config_controls_minimum_confidence() {
        let mut state = ServerState::new();
        let config = Config {
            minimum_confidence: Confidence::Low,
            ..Default::default()
        };
        state.config = Some(config);

        assert_eq!(state.minimum_confidence(), Confidence::Low);
    }

    #[test]
    fn override_beats_config() {
        let mut state = ServerState::new();
        let config = Config {
            minimum_confidence: Confidence::Low,
            ..Default::default()
        };
        state.config = Some(config);
        state.minimum_confidence_override = Some(Confidence::High);

        assert_eq!(state.minimum_confidence(), Confidence::High);
    }

    #[test]
    fn primary_workspace_root_returns_first() {
        let mut state = ServerState::new();
        state.workspace_roots = vec![PathBuf::from("/project-a"), PathBuf::from("/project-b")];

        assert_eq!(state.primary_workspace_root(), Some(&PathBuf::from("/project-a")));
    }

    #[test]
    fn primary_workspace_root_none_when_empty() {
        let state = ServerState::new();
        assert!(state.primary_workspace_root().is_none());
    }

    #[test]
    fn get_document_returns_none_for_missing() {
        let state = ServerState::new();
        let uri = Url::parse("file:///test.rs").unwrap();
        assert!(state.get_document(&uri).is_none());
    }

    #[test]
    fn get_document_returns_document() {
        let mut state = ServerState::new();
        let uri = Url::parse("file:///test.rs").unwrap();
        state.open_documents.insert(
            uri.clone(),
            OpenDocument::new("content".to_string(), "rust".to_string()),
        );

        let doc = state.get_document(&uri).expect("document should exist");
        assert_eq!(doc.content, "content");
        assert_eq!(&*doc.language_id, "rust");
    }

    #[test]
    fn get_diagnostics_returns_none_for_missing() {
        let state = ServerState::new();
        let uri = Url::parse("file:///test.rs").unwrap();
        assert!(state.get_diagnostics(&uri).is_none());
    }

    #[test]
    fn get_diagnostics_returns_diagnostics() {
        let mut state = ServerState::new();
        let uri = Url::parse("file:///test.rs").unwrap();
        let diagnostics = vec![make_diagnostic(0, "aws/access-key")];
        state.diagnostics.insert(uri.clone(), diagnostics);

        let result = state.get_diagnostics(&uri).expect("diagnostics should exist");
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn debug_format_includes_gitignore_info() {
        let state = ServerState::new();
        let debug = format!("{state:?}");
        assert!(debug.contains("respect_gitignore"));
    }

    #[test]
    fn cached_verification_new_creates_with_current_time() {
        let result = VerificationResult::inactive("TestProvider");
        let cached = CachedVerification::new(result.clone());

        assert_eq!(cached.result.status, result.status);
        assert!(!cached.is_expired());
    }

    #[test]
    fn cached_verification_not_expired_when_fresh() {
        let result = VerificationResult::live(ServiceInfo {
            provider: Some("GitHub".into()),
            details: "test".into(),
            documentation_url: None,
        });
        let cached = CachedVerification::new(result);

        assert!(!cached.is_expired());
    }

    #[test]
    fn cached_verification_stores_result() {
        let result = VerificationResult::inconclusive("rate limited");
        let cached = CachedVerification::new(result);

        assert_eq!(cached.result.status, VerificationStatus::Inconclusive);
        assert!(cached.result.service.is_some());
    }

    #[test]
    fn extract_range_returns_substring() {
        let doc = OpenDocument::new("hello world".to_string(), "text".to_string());
        let result = doc.extract_range(0, 0, 5);
        assert_eq!(result, Some("hello".to_string()));
    }

    #[test]
    fn extract_range_middle_of_line() {
        let doc = OpenDocument::new("hello world".to_string(), "text".to_string());
        let result = doc.extract_range(0, 6, 11);
        assert_eq!(result, Some("world".to_string()));
    }

    #[test]
    fn extract_range_multiline_gets_correct_line() {
        let doc = OpenDocument::new("line one\nline two\nline three".to_string(), "text".to_string());
        let result = doc.extract_range(1, 0, 8);
        assert_eq!(result, Some("line two".to_string()));
    }

    #[test]
    fn extract_range_returns_none_for_invalid_line() {
        let doc = OpenDocument::new("hello".to_string(), "text".to_string());
        let result = doc.extract_range(5, 0, 3);
        assert!(result.is_none());
    }

    #[test]
    fn extract_range_returns_none_for_out_of_bounds() {
        let doc = OpenDocument::new("hello".to_string(), "text".to_string());
        let result = doc.extract_range(0, 0, 100);
        assert!(result.is_none());
    }

    #[test]
    fn extract_range_returns_none_for_invalid_range() {
        let doc = OpenDocument::new("hello".to_string(), "text".to_string());
        let result = doc.extract_range(0, 5, 2); // start > end
        assert!(result.is_none());
    }

    #[test]
    fn verification_state_expired_entries_not_returned() {
        let mut vs = VerificationState::new();
        vs.cache.put(
            "test".to_string(),
            CachedVerification {
                result: VerificationResult::inactive("Test"),
                cached_at: Instant::now()
                    .checked_sub(std::time::Duration::from_secs(CachedVerification::CACHE_TTL_SECS + 1))
                    .expect("test duration subtraction should not underflow"),
            },
        );
        assert_eq!(vs.cache.len(), 1);
        assert!(vs.get_cached("test").is_none());
    }

    #[test]
    fn verification_state_pending_timeout() {
        let mut vs = VerificationState::new();
        vs.pending.insert(
            "stale".to_string(),
            PendingVerification {
                started_at: Instant::now()
                    .checked_sub(std::time::Duration::from_secs(PENDING_TIMEOUT_SECS + 1))
                    .expect("test duration subtraction should not underflow"),
            },
        );
        assert!(!vs.is_pending("stale"));
    }

    #[test]
    fn verification_state_mark_pending_prevents_duplicate() {
        let mut vs = VerificationState::new();
        assert!(vs.mark_pending("test".to_string()));
        assert!(!vs.mark_pending("test".to_string()));
    }

    #[test]
    fn verification_state_insert_result_clears_pending() {
        let mut vs = VerificationState::new();
        vs.mark_pending("test".to_string());
        vs.insert_result("test", VerificationResult::inactive("Test"));
        assert!(!vs.is_pending("test"));
        assert!(vs.get_cached("test").is_some());
    }
}
