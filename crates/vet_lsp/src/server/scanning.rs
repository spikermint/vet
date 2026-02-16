//! Document scanning and diagnostics.

use std::fmt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use tower_lsp::lsp_types::Url;
use tracing::{debug, info, warn};

use super::VetLanguageServer;
use crate::diagnostics::{DiagnosticContext, filter_by_confidence, findings_to_diagnostics_with_context};
use crate::exclusions;
use crate::uri::try_uri_to_path;

/// The event that triggered a document scan.
#[derive(Debug, Clone, Copy)]
pub enum ScanTrigger {
    /// The document was just opened in the editor.
    Open,
    /// A debounced edit notification fired after the user stopped typing.
    Debounce,
    /// The workspace configuration changed (e.g. `.vet.toml` was modified).
    ConfigChange,
}

impl fmt::Display for ScanTrigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => write!(f, "open"),
            Self::Debounce => write!(f, "debounce"),
            Self::ConfigChange => write!(f, "config"),
        }
    }
}

impl VetLanguageServer {
    /// Scans a document for secrets and publishes the resulting diagnostics.
    pub(super) async fn scan_document(&self, uri: &Url, content: &str, trigger: ScanTrigger) {
        let start = Instant::now();
        let file_path = try_uri_to_path(uri);
        let state = self.state.read().await;

        let display_path = file_path
            .as_ref()
            .map_or_else(|| uri.path().to_string(), |p| p.display().to_string());

        if let Some(path) = &file_path {
            // Skip files outside all workspace roots
            if !state.workspace_roots.is_empty() && !state.workspace_roots.iter().any(|root| path.starts_with(root)) {
                debug!("Skipped {} (outside workspace)", display_path);
                return;
            }

            if state.respect_gitignore
                && let Some(root) = state.primary_workspace_root()
                && exclusions::is_gitignored(state.gitignore.as_ref(), path, root)
            {
                info!("Skipped {} (gitignored)", display_path);
                drop(state);
                self.clear_diagnostics(uri).await;
                return;
            }

            if exclusions::is_excluded(state.exclude_matcher.as_ref(), path, &state.workspace_roots) {
                info!("Skipped {} (excluded by config)", display_path);
                drop(state);
                self.clear_diagnostics(uri).await;
                return;
            }
        }

        let Some(scanner) = &state.scanner else {
            warn!("Scanner not initialised");
            return;
        };

        let scan_path = file_path.unwrap_or_else(|| PathBuf::from(uri.path()));
        let findings = scanner.scan_content(content, &scan_path);
        let minimum_confidence = state.minimum_confidence();
        let filtered = filter_by_confidence(findings, minimum_confidence);

        let filtered = if let Some(matcher) = &state.ignore_matcher {
            filtered
                .into_iter()
                .filter(|f| !matcher.is_ignored(&f.baseline_fingerprint()))
                .collect()
        } else {
            filtered
        };

        let elapsed = start.elapsed();

        let finding_count = filtered.len();

        if finding_count > 0 {
            let pattern_ids: Vec<&str> = filtered.iter().map(|f| &*f.pattern_id).collect();
            info!(
                "Scanned {} [{}] in {} ({} finding{}: {})",
                display_path,
                trigger,
                format_duration(elapsed),
                finding_count,
                if finding_count == 1 { "" } else { "s" },
                pattern_ids.join(", ")
            );
        } else {
            debug!(
                "Scanned {} [{}] in {} (clean)",
                display_path,
                trigger,
                format_duration(elapsed)
            );
        }

        let diagnostic_context = DiagnosticContext {
            verifier_registry: state.verification.registry.as_ref(),
            verification_cache: &state.verification.cache,
        };

        let diagnostics = findings_to_diagnostics_with_context(&filtered, &diagnostic_context);

        drop(state);

        self.state
            .write()
            .await
            .diagnostics
            .insert(uri.clone(), diagnostics.clone());

        self.client.publish_diagnostics(uri.clone(), diagnostics, None).await;
    }

    /// Removes stored diagnostics for a document and publishes an empty set.
    pub(super) async fn clear_diagnostics(&self, uri: &Url) {
        self.state.write().await.diagnostics.remove(uri);
        self.client.publish_diagnostics(uri.clone(), vec![], None).await;
    }
}

fn format_duration(d: Duration) -> String {
    let nanos = d.as_nanos();

    if nanos < 1_000 {
        format!("{nanos}ns")
    } else if nanos < 1_000_000 {
        #[expect(clippy::cast_precision_loss, reason = "sub-second nanos fit precisely in f64")]
        let micros = nanos as f64 / 1_000.0;
        format!("{micros:.1}µs")
    } else if nanos < 1_000_000_000 {
        #[expect(clippy::cast_precision_loss, reason = "sub-second nanos fit precisely in f64")]
        let millis = nanos as f64 / 1_000_000.0;
        format!("{millis:.1}ms")
    } else {
        #[expect(
            clippy::cast_precision_loss,
            reason = "duration display tolerance accepts f64 precision"
        )]
        let secs = nanos as f64 / 1_000_000_000.0;
        format!("{secs:.2}s")
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tower_lsp::lsp_types::Url;

    use crate::uri::try_uri_to_path;

    #[test]
    fn try_uri_to_path_returns_none_for_untitled() {
        let uri = Url::parse("untitled:Untitled-1").unwrap();
        assert!(try_uri_to_path(&uri).is_none());
    }

    #[test]
    fn try_uri_to_path_returns_some_for_file() {
        #[cfg(not(windows))]
        let uri = Url::parse("file:///home/user/test.rs").unwrap();
        #[cfg(windows)]
        let uri = Url::parse("file:///C:/Users/user/test.rs").unwrap();

        assert!(try_uri_to_path(&uri).is_some());
    }

    #[test]
    fn untitled_uri_path_extracts_filename() {
        let uri = Url::parse("untitled:Untitled-1").unwrap();
        let fallback = PathBuf::from(uri.path());
        assert_eq!(fallback, PathBuf::from("Untitled-1"));
    }

    #[test]
    fn untitled_uri_with_extension_extracts_filename() {
        let uri = Url::parse("untitled:scratch.rs").unwrap();
        let fallback = PathBuf::from(uri.path());
        assert_eq!(fallback, PathBuf::from("scratch.rs"));
    }

    #[test]
    fn path_outside_workspace_is_detected() {
        let workspace_roots = [PathBuf::from("/home/user/project")];
        let external_path = PathBuf::from("/home/user/.cargo/registry/src/crate/lib.rs");

        let is_inside = workspace_roots.iter().any(|root| external_path.starts_with(root));
        assert!(!is_inside);
    }

    #[test]
    fn path_inside_workspace_is_detected() {
        let workspace_roots = [PathBuf::from("/home/user/project")];
        let internal_path = PathBuf::from("/home/user/project/src/main.rs");

        let is_inside = workspace_roots.iter().any(|root| internal_path.starts_with(root));
        assert!(is_inside);
    }
}
