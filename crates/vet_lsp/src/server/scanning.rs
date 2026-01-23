//! Document scanning and diagnostics.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use tower_lsp::lsp_types::Url;
use tracing::{debug, info, warn};

use super::VetLanguageServer;
use crate::diagnostics::{filter_by_confidence, findings_to_diagnostics};
use crate::exclusions;
use crate::uri::try_uri_to_path;

impl VetLanguageServer {
    pub(super) async fn scan_document(&self, uri: &Url, content: &str) {
        let start = Instant::now();
        let file_path = try_uri_to_path(uri);
        let state = self.state.read().await;

        if let Some(path) = &file_path {
            if state.respect_gitignore
                && let Some(root) = state.primary_workspace_root()
                && exclusions::is_gitignored(state.gitignore.as_ref(), path, root)
            {
                debug!("Skipping gitignored file: {}", path.display());
                drop(state);
                self.clear_diagnostics(uri).await;
                return;
            }

            if exclusions::is_excluded(state.exclude_matcher.as_ref(), path, &state.workspace_roots) {
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
        let include_low_confidence = state.includes_low_confidence_findings();
        let filtered = filter_by_confidence(findings, include_low_confidence);
        let elapsed = start.elapsed();

        let filename = scan_path.file_name().unwrap_or_default().to_string_lossy();
        let finding_count = filtered.len();

        if finding_count > 0 {
            info!(
                "Scanned {} in {} ({} finding{})",
                filename,
                format_duration(elapsed),
                finding_count,
                if finding_count == 1 { "" } else { "s" }
            );
        } else {
            debug!("Scanned {} in {} (clean)", filename, format_duration(elapsed));
        }

        let diagnostics = findings_to_diagnostics(&filtered);

        drop(state);

        self.state
            .write()
            .await
            .diagnostics
            .insert(uri.clone(), diagnostics.clone());
        self.client.publish_diagnostics(uri.clone(), diagnostics, None).await;
    }

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
        #[allow(clippy::cast_precision_loss)]
        let micros = nanos as f64 / 1_000.0;
        format!("{micros:.1}µs")
    } else if nanos < 1_000_000_000 {
        #[allow(clippy::cast_precision_loss)]
        let millis = nanos as f64 / 1_000_000.0;
        format!("{millis:.1}ms")
    } else {
        format!("{:.2}s", d.as_secs_f64())
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
}
