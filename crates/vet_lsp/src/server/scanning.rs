//! Document scanning and diagnostics.

use std::time::{Duration, Instant};

use tower_lsp::lsp_types::Url;
use tracing::{debug, info, warn};

use super::VetLanguageServer;
use crate::diagnostics::{filter_by_confidence, findings_to_diagnostics};
use crate::exclusions;
use crate::uri::uri_to_path_lossy;

impl VetLanguageServer {
    pub(super) async fn scan_document(&self, uri: &Url, content: &str) {
        let start = Instant::now();
        let path = uri_to_path_lossy(uri);
        let state = self.state.read().await;

        if state.respect_gitignore
            && let Some(root) = state.primary_workspace_root()
            && exclusions::is_gitignored(state.gitignore.as_ref(), &path, root)
        {
            debug!("[vet-lsp] Skipping gitignored file: {}", path.display());
            drop(state);
            self.clear_diagnostics(uri).await;
            return;
        }

        if exclusions::is_excluded(state.exclude_matcher.as_ref(), &path, &state.workspace_roots) {
            drop(state);
            self.clear_diagnostics(uri).await;
            return;
        }

        let Some(scanner) = &state.scanner else {
            warn!("Scanner not initialised");
            return;
        };

        let findings = scanner.scan_content(content, &path);
        let include_low_confidence = state.includes_low_confidence_findings();
        let filtered = filter_by_confidence(findings, include_low_confidence);
        let elapsed = start.elapsed();

        let filename = path.file_name().unwrap_or_default().to_string_lossy();
        let finding_count = filtered.len();

        if finding_count > 0 {
            info!(
                "[vet-lsp] Scanned {} in {} ({} finding{})",
                filename,
                format_duration(elapsed),
                finding_count,
                if finding_count == 1 { "" } else { "s" }
            );
        } else {
            debug!("[vet-lsp] Scanned {} in {} (clean)", filename, format_duration(elapsed));
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
