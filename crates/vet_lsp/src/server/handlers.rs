//! Document lifecycle event handlers.

use tower_lsp::lsp_types::{
    DidChangeTextDocumentParams, DidCloseTextDocumentParams, DidOpenTextDocumentParams, DidSaveTextDocumentParams,
};
use tracing::{debug, info};

use super::VetLanguageServer;
use super::scanning::ScanTrigger;
use crate::state::OpenDocument;
use crate::uri::filename_from_uri;

impl VetLanguageServer {
    /// Stores the opened document and triggers an initial scan.
    pub(super) async fn handle_did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        let content = params.text_document.text.clone();
        let language_id = params.text_document.language_id.clone();

        info!("Opened {} ({language_id})", filename_from_uri(&uri));

        self.state
            .write()
            .await
            .open_documents
            .insert(uri.clone(), OpenDocument::new(content.clone(), language_id));

        self.scan_document(&uri, &content, ScanTrigger::Open).await;
    }

    /// Updates the stored document content when the file is saved.
    pub(super) async fn handle_did_save(&self, params: DidSaveTextDocumentParams) {
        let uri = params.text_document.uri;

        debug!("Saved {}", filename_from_uri(&uri));

        if let Some(content) = params.text {
            let mut state = self.state.write().await;
            if let Some(doc) = state.open_documents.get_mut(&uri) {
                doc.content = content;
            }
        }
    }

    /// Applies the latest content change and schedules a debounced scan.
    pub(super) async fn handle_did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri.clone();

        debug!("Changed {}", filename_from_uri(&uri));

        let Some(change) = params.content_changes.into_iter().next_back() else {
            return;
        };

        let content = change.text;

        {
            let mut state = self.state.write().await;
            if let Some(doc) = state.open_documents.get_mut(&uri) {
                doc.content.clone_from(&content);
            }
        }

        self.debouncer.schedule(uri, content);
    }

    /// Removes the document from tracking and clears its diagnostics.
    pub(super) async fn handle_did_close(&self, params: DidCloseTextDocumentParams) {
        let uri = &params.text_document.uri;

        debug!("Closed {}", filename_from_uri(uri));

        {
            let mut state = self.state.write().await;
            state.open_documents.remove(uri);
            state.diagnostics.remove(uri);
        }

        self.client.publish_diagnostics(uri.clone(), vec![], None).await;
    }
}
