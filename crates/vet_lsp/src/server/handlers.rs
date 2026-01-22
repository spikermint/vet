//! Document lifecycle event handlers.

use tower_lsp::lsp_types::{
    DidChangeTextDocumentParams, DidCloseTextDocumentParams, DidOpenTextDocumentParams, DidSaveTextDocumentParams,
};
use tracing::{debug, warn};

use super::VetLanguageServer;
use crate::state::OpenDocument;

/// Minimum change size (in bytes) to trigger a rescan.
/// Most secrets are longer than 8 characters.
const MIN_CHANGE_SIZE: usize = 8;

impl VetLanguageServer {
    pub(super) async fn handle_did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        let content = params.text_document.text.clone();
        let language_id = params.text_document.language_id.clone();

        debug!("Document opened: {uri} (language: {language_id})");

        self.state
            .write()
            .await
            .open_documents
            .insert(uri.clone(), OpenDocument::new(content.clone(), language_id));

        self.scan_document(&uri, &content).await;
    }

    pub(super) async fn handle_did_save(&self, params: DidSaveTextDocumentParams) {
        let uri = params.text_document.uri.clone();

        let Some(content) = params.text else {
            warn!("Save event missing text content");
            return;
        };

        debug!("Document saved: {uri}");

        {
            let mut state = self.state.write().await;
            if let Some(doc) = state.open_documents.get_mut(&uri) {
                doc.content.clone_from(&content);
            }
        }

        self.scan_document(&uri, &content).await;
    }

    pub(super) async fn handle_did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri.clone();

        let total_changed: usize = params.content_changes.iter().map(|c| c.text.len()).sum();

        if total_changed < MIN_CHANGE_SIZE {
            if let Some(change) = params.content_changes.into_iter().last() {
                let mut state = self.state.write().await;
                if let Some(doc) = state.open_documents.get_mut(&uri) {
                    doc.content = change.text;
                }
            }
            return;
        }

        let Some(change) = params.content_changes.into_iter().last() else {
            return;
        };

        let content = change.text.clone();

        {
            let mut state = self.state.write().await;
            if let Some(doc) = state.open_documents.get_mut(&uri) {
                doc.content = content.clone();
            }
        }

        self.scan_document(&uri, &content).await;
    }

    pub(super) async fn handle_did_close(&self, params: DidCloseTextDocumentParams) {
        let uri = &params.text_document.uri;

        {
            let mut state = self.state.write().await;
            state.open_documents.remove(uri);
            state.diagnostics.remove(uri);
        }

        self.client.publish_diagnostics(uri.clone(), vec![], None).await;
    }
}
