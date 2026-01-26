//! Document lifecycle event handlers.

use tower_lsp::lsp_types::{
    DidChangeTextDocumentParams, DidCloseTextDocumentParams, DidOpenTextDocumentParams, DidSaveTextDocumentParams,
};
use tracing::{debug, info};

use super::VetLanguageServer;
use super::scanning::ScanTrigger;
use crate::state::OpenDocument;

impl VetLanguageServer {
    pub(super) async fn handle_did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        let content = params.text_document.text.clone();
        let language_id = params.text_document.language_id.clone();

        let filename = uri.path_segments().and_then(|s| s.last()).unwrap_or("unknown");

        info!("Opened {filename} ({language_id})");

        self.state
            .write()
            .await
            .open_documents
            .insert(uri.clone(), OpenDocument::new(content.clone(), language_id));

        self.scan_document(&uri, &content, ScanTrigger::Open).await;
    }

    pub(super) async fn handle_did_save(&self, params: DidSaveTextDocumentParams) {
        let uri = params.text_document.uri;

        let filename = uri.path_segments().and_then(|s| s.last()).unwrap_or("unknown");

        debug!("Saved {filename}");

        if let Some(content) = params.text {
            let mut state = self.state.write().await;
            if let Some(doc) = state.open_documents.get_mut(&uri) {
                doc.content = content;
            }
        }
    }

    pub(super) async fn handle_did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri.clone();

        let filename = uri.path_segments().and_then(|s| s.last()).unwrap_or("unknown");

        debug!("Changed {filename}");

        let Some(change) = params.content_changes.into_iter().last() else {
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

    pub(super) async fn handle_did_close(&self, params: DidCloseTextDocumentParams) {
        let uri = &params.text_document.uri;

        let filename = uri.path_segments().and_then(|s| s.last()).unwrap_or("unknown");

        debug!("Closed {filename}");

        {
            let mut state = self.state.write().await;
            state.open_documents.remove(uri);
            state.diagnostics.remove(uri);
        }

        self.client.publish_diagnostics(uri.clone(), vec![], None).await;
    }
}
