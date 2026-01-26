//! LSP server implementation.

mod handlers;
mod scanning;
mod workspace;

use std::sync::Arc;

use tokio::sync::RwLock;
use tokio::sync::mpsc::UnboundedReceiver;
use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::{
    CodeActionParams, CodeActionProviderCapability, CodeActionResponse, DidChangeConfigurationParams,
    DidChangeTextDocumentParams, DidChangeWatchedFilesParams, DidChangeWatchedFilesRegistrationOptions,
    DidChangeWorkspaceFoldersParams, DidCloseTextDocumentParams, DidOpenTextDocumentParams, DidSaveTextDocumentParams,
    FileSystemWatcher, GlobPattern, Hover, HoverParams, HoverProviderCapability, InitializeParams, InitializeResult,
    InitializedParams, OneOf, Position, Range, Registration, SaveOptions, ServerCapabilities,
    TextDocumentSyncCapability, TextDocumentSyncKind, TextDocumentSyncOptions, TextDocumentSyncSaveOptions, WatchKind,
    WorkspaceFoldersServerCapabilities, WorkspaceServerCapabilities,
};
use tower_lsp::{Client, LanguageServer};
use tracing::{debug, info, warn};
use vet_core::CONFIG_FILENAME;

use crate::code_actions::actions_for_diagnostics;
use crate::debounce::{self, Debouncer, ScanRequest};
use crate::git::{ExposureRisk, GitContext};
use crate::hover::pattern_hover;
use crate::state::ServerState;
use crate::uri::{extract_workspace_roots, try_uri_to_path};

use scanning::ScanTrigger;

const CONFIG_WATCHER_ID: &str = "config-watcher";

#[derive(Debug, Clone)]
pub struct VetLanguageServer {
    pub(super) client: Client,
    pub(super) state: Arc<RwLock<ServerState>>,
    pub(super) debouncer: Debouncer,
    scan_rx: Arc<RwLock<Option<UnboundedReceiver<ScanRequest>>>>,
}

impl VetLanguageServer {
    pub fn new(client: Client) -> Self {
        let (debouncer, scan_rx) = debounce::spawn();

        Self {
            client,
            state: Arc::new(RwLock::new(ServerState::new())),
            debouncer,
            scan_rx: Arc::new(RwLock::new(Some(scan_rx))),
        }
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for VetLanguageServer {
    async fn initialize(&self, params: InitializeParams) -> Result<InitializeResult> {
        info!("vet-lsp v{}", env!("CARGO_PKG_VERSION"));

        let roots = extract_workspace_roots(&params);
        info!("Initialising with {} workspace root(s)", roots.len());

        self.init_scanner().await;
        self.set_workspace_roots(roots).await;

        Ok(InitializeResult {
            capabilities: server_capabilities(),
            ..Default::default()
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        info!("Server initialised");

        if let Err(e) = self.register_file_watchers().await {
            warn!("Failed to register file watchers: {e}");
        }

        self.start_scan_handler().await;
    }

    async fn shutdown(&self) -> Result<()> {
        info!("Shutting down");
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        self.handle_did_open(params).await;
    }

    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        self.handle_did_save(params).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        self.handle_did_change(params).await;
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        self.handle_did_close(params).await;
    }

    async fn code_action(&self, params: CodeActionParams) -> Result<Option<CodeActionResponse>> {
        let uri = &params.text_document.uri;
        let range = &params.range;
        let diagnostics = &params.context.diagnostics;

        let state = self.state.read().await;
        let document = state.get_document(uri);
        let actions = actions_for_diagnostics(uri, range, diagnostics, document);

        Ok(Some(actions).filter(|a| !a.is_empty()))
    }

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;

        let state = self.state.read().await;

        let Some(diagnostics) = state.get_diagnostics(uri) else {
            return Ok(None);
        };

        let diagnostic = diagnostics.iter().find(|d| position_in_range(position, d.range));

        let Some(diagnostic) = diagnostic else {
            return Ok(None);
        };

        let pattern_id = match &diagnostic.code {
            Some(tower_lsp::lsp_types::NumberOrString::String(s)) => s.as_str(),
            _ => return Ok(None),
        };

        let Some(scanner) = &state.scanner else {
            return Ok(None);
        };

        let Some(pattern) = scanner.get_pattern(pattern_id) else {
            return Ok(None);
        };

        let exposure = determine_exposure_risk(
            &state,
            uri,
            diagnostic.range.start.line,
            diagnostic.range.start.character,
            diagnostic.range.end.character,
        );

        Ok(Some(pattern_hover(pattern, diagnostic.range, exposure)))
    }

    async fn did_change_workspace_folders(&self, params: DidChangeWorkspaceFoldersParams) {
        let mut state = self.state.write().await;

        for removed in &params.event.removed {
            if let Some(path) = try_uri_to_path(&removed.uri) {
                state.workspace_roots.retain(|r| r != &path);
            }
        }

        for added in &params.event.added {
            if let Some(path) = try_uri_to_path(&added.uri)
                && !state.workspace_roots.contains(&path)
            {
                state.workspace_roots.push(path);
            }
        }

        info!("Workspace folders changed: {} root(s)", state.workspace_roots.len());
        drop(state);

        self.reload_config().await;
    }

    async fn did_change_watched_files(&self, params: DidChangeWatchedFilesParams) {
        let config_changed = params
            .changes
            .iter()
            .any(|change| change.uri.path().ends_with(CONFIG_FILENAME));

        let gitignore_changed = params
            .changes
            .iter()
            .any(|change| change.uri.path().ends_with(".gitignore"));

        if config_changed || gitignore_changed {
            debug!("Detected config/gitignore change, reloading...");
            self.reload_config().await;
        }
    }

    async fn did_change_configuration(&self, params: DidChangeConfigurationParams) {
        let Some(settings) = params.settings.as_object() else {
            return;
        };

        let Some(vet_settings) = settings.get("vet") else {
            return;
        };

        let new_include_low = vet_settings
            .get("includeLowConfidence")
            .and_then(serde_json::Value::as_bool);
        let new_respect_gitignore = vet_settings
            .get("respectGitignore")
            .and_then(serde_json::Value::as_bool);

        let documents_to_rescan = {
            let mut state = self.state.write().await;
            let mut needs_rescan = false;

            if let Some(include_low) = new_include_low {
                state.include_low_confidence_override = Some(include_low);
                debug!("Updated includeLowConfidence override: {:?}", include_low);
                needs_rescan = true;
            }

            if let Some(respect_gitignore) = new_respect_gitignore
                && respect_gitignore != state.respect_gitignore
            {
                state.respect_gitignore = respect_gitignore;
                debug!("Updated respectGitignore: {}", state.respect_gitignore);
                needs_rescan = true;
            }

            if needs_rescan {
                state
                    .open_documents
                    .iter()
                    .map(|(uri, doc)| (uri.clone(), doc.content.clone()))
                    .collect()
            } else {
                vec![]
            }
        };

        for (uri, content) in documents_to_rescan {
            self.scan_document(&uri, &content, ScanTrigger::ConfigChange).await;
        }
    }
}

fn determine_exposure_risk(
    state: &ServerState,
    uri: &tower_lsp::lsp_types::Url,
    line: u32,
    start_char: u32,
    end_char: u32,
) -> ExposureRisk {
    let file_path = match try_uri_to_path(uri) {
        Some(p) => p,
        None => {
            debug!("Git check: could not resolve file path");
            return ExposureRisk::Unknown;
        }
    };

    let document = match state.get_document(uri) {
        Some(d) => d,
        None => {
            debug!("Git check: document not found in state");
            return ExposureRisk::Unknown;
        }
    };

    let secret = match document.extract_range(line, start_char, end_char) {
        Some(s) => s,
        None => {
            debug!("Git check: could not extract secret from range");
            return ExposureRisk::Unknown;
        }
    };

    let workspace_root = match state.primary_workspace_root() {
        Some(r) => r,
        None => {
            debug!("Git check: no workspace root");
            return ExposureRisk::Unknown;
        }
    };

    let git_context = match GitContext::discover(workspace_root) {
        Some(ctx) => ctx,
        None => {
            debug!("Git check: not a git repository");
            return ExposureRisk::Unknown;
        }
    };

    let exposure = git_context.check_secret_exposure(&file_path, &secret);

    let filename = file_path.file_name().map(|s| s.to_string_lossy()).unwrap_or_default();

    debug!("Git check: {} -> {:?}", filename, exposure);

    exposure
}

impl VetLanguageServer {
    async fn register_file_watchers(&self) -> std::result::Result<(), tower_lsp::jsonrpc::Error> {
        let watchers = vec![
            FileSystemWatcher {
                glob_pattern: GlobPattern::String("**/.vet.toml".to_string()),
                kind: Some(WatchKind::all()),
            },
            FileSystemWatcher {
                glob_pattern: GlobPattern::String("**/.gitignore".to_string()),
                kind: Some(WatchKind::all()),
            },
        ];

        let registration = Registration {
            id: CONFIG_WATCHER_ID.to_string(),
            method: "workspace/didChangeWatchedFiles".to_string(),
            #[allow(clippy::expect_used)] // Static struct serialization; cannot fail
            register_options: Some(
                serde_json::to_value(DidChangeWatchedFilesRegistrationOptions { watchers })
                    .expect("file watcher options should serialize"),
            ),
        };

        self.client.register_capability(vec![registration]).await
    }

    async fn start_scan_handler(&self) {
        let scan_rx = self.scan_rx.write().await.take();

        let Some(mut rx) = scan_rx else {
            warn!("Scan handler already started");
            return;
        };

        let server = self.clone();

        tokio::spawn(async move {
            while let Some(request) = rx.recv().await {
                server
                    .scan_document(&request.uri, &request.content, ScanTrigger::Debounce)
                    .await;
            }
        });

        debug!("Scan handler started");
    }
}

fn server_capabilities() -> ServerCapabilities {
    ServerCapabilities {
        text_document_sync: Some(TextDocumentSyncCapability::Options(TextDocumentSyncOptions {
            open_close: Some(true),
            change: Some(TextDocumentSyncKind::FULL),
            save: Some(TextDocumentSyncSaveOptions::SaveOptions(SaveOptions {
                include_text: Some(true),
            })),
            ..Default::default()
        })),
        code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
        hover_provider: Some(HoverProviderCapability::Simple(true)),
        workspace: Some(WorkspaceServerCapabilities {
            workspace_folders: Some(WorkspaceFoldersServerCapabilities {
                supported: Some(true),
                change_notifications: Some(OneOf::Left(true)),
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn position_in_range(pos: Position, range: Range) -> bool {
    pos.line >= range.start.line
        && pos.line <= range.end.line
        && (pos.line != range.start.line || pos.character >= range.start.character)
        && (pos.line != range.end.line || pos.character <= range.end.character)
}
