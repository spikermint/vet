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
    ExecuteCommandParams, FileSystemWatcher, GlobPattern, HoverParams, InitializeParams, InitializeResult,
    InitializedParams, OneOf, Position, Range, Registration, SaveOptions, ServerCapabilities,
    TextDocumentSyncCapability, TextDocumentSyncKind, TextDocumentSyncOptions, TextDocumentSyncSaveOptions, WatchKind,
    WorkspaceFoldersServerCapabilities, WorkspaceServerCapabilities,
};
use tower_lsp::{Client, LanguageServer};
use tracing::{debug, info, warn};
use vet_core::CONFIG_FILENAME;
use vet_core::finding::Confidence;

use crate::code_actions::actions_for_diagnostics;
use crate::debounce::{self, Debouncer, ScanRequest};
use crate::diagnostics::{DiagnosticContext, findings_to_diagnostics_with_context};
use crate::git::{ExposureRisk, GitContext};
use crate::hover::{VetHoverResponse, build_hover_data};
use crate::state::ServerState;
use crate::uri::{extract_workspace_roots, try_uri_to_path};

use scanning::ScanTrigger;

const CONFIG_WATCHER_ID: &str = "config-watcher";

struct IgnoreInConfigParams {
    fingerprint: String,
    pattern_id: String,
    uri: String,
    reason: String,
    workspace_path: String,
}

struct VerifySecretParams {
    finding_id: String,
    pattern_id: String,
    uri: String,
}

fn extract_first_argument(arguments: Option<Vec<serde_json::Value>>) -> Option<serde_json::Value> {
    let args = arguments?;
    if args.is_empty() {
        warn!("No arguments provided to command");
        return None;
    }
    args.into_iter().next()
}

fn extract_ignore_in_config_params(arg: &serde_json::Value) -> Option<IgnoreInConfigParams> {
    let fingerprint = arg.get("fingerprint")?.as_str()?;
    let pattern_id = arg.get("patternId")?.as_str()?;
    let uri = arg.get("uri")?.as_str()?;
    let reason = arg.get("reason")?.as_str()?;
    let workspace_path = arg.get("workspacePath")?.as_str()?;

    if fingerprint.is_empty()
        || pattern_id.is_empty()
        || uri.is_empty()
        || reason.is_empty()
        || workspace_path.is_empty()
    {
        warn!("One or more required fields are empty in ignoreInConfig");
        return None;
    }

    Some(IgnoreInConfigParams {
        fingerprint: fingerprint.to_string(),
        pattern_id: pattern_id.to_string(),
        uri: uri.to_string(),
        reason: reason.to_string(),
        workspace_path: workspace_path.to_string(),
    })
}

fn extract_verify_params(arg: &serde_json::Value) -> Option<VerifySecretParams> {
    let finding_id = arg.get("findingId")?.as_str()?;
    let pattern_id = arg.get("patternId")?.as_str()?;
    let uri = arg.get("uri")?.as_str()?;

    if finding_id.is_empty() || pattern_id.is_empty() || uri.is_empty() {
        warn!("One or more required fields are empty in verifySecret");
        return None;
    }

    Some(VerifySecretParams {
        finding_id: finding_id.to_string(),
        pattern_id: pattern_id.to_string(),
        uri: uri.to_string(),
    })
}

fn parse_minimum_confidence(vet_settings: &serde_json::Value) -> Option<Confidence> {
    match vet_settings
        .get("minimumConfidence")
        .and_then(serde_json::Value::as_str)
    {
        Some("low") => Some(Confidence::Low),
        Some("high") => Some(Confidence::High),
        _ => None,
    }
}

/// The vet language server, providing real-time secret scanning via LSP.
#[derive(Debug, Clone)]
pub struct VetLanguageServer {
    /// Tower-lsp client handle for sending notifications to the editor.
    pub(super) client: Client,
    /// Shared server state behind an async read-write lock.
    pub(super) state: Arc<RwLock<ServerState>>,
    /// Debouncer for throttling document scan requests.
    pub(super) debouncer: Debouncer,
    /// Receiver for debounced scan requests, taken once on initialisation.
    scan_rx: Arc<RwLock<Option<UnboundedReceiver<ScanRequest>>>>,
}

impl VetLanguageServer {
    /// Creates a new server instance bound to the given LSP client.
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

        let new_minimum_confidence = parse_minimum_confidence(vet_settings);
        let new_respect_gitignore = vet_settings
            .get("respectGitignore")
            .and_then(serde_json::Value::as_bool);

        let documents_to_rescan = {
            let mut state = self.state.write().await;
            let mut needs_rescan = false;

            if let Some(minimum) = new_minimum_confidence {
                state.minimum_confidence_override = Some(minimum);
                debug!("Updated minimumConfidence override: {minimum}");
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

    async fn execute_command(&self, params: ExecuteCommandParams) -> Result<Option<serde_json::Value>> {
        match params.command.as_str() {
            "vet.ignoreInConfig" => {
                self.handle_ignore_in_config(Some(params.arguments)).await;
                Ok(None)
            }
            "vet.verifySecret" => {
                let result = self.handle_verify_secret(Some(params.arguments)).await;
                Ok(result.and_then(|r| serde_json::to_value(r).ok()))
            }
            _ => Ok(None),
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
    let Some(file_path) = try_uri_to_path(uri) else {
        debug!("Git check: could not resolve file path");
        return ExposureRisk::Unknown;
    };

    let Some(document) = state.get_document(uri) else {
        debug!("Git check: document not found in state");
        return ExposureRisk::Unknown;
    };

    let Some(secret) = document.extract_range(line, start_char, end_char) else {
        debug!("Git check: could not extract secret from range");
        return ExposureRisk::Unknown;
    };

    let Some(workspace_root) = state.primary_workspace_root() else {
        debug!("Git check: no workspace root");
        return ExposureRisk::Unknown;
    };

    let Some(git_context) = GitContext::discover(workspace_root) else {
        debug!("Git check: not a git repository");
        return ExposureRisk::Unknown;
    };

    let exposure = git_context.check_secret_exposure(&file_path, &secret);

    let filename = file_path
        .file_name()
        .map_or_else(std::borrow::Cow::default, |s| s.to_string_lossy());

    debug!("Git check: {filename} -> {exposure:?}");

    exposure
}

impl VetLanguageServer {
    async fn handle_ignore_in_config(&self, arguments: Option<Vec<serde_json::Value>>) {
        let Some(arg) = extract_first_argument(arguments) else {
            warn!("No arguments provided to ignoreInConfig command");
            return;
        };

        let Some(params) = extract_ignore_in_config_params(&arg) else {
            warn!("Invalid parameters for ignoreInConfig command");
            return;
        };

        let config_path = std::path::PathBuf::from(&params.workspace_path).join(CONFIG_FILENAME);

        let mut config = if config_path.exists() {
            match vet_core::Config::load(&config_path) {
                Ok(c) => c,
                Err(e) => {
                    warn!("Failed to load config: {e}");
                    return;
                }
            }
        } else {
            vet_core::Config::new()
        };

        let file = params
            .uri
            .parse::<tower_lsp::lsp_types::Url>()
            .ok()
            .and_then(|uri| try_uri_to_path(&uri))
            .and_then(|path| {
                let workspace = std::path::Path::new(&params.workspace_path);
                path.strip_prefix(workspace).ok().map(|p| p.display().to_string())
            })
            .unwrap_or_else(|| params.uri.clone());

        config.ignores.push(vet_core::ConfigIgnore {
            fingerprint: params.fingerprint.clone(),
            pattern_id: params.pattern_id,
            file,
            reason: params.reason,
        });

        if let Err(e) = config.save(&config_path) {
            warn!("Failed to save config: {e}");
            return;
        }

        info!("Added ignore to config: {}", params.fingerprint);

        self.reload_config().await;
    }

    async fn handle_verify_secret(
        &self,
        arguments: Option<Vec<serde_json::Value>>,
    ) -> Option<vet_providers::VerificationResult> {
        let Some(arg) = extract_first_argument(arguments) else {
            warn!("No arguments provided to verifySecret command");
            return None;
        };

        let Some(params) = extract_verify_params(&arg) else {
            warn!("Invalid parameters for verifySecret command");
            return None;
        };

        let Ok(uri) = params.uri.parse::<tower_lsp::lsp_types::Url>() else {
            warn!("Invalid URI: {}", params.uri);
            return None;
        };

        {
            let state = self.state.read().await;

            if let Some(cached) = state.verification.get_cached(&params.finding_id) {
                debug!("Verification cache hit for {}", params.finding_id);
                let result = cached.result.clone();
                drop(state);
                self.republish_diagnostics_for_uri(&uri).await;
                return Some(result);
            }

            let registry_supports = state
                .verification
                .registry
                .as_ref()
                .is_some_and(|r| r.supports_verification(&params.pattern_id));

            if !registry_supports {
                warn!("Pattern not supported for verification: {}", params.pattern_id);
                return None;
            }
        }

        {
            let mut state = self.state.write().await;
            if !state.verification.mark_pending(params.finding_id.clone()) {
                debug!("Verification already in progress for {}", params.finding_id);
                return None;
            }
        }

        let secret = {
            let state = self.state.read().await;
            let diagnostics = state.get_diagnostics(&uri)?;
            let diagnostic = diagnostics.iter().find(|d| {
                d.data
                    .as_ref()
                    .and_then(|data| data.get("findingId"))
                    .and_then(|v| v.as_str())
                    == Some(&params.finding_id)
            })?;

            let document = state.get_document(&uri)?;
            document.extract_range(
                diagnostic.range.start.line,
                diagnostic.range.start.character,
                diagnostic.range.end.character,
            )
        };

        let Some(secret) = secret else {
            warn!(
                "Could not extract secret from document for finding: {}",
                params.finding_id
            );
            self.state.write().await.verification.clear_pending(&params.finding_id);
            return None;
        };

        info!("Verifying secret for finding: {}", params.finding_id);

        let verification_result = {
            let state = self.state.read().await;
            let Some(registry) = &state.verification.registry else {
                warn!("Verifier registry not initialized");
                drop(state);
                self.state.write().await.verification.clear_pending(&params.finding_id);
                return None;
            };
            registry.verify(&secret, &params.pattern_id).await
        };

        match verification_result {
            Ok(result) => {
                info!("Verification result for {}: {:?}", params.finding_id, result.status);

                self.state
                    .write()
                    .await
                    .verification
                    .insert_result(&params.finding_id, result.clone());

                self.republish_diagnostics_for_uri(&uri).await;
                Some(result)
            }
            Err(e) => {
                warn!("Verification failed for {}: {e}", params.finding_id);
                self.state.write().await.verification.clear_pending(&params.finding_id);
                None
            }
        }
    }

    /// Handles the custom `vet/hoverData` request.
    pub async fn handle_hover_data(&self, params: HoverParams) -> Result<Option<VetHoverResponse>> {
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

        let verification = diagnostic
            .data
            .as_ref()
            .and_then(|d| d.get("findingId"))
            .and_then(|v| v.as_str())
            .and_then(|fid| state.verification.get_cached(fid))
            .map(|c| &c.result);

        let data = build_hover_data(pattern, exposure, verification);

        Ok(Some(VetHoverResponse {
            data,
            range: Some(diagnostic.range),
        }))
    }

    /// Re-scans a document and publishes updated diagnostics for the given URI.
    pub(super) async fn republish_diagnostics_for_uri(&self, uri: &tower_lsp::lsp_types::Url) {
        let state = self.state.read().await;

        let Some(document) = state.get_document(uri) else {
            debug!("Document not found for republish: {uri}");
            return;
        };

        let Some(scanner) = &state.scanner else {
            return;
        };

        let file_path = try_uri_to_path(uri).unwrap_or_else(|| std::path::PathBuf::from(uri.path()));
        let findings = scanner.scan_content(&document.content, &file_path);
        let minimum_confidence = state.minimum_confidence();
        let filtered = crate::diagnostics::filter_by_confidence(findings, minimum_confidence);

        let filtered = if let Some(matcher) = &state.ignore_matcher {
            filtered
                .into_iter()
                .filter(|f| !matcher.is_ignored(&f.baseline_fingerprint()))
                .collect()
        } else {
            filtered
        };

        let context = DiagnosticContext {
            verifier_registry: state.verification.registry.as_ref(),
            verification_cache: &state.verification.cache,
        };

        let diagnostics = findings_to_diagnostics_with_context(&filtered, &context);

        drop(state);

        self.state
            .write()
            .await
            .diagnostics
            .insert(uri.clone(), diagnostics.clone());
        self.client.publish_diagnostics(uri.clone(), diagnostics, None).await;
    }

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
            #[expect(clippy::expect_used, reason = "static struct serialization cannot fail")]
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

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests use expect for clearer failure messages")]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extract_verify_params_valid_input() {
        let arg = json!({
            "findingId": "abc123",
            "patternId": "vcs/github-pat",
            "uri": "file:///test.ts"
        });

        let params = extract_verify_params(&arg).expect("should parse");
        assert_eq!(params.finding_id, "abc123");
        assert_eq!(params.pattern_id, "vcs/github-pat");
        assert_eq!(params.uri, "file:///test.ts");
    }

    #[test]
    fn extract_verify_params_missing_finding_id() {
        let arg = json!({
            "patternId": "vcs/github-pat",
            "uri": "file:///test.ts"
        });

        assert!(extract_verify_params(&arg).is_none());
    }

    #[test]
    fn extract_verify_params_missing_pattern_id() {
        let arg = json!({
            "findingId": "abc123",
            "uri": "file:///test.ts"
        });

        assert!(extract_verify_params(&arg).is_none());
    }

    #[test]
    fn extract_verify_params_missing_uri() {
        let arg = json!({
            "findingId": "abc123",
            "patternId": "vcs/github-pat"
        });

        assert!(extract_verify_params(&arg).is_none());
    }

    #[test]
    fn extract_verify_params_empty_finding_id() {
        let arg = json!({
            "findingId": "",
            "patternId": "vcs/github-pat",
            "uri": "file:///test.ts"
        });

        assert!(extract_verify_params(&arg).is_none());
    }

    #[test]
    fn extract_verify_params_empty_pattern_id() {
        let arg = json!({
            "findingId": "abc123",
            "patternId": "",
            "uri": "file:///test.ts"
        });

        assert!(extract_verify_params(&arg).is_none());
    }

    #[test]
    fn extract_verify_params_empty_uri() {
        let arg = json!({
            "findingId": "abc123",
            "patternId": "vcs/github-pat",
            "uri": ""
        });

        assert!(extract_verify_params(&arg).is_none());
    }

    #[test]
    fn extract_verify_params_wrong_type() {
        let arg = json!({
            "findingId": 123,
            "patternId": "vcs/github-pat",
            "uri": "file:///test.ts"
        });

        assert!(extract_verify_params(&arg).is_none());
    }

    #[test]
    fn extract_first_argument_returns_first() {
        let args = Some(vec![json!({"a": 1}), json!({"b": 2})]);
        let arg = extract_first_argument(args).expect("should extract");
        assert_eq!(arg, json!({"a": 1}));
    }

    #[test]
    fn extract_first_argument_returns_none_for_empty() {
        let args: Option<Vec<serde_json::Value>> = Some(vec![]);
        assert!(extract_first_argument(args).is_none());
    }

    #[test]
    fn extract_first_argument_returns_none_for_none() {
        assert!(extract_first_argument(None).is_none());
    }

    #[test]
    fn position_in_range_start_of_range() {
        let pos = Position::new(5, 10);
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        assert!(position_in_range(pos, range));
    }

    #[test]
    fn position_in_range_end_of_range() {
        let pos = Position::new(5, 20);
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        assert!(position_in_range(pos, range));
    }

    #[test]
    fn position_in_range_middle() {
        let pos = Position::new(5, 15);
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        assert!(position_in_range(pos, range));
    }

    #[test]
    fn position_in_range_before_range() {
        let pos = Position::new(5, 5);
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        assert!(!position_in_range(pos, range));
    }

    #[test]
    fn position_in_range_after_range() {
        let pos = Position::new(5, 25);
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        assert!(!position_in_range(pos, range));
    }

    #[test]
    fn position_in_range_multiline() {
        let pos = Position::new(6, 5);
        let range = Range::new(Position::new(5, 10), Position::new(7, 20));
        assert!(position_in_range(pos, range));
    }

    #[test]
    fn position_in_range_before_start_line() {
        let pos = Position::new(4, 15);
        let range = Range::new(Position::new(5, 10), Position::new(7, 20));
        assert!(!position_in_range(pos, range));
    }

    #[test]
    fn position_in_range_after_end_line() {
        let pos = Position::new(8, 15);
        let range = Range::new(Position::new(5, 10), Position::new(7, 20));
        assert!(!position_in_range(pos, range));
    }
}
