//! Workspace and configuration management.

use std::path::PathBuf;

use tracing::{info, warn};
use vet_core::CONFIG_FILENAME;
use vet_core::prelude::*;

use super::VetLanguageServer;
use crate::exclusions;

impl VetLanguageServer {
    pub(super) async fn init_scanner(&self) -> bool {
        let Ok(registry) = PatternRegistry::builtin().inspect_err(|e| {
            warn!("Failed to load patterns: {e}");
        }) else {
            return false;
        };

        self.state.write().await.scanner = Some(Scanner::new(registry));
        true
    }

    pub(super) async fn set_workspace_roots(&self, roots: Vec<PathBuf>) {
        let gitignore = roots.first().and_then(|root| {
            exclusions::build_gitignore(root).inspect(|_| info!("Loaded .gitignore from {}", root.display()))
        });

        let mut config = None;
        let mut exclude_matcher = None;

        for root in &roots {
            let config_path = root.join(CONFIG_FILENAME);

            if !config_path.exists() {
                continue;
            }

            match Config::load(&config_path) {
                Ok(loaded_config) => {
                    info!("Loaded config from {}", config_path.display());
                    exclude_matcher = exclusions::build_exclude_matcher(&loaded_config.exclude_paths, root);
                    config = Some(loaded_config);
                    break;
                }
                Err(e) => warn!("Failed to load config from {}: {e}", config_path.display()),
            }
        }

        let mut state = self.state.write().await;
        state.workspace_roots = roots;
        state.gitignore = gitignore;
        state.config = config;
        state.exclude_matcher = exclude_matcher;
    }

    pub(super) async fn reload_config(&self) {
        let mut state = self.state.write().await;
        state.config = None;
        state.exclude_matcher = None;
        state.gitignore = None;

        for root in state.workspace_roots.clone() {
            state.gitignore =
                exclusions::build_gitignore(&root).inspect(|_| info!("Reloaded .gitignore from {}", root.display()));

            let config_path = root.join(CONFIG_FILENAME);

            if !config_path.exists() {
                continue;
            }

            match Config::load(&config_path) {
                Ok(config) => {
                    info!("Reloaded config from {}", config_path.display());
                    state.exclude_matcher = exclusions::build_exclude_matcher(&config.exclude_paths, &root);
                    state.config = Some(config);
                    break;
                }
                Err(e) => warn!("Failed to reload config from {}: {e}", config_path.display()),
            }
        }

        let documents_to_rescan: Vec<_> = state
            .open_documents
            .iter()
            .map(|(uri, doc)| (uri.clone(), doc.content.clone()))
            .collect();

        drop(state);

        info!("Rescanning {} open document(s)", documents_to_rescan.len());
        for (uri, content) in documents_to_rescan {
            self.scan_document(&uri, &content).await;
        }
    }
}
