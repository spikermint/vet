//! Workspace and configuration management.

use std::path::PathBuf;

use tracing::{debug, info, warn};
use vet_core::CONFIG_FILENAME;
use vet_core::prelude::*;
use vet_providers::ProviderRegistry;

use super::VetLanguageServer;
use super::scanning::ScanTrigger;
use crate::exclusions;

impl VetLanguageServer {
    /// Initialises the pattern scanner and verification registry.
    ///
    /// Returns `true` if the scanner was loaded successfully.
    pub(super) async fn init_scanner(&self) -> bool {
        let registry = match PatternRegistry::builtin() {
            Ok(r) => r,
            Err(e) => {
                warn!("Failed to load patterns: {e}");
                return false;
            }
        };

        let pattern_count = registry.patterns().len();
        info!("Loaded {pattern_count} patterns");

        let verifier_registry = match ProviderRegistry::with_verification() {
            Ok(r) => {
                info!("Loaded {} verifiable pattern(s)", r.verifiable_patterns().count());
                Some(r)
            }
            Err(e) => {
                warn!("Failed to initialize verifier registry: {e}");
                None
            }
        };

        let mut state = self.state.write().await;
        state.scanner = Some(Scanner::new(registry));
        state.verification.registry = verifier_registry;
        true
    }

    /// Configures workspace roots, loading gitignore rules, config, and baseline.
    pub(super) async fn set_workspace_roots(&self, roots: Vec<PathBuf>) {
        for root in &roots {
            info!("Workspace root: {}", root.display());
        }

        let gitignore = roots.first().and_then(|root| {
            exclusions::build_gitignore(root).inspect(|_| {
                info!("Loaded .gitignore from {}", root.display());
            })
        });

        if gitignore.is_none() && !roots.is_empty() {
            debug!("No .gitignore found");
        }

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

                    if !loaded_config.exclude_paths.is_empty() {
                        debug!("Excluding {} path pattern(s)", loaded_config.exclude_paths.len());
                    }

                    exclude_matcher = exclusions::build_exclude_matcher(&loaded_config.exclude_paths, root);
                    config = Some(loaded_config);
                    break;
                }
                Err(e) => warn!("Failed to load config from {}: {e}", config_path.display()),
            }
        }

        if config.is_none() && !roots.is_empty() {
            debug!("No {} found, using defaults", CONFIG_FILENAME);
        }

        let (baseline, ignore_matcher) = load_baseline_and_matcher(config.as_ref(), &roots);

        let mut state = self.state.write().await;
        state.workspace_roots = roots;
        state.gitignore = gitignore;
        state.config = config;
        state.exclude_matcher = exclude_matcher;
        state.baseline = baseline;
        state.ignore_matcher = ignore_matcher;
    }

    /// Reloads configuration from disk and rescans all open documents.
    pub(super) async fn reload_config(&self) {
        info!("Reloading configuration...");

        let mut state = self.state.write().await;
        state.config = None;
        state.exclude_matcher = None;
        state.gitignore = None;
        state.baseline = None;
        state.ignore_matcher = None;

        for root in state.workspace_roots.clone() {
            state.gitignore = exclusions::build_gitignore(&root).inspect(|_| {
                info!("Reloaded .gitignore from {}", root.display());
            });

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

        let (baseline, ignore_matcher) = load_baseline_and_matcher(state.config.as_ref(), &state.workspace_roots);
        state.baseline = baseline;
        state.ignore_matcher = ignore_matcher;

        let documents_to_rescan: Vec<_> = state
            .open_documents
            .iter()
            .map(|(uri, doc)| (uri.clone(), doc.content.clone()))
            .collect();

        drop(state);

        info!("Rescanning {} open document(s)", documents_to_rescan.len());

        for (uri, content) in documents_to_rescan {
            self.scan_document(&uri, &content, ScanTrigger::ConfigChange).await;
        }
    }
}

fn load_baseline_and_matcher(config: Option<&Config>, roots: &[PathBuf]) -> (Option<Baseline>, Option<IgnoreMatcher>) {
    let Some(config) = config else {
        return (None, None);
    };

    let baseline_path = if let Some(path) = &config.baseline_path {
        let path = std::path::Path::new(path);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            let Some(root) = roots.first() else {
                if !config.ignores.is_empty() {
                    let matcher = IgnoreMatcher::new(None, &config.ignores);
                    return (None, Some(matcher));
                }
                return (None, None);
            };
            root.join(path)
        }
    } else {
        if !config.ignores.is_empty() {
            let matcher = IgnoreMatcher::new(None, &config.ignores);
            return (None, Some(matcher));
        }
        return (None, None);
    };

    if !baseline_path.exists() {
        debug!("Baseline file not found: {}", baseline_path.display());
        // Baseline file doesn't exist, but still create matcher for config ignores
        if !config.ignores.is_empty() {
            let matcher = IgnoreMatcher::new(None, &config.ignores);
            return (None, Some(matcher));
        }
        return (None, None);
    }

    match Baseline::load(&baseline_path) {
        Ok(baseline) => {
            info!("Loaded baseline from {}", baseline_path.display());
            let matcher = IgnoreMatcher::new(Some(&baseline), &config.ignores);
            (Some(baseline), Some(matcher))
        }
        Err(e) => {
            warn!("Failed to load baseline from {}: {e}", baseline_path.display());
            // Baseline failed to load, but still create matcher for config ignores
            if !config.ignores.is_empty() {
                let matcher = IgnoreMatcher::new(None, &config.ignores);
                return (None, Some(matcher));
            }
            (None, None)
        }
    }
}
