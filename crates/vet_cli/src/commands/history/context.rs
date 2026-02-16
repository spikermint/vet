//! History context - configuration and pattern loading.

use std::path::Path;

use anyhow::Context as _;
use globset::{Glob, GlobSet, GlobSetBuilder};
use vet_core::prelude::*;

use crate::scanning::{build_scanner, load_patterns};
use crate::{CONFIG_FILENAME, HistoryArgs};

/// Loaded scanner, patterns, and configuration for a history scan.
#[derive(Debug)]
pub struct HistoryContext {
    /// The compiled secret scanner.
    pub scanner: Scanner,
    /// All loaded detection patterns.
    pub patterns: Vec<Pattern>,
    /// Parsed configuration from `.vet.toml`.
    pub config: Config,
}

impl HistoryContext {
    /// Loads configuration, patterns, and builds the scanner from CLI arguments.
    pub fn load(args: &HistoryArgs) -> anyhow::Result<Self> {
        let config_path = args.config.as_deref().unwrap_or(Path::new(CONFIG_FILENAME));
        let config = Config::load(config_path).context("loading config")?;

        let registry = load_patterns(&config)?;
        let patterns = registry.patterns().to_vec();
        let severity = args.severity.or(config.severity);
        let scanner = build_scanner(registry, severity);

        Ok(Self {
            scanner,
            patterns,
            config,
        })
    }

    /// Merges config and CLI exclude patterns into a compiled glob set.
    pub fn build_excludes(&self, arg_excludes: &[String]) -> GlobSet {
        build_excludes(&self.config.exclude_paths, arg_excludes)
    }

    /// Returns the effective max file size, preferring the CLI argument over config.
    pub fn max_file_size(&self, arg_max: Option<u64>) -> Option<u64> {
        arg_max.or(self.config.max_file_size)
    }

    /// Returns the effective minimum confidence level, preferring the CLI argument.
    pub fn minimum_confidence(&self, arg_minimum: Option<Confidence>) -> Confidence {
        arg_minimum.unwrap_or(self.config.minimum_confidence)
    }
}

fn build_excludes(config_excludes: &[String], arg_excludes: &[String]) -> GlobSet {
    let mut builder = GlobSetBuilder::new();

    for pattern in config_excludes.iter().chain(arg_excludes.iter()) {
        match Glob::new(pattern) {
            Ok(glob) => {
                builder.add(glob);
            }
            Err(e) => {
                crate::ui::print_warning(&format!("invalid exclude pattern '{pattern}': {e}"));
            }
        }
    }

    builder.build().unwrap_or_else(|_| GlobSet::empty())
}
