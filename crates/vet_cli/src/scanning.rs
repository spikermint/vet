//! Pattern loading and scanner construction.

use std::collections::HashSet;

use anyhow::Context as _;
use vet_core::prelude::*;

/// Loads built-in patterns, removes any disabled by configuration, and merges
/// in user-defined custom patterns.
pub fn load_patterns(config: &Config) -> anyhow::Result<PatternRegistry> {
    let mut patterns = PatternRegistry::builtin()?.into_patterns();

    if !config.disabled_patterns.is_empty() {
        let disabled: HashSet<&str> = config.disabled_patterns.iter().map(String::as_str).collect();
        patterns.retain(|p| !disabled.contains(p.id.as_ref()));
    }

    let custom = config.compile_custom_patterns().context("compiling custom patterns")?;
    patterns.extend(custom);

    Ok(PatternRegistry::new(patterns))
}

/// Builds a `Scanner` from a registry, optionally applying a minimum
/// severity threshold.
#[must_use]
pub fn build_scanner(registry: PatternRegistry, severity: Option<Severity>) -> Scanner {
    let mut scanner = Scanner::new(registry);

    if let Some(severity) = severity {
        scanner = scanner.with_severity_threshold(severity);
    }

    scanner
}

/// Configures the global rayon thread pool with the requested number of
/// threads, if specified.
pub fn configure_thread_pool(concurrency: Option<usize>) -> anyhow::Result<()> {
    if let Some(n) = concurrency {
        rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .build_global()
            .context("failed to configure thread pool")?;
    }
    Ok(())
}
