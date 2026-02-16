//! Scan context - configuration and pattern loading.

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use vet_core::prelude::*;

use crate::scanning::{build_scanner, load_patterns};
use crate::ui::colors;
use crate::{CONFIG_FILENAME, ScanArgs};

/// Loaded scanner, patterns, and configuration for a scan run.
#[derive(Debug)]
pub struct ScanContext {
    /// The compiled secret scanner.
    pub scanner: Scanner,
    /// All loaded detection patterns.
    pub patterns: Vec<Pattern>,
    /// Parsed configuration from `.vet.toml`.
    pub config: Config,
}

impl ScanContext {
    /// Loads configuration, patterns, and builds the scanner from CLI arguments.
    pub fn load(args: &ScanArgs) -> anyhow::Result<Self> {
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
}

/// Data collected for verbose output display.
#[derive(Debug)]
pub struct VerboseInfo {
    /// Path to the configuration file.
    pub config_path: PathBuf,
    /// Active severity filter, if any.
    pub severity: Option<Severity>,
    /// Number of loaded patterns.
    pub pattern_count: usize,
    /// Number of files to scan.
    pub file_count: usize,
    /// Active exclude glob patterns.
    pub excludes: Vec<String>,
    /// Paths being scanned.
    pub paths: Vec<PathBuf>,
    /// Maximum file size limit in bytes.
    pub max_file_size: Option<u64>,
}

/// Prints verbose scan context to the terminal.
pub fn print_verbose_context(info: &VerboseInfo, level: u8) {
    let severity_str = info
        .severity
        .map_or_else(|| "all".to_string(), |s| s.to_string().to_lowercase());

    let context_line = format!(
        "{} · {} · {} patterns · {} files",
        info.config_path.display(),
        severity_str,
        info.pattern_count,
        info.file_count
    );

    println!("{}", colors::muted().apply_to(&context_line));

    if level >= 2 {
        print_verbose_details(info);
    }

    println!();
}

fn print_verbose_details(info: &VerboseInfo) {
    if !info.excludes.is_empty() {
        println!(
            "  {}",
            colors::muted().apply_to(format!("exclude {}", info.excludes.join(" ")))
        );
    }

    if let Some(max_size) = info.max_file_size {
        println!(
            "  {}",
            colors::muted().apply_to(format!("max {}", format_file_size(max_size)))
        );
    }

    let paths: Vec<_> = info.paths.iter().map(|p| p.display().to_string()).collect();
    println!("  {}", colors::muted().apply_to(format!("paths {}", paths.join(" "))));
}

fn format_file_size(bytes: u64) -> String {
    if bytes >= 1_048_576 {
        format!("{}MB", bytes / 1_048_576)
    } else if bytes >= 1024 {
        format!("{}KB", bytes / 1024)
    } else {
        format!("{bytes}B")
    }
}
