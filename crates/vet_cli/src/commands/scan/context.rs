//! Scan context - configuration and pattern loading.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use vet_core::prelude::*;

use crate::ui::colors;
use crate::{CONFIG_FILENAME, ScanArgs};

pub struct ScanContext {
    pub scanner: Scanner,
    pub patterns: Vec<Pattern>,
    pub config: Config,
}

impl ScanContext {
    pub fn load(args: &ScanArgs) -> anyhow::Result<Self> {
        let config_path = args.config.as_deref().unwrap_or(Path::new(CONFIG_FILENAME));
        let config = Config::load(config_path).context("loading config")?;

        let registry = load_patterns(&config)?;
        let patterns = registry.patterns().to_vec();
        let scanner = build_scanner(registry, &config, args);

        Ok(Self {
            scanner,
            patterns,
            config,
        })
    }
}

fn load_patterns(config: &Config) -> anyhow::Result<PatternRegistry> {
    let mut patterns = PatternRegistry::builtin()?.into_patterns();

    if !config.disabled_patterns.is_empty() {
        let disabled: HashSet<&str> = config.disabled_patterns.iter().map(String::as_str).collect();
        patterns.retain(|p| !disabled.contains(p.id.as_ref()));
    }

    let custom_patterns = config.compile_custom_patterns().context("compiling custom patterns")?;

    patterns.extend(custom_patterns);

    Ok(PatternRegistry::new(patterns))
}

fn build_scanner(registry: PatternRegistry, config: &Config, args: &ScanArgs) -> Scanner {
    let mut scanner = Scanner::new(registry);

    let severity = args.severity.or(config.severity);
    if let Some(severity) = severity {
        scanner = scanner.with_severity_threshold(severity);
    }

    scanner
}

pub struct VerboseInfo {
    pub config_path: PathBuf,
    pub severity: Option<Severity>,
    pub pattern_count: usize,
    pub file_count: usize,
    pub excludes: Vec<String>,
    pub paths: Vec<PathBuf>,
    pub max_file_size: Option<u64>,
}

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
