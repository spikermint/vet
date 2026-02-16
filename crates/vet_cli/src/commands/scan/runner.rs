//! File collection and parallel scanning.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use rayon::prelude::*;
use vet_core::prelude::*;

use crate::ScanArgs;
use crate::files::{collect_files, read_text_file};
use crate::git;
use crate::ui::{colors, create_file_progress};

/// Aggregated results from scanning all files.
#[derive(Debug)]
pub struct ScanResult {
    /// All findings across every scanned file.
    pub findings: Vec<Finding>,
    /// File content keyed by path, retained for verification and output.
    pub content_cache: ContentCache,
}

/// Maps file paths to their text content for post-scan access.
pub type ContentCache = HashMap<PathBuf, String>;

type FileScanResult = (Vec<Finding>, PathBuf, String);

/// Collects files to scan, either from staged git changes or filesystem paths.
#[must_use]
pub fn collect_scan_files(args: &ScanArgs, config: &Config) -> Vec<PathBuf> {
    if args.staged {
        return git::staged_files().unwrap_or_default();
    }

    let all_excludes: Vec<String> = config
        .exclude_paths
        .iter()
        .chain(args.exclude.iter())
        .cloned()
        .collect();

    collect_files(&args.paths, &all_excludes, !args.skip_gitignore)
}

/// Scans all files in parallel using rayon, returning findings and cached content.
#[must_use]
pub fn run_scan(
    scanner: &Scanner,
    files: &[PathBuf],
    max_file_size: Option<u64>,
    show_progress: bool,
    staged: bool,
) -> ScanResult {
    if show_progress {
        scan_with_progress(scanner, files, max_file_size, staged)
    } else {
        scan_quiet(scanner, files, max_file_size, staged)
    }
}

/// Prints a message when no files are available to scan.
pub fn print_no_files(staged: bool) {
    if staged {
        println!("{} no staged files", colors::success().apply_to("✓"));
    } else {
        println!("{} no files to scan", colors::warning().apply_to("●"));
        println!();
        println!("  Check your .gitignore or exclude patterns.");
        println!();
    }
}

fn scan_with_progress(scanner: &Scanner, files: &[PathBuf], max_file_size: Option<u64>, staged: bool) -> ScanResult {
    let pb = create_file_progress(files.len());

    let results: Vec<FileScanResult> = files
        .par_iter()
        .filter_map(|path| {
            let result = scan_file(scanner, path, max_file_size, staged);
            pb.inc(1);
            result
        })
        .collect();

    pb.finish_and_clear();

    aggregate_results(results)
}

fn scan_quiet(scanner: &Scanner, files: &[PathBuf], max_file_size: Option<u64>, staged: bool) -> ScanResult {
    let results: Vec<FileScanResult> = files
        .par_iter()
        .filter_map(|path| scan_file(scanner, path, max_file_size, staged))
        .collect();

    aggregate_results(results)
}

fn scan_file(scanner: &Scanner, path: &Path, max_file_size: Option<u64>, staged: bool) -> Option<FileScanResult> {
    let content = if staged {
        git::staged_content(path)?
    } else {
        read_text_file(path, max_file_size)?
    };

    let findings = scanner.scan_content(&content, path);

    if findings.is_empty() {
        None
    } else {
        Some((findings, path.to_path_buf(), content))
    }
}

fn aggregate_results(results: Vec<FileScanResult>) -> ScanResult {
    let mut findings = Vec::new();
    let mut content_cache = HashMap::new();

    for (file_findings, path, content) in results {
        findings.extend(file_findings);
        content_cache.insert(path, content);
    }

    ScanResult {
        findings,
        content_cache,
    }
}
