//! History scanning and deduplication logic.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use globset::GlobSet;
use rayon::prelude::*;
use vet_core::prelude::*;

use super::{HistoryFinding, HistoryOptions, HistoryScanResult, SecretOccurrence};
use crate::git::{ObjectId, Repo};
use crate::ui::{create_commit_progress, print_warning};

struct RawFinding {
    pattern_id: Arc<str>,
    fingerprint: u64,
    finding: vet_core::Finding,
    occurrence: SecretOccurrence,
}

struct CommitScanResult {
    findings: Vec<RawFinding>,
}

/// Scans git history for secrets, deduplicating by fingerprint and tracking
/// the earliest commit each secret was introduced in.
pub fn scan_history(
    repo: &Repo,
    scanner: &Scanner,
    opts: &HistoryOptions,
    excludes: &GlobSet,
    max_file_size: Option<u64>,
    show_progress: bool,
) -> anyhow::Result<HistoryScanResult> {
    if repo.is_shallow() {
        print_warning(
            "shallow clone detected, history scan limited to available commits\nrun `git fetch --unshallow` for full history\n",
        );
    }

    let commit_ids = repo.collect_commits(opts)?;
    let commits_scanned = commit_ids.len();

    if commits_scanned == 0 {
        return Ok(HistoryScanResult {
            findings: Vec::new(),
            commits_scanned: 0,
        });
    }

    let pb = show_progress.then(|| create_commit_progress(commits_scanned));

    let progress = AtomicUsize::new(0);

    let chunk_size = (commits_scanned / rayon::current_num_threads().max(1)).max(64);

    let chunk_results: Vec<CommitScanResult> = commit_ids
        .par_chunks(chunk_size)
        .flat_map(|chunk| {
            let local_repo = repo.thread_local();
            chunk
                .iter()
                .filter_map(|&oid| {
                    let result = scan_commit_isolated(&local_repo, oid, scanner, excludes, max_file_size);

                    let completed = progress.fetch_add(1, Ordering::Relaxed) + 1;
                    if let Some(ref pb) = pb {
                        pb.set_position(completed as u64);
                    }

                    result
                })
                .collect::<Vec<_>>()
        })
        .collect();

    if let Some(pb) = pb {
        pb.finish_and_clear();
    }

    let mut findings_map: HashMap<(Arc<str>, u64), HistoryFinding> = HashMap::new();

    for result in chunk_results {
        for raw in result.findings {
            let key = (raw.pattern_id, raw.fingerprint);

            match findings_map.entry(key) {
                Entry::Occupied(mut entry) => {
                    let existing = entry.get_mut();
                    existing.occurrence_count += 1;

                    if opts.all {
                        existing.occurrences.push(raw.occurrence.clone());
                    }

                    if raw.occurrence.commit.date < existing.introduced_in.commit.date {
                        existing.introduced_in = raw.occurrence;
                    }
                }
                Entry::Vacant(entry) => {
                    entry.insert(HistoryFinding {
                        finding: raw.finding,
                        introduced_in: raw.occurrence.clone(),
                        occurrences: if opts.all { vec![raw.occurrence] } else { vec![] },
                        occurrence_count: 1,
                    });
                }
            }
        }
    }

    let mut findings: Vec<_> = findings_map.into_values().collect();
    findings.sort_by_key(|f| f.introduced_in.commit.date);

    Ok(HistoryScanResult {
        findings,
        commits_scanned,
    })
}

fn scan_commit_isolated(
    repo: &crate::git::LocalRepo,
    oid: ObjectId,
    scanner: &Scanner,
    excludes: &GlobSet,
    max_file_size: Option<u64>,
) -> Option<CommitScanResult> {
    let commit_info = repo.commit_info(oid)?;
    let commit_info = Arc::new(commit_info);
    let changed_files = repo.commit_changes(oid);

    let mut findings = Vec::new();

    for file in changed_files {
        if excludes.is_match(&file.path) {
            continue;
        }

        let Some(content) = repo.read_blob_as_text(file.blob_id, max_file_size) else {
            continue;
        };

        let file_findings = scanner.scan_content(&content, &file.path);

        for finding in file_findings {
            let line_content = content
                .lines()
                .nth(finding.span.line.saturating_sub(1) as usize)
                .unwrap_or("")
                .to_string();

            let occurrence = SecretOccurrence {
                commit: Arc::clone(&commit_info),
                path: file.path.clone(),
                line: finding.span.line,
                column: finding.span.column,
                line_content,
            };

            findings.push(RawFinding {
                pattern_id: Arc::clone(&finding.pattern_id),
                fingerprint: finding.secret.fingerprint(),
                finding,
                occurrence,
            });
        }
    }

    Some(CommitScanResult { findings })
}
