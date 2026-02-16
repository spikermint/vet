//! History command - scans git history for secrets.

mod context;
mod output;
mod scanner;
mod types;

pub use scanner::scan_history;
pub use types::*;

use std::time::Instant;

use self::context::HistoryContext;
use self::output::{HistoryStats, OutputContext};
use crate::git::Repo;
use crate::scanning::configure_thread_pool;
use crate::ui::{exit, print_command_header};
use crate::{HistoryArgs, OutputFormat};

pub use crate::git::CommitInfo;

/// Executes the `vet history` command.
pub fn run(args: &HistoryArgs) -> super::Result {
    configure_thread_pool(args.concurrency)?;

    let show_progress = should_show_progress(args);
    let start = Instant::now();

    if show_progress {
        print_command_header("history");
    }

    let repo = Repo::open_cwd().ok_or_else(|| anyhow::anyhow!("not a git repository"))?;

    let context = HistoryContext::load(args)?;

    let options = HistoryOptions {
        limit: args.limit,
        since: args.since.clone(),
        until: args.until.clone(),
        branch: args.branch.clone(),
        first_parent: args.first_parent,
        all: args.all,
    };

    let excludes = context.build_excludes(&args.exclude);
    let max_file_size = context.max_file_size(args.max_file_size);

    let result = scan_history(
        &repo,
        &context.scanner,
        &options,
        &excludes,
        max_file_size,
        show_progress,
    )?;

    let elapsed = start.elapsed();

    let minimum_confidence = context.minimum_confidence(args.minimum_confidence);
    let findings: Vec<_> = result
        .findings
        .into_iter()
        .filter(|f| f.finding.confidence >= minimum_confidence)
        .collect();

    let total_occurrences: usize = findings.iter().map(|f| f.occurrence_count).sum();

    let stats = HistoryStats {
        commits_scanned: result.commits_scanned,
        secrets_found: findings.len(),
        total_occurrences,
        elapsed,
    };

    let ctx = OutputContext {
        findings: &findings,
        patterns: &context.patterns,
        stats,
        all: args.all,
    };

    output::write_output(args, &ctx)?;

    if !args.exit_zero && !findings.is_empty() {
        std::process::exit(exit::FINDINGS);
    }

    Ok(())
}

fn should_show_progress(args: &HistoryArgs) -> bool {
    args.output.is_none() && matches!(args.format, OutputFormat::Text)
}
