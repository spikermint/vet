//! Scan command - scans files for secrets.

mod context;
mod output;
mod runner;

use std::path::Path;
use std::time::Instant;

use vet_core::prelude::*;

use self::context::{ScanContext, VerboseInfo};
use self::output::{OutputContext, ScanStats, write_output};
use self::runner::{collect_scan_files, run_scan};
use crate::scanning::configure_thread_pool;
use crate::ui::{exit, print_command_header};
use crate::{CONFIG_FILENAME, OutputFormat, ScanArgs};

pub fn run(args: &ScanArgs) -> super::Result {
    configure_thread_pool(args.concurrency)?;

    let show_progress = should_show_progress(args);
    let start = Instant::now();

    if show_progress {
        print_command_header("scan");
    }

    let context = ScanContext::load(args)?;
    let include_low_confidence = args.include_low_confidence || context.config.include_low_confidence;
    let files = collect_scan_files(args, &context.config);

    if show_progress && args.verbose > 0 {
        let info = build_verbose_info(args, &context, files.len());
        context::print_verbose_context(&info, args.verbose);
    }

    if files.is_empty() {
        runner::print_no_files(args.staged);
        return Ok(());
    }

    let max_file_size = args.max_file_size.or(context.config.max_file_size);
    let scan_result = run_scan(&context.scanner, &files, max_file_size, show_progress, args.staged);

    let all_findings_count = scan_result.findings.len();
    let findings = filter_by_confidence(scan_result.findings, include_low_confidence);
    let filtered_count = all_findings_count - findings.len();
    let elapsed = start.elapsed();

    let stats = ScanStats {
        file_count: files.len(),
        elapsed,
        total_findings: all_findings_count,
        filtered_count,
    };

    let ctx = OutputContext {
        findings: &findings,
        patterns: &context.patterns,
        content_cache: &scan_result.content_cache,
        stats,
    };

    write_output(args, &ctx)?;

    handle_exit_code(args, &findings);

    Ok(())
}

const fn should_show_progress(args: &ScanArgs) -> bool {
    args.output.is_none() && matches!(args.format, OutputFormat::Text)
}

fn build_verbose_info(args: &ScanArgs, context: &ScanContext, file_count: usize) -> VerboseInfo {
    VerboseInfo {
        config_path: args
            .config
            .as_deref()
            .unwrap_or(Path::new(CONFIG_FILENAME))
            .to_path_buf(),
        severity: args.severity.or(context.config.severity),
        pattern_count: context.patterns.len(),
        file_count,
        excludes: context.config.exclude_paths.clone(),
        paths: args.paths.clone(),
        max_file_size: args.max_file_size.or(context.config.max_file_size),
    }
}

fn filter_by_confidence(findings: Vec<vet_core::Finding>, include_low_confidence: bool) -> Vec<vet_core::Finding> {
    if include_low_confidence {
        findings
    } else {
        findings
            .into_iter()
            .filter(|f| f.confidence == Confidence::High)
            .collect()
    }
}

fn handle_exit_code(args: &ScanArgs, findings: &[vet_core::Finding]) {
    if args.exit_zero {
        return;
    }

    let high_confidence_count = findings.iter().filter(|f| f.confidence == Confidence::High).count();

    if high_confidence_count > 0 {
        std::process::exit(exit::FINDINGS);
    }
}
