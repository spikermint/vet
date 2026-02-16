//! Scan command - scans files for secrets.

mod context;
mod output;
mod runner;

use std::path::Path;
use std::time::Instant;

use vet_core::prelude::*;
use vet_providers::{ProviderRegistry, VerificationResult, VerificationStatus};

use self::context::{ScanContext, VerboseInfo};
use self::output::{OutputContext, ScanStats, VerificationMap, write_output};
use self::runner::{ContentCache, collect_scan_files, run_scan};
use crate::scanning::configure_thread_pool;
use crate::ui::{colors, exit, print_command_header};
use crate::{CONFIG_FILENAME, OutputFormat, ScanArgs};

/// Executes the `vet scan` command.
pub fn run(args: &ScanArgs) -> super::Result {
    configure_thread_pool(args.concurrency)?;

    let show_progress = should_show_progress(args);
    let start = Instant::now();

    if show_progress {
        print_command_header("scan");
    }

    let context = ScanContext::load(args)?;
    let minimum_confidence = args.minimum_confidence.unwrap_or(context.config.minimum_confidence);
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

    let (findings_after_baseline, baseline_count) =
        filter_by_baseline(scan_result.findings, args.baseline.as_deref(), &context.config)?;

    let findings = filter_by_confidence(findings_after_baseline, minimum_confidence);
    let filtered_count = all_findings_count - findings.len() - baseline_count;

    let verifications = if args.verify {
        Some(run_verification(&findings, &scan_result.content_cache, show_progress)?)
    } else {
        None
    };

    let elapsed = start.elapsed();

    let stats = ScanStats {
        file_count: files.len(),
        elapsed,
        total_findings: all_findings_count,
        filtered_count,
        baseline_count,
    };

    let ctx = OutputContext {
        findings: &findings,
        patterns: &context.patterns,
        content_cache: &scan_result.content_cache,
        stats,
        verifications: verifications.as_ref(),
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

fn filter_by_confidence(findings: Vec<Finding>, minimum: Confidence) -> Vec<Finding> {
    findings.into_iter().filter(|f| f.confidence >= minimum).collect()
}

fn filter_by_baseline(
    findings: Vec<vet_core::Finding>,
    baseline_path: Option<&Path>,
    config: &Config,
) -> super::Result<(Vec<vet_core::Finding>, usize)> {
    let explicit_baseline = baseline_path;
    let baseline_path = baseline_path.or_else(|| config.baseline_path.as_deref().map(Path::new));

    let baseline = match baseline_path {
        None => {
            // No baseline configured, but still apply config ignores
            if config.ignores.is_empty() {
                return Ok((findings, 0));
            }
            None
        }
        Some(path) => {
            if path.exists() {
                Some(Baseline::load(path)?)
            } else {
                // Error if explicitly provided via --baseline flag
                if explicit_baseline.is_some() {
                    anyhow::bail!("baseline file not found: {}", path.display());
                }
                // No baseline file, but still apply config ignores
                if config.ignores.is_empty() {
                    return Ok((findings, 0));
                }
                None
            }
        }
    };

    let matcher = IgnoreMatcher::new(baseline.as_ref(), &config.ignores);

    let mut filtered_findings = Vec::new();
    let mut baseline_count = 0;

    for finding in findings {
        if matcher.is_ignored(&finding.baseline_fingerprint()) {
            baseline_count += 1;
        } else {
            filtered_findings.push(finding);
        }
    }

    Ok((filtered_findings, baseline_count))
}

fn handle_exit_code(args: &ScanArgs, findings: &[vet_core::Finding]) {
    if args.exit_zero || args.allow_new {
        return;
    }

    let high_confidence_count = findings.iter().filter(|f| f.confidence == Confidence::High).count();

    if high_confidence_count > 0 {
        std::process::exit(exit::FINDINGS);
    }
}

fn run_verification(
    findings: &[Finding],
    content_cache: &ContentCache,
    show_progress: bool,
) -> anyhow::Result<VerificationMap> {
    if findings.is_empty() {
        return Ok(VerificationMap::new());
    }

    let registry =
        ProviderRegistry::with_verification().map_err(|e| anyhow::anyhow!("failed to initialize verifier: {e}"))?;
    let total = findings.len();

    if show_progress {
        println!(
            "{} verifying {} {} against live services...",
            colors::info().apply_to("ℹ"),
            total,
            if total == 1 { "secret" } else { "secrets" }
        );
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("failed to create async runtime: {e}"))?;

    let results: VerificationMap = rt.block_on(async {
        let mut map = VerificationMap::new();

        for (idx, finding) in findings.iter().enumerate() {
            let is_supported = registry.supports_verification(&finding.pattern_id);

            if !is_supported {
                if show_progress {
                    print_verification_progress(idx + 1, total, &finding.pattern_id, None);
                }
                continue;
            }

            let raw_secret = content_cache
                .get(finding.path.as_ref())
                .and_then(|content| content.get(finding.span.byte_start..finding.span.byte_end));

            if let Some(secret) = raw_secret {
                let result = match registry.verify(secret, &finding.pattern_id).await {
                    Ok(result) => result,
                    Err(e) => VerificationResult::inconclusive(&e.to_string()),
                };

                if show_progress {
                    print_verification_progress(idx + 1, total, &finding.pattern_id, Some(&result.status));
                }
                map.insert(finding.id.as_str().to_string(), result);
            }
        }

        map
    });

    if show_progress {
        println!();
    }

    Ok(results)
}

fn print_verification_progress(idx: usize, total: usize, pattern_id: &str, status: Option<&VerificationStatus>) {
    let counter = format!("[{idx}/{total}]");
    let prefix = format!("  {counter} ");
    let prefix_len = prefix.chars().count();

    let pattern_display = pattern_id;
    let pattern_len = pattern_display.chars().count();

    let result_col: usize = 50;
    let available_for_dots = result_col.saturating_sub(prefix_len + pattern_len + 1);
    let dots = " ".to_string() + &"·".repeat(available_for_dots);

    let status_display = match status {
        Some(VerificationStatus::Live) => format!("{}", colors::error().bold().apply_to("LIVE")),
        Some(VerificationStatus::Inactive) => format!("{}", colors::success().apply_to("inactive")),
        Some(VerificationStatus::Inconclusive) => format!("{}", colors::warning().apply_to("inconclusive")),
        None => format!("{}", colors::muted().apply_to("skipped")),
    };

    println!(
        "{}{}{}{}",
        prefix,
        colors::secondary().apply_to(pattern_display),
        colors::muted().apply_to(dots),
        status_display
    );
}
