//! # Commands
//!
//! - `vet scan` - Scan files for secrets
//! - `vet fix` - Interactively fix detected secrets
//! - `vet history` - Scan commits in git repository for secrets
//! - `vet init` - Create configuration file
//! - `vet hook` - Manage git pre-commit hooks
//! - `vet patterns` - List detection patterns

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod commands;
mod files;
mod git;
mod scanning;
mod ui;

use std::path::PathBuf;

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use console::style;
pub use vet_core::CONFIG_FILENAME;
use vet_core::prelude::*;

use crate::ui::colors;

fn parse_confidence(s: &str) -> Result<Confidence, String> {
    match s.to_lowercase().as_str() {
        "low" => Ok(Confidence::Low),
        "high" => Ok(Confidence::High),
        _ => Err(format!("invalid confidence level '{s}' (expected 'low' or 'high')")),
    }
}

const REPO_URL: &str = "https://github.com/spikermint/vet";

#[derive(Debug, Parser)]
#[command(
    name = "vet",
    version,
    styles = ui::clap_styles(),
    arg_required_else_help = true,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(visible_alias = "s")]
    Scan(ScanArgs),

    #[command(visible_alias = "f")]
    Fix(FixArgs),

    #[command(visible_alias = "p")]
    Patterns(PatternsArgs),

    Init(InitArgs),

    #[command(visible_alias = "h")]
    History(HistoryArgs),

    #[command(visible_alias = "b")]
    Baseline(BaselineArgs),

    Hook {
        #[command(subcommand)]
        command: Option<HookCommand>,
    },
}

/// Output format for scan and history results.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// Human-readable terminal output.
    #[default]
    Text,
    /// Machine-readable JSON.
    Json,
    /// SARIF (Static Analysis Results Interchange Format).
    Sarif,
}

/// Arguments for the `vet scan` command.
#[derive(Debug, Parser)]
pub struct ScanArgs {
    /// Paths to scan for secrets.
    #[arg(default_value = ".")]
    pub paths: Vec<PathBuf>,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t)]
    pub format: OutputFormat,

    /// Write output to a file instead of stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Path to `.vet.toml` configuration file.
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Minimum severity level to report.
    #[arg(short, long)]
    pub severity: Option<Severity>,

    /// Increase output verbosity (repeat for more detail).
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Minimum confidence level to report (low or high).
    #[arg(long, value_parser = parse_confidence)]
    pub minimum_confidence: Option<Confidence>,

    /// Always exit with code 0, even when secrets are found.
    #[arg(long)]
    pub exit_zero: bool,

    /// Glob patterns to exclude from scanning.
    #[arg(short, long)]
    pub exclude: Vec<String>,

    /// Skip `.gitignore` rules when collecting files.
    #[arg(long)]
    pub skip_gitignore: bool,

    /// Skip files larger than this size in bytes.
    #[arg(long)]
    pub max_file_size: Option<u64>,

    /// Number of parallel scanning threads.
    #[arg(long)]
    pub concurrency: Option<usize>,

    /// Scan only files staged in the git index.
    #[arg(long)]
    pub staged: bool,

    /// Baseline file for suppressing acknowledged secrets.
    #[arg(short = 'b', long, value_name = "PATH")]
    pub baseline: Option<PathBuf>,

    /// When used with `--baseline`, only report new secrets.
    #[arg(long)]
    pub allow_new: bool,

    /// Verify detected secrets against provider APIs.
    #[arg(long)]
    pub verify: bool,
}

/// Arguments for the `vet fix` command.
#[derive(Debug, Parser)]
pub struct FixArgs {
    /// Paths to scan and fix.
    #[arg(default_value = ".")]
    pub paths: Vec<PathBuf>,

    /// Path to `.vet.toml` configuration file.
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Minimum severity level to fix.
    #[arg(long, value_enum)]
    pub severity: Option<Severity>,

    /// Glob patterns to exclude from scanning.
    #[arg(long)]
    pub exclude: Vec<String>,

    /// Skip `.gitignore` rules when collecting files.
    #[arg(long)]
    pub skip_gitignore: bool,

    /// Preview fixes without modifying files.
    #[arg(long)]
    pub dry_run: bool,

    /// Skip files larger than this size in bytes.
    #[arg(long)]
    pub max_file_size: Option<u64>,
}

/// Arguments for the `vet history` command.
#[derive(Debug, Parser)]
pub struct HistoryArgs {
    /// Maximum number of commits to scan.
    #[arg(short = 'n', long, value_name = "N")]
    pub limit: Option<usize>,

    /// Start scanning from this commit or ref.
    #[arg(long, value_name = "REF")]
    pub since: Option<String>,

    /// Stop scanning at this commit or ref.
    #[arg(long, value_name = "REF", default_value = "HEAD")]
    pub until: String,

    /// Branch to scan.
    #[arg(long, value_name = "NAME")]
    pub branch: Option<String>,

    /// Follow only the first parent of merge commits.
    #[arg(long)]
    pub first_parent: bool,

    /// Scan all branches and refs.
    #[arg(long)]
    pub all: bool,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t)]
    pub format: OutputFormat,

    /// Write output to a file instead of stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Path to `.vet.toml` configuration file.
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Minimum severity level to report.
    #[arg(short, long)]
    pub severity: Option<Severity>,

    /// Increase output verbosity (repeat for more detail).
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Minimum confidence level to report (low or high).
    #[arg(long, value_parser = parse_confidence)]
    pub minimum_confidence: Option<Confidence>,

    /// Always exit with code 0, even when secrets are found.
    #[arg(long)]
    pub exit_zero: bool,

    /// Glob patterns to exclude from scanning.
    #[arg(short, long)]
    pub exclude: Vec<String>,

    /// Skip files larger than this size in bytes.
    #[arg(long)]
    pub max_file_size: Option<u64>,

    /// Number of parallel scanning threads.
    #[arg(long)]
    pub concurrency: Option<usize>,
}

/// Arguments for the `vet baseline` command.
#[derive(Debug, Parser)]
pub struct BaselineArgs {
    /// Paths to scan when generating the baseline.
    #[arg(default_value = ".")]
    pub paths: Vec<PathBuf>,

    /// Output path for the baseline file.
    #[arg(short, long, default_value = ".vet-baseline.json")]
    pub output: PathBuf,

    /// Path to `.vet.toml` configuration file.
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Minimum severity level to include.
    #[arg(short, long)]
    pub severity: Option<Severity>,

    /// Glob patterns to exclude from scanning.
    #[arg(short, long)]
    pub exclude: Vec<String>,

    /// Accept all findings without interactive confirmation.
    #[arg(long)]
    pub accept_all: bool,

    /// Reason to record for accepted findings.
    #[arg(long, value_name = "TEXT")]
    pub reason: Option<String>,

    /// Minimum confidence level to include (low or high).
    #[arg(long, value_parser = parse_confidence)]
    pub minimum_confidence: Option<Confidence>,

    /// Baseline subcommand.
    #[command(subcommand)]
    pub command: Option<BaselineSubcommand>,
}

/// Subcommands for `vet baseline`.
#[derive(Debug, Subcommand)]
pub enum BaselineSubcommand {
    /// Show statistics about an existing baseline file.
    Stats(BaselineStatsArgs),
}

/// Arguments for the `vet baseline stats` subcommand.
#[derive(Debug, Parser)]
pub struct BaselineStatsArgs {
    /// Path to the baseline file.
    #[arg(short = 'b', long, value_name = "PATH")]
    pub baseline: Option<PathBuf>,

    /// Output statistics as JSON.
    #[arg(long)]
    pub json: bool,
}

/// Arguments for the `vet patterns` command.
#[derive(Debug, Parser)]
pub struct PatternsArgs {
    /// Filter patterns by group name.
    #[arg(short, long)]
    pub group: Option<String>,

    /// Filter patterns by severity level.
    #[arg(short, long)]
    pub severity: Option<String>,

    /// Show pattern details including regex and keywords.
    #[arg(short, long)]
    pub verbose: bool,
}

/// Arguments for the `vet init` command.
#[derive(Debug, Parser)]
pub struct InitArgs {
    /// Skip confirmation prompts.
    #[arg(short, long)]
    pub yes: bool,

    /// Generate a minimal configuration file.
    #[arg(short, long)]
    pub minimal: bool,

    /// Write the config file to a custom path.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

/// Subcommands for `vet hook`.
#[derive(Debug, Subcommand)]
pub enum HookCommand {
    /// Install a git pre-commit hook.
    Install,
    /// Uninstall the git pre-commit hook.
    Uninstall,
}

fn main() {
    #[cfg(feature = "tracing")]
    {
        use tracing_subscriber::{EnvFilter, fmt, prelude::*};

        tracing_subscriber::registry()
            .with(fmt::layer().with_target(false).without_time())
            .with(EnvFilter::from_default_env())
            .init();
    }

    let cli = parse_cli();

    if let Err(e) = run(cli.command) {
        ui::print_error(&format!("{e:#}"));
        std::process::exit(ui::exit::ERROR);
    }
}

fn parse_cli() -> Cli {
    let cmd = Cli::command().about(build_about()).after_help(build_after_help());

    let matches = cmd.get_matches();

    #[expect(clippy::expect_used, reason = "clap already validated args; this cannot fail")]
    Cli::from_arg_matches(&matches).expect("failed to parse arguments")
}

fn run(command: Command) -> anyhow::Result<()> {
    match command {
        Command::Fix(args) => commands::fix::run(
            &args.paths,
            args.config.as_deref(),
            args.severity,
            &args.exclude,
            args.skip_gitignore,
            args.dry_run,
            args.max_file_size,
        ),
        Command::History(args) => commands::history::run(&args),
        Command::Baseline(args) => commands::baseline::run(&args),
        Command::Hook { command } => commands::hook::run(command.as_ref()),
        Command::Init(args) => commands::init::run(args.yes, args.minimal, args.output),
        Command::Patterns(args) => {
            commands::patterns::run(args.group.as_deref(), args.severity.as_deref(), args.verbose)
        }
        Command::Scan(args) => commands::scan::run(&args),
    }
}

fn build_about() -> String {
    format!(
        r"
  {} is a blazingly fast, local-first secret scanner for source code.
  
  Detects API keys, tokens, passwords, and other secrets before
  they reach your repository. Works offline. Zero configuration.",
        colors::accent().apply_to("vet").bold()
    )
}

fn build_after_help() -> String {
    format!(
        r"
  {}
    vet scan .                     Scan current directory
    vet scan src/ tests/           Scan multiple paths
    vet scan . --format json       Output as JSON
    vet fix                        Interactively fix secrets
    vet fix --dry-run              Preview fixes without changing files
    vet history                    Scan git history
    vet history -n 100             Scan last 100 commits
    vet init                       Create config file

  Learn more: {}",
        style("Examples:").bold(),
        colors::accent().apply_to(REPO_URL).underlined()
    )
}
