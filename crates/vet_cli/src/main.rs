//! # Commands
//!
//! - `vet scan` - Scan files for secrets
//! - `vet fix` - Interactively fix detected secrets
//! - `vet history` - Scan commits in git repository for secrets
//! - `vet init` - Create configuration file
//! - `vet hook` - Manage git pre-commit hooks
//! - `vet patterns` - List detection patterns

mod commands;
mod files;
mod git;
mod scanning;
mod ui;

use std::path::PathBuf;

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use clap_complete::Shell;
use console::style;
pub use vet_core::CONFIG_FILENAME;
use vet_core::prelude::*;

use crate::ui::colors;

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

    Hook {
        #[command(subcommand)]
        command: Option<HookCommand>,
    },

    Completions {
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    Sarif,
}

#[derive(Debug, Parser)]
pub struct ScanArgs {
    #[arg(default_value = ".")]
    pub paths: Vec<PathBuf>,

    #[arg(short, long, value_enum, default_value_t)]
    pub format: OutputFormat,

    #[arg(short, long)]
    pub output: Option<PathBuf>,

    #[arg(short, long)]
    pub config: Option<PathBuf>,

    #[arg(short, long)]
    pub severity: Option<Severity>,

    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[arg(long)]
    pub include_low_confidence: bool,

    #[arg(long)]
    pub exit_zero: bool,

    #[arg(short, long)]
    pub exclude: Vec<String>,

    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub use_gitignore: bool,

    #[arg(long)]
    pub max_file_size: Option<u64>,

    #[arg(long)]
    pub concurrency: Option<usize>,

    #[arg(long)]
    pub staged: bool,
}

#[derive(Debug, Parser)]
pub struct FixArgs {
    #[arg(default_value = ".")]
    pub paths: Vec<PathBuf>,

    #[arg(short, long)]
    pub config: Option<PathBuf>,

    #[arg(long, value_enum)]
    pub severity: Option<Severity>,

    #[arg(long)]
    pub exclude: Vec<String>,

    #[arg(long)]
    pub no_gitignore: bool,

    #[arg(long)]
    pub dry_run: bool,

    #[arg(long)]
    pub max_file_size: Option<u64>,
}

#[derive(Debug, Parser)]
pub struct HistoryArgs {
    #[arg(short = 'n', long, value_name = "N")]
    pub limit: Option<usize>,

    #[arg(long, value_name = "REF")]
    pub since: Option<String>,

    #[arg(long, value_name = "REF", default_value = "HEAD")]
    pub until: String,

    #[arg(long, value_name = "NAME")]
    pub branch: Option<String>,

    #[arg(long)]
    pub first_parent: bool,

    #[arg(long)]
    pub all: bool,

    #[arg(short, long, value_enum, default_value_t)]
    pub format: OutputFormat,

    #[arg(short, long)]
    pub output: Option<PathBuf>,

    #[arg(short, long)]
    pub config: Option<PathBuf>,

    #[arg(short, long)]
    pub severity: Option<Severity>,

    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[arg(long)]
    pub include_low_confidence: bool,

    #[arg(long)]
    pub exit_zero: bool,

    #[arg(short, long)]
    pub exclude: Vec<String>,

    #[arg(long)]
    pub max_file_size: Option<u64>,

    #[arg(long)]
    pub concurrency: Option<usize>,
}

#[derive(Debug, Parser)]
pub struct PatternsArgs {
    #[arg(short, long)]
    pub group: Option<String>,

    #[arg(short, long)]
    pub severity: Option<String>,

    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(Debug, Parser)]
pub struct InitArgs {
    #[arg(short, long)]
    pub yes: bool,

    #[arg(short, long)]
    pub minimal: bool,

    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum HookCommand {
    Install,
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

    #[allow(clippy::expect_used)] // Clap already validated args; this cannot fail
    Cli::from_arg_matches(&matches).expect("failed to parse arguments")
}

fn run(command: Command) -> anyhow::Result<()> {
    match command {
        Command::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "vet", &mut std::io::stdout());
            Ok(())
        }
        Command::Fix(args) => commands::fix::run(
            &args.paths,
            args.config.as_deref(),
            args.severity,
            &args.exclude,
            args.no_gitignore,
            args.dry_run,
            args.max_file_size,
        ),
        Command::History(args) => commands::history::run(&args),
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
