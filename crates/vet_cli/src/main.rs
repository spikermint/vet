//! Vet CLI - A local-first secret scanner for source code.
//!
//! Detects API keys, tokens, passwords, and other secrets before they
//! reach your repository. Works offline with zero configuration.
//!
//! # Commands
//!
//! - `vet scan` - Scan files for secrets
//! - `vet init` - Create configuration file
//! - `vet hook` - Manage git pre-commit hooks
//! - `vet patterns` - List detection patterns

mod commands;
mod files;
mod git;
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

    #[command(visible_alias = "p")]
    Patterns(PatternsArgs),

    Init(InitArgs),

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
    vet init                       Create config file

  Learn more: {}",
        style("Examples:").bold(),
        colors::accent().apply_to(REPO_URL).underlined()
    )
}
