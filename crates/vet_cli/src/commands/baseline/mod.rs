//! Baseline command - manages acknowledged-secret baselines.

mod interactive;
mod stats;

use anyhow::Result;

use crate::{BaselineArgs, BaselineSubcommand};

/// Executes the `vet baseline` command, dispatching to a subcommand or
/// running the interactive baseline review.
pub fn run(args: &BaselineArgs) -> Result<()> {
    if let Some(subcommand) = &args.command {
        match subcommand {
            BaselineSubcommand::Stats(stats_args) => stats::run(stats_args),
        }
    } else {
        interactive::run(args)
    }
}
