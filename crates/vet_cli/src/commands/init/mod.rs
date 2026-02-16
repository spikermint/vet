//! Init command - creates `.vet.toml` configuration file.

mod detection;
mod prompts;
/// Configuration file and hook templates for `vet init`.
pub mod templates;

use std::path::{Path, PathBuf};
use std::time::Instant;

use console::style;

use self::templates::{DEFAULT_SEVERITY, PRECOMMIT_HOOK_PATH};
use crate::CONFIG_FILENAME;
use crate::ui::{colors, format_duration, indicators, print_command_header, print_info};

/// Executes the `vet init` command, creating a `.vet.toml` configuration file
/// either interactively or with default settings.
pub fn run(non_interactive: bool, minimal: bool, output_path: Option<PathBuf>) -> super::Result {
    print_command_header("init");

    let output_path = output_path.unwrap_or_else(|| PathBuf::from(CONFIG_FILENAME));

    if output_path.exists() && !handle_existing(&output_path, non_interactive) {
        return Ok(());
    }

    let options = if non_interactive { defaults() } else { interactive()? };

    execute(&output_path, &options, minimal)
}

struct InitOptions {
    severity: &'static str,
    excludes: Vec<&'static str>,
    install_hook: bool,
}

const fn defaults() -> InitOptions {
    InitOptions {
        severity: DEFAULT_SEVERITY,
        excludes: Vec::new(),
        install_hook: false,
    }
}

fn interactive() -> anyhow::Result<InitOptions> {
    let results = prompts::collect_interactive()?;

    Ok(InitOptions {
        severity: results.severity,
        excludes: results.excludes,
        install_hook: results.install_hook,
    })
}

fn handle_existing(path: &Path, non_interactive: bool) -> bool {
    println!(
        "{} {} already exists",
        colors::warning().apply_to(indicators::WARNING),
        style(path.display()).bold()
    );

    if non_interactive {
        println!(
            "  {}",
            colors::secondary().apply_to("use interactive mode to overwrite")
        );
        println!();
        return false;
    }

    println!();

    if prompts::confirm_overwrite() {
        true
    } else {
        println!();
        false
    }
}

fn execute(output_path: &Path, options: &InitOptions, minimal: bool) -> anyhow::Result<()> {
    let start = Instant::now();

    let config_content = templates::build_config(options.severity, &options.excludes, minimal);
    templates::write_config(output_path, &config_content)?;
    let config_elapsed = start.elapsed();

    let hook_elapsed = if options.install_hook {
        let t = Instant::now();
        templates::install_hook()?;
        Some(t.elapsed())
    } else {
        None
    };

    print_results(output_path, config_elapsed, hook_elapsed);

    Ok(())
}

fn print_results(config_path: &Path, config_elapsed: std::time::Duration, hook_elapsed: Option<std::time::Duration>) {
    println!();
    println!(
        "{} {} {}",
        colors::success().apply_to(indicators::ADDED),
        style(config_path.display()).bold(),
        colors::muted().apply_to(format!("({})", format_duration(config_elapsed)))
    );

    if let Some(elapsed) = hook_elapsed {
        println!(
            "{} {} {}",
            colors::success().apply_to(indicators::ADDED),
            style(PRECOMMIT_HOOK_PATH).bold(),
            colors::muted().apply_to(format!("({})", format_duration(elapsed)))
        );
    }

    println!();
    print_info("Run `vet scan .` to scan your project");
}
