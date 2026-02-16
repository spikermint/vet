//! Hook command - installs and manages git pre-commit hooks.

use std::path::Path;

use anyhow::Context;

use super::init::templates::{PRECOMMIT_HOOK_PATH, VET_HOOK_MARKER, install_hook};
use crate::HookCommand;
use crate::git;
use crate::ui::{colors, exit, indicators, print_command_header, print_hint, print_info};

/// Executes the `vet hook` command, showing status or installing/uninstalling
/// the git pre-commit hook.
pub fn run(command: Option<&HookCommand>) -> super::Result {
    let hook_path = Path::new(PRECOMMIT_HOOK_PATH);

    match command {
        Some(HookCommand::Install) => install(hook_path),
        Some(HookCommand::Uninstall) => uninstall(hook_path),
        None => {
            show_status(hook_path);
            Ok(())
        }
    }
}

fn show_status(hook_path: &Path) {
    print_command_header("hook");

    match check_hook_status(hook_path) {
        HookStatus::NotExists => {
            println!(
                "{} {}",
                colors::muted().apply_to("○"),
                colors::secondary().apply_to("no hook installed")
            );
            println!();
            print_hint("vet hook install", "Install pre-commit hook");
        }
        HookStatus::ManagedByVet => {
            println!(
                "{} {}",
                colors::success().apply_to(indicators::SUCCESS),
                colors::secondary().apply_to("pre-commit installed")
            );
            println!();
            print_hint("vet hook uninstall", "Remove hook");
        }
        HookStatus::ExternalHook => {
            println!(
                "{} {}",
                colors::warning().apply_to(indicators::WARNING),
                colors::secondary().apply_to("external hook (not managed by vet)")
            );
            println!();
            print_info("Add to your pre-commit hook: `vet scan --staged`");
        }
    }
}

fn install(hook_path: &Path) -> super::Result {
    print_command_header("hook install");

    verify_git_repository()?;

    match check_hook_status(hook_path) {
        HookStatus::NotExists => {
            install_hook()?;
            print_created(hook_path);
        }
        HookStatus::ManagedByVet => {
            print_already_installed();
        }
        HookStatus::ExternalHook => {
            external_hook_error();
        }
    }

    Ok(())
}

fn uninstall(hook_path: &Path) -> super::Result {
    print_command_header("hook uninstall");

    match check_hook_status(hook_path) {
        HookStatus::NotExists => {
            print_no_hook();
        }
        HookStatus::ManagedByVet => {
            std::fs::remove_file(hook_path).context("removing hook")?;
            print_removed(hook_path);
        }
        HookStatus::ExternalHook => {
            not_managed_error();
        }
    }

    Ok(())
}

fn verify_git_repository() -> anyhow::Result<()> {
    if git::in_repo() {
        return Ok(());
    }

    println!(
        "{} {}",
        colors::error().apply_to(indicators::ERROR),
        colors::secondary().apply_to("not a git repository")
    );
    std::process::exit(exit::ERROR)
}

fn print_created(hook_path: &Path) {
    println!(
        "{} {}",
        colors::success().apply_to(indicators::ADDED),
        colors::emphasis().apply_to(hook_path.display())
    );
}

fn print_already_installed() {
    println!(
        "{} {}",
        colors::success().apply_to(indicators::SUCCESS),
        colors::secondary().apply_to("pre-commit already installed")
    );
}

fn external_hook_error() -> ! {
    println!(
        "{} {} {}",
        colors::error().apply_to(indicators::ERROR),
        colors::secondary().apply_to("external hook exists at"),
        colors::emphasis().apply_to(PRECOMMIT_HOOK_PATH)
    );
    println!();
    println!(
        "  {} {}",
        colors::info().apply_to(indicators::INFO),
        colors::secondary().apply_to("Add to your existing hook: `vet scan --staged`")
    );
    println!(
        "  {} {}",
        colors::info().apply_to(indicators::INFO),
        colors::secondary().apply_to("Or remove it first to let vet manage the hook")
    );

    std::process::exit(exit::ERROR)
}

fn print_no_hook() {
    println!(
        "{} {}",
        colors::muted().apply_to("○"),
        colors::secondary().apply_to("no hook installed")
    );
}

fn print_removed(hook_path: &Path) {
    println!(
        "{} {} {}",
        colors::success().apply_to(indicators::SUCCESS),
        colors::secondary().apply_to("removed"),
        colors::emphasis().apply_to(hook_path.display())
    );
}

fn not_managed_error() -> ! {
    println!(
        "{} {}",
        colors::error().apply_to(indicators::ERROR),
        colors::secondary().apply_to("hook not managed by vet")
    );

    std::process::exit(exit::ERROR)
}

enum HookStatus {
    NotExists,
    ManagedByVet,
    ExternalHook,
}

fn check_hook_status(hook_path: &Path) -> HookStatus {
    if !hook_path.exists() {
        return HookStatus::NotExists;
    }

    let content = std::fs::read_to_string(hook_path).unwrap_or_default();

    if content.contains(VET_HOOK_MARKER) {
        HookStatus::ManagedByVet
    } else {
        HookStatus::ExternalHook
    }
}
