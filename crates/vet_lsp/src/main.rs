//! Binary entry point for the vet language server.

mod code_actions;
mod debounce;
mod diagnostics;
mod exclusions;
mod git;
mod hover;
mod server;
mod state;
mod uri;

use std::fmt;

use server::VetLanguageServer;
use tower_lsp::{LspService, Server};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;

#[tokio::main]
async fn main() {
    init_logging();

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = LspService::build(VetLanguageServer::new)
        .custom_method("vet/hoverData", VetLanguageServer::handle_hover_data)
        .finish();
    Server::new(stdin, stdout, socket).serve(service).await;
}

fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_target(false)
        .with_level(false)
        .with_timer(LspPrefix)
        .init();
}

struct LspPrefix;

impl FormatTime for LspPrefix {
    fn format_time(&self, w: &mut Writer<'_>) -> fmt::Result {
        write!(w, "[lsp]   ")
    }
}
