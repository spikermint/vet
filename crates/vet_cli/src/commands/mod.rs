//! CLI command handlers.

pub mod fix;
pub mod history;
pub mod hook;
pub mod init;
pub mod patterns;
pub mod scan;

pub type Result<T = ()> = anyhow::Result<T>;
