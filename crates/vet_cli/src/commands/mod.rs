//! CLI command handlers.

pub mod hook;
pub mod init;
pub mod patterns;
pub mod scan;

pub type Result<T = ()> = anyhow::Result<T>;
