//! Core secret scanning engine for vet.
//!
//! This crate provides pattern-based secret detection with optimised matching.
//! It's designed to be embedded in CLIs, editors (via LSP), and CI pipelines.
//!
//! # Main Types
//!
//! - [`Scanner`] - Runs patterns against content and produces findings
//! - [`PatternRegistry`] - Collection of patterns with keyword pre-filtering
//! - [`Finding`] - A detected secret with location and metadata
//! - [`Config`] - User configuration loaded from `.vet.toml`
//!
//! # Error Handling
//!
//! This crate uses [`thiserror`] for structured, typed errors that library
//! consumers can match on:
//!
//! - [`PatternError`] - Pattern compilation failures
//! - [`ConfigError`] - Configuration loading/parsing failures  
//! - [`VetError`] - Top-level error enum combining the above
//!
//! The CLI crate (`vet_cli`) uses [`anyhow`] for error propagation.

pub mod binary;
pub mod config;
pub(crate) mod entropy;
pub mod error;
pub mod finding;
pub mod pattern;
pub mod prelude;
pub mod scanner;
#[cfg(test)]
pub(crate) mod test_utils;
pub(crate) mod text;

pub use config::{Config, ConfigError, CustomPattern};
pub use error::{PatternError, VetError};
pub use finding::{Confidence, Finding, FindingId, Secret, Span};
pub use pattern::{Pattern, PatternRegistry, Severity};
pub use scanner::Scanner;

/// Default filename for vet configuration.
pub const CONFIG_FILENAME: &str = ".vet.toml";
