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
//! The CLI crate (`vet_cli`) uses `anyhow` for error propagation.

/// Baseline tracking for acknowledged secrets.
pub mod baseline;
/// Binary file detection heuristics.
pub mod binary;
/// Comment syntax detection for stripping false positives.
pub mod comment_syntax;
/// User configuration loaded from `.vet.toml`.
pub mod config;
pub(crate) mod entropy;
/// Error types for pattern compilation, configuration, and baseline operations.
pub mod error;
/// Types representing detected secrets and their locations.
pub mod finding;
/// Filesystem helpers for atomic writes and path operations.
pub mod fs_util;
/// Pattern definitions and the keyword-indexed registry.
pub mod pattern;
/// Common re-exports for internal use.
pub mod prelude;
/// Editor-agnostic protocol types for LSP and tooling consumers.
pub mod protocol;
/// The core scanning engine that matches patterns against content.
pub mod scanner;
#[cfg(test)]
pub(crate) mod test_utils;
/// Text utilities for line boundary detection.
pub mod text;

pub use baseline::{Baseline, BaselineError, BaselineFinding, BaselineStatus, Fingerprint, IgnoreMatcher};
pub use config::{Config, ConfigError, ConfigIgnore, CustomPattern};
pub use error::{PatternError, VetError};
pub use finding::{Confidence, Finding, FindingId, Secret, Span};
pub use pattern::{Group, Pattern, PatternRegistry, Severity};
pub use protocol::{
    DiagnosticData, DiagnosticVerification, ExposureRisk, HoverData, RemediationInfo, VerificationInfo,
};
pub use scanner::{Scanner, dedup_generic_findings};

/// Default filename for vet configuration.
pub const CONFIG_FILENAME: &str = ".vet.toml";
