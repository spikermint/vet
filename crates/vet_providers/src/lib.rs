//! Secret patterns and verification providers for vet.
//!
//! This crate provides pattern definitions for detecting secrets and optional
//! verification logic for checking if detected secrets are still active.

mod pattern;
mod provider;
/// Secret detection providers organised by service category.
pub mod providers;
mod registry;
mod verify;

pub use pattern::{Group, ParseSeverityError, PatternDef, Severity};
pub use provider::Provider;
pub use registry::ProviderRegistry;
pub use verify::{SecretVerifier, ServiceInfo, VerificationError, VerificationResult, VerificationStatus};

/// HTTP `User-Agent` header sent during secret verification requests.
pub(crate) const USER_AGENT: &str = concat!("vet-secret-scanner/", env!("CARGO_PKG_VERSION"));
