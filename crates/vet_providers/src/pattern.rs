//! Pattern definition types for secret detection.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Error returned when parsing an invalid severity string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseSeverityError {
    invalid_value: Box<str>,
}

impl ParseSeverityError {
    fn new(value: &str) -> Self {
        Self {
            invalid_value: value.into(),
        }
    }

    /// Returns the invalid value that caused the parse failure.
    #[must_use]
    pub fn invalid_value(&self) -> &str {
        &self.invalid_value
    }
}

impl fmt::Display for ParseSeverityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid severity '{}': expected one of 'low', 'medium', 'high', 'critical'",
            self.invalid_value
        )
    }
}

impl std::error::Error for ParseSeverityError {}

/// How severe a detected secret exposure is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Low risk - the secret has limited scope or is unlikely to be exploitable.
    Low,
    /// Medium risk - the secret could grant partial access.
    Medium,
    /// High risk - the secret grants broad access to sensitive resources.
    High,
    /// Critical risk - the secret grants full administrative or billing access.
    Critical,
}

impl Severity {
    /// All severity levels in ascending order.
    pub const ALL: [Self; 4] = [Self::Low, Self::Medium, Self::High, Self::Critical];
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        write!(f, "{s}")
    }
}

impl FromStr for Severity {
    type Err = ParseSeverityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(ParseSeverityError::new(s)),
        }
    }
}

/// Logical grouping of patterns by category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Group {
    /// AI and machine-learning service API keys.
    Ai,
    /// Authentication tokens and session credentials.
    Auth,
    /// Cloud provider API keys and service credentials.
    Cloud,
    /// User-defined patterns from `.vet.toml` configuration.
    Custom,
    /// Database connection strings and credentials.
    Database,
    /// Email service API keys.
    Email,
    /// Heuristic context-based detections (variable name + assignment + entropy).
    Generic,
    /// Infrastructure and `DevOps` tool credentials.
    Infra,
    /// Private keys and certificates.
    Keys,
    /// Messaging platform tokens and webhooks.
    Messaging,
    /// Package and container registry tokens.
    Packages,
    /// Payment processor API keys.
    Payments,
    /// Version control system tokens and credentials.
    Vcs,
}

impl Group {
    /// Returns the human-readable display name for this group.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ai => "AI Services",
            Self::Auth => "Authentication Tokens",
            Self::Cloud => "Cloud Providers",
            Self::Custom => "Custom Patterns",
            Self::Database => "Database Credentials",
            Self::Email => "Email Services",
            Self::Generic => "Generic Secrets",
            Self::Infra => "Infrastructure Tools",
            Self::Keys => "Private Keys & Certificates",
            Self::Messaging => "Messaging Platforms",
            Self::Packages => "Package & Container Registries",
            Self::Payments => "Payment Processors",
            Self::Vcs => "Version Control Systems",
        }
    }

    /// Returns the recommended remediation steps for secrets in this group.
    #[must_use]
    pub const fn remediation(self) -> &'static str {
        match self {
            Self::Ai => "Revoke key in provider dashboard, review usage logs for unauthorised API calls.",
            Self::Auth => "Invalidate token, review access logs for unauthorised usage.",
            Self::Cloud => "Revoke in provider console immediately, review audit logs for unauthorised access.",
            Self::Custom => "Revoke or rotate the credential immediately, review access logs for unauthorised usage.",
            Self::Database => "Rotate password immediately, review access logs for unauthorised queries.",
            Self::Email => "Revoke API key, review sending logs for unauthorised emails.",
            Self::Generic => {
                "Rotate the credential immediately. Generic detections may require manual review to identify the service."
            }
            Self::Infra => "Revoke token, review audit logs for unauthorised infrastructure changes.",
            Self::Keys => "Revoke or rotate the key immediately, generate new key pair.",
            Self::Messaging => "Revoke in app settings, review message logs for unauthorised activity.",
            Self::Packages => "Revoke token, audit published packages for unauthorised versions.",
            Self::Payments => "Roll API key immediately, review transaction logs for unauthorised charges.",
            Self::Vcs => "Revoke token immediately, review audit logs for unauthorised commits.",
        }
    }

    /// Returns the lowercase string identifier used in pattern IDs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ai => "ai",
            Self::Auth => "auth",
            Self::Cloud => "cloud",
            Self::Custom => "custom",
            Self::Database => "database",
            Self::Email => "email",
            Self::Generic => "generic",
            Self::Infra => "infra",
            Self::Keys => "keys",
            Self::Messaging => "messaging",
            Self::Packages => "packages",
            Self::Payments => "payments",
            Self::Vcs => "vcs",
        }
    }
}

impl fmt::Display for Group {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A single pattern definition for detecting a specific type of secret.
#[derive(Debug, Clone)]
pub struct PatternDef {
    /// Unique identifier in `"group/name"` format (e.g. `"vcs/github-pat"`).
    pub id: &'static str,
    /// The category this pattern belongs to.
    pub group: Group,
    /// Short human-readable name (e.g. `"GitHub Personal Access Token"`).
    pub name: &'static str,
    /// Longer description of what this pattern detects.
    pub description: &'static str,
    /// How severe an exposure of this secret type is.
    pub severity: Severity,
    /// The regular expression used to match this secret.
    pub regex: &'static str,
    /// Keywords for Aho-Corasick pre-filtering.
    pub keywords: &'static [&'static str],
    /// Whether this pattern is enabled by default.
    pub default_enabled: bool,
    /// Optional minimum Shannon entropy threshold for matched text.
    pub min_entropy: Option<f64>,
    /// Whether this pattern supports live verification.
    pub verifiable: bool,
}

/// Creates a `PatternDef` with `verifiable` defaulting to `false`.
#[macro_export]
macro_rules! pattern {
    (
        id: $id:expr,
        group: $group:expr,
        name: $name:expr,
        description: $description:expr,
        severity: $severity:expr,
        regex: $regex:expr,
        keywords: $keywords:expr,
        default_enabled: $enabled:expr,
        min_entropy: $entropy:expr $(,)?
    ) => {
        $crate::pattern::PatternDef {
            id: $id,
            group: $group,
            name: $name,
            description: $description,
            severity: $severity,
            regex: $regex,
            keywords: $keywords,
            default_enabled: $enabled,
            min_entropy: $entropy,
            verifiable: false,
        }
    };
    (
        id: $id:expr,
        group: $group:expr,
        name: $name:expr,
        description: $description:expr,
        severity: $severity:expr,
        regex: $regex:expr,
        keywords: $keywords:expr,
        default_enabled: $enabled:expr,
        min_entropy: $entropy:expr,
        verifiable: $verifiable:expr $(,)?
    ) => {
        $crate::pattern::PatternDef {
            id: $id,
            group: $group,
            name: $name,
            description: $description,
            severity: $severity,
            regex: $regex,
            keywords: $keywords,
            default_enabled: $enabled,
            min_entropy: $entropy,
            verifiable: $verifiable,
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_low_to_critical() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn severity_display_formats_as_lowercase() {
        assert_eq!(format!("{}", Severity::Low), "low");
        assert_eq!(format!("{}", Severity::Critical), "critical");
    }

    #[test]
    fn severity_from_str_is_case_insensitive() {
        assert_eq!(Severity::from_str("LOW"), Ok(Severity::Low));
        assert_eq!(Severity::from_str("Critical"), Ok(Severity::Critical));
    }

    #[test]
    fn severity_from_str_returns_error_for_invalid_value() {
        let result = Severity::from_str("extreme");
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert_eq!(err.invalid_value(), "extreme");
        assert!(err.to_string().contains("extreme"));
        assert!(err.to_string().contains("expected one of"));
    }

    #[test]
    fn parse_severity_error_implements_std_error() {
        let err = ParseSeverityError::new("bad");
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn group_as_str_matches_pattern_id_prefix() {
        assert_eq!(Group::Vcs.as_str(), "vcs");
        assert_eq!(Group::Payments.as_str(), "payments");
    }

    #[test]
    fn group_name_is_human_readable() {
        assert_eq!(Group::Vcs.name(), "Version Control Systems");
        assert_eq!(Group::Ai.name(), "AI Services");
    }
}
