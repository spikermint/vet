//! Stripe secret patterns and verification.

use crate::USER_AGENT;
use crate::pattern;
use crate::pattern::{Group, PatternDef, Severity};
use crate::provider::Provider;
use crate::verify::{BoxFuture, SecretVerifier, ServiceInfo, VerificationError, VerificationResult};

const STRIPE_API_URL: &str = "https://api.stripe.com/v1/charges";
const DOCUMENTATION_URL: &str = "https://stripe.com/docs/keys#revoking-keys";

static PATTERNS: &[PatternDef] = &[
    pattern! {
        id: "payments/stripe-live-secret-key",
        group: Group::Payments,
        name: "Stripe Live Secret Key",
        description: "Grants full API access to production payment processing.",
        severity: Severity::Critical,
        regex: r"\b(sk_live_[a-zA-Z0-9]{10,99})\b",
        keywords: &["sk_live_"],
        default_enabled: true,
        min_entropy: Some(3.0),
        verifiable: true,
    },
    pattern! {
        id: "payments/stripe-test-secret-key",
        group: Group::Payments,
        name: "Stripe Test Secret Key",
        description: "Exposes test data and configuration (no real money access).",
        severity: Severity::Low,
        regex: r"\b(sk_test_[a-zA-Z0-9]{10,99})\b",
        keywords: &["sk_test_"],
        default_enabled: true,
        min_entropy: Some(3.0),
        verifiable: true,
    },
    pattern! {
        id: "payments/stripe-live-restricted-key",
        group: Group::Payments,
        name: "Stripe Live Restricted API Key",
        description: "Grants scoped production access based on key permissions.",
        severity: Severity::Critical,
        regex: r"\b(rk_live_[a-zA-Z0-9]{10,99})\b",
        keywords: &["rk_live_"],
        default_enabled: true,
        min_entropy: Some(3.0),
        verifiable: true,
    },
    pattern! {
        id: "payments/stripe-test-restricted-key",
        group: Group::Payments,
        name: "Stripe Test Restricted API Key",
        description: "Grants scoped test mode access.",
        severity: Severity::Low,
        regex: r"\b(rk_test_[a-zA-Z0-9]{10,99})\b",
        keywords: &["rk_test_"],
        default_enabled: true,
        min_entropy: Some(3.0),
        verifiable: true,
    },
    pattern! {
        id: "payments/stripe-webhook-secret",
        group: Group::Payments,
        name: "Stripe Webhook Signing Secret",
        description: "Allows forging webhook events to your application if compromised.",
        severity: Severity::High,
        regex: r"\b(whsec_[a-zA-Z0-9]{24,64})\b",
        keywords: &["whsec_"],
        default_enabled: true,
        min_entropy: Some(3.0),
    },
];

/// Stripe secret detection provider with live verification support.
pub struct StripeProvider;

impl Provider for StripeProvider {
    fn id(&self) -> &'static str {
        "stripe"
    }

    fn name(&self) -> &'static str {
        "Stripe"
    }

    fn patterns(&self) -> &'static [PatternDef] {
        PATTERNS
    }

    fn verifier(&self) -> Option<&dyn SecretVerifier> {
        Some(&StripeVerifier)
    }
}

/// Verifies Stripe API keys by calling the `/v1/charges` endpoint.
pub struct StripeVerifier;

impl StripeVerifier {
    /// Returns `true` if the key prefix indicates a test-mode key.
    fn is_test_key(secret: &str) -> bool {
        secret.starts_with("sk_test_") || secret.starts_with("pk_test_") || secret.starts_with("rk_test_")
    }

    /// Returns `true` if the key prefix indicates a restricted key.
    fn is_restricted_key(secret: &str) -> bool {
        secret.starts_with("rk_live_") || secret.starts_with("rk_test_")
    }
}

impl SecretVerifier for StripeVerifier {
    fn verify<'a>(
        &'a self,
        client: &'a reqwest::Client,
        secret: &'a str,
        _pattern_id: &'a str,
    ) -> BoxFuture<'a, Result<VerificationResult, VerificationError>> {
        Box::pin(async move {
            let response = client
                .get(STRIPE_API_URL)
                .query(&[("limit", "1")])
                .header("Authorization", format!("Bearer {secret}"))
                .header("User-Agent", USER_AGENT)
                .send()
                .await?;

            let status = response.status();

            match status.as_u16() {
                200 => {
                    let mode = if Self::is_test_key(secret) {
                        "test mode"
                    } else {
                        "live mode"
                    };

                    let access = if Self::is_restricted_key(secret) {
                        "restricted key"
                    } else {
                        "full access"
                    };

                    Ok(VerificationResult::live(ServiceInfo {
                        provider: Some("Stripe".into()),
                        details: format!("{mode}, {access}").into(),
                        documentation_url: Some(DOCUMENTATION_URL.into()),
                    }))
                }
                401 => Ok(VerificationResult::inactive("Stripe")),
                403 => {
                    let mode = if Self::is_test_key(secret) {
                        "test mode"
                    } else {
                        "live mode"
                    };

                    Ok(VerificationResult::live(ServiceInfo {
                        provider: Some("Stripe".into()),
                        details: format!("{mode}, restricted key (insufficient permissions)").into(),
                        documentation_url: Some(DOCUMENTATION_URL.into()),
                    }))
                }
                429 => {
                    let retry_after = response
                        .headers()
                        .get("Retry-After")
                        .and_then(|v| v.to_str().ok())
                        .map_or_else(
                            || "rate limited, try again later".to_string(),
                            |v| format!("rate limited, retry after {v}s"),
                        );
                    Ok(VerificationResult::inconclusive(&retry_after))
                }
                _ => Ok(VerificationResult::inconclusive(&format!(
                    "unexpected status code: {status}"
                ))),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_has_correct_id() {
        assert_eq!(StripeProvider.id(), "stripe");
    }

    #[test]
    fn provider_has_patterns() {
        assert!(!StripeProvider.patterns().is_empty());
    }

    #[test]
    fn provider_has_verifier() {
        assert!(StripeProvider.verifier().is_some());
    }

    #[test]
    fn all_patterns_have_payments_group() {
        for pattern in StripeProvider.patterns() {
            assert_eq!(pattern.group, Group::Payments);
        }
    }

    #[test]
    fn is_test_key_detects_test_keys() {
        assert!(StripeVerifier::is_test_key("sk_test_abc123"));
        assert!(StripeVerifier::is_test_key("rk_test_abc123"));
        assert!(!StripeVerifier::is_test_key("sk_live_abc123"));
    }

    #[test]
    fn is_restricted_key_detects_restricted_keys() {
        assert!(StripeVerifier::is_restricted_key("rk_live_abc123"));
        assert!(StripeVerifier::is_restricted_key("rk_test_abc123"));
        assert!(!StripeVerifier::is_restricted_key("sk_live_abc123"));
    }
}
