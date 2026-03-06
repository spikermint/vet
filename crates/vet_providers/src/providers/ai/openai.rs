//! OpenAI secret patterns and verification.

use crate::USER_AGENT;
use crate::pattern;
use crate::pattern::{Group, PatternDef, Severity};
use crate::provider::Provider;
use crate::verify::{BoxFuture, SecretVerifier, ServiceInfo, ServiceMetadata, VerificationError, VerificationResult};

const OPENAI_API_URL: &str = "https://api.openai.com/v1/models";
const DOCUMENTATION_URL: &str = "https://platform.openai.com/api-keys";

static PATTERNS: &[PatternDef] = &[
    pattern! {
        id: "ai/openai-admin-key",
        group: Group::Ai,
        name: "OpenAI Admin API Key",
        description: "Grants administrative access to organisation.",
        severity: Severity::Critical,
        regex: r"\b(sk-admin-[a-zA-Z0-9_-]{20,})\b",
        keywords: &["sk-admin-"],
        default_enabled: true,
        min_entropy: Some(4.0),
        verifiable: true,
    },
    pattern! {
        id: "ai/openai-api-key",
        group: Group::Ai,
        name: "OpenAI Project API Key",
        description: "Grants access to OpenAI models with billing.",
        severity: Severity::Critical,
        regex: r"\b(sk-proj-[a-zA-Z0-9_-]{48,160})\b",
        keywords: &["sk-proj-"],
        default_enabled: true,
        min_entropy: Some(4.0),
        verifiable: true,
    },
    pattern! {
        id: "ai/openai-service-account-key",
        group: Group::Ai,
        name: "OpenAI Service Account Key",
        description: "Grants programmatic access to OpenAI services via a service account.",
        severity: Severity::Critical,
        regex: r"\b(sk-svcacct-[a-zA-Z0-9_-]{48,160})\b",
        keywords: &["sk-svcacct-"],
        default_enabled: true,
        min_entropy: Some(4.0),
        verifiable: true,
    },
    pattern! {
        id: "ai/openai-none-key",
        group: Group::Ai,
        name: "OpenAI None-Scoped Key",
        description: "Grants access to OpenAI services via an unscoped API key.",
        severity: Severity::Critical,
        regex: r"\b(sk-None-[a-zA-Z0-9_-]{48,160})\b",
        keywords: &["sk-None-"],
        default_enabled: true,
        min_entropy: Some(4.0),
        verifiable: true,
    },
];

/// OpenAI secret detection provider with live verification support.
pub struct OpenAiProvider;

impl Provider for OpenAiProvider {
    fn id(&self) -> &'static str {
        "openai"
    }

    fn name(&self) -> &'static str {
        "OpenAI"
    }

    fn patterns(&self) -> &'static [PatternDef] {
        PATTERNS
    }

    fn verifier(&self) -> Option<&dyn SecretVerifier> {
        Some(&OpenAiVerifier)
    }
}

/// Verifies OpenAI API keys by calling the `/v1/models` endpoint.
pub struct OpenAiVerifier;

impl OpenAiVerifier {
    fn key_type(secret: &str) -> &'static str {
        if secret.starts_with("sk-admin-") {
            "admin key"
        } else if secret.starts_with("sk-proj-") {
            "project key"
        } else if secret.starts_with("sk-svcacct-") {
            "service account key"
        } else if secret.starts_with("sk-None-") {
            "none-scoped key"
        } else {
            "unknown key type"
        }
    }
}

impl SecretVerifier for OpenAiVerifier {
    fn verify<'a>(
        &'a self,
        client: &'a reqwest::Client,
        secret: &'a str,
        _pattern_id: &'a str,
    ) -> BoxFuture<'a, Result<VerificationResult, VerificationError>> {
        Box::pin(async move {
            let response = client
                .get(OPENAI_API_URL)
                .header("Authorization", format!("Bearer {secret}"))
                .header("User-Agent", USER_AGENT)
                .send()
                .await?;

            let status = response.status();

            match status.as_u16() {
                200 => Ok(VerificationResult::live(ServiceInfo {
                    provider: Some("OpenAI".into()),
                    metadata: vec![ServiceMetadata {
                        label: "Key Type".into(),
                        value: Self::key_type(secret).into(),
                    }],
                    documentation_url: Some(DOCUMENTATION_URL.into()),
                })),
                401 => Ok(VerificationResult::inactive("OpenAI")),
                403 => Ok(VerificationResult::live(ServiceInfo {
                    provider: Some("OpenAI".into()),
                    metadata: vec![
                        ServiceMetadata {
                            label: "Key Type".into(),
                            value: Self::key_type(secret).into(),
                        },
                        ServiceMetadata {
                            label: "Note".into(),
                            value: "authenticated, insufficient permissions".into(),
                        },
                    ],
                    documentation_url: Some(DOCUMENTATION_URL.into()),
                })),
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
#[expect(clippy::expect_used, reason = "tests use expect for clearer failure messages")]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn provider_has_correct_id() {
        assert_eq!(OpenAiProvider.id(), "openai");
    }

    #[test]
    fn provider_has_patterns() {
        assert!(!OpenAiProvider.patterns().is_empty());
    }

    #[test]
    fn provider_has_verifier() {
        assert!(OpenAiProvider.verifier().is_some());
    }

    #[test]
    fn all_patterns_have_ai_group() {
        for pattern in OpenAiProvider.patterns() {
            assert_eq!(pattern.group, Group::Ai);
        }
    }

    #[test]
    fn key_type_detects_admin_key() {
        assert_eq!(OpenAiVerifier::key_type("sk-admin-abc"), "admin key");
    }

    #[test]
    fn key_type_detects_project_key() {
        assert_eq!(OpenAiVerifier::key_type("sk-proj-abc"), "project key");
    }

    #[test]
    fn key_type_detects_service_account_key() {
        assert_eq!(OpenAiVerifier::key_type("sk-svcacct-abc"), "service account key");
    }

    #[test]
    fn key_type_detects_none_scoped_key() {
        assert_eq!(OpenAiVerifier::key_type("sk-None-abc"), "none-scoped key");
    }

    #[test]
    fn key_type_returns_unknown_for_unrecognised_prefix() {
        assert_eq!(OpenAiVerifier::key_type("sk-other-abc"), "unknown key type");
    }

    fn create_test_client() -> reqwest::Client {
        reqwest::Client::builder().build().expect("client should build")
    }

    async fn mock_openai_response(status: u16) -> MockServer {
        let server = MockServer::start().await;

        let response = ResponseTemplate::new(status);

        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .and(header("Authorization", "Bearer test_token"))
            .respond_with(response)
            .mount(&server)
            .await;

        server
    }

    #[tokio::test]
    async fn valid_key_returns_200() {
        let server = mock_openai_response(200).await;

        let client = create_test_client();
        let response = client
            .get(format!("{}/v1/models", server.uri()))
            .header("Authorization", "Bearer test_token")
            .header("User-Agent", USER_AGENT)
            .send()
            .await
            .expect("request should succeed");

        assert_eq!(response.status().as_u16(), 200);
    }

    #[tokio::test]
    async fn revoked_key_returns_401() {
        let server = mock_openai_response(401).await;

        let client = create_test_client();
        let response = client
            .get(format!("{}/v1/models", server.uri()))
            .header("Authorization", "Bearer test_token")
            .header("User-Agent", USER_AGENT)
            .send()
            .await
            .expect("request should succeed");

        assert_eq!(response.status().as_u16(), 401);
    }

    #[tokio::test]
    async fn restricted_key_returns_403() {
        let server = mock_openai_response(403).await;

        let client = create_test_client();
        let response = client
            .get(format!("{}/v1/models", server.uri()))
            .header("Authorization", "Bearer test_token")
            .header("User-Agent", USER_AGENT)
            .send()
            .await
            .expect("request should succeed");

        assert_eq!(response.status().as_u16(), 403);
    }

    #[tokio::test]
    async fn rate_limited_returns_429() {
        let server = mock_openai_response(429).await;

        let client = create_test_client();
        let response = client
            .get(format!("{}/v1/models", server.uri()))
            .header("Authorization", "Bearer test_token")
            .header("User-Agent", USER_AGENT)
            .send()
            .await
            .expect("request should succeed");

        assert_eq!(response.status().as_u16(), 429);
    }
}
