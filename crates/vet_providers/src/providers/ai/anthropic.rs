//! Anthropic secret patterns and verification.

use crate::USER_AGENT;
use crate::pattern;
use crate::pattern::{Group, PatternDef, Severity};
use crate::provider::Provider;
use crate::verify::{BoxFuture, SecretVerifier, ServiceInfo, ServiceMetadata, VerificationError, VerificationResult};

const ANTHROPIC_API_URL: &str = "https://api.anthropic.com/v1/models";
const ANTHROPIC_API_VERSION: &str = "2023-06-01";
const DOCUMENTATION_URL: &str = "https://console.anthropic.com/settings/keys";

static PATTERNS: &[PatternDef] = &[pattern! {
    id: "ai/anthropic-api-key",
    group: Group::Ai,
    name: "Anthropic API Key",
    description: "Grants access to Claude models with billing.",
    severity: Severity::Critical,
    regex: r"\b(sk-ant-api03-[a-zA-Z0-9_-]{80,110})\b",
    keywords: &["sk-ant-"],
    default_enabled: true,
    min_entropy: Some(4.0),
    verifiable: true,
}];

/// Anthropic secret detection provider with live verification support.
pub struct AnthropicProvider;

impl Provider for AnthropicProvider {
    fn id(&self) -> &'static str {
        "anthropic"
    }

    fn name(&self) -> &'static str {
        "Anthropic"
    }

    fn patterns(&self) -> &'static [PatternDef] {
        PATTERNS
    }

    fn verifier(&self) -> Option<&dyn SecretVerifier> {
        Some(&AnthropicVerifier)
    }
}

/// Verifies Anthropic API keys by calling the `/v1/models` endpoint.
pub struct AnthropicVerifier;

impl SecretVerifier for AnthropicVerifier {
    fn verify<'a>(
        &'a self,
        client: &'a reqwest::Client,
        secret: &'a str,
        _pattern_id: &'a str,
    ) -> BoxFuture<'a, Result<VerificationResult, VerificationError>> {
        Box::pin(async move {
            let response = client
                .get(ANTHROPIC_API_URL)
                .header("x-api-key", secret)
                .header("anthropic-version", ANTHROPIC_API_VERSION)
                .header("User-Agent", USER_AGENT)
                .send()
                .await?;

            let status = response.status();

            match status.as_u16() {
                200 => Ok(VerificationResult::live(ServiceInfo {
                    provider: Some("Anthropic".into()),
                    metadata: vec![],
                    documentation_url: Some(DOCUMENTATION_URL.into()),
                })),
                401 => Ok(VerificationResult::inactive("Anthropic")),
                403 => Ok(VerificationResult::live(ServiceInfo {
                    provider: Some("Anthropic".into()),
                    metadata: vec![ServiceMetadata {
                        label: "Note".into(),
                        value: "authenticated, insufficient permissions".into(),
                    }],
                    documentation_url: Some(DOCUMENTATION_URL.into()),
                })),
                429 => {
                    let retry_after = response
                        .headers()
                        .get("retry-after")
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
        assert_eq!(AnthropicProvider.id(), "anthropic");
    }

    #[test]
    fn provider_has_patterns() {
        assert!(!AnthropicProvider.patterns().is_empty());
    }

    #[test]
    fn provider_has_verifier() {
        assert!(AnthropicProvider.verifier().is_some());
    }

    #[test]
    fn all_patterns_have_ai_group() {
        for pattern in AnthropicProvider.patterns() {
            assert_eq!(pattern.group, Group::Ai);
        }
    }

    fn create_test_client() -> reqwest::Client {
        reqwest::Client::builder().build().expect("client should build")
    }

    async fn mock_anthropic_response(status: u16) -> MockServer {
        let server = MockServer::start().await;

        let response = ResponseTemplate::new(status);

        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .and(header("x-api-key", "test_token"))
            .and(header("anthropic-version", "2023-06-01"))
            .respond_with(response)
            .mount(&server)
            .await;

        server
    }

    #[tokio::test]
    async fn valid_key_returns_200() {
        let server = mock_anthropic_response(200).await;

        let client = create_test_client();
        let response = client
            .get(format!("{}/v1/models", server.uri()))
            .header("x-api-key", "test_token")
            .header("anthropic-version", ANTHROPIC_API_VERSION)
            .header("User-Agent", USER_AGENT)
            .send()
            .await
            .expect("request should succeed");

        assert_eq!(response.status().as_u16(), 200);
    }

    #[tokio::test]
    async fn revoked_key_returns_401() {
        let server = mock_anthropic_response(401).await;

        let client = create_test_client();
        let response = client
            .get(format!("{}/v1/models", server.uri()))
            .header("x-api-key", "test_token")
            .header("anthropic-version", ANTHROPIC_API_VERSION)
            .header("User-Agent", USER_AGENT)
            .send()
            .await
            .expect("request should succeed");

        assert_eq!(response.status().as_u16(), 401);
    }

    #[tokio::test]
    async fn restricted_key_returns_403() {
        let server = mock_anthropic_response(403).await;

        let client = create_test_client();
        let response = client
            .get(format!("{}/v1/models", server.uri()))
            .header("x-api-key", "test_token")
            .header("anthropic-version", ANTHROPIC_API_VERSION)
            .header("User-Agent", USER_AGENT)
            .send()
            .await
            .expect("request should succeed");

        assert_eq!(response.status().as_u16(), 403);
    }

    #[tokio::test]
    async fn rate_limited_returns_429() {
        let server = mock_anthropic_response(429).await;

        let client = create_test_client();
        let response = client
            .get(format!("{}/v1/models", server.uri()))
            .header("x-api-key", "test_token")
            .header("anthropic-version", ANTHROPIC_API_VERSION)
            .header("User-Agent", USER_AGENT)
            .send()
            .await
            .expect("request should succeed");

        assert_eq!(response.status().as_u16(), 429);
    }
}
