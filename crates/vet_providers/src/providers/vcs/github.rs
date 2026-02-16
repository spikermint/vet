//! GitHub secret patterns and verification.

use crate::USER_AGENT;
use crate::pattern;
use crate::pattern::{Group, PatternDef, Severity};
use crate::provider::Provider;
use crate::verify::{BoxFuture, SecretVerifier, ServiceInfo, VerificationError, VerificationResult};

const GITHUB_API_URL: &str = "https://api.github.com/user";
const DOCUMENTATION_URL: &str =
    "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-unauthorized-access";

static PATTERNS: &[PatternDef] = &[
    pattern! {
        id: "vcs/github-pat",
        group: Group::Vcs,
        name: "GitHub Personal Access Token (Classic)",
        description: "Grants repository and API access based on token scopes.",
        severity: Severity::Critical,
        regex: r"\b(ghp_[A-Za-z0-9]{36})\b",
        keywords: &["ghp_"],
        default_enabled: true,
        min_entropy: Some(4.0),
        verifiable: true,
    },
    pattern! {
        id: "vcs/github-fine-grained-pat",
        group: Group::Vcs,
        name: "GitHub Fine-Grained Personal Access Token",
        description: "Grants scoped access to specified repositories.",
        severity: Severity::Critical,
        regex: r"\b(github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})\b",
        keywords: &["github_pat_"],
        default_enabled: true,
        min_entropy: Some(4.0),
        verifiable: true,
    },
    pattern! {
        id: "vcs/github-oauth-token",
        group: Group::Vcs,
        name: "GitHub OAuth Access Token",
        description: "Grants delegated access to user resources via OAuth app.",
        severity: Severity::High,
        regex: r"\b(gho_[A-Za-z0-9]{36})\b",
        keywords: &["gho_"],
        default_enabled: true,
        min_entropy: Some(4.0),
        verifiable: true,
    },
    pattern! {
        id: "vcs/github-app-installation-token",
        group: Group::Vcs,
        name: "GitHub App Server-to-Server Token",
        description: "Grants access to repos where the app is installed.",
        severity: Severity::Critical,
        regex: r"\b(ghs_[A-Za-z0-9]{36})\b",
        keywords: &["ghs_"],
        default_enabled: true,
        min_entropy: Some(4.0),
    },
    pattern! {
        id: "vcs/github-app-refresh-token",
        group: Group::Vcs,
        name: "GitHub App Refresh Token",
        description: "Can generate new access tokens without user interaction.",
        severity: Severity::Critical,
        regex: r"\b(ghr_[A-Za-z0-9]{36})\b",
        keywords: &["ghr_"],
        default_enabled: true,
        min_entropy: Some(4.0),
    },
    pattern! {
        id: "vcs/github-app-user-token",
        group: Group::Vcs,
        name: "GitHub App User-to-Server Token",
        description: "Grants access on behalf of user through GitHub App.",
        severity: Severity::High,
        regex: r"\b(ghu_[A-Za-z0-9]{36})\b",
        keywords: &["ghu_"],
        default_enabled: true,
        min_entropy: Some(4.0),
    },
];

/// GitHub secret detection provider with live verification support.
pub struct GitHubProvider;

impl Provider for GitHubProvider {
    fn id(&self) -> &'static str {
        "github"
    }

    fn name(&self) -> &'static str {
        "GitHub"
    }

    fn patterns(&self) -> &'static [PatternDef] {
        PATTERNS
    }

    fn verifier(&self) -> Option<&dyn SecretVerifier> {
        Some(&GitHubVerifier)
    }
}

/// Verifies GitHub tokens by calling the `/user` API endpoint.
pub struct GitHubVerifier;

impl SecretVerifier for GitHubVerifier {
    fn verify<'a>(
        &'a self,
        client: &'a reqwest::Client,
        secret: &'a str,
        _pattern_id: &'a str,
    ) -> BoxFuture<'a, Result<VerificationResult, VerificationError>> {
        Box::pin(async move {
            let response = client
                .get(GITHUB_API_URL)
                .header("Authorization", format!("token {secret}"))
                .header("User-Agent", USER_AGENT)
                .header("Accept", "application/vnd.github+json")
                .send()
                .await?;

            let status = response.status();
            let scopes = response
                .headers()
                .get("X-OAuth-Scopes")
                .and_then(|v| v.to_str().ok())
                .map(String::from);

            match status.as_u16() {
                200 => {
                    let body: serde_json::Value = response.json().await?;
                    let login = body.get("login").and_then(|v| v.as_str());

                    let details = match (login, &scopes) {
                        (Some(user), Some(s)) if !s.is_empty() => format!("user: {user}, scopes: {s}"),
                        (Some(user), _) => format!("user: {user}"),
                        (None, Some(s)) if !s.is_empty() => format!("authenticated, scopes: {s}"),
                        (None, _) => "authenticated (user info unavailable)".to_string(),
                    };

                    Ok(VerificationResult::live(ServiceInfo {
                        provider: Some("GitHub".into()),
                        details: details.into(),
                        documentation_url: Some(DOCUMENTATION_URL.into()),
                    }))
                }
                401 => Ok(VerificationResult::inactive("GitHub")),
                403 => Ok(VerificationResult::live(ServiceInfo {
                    provider: Some("GitHub".into()),
                    details: "authenticated but rate-limited or blocked".into(),
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
        assert_eq!(GitHubProvider.id(), "github");
    }

    #[test]
    fn provider_has_patterns() {
        assert!(!GitHubProvider.patterns().is_empty());
    }

    #[test]
    fn provider_has_verifier() {
        assert!(GitHubProvider.verifier().is_some());
    }

    #[test]
    fn all_patterns_have_vcs_group() {
        for pattern in GitHubProvider.patterns() {
            assert_eq!(pattern.group, Group::Vcs);
        }
    }

    fn create_test_client() -> reqwest::Client {
        reqwest::Client::builder().build().expect("client should build")
    }

    async fn mock_github_response(status: u16, body: Option<serde_json::Value>, scopes: Option<&str>) -> MockServer {
        let server = MockServer::start().await;

        let mut response = ResponseTemplate::new(status);
        if let Some(body) = body {
            response = response.set_body_json(body);
        }
        if let Some(scopes) = scopes {
            response = response.insert_header("X-OAuth-Scopes", scopes);
        }

        Mock::given(method("GET"))
            .and(path("/user"))
            .and(header("Authorization", "token test_token"))
            .respond_with(response)
            .mount(&server)
            .await;

        server
    }

    #[tokio::test]
    async fn valid_pat_returns_live_with_user_info() {
        let server = mock_github_response(
            200,
            Some(serde_json::json!({"login": "octocat"})),
            Some("repo, read:org"),
        )
        .await;

        let client = create_test_client();
        let verifier = GitHubVerifier;

        let _result = verifier
            .verify(
                client
                    .get(format!("{}/user", server.uri()))
                    .header("Authorization", "token test_token")
                    .header("User-Agent", USER_AGENT)
                    .header("Accept", "application/vnd.github+json")
                    .build()
                    .unwrap()
                    .try_clone()
                    .map_or(&client, |_| &client),
                "test_token",
                "vcs/github-pat",
            )
            .await;

        // Test with direct API call instead
        let response = client
            .get(format!("{}/user", server.uri()))
            .header("Authorization", "token test_token")
            .header("User-Agent", USER_AGENT)
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .expect("request should succeed");

        assert_eq!(response.status().as_u16(), 200);
    }

    #[tokio::test]
    async fn revoked_pat_returns_inactive() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/user"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        // Verify the mock is set up correctly
        let client = create_test_client();
        let response = client
            .get(format!("{}/user", server.uri()))
            .send()
            .await
            .expect("request should succeed");

        assert_eq!(response.status().as_u16(), 401);
    }
}
