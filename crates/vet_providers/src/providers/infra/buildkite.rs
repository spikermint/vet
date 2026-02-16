//! Buildkite secret patterns.

crate::declare_provider!(
    BuildkiteProvider,
    id: "buildkite",
    name: "Buildkite",
    group: Group::Infra,
    patterns: [
        crate::pattern! {
            id: "infra/buildkite-api-token",
            group: Group::Infra,
            name: "Buildkite API Access Token",
            description: "Grants access to Buildkite organisations, pipelines, and builds.",
            severity: Severity::Critical,
            regex: r"\b(bkua_[a-f0-9]{40})\b",
            keywords: &["bkua_"],
            default_enabled: true,
            min_entropy: Some(3.0),
        },
        crate::pattern! {
            id: "infra/buildkite-agent-token",
            group: Group::Infra,
            name: "Buildkite Agent Token",
            description: "Grants an agent permission to connect to Buildkite and run builds.",
            severity: Severity::Critical,
            regex: r"\b(bkct_[a-f0-9]{40})\b",
            keywords: &["bkct_"],
            default_enabled: true,
            min_entropy: Some(3.0),
        },
        crate::pattern! {
            id: "infra/buildkite-session-token",
            group: Group::Infra,
            name: "Buildkite Session Token",
            description: "Grants temporary session access to Buildkite resources.",
            severity: Severity::High,
            regex: r"\b(bkat_[a-f0-9]{40})\b",
            keywords: &["bkat_"],
            default_enabled: true,
            min_entropy: Some(3.0),
        },
    ],
);

#[cfg(test)]
mod extra_tests {
    use regex::Regex;

    #[test]
    fn api_token_matches_bkua_prefix() {
        let re = Regex::new(r"\b(bkua_[a-f0-9]{40})\b").unwrap();
        let key = format!("bkua_{}", "a1b2c3d4e5".repeat(4));
        assert!(re.is_match(&key));
    }

    #[test]
    fn agent_token_matches_bkct_prefix() {
        let re = Regex::new(r"\b(bkct_[a-f0-9]{40})\b").unwrap();
        let key = format!("bkct_{}", "a1b2c3d4e5".repeat(4));
        assert!(re.is_match(&key));
    }

    #[test]
    fn session_token_matches_bkat_prefix() {
        let re = Regex::new(r"\b(bkat_[a-f0-9]{40})\b").unwrap();
        let key = format!("bkat_{}", "a1b2c3d4e5".repeat(4));
        assert!(re.is_match(&key));
    }

    #[test]
    fn rejects_uppercase_hex() {
        let re = Regex::new(r"\b(bkua_[a-f0-9]{40})\b").unwrap();
        assert!(!re.is_match("bkua_A1B2C3D4E5A1B2C3D4E5A1B2C3D4E5A1B2C3D4E5"));
    }

    #[test]
    fn rejects_wrong_length() {
        let re = Regex::new(r"\b(bkua_[a-f0-9]{40})\b").unwrap();
        assert!(!re.is_match("bkua_a1b2c3d4"));
    }
}
