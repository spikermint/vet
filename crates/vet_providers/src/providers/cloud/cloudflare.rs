//! Cloudflare secret patterns.
//!
//! Cloudflare API tokens and Global API keys have no distinctive prefix,
//! so detection requires contextual matching on the variable name.
//!
//! Regex structure: `<var containing "cloudflare"> <assignment op> <quoted value>`
//!   - Variable: `[\w.-]+` with `cloudflare` somewhere in the name
//!   - Assignment: `=`, `:`, `=>`, or `:=`
//!   - API token value: 40-char base62 with underscores/hyphens
//!   - Global API key value: 37-char lowercase hex

crate::declare_provider!(
    CloudflareProvider,
    id: "cloudflare",
    name: "Cloudflare",
    group: Group::Cloud,
    patterns: [
        crate::pattern! {
            id: "cloud/cloudflare-api-token",
            group: Group::Cloud,
            name: "Cloudflare API Token",
            description: "Grants scoped access to Cloudflare services (DNS, Workers, R2, etc.).",
            severity: Severity::High,
            regex: r#"(?i)(?:[\w.-]+[_.\-])?(?:cloudflare)(?:[_.\-][\w]*)?\s*(?:=|:|=>|:=)\s*['"`]([A-Za-z0-9_-]{40})['"`]"#,
            keywords: &["cloudflare"],
            default_enabled: true,
            min_entropy: Some(4.0),
        },
        crate::pattern! {
            id: "cloud/cloudflare-global-api-key",
            group: Group::Cloud,
            name: "Cloudflare Global API Key",
            description: "Grants full administrative access to all Cloudflare account resources.",
            severity: Severity::Critical,
            regex: r#"(?i)(?:[\w.-]+[_.\-])?(?:cloudflare)(?:[_.\-][\w]*)?\s*(?:=|:|=>|:=)\s*['"`]([a-f0-9]{37})['"`]"#,
            keywords: &["cloudflare"],
            default_enabled: true,
            min_entropy: Some(3.5),
        },
    ],
);

#[cfg(test)]
mod extra_tests {
    use regex::Regex;

    fn api_token_regex() -> Regex {
        Regex::new(
            r#"(?i)(?:[\w.-]+[_.\-])?(?:cloudflare)(?:[_.\-][\w]*)?\s*(?:=|:|=>|:=)\s*['"`]([A-Za-z0-9_-]{40})['"`]"#,
        )
        .unwrap()
    }

    fn global_key_regex() -> Regex {
        Regex::new(r#"(?i)(?:[\w.-]+[_.\-])?(?:cloudflare)(?:[_.\-][\w]*)?\s*(?:=|:|=>|:=)\s*['"`]([a-f0-9]{37})['"`]"#)
            .unwrap()
    }

    #[test]
    fn api_token_matches_cloudflare_api_token_var() {
        let re = api_token_regex();
        assert!(re.is_match(r#"CLOUDFLARE_API_TOKEN = "aBcDeFgHiJkLmNoPqRsTuVwXyZ12345678901234""#));
    }

    #[test]
    fn api_token_rejects_without_cloudflare_context() {
        let re = api_token_regex();
        assert!(!re.is_match(r#"API_TOKEN = "aBcDeFgHiJkLmNoPqRsTuVwXyZ12345678901234""#));
    }

    #[test]
    fn global_key_matches_cloudflare_global_key_var() {
        let re = global_key_regex();
        assert!(re.is_match(r#"CLOUDFLARE_GLOBAL_KEY = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a""#));
    }

    #[test]
    fn global_key_rejects_without_cloudflare_context() {
        let re = global_key_regex();
        assert!(!re.is_match(r#"API_KEY = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a""#));
    }
}
