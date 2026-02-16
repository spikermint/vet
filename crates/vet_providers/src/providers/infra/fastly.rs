//! Fastly secret patterns.
//!
//! Fastly tokens are 32-character alphanumeric strings with no distinctive
//! prefix, so detection requires contextual matching on the variable name.
//!
//! Regex structure: `<var containing "fastly"> <assignment op> <quoted value>`
//!   - Variable: `[\w.-]+` with `fastly` somewhere in the name
//!   - Assignment: `=`, `:`, `=>`, or `:=`
//!   - Value: 32-char alphanumeric with underscores/hyphens

crate::declare_provider!(
    FastlyProvider,
    id: "fastly",
    name: "Fastly",
    group: Group::Infra,
    patterns: [
        crate::pattern! {
            id: "infra/fastly-api-token",
            group: Group::Infra,
            name: "Fastly API Token",
            description: "Grants access to Fastly CDN configuration, purging, and service management.",
            severity: Severity::High,
            regex: r#"(?i)(?:[\w.-]+[_.\-])?(?:fastly)(?:[_.\-][\w]*)?\s*(?:=|:|=>|:=)\s*['"`]([A-Za-z0-9_-]{32})['"`]"#,
            keywords: &["fastly"],
            default_enabled: true,
            min_entropy: Some(3.5),
        },
    ],
);

#[cfg(test)]
mod extra_tests {
    use regex::Regex;

    fn regex() -> Regex {
        Regex::new(
            r#"(?i)(?:[\w.-]+[_.\-])?(?:fastly)(?:[_.\-][\w]*)?\s*(?:=|:|=>|:=)\s*['"`]([A-Za-z0-9_-]{32})['"`]"#,
        )
        .unwrap()
    }

    #[test]
    fn matches_fastly_api_token_var() {
        let re = regex();
        assert!(re.is_match(r#"FASTLY_API_TOKEN = "aBcDeFgH12345678aBcDeFgH12345678""#));
    }

    #[test]
    fn rejects_without_fastly_context() {
        let re = regex();
        assert!(!re.is_match(r#"API_TOKEN = "aBcDeFgH12345678aBcDeFgH12345678""#));
    }

    #[test]
    fn matches_fastly_key_with_dot_separator() {
        let re = regex();
        assert!(re.is_match(r#"fastly.token = "aBcDeFgH12345678aBcDeFgH12345678""#));
    }
}
