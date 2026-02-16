//! Confluent secret patterns.
//!
//! Confluent keys have no distinctive prefix, so detection requires
//! contextual matching on the variable name.
//!
//! Regex structure: `<var containing "confluent"> <assignment op> <quoted value>`
//!   - Variable: `[\w.-]+` with `confluent` somewhere in the name
//!   - Assignment: `=`, `:`, `=>`, or `:=`
//!   - API key value: 16-char alphanumeric
//!   - API secret value: 64-char base64

crate::declare_provider!(
    ConfluentProvider,
    id: "confluent",
    name: "Confluent",
    group: Group::Infra,
    patterns: [
        crate::pattern! {
            id: "infra/confluent-api-key",
            group: Group::Infra,
            name: "Confluent API Key",
            description: "Grants access to Confluent Cloud Kafka clusters and resources.",
            severity: Severity::High,
            regex: r#"(?i)(?:[\w.-]+[_.\-])?(?:confluent)(?:[_.\-][\w]*)?\s*(?:=|:|=>|:=)\s*['"`]([A-Za-z0-9]{16})['"`]"#,
            keywords: &["confluent"],
            default_enabled: true,
            min_entropy: Some(3.5),
        },
        crate::pattern! {
            id: "infra/confluent-api-secret",
            group: Group::Infra,
            name: "Confluent API Secret",
            description: "Grants full access to Confluent Cloud Kafka clusters and streaming resources.",
            severity: Severity::Critical,
            regex: r#"(?i)(?:[\w.-]+[_.\-])?(?:confluent)(?:[_.\-][\w]*)?\s*(?:=|:|=>|:=)\s*['"`]([A-Za-z0-9+/]{64})['"`]"#,
            keywords: &["confluent"],
            default_enabled: true,
            min_entropy: Some(4.0),
        },
    ],
);

#[cfg(test)]
mod extra_tests {
    use regex::Regex;

    fn api_key_regex() -> Regex {
        Regex::new(
            r#"(?i)(?:[\w.-]+[_.\-])?(?:confluent)(?:[_.\-][\w]*)?\s*(?:=|:|=>|:=)\s*['"`]([A-Za-z0-9]{16})['"`]"#,
        )
        .unwrap()
    }

    fn api_secret_regex() -> Regex {
        Regex::new(
            r#"(?i)(?:[\w.-]+[_.\-])?(?:confluent)(?:[_.\-][\w]*)?\s*(?:=|:|=>|:=)\s*['"`]([A-Za-z0-9+/]{64})['"`]"#,
        )
        .unwrap()
    }

    #[test]
    fn api_key_matches_confluent_key_var() {
        let re = api_key_regex();
        assert!(re.is_match(r#"CONFLUENT_API_KEY = "aBcDeFgH12345678""#));
    }

    #[test]
    fn api_key_rejects_without_confluent_context() {
        let re = api_key_regex();
        assert!(!re.is_match(r#"API_KEY = "aBcDeFgH12345678""#));
    }

    #[test]
    fn api_secret_matches_confluent_secret_var() {
        let re = api_secret_regex();
        let secret = "A".repeat(64);
        assert!(re.is_match(&format!(r#"CONFLUENT_SECRET = "{secret}""#)));
    }

    #[test]
    fn api_secret_rejects_without_confluent_context() {
        let re = api_secret_regex();
        let secret = "A".repeat(64);
        assert!(!re.is_match(&format!(r#"API_SECRET = "{secret}""#)));
    }
}
