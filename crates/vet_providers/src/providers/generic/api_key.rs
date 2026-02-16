//! Generic API key assignment patterns.

crate::declare_provider!(
    GenericApiKeyProvider,
    id: "generic-api-key",
    name: "Generic API Key",
    group: Group::Generic,
    patterns: [
        crate::pattern! {
            id: "generic/api-key-assignment",
            group: Group::Generic,
            name: "Generic API Key Assignment",
            description: "Grants access to an unidentified service via a hardcoded API key.",
            severity: Severity::Medium,
            regex: r#"(?i)(?:[\w.-]+[_.\-])?api[_.\-]?key(?:[_.\-][\w]*)?\s*(?:=|:|=>|:=)\s*['"`]([^\s'"`]{8,120})['"`]"#,
            keywords: &["api_key", "apikey", "api-key", "api.key"],
            default_enabled: false,
            min_entropy: Some(4.0),
        },
    ],
);

#[cfg(test)]
mod extra_tests {
    use regex::Regex;

    fn regex() -> Regex {
        Regex::new(
            r#"(?i)(?:[\w.-]+[_.\-])?api[_.\-]?key(?:[_.\-][\w]*)?\s*(?:=|:|=>|:=)\s*['"`]([^\s'"`]{8,120})['"`]"#,
        )
        .unwrap()
    }

    #[test]
    fn matches_my_api_key_double_quotes() {
        let re = regex();
        let m = re.captures(r#"MY_API_KEY = "a8Kj2mNx9pQ4rT7v""#);
        assert!(m.is_some());
        assert_eq!(m.unwrap().get(1).unwrap().as_str(), "a8Kj2mNx9pQ4rT7v");
    }

    #[test]
    fn matches_bare_api_key() {
        let re = regex();
        assert!(re.is_match(r#"api_key = "xK9mN2pQ4rT7vB5c""#));
    }

    #[test]
    fn matches_apikey_no_separator() {
        let re = regex();
        assert!(re.is_match(r#"apikey = "xK9mN2pQ4rT7vB5c""#));
    }

    #[test]
    fn matches_api_dash_key() {
        let re = regex();
        assert!(re.is_match(r#"api-key = "xK9mN2pQ4rT7vB5c""#));
    }

    #[test]
    fn matches_service_api_key_with_suffix() {
        let re = regex();
        assert!(re.is_match(r#"service_api_key_v2 = "xK9mN2pQ4rT7vB5c""#));
    }

    #[test]
    fn rejects_unquoted_value() {
        let re = regex();
        assert!(!re.is_match("API_KEY = some_variable_ref"));
    }

    #[test]
    fn rejects_short_value() {
        let re = regex();
        assert!(!re.is_match(r#"API_KEY = "short""#));
    }
}
