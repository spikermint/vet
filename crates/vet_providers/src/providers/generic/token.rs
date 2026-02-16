//! Generic token assignment patterns.

crate::declare_provider!(
    GenericTokenProvider,
    id: "generic-token",
    name: "Generic Token",
    group: Group::Generic,
    patterns: [
        crate::pattern! {
            id: "generic/token-assignment",
            group: Group::Generic,
            name: "Generic Token Assignment",
            description: "Grants access to an unidentified service via a hardcoded access or auth token.",
            severity: Severity::Medium,
            regex: r#"(?i)(?:[\w.-]+[_.\-])?(?:access[_.\-]?token|auth[_.\-]?token|bearer[_.\-]?token|refresh[_.\-]?token)(?:[_.\-][\w]*)?\s*(?:=|:|=>|:=)\s*['"`]([^\s'"`]{8,120})['"`]"#,
            keywords: &["access_token", "auth_token", "bearer_token", "refresh_token"],
            default_enabled: false,
            min_entropy: Some(4.0),
        },
    ],
);

#[cfg(test)]
mod extra_tests {
    use regex::Regex;

    fn regex() -> Regex {
        Regex::new(r#"(?i)(?:[\w.-]+[_.\-])?(?:access[_.\-]?token|auth[_.\-]?token|bearer[_.\-]?token|refresh[_.\-]?token)(?:[_.\-][\w]*)?\s*(?:=|:|=>|:=)\s*['"`]([^\s'"`]{8,120})['"`]"#).unwrap()
    }

    #[test]
    fn matches_access_token_double_quotes() {
        let re = regex();
        let m = re.captures(r#"access_token = "a8Kj2mNx9pQ4rT7v""#);
        assert!(m.is_some());
        assert_eq!(m.unwrap().get(1).unwrap().as_str(), "a8Kj2mNx9pQ4rT7v");
    }

    #[test]
    fn matches_my_auth_token() {
        let re = regex();
        assert!(re.is_match(r#"MY_AUTH_TOKEN = "xK9mN2pQ4rT7vB5c""#));
    }

    #[test]
    fn matches_bearer_token() {
        let re = regex();
        assert!(re.is_match(r#"bearer_token = "xK9mN2pQ4rT7vB5c""#));
    }

    #[test]
    fn matches_refresh_token() {
        let re = regex();
        assert!(re.is_match(r#"refresh_token = "xK9mN2pQ4rT7vB5c""#));
    }

    #[test]
    fn matches_with_prefix_and_suffix() {
        let re = regex();
        assert!(re.is_match(r#"app_access_token_v2 = "xK9mN2pQ4rT7vB5c""#));
    }

    #[test]
    fn rejects_unquoted_value() {
        let re = regex();
        assert!(!re.is_match("access_token = some_variable_ref"));
    }

    #[test]
    fn rejects_bare_token_without_qualifier() {
        let re = regex();
        assert!(!re.is_match(r#"token = "xK9mN2pQ4rT7vB5c""#));
    }
}
