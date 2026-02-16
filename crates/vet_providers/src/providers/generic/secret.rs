//! Generic secret assignment patterns.

crate::declare_provider!(
    GenericSecretProvider,
    id: "generic-secret",
    name: "Generic Secret",
    group: Group::Generic,
    patterns: [
        crate::pattern! {
            id: "generic/secret-assignment",
            group: Group::Generic,
            name: "Generic Secret Assignment",
            description: "Grants access to an unidentified service via a hardcoded secret or credential.",
            severity: Severity::Medium,
            regex: r#"(?i)(?:[\w.-]+[_.\-])(?:secret|credential)(?:[_.\-][\w]*)?\s*(?:=|:|=>|:=)\s*['"`]([^\s'"`]{8,120})['"`]"#,
            keywords: &["secret", "credential"],
            default_enabled: false,
            min_entropy: Some(4.0),
        },
    ],
);

#[cfg(test)]
mod extra_tests {
    use regex::Regex;

    fn regex() -> Regex {
        Regex::new(r#"(?i)(?:[\w.-]+[_.\-])(?:secret|credential)(?:[_.\-][\w]*)?\s*(?:=|:|=>|:=)\s*['"`]([^\s'"`]{8,120})['"`]"#).unwrap()
    }

    #[test]
    fn matches_db_secret_with_underscore_prefix() {
        let re = regex();
        let m = re.captures(r#"DB_SECRET = "a8Kj2mNx9pQ4rT7v""#);
        assert!(m.is_some());
        assert_eq!(m.unwrap().get(1).unwrap().as_str(), "a8Kj2mNx9pQ4rT7v");
    }

    #[test]
    fn matches_api_credential_with_dot_prefix() {
        let re = regex();
        assert!(re.is_match(r#"api.credential = "xK9mN2pQ4rT7vB5c""#));
    }

    #[test]
    fn matches_colon_assignment() {
        let re = regex();
        assert!(re.is_match(r#"my_secret: "xK9mN2pQ4rT7vB5c""#));
    }

    #[test]
    fn matches_fat_arrow_assignment() {
        let re = regex();
        assert!(re.is_match(r#"app_secret => "xK9mN2pQ4rT7vB5c""#));
    }

    #[test]
    fn rejects_bare_secret_without_prefix() {
        let re = regex();
        assert!(!re.is_match(r#"secret = "xK9mN2pQ4rT7vB5c""#));
    }

    #[test]
    fn rejects_unquoted_value() {
        let re = regex();
        assert!(!re.is_match("DB_SECRET = some_variable_ref"));
    }

    #[test]
    fn rejects_short_value() {
        let re = regex();
        assert!(!re.is_match(r#"DB_SECRET = "short""#));
    }

    #[test]
    fn rejects_substring_trigger_ossecret() {
        let re = regex();
        assert!(!re.is_match(r#"ossecret = "xK9mN2pQ4rT7vB5c""#));
    }
}
