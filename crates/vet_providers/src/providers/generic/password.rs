//! Generic password assignment patterns.

crate::declare_provider!(
    GenericPasswordProvider,
    id: "generic-password",
    name: "Generic Password",
    group: Group::Generic,
    patterns: [
        crate::pattern! {
            id: "generic/password-assignment",
            group: Group::Generic,
            name: "Generic Password Assignment",
            description: "Grants access to an unidentified service via a hardcoded password.",
            severity: Severity::Medium,
            regex: r#"(?i)(?:[\w.-]+[_.\-])(?:password|passwd|pwd)(?:[_.\-][\w]*)?\s*(?:=|:|=>|:=)\s*['"`]([^\s'"`]{8,120})['"`]"#,
            keywords: &["password", "passwd", "pwd"],
            default_enabled: true,
            min_entropy: Some(4.0),
            strategy: crate::pattern::DetectionStrategy::AstAssignment,
        },
    ],
);

#[cfg(test)]
mod extra_tests {
    use regex::Regex;

    fn regex() -> Regex {
        Regex::new(r#"(?i)(?:[\w.-]+[_.\-])(?:password|passwd|pwd)(?:[_.\-][\w]*)?\s*(?:=|:|=>|:=)\s*['"`]([^\s'"`]{8,120})['"`]"#).unwrap()
    }

    #[test]
    fn matches_db_password_double_quotes() {
        let re = regex();
        let m = re.captures(r#"DB_PASSWORD = "a8Kj2mNx9pQ4rT7v""#);
        assert!(m.is_some());
        assert_eq!(m.unwrap().get(1).unwrap().as_str(), "a8Kj2mNx9pQ4rT7v");
    }

    #[test]
    fn matches_my_password_hash_with_suffix() {
        let re = regex();
        assert!(re.is_match(r#"my_password_hash = "xK9mN2pQ4rT7vB5c""#));
    }

    #[test]
    fn matches_api_dot_password_dot_value() {
        let re = regex();
        assert!(re.is_match(r#"api.password.value = "xK9mN2pQ4rT7vB5c""#));
    }

    #[test]
    fn matches_passwd_variant() {
        let re = regex();
        assert!(re.is_match(r#"db_passwd = "xK9mN2pQ4rT7vB5c""#));
    }

    #[test]
    fn matches_pwd_variant() {
        let re = regex();
        assert!(re.is_match(r#"admin_pwd = "xK9mN2pQ4rT7vB5c""#));
    }

    #[test]
    fn rejects_ospassword_substring() {
        let re = regex();
        assert!(!re.is_match(r#"ospassword = "xK9mN2pQ4rT7vB5c""#));
    }

    #[test]
    fn rejects_keyboard_no_trigger() {
        let re = regex();
        assert!(!re.is_match(r#"keyboard = "xK9mN2pQ4rT7vB5c""#));
    }

    #[test]
    fn rejects_unquoted_function_call() {
        let re = regex();
        assert!(!re.is_match("DB_PASSWORD = memblock_alloc_raw(len, SMP_CACHE_BYTES)"));
    }

    #[test]
    fn rejects_bare_password_without_prefix() {
        let re = regex();
        assert!(!re.is_match(r#"password = "xK9mN2pQ4rT7vB5c""#));
    }
}
