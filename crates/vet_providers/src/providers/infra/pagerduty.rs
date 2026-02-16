//! `PagerDuty` secret patterns.
//!
//! `PagerDuty` tokens are 20-character alphanumeric strings with no distinctive
//! prefix, so detection requires contextual matching on the variable name.
//!
//! Regex structure: `<var containing "pagerduty"> <assignment op> <quoted value>`
//!   - Variable: `[\w.-]+` with `pagerduty` somewhere in the name
//!   - Assignment: `=`, `:`, `=>`, or `:=`
//!   - Value: 20-char alphanumeric with `+`

crate::declare_provider!(
    PagerDutyProvider,
    id: "pagerduty",
    name: "PagerDuty",
    group: Group::Infra,
    patterns: [
        crate::pattern! {
            id: "infra/pagerduty-api-key",
            group: Group::Infra,
            name: "PagerDuty API Key",
            description: "Grants access to PagerDuty incident management, on-call schedules, and services.",
            severity: Severity::High,
            regex: r#"(?i)(?:[\w.-]+[_.\-])?(?:pagerduty)(?:[_.\-][\w]*)?\s*(?:=|:|=>|:=)\s*['"`]([A-Za-z0-9+]{20})['"`]"#,
            keywords: &["pagerduty"],
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
            r#"(?i)(?:[\w.-]+[_.\-])?(?:pagerduty)(?:[_.\-][\w]*)?\s*(?:=|:|=>|:=)\s*['"`]([A-Za-z0-9+]{20})['"`]"#,
        )
        .unwrap()
    }

    #[test]
    fn matches_pagerduty_api_key_var() {
        let re = regex();
        assert!(re.is_match(r#"PAGERDUTY_API_KEY = "aBcDeFgH12345678abCd""#));
    }

    #[test]
    fn rejects_without_pagerduty_context() {
        let re = regex();
        assert!(!re.is_match(r#"API_KEY = "aBcDeFgH12345678abCd""#));
    }

    #[test]
    fn matches_pagerduty_token_with_dot() {
        let re = regex();
        assert!(re.is_match(r#"pagerduty.token = "aBcDeFgH12345678abCd""#));
    }
}
