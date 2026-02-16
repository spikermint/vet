//! `DeepSeek` secret patterns.

crate::declare_provider!(
    DeepSeekProvider,
    id: "deepseek",
    name: "DeepSeek",
    group: Group::Ai,
    patterns: [
        crate::pattern! {
            id: "ai/deepseek-api-key",
            group: Group::Ai,
            name: "DeepSeek API Key",
            description: "Grants access to DeepSeek AI models with billing.",
            severity: Severity::Critical,
            regex: r"\b(sk-[a-f0-9]{48})\b",
            keywords: &["sk-"],
            default_enabled: true,
            min_entropy: Some(3.5),
        },
    ],
);

#[cfg(test)]
mod extra_tests {
    use regex::Regex;

    fn regex() -> Regex {
        Regex::new(r"\b(sk-[a-f0-9]{48})\b").unwrap()
    }

    #[test]
    fn matches_deepseek_key_format() {
        let re = regex();
        let key = format!("sk-{}", "a1b2c3d4e5f6".repeat(4));
        assert!(re.is_match(&key));
    }

    #[test]
    fn rejects_openai_project_key_prefix() {
        let re = regex();
        assert!(!re.is_match("sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcdef12345678"));
    }

    #[test]
    fn rejects_uppercase_hex() {
        let re = regex();
        let key = format!("sk-{}", "A1B2C3D4E5F6".repeat(4));
        assert!(!re.is_match(&key));
    }

    #[test]
    fn rejects_wrong_length() {
        let re = regex();
        assert!(!re.is_match("sk-a1b2c3d4e5f6a1b2c3d4"));
    }
}
