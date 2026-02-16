//! Airtable secret patterns.

crate::declare_provider!(
    AirtableProvider,
    id: "airtable",
    name: "Airtable",
    group: Group::Cloud,
    patterns: [
        crate::pattern! {
            id: "cloud/airtable-pat",
            group: Group::Cloud,
            name: "Airtable Personal Access Token",
            description: "Grants access to Airtable bases, tables, and records.",
            severity: Severity::Critical,
            regex: r"\b(pat[a-zA-Z0-9]{14}\.[a-f0-9]{64})\b",
            keywords: &["pat"],
            default_enabled: true,
            min_entropy: Some(4.0),
        },
    ],
);

#[cfg(test)]
mod extra_tests {
    use regex::Regex;

    fn regex() -> Regex {
        Regex::new(r"\b(pat[a-zA-Z0-9]{14}\.[a-f0-9]{64})\b").unwrap()
    }

    #[test]
    fn matches_airtable_pat_format() {
        let re = regex();
        let key = format!("pat{}.", "aBcDeFgHiJkLmN");
        let key = format!("{key}{}", "a1b2c3d4".repeat(8));
        assert!(re.is_match(&key));
    }

    #[test]
    fn rejects_missing_dot_separator() {
        let re = regex();
        let key = format!("pat{}{}", "aBcDeFgHiJkLmN", "a1b2c3d4".repeat(8));
        assert!(!re.is_match(&key));
    }

    #[test]
    fn rejects_wrong_hex_part_length() {
        let re = regex();
        let key = format!("pat{}.{}", "aBcDeFgHiJkLmN", "a1b2c3d4");
        assert!(!re.is_match(&key));
    }
}
