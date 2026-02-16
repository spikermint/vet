//! Databricks secret patterns.

crate::declare_provider!(
    DatabricksProvider,
    id: "databricks",
    name: "Databricks",
    group: Group::Cloud,
    patterns: [
        crate::pattern! {
            id: "cloud/databricks-pat",
            group: Group::Cloud,
            name: "Databricks Personal Access Token",
            description: "Grants access to Databricks workspaces, clusters, and data.",
            severity: Severity::Critical,
            regex: r"\b(dapi[a-f0-9]{32,40})\b",
            keywords: &["dapi"],
            default_enabled: true,
            min_entropy: Some(3.0),
        },
    ],
);

#[cfg(test)]
mod extra_tests {
    use regex::Regex;

    fn regex() -> Regex {
        Regex::new(r"\b(dapi[a-f0-9]{32,40})\b").unwrap()
    }

    #[test]
    fn matches_32_char_hex_token() {
        let re = regex();
        let key = format!("dapi{}", "a1b2c3d4".repeat(4));
        assert!(re.is_match(&key));
    }

    #[test]
    fn matches_40_char_hex_token() {
        let re = regex();
        let key = format!("dapi{}", "a1b2c3d4e5".repeat(4));
        assert!(re.is_match(&key));
    }

    #[test]
    fn rejects_uppercase_hex() {
        let re = regex();
        // Built at runtime to avoid triggering GitHub push protection.
        let key = format!("dapi{}", "A1B2C3D4".repeat(4));
        assert!(!re.is_match(&key));
    }

    #[test]
    fn rejects_too_short() {
        let re = regex();
        assert!(!re.is_match("dapia1b2c3d4a1b2c3d4"));
    }
}
