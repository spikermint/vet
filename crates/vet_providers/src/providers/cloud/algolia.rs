//! Algolia secret patterns.

crate::declare_provider!(
    AlgoliaProvider,
    id: "algolia",
    name: "Algolia",
    group: Group::Cloud,
    patterns: [
        crate::pattern! {
            id: "cloud/algolia-api-key",
            group: Group::Cloud,
            name: "Algolia API Key",
            description: "Grants access to search, index, and manage Algolia data.",
            severity: Severity::High,
            regex: r#"(?i)algolia[_-]?(?:api[_-]?)?key[\s=:]+['"]?([a-f0-9]{32})['"]?"#,
            keywords: &["algolia"],
            default_enabled: true,
            min_entropy: Some(3.5),
        },
    ],
);
