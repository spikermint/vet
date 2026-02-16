//! Linear secret patterns.

crate::declare_provider!(
    LinearProvider,
    id: "linear",
    name: "Linear",
    group: Group::Cloud,
    patterns: [
        crate::pattern! {
            id: "cloud/linear-api-key",
            group: Group::Cloud,
            name: "Linear API Key",
            description: "Grants full API access to issues, projects, and organisation data.",
            severity: Severity::Critical,
            regex: r"\b(lin_api_[a-zA-Z0-9]{40})\b",
            keywords: &["lin_api_"],
            default_enabled: true,
            min_entropy: Some(3.5),
        },
    ],
);
