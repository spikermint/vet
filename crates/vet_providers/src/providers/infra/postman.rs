//! Postman secret patterns.

crate::declare_provider!(
    PostmanProvider,
    id: "postman",
    name: "Postman",
    group: Group::Infra,
    patterns: [
        crate::pattern! {
            id: "infra/postman-api-key",
            group: Group::Infra,
            name: "Postman API Key",
            description: "Grants access to collections, environments, and workspace data.",
            severity: Severity::High,
            regex: r"\b(PMAK-[a-f0-9]{24}-[a-f0-9]{34})\b",
            keywords: &["PMAK-"],
            default_enabled: true,
            min_entropy: Some(3.5),
        },
    ],
);
