//! CircleCI secret patterns.

crate::declare_provider!(
    CircleCIProvider,
    id: "circleci",
    name: "CircleCI",
    group: Group::Infra,
    patterns: [
        crate::pattern! {
            id: "infra/circleci-token",
            group: Group::Infra,
            name: "CircleCI Personal API Token",
            description: "Grants access to trigger builds, view pipelines, and manage CircleCI projects.",
            severity: Severity::High,
            regex: r#"(?i)circle(?:ci)?[_-]?token[\s=:]+['"]?([a-f0-9]{40})['"]?"#,
            keywords: &["circleci", "CIRCLECI", "CIRCLE_TOKEN"],
            default_enabled: true,
            min_entropy: Some(3.5),
        },
    ],
);
