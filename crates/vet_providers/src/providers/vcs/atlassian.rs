//! Atlassian secret patterns (Jira, Confluence, Bitbucket).

crate::declare_provider!(
    AtlassianProvider,
    id: "atlassian",
    name: "Atlassian",
    group: Group::Vcs,
    patterns: [
        crate::pattern! {
            id: "vcs/atlassian-api-token",
            group: Group::Vcs,
            name: "Atlassian API Token",
            description: "Grants full API access to Jira, Confluence, and Bitbucket Cloud.",
            severity: Severity::Critical,
            regex: r"\b(ATATT3[A-Za-z0-9_=-]{186})\b",
            keywords: &["ATATT3"],
            default_enabled: true,
            min_entropy: Some(3.5),
        },
    ],
);
