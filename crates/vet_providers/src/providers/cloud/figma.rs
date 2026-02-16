//! Figma secret patterns.

crate::declare_provider!(
    FigmaProvider,
    id: "figma",
    name: "Figma",
    group: Group::Cloud,
    patterns: [
        crate::pattern! {
            id: "cloud/figma-personal-access-token",
            group: Group::Cloud,
            name: "Figma Personal Access Token",
            description: "Grants access to Figma files, projects, and team resources.",
            severity: Severity::High,
            regex: r"\b(figd_[A-Za-z0-9_-]{40,})\b",
            keywords: &["figd_"],
            default_enabled: true,
            min_entropy: Some(3.5),
        },
    ],
);
