//! Vercel secret patterns.

crate::declare_provider!(
    VercelProvider,
    id: "vercel",
    name: "Vercel",
    group: Group::Cloud,
    patterns: [
        crate::pattern! {
            id: "cloud/vercel-access-token",
            group: Group::Cloud,
            name: "Vercel Access Token",
            description: "Grants access to deploy, manage projects, and configure Vercel resources.",
            severity: Severity::High,
            regex: r#"(?i)vercel[_-]?(?:access[_-]?)?token[\s=:]+['"]?([a-zA-Z0-9]{24})['"]?"#,
            keywords: &["vercel"],
            default_enabled: true,
            min_entropy: Some(3.5),
        },
    ],
);
