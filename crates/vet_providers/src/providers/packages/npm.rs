//! npm registry secret patterns.

crate::declare_provider!(
    NpmProvider,
    id: "npm",
    name: "npm",
    group: Group::Packages,
    patterns: [
        crate::pattern! {
            id: "packages/npm-access-token",
            group: Group::Packages,
            name: "npm Access Token",
            description: "Grants publish access to npm packages (supply chain risk).",
            severity: Severity::Critical,
            regex: r"\b(npm_[A-Za-z0-9]{36,40})\b",
            keywords: &["npm_"],
            default_enabled: true,
            min_entropy: Some(3.5),
        },
    ],
);
