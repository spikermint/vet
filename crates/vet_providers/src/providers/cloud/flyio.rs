//! Fly.io secret patterns.

crate::declare_provider!(
    FlyioProvider,
    id: "flyio",
    name: "Fly.io",
    group: Group::Cloud,
    patterns: [
        crate::pattern! {
                id: "cloud/flyio-access-token",
                group: Group::Cloud,
                name: "Fly.io Access Token",
                description: "Grants access to deploy and manage Fly.io applications.",
                severity: Severity::Critical,
                regex: r"\b(fo1_[A-Za-z0-9_-]{20,})\b",
                keywords: &["fo1_"],
                default_enabled: true,
                min_entropy: Some(3.5),
            },
            crate::pattern! {
                id: "cloud/flyio-deploy-token",
                group: Group::Cloud,
                name: "Fly.io Deploy Token",
                description: "Grants deployment access to Fly.io applications.",
                severity: Severity::High,
                regex: r"\b(fm2_[A-Za-z0-9_-]{20,})\b",
                keywords: &["fm2_"],
                default_enabled: true,
                min_entropy: Some(3.5),
            },
    ],
);
