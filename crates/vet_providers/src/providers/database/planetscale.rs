//! PlanetScale secret patterns.

crate::declare_provider!(
    PlanetScaleProvider,
    id: "planetscale",
    name: "PlanetScale",
    group: Group::Database,
    patterns: [
        crate::pattern! {
                id: "database/planetscale-service-token",
                group: Group::Database,
                name: "PlanetScale Service Token",
                description: "Grants API access for database branch and deploy operations.",
                severity: Severity::Critical,
                regex: r"\b(pscale_tkn_[a-zA-Z0-9_.-]{32,64})\b",
                keywords: &["pscale_tkn_"],
                default_enabled: true,
                min_entropy: Some(3.5),
            },
            crate::pattern! {
                id: "database/planetscale-password",
                group: Group::Database,
                name: "PlanetScale Database Password",
                description: "Grants direct read/write access to database branches.",
                severity: Severity::Critical,
                regex: r"\b(pscale_pw_[a-zA-Z0-9_.-]{32,64})\b",
                keywords: &["pscale_pw_"],
                default_enabled: true,
                min_entropy: Some(3.5),
            },
            crate::pattern! {
                id: "database/planetscale-oauth-token",
                group: Group::Database,
                name: "PlanetScale OAuth Token",
                description: "Grants scoped API access based on OAuth permissions.",
                severity: Severity::High,
                regex: r"\b(pscale_oauth_[a-zA-Z0-9_.-]{32,64})\b",
                keywords: &["pscale_oauth_"],
                default_enabled: true,
                min_entropy: Some(3.5),
            },
    ],
);
