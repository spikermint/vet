//! DigitalOcean secret patterns.

crate::declare_provider!(
    DigitalOceanProvider,
    id: "digitalocean",
    name: "DigitalOcean",
    group: Group::Cloud,
    patterns: [
        crate::pattern! {
                id: "cloud/digitalocean-oauth-token",
                group: Group::Cloud,
                name: "DigitalOcean OAuth Token",
                description: "Grants scoped API access via OAuth flow.",
                severity: Severity::Critical,
                regex: r"\b(doo_v1_[a-f0-9]{64})\b",
                keywords: &["doo_v1_"],
                default_enabled: true,
                min_entropy: Some(3.0),
            },
            crate::pattern! {
                id: "cloud/digitalocean-pat",
                group: Group::Cloud,
                name: "DigitalOcean Personal Access Token",
                description: "Grants full API access to manage cloud resources.",
                severity: Severity::Critical,
                regex: r"\b(dop_v1_[a-f0-9]{64})\b",
                keywords: &["dop_v1_"],
                default_enabled: true,
                min_entropy: Some(3.0),
            },
            crate::pattern! {
                id: "cloud/digitalocean-refresh-token",
                group: Group::Cloud,
                name: "DigitalOcean OAuth Refresh Token",
                description: "Can be exchanged for new access tokens.",
                severity: Severity::High,
                regex: r"\b(dor_v1_[a-f0-9]{64})\b",
                keywords: &["dor_v1_"],
                default_enabled: true,
                min_entropy: Some(3.0),
            },
    ],
);
