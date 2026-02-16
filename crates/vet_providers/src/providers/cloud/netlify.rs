//! Netlify secret patterns.

crate::declare_provider!(
    NetlifyProvider,
    id: "netlify",
    name: "Netlify",
    group: Group::Cloud,
    patterns: [
        crate::pattern! {
            id: "cloud/netlify-personal-access-token",
            group: Group::Cloud,
            name: "Netlify Personal Access Token",
            description: "Grants full API access to deploy sites and manage account.",
            severity: Severity::Critical,
            regex: r"\b(nfp_[a-zA-Z0-9]{36,40})\b",
            keywords: &["nfp_"],
            default_enabled: true,
            min_entropy: Some(3.5),
        },
    ],
);
