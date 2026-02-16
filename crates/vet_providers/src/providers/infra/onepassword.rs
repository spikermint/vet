//! 1Password secret patterns.

crate::declare_provider!(
    OnePasswordProvider,
    id: "onepassword",
    name: "1Password",
    group: Group::Infra,
    patterns: [
        crate::pattern! {
            id: "infra/onepassword-service-account-token",
            group: Group::Infra,
            name: "1Password Service Account Token",
            description: "Grants access to 1Password vaults via service account.",
            severity: Severity::Critical,
            regex: r"\b(ops_[A-Za-z0-9_-]{40,})\b",
            keywords: &["ops_"],
            default_enabled: true,
            min_entropy: Some(4.0),
        },
    ],
);
