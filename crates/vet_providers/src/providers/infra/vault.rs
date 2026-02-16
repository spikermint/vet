//! HashiCorp Vault secret patterns.

crate::declare_provider!(
    VaultProvider,
    id: "vault",
    name: "HashiCorp Vault",
    group: Group::Infra,
    patterns: [
        crate::pattern! {
                id: "infra/vault-batch-token",
                group: Group::Infra,
                name: "HashiCorp Vault Batch Token",
                description: "Grants access to secrets based on token policies.",
                severity: Severity::High,
                regex: r"\b(hvb\.[a-zA-Z0-9_-]{24,})\b",
                keywords: &["hvb."],
                default_enabled: true,
                min_entropy: Some(3.0),
            },
            crate::pattern! {
                id: "infra/vault-service-token",
                group: Group::Infra,
                name: "HashiCorp Vault Service Token",
                description: "Grants access to secrets and encryption keys.",
                severity: Severity::Critical,
                regex: r"\b(hvs\.[a-zA-Z0-9_-]{24,})\b",
                keywords: &["hvs."],
                default_enabled: true,
                min_entropy: Some(3.0),
            },
    ],
);
