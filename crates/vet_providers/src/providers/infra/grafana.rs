//! Grafana secret patterns.

crate::declare_provider!(
    GrafanaProvider,
    id: "grafana",
    name: "Grafana",
    group: Group::Infra,
    patterns: [
        crate::pattern! {
                id: "infra/grafana-service-account-token",
                group: Group::Infra,
                name: "Grafana Service Account Token",
                description: "Authenticates as a service account with assigned RBAC roles.",
                severity: Severity::Critical,
                regex: r"\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})\b",
                keywords: &["glsa_"],
                default_enabled: true,
                min_entropy: Some(3.5),
            },
            crate::pattern! {
                id: "infra/grafana-cloud-api-token",
                group: Group::Infra,
                name: "Grafana Cloud API Token",
                description: "Grants scoped access to Grafana Cloud stacks and APIs.",
                severity: Severity::Critical,
                regex: r"\b(glc_[A-Za-z0-9+/]{20,}={0,2})\b",
                keywords: &["glc_"],
                default_enabled: true,
                min_entropy: Some(3.5),
            },
    ],
);
