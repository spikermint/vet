//! Datadog secret patterns.

crate::declare_provider!(
    DatadogProvider,
    id: "datadog",
    name: "Datadog",
    group: Group::Infra,
    patterns: [
        crate::pattern! {
                id: "infra/datadog-api-key",
                group: Group::Infra,
                name: "Datadog API Key",
                description: "Grants access to submit metrics, events, and logs to Datadog.",
                severity: Severity::High,
                regex: r#"(?i)(?:datadog|dd)[_-]?api[_-]?key[\s=:]+['"]?([a-f0-9]{32})['"]?"#,
                keywords: &["datadog", "dd_api", "dd-api"],
                default_enabled: true,
                min_entropy: Some(3.0),
            },
            crate::pattern! {
                id: "infra/datadog-app-key",
                group: Group::Infra,
                name: "Datadog Application Key",
                description: "Grants access to Datadog dashboards, monitors, and configuration.",
                severity: Severity::High,
                regex: r#"(?i)(?:datadog|dd)[_-]?app(?:lication)?[_-]?key[\s=:]+['"]?([a-f0-9]{40})['"]?"#,
                keywords: &["datadog", "dd_app", "dd-app"],
                default_enabled: true,
                min_entropy: Some(3.0),
            },
    ],
);
