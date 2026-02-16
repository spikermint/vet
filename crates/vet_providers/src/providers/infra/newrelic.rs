//! New Relic secret patterns.

crate::declare_provider!(
    NewRelicProvider,
    id: "newrelic",
    name: "New Relic",
    group: Group::Infra,
    patterns: [
        crate::pattern! {
            id: "infra/newrelic-user-api-key",
            group: Group::Infra,
            name: "New Relic User API Key",
            description: "Grants full API access to query telemetry and manage alerting.",
            severity: Severity::Critical,
            regex: r"\b(NRAK-[A-Z0-9]{27})\b",
            keywords: &["NRAK-"],
            default_enabled: true,
            min_entropy: Some(3.5),
        },
    ],
);
