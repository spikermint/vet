//! Sentry secret patterns.

crate::declare_provider!(
    SentryProvider,
    id: "sentry",
    name: "Sentry",
    group: Group::Infra,
    patterns: [
        crate::pattern! {
            id: "infra/sentry-auth-token",
            group: Group::Infra,
            name: "Sentry Auth Token",
            description: "Grants access to Sentry API for managing projects, releases, and issues.",
            severity: Severity::High,
            regex: r"\b(sntrys_[A-Za-z0-9_]{50,})\b",
            keywords: &["sntrys_"],
            default_enabled: true,
            min_entropy: Some(3.5),
        },
    ],
);
