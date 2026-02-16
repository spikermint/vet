//! Square payment secret patterns.

crate::declare_provider!(
    SquareProvider,
    id: "square",
    name: "Square",
    group: Group::Payments,
    patterns: [
        crate::pattern! {
                id: "payments/square-access-token",
                group: Group::Payments,
                name: "Square Access Token",
                description: "Grants access to payment, inventory, and customer APIs.",
                severity: Severity::Critical,
                regex: r"\b((?:EAAA[a-zA-Z0-9_-]{40,80}|sq0atp-[a-zA-Z0-9_-]{22,60}))\b",
                keywords: &["EAAA", "sq0atp-"],
                default_enabled: true,
                min_entropy: Some(4.0),
            },
            crate::pattern! {
                id: "payments/square-application-secret",
                group: Group::Payments,
                name: "Square Application Secret",
                description: "Allows OAuth flows to obtain access tokens.",
                severity: Severity::Critical,
                regex: r"\b(sq0csp-[a-zA-Z0-9_-]{40,50})\b",
                keywords: &["sq0csp-"],
                default_enabled: true,
                min_entropy: Some(4.0),
            },
    ],
);
