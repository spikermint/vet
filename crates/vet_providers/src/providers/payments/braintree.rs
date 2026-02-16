//! Braintree payment secret patterns.

crate::declare_provider!(
    BraintreeProvider,
    id: "braintree",
    name: "Braintree",
    group: Group::Payments,
    patterns: [
        crate::pattern! {
            id: "payments/braintree-access-token",
            group: Group::Payments,
            name: "Braintree Access Token",
            description: "Grants access to payment processing APIs.",
            severity: Severity::Critical,
            regex: r"\b(access_token\$(?:production|sandbox)\$[a-z0-9]{16}\$[a-f0-9]{32})\b",
            keywords: &["access_token$production$", "access_token$sandbox$"],
            default_enabled: true,
            min_entropy: Some(4.0),
        },
    ],
);
