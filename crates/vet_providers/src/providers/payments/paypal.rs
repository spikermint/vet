//! PayPal payment secret patterns.

crate::declare_provider!(
    PayPalProvider,
    id: "paypal",
    name: "PayPal",
    group: Group::Payments,
    patterns: [
        crate::pattern! {
                id: "payments/paypal-access-token",
                group: Group::Payments,
                name: "PayPal Access Token",
                description: "Grants short-lived API authentication for payment operations.",
                severity: Severity::High,
                regex: r"\b(A21AA[A-Za-z0-9_-]{50,100})\b",
                keywords: &["A21AA"],
                default_enabled: true,
                min_entropy: Some(4.0),
            },
            crate::pattern! {
                id: "payments/paypal-client-secret",
                group: Group::Payments,
                name: "PayPal Client Secret",
                description: "Grants access to process payments and refunds.",
                severity: Severity::Critical,
                regex: r#"(?i)(?:paypal|pp)[\s_-]*(?:client)?[\s_-]*secret[\s]*[=:]["']?\s*([A-Za-z0-9_-]{40,80})["']?"#,
                keywords: &["paypal", "PAYPAL"],
                default_enabled: true,
                min_entropy: Some(4.0),
            },
    ],
);
