//! Razorpay payment secret patterns.

crate::declare_provider!(
    RazorpayProvider,
    id: "razorpay",
    name: "Razorpay",
    group: Group::Payments,
    patterns: [
        crate::pattern! {
                id: "payments/razorpay-live-key",
                group: Group::Payments,
                name: "Razorpay Live API Key",
                description: "Grants access to collect real payments in production.",
                severity: Severity::Critical,
                regex: r"\b(rzp_live_[a-zA-Z0-9]{14,20})\b",
                keywords: &["rzp_live_"],
                default_enabled: true,
                min_entropy: Some(3.0),
            },
            crate::pattern! {
                id: "payments/razorpay-test-key",
                group: Group::Payments,
                name: "Razorpay Test API Key",
                description: "Exposes test account configuration (no real money access).",
                severity: Severity::Low,
                regex: r"\b(rzp_test_[a-zA-Z0-9]{14,20})\b",
                keywords: &["rzp_test_"],
                default_enabled: true,
                min_entropy: Some(3.0),
            },
    ],
);
