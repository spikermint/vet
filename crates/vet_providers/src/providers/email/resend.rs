//! Resend secret patterns.

crate::declare_provider!(
    ResendProvider,
    id: "resend",
    name: "Resend",
    group: Group::Email,
    patterns: [
        crate::pattern! {
            id: "email/resend-api-key",
            group: Group::Email,
            name: "Resend API Key",
            description: "Grants access to send emails via Resend API.",
            severity: Severity::High,
            regex: r"\b(re_[A-Za-z0-9_]{20,})\b",
            keywords: &["re_"],
            default_enabled: true,
            min_entropy: Some(3.5),
        },
    ],
);
