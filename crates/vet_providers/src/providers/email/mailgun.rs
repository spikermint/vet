//! Mailgun secret patterns.

crate::declare_provider!(
    MailgunProvider,
    id: "mailgun",
    name: "Mailgun",
    group: Group::Email,
    patterns: [
        crate::pattern! {
                id: "email/mailgun-api-key",
                group: Group::Email,
                name: "Mailgun Private API Key",
                description: "Grants full access to send emails and manage domains.",
                severity: Severity::Critical,
                regex: r"\b(key-[a-f0-9]{32})\b",
                keywords: &["mailgun", "MAILGUN_API"],
                default_enabled: true,
                min_entropy: Some(3.0),
            },
            crate::pattern! {
                id: "email/mailgun-validation-key",
                group: Group::Email,
                name: "Mailgun Public Validation Key",
                description: "Grants access to email verification API.",
                severity: Severity::Medium,
                regex: r"\b(pubkey-[a-f0-9]{32})\b",
                keywords: &["pubkey-"],
                default_enabled: true,
                min_entropy: Some(3.0),
            },
    ],
);
