//! SendGrid secret patterns.

crate::declare_provider!(
    SendGridProvider,
    id: "sendgrid",
    name: "SendGrid",
    group: Group::Email,
    patterns: [
        crate::pattern! {
            id: "email/sendgrid-api-key",
            group: Group::Email,
            name: "SendGrid API Key",
            description: "Can send emails and manage email infrastructure.",
            severity: Severity::Critical,
            regex: r"\b(SG\.[a-zA-Z0-9_-]{20,24}\.[a-zA-Z0-9_-]{40,50})\b",
            keywords: &["SG."],
            default_enabled: true,
            min_entropy: Some(3.0),
        },
    ],
);
