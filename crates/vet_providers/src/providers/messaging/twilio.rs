//! Twilio secret patterns.

crate::declare_provider!(
    TwilioProvider,
    id: "twilio",
    name: "Twilio",
    group: Group::Messaging,
    patterns: [
        crate::pattern! {
                id: "messaging/twilio-account-sid",
                group: Group::Messaging,
                name: "Twilio Account SID",
                description: "Identifies account; often leaked alongside auth tokens.",
                severity: Severity::Medium,
                regex: r"\b(AC[0-9a-fA-F]{32})\b",
                keywords: &["twilio", "TWILIO", "TWILIO_ACCOUNT"],
                default_enabled: true,
                min_entropy: Some(3.0),
            },
            crate::pattern! {
                id: "messaging/twilio-api-key",
                group: Group::Messaging,
                name: "Twilio API Key SID",
                description: "Grants access to send SMS, make calls, and use Twilio services.",
                severity: Severity::Critical,
                regex: r"\b(SK[0-9a-fA-F]{32})\b",
                keywords: &["twilio", "TWILIO", "TWILIO_API"],
                default_enabled: true,
                min_entropy: Some(3.0),
            },
    ],
);
