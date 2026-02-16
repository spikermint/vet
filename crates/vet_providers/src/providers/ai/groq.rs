//! Groq secret patterns.

crate::declare_provider!(
    GroqProvider,
    id: "groq",
    name: "Groq",
    group: Group::Ai,
    patterns: [
        crate::pattern! {
            id: "ai/groq-api-key",
            group: Group::Ai,
            name: "Groq API Key",
            description: "Grants access to Groq's LPU inference API.",
            severity: Severity::Critical,
            regex: r"\b(gsk_[a-zA-Z0-9]{48})\b",
            keywords: &["gsk_"],
            default_enabled: true,
            min_entropy: Some(4.0),
        },
    ],
);
