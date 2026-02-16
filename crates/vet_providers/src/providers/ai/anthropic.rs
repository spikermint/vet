//! Anthropic secret patterns.

crate::declare_provider!(
    AnthropicProvider,
    id: "anthropic",
    name: "Anthropic",
    group: Group::Ai,
    patterns: [
        crate::pattern! {
            id: "ai/anthropic-api-key",
            group: Group::Ai,
            name: "Anthropic API Key",
            description: "Grants access to Claude models with billing.",
            severity: Severity::Critical,
            regex: r"\b(sk-ant-api03-[a-zA-Z0-9_-]{80,110})\b",
            keywords: &["sk-ant-"],
            default_enabled: true,
            min_entropy: Some(4.0),
        },
    ],
);
