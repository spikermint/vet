//! Perplexity AI secret patterns.

crate::declare_provider!(
    PerplexityProvider,
    id: "perplexity",
    name: "Perplexity AI",
    group: Group::Ai,
    patterns: [
        crate::pattern! {
            id: "ai/perplexity-api-key",
            group: Group::Ai,
            name: "Perplexity API Key",
            description: "Grants access to Perplexity AI search and chat API.",
            severity: Severity::High,
            regex: r"\b(pplx-[A-Za-z0-9]{40,})\b",
            keywords: &["pplx-"],
            default_enabled: true,
            min_entropy: Some(3.5),
        },
    ],
);
