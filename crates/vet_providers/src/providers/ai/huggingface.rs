//! Hugging Face secret patterns.

crate::declare_provider!(
    HuggingFaceProvider,
    id: "huggingface",
    name: "Hugging Face",
    group: Group::Ai,
    patterns: [
        crate::pattern! {
            id: "ai/huggingface-token",
            group: Group::Ai,
            name: "Hugging Face Access Token",
            description: "Grants access to models, datasets, and Inference API.",
            severity: Severity::High,
            regex: r"\b(hf_[a-zA-Z0-9]{20,})\b",
            keywords: &["hf_"],
            default_enabled: true,
            min_entropy: Some(3.5),
        },
    ],
);
