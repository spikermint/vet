//! RubyGems registry secret patterns.

crate::declare_provider!(
    RubyGemsProvider,
    id: "rubygems",
    name: "RubyGems",
    group: Group::Packages,
    patterns: [
        crate::pattern! {
            id: "packages/rubygems-api-key",
            group: Group::Packages,
            name: "RubyGems API Key",
            description: "Grants publish access to Ruby gems (supply chain risk).",
            severity: Severity::Critical,
            regex: r"\b(rubygems_[a-fA-F0-9]{48})\b",
            keywords: &["rubygems_"],
            default_enabled: true,
            min_entropy: Some(3.5),
        },
    ],
);
