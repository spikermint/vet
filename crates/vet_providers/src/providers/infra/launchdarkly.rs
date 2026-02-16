//! LaunchDarkly secret patterns.

crate::declare_provider!(
    LaunchDarklyProvider,
    id: "launchdarkly",
    name: "LaunchDarkly",
    group: Group::Infra,
    patterns: [
        crate::pattern! {
                id: "infra/launchdarkly-sdk-key",
                group: Group::Infra,
                name: "LaunchDarkly SDK Key",
                description: "Grants server-side SDK access to evaluate feature flags.",
                severity: Severity::High,
                regex: r"\b(sdk-[a-zA-Z0-9-]{32,})\b",
                keywords: &["launchdarkly", "LAUNCHDARKLY", "launch_darkly"],
                default_enabled: true,
                min_entropy: Some(3.0),
            },
            crate::pattern! {
                id: "infra/launchdarkly-mobile-key",
                group: Group::Infra,
                name: "LaunchDarkly Mobile Key",
                description: "Grants mobile SDK access to evaluate feature flags.",
                severity: Severity::Medium,
                regex: r"\b(mob-[a-zA-Z0-9-]{32,})\b",
                keywords: &["launchdarkly", "LAUNCHDARKLY", "launch_darkly"],
                default_enabled: true,
                min_entropy: Some(3.0),
            },
    ],
);
