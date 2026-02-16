//! Heroku secret patterns.

crate::declare_provider!(
    HerokuProvider,
    id: "heroku",
    name: "Heroku",
    group: Group::Cloud,
    patterns: [
        crate::pattern! {
                id: "cloud/heroku-api-key",
                group: Group::Cloud,
                name: "Heroku API Key",
                description: "Grants full access to Heroku apps, dynos, and account resources.",
                severity: Severity::Critical,
                regex: r"\b(HRKU-[A-Za-z0-9_-]{60,70})\b",
                keywords: &["HRKU-"],
                default_enabled: true,
                min_entropy: Some(3.5),
            },
            crate::pattern! {
                id: "cloud/heroku-oauth-token",
                group: Group::Cloud,
                name: "Heroku OAuth Token",
                description: "Grants scoped access to Heroku resources via OAuth.",
                severity: Severity::High,
                regex: r#"(?i)heroku[_-]?(?:oauth[_-]?)?token[\s=:]+['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?"#,
                keywords: &["heroku"],
                default_enabled: true,
                min_entropy: Some(3.0),
            },
    ],
);
