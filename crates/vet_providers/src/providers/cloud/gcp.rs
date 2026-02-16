//! Google Cloud Platform secret patterns.

crate::declare_provider!(
    GcpProvider,
    id: "gcp",
    name: "Google Cloud Platform",
    group: Group::Cloud,
    patterns: [
        crate::pattern! {
                id: "cloud/gcp-api-key",
                group: Group::Cloud,
                name: "GCP API Key",
                description: "Can access Google APIs and incur billing charges.",
                severity: Severity::High,
                regex: r"\b(AIza[A-Za-z0-9_-]{35})\b",
                keywords: &["AIza"],
                default_enabled: true,
                min_entropy: Some(3.5),
            },
            crate::pattern! {
                id: "cloud/gcp-oauth-client-secret",
                group: Group::Cloud,
                name: "Google OAuth Client Secret",
                description: "Allows impersonating OAuth client for user tokens.",
                severity: Severity::High,
                regex: r"\b(GOCSPX-[A-Za-z0-9_-]{20,40})\b",
                keywords: &["GOCSPX-"],
                default_enabled: true,
                min_entropy: Some(4.0),
            },
            crate::pattern! {
                id: "cloud/gcp-service-account-key",
                group: Group::Cloud,
                name: "GCP Service Account Key",
                description: "Grants access to GCP resources assigned to the service account.",
                severity: Severity::Critical,
                regex: r#""client_email"\s*:\s*"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.iam\.gserviceaccount\.com)""#,
                keywords: &["gserviceaccount.com", "client_email"],
                default_enabled: true,
                min_entropy: None,
            },
    ],
);
