//! Supabase secret patterns.

crate::declare_provider!(
    SupabaseProvider,
    id: "supabase",
    name: "Supabase",
    group: Group::Cloud,
    patterns: [
        crate::pattern! {
                id: "cloud/supabase-access-token",
                group: Group::Cloud,
                name: "Supabase Access Token",
                description: "Grants Management API access to projects.",
                severity: Severity::Critical,
                regex: r"\b(sbp_[a-f0-9]{40})\b",
                keywords: &["sbp_"],
                default_enabled: true,
                min_entropy: Some(3.5),
            },
            crate::pattern! {
                id: "cloud/supabase-secret-key",
                group: Group::Cloud,
                name: "Supabase Secret Key",
                description: "Grants privileged database access, bypasses RLS.",
                severity: Severity::Critical,
                regex: r"\b(sb_secret_[a-zA-Z0-9_-]{20,})\b",
                keywords: &["sb_secret_"],
                default_enabled: true,
                min_entropy: Some(3.5),
            },
    ],
);
