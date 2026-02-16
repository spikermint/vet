//! Firebase secret patterns.

crate::declare_provider!(
    FirebaseProvider,
    id: "firebase",
    name: "Firebase",
    group: Group::Cloud,
    patterns: [
        crate::pattern! {
            id: "cloud/firebase-service-account",
            group: Group::Cloud,
            name: "Firebase Service Account Key",
            description: "Grants full admin access to Firebase and Google Cloud resources.",
            severity: Severity::Critical,
            regex: r#""client_email"\s*:\s*"([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.iam\.gserviceaccount\.com)""#,
            keywords: &["firebase-adminsdk", "iam.gserviceaccount.com"],
            default_enabled: true,
            min_entropy: None,
        },
    ],
);
