//! Docker Hub secret patterns.

crate::declare_provider!(
    DockerProvider,
    id: "docker",
    name: "Docker Hub",
    group: Group::Packages,
    patterns: [
        crate::pattern! {
            id: "packages/docker-hub-pat",
            group: Group::Packages,
            name: "Docker Hub Personal Access Token",
            description: "Grants push/pull access to container images.",
            severity: Severity::High,
            regex: r"\b(dckr_pat_[a-zA-Z0-9_-]{20,60})\b",
            keywords: &["dckr_pat_"],
            default_enabled: true,
            min_entropy: Some(3.0),
        },
    ],
);
