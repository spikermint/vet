//! Terraform Cloud secret patterns.

crate::declare_provider!(
    TerraformProvider,
    id: "terraform",
    name: "Terraform Cloud",
    group: Group::Infra,
    patterns: [
        crate::pattern! {
            id: "infra/terraform-cloud-token",
            group: Group::Infra,
            name: "Terraform Cloud API Token",
            description: "Grants access to infrastructure state and workspaces.",
            severity: Severity::Critical,
            regex: r"\b([a-zA-Z0-9]{14,16}\.atlasv1\.[a-zA-Z0-9]{60,70})\b",
            keywords: &[".atlasv1."],
            default_enabled: true,
            min_entropy: Some(3.0),
        },
    ],
);
