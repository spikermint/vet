//! AWS secret patterns.

crate::declare_provider!(
    AwsProvider,
    id: "aws",
    name: "Amazon Web Services",
    group: Group::Cloud,
    patterns: [
        crate::pattern! {
                id: "cloud/aws-access-key-id",
                group: Group::Cloud,
                name: "AWS Access Key ID",
                description: "Identifies the key pair but requires the secret key for access.",
                severity: Severity::High,
                regex: r"\b((AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b",
                keywords: &["AKIA", "ASIA", "ABIA", "ACCA"],
                default_enabled: true,
                min_entropy: Some(3.0),
            },
            crate::pattern! {
                id: "cloud/aws-appsync-api-key",
                group: Group::Cloud,
                name: "AWS AppSync API Key",
                description: "Grants access to GraphQL APIs and underlying data sources.",
                severity: Severity::High,
                regex: r"\b(da2-[a-z0-9]{26})\b",
                keywords: &["da2-"],
                default_enabled: true,
                min_entropy: Some(3.0),
            },
            crate::pattern! {
                id: "cloud/aws-bedrock-api-key",
                group: Group::Cloud,
                name: "AWS Bedrock API Key",
                description: "Grants access to AI model invocations.",
                severity: Severity::Critical,
                regex: r"\b(ABSK[A-Za-z0-9+/]{109,269}={0,2})\b",
                keywords: &["ABSK"],
                default_enabled: true,
                min_entropy: Some(4.0),
            },
    ],
);
