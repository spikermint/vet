//! Discord secret patterns.

crate::declare_provider!(
    DiscordProvider,
    id: "discord",
    name: "Discord",
    group: Group::Messaging,
    patterns: [
        crate::pattern! {
            id: "messaging/discord-webhook",
            group: Group::Messaging,
            name: "Discord Webhook URL",
            description: "Allows posting messages to Discord channels.",
            severity: Severity::Medium,
            regex: r"(https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+)",
            keywords: &["discord.com/api/webhooks", "discordapp.com/api/webhooks"],
            default_enabled: true,
            min_entropy: Some(3.0),
        },
    ],
);
