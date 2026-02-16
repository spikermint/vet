//! Builtin providers for secret detection and verification.

mod ai;
mod cloud;
mod database;
mod email;
mod generic;
mod infra;
mod keys;
mod messaging;
mod packages;
mod payments;
mod vcs;

use crate::provider::Provider;

/// Returns all builtin providers, one per supported service.
#[must_use]
pub fn builtin_providers() -> Vec<&'static dyn Provider> {
    vec![
        // AI providers
        &ai::AnthropicProvider,
        &ai::DeepSeekProvider,
        &ai::GroqProvider,
        &ai::HuggingFaceProvider,
        &ai::OpenAiProvider,
        &ai::PerplexityProvider,
        // Cloud providers
        &cloud::AirtableProvider,
        &cloud::AlgoliaProvider,
        &cloud::AwsProvider,
        &cloud::AzureProvider,
        &cloud::CloudflareProvider,
        &cloud::DatabricksProvider,
        &cloud::DigitalOceanProvider,
        &cloud::FigmaProvider,
        &cloud::FirebaseProvider,
        &cloud::FlyioProvider,
        &cloud::GcpProvider,
        &cloud::HerokuProvider,
        &cloud::LinearProvider,
        &cloud::NetlifyProvider,
        &cloud::SupabaseProvider,
        &cloud::VercelProvider,
        // Database providers
        &database::DatabaseProvider,
        &database::PlanetScaleProvider,
        // Email providers
        &email::MailgunProvider,
        &email::ResendProvider,
        &email::SendGridProvider,
        // Generic providers
        &generic::GenericApiKeyProvider,
        &generic::GenericPasswordProvider,
        &generic::GenericSecretProvider,
        &generic::GenericTokenProvider,
        // Infrastructure providers
        &infra::BuildkiteProvider,
        &infra::CircleCIProvider,
        &infra::ConfluentProvider,
        &infra::DatadogProvider,
        &infra::DopplerProvider,
        &infra::FastlyProvider,
        &infra::GrafanaProvider,
        &infra::LaunchDarklyProvider,
        &infra::NewRelicProvider,
        &infra::OnePasswordProvider,
        &infra::PagerDutyProvider,
        &infra::PostmanProvider,
        &infra::SentryProvider,
        &infra::TerraformProvider,
        &infra::VaultProvider,
        // Key providers
        &keys::KeysProvider,
        // Messaging providers
        &messaging::DiscordProvider,
        &messaging::SlackProvider,
        &messaging::TelegramProvider,
        &messaging::TwilioProvider,
        // Package providers
        &packages::DockerProvider,
        &packages::NpmProvider,
        &packages::PyPiProvider,
        &packages::RubyGemsProvider,
        // Payment providers
        &payments::BraintreeProvider,
        &payments::PayPalProvider,
        &payments::RazorpayProvider,
        &payments::ShopifyProvider,
        &payments::SquareProvider,
        &payments::StripeProvider,
        // VCS providers
        &vcs::AtlassianProvider,
        &vcs::GitHubProvider,
        &vcs::GitLabProvider,
    ]
}
