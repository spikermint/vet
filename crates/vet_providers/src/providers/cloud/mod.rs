//! Cloud provider patterns.

mod airtable;
mod algolia;
mod aws;
mod azure;
mod cloudflare;
mod databricks;
mod digitalocean;
mod figma;
mod firebase;
mod flyio;
mod gcp;
mod heroku;
mod linear;
mod netlify;
mod supabase;
mod vercel;

pub use airtable::AirtableProvider;
pub use algolia::AlgoliaProvider;
pub use aws::AwsProvider;
pub use azure::AzureProvider;
pub use cloudflare::CloudflareProvider;
pub use databricks::DatabricksProvider;
pub use digitalocean::DigitalOceanProvider;
pub use figma::FigmaProvider;
pub use firebase::FirebaseProvider;
pub use flyio::FlyioProvider;
pub use gcp::GcpProvider;
pub use heroku::HerokuProvider;
pub use linear::LinearProvider;
pub use netlify::NetlifyProvider;
pub use supabase::SupabaseProvider;
pub use vercel::VercelProvider;
