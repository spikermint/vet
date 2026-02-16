//! Generic secret detection patterns.
//!
//! These patterns detect secrets by matching variable names (e.g. `password`,
//! `api_key`) combined with assignment operators and quoted string values.
//! They require higher entropy thresholds than prefix-matched patterns to
//! compensate for the lack of a distinctive secret format.

mod api_key;
mod password;
mod secret;
mod token;

pub use api_key::GenericApiKeyProvider;
pub use password::GenericPasswordProvider;
pub use secret::GenericSecretProvider;
pub use token::GenericTokenProvider;
