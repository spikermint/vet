//! Provider registry for accessing all builtin providers.

use std::collections::HashMap;
use std::time::Duration;

use crate::USER_AGENT;
use crate::pattern::PatternDef;
use crate::provider::Provider;
use crate::providers::builtin_providers;
use crate::verify::{VerificationError, VerificationResult};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Central registry of all builtin secret detection providers.
///
/// Maps pattern identifiers to their owning providers and optionally holds
/// an HTTP client for live secret verification.
pub struct ProviderRegistry {
    providers: Vec<&'static dyn Provider>,
    pattern_to_provider: HashMap<&'static str, PatternEntry>,
    client: Option<reqwest::Client>,
}

struct PatternEntry {
    provider_idx: usize,
    verifiable: bool,
}

impl ProviderRegistry {
    /// Creates a registry pre-loaded with all builtin providers.
    #[must_use]
    pub fn builtin() -> Self {
        let providers = builtin_providers();
        let mut pattern_to_provider = HashMap::new();

        for (idx, provider) in providers.iter().enumerate() {
            for pattern in provider.patterns() {
                pattern_to_provider.insert(
                    pattern.id,
                    PatternEntry {
                        provider_idx: idx,
                        verifiable: pattern.verifiable,
                    },
                );
            }
        }

        Self {
            providers,
            pattern_to_provider,
            client: None,
        }
    }

    /// Creates a registry with an HTTP client for live secret verification.
    pub fn with_verification() -> Result<Self, VerificationError> {
        let client = reqwest::Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .user_agent(USER_AGENT)
            .build()
            .map_err(|e| VerificationError::ClientInit(e.to_string()))?;

        let mut registry = Self::builtin();
        registry.client = Some(client);
        Ok(registry)
    }

    /// Returns an iterator over every pattern definition across all providers.
    pub fn all_patterns(&self) -> impl Iterator<Item = &PatternDef> {
        self.providers.iter().flat_map(|p| p.patterns().iter())
    }

    /// Returns all pattern definitions as a collected `Vec`.
    #[must_use]
    pub fn patterns(&self) -> Vec<&PatternDef> {
        self.all_patterns().collect()
    }

    /// Returns the total number of patterns across all providers.
    #[must_use]
    pub fn pattern_count(&self) -> usize {
        self.providers.iter().map(|p| p.patterns().len()).sum()
    }

    /// Returns an iterator over patterns that support live verification.
    pub fn verifiable_patterns(&self) -> impl Iterator<Item = &PatternDef> {
        self.all_patterns().filter(|p| p.verifiable)
    }

    /// Returns `true` if the given pattern supports live verification.
    #[must_use]
    pub fn supports_verification(&self, pattern_id: &str) -> bool {
        self.pattern_to_provider.get(pattern_id).is_some_and(|entry| {
            entry.verifiable
                && self
                    .providers
                    .get(entry.provider_idx)
                    .is_some_and(|p| p.verifier().is_some())
        })
    }

    /// Verifies a secret against the provider registered for `pattern_id`.
    pub async fn verify(&self, secret: &str, pattern_id: &str) -> Result<VerificationResult, VerificationError> {
        let client = self.client.as_ref().ok_or_else(|| {
            VerificationError::ClientInit("registry not initialized with verification support".to_string())
        })?;

        let entry = self
            .pattern_to_provider
            .get(pattern_id)
            .ok_or_else(|| VerificationError::UnsupportedPattern {
                pattern_id: pattern_id.to_string(),
            })?;

        if !entry.verifiable {
            return Err(VerificationError::UnsupportedPattern {
                pattern_id: pattern_id.to_string(),
            });
        }

        let provider = self
            .providers
            .get(entry.provider_idx)
            .ok_or_else(|| VerificationError::UnsupportedPattern {
                pattern_id: pattern_id.to_string(),
            })?;

        let verifier = provider
            .verifier()
            .ok_or_else(|| VerificationError::UnsupportedPattern {
                pattern_id: pattern_id.to_string(),
            })?;

        verifier.verify(client, secret, pattern_id).await
    }

    /// Returns the underlying slice of registered providers.
    #[must_use]
    pub fn providers(&self) -> &[&'static dyn Provider] {
        &self.providers
    }
}

impl std::fmt::Debug for ProviderRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderRegistry")
            .field("provider_count", &self.providers.len())
            .field("pattern_count", &self.pattern_count())
            .field("has_client", &self.client.is_some())
            .finish_non_exhaustive()
    }
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::builtin()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_registry_has_patterns() {
        let registry = ProviderRegistry::builtin();
        assert!(registry.pattern_count() > 0);
    }

    #[test]
    fn builtin_registry_has_providers() {
        let registry = ProviderRegistry::builtin();
        assert!(!registry.providers().is_empty());
    }

    #[test]
    fn supports_verification_for_github_patterns() {
        let registry = ProviderRegistry::builtin();
        assert!(registry.supports_verification("vcs/github-pat"));
    }

    #[test]
    fn does_not_support_verification_for_unknown_patterns() {
        let registry = ProviderRegistry::builtin();
        assert!(!registry.supports_verification("unknown/pattern"));
    }

    #[test]
    fn all_patterns_returns_iterator() {
        let registry = ProviderRegistry::builtin();
        let count = registry.all_patterns().count();
        assert_eq!(count, registry.pattern_count());
    }

    #[test]
    fn default_is_equivalent_to_builtin() {
        let default_registry = ProviderRegistry::default();
        let builtin_registry = ProviderRegistry::builtin();

        assert_eq!(default_registry.pattern_count(), builtin_registry.pattern_count());
        assert_eq!(default_registry.providers().len(), builtin_registry.providers().len());
    }
}
