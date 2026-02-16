//! Provider trait for pattern definitions.

use crate::pattern::PatternDef;
use crate::verify::SecretVerifier;

/// A provider of secret detection patterns.
///
/// Each provider contributes one or more `PatternDef` entries and optionally
/// a `SecretVerifier` for live-checking detected secrets.
pub trait Provider: Send + Sync {
    /// Returns the unique identifier for this provider (e.g. `"vcs/github"`).
    fn id(&self) -> &'static str;

    /// Returns the human-readable display name (e.g. `"GitHub"`).
    fn name(&self) -> &'static str;

    /// Returns the static slice of pattern definitions this provider contributes.
    fn patterns(&self) -> &'static [PatternDef];

    /// Returns an optional verifier for live-checking secrets matched by this provider.
    fn verifier(&self) -> Option<&dyn SecretVerifier> {
        None
    }
}

/// Generates a `Provider` implementation with optional `SecretVerifier` support.
///
/// Creates a unit struct, implements `Provider` for it, and emits basic tests
/// asserting the provider has patterns and they all belong to the declared group.
#[macro_export]
macro_rules! declare_provider {
    (
        $struct_name:ident,
        id: $id:expr,
        name: $display_name:expr,
        group: $group:expr,
        verifier: $verifier:ident,
        patterns: [$($pattern:expr),+ $(,)?] $(,)?
    ) => {
        use $crate::pattern::{Group, PatternDef, Severity};
        use $crate::provider::Provider;
        use $crate::verify::SecretVerifier as _;

        static PATTERNS: &[PatternDef] = &[$($pattern),+];

        #[doc = concat!("Secret detection provider for ", $display_name, " with live verification.")]
        pub struct $struct_name;

        impl Provider for $struct_name {
            fn id(&self) -> &'static str {
                $id
            }

            fn name(&self) -> &'static str {
                $display_name
            }

            fn patterns(&self) -> &'static [PatternDef] {
                PATTERNS
            }

            fn verifier(&self) -> Option<&dyn $crate::verify::SecretVerifier> {
                Some(&$verifier)
            }
        }

        #[cfg(test)]
        mod tests {
            use super::*;

            #[test]
            fn provider_has_patterns() {
                assert!(!$struct_name.patterns().is_empty());
            }

            #[test]
            fn all_patterns_have_correct_group() {
                for pattern in $struct_name.patterns() {
                    assert_eq!(pattern.group, $group);
                }
            }

            #[test]
            fn provider_has_verifier() {
                assert!($struct_name.verifier().is_some());
            }
        }
    };

    (
        $struct_name:ident,
        id: $id:expr,
        name: $display_name:expr,
        group: $group:expr,
        patterns: [$($pattern:expr),+ $(,)?] $(,)?
    ) => {
        use $crate::pattern::{Group, PatternDef, Severity};
        use $crate::provider::Provider;

        static PATTERNS: &[PatternDef] = &[$($pattern),+];

        #[doc = concat!("Secret detection provider for ", $display_name, ".")]
        pub struct $struct_name;

        impl Provider for $struct_name {
            fn id(&self) -> &'static str {
                $id
            }

            fn name(&self) -> &'static str {
                $display_name
            }

            fn patterns(&self) -> &'static [PatternDef] {
                PATTERNS
            }
        }

        #[cfg(test)]
        mod tests {
            use super::*;

            #[test]
            fn provider_has_patterns() {
                assert!(!$struct_name.patterns().is_empty());
            }

            #[test]
            fn all_patterns_have_correct_group() {
                for pattern in $struct_name.patterns() {
                    assert_eq!(pattern.group, $group);
                }
            }
        }
    };
}
