//! Version control system providers.

mod atlassian;
mod github;
mod gitlab;

pub use atlassian::AtlassianProvider;
pub use github::GitHubProvider;
pub use gitlab::GitLabProvider;
