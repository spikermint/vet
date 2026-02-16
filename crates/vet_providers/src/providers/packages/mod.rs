//! Package & container registry providers.

mod docker;
mod npm;
mod pypi;
mod rubygems;

pub use docker::DockerProvider;
pub use npm::NpmProvider;
pub use pypi::PyPiProvider;
pub use rubygems::RubyGemsProvider;
