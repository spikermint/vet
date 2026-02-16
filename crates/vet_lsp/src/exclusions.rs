//! File exclusion logic for gitignore and glob-based patterns.

use std::path::Path;

use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use tracing::{debug, warn};

/// Parses the `.gitignore` file at the workspace root, if present.
#[must_use]
pub fn build_gitignore(workspace_root: &Path) -> Option<Gitignore> {
    let gitignore_path = workspace_root.join(".gitignore");

    if !gitignore_path.exists() {
        return None;
    }

    let mut builder = GitignoreBuilder::new(workspace_root);

    if let Some(err) = builder.add(&gitignore_path) {
        let path = gitignore_path.display();
        warn!("Failed to parse {path}: {err}");
        return None;
    }

    match builder.build() {
        Ok(gi) => {
            let root = workspace_root.display();
            debug!("Loaded .gitignore from {root}");
            Some(gi)
        }
        Err(e) => {
            warn!("Failed to build gitignore matcher: {e}");
            None
        }
    }
}

/// Returns `true` if the path is ignored by the root or any nested `.gitignore`.
#[must_use]
pub fn is_gitignored(root_gitignore: Option<&Gitignore>, path: &Path, workspace_root: &Path) -> bool {
    if !path.starts_with(workspace_root) {
        return false;
    }

    if let Some(gi) = root_gitignore
        && gi.matched_path_or_any_parents(path, path.is_dir()).is_ignore()
    {
        return true;
    }

    is_ignored_by_nested_gitignore(path, workspace_root)
}

fn is_ignored_by_nested_gitignore(path: &Path, workspace_root: &Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };

    for ancestor in parent.ancestors() {
        if ancestor == workspace_root {
            break;
        }

        if !ancestor.starts_with(workspace_root) {
            break;
        }

        let nested_gitignore = ancestor.join(".gitignore");
        if !nested_gitignore.exists() {
            continue;
        }

        let mut builder = GitignoreBuilder::new(ancestor);
        if builder.add(&nested_gitignore).is_some() {
            continue; // Skip malformed gitignore
        }

        if let Ok(gi) = builder.build()
            && gi.matched_path_or_any_parents(path, path.is_dir()).is_ignore()
        {
            return true;
        }
    }

    false
}

/// Compiles user-configured exclude patterns into a `GlobSet` matcher.
#[must_use]
pub fn build_exclude_matcher(patterns: &[String], root: &Path) -> Option<GlobSet> {
    if patterns.is_empty() {
        return None;
    }

    let mut builder = GlobSetBuilder::new();

    for pattern in patterns {
        let full_pattern = if pattern.starts_with('/') {
            let root_display = root.display();
            format!("{root_display}{pattern}")
        } else {
            format!("**/{pattern}")
        };

        match Glob::new(&full_pattern) {
            Ok(glob) => {
                builder.add(glob);
            }
            Err(e) => {
                warn!("Invalid exclude pattern '{pattern}': {e}");
            }
        }
    }

    builder.build().ok()
}

/// Returns `true` if the path matches any user-configured exclude pattern.
#[must_use]
pub fn is_excluded(matcher: Option<&GlobSet>, path: &Path, workspace_roots: &[impl AsRef<Path>]) -> bool {
    let Some(matcher) = matcher else {
        return false;
    };

    // Try absolute path first
    if matcher.is_match(path) {
        return true;
    }

    // Try relative to each workspace root
    for root in workspace_roots {
        if let Ok(relative) = path.strip_prefix(root.as_ref())
            && matcher.is_match(relative)
        {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn build_gitignore_returns_none_when_no_file() {
        let dir = TempDir::new().unwrap();
        assert!(build_gitignore(dir.path()).is_none());
    }

    #[test]
    fn build_gitignore_parses_valid_file() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".gitignore"), "*.log\ntarget/\n").unwrap();

        let gi = build_gitignore(dir.path());
        assert!(gi.is_some());
    }

    #[test]
    fn is_gitignored_matches_pattern() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".gitignore"), "*.env\n").unwrap();

        let gi = build_gitignore(dir.path()).unwrap();
        let path = dir.path().join("secrets.env");

        assert!(is_gitignored(Some(&gi), &path, dir.path()));
    }

    #[test]
    fn is_gitignored_respects_negation() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".gitignore"), "*.env\n!example.env\n").unwrap();

        let gi = build_gitignore(dir.path()).unwrap();

        let ignored = dir.path().join("secrets.env");
        let not_ignored = dir.path().join("example.env");

        assert!(is_gitignored(Some(&gi), &ignored, dir.path()));
        assert!(!is_gitignored(Some(&gi), &not_ignored, dir.path()));
    }

    #[test]
    fn is_gitignored_matches_directories() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".gitignore"), "node_modules/\n").unwrap();

        let gi = build_gitignore(dir.path()).unwrap();
        let path = dir.path().join("node_modules/lodash/index.js");

        assert!(is_gitignored(Some(&gi), &path, dir.path()));
    }

    #[test]
    fn nested_gitignore_is_checked() {
        let dir = TempDir::new().unwrap();

        // Root gitignore
        fs::write(dir.path().join(".gitignore"), "*.log\n").unwrap();

        // Nested directory with its own gitignore
        let subdir = dir.path().join("src");
        fs::create_dir(&subdir).unwrap();
        fs::write(subdir.join(".gitignore"), "*.generated.rs\n").unwrap();

        let root_gi = build_gitignore(dir.path()).unwrap();

        // File matched by nested gitignore
        let generated = subdir.join("types.generated.rs");
        assert!(is_gitignored(Some(&root_gi), &generated, dir.path()));

        // File not matched by any gitignore
        let normal = subdir.join("main.rs");
        assert!(!is_gitignored(Some(&root_gi), &normal, dir.path()));
    }

    #[test]
    fn is_gitignored_returns_false_with_no_matcher() {
        let path = Path::new("/project/file.rs");
        assert!(!is_gitignored(None, path, Path::new("/project")));
    }

    #[test]
    fn is_gitignored_returns_false_for_path_outside_workspace() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".gitignore"), "*.env\n").unwrap();

        let gi = build_gitignore(dir.path()).unwrap();
        let external_path = Path::new("/some/other/location/secrets.env");

        assert!(!is_gitignored(Some(&gi), external_path, dir.path()));
    }

    #[test]
    fn build_exclude_matcher_empty_patterns() {
        let patterns: Vec<String> = vec![];
        assert!(build_exclude_matcher(&patterns, Path::new("/project")).is_none());
    }

    #[test]
    fn build_exclude_matcher_with_patterns() {
        let patterns = vec!["target/**".to_string(), "*.log".to_string()];
        let matcher = build_exclude_matcher(&patterns, Path::new("/project"));
        assert!(matcher.is_some());
    }

    #[test]
    fn is_excluded_matches_glob() {
        let patterns = vec!["target/**".to_string()];
        let matcher = build_exclude_matcher(&patterns, Path::new("/project")).unwrap();

        let excluded = Path::new("/project/target/debug/app");
        let not_excluded = Path::new("/project/src/main.rs");

        assert!(is_excluded(Some(&matcher), excluded, &["/project"]));
        assert!(!is_excluded(Some(&matcher), not_excluded, &["/project"]));
    }
}
