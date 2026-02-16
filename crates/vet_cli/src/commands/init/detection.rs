//! Project type detection for automatic exclude suggestions.

use std::path::Path;

/// A recognised project type with marker files and recommended exclude globs.
#[derive(Debug)]
pub struct ProjectType {
    /// Human-readable name (e.g. "Node.js", "Rust").
    pub name: &'static str,
    /// File or glob patterns whose presence indicates this project type.
    pub markers: &'static [&'static str],
    /// Exclude globs to suggest for this project type.
    pub excludes: &'static [&'static str],
}

/// All known project types and their associated exclude patterns.
pub const PROJECT_TYPES: &[ProjectType] = &[
    ProjectType {
        name: "Node.js",
        markers: &["package.json"],
        excludes: &["node_modules/**", "dist/**", ".next/**", ".nuxt/**", "build/**"],
    },
    ProjectType {
        name: "Python",
        markers: &["pyproject.toml", "requirements.txt", "setup.py", "Pipfile"],
        excludes: &["venv/**", ".venv/**", "__pycache__/**", ".tox/**", "*.egg-info/**"],
    },
    ProjectType {
        name: "Rust",
        markers: &["Cargo.toml"],
        excludes: &["target/**"],
    },
    ProjectType {
        name: "Go",
        markers: &["go.mod"],
        excludes: &["vendor/**"],
    },
    ProjectType {
        name: "Ruby",
        markers: &["Gemfile"],
        excludes: &["vendor/bundle/**", ".bundle/**"],
    },
    ProjectType {
        name: "PHP",
        markers: &["composer.json"],
        excludes: &["vendor/**"],
    },
    ProjectType {
        name: "Java",
        markers: &["pom.xml", "build.gradle", "build.gradle.kts"],
        excludes: &["target/**", "build/**", ".gradle/**"],
    },
    ProjectType {
        name: ".NET",
        markers: &["*.csproj", "*.sln", "*.fsproj"],
        excludes: &["bin/**", "obj/**"],
    },
];

/// Scans a directory for marker files and returns all matching project types.
#[must_use]
pub fn detect_projects(dir: &Path) -> Vec<&'static ProjectType> {
    PROJECT_TYPES
        .iter()
        .filter(|pt| has_any_marker(dir, pt.markers))
        .collect()
}

/// Merges, deduplicates, and sorts exclude globs from the given project types.
#[must_use]
pub fn collect_excludes(projects: &[&ProjectType]) -> Vec<&'static str> {
    let mut excludes: Vec<&str> = projects.iter().flat_map(|p| p.excludes.iter().copied()).collect();

    excludes.sort_unstable();
    excludes.dedup();
    excludes
}

fn has_any_marker(dir: &Path, markers: &[&str]) -> bool {
    markers.iter().any(|marker| {
        if marker.contains('*') {
            glob_exists(dir, marker)
        } else {
            dir.join(marker).exists()
        }
    })
}

fn glob_exists(dir: &Path, pattern: &str) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };

    let suffix = pattern.trim_start_matches('*');

    entries
        .filter_map(Result::ok)
        .any(|e| e.file_name().to_str().is_some_and(|n| n.ends_with(suffix)))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn detect_nodejs_project() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();

        let projects = detect_projects(dir.path());

        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].name, "Node.js");
    }

    #[test]
    fn detect_rust_project() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("Cargo.toml"), "[package]").unwrap();

        let projects = detect_projects(dir.path());

        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].name, "Rust");
    }

    #[test]
    fn detect_python_project_pyproject() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("pyproject.toml"), "[project]").unwrap();

        let projects = detect_projects(dir.path());

        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].name, "Python");
    }

    #[test]
    fn detect_python_project_requirements() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("requirements.txt"), "flask").unwrap();

        let projects = detect_projects(dir.path());

        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].name, "Python");
    }

    #[test]
    fn detect_go_project() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("go.mod"), "module example").unwrap();

        let projects = detect_projects(dir.path());

        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].name, "Go");
    }

    #[test]
    fn detect_multiple_projects() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();
        fs::write(dir.path().join("Cargo.toml"), "[package]").unwrap();

        let projects = detect_projects(dir.path());

        assert_eq!(projects.len(), 2);
        let names: Vec<_> = projects.iter().map(|p| p.name).collect();
        assert!(names.contains(&"Node.js"));
        assert!(names.contains(&"Rust"));
    }

    #[test]
    fn detect_no_project() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("README.md"), "# Hello").unwrap();

        let projects = detect_projects(dir.path());

        assert!(projects.is_empty());
    }

    #[test]
    fn detect_java_maven() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("pom.xml"), "<project>").unwrap();

        let projects = detect_projects(dir.path());

        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].name, "Java");
    }

    #[test]
    fn detect_java_gradle() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("build.gradle"), "plugins {}").unwrap();

        let projects = detect_projects(dir.path());

        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].name, "Java");
    }

    #[test]
    fn detect_ruby_project() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("Gemfile"), "source 'https://rubygems.org'").unwrap();

        let projects = detect_projects(dir.path());

        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].name, "Ruby");
    }

    #[test]
    fn detect_php_project() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("composer.json"), "{}").unwrap();

        let projects = detect_projects(dir.path());

        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].name, "PHP");
    }

    #[test]
    fn detect_dotnet_csproj() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("App.csproj"), "<Project>").unwrap();

        let projects = detect_projects(dir.path());

        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].name, ".NET");
    }

    #[test]
    fn detect_dotnet_sln() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("Solution.sln"), "Microsoft Visual Studio").unwrap();

        let projects = detect_projects(dir.path());

        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].name, ".NET");
    }

    #[test]
    fn collect_excludes_single_project() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("Cargo.toml"), "[package]").unwrap();

        let projects = detect_projects(dir.path());
        let excludes = collect_excludes(&projects);

        assert!(excludes.contains(&"target/**"));
    }

    #[test]
    fn collect_excludes_nodejs() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();

        let projects = detect_projects(dir.path());
        let excludes = collect_excludes(&projects);

        assert!(excludes.contains(&"node_modules/**"));
        assert!(excludes.contains(&"dist/**"));
    }

    #[test]
    fn collect_excludes_multiple_projects_deduped() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();
        fs::write(dir.path().join("Cargo.toml"), "[package]").unwrap();

        let projects = detect_projects(dir.path());
        let excludes = collect_excludes(&projects);

        let count = excludes.iter().filter(|&&e| e == "node_modules/**").count();
        assert_eq!(count, 1);
    }

    #[test]
    fn collect_excludes_sorted() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();

        let projects = detect_projects(dir.path());
        let excludes = collect_excludes(&projects);

        let mut sorted = excludes.clone();
        sorted.sort_unstable();
        assert_eq!(excludes, sorted);
    }

    #[test]
    fn collect_excludes_empty_when_no_projects() {
        let excludes = collect_excludes(&[]);
        assert!(excludes.is_empty());
    }

    #[test]
    fn project_types_have_excludes() {
        for pt in PROJECT_TYPES {
            assert!(!pt.excludes.is_empty(), "{} should have excludes", pt.name);
        }
    }

    #[test]
    fn project_types_have_markers() {
        for pt in PROJECT_TYPES {
            assert!(!pt.markers.is_empty(), "{} should have markers", pt.name);
        }
    }
}
