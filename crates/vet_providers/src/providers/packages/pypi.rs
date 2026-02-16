//! PyPI registry secret patterns.

crate::declare_provider!(
    PyPiProvider,
    id: "pypi",
    name: "PyPI",
    group: Group::Packages,
    patterns: [
        crate::pattern! {
            id: "packages/pypi-api-token",
            group: Group::Packages,
            name: "PyPI API Token",
            description: "Grants publish access to Python packages (supply chain risk).",
            severity: Severity::Critical,
            regex: r"\b(pypi-[A-Za-z0-9_-]{50,})\b",
            keywords: &["pypi-"],
            default_enabled: true,
            min_entropy: Some(4.0),
        },
    ],
);
