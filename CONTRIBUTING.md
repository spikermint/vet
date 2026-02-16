# Contributing to vet

Thanks for your interest in contributing to vet! Whether it is a bug report, a new secret pattern, a feature idea, or a code change, every contribution helps make vet better for everyone.

## Quick Links

- [Issue Tracker](https://github.com/spikermint/vet/issues)
- [Discussions](https://github.com/spikermint/vet/discussions)
- [Security Vulnerabilities](https://github.com/spikermint/vet/security/advisories/new) - please report privately, not via public issues
- [VS Code Extension](https://marketplace.visualstudio.com/items?itemName=vet.vet)

## Getting Started

### Prerequisites

- [Rust](https://rustup.rs/) 1.85 or newer
- [Node.js](https://nodejs.org/) 22+ and npm (only for VS Code extension work)

### Build and Test

```bash
git clone https://github.com/spikermint/vet.git
cd vet

cargo build          # Build all crates
cargo test           # Run test suite
cargo clippy --workspace --all-targets --all-features -- -D warnings  # Lint
cargo fmt --check    # Check formatting
```

### Workspace Lint Configuration

The workspace enforces strict lints that you will encounter immediately. The important ones to know about:

- `deny(missing_docs)` - all public items require documentation
- `deny(unsafe_code)` - no unsafe code permitted
- `deny(unwrap_used)`, `deny(expect_used)`, `deny(panic)` - use proper error handling
- Clippy pedantic is enabled across the workspace

These exist because vet is a security tool and correctness matters. If clippy or the compiler flags something in your PR, it is almost certainly intentional.

## Project Structure

vet is a Cargo workspace with four crates:

| Crate | Purpose |
|-------|---------|
| `vet_cli` | CLI binary and commands (`scan`, `fix`, `init`, `baseline`, `hook`, `patterns`, `history`) |
| `vet_core` | Scanning engine, configuration parsing, pattern registry, fingerprinting |
| `vet_providers` | Secret pattern definitions, provider modules, verification logic |
| `vet_lsp` | Language Server Protocol server powering the VS Code extension |

The VS Code extension lives in `editors/vscode/` and is a TypeScript project that communicates with `vet-lsp`.

## Adding a Secret Pattern

Pattern contributions are one of the most valuable ways to contribute. You do not need to be a Rust expert to add one.

### 1. Find the right provider module

Patterns are organised by group in `crates/vet_providers/src/providers/<group>/`. The groups map to the services they protect:

| Group | Directory | Examples |
|-------|-----------|----------|
| `ai` | `providers/ai/` | OpenAI, Anthropic, Hugging Face |
| `cloud` | `providers/cloud/` | AWS, GCP, Azure |
| `payments` | `providers/payments/` | Stripe, PayPal, Square |
| `vcs` | `providers/vcs/` | GitHub, GitLab, Bitbucket |
| `infra` | `providers/infra/` | Fastly, PagerDuty, Terraform |

If the service does not fit an existing group, open an issue to discuss where it should go.

### 2. Define the pattern

Each pattern uses the `pattern!` macro. Here is a minimal example:

```rust
crate::pattern! {
    id: "cloud/example-api-key",
    group: Group::Cloud,
    name: "Example API Key",
    description: "Grants access to the Example Cloud API.",
    severity: Severity::High,
    regex: r"\b(example_[A-Za-z0-9]{32})\b",
    keywords: &["example_"],
    default_enabled: true,
    min_entropy: Some(3.5),
}
```

Key fields to get right:

- **`id`** - format is `group/service-token-type` (e.g. `vcs/github-pat`)
- **`keywords`** - used for Aho-Corasick pre-filtering; include any fixed prefix the token has
- **`min_entropy`** - Shannon entropy threshold to reduce false positives; 3.0-4.0 is typical
- **`severity`** - `Critical` for full account access, `High` for broad access, `Medium` for limited scope, `Low` for minimal impact

### 3. Register the provider

Use the `declare_provider!` macro to wrap your patterns:

```rust
crate::declare_provider!(
    ExampleProvider,
    id: "example",
    name: "Example",
    group: Group::Cloud,
    patterns: [
        // your pattern! definitions here
    ],
);
```

### 4. Add tests

Every pattern should have tests verifying matches and rejections:

```rust
#[cfg(test)]
mod extra_tests {
    use regex::Regex;

    fn regex() -> Regex {
        Regex::new(r"\b(example_[A-Za-z0-9]{32})\b").unwrap()
    }

    #[test]
    fn matches_example_api_key() {
        let re = regex();
        assert!(re.is_match(r#"EXAMPLE_KEY = "example_aBcDeFgH12345678aBcDeFgH12345678""#));
    }

    #[test]
    fn rejects_short_string() {
        let re = regex();
        assert!(!re.is_match(r#"example_tooshort"#));
    }
}
```

### 5. Verify

```bash
cargo test -p vet_providers
cargo clippy -p vet_providers -- -D warnings
```

If you are unsure about any of these steps, open a [pattern request issue](https://github.com/spikermint/vet/issues/new?template=pattern_request.yml) with the token format and documentation link. A maintainer can help turn it into a PR.

## Contributing to the VS Code Extension

The extension source is in `editors/vscode/`:

```bash
cd editors/vscode
npm ci
npm run compile
```

To test locally, open the `editors/vscode/` folder in VS Code and press `F5` to launch an Extension Development Host with the extension loaded. The extension communicates with the `vet-lsp` binary, so make sure you have built it first with `cargo build -p vet_lsp`.

Relevant settings for development:

- `vet.serverPath` - point to your local `target/debug/vet-lsp` binary
- `vet.logLevel` - set to `debug` or `trace` to see LSP traffic in the Output panel

## Commit Convention

We use [conventional commits](https://www.conventionalcommits.org/) and enforce this on PR titles via CI.

Valid types:

| Type | Use for |
|------|---------|
| `feat` | New feature or capability |
| `fix` | Bug fix |
| `security` | New or improved secret pattern |
| `perf` | Performance improvement |
| `docs` | Documentation only |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `style` | Formatting, whitespace, etc. |
| `test` | Adding or updating tests |
| `chore` | Maintenance tasks |
| `ci` | CI/CD changes |
| `build` | Build system or dependency changes |

Scopes are optional but encouraged for clarity:

```
feat(providers): add notion api token pattern
fix(lsp): handle missing .vet.toml gracefully
docs(readme): update installation instructions
```

Releases are automated via [Knope](https://knope.tech/) based on conventional commit history, so getting the type right matters for changelogs.

## Pull Request Process

1. **Small changes** (bug fixes, new patterns, typo fixes) can go straight to a PR.
2. **Larger changes** (new commands, architectural changes, new features) should start with an issue to discuss the approach before writing code.
3. PR titles must follow the conventional commit format. CI will reject PRs with invalid titles.
4. All PRs run through `cargo clippy`, `cargo fmt`, and `cargo test` in CI.
5. One approval from a maintainer is required before merging.

## Reporting Security Vulnerabilities

If you discover a security vulnerability in vet itself, please report it privately through [GitHub Security Advisories](https://github.com/spikermint/vet/security/advisories/new).

**Do not open a public issue for security vulnerabilities.** We take security seriously and will respond promptly to any reports.

## License

By contributing to vet, you agree that your contributions will be licensed under the [MIT License](LICENSE).