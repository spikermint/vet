<p align="center">
  <img src=".github/assets/logo.svg" alt="vet logo" width="120" />
</p>

<h1 align="center">vet</h1>

<p align="center">
  <strong>A blazingly fast, local-first secret scanner for your source code.</strong>
</p>

<p align="center">
  <a href="https://github.com/spikermint/vet/actions/workflows/ci.yml"><img src="https://github.com/spikermint/vet/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/spikermint/vet/releases"><img src="https://img.shields.io/github/v/release/spikermint/vet" alt="Release"></a>
  <a href="https://marketplace.visualstudio.com/items?itemName=vet.vet"><img src="https://img.shields.io/visual-studio-marketplace/v/vet.vet" alt="VS Code Marketplace"></a>
  <a href="https://github.com/spikermint/vet/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="Licence"></a>
</p>

<p align="center">
  <a href="#vs-code-extension">VS Code</a> •
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#cli-reference">CLI Reference</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#ci-integration">CI Integration</a>
</p>

---

**vet** detects API keys, tokens, passwords, and other secrets before they reach your repository. Works offline. Zero configuration required.

## Features

- **Fast** — Built in Rust with parallel scanning
- **Offline** — No network requests, everything runs locally
- **95+ patterns** — Detects secrets from AWS, GCP, Azure, OpenAI, Stripe, and more
- **Git-aware** — Respects `.gitignore` and can scan staged changes only
- **Multiple formats** — Output as text, JSON, or SARIF
- **Pre-commit hooks** — Catch secrets before they're committed

## VS Code Extension

Install the [Vet extension](https://marketplace.visualstudio.com/items?itemName=vet.vet) for real-time secret detection in your editor.

- Search for "Vet" in the Extensions view (`Cmd+Shift+X`)
- Or install from the [Visual Studio Code Marketplace](https://marketplace.visualstudio.com/items?itemName=vet.vet)

The extension highlights secrets as you type and respects your `.gitignore` and `.vet.toml` configuration.

## Installation

Download the latest release for your platform from [GitHub Releases](https://github.com/spikermint/vet/releases).

| Platform | Download |
|----------|----------|
| Linux (x64) | [vet-linux-x64](https://github.com/spikermint/vet/releases/latest/download/vet-linux-x64) |
| Linux (ARM64) | [vet-linux-arm64](https://github.com/spikermint/vet/releases/latest/download/vet-linux-arm64) |
| macOS (Intel) | [vet-darwin-x64](https://github.com/spikermint/vet/releases/latest/download/vet-darwin-x64) |
| macOS (Apple Silicon) | [vet-darwin-arm64](https://github.com/spikermint/vet/releases/latest/download/vet-darwin-arm64) |
| Windows (x64) | [vet-windows-x64.exe](https://github.com/spikermint/vet/releases/latest/download/vet-windows-x64.exe) |
| Windows (ARM64) | [vet-windows-arm64.exe](https://github.com/spikermint/vet/releases/latest/download/vet-windows-arm64.exe) |

## Quick Start

```bash
# Scan current directory
vet scan

# Scan specific paths
vet scan src/ tests/

# Output as JSON
vet scan --format json

# Only scan staged git changes (great for pre-commit)
vet scan --staged
```

## CLI Reference

```
vet <command>

Commands:
  scan       Scan files for secrets
  init       Create configuration file
  hook       Manage git pre-commit hooks
  patterns   List available detection patterns

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### Scan Options

| Option | Description |
|--------|-------------|
| `-f, --format <FORMAT>` | Output format: `text`, `json`, or `sarif` (default: `text`) |
| `-o, --output <FILE>` | Write output to file |
| `-c, --config <FILE>` | Path to configuration file |
| `-s, --severity <LEVEL>` | Minimum severity to report |
| `-e, --exclude <PATTERN>` | Additional paths to exclude |
| `--staged` | Only scan staged git changes |
| `--exit-zero` | Exit with code 0 even if secrets found |
| `--include-low-confidence` | Include low confidence matches |
| `--max-file-size <BYTES>` | Skip files larger than this size |
| `--concurrency <N>` | Number of parallel threads |
| `-v, --verbose` | Increase verbosity |

## Configuration

Create a `.vet.toml` configuration file to customise scanning behaviour:

```bash
# Interactive setup
vet init

# Quick setup with defaults
vet init --yes
```

### Configuration Reference

| Key | Type | Description |
|-----|------|-------------|
| `severity` | `string` | Minimum severity to report: `low`, `medium`, `high`, `critical` |
| `exclude_paths` | `string[]` | Glob patterns for paths to exclude |
| `max_file_size` | `integer` | Skip files larger than this size (in bytes) |
| `include_low_confidence` | `boolean` | Include matches with low confidence scores |
| `disabled_patterns` | `string[]` | Pattern IDs to disable (e.g., `generic/password-in-url`) |
| `patterns` | `CustomPattern[]` | Custom patterns to add (see below) |

### Custom Patterns

```toml
[[patterns]]
id = "custom/my-secret"
name = "My Custom Secret"
regex = '''my-secret-[a-zA-Z0-9]{32}'''
severity = "high"
description = "Custom secret pattern"  # optional
keywords = ["my-secret-"]              # optional, improves performance
min_entropy = 3.5                      # optional, filters low-entropy matches
```

## Pre-commit Hook

Install a git pre-commit hook to automatically scan staged changes:

```bash
# Install hook
vet hook install

# Remove hook
vet hook uninstall
```

## CI Integration

### GitHub Actions

```yaml
- name: Scan for secrets
  run: |
    curl -sSL https://github.com/spikermint/vet/releases/latest/download/vet-linux-x64 -o vet
    chmod +x vet
    ./vet scan --format sarif --output results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Supported Secrets

vet detects 95+ secret patterns across these categories:

| Category | Examples |
|----------|----------|
| AI Services | OpenAI, Anthropic, Groq, Hugging Face |
| Cloud Platforms | AWS, GCP, Azure, DigitalOcean |
| Version Control | GitHub, GitLab, Bitbucket |
| Payments | Stripe, PayPal, Square |
| Databases | PostgreSQL, MySQL, MongoDB, Redis |
| Communication | Slack, Discord, Twilio, SendGrid |
| Infrastructure | Terraform, Vault, Doppler |

Run `vet patterns` to see the full list with descriptions.

## Build from Source

Requires [Rust](https://rust-lang.org/) 1.85 or later.

```bash
git clone https://github.com/spikermint/vet
cd vet
cargo build --release
```

## License

vet is [MIT licensed](LICENSE)
