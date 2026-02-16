<p align="center">
  <img src=".github/assets/logo.svg" alt="vet logo" width="120" />
</p>

<h1 align="center">vet</h1>

<p align="center">
  <strong>Catch secrets before they leave your machine.</strong>
</p>

<p align="center">
  <a href="https://github.com/spikermint/vet/actions/workflows/ci.yml"><img src="https://github.com/spikermint/vet/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/spikermint/vet/releases"><img src="https://img.shields.io/github/v/release/spikermint/vet" alt="Release"></a>
  <a href="https://marketplace.visualstudio.com/items?itemName=vet.vet"><img src="https://img.shields.io/badge/VS%20Code-Install-007ACC?logo=visualstudiocode&logoColor=white" alt="VS Code"></a>
</p>

<p align="center">
  <a href="#vscode-extension">VS Code</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#ci-integration">CI</a>
</p>

---

<p align="center">
  <img src=".github/assets/extension/recording.gif" alt="vet detecting a Stripe key in VS Code" width="720" />
</p>

---

## Why Vet?

Secrets leak when they hit git history.

Existing tools scan in CI - **after** the secret is already pushed. Vet catches them **before** they leave your machine.

- **Fast** - sub-100ms scans, Rust-powered
- **Zero config** - works immediately
- **140+ patterns** - AWS, Stripe, OpenAI, GitHub, and more

## VS Code Extension

Install from the [marketplace](https://marketplace.visualstudio.com/items?itemName=vet.vet) or search "Vet" in extensions.

Real-time detection as you type. Respects `.gitignore`.

## Installation
```bash
# macOS / Linux
curl -fsSL https://vet.codes/install.sh | sh

# Windows
powershell -c "irm https://vet.codes/install.ps1 | iex"

# Or download directly
# https://github.com/spikermint/vet/releases
```

## Usage

<img src=".github/assets/cli/recording.gif" alt="vet scan command" width="600" />

```bash
# Scan current directory
vet scan

# Scan specific paths
vet scan src/ config/

# Only staged changes (pre-commit)
vet scan --staged

# Output as JSON
vet scan --format json
```

### Interactive Fixing

Found secrets? Fix them interactively:
```bash
# Review and fix each secret
vet fix

# Preview changes without modifying files
vet fix --dry-run

# Fix specific paths
vet fix src/ config/
```

Actions available:
- **Redact** - Replace with `<REDACTED>`
- **Placeholder** - Replace with `${ENV_VAR_NAME}`
- **Delete line** - Remove the entire line
- **Ignore** - Append `vet:ignore` comment
- **Skip** - Leave unchanged

### Pre-commit Hook
```bash
vet hook install
```

Now secrets are blocked before every commit.

### History Scanning

Already have secrets in your git history? Audit your entire repo:

```bash
# Scan all commits
vet history

# Scan last 100 commits
vet history -n 100

# Scan commits since a tag or date
vet history --since v1.0.0
vet history --since 2024-01-01

# Show all occurrences of each secret
vet history --all

# Output as JSON or SARIF
vet history --format json
vet history --format sarif -o report.sarif
```

Secrets are deduplicated and shown with their first introduction point by default

## Baseline Support

Working with an existing codebase? Create a baseline to acknowledge existing secrets while preventing new ones:

```bash
# Create baseline interactively
vet baseline

# Review each finding and choose:
#   Accept  - Acknowledge this secret
#   Ignore  - Mark as false positive
#   Skip    - Decide later
#   Quit    - Save progress and exit

# Non-interactive mode
vet baseline --accept-all --reason "Initial baseline, rotation planned Q2 2026"

# View baseline statistics
vet baseline stats

# Scan with baseline (ignores baselined secrets)
vet scan --baseline .vet-baseline.json

# Or configure in .vet.toml
# baseline_path = ".vet-baseline.json"
```

Findings in your baseline are ignored during scans, but new secrets will still be caught. Perfect for gradual remediation.

### How It Works

Each secret gets a unique **fingerprint** based on:
- The detection pattern (e.g., `aws/access-key-id`)
- The file path (e.g., `src/config.py`)
- The secret value (hashed)

If a secret moves to a different file, it's treated as new. Same secret, same file = ignored.

### Configuration

Add to your `.vet.toml`:

```toml
# Automatically use this baseline for all scans
baseline_path = ".vet-baseline.json"

# Ad-hoc ignores (alternative to baseline)
[[ignore]]
fingerprint = "sha256:a1b2c3d4..."
pattern_id = "stripe/test-key"
file = "tests/fixtures/payments.py"
reason = "Stripe test mode key, not usable in production"
```

Both baseline files and config ignores work together - a secret matching either will be filtered out.

## Detected Secrets

| Category | Examples |
|----------|----------|
| AI | OpenAI, Anthropic, Hugging Face |
| Cloud | AWS, GCP, Azure, DigitalOcean |
| Payments | Stripe, PayPal, Square |
| VCS | GitHub, GitLab, Bitbucket |
| Database | PostgreSQL, MySQL, MongoDB, Redis |
| Comms | Slack, Twilio, SendGrid |

Run `vet patterns` for the full list.

## Configuration

Create `.vet.toml` in your project root:
```toml
severity = "medium"
exclude_paths = ["vendor/**", "*.test.js"]

# Add custom patterns
[[patterns]]
id = "custom/internal-token"
name = "Internal API Token"
regex = 'INTERNAL_[A-Z0-9]{32}'
severity = "high"
keywords = ["INTERNAL_"]
```

Or run `vet init` for interactive setup.

## CI Integration

### GitHub Actions

```yaml
- name: Scan for secrets
  run: |
    curl -fsSL https://vet.codes/install.sh | sh
    vet scan --format sarif -o results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## License

vet is [MIT licensed](LICENSE)
