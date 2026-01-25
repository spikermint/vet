# Vet for Visual Studio Code

Catch secrets before they leak. Right in your editor.

![Vet detecting a Stripe secret key](https://raw.githubusercontent.com/spikermint/vet/refs/heads/main/.github/assets/extension/recording.gif)

## Features

- **Real-time detection** - Secrets highlighted as you type
- **95+ patterns** - AWS, GCP, Azure, Stripe, OpenAI, GitHub, and more
- **Hover for details** - Severity, description, and remediation steps
- **Quick fixes** - Add ignore comments with one click
- **Git-aware** - Respects your `.gitignore`

## Installation

Search **"Vet"** in the Extensions view (`Cmd+Shift+X`) or install from the [Marketplace](https://marketplace.visualstudio.com/items?itemName=vet.vet).

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `vet.enable` | `true` | Enable or disable scanning |
| `vet.includeLowConfidence` | `false` | Show low-confidence findings |
| `vet.respectGitignore` | `true` | Skip gitignored files |

## Project Configuration

Create a `.vet.toml` in your workspace root:
```toml
severity = "medium"
exclude_paths = ["vendor/**", "*.test.js"]

# Custom patterns
[[patterns]]
id = "custom/internal-token"
name = "Internal Token"
regex = 'INTERNAL_[A-Z0-9]{32}'
severity = "high"
```

See the [full configuration docs](https://github.com/spikermint/vet#configuration).

## Links

- [GitHub](https://github.com/spikermint/vet)
- [CLI Tool](https://github.com/spikermint/vet#installation)
- [Report an Issue](https://github.com/spikermint/vet/issues)

## Licence

vet is [MIT licensed](LICENSE)
