# Vet for Visual Studio Code

Detect secrets in your code before they leak — right in your editor.

## Features

- **Real-time scanning** — Secrets are highlighted as you type
- **95+ patterns** — AWS, GCP, Azure, Stripe, OpenAI, and more
- **Hover for details** — See pattern info and remediation tips
- **Low noise** — Filters out placeholders and example values
- **Git-aware** — Respects your `.gitignore`

## Installation

Install from the [Visual Studio Code Marketplace](https://marketplace.visualstudio.com/items?itemName=vet.vet) or search for "Vet" in the Extensions view (`Cmd+Shift+X`).

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `vet.enable` | `true` | Enable or disable secret scanning |
| `vet.includeLowConfidence` | `false` | Show low-confidence findings (likely placeholders) |
| `vet.respectGitignore` | `true` | Skip files ignored by `.gitignore` |

## Commands

| Command | Description |
|---------|-------------|
| `Vet: Restart Language Server` | Restart the scanner |

## Configuration File

For project-specific settings, create a `.vet.toml` file in your workspace root. See the [configuration documentation](https://github.com/spikermint/vet#configuration) for details.

## Links

- [GitHub](https://github.com/spikermint/vet)
- [Report an Issue](https://github.com/spikermint/vet/issues)
- [CLI Documentation](https://github.com/spikermint/vet#cli-reference)

## Licence

[MIT](https://github.com/spikermint/vet/blob/main/LICENSE)
