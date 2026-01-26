import {
	ColorThemeKind,
	type ExtensionContext,
	Hover,
	MarkdownString,
	type OutputChannel,
	window,
	workspace,
} from "vscode";
import {
	LanguageClient,
	type LanguageClientOptions,
	type ServerOptions,
} from "vscode-languageclient/node";
import type { NotificationService } from "../services/NotificationService";
import { resolveServerPath } from "../services/ServerResolver";
import type { StatusBarService } from "../services/StatusBarService";

type ColorToken = "danger" | "warning" | "info" | "success" | "muted";

const COLOR_PALETTES: Record<
	"dark" | "light" | "highContrastDark" | "highContrastLight",
	Record<ColorToken, string>
> = {
	dark: {
		danger: "#f14c4c",
		warning: "#cca700",
		info: "#3794ff",
		success: "#89d185",
		muted: "#8c8c8c",
	},
	light: {
		danger: "#c42020",
		warning: "#8a5700",
		info: "#005fb8",
		success: "#2e7d32",
		muted: "#505050",
	},
	highContrastDark: {
		danger: "#ff6b6b",
		warning: "#ffcc00",
		info: "#6bc5ff",
		success: "#89ff89",
		muted: "#d4d4d4",
	},
	highContrastLight: {
		danger: "#a00000",
		warning: "#6b4400",
		info: "#003d7a",
		success: "#1b5e20",
		muted: "#3a3a3a",
	},
};

export class VetClient {
	private client: LanguageClient | undefined;
	private isRestarting = false;

	constructor(
		private readonly context: ExtensionContext,
		private readonly outputChannel: OutputChannel,
		private readonly statusBar: StatusBarService,
		private readonly notifications: NotificationService,
	) {}

	async start(): Promise<void> {
		const startTime = Date.now();
		const version = this.context.extension.packageJSON.version as string;
		this.log(`Vet v${version} starting...`);

		const result = resolveServerPath(this.context);

		if (!result.ok) {
			this.handleResolutionError(result.error);
			return;
		}

		const { resolution } = result;

		if (resolution.warning) {
			this.notifications.showWarning(resolution.warning);
			this.log(`Warning: ${resolution.warning}`);
		}

		this.log(`Using server: ${resolution.path}`);

		const config = workspace.getConfiguration("vet");
		const logLevel = config.get<string>("logLevel", "info");

		this.log(`Log level: ${logLevel}`);

		const serverOptions: ServerOptions = {
			command: resolution.path,
			args: [],
			options: {
				env: {
					...process.env,
					RUST_LOG: logLevel,
				},
			},
		};

		const clientOptions: LanguageClientOptions = {
			documentSelector: [{ scheme: "file" }, { scheme: "untitled" }],
			outputChannel: this.outputChannel,
			initializationOptions: {
				includeLowConfidence: config.get<boolean>(
					"includeLowConfidence",
					false,
				),
				respectGitignore: config.get<boolean>("respectGitignore", true),
			},
			synchronize: {
				configurationSection: "vet",
			},
			middleware: {
				provideHover: async (document, position, token, next) => {
					const hover = await next(document, position, token);
					return hover ? this.enhanceHover(hover) : hover;
				},
			},
		};

		this.client = new LanguageClient(
			"vet",
			"Vet Language Server",
			serverOptions,
			clientOptions,
		);

		try {
			await this.client.start();
			const elapsed = Date.now() - startTime;
			this.statusBar.setReady();
			this.log(`Language server started in ${elapsed}ms`);
		} catch (error) {
			this.handleStartupError(error);
		}
	}

	async stop(): Promise<void> {
		if (this.client) {
			await this.client.stop();
			this.client = undefined;
		}
	}

	async restart(): Promise<void> {
		if (this.isRestarting) {
			return;
		}

		this.isRestarting = true;
		this.statusBar.setRestarting();
		this.log("Restarting language server...");

		try {
			await this.stop();
			await this.start();
		} finally {
			this.isRestarting = false;
		}
	}

	private enhanceHover(hover: Hover): Hover {
		const contents = hover.contents;

		if (!Array.isArray(contents)) {
			return hover;
		}

		const enhanced = contents.map((item) => {
			const raw = typeof item === "string" ? item : item.value;
			const value = this.replaceColorTokens(raw);

			const md = new MarkdownString(value, true);
			md.supportHtml = true;
			md.supportThemeIcons = true;
			md.isTrusted = true;
			return md;
		});

		return new Hover(enhanced, hover.range);
	}

	private replaceColorTokens(value: string): string {
		const palette = this.getColorPalette();

		return value
			.replace(/\{\{danger\}\}/g, palette.danger)
			.replace(/\{\{warning\}\}/g, palette.warning)
			.replace(/\{\{info\}\}/g, palette.info)
			.replace(/\{\{success\}\}/g, palette.success)
			.replace(/\{\{muted\}\}/g, palette.muted);
	}

	private getColorPalette(): Record<ColorToken, string> {
		switch (window.activeColorTheme.kind) {
			case ColorThemeKind.Light:
				return COLOR_PALETTES.light;
			case ColorThemeKind.HighContrast:
				return COLOR_PALETTES.highContrastDark;
			case ColorThemeKind.HighContrastLight:
				return COLOR_PALETTES.highContrastLight;
			default:
				return COLOR_PALETTES.dark;
		}
	}

	private handleResolutionError(error: {
		reason: string;
		message: string;
	}): void {
		this.statusBar.setError("Server not found");
		this.notifications.showError(error.message);
		this.log(`Error: ${error.message}`);
	}

	private handleStartupError(error: unknown): void {
		const message = `Failed to start language server: ${error}`;
		this.statusBar.setError("Failed to start");
		this.notifications.showError(message);
		this.log(`Error: ${message}`);
	}

	private log(message: string): void {
		this.outputChannel.appendLine(`[client] ${message}`);
	}
}
