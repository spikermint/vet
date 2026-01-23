import { type ExtensionContext, type OutputChannel, workspace } from "vscode";
import {
	LanguageClient,
	type LanguageClientOptions,
	type ServerOptions,
} from "vscode-languageclient/node";
import type { NotificationService } from "../services/NotificationService";
import { resolveServerPath } from "../services/ServerResolver";
import type { StatusBarService } from "../services/StatusBarService";

export class VetClient {
	private client: LanguageClient | undefined;
	private isRestarting = false;

	constructor(
		private readonly context: ExtensionContext,
		private readonly outputChannel: OutputChannel,
		private readonly statusBar: StatusBarService,
		private readonly notifications: NotificationService,
	) { }

	async start(): Promise<void> {
		const resolution = resolveServerPath(this.context);

		if (!resolution) {
			this.handleServerNotFound();
			return;
		}

		if (resolution.warning) {
			this.notifications.showWarning(resolution.warning);
			this.outputChannel.appendLine(`[Vet] Warning: ${resolution.warning}`);
		}

		this.outputChannel.appendLine(`[Vet] Using server: ${resolution.path}`);

		const serverOptions: ServerOptions = {
			command: resolution.path,
			args: [],
		};

		const config = workspace.getConfiguration("vet");

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
		};

		this.client = new LanguageClient(
			"vet",
			"Vet Language Server",
			serverOptions,
			clientOptions,
		);

		try {
			await this.client.start();
			this.statusBar.setReady();
			this.outputChannel.appendLine("[Vet] Language server started");
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

		try {
			await this.stop();
			await this.start();
		} finally {
			this.isRestarting = false;
		}
	}

	private handleServerNotFound(): void {
		const message =
			"Could not find Vet language server. Set vet.serverPath in settings or reinstall the extension.";
		this.statusBar.setError("Server not found");
		this.notifications.showError(message);
		this.outputChannel.appendLine(`[Vet] Error: ${message}`);
	}

	private handleStartupError(error: unknown): void {
		const message = `Failed to start Vet language server: ${error}`;
		this.statusBar.setError("Failed to start");
		this.notifications.showError(message);
		this.outputChannel.appendLine(`[Vet] Error: ${message}`);
	}
}