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
