import {
	type CancellationToken,
	type ExtensionContext,
	type OutputChannel,
	type Position,
	type TextDocument,
	workspace,
} from "vscode";
import {
	LanguageClient,
	type LanguageClientOptions,
	type ServerOptions,
} from "vscode-languageclient/node";
import type { VetHoverResponse } from "../protocol/types";
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
				minimumConfidence: config.get<string>("minimumConfidence", "high"),
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

	async executeCommand<T = unknown>(
		command: string,
		args: unknown,
	): Promise<T | undefined> {
		if (!this.client) {
			throw new Error("Language client not initialised");
		}

		return (await this.client.sendRequest("workspace/executeCommand", {
			command,
			arguments: [args],
		})) as T | undefined;
	}

	async sendHoverDataRequest(
		document: TextDocument,
		position: Position,
		token: CancellationToken,
	): Promise<VetHoverResponse | null> {
		if (!this.client) {
			return null;
		}

		return this.client.sendRequest<VetHoverResponse | null>(
			"vet/hoverData",
			{
				textDocument: { uri: document.uri.toString() },
				position: {
					line: position.line,
					character: position.character,
				},
			},
			token,
		);
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
