import {
    type ExtensionContext,
    type OutputChannel,
    workspace,
} from "vscode";
import {
    LanguageClient,
    type LanguageClientOptions,
    type ServerOptions,
} from "vscode-languageclient/node";
import { resolveServerPath } from "../services/ServerResolver";
import type { StatusBarService } from "../services/StatusBarService";

export class VetClient {
    private client: LanguageClient | undefined;
    private isRestarting = false;

    constructor(
        private readonly context: ExtensionContext,
        private readonly outputChannel: OutputChannel,
        private readonly statusBar: StatusBarService,
    ) { }

    async start(): Promise<void> {
        const serverPath = resolveServerPath(this.context);

        if (!serverPath) {
            this.statusBar.setError("Server not found");
            this.outputChannel.appendLine(
                "[Vet] Could not find vet-lsp binary. Set vet.serverPath or reinstall the extension.",
            );
            return;
        }

        this.outputChannel.appendLine(`[Vet] Using server: ${serverPath}`);

        const serverOptions: ServerOptions = {
            command: serverPath,
            args: [],
        };

        const config = workspace.getConfiguration("vet");

        const clientOptions: LanguageClientOptions = {
            documentSelector: [{ scheme: "file" }, { scheme: "untitled" }],
            outputChannel: this.outputChannel,
            initializationOptions: {
                includeLowConfidence: config.get<boolean>("includeLowConfidence", false),
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
            this.statusBar.setError("Failed to start");
            this.outputChannel.appendLine(`[Vet] Failed to start server: ${error}`);
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
}