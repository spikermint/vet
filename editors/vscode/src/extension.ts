import { type ExtensionContext, languages, window, workspace } from "vscode";
import { VetClient } from "./client/VetClient";
import { createIgnoreInConfigCommand } from "./commands/ignoreInConfig";
import { createRestartCommand } from "./commands/restart";
import { createVerifySecretCommand } from "./commands/verifySecret";
import { VetHoverProvider } from "./providers/HoverProvider";
import { NotificationService } from "./services/NotificationService";
import { StatusBarService } from "./services/StatusBarService";

let client: VetClient | undefined;

export async function activate(context: ExtensionContext): Promise<void> {
	const config = workspace.getConfiguration("vet");

	if (!config.get<boolean>("enable", true)) {
		return;
	}

	const outputChannel = window.createOutputChannel("Vet");
	const statusBar = new StatusBarService();
	const notifications = new NotificationService();

	client = new VetClient(context, outputChannel, statusBar, notifications);

	context.subscriptions.push(
		outputChannel,
		statusBar,
		notifications,
		createRestartCommand(client),
		createIgnoreInConfigCommand(client),
		createVerifySecretCommand(client),
		languages.registerHoverProvider(
			[{ scheme: "file" }, { scheme: "untitled" }],
			new VetHoverProvider(client),
		),
	);

	await client.start();
}

export async function deactivate(): Promise<void> {
	await client?.stop();
}
