import { type ExtensionContext, window, workspace } from "vscode";
import { VetClient } from "./client/VetClient";
import { createRestartCommand } from "./commands/restart";
import { StatusBarService } from "./services/StatusBarService";

let client: VetClient | undefined;

export async function activate(context: ExtensionContext): Promise<void> {
	const config = workspace.getConfiguration("vet");

	if (!config.get<boolean>("enable", true)) {
		return;
	}

	const outputChannel = window.createOutputChannel("Vet");
	const statusBar = new StatusBarService();

	client = new VetClient(context, outputChannel, statusBar);

	context.subscriptions.push(
		outputChannel,
		statusBar,
		createRestartCommand(client),
	);

	await client.start();
}

export async function deactivate(): Promise<void> {
	await client?.stop();
}
