import { commands, type Disposable, Uri, window, workspace } from "vscode";
import type { VetClient } from "../client/VetClient";

interface IgnoreInConfigParams {
	fingerprint: string;
	patternId: string;
	uri: string;
}

export function createIgnoreInConfigCommand(client: VetClient): Disposable {
	return commands.registerCommand(
		"vet.ignoreInConfig",
		async (params: IgnoreInConfigParams) => {
			const reason = await promptForReason();
			if (!reason) {
				return;
			}

			const workspaceFolder = workspace.getWorkspaceFolder(
				Uri.parse(params.uri),
			);
			if (!workspaceFolder) {
				window.showErrorMessage("No workspace folder found for this file");
				return;
			}

			try {
				await client.executeCommand("vet.ignoreInConfig", {
					...params,
					reason,
					workspacePath: workspaceFolder.uri.fsPath,
				});

				const action = await window.showInformationMessage(
					`Added ${params.patternId} to .vet.toml`,
					"Open Config",
				);

				if (action === "Open Config") {
					const configUri = Uri.joinPath(workspaceFolder.uri, ".vet.toml");
					await window.showTextDocument(configUri);
				}
			} catch (error) {
				window.showErrorMessage(
					`Failed to update .vet.toml: ${error instanceof Error ? error.message : String(error)}`,
				);
			}
		},
	);
}

async function promptForReason(): Promise<string | undefined> {
	return await window.showInputBox({
		prompt: "Why are you ignoring this finding?",
		placeHolder: "e.g., Test fixture with fake credentials",
		validateInput: (value: string): string | undefined => {
			if (!value.trim()) {
				return "Reason is required";
			}
			if (value.length < 3) {
				return "Reason must be at least 3 characters";
			}
			return undefined;
		},
	});
}
