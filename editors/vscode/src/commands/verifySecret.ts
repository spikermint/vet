import {
	type CancellationToken,
	commands,
	type Disposable,
	ProgressLocation,
	window,
} from "vscode";
import type { VetClient } from "../client/VetClient";

interface VerifySecretArgs {
	findingId: string;
	patternId: string;
	uri: string;
}

interface VerificationResult {
	status: "live" | "inactive" | "inconclusive";
	service?: {
		provider: string;
		details: string;
	};
}

export function createVerifySecretCommand(client: VetClient): Disposable {
	return commands.registerCommand(
		"vet.verifySecret",
		async (args: VerifySecretArgs) => {
			let result: VerificationResult | null | undefined;

			try {
				result = await window.withProgress(
					{
						location: ProgressLocation.Notification,
						title: `Verifying ${args.patternId}...`,
						cancellable: true,
					},
					async (_progress, token: CancellationToken) => {
						const commandPromise =
							client.executeCommand<VerificationResult | null>(
								"vet.verifySecret",
								args,
							);

						return new Promise<VerificationResult | null | undefined>(
							(resolve, reject) => {
								token.onCancellationRequested(() => {
									resolve(undefined);
								});
								commandPromise.then(resolve, reject);
							},
						);
					},
				);
			} catch (error) {
				window.showErrorMessage(
					`Verification failed: ${error instanceof Error ? error.message : String(error)}`,
				);
				return;
			}

			if (!result) {
				return;
			}

			const details = result.service?.details;
			const detailSuffix = details ? ` - ${details}` : "";

			switch (result.status) {
				case "live":
					window.showErrorMessage(
						`Secret is live: ${args.patternId}${detailSuffix}`,
					);
					break;
				case "inactive":
					window.showInformationMessage(
						`Secret is inactive: ${args.patternId}${detailSuffix}`,
					);
					break;
				case "inconclusive":
					window.showInformationMessage(
						`Verification inconclusive: ${args.patternId}${detailSuffix}`,
					);
					break;
			}
		},
	);
}
