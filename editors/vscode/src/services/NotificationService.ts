import { type Disposable, window } from "vscode";

export class NotificationService implements Disposable {
	showError(message: string): Thenable<string | undefined> {
		return window.showErrorMessage(message);
	}

	showWarning(message: string): Thenable<string | undefined> {
		return window.showWarningMessage(message);
	}

	showInfo(message: string): Thenable<string | undefined> {
		return window.showInformationMessage(message);
	}

	dispose(): void {
		// No resources to dispose
	}
}
