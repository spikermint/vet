import {
	type Disposable,
	StatusBarAlignment,
	type StatusBarItem,
	ThemeColor,
	window,
} from "vscode";

export class StatusBarService implements Disposable {
	private readonly item: StatusBarItem;

	constructor() {
		this.item = window.createStatusBarItem(StatusBarAlignment.Right, 100);
		this.item.command = "vet.restart";
		this.item.text = "$(shield) Vet";
		this.item.show();
	}

	setReady(): void {
		this.item.text = "$(shield) Vet";
		this.item.tooltip = "Vet is running. Click to restart.";
		this.item.backgroundColor = undefined;
	}

	setRestarting(): void {
		this.item.text = "$(sync~spin) Vet";
		this.item.tooltip = "Vet is restarting...";
		this.item.backgroundColor = undefined;
	}

	setError(message: string): void {
		this.item.text = "$(shield) Vet $(warning)";
		this.item.tooltip = `Vet: ${message}. Click to restart.`;
		this.item.backgroundColor = new ThemeColor("statusBarItem.errorBackground");
	}

	dispose(): void {
		this.item.dispose();
	}
}
