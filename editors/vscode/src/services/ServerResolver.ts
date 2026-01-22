import * as fs from "node:fs";
import * as path from "node:path";
import { type ExtensionContext, workspace } from "vscode";

const PLATFORM_TARGETS: Record<string, string> = {
	"darwin-arm64": "darwin-arm64",
	"darwin-x64": "darwin-x64",
	"linux-arm64": "linux-arm64",
	"linux-x64": "linux-x64",
	"win32-x64": "windows-x64",
	"win32-arm64": "windows-arm64",
};

export function resolveServerPath(
	context: ExtensionContext,
): string | undefined {
	const configuredPath = workspace
		.getConfiguration("vet")
		.get<string>("serverPath");

	if (configuredPath && configuredPath.trim() !== "") {
		if (fs.existsSync(configuredPath)) {
			return configuredPath;
		}
		console.warn(
			`[Vet] Configured serverPath does not exist: ${configuredPath}`,
		);
	}

	return getBundledServerPath(context);
}

function getBundledServerPath(context: ExtensionContext): string | undefined {
	const platformKey = `${process.platform}-${process.arch}`;
	const target = PLATFORM_TARGETS[platformKey];

	if (!target) {
		console.error(`[Vet] Unsupported platform: ${platformKey}`);
		return undefined;
	}

	const ext = process.platform === "win32" ? ".exe" : "";
	const binaryName = `vet-lsp-${target}${ext}`;
	const serverPath = path.join(context.extensionPath, "server", binaryName);

	if (fs.existsSync(serverPath)) {
		return serverPath;
	}

	console.error(`[Vet] Bundled server not found: ${serverPath}`);
	return undefined;
}
