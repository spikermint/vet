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

export interface ServerResolution {
	path: string;
	warning?: string;
}

export function resolveServerPath(
	context: ExtensionContext,
): ServerResolution | undefined {
	const configuredPath = workspace
		.getConfiguration("vet")
		.get<string>("serverPath");

	if (configuredPath && configuredPath.trim() !== "") {
		if (fs.existsSync(configuredPath)) {
			return { path: configuredPath };
		}

		const bundledPath = getBundledServerPath(context);
		if (bundledPath) {
			return {
				path: bundledPath,
				warning: `Configured vet.serverPath does not exist: ${configuredPath}. Falling back to bundled binary.`,
			};
		}

		return undefined;
	}

	const bundledPath = getBundledServerPath(context);
	if (bundledPath) {
		return { path: bundledPath };
	}

	return undefined;
}

function getBundledServerPath(context: ExtensionContext): string | undefined {
	const platformKey = `${process.platform}-${process.arch}`;
	const target = PLATFORM_TARGETS[platformKey];

	if (!target) {
		return undefined;
	}

	const ext = process.platform === "win32" ? ".exe" : "";
	const binaryName = `vet-lsp-${target}${ext}`;
	const serverPath = path.join(context.extensionPath, "server", binaryName);

	if (fs.existsSync(serverPath)) {
		return serverPath;
	}

	return undefined;
}
