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

export interface ServerResolutionError {
	reason: "invalid-config" | "unsupported-platform" | "binary-not-found";
	message: string;
	platform?: string;
}

export type ResolveResult =
	| { ok: true; resolution: ServerResolution }
	| { ok: false; error: ServerResolutionError };

export function resolveServerPath(context: ExtensionContext): ResolveResult {
	const configuredPath = workspace
		.getConfiguration("vet")
		.get<string>("serverPath");

	if (configuredPath && configuredPath.trim() !== "") {
		if (fs.existsSync(configuredPath)) {
			return { ok: true, resolution: { path: configuredPath } };
		}

		const bundled = getBundledServerPath(context);
		if (bundled.ok) {
			return {
				ok: true,
				resolution: {
					path: bundled.path,
					warning: `Configured vet.serverPath does not exist: ${configuredPath}. Falling back to bundled binary.`,
				},
			};
		}

		return {
			ok: false,
			error: {
				reason: "invalid-config",
				message: `Configured vet.serverPath does not exist: ${configuredPath}`,
			},
		};
	}

	const bundled = getBundledServerPath(context);
	if (bundled.ok) {
		return { ok: true, resolution: { path: bundled.path } };
	}

	return { ok: false, error: bundled.error };
}

type BundledResult =
	| { ok: true; path: string }
	| { ok: false; error: ServerResolutionError };

function getBundledServerPath(context: ExtensionContext): BundledResult {
	const platformKey = `${process.platform}-${process.arch}`;
	const target = PLATFORM_TARGETS[platformKey];

	if (!target) {
		return {
			ok: false,
			error: {
				reason: "unsupported-platform",
				message: `Unsupported platform: ${platformKey}. Vet supports: macOS (x64, arm64), Linux (x64, arm64), Windows (x64, arm64).`,
				platform: platformKey,
			},
		};
	}

	const ext = process.platform === "win32" ? ".exe" : "";
	const binaryName = `vet-lsp-${target}${ext}`;
	const serverPath = path.join(context.extensionPath, "server", binaryName);

	if (fs.existsSync(serverPath)) {
		return { ok: true, path: serverPath };
	}

	return {
		ok: false,
		error: {
			reason: "binary-not-found",
			message: `Bundled server not found at: ${serverPath}. Try reinstalling the extension.`,
		},
	};
}
