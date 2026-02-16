import {
	type CancellationToken,
	ColorThemeKind,
	Hover,
	MarkdownString,
	type Position,
	type TextDocument,
	window,
} from "vscode";
import type { VetClient } from "../client/VetClient";
import type {
	ExposureRisk,
	HoverData,
	Severity,
	VerificationInfo,
} from "../protocol/types";

type ColorToken = "danger" | "warning" | "info" | "success" | "muted";

const COLOR_PALETTES: Record<
	"dark" | "light" | "highContrastDark" | "highContrastLight",
	Record<ColorToken, string>
> = {
	dark: {
		danger: "#f25555",
		warning: "#cca700",
		info: "#3794ff",
		success: "#89d185",
		muted: "#8c8c8c",
	},
	light: {
		danger: "#c42020",
		warning: "#8a5700",
		info: "#005fb8",
		success: "#2e7d32",
		muted: "#505050",
	},
	highContrastDark: {
		danger: "#ff6b6b",
		warning: "#ffcc00",
		info: "#6bc5ff",
		success: "#89ff89",
		muted: "#d4d4d4",
	},
	highContrastLight: {
		danger: "#a00000",
		warning: "#6b4400",
		info: "#003d7a",
		success: "#1b5e20",
		muted: "#3a3a3a",
	},
};

export class VetHoverProvider {
	constructor(private readonly client: VetClient) {}

	async provideHover(
		document: TextDocument,
		position: Position,
		token: CancellationToken,
	): Promise<Hover | null> {
		const response = await this.client.sendHoverDataRequest(
			document,
			position,
			token,
		);

		if (!response) {
			return null;
		}

		const markdown = renderHoverMarkdown(response.data);

		if (response.range) {
			const { Range, Position } = await import("vscode");
			const range = new Range(
				new Position(response.range.start.line, response.range.start.character),
				new Position(response.range.end.line, response.range.end.character),
			);
			return new Hover(markdown, range);
		}

		return new Hover(markdown);
	}
}

export function renderHoverMarkdown(data: HoverData): MarkdownString {
	const palette = getColorPalette();
	const lines: string[] = [];

	const severityColor = mapSeverityColor(data.severity, palette);
	const severityLabel = formatSeverityLabel(data.severity);
	lines.push(
		`**${data.patternName}** · **<span style="color:${severityColor};">${severityLabel}</span>**`,
	);
	lines.push("");
	lines.push(
		`<span style="color:${palette.muted};">${data.description}</span>`,
	);

	if (data.verification) {
		lines.push("");
		lines.push("---");
		lines.push("");
		lines.push(formatVerificationStatus(data.verification, palette));
	}

	lines.push("");
	lines.push("---");
	lines.push("");
	lines.push(
		formatRemediation(
			data.remediation.exposure,
			data.remediation.advice,
			palette,
		),
	);

	const md = new MarkdownString(lines.join("\n"), true);
	md.supportHtml = true;
	md.supportThemeIcons = true;
	md.isTrusted = true;
	return md;
}

function formatVerificationStatus(
	verification: VerificationInfo,
	palette: Record<ColorToken, string>,
): string {
	const relativeTime = formatRelativeTime(verification.verifiedAt);

	switch (verification.status) {
		case "live": {
			const info = formatProviderInfo(
				verification.provider,
				verification.details,
				"",
			);
			let out = `$(circle-filled) **<span style="color:${palette.danger};">Live</span>**`;
			if (info) {
				out += ` · <span style="color:${palette.muted};">${info}</span>`;
			}
			out += ` · <span style="color:${palette.muted};">${relativeTime}</span>`;
			return out;
		}
		case "inactive": {
			const info = formatProviderInfo(
				verification.provider,
				verification.details,
				"revoked or expired",
			);
			return (
				`$(pass) **<span style="color:${palette.success};">Inactive</span>**` +
				` · <span style="color:${palette.muted};">${info} · ${relativeTime}</span>`
			);
		}
		case "inconclusive": {
			const reason =
				verification.reason ??
				verification.details ??
				"rate limited, try again later";
			return (
				`$(question) **<span style="color:${palette.warning};">Inconclusive</span>**` +
				` · <span style="color:${palette.muted};">${reason} · ${relativeTime}</span>`
			);
		}
	}
}

function formatProviderInfo(
	provider: string | undefined,
	details: string | undefined,
	fallback: string,
): string {
	if (provider && details) {
		return `${provider} - ${details}`;
	}
	if (provider) {
		return provider;
	}
	return fallback;
}

function formatRemediation(
	exposure: ExposureRisk,
	advice: string,
	palette: Record<ColorToken, string>,
): string {
	if (exposure === "inHistory") {
		const [firstLine, ...rest] = advice.split("\n\n");
		const warning = `**<span style="color:${palette.danger};">${firstLine ?? advice}</span>**`;
		if (rest.length > 0) {
			return `${warning}\n\n${rest.join("\n\n")}`;
		}
		return warning;
	}
	return advice;
}

function formatRelativeTime(isoTimestamp: string): string {
	const verifiedAt = new Date(isoTimestamp);
	const now = new Date();
	const diffMs = now.getTime() - verifiedAt.getTime();

	if (diffMs < 0 || diffMs < 60_000) {
		return "verified just now";
	}

	const minutes = Math.floor(diffMs / 60_000);
	if (minutes === 1) {
		return "verified 1 minute ago";
	}
	if (minutes < 60) {
		return `verified ${minutes} minutes ago`;
	}

	const hours = Math.floor(diffMs / 3_600_000);
	if (hours === 1) {
		return "verified 1 hour ago";
	}
	if (hours < 24) {
		return `verified ${hours} hours ago`;
	}

	const days = Math.floor(diffMs / 86_400_000);
	if (days === 1) {
		return "verified 1 day ago";
	}
	return `verified ${days} days ago`;
}

function mapSeverityColor(
	severity: Severity,
	palette: Record<ColorToken, string>,
): string {
	switch (severity) {
		case "critical":
			return palette.danger;
		case "high":
			return palette.warning;
		case "medium":
			return palette.info;
		case "low":
			return palette.success;
	}
}

function formatSeverityLabel(severity: Severity): string {
	switch (severity) {
		case "critical":
			return "Critical";
		case "high":
			return "High";
		case "medium":
			return "Medium";
		case "low":
			return "Low";
	}
}

function getColorPalette(): Record<ColorToken, string> {
	switch (window.activeColorTheme.kind) {
		case ColorThemeKind.Light:
			return COLOR_PALETTES.light;
		case ColorThemeKind.HighContrast:
			return COLOR_PALETTES.highContrastDark;
		case ColorThemeKind.HighContrastLight:
			return COLOR_PALETTES.highContrastLight;
		default:
			return COLOR_PALETTES.dark;
	}
}
