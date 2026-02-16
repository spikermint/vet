import { describe, it, expect } from "vitest";
import { MarkdownString } from "vscode";
import { renderHoverMarkdown } from "../../../src/providers/HoverProvider";
import type { HoverData } from "../../../src/protocol/types";

function makeHoverData(overrides: Partial<HoverData> = {}): HoverData {
	return {
		patternName: "AWS Secret Key",
		severity: "high",
		description: "Matches AWS secret access keys",
		remediation: {
			exposure: "unknown",
			advice: "Avoid committing secrets. Use environment variables or a secrets manager.\n\nIf exposed: Revoke or rotate the key.",
		},
		...overrides,
	};
}

describe("renderHoverMarkdown", () => {
	it("returns a MarkdownString", () => {
		const result = renderHoverMarkdown(makeHoverData());

		expect(result).toBeInstanceOf(MarkdownString);
	});

	it("contains the pattern name", () => {
		const result = renderHoverMarkdown(makeHoverData());

		expect(result.value).toContain("AWS Secret Key");
	});

	it("contains severity label for critical", () => {
		const result = renderHoverMarkdown(
			makeHoverData({ severity: "critical" }),
		);

		expect(result.value).toContain("Critical");
	});

	it("contains severity label for high", () => {
		const result = renderHoverMarkdown(makeHoverData({ severity: "high" }));

		expect(result.value).toContain("High");
	});

	it("contains severity label for medium", () => {
		const result = renderHoverMarkdown(
			makeHoverData({ severity: "medium" }),
		);

		expect(result.value).toContain("Medium");
	});

	it("contains severity label for low", () => {
		const result = renderHoverMarkdown(makeHoverData({ severity: "low" }));

		expect(result.value).toContain("Low");
	});

	it("contains description", () => {
		const result = renderHoverMarkdown(makeHoverData());

		expect(result.value).toContain("Matches AWS secret access keys");
	});

	it("omits verification section when not present", () => {
		const result = renderHoverMarkdown(makeHoverData());

		expect(result.value).not.toContain("Live");
		expect(result.value).not.toContain("Inactive");
		expect(result.value).not.toContain("Inconclusive");
	});

	it("shows live verification status", () => {
		const result = renderHoverMarkdown(
			makeHoverData({
				verification: {
					status: "live",
					provider: "GitHub",
					details: "user: octocat",
					verifiedAt: new Date().toISOString(),
				},
			}),
		);

		expect(result.value).toContain("Live");
		expect(result.value).toContain("$(circle-filled)");
		expect(result.value).toContain("GitHub");
		expect(result.value).toContain("user: octocat");
	});

	it("shows inactive verification status", () => {
		const result = renderHoverMarkdown(
			makeHoverData({
				verification: {
					status: "inactive",
					provider: "GitHub",
					verifiedAt: new Date().toISOString(),
				},
			}),
		);

		expect(result.value).toContain("Inactive");
		expect(result.value).toContain("$(pass)");
	});

	it("shows inconclusive verification status with reason", () => {
		const result = renderHoverMarkdown(
			makeHoverData({
				verification: {
					status: "inconclusive",
					reason: "rate limited",
					verifiedAt: new Date().toISOString(),
				},
			}),
		);

		expect(result.value).toContain("Inconclusive");
		expect(result.value).toContain("$(question)");
		expect(result.value).toContain("rate limited");
	});

	it("shows remediation advice", () => {
		const result = renderHoverMarkdown(makeHoverData());

		expect(result.value).toContain("Avoid committing secrets");
	});

	it("formats in-history remediation with danger colour", () => {
		const result = renderHoverMarkdown(
			makeHoverData({
				remediation: {
					exposure: "inHistory",
					advice: "This secret is in your git history.\n\nRevoke or rotate the key.",
				},
			}),
		);

		expect(result.value).toContain("git history");
		expect(result.value).toContain("Revoke or rotate");
	});

	it("shows not-in-history advice directly", () => {
		const result = renderHoverMarkdown(
			makeHoverData({
				remediation: {
					exposure: "notInHistory",
					advice: "Remove before committing. Use environment variables or a secrets manager instead.",
				},
			}),
		);

		expect(result.value).toContain("Remove before committing");
	});

	it("enables HTML support", () => {
		const result = renderHoverMarkdown(makeHoverData());

		expect(result.supportHtml).toBe(true);
	});

	it("enables theme icon support", () => {
		const result = renderHoverMarkdown(makeHoverData());

		expect(result.supportThemeIcons).toBe(true);
	});

	it("marks content as trusted", () => {
		const result = renderHoverMarkdown(makeHoverData());

		expect(result.isTrusted).toBe(true);
	});

	it("shows verified just now for recent timestamp", () => {
		const result = renderHoverMarkdown(
			makeHoverData({
				verification: {
					status: "live",
					provider: "GitHub",
					verifiedAt: new Date().toISOString(),
				},
			}),
		);

		expect(result.value).toContain("verified just now");
	});
});
