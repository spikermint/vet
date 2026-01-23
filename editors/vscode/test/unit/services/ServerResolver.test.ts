import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import type { ExtensionContext } from "vscode";

vi.mock("node:fs");

import { workspace } from "vscode";
import { resolveServerPath } from "../../../src/services/ServerResolver";

const mockContext = {
    extensionPath: "/mock/extension/path",
} as ExtensionContext;

describe("ServerResolver", () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    function mockPlatform(platform: string, arch: string) {
        vi.stubGlobal("process", { ...process, platform, arch });
    }

    function mockConfiguration(serverPath: string | undefined) {
        vi.mocked(workspace.getConfiguration).mockReturnValue({
            get: vi.fn().mockReturnValue(serverPath),
        } as any);
    }

    describe("when no custom path is configured", () => {
        beforeEach(() => {
            mockConfiguration("");
            mockPlatform("darwin", "arm64");
        });

        it("returns bundled binary path when it exists", () => {
            vi.mocked(fs.existsSync).mockReturnValue(true);

            const result = resolveServerPath(mockContext);

            expect(result.ok).toBe(true);
            if (result.ok) {
                expect(result.resolution.path).toBe(
                    "/mock/extension/path/server/vet-lsp-darwin-arm64",
                );
                expect(result.resolution.warning).toBeUndefined();
            }
        });

        it("returns error when bundled binary does not exist", () => {
            vi.mocked(fs.existsSync).mockReturnValue(false);

            const result = resolveServerPath(mockContext);

            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.reason).toBe("binary-not-found");
                expect(result.error.message).toContain("Bundled server not found");
            }
        });
    });

    describe("when custom path is configured", () => {
        beforeEach(() => {
            mockPlatform("darwin", "arm64");
        });

        it("returns custom path when it exists", () => {
            mockConfiguration("/custom/path/to/lsp");
            vi.mocked(fs.existsSync).mockReturnValue(true);

            const result = resolveServerPath(mockContext);

            expect(result.ok).toBe(true);
            if (result.ok) {
                expect(result.resolution.path).toBe("/custom/path/to/lsp");
            }
        });

        it("falls back to bundled with warning when custom path does not exist", () => {
            mockConfiguration("/invalid/path");
            vi.mocked(fs.existsSync)
                .mockReturnValueOnce(false) // Custom path check
                .mockReturnValueOnce(true); // Bundled path check

            const result = resolveServerPath(mockContext);

            expect(result.ok).toBe(true);
            if (result.ok) {
                expect(result.resolution.warning).toContain("does not exist");
                expect(result.resolution.warning).toContain("Falling back");
            }
        });

        it("returns error when both custom and bundled paths fail", () => {
            mockConfiguration("/invalid/path");
            vi.mocked(fs.existsSync).mockReturnValue(false);

            const result = resolveServerPath(mockContext);

            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.reason).toBe("invalid-config");
            }
        });
    });

    describe("platform detection", () => {
        beforeEach(() => {
            mockConfiguration("");
            vi.mocked(fs.existsSync).mockReturnValue(true);
        });

        const platforms = [
            { platform: "darwin", arch: "arm64", expected: "darwin-arm64" },
            { platform: "darwin", arch: "x64", expected: "darwin-x64" },
            { platform: "linux", arch: "x64", expected: "linux-x64" },
            { platform: "linux", arch: "arm64", expected: "linux-arm64" },
            { platform: "win32", arch: "x64", expected: "windows-x64", ext: ".exe" },
            { platform: "win32", arch: "arm64", expected: "windows-arm64", ext: ".exe" },
        ];

        platforms.forEach(({ platform, arch, expected, ext = "" }) => {
            it(`resolves correct binary for ${platform}-${arch}`, () => {
                mockPlatform(platform, arch);

                const result = resolveServerPath(mockContext);

                expect(result.ok).toBe(true);
                if (result.ok) {
                    expect(result.resolution.path).toContain(`vet-lsp-${expected}${ext}`);
                }
            });
        });

        it("returns error for unsupported platform", () => {
            mockPlatform("freebsd", "x64");

            const result = resolveServerPath(mockContext);

            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.reason).toBe("unsupported-platform");
                expect(result.error.platform).toBe("freebsd-x64");
            }
        });
    });
});