import { describe, it, expect, vi, beforeEach } from "vitest";
import { workspace } from "vscode";
import * as ServerResolver from "../../../src/services/ServerResolver";

const mockStart = vi.fn();
const mockStop = vi.fn();

vi.mock("vscode-languageclient/node", () => {
    return {
        LanguageClient: class {
            start = mockStart;
            stop = mockStop;
        },
    };
});

vi.mock("../../../src/services/ServerResolver", () => ({
    resolveServerPath: vi.fn(),
}));

import { VetClient } from "../../../src/client/VetClient";

describe("VetClient", () => {
    let client: VetClient;
    let mockContext: any;
    let mockOutputChannel: any;
    let mockStatusBar: any;
    let mockNotifications: any;

    beforeEach(() => {
        vi.clearAllMocks();
        mockStart.mockResolvedValue(undefined);
        mockStop.mockResolvedValue(undefined);

        mockContext = {
            extensionPath: "/mock/extension",
            extension: {
                packageJSON: { version: "1.2.3" },
            },
        };

        mockOutputChannel = {
            appendLine: vi.fn(),
        };

        mockStatusBar = {
            setReady: vi.fn(),
            setRestarting: vi.fn(),
            setError: vi.fn(),
        };

        mockNotifications = {
            showError: vi.fn(),
            showWarning: vi.fn(),
            showInfo: vi.fn(),
        };

        vi.mocked(workspace.getConfiguration).mockReturnValue({
            get: vi.fn().mockReturnValue(false),
        } as any);

        client = new VetClient(
            mockContext,
            mockOutputChannel,
            mockStatusBar,
            mockNotifications,
        );
    });

    describe("start", () => {
        it("logs version on startup", async () => {
            vi.mocked(ServerResolver.resolveServerPath).mockReturnValue({
                ok: true,
                resolution: { path: "/mock/server" },
            });

            await client.start();

            expect(mockOutputChannel.appendLine).toHaveBeenCalledWith(
                expect.stringContaining("v1.2.3"),
            );
        });

        it("sets status bar to ready on successful start", async () => {
            vi.mocked(ServerResolver.resolveServerPath).mockReturnValue({
                ok: true,
                resolution: { path: "/mock/server" },
            });

            await client.start();

            expect(mockStatusBar.setReady).toHaveBeenCalled();
        });

        it("shows warning when resolution has warning", async () => {
            vi.mocked(ServerResolver.resolveServerPath).mockReturnValue({
                ok: true,
                resolution: {
                    path: "/mock/server",
                    warning: "Using fallback binary",
                },
            });

            await client.start();

            expect(mockNotifications.showWarning).toHaveBeenCalledWith(
                "Using fallback binary",
            );
        });

        it("handles resolution error", async () => {
            vi.mocked(ServerResolver.resolveServerPath).mockReturnValue({
                ok: false,
                error: {
                    reason: "binary-not-found",
                    message: "Server not found at path",
                },
            });

            await client.start();

            expect(mockStatusBar.setError).toHaveBeenCalledWith("Server not found");
            expect(mockNotifications.showError).toHaveBeenCalledWith(
                "Server not found at path",
            );
        });

        it("logs server path on start", async () => {
            vi.mocked(ServerResolver.resolveServerPath).mockReturnValue({
                ok: true,
                resolution: { path: "/custom/lsp/path" },
            });

            await client.start();

            expect(mockOutputChannel.appendLine).toHaveBeenCalledWith(
                expect.stringContaining("/custom/lsp/path"),
            );
        });

        it("handles client start failure", async () => {
            vi.mocked(ServerResolver.resolveServerPath).mockReturnValue({
                ok: true,
                resolution: { path: "/mock/server" },
            });
            mockStart.mockRejectedValue(new Error("Connection refused"));

            await client.start();

            expect(mockStatusBar.setError).toHaveBeenCalledWith("Failed to start");
            expect(mockNotifications.showError).toHaveBeenCalledWith(
                expect.stringContaining("Connection refused"),
            );
        });
    });

    describe("stop", () => {
        it("stops the client when running", async () => {
            vi.mocked(ServerResolver.resolveServerPath).mockReturnValue({
                ok: true,
                resolution: { path: "/mock/server" },
            });

            await client.start();
            await client.stop();

            expect(mockStop).toHaveBeenCalled();
        });

        it("handles stop when not started", async () => {
            await client.stop();

            expect(mockStop).not.toHaveBeenCalled();
        });
    });

    describe("restart", () => {
        beforeEach(() => {
            vi.mocked(ServerResolver.resolveServerPath).mockReturnValue({
                ok: true,
                resolution: { path: "/mock/server" },
            });
        });

        it("sets restarting state", async () => {
            await client.restart();

            expect(mockStatusBar.setRestarting).toHaveBeenCalled();
        });

        it("logs restart message", async () => {
            await client.restart();

            expect(mockOutputChannel.appendLine).toHaveBeenCalledWith(
                expect.stringContaining("Restarting"),
            );
        });

        it("prevents concurrent restarts", async () => {
            const restart1 = client.restart();
            const restart2 = client.restart();

            await Promise.all([restart1, restart2]);

            expect(mockStatusBar.setRestarting).toHaveBeenCalledTimes(1);
        });
    });
});