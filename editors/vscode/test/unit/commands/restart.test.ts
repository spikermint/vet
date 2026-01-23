import { describe, it, expect, vi, beforeEach } from "vitest";
import { commands } from "vscode";
import { createRestartCommand } from "../../../src/commands/restart";

describe("createRestartCommand", () => {
    let mockClient: any;
    let registeredCallback: () => Promise<void>;

    beforeEach(() => {
        vi.clearAllMocks();

        mockClient = {
            restart: vi.fn().mockResolvedValue(undefined),
        };

        vi.mocked(commands.registerCommand).mockImplementation(
            (_command: string, callback: any) => {
                registeredCallback = callback;
                return { dispose: vi.fn() };
            },
        );
    });

    it("registers the vet.restart command", () => {
        createRestartCommand(mockClient);

        expect(commands.registerCommand).toHaveBeenCalledWith(
            "vet.restart",
            expect.any(Function),
        );
    });

    it("returns a disposable", () => {
        const disposable = createRestartCommand(mockClient);

        expect(disposable).toHaveProperty("dispose");
    });

    it("calls client.restart when command is executed", async () => {
        createRestartCommand(mockClient);

        await registeredCallback();

        expect(mockClient.restart).toHaveBeenCalled();
    });
});