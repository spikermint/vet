import { describe, it, expect, vi, beforeEach } from "vitest";
import { window, StatusBarAlignment, ThemeColor } from "vscode";
import { StatusBarService } from "../../../src/services/StatusBarService";

describe("StatusBarService", () => {
    let service: StatusBarService;
    let mockItem: ReturnType<typeof window.createStatusBarItem>;

    beforeEach(() => {
        vi.clearAllMocks();
        mockItem = window.createStatusBarItem(StatusBarAlignment.Right, 100);
        vi.mocked(window.createStatusBarItem).mockReturnValue(mockItem);
        service = new StatusBarService();
    });

    describe("construction", () => {
        it("creates status bar item on right side", () => {
            expect(window.createStatusBarItem).toHaveBeenCalledWith(
                StatusBarAlignment.Right,
                100,
            );
        });

        it("sets restart command", () => {
            expect(mockItem.command).toBe("vet.restart");
        });

        it("shows the status bar item", () => {
            expect(mockItem.show).toHaveBeenCalled();
        });
    });

    describe("setReady", () => {
        it("sets text with shield icon", () => {
            service.setReady();
            expect(mockItem.text).toBe("$(shield) Vet");
        });

        it("sets tooltip indicating running state", () => {
            service.setReady();
            expect(mockItem.tooltip).toContain("running");
        });

        it("clears error background", () => {
            mockItem.backgroundColor = new ThemeColor("error");
            service.setReady();
            expect(mockItem.backgroundColor).toBeUndefined();
        });
    });

    describe("setRestarting", () => {
        it("sets text with spinning icon", () => {
            service.setRestarting();
            expect(mockItem.text).toBe("$(sync~spin) Vet");
        });

        it("sets tooltip indicating restarting state", () => {
            service.setRestarting();
            expect(mockItem.tooltip).toContain("restarting");
        });
    });

    describe("setError", () => {
        it("sets text with warning icon", () => {
            service.setError("Connection failed");
            expect(mockItem.text).toContain("$(warning)");
        });

        it("includes error message in tooltip", () => {
            service.setError("Server crashed");
            expect(mockItem.tooltip).toContain("Server crashed");
        });

        it("sets error background colour", () => {
            service.setError("Error");
            expect(mockItem.backgroundColor).toBeInstanceOf(ThemeColor);
        });
    });

    describe("dispose", () => {
        it("disposes the status bar item", () => {
            service.dispose();
            expect(mockItem.dispose).toHaveBeenCalled();
        });
    });
});