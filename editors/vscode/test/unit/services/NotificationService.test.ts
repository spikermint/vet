import { describe, it, expect, vi, beforeEach } from "vitest";
import { window } from "vscode";
import { NotificationService } from "../../../src/services/NotificationService";

describe("NotificationService", () => {
    let service: NotificationService;

    beforeEach(() => {
        vi.clearAllMocks();
        service = new NotificationService();
    });

    describe("showError", () => {
        it("calls showErrorMessage with the message", () => {
            service.showError("Something went wrong");
            expect(window.showErrorMessage).toHaveBeenCalledWith("Something went wrong");
        });

        it("returns the result from VSCode API", async () => {
            vi.mocked(window.showErrorMessage).mockResolvedValue("Retry" as any);
            const result = await service.showError("Error");
            expect(result).toBe("Retry");
        });
    });

    describe("showWarning", () => {
        it("calls showWarningMessage with the message", () => {
            service.showWarning("Be careful");
            expect(window.showWarningMessage).toHaveBeenCalledWith("Be careful");
        });
    });

    describe("showInfo", () => {
        it("calls showInformationMessage with the message", () => {
            service.showInfo("All good");
            expect(window.showInformationMessage).toHaveBeenCalledWith("All good");
        });
    });

    describe("dispose", () => {
        it("does not throw", () => {
            expect(() => service.dispose()).not.toThrow();
        });
    });
});