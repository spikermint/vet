import { vi } from "vitest";

export const window = {
    showInformationMessage: vi.fn().mockResolvedValue(undefined),
    showWarningMessage: vi.fn().mockResolvedValue(undefined),
    showErrorMessage: vi.fn().mockResolvedValue(undefined),
    createOutputChannel: vi.fn(() => ({
        appendLine: vi.fn(),
        append: vi.fn(),
        clear: vi.fn(),
        show: vi.fn(),
        hide: vi.fn(),
        dispose: vi.fn(),
        name: "Vet",
    })),
    createStatusBarItem: vi.fn(() => ({
        text: "",
        tooltip: "",
        command: "",
        backgroundColor: undefined,
        show: vi.fn(),
        hide: vi.fn(),
        dispose: vi.fn(),
    })),
};

export const workspace = {
    getConfiguration: vi.fn(() => ({
        get: vi.fn(),
        update: vi.fn(),
        has: vi.fn(),
        inspect: vi.fn(),
    })),
    workspaceFolders: undefined,
    onDidChangeConfiguration: vi.fn(() => ({ dispose: vi.fn() })),
};

export const commands = {
    registerCommand: vi.fn(() => ({ dispose: vi.fn() })),
    executeCommand: vi.fn(),
};

export const StatusBarAlignment = {
    Left: 1,
    Right: 2,
} as const;

export class ThemeColor {
    constructor(public id: string) { }
}