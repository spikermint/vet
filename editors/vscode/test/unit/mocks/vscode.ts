import { vi } from "vitest";

const mockCancellationToken = {
    isCancellationRequested: false,
    onCancellationRequested: vi.fn(() => ({ dispose: vi.fn() })),
};

export const window = {
    showInformationMessage: vi.fn().mockResolvedValue(undefined),
    showWarningMessage: vi.fn().mockResolvedValue(undefined),
    showErrorMessage: vi.fn().mockResolvedValue(undefined),
    withProgress: vi.fn((_options: unknown, task: (progress: { report: () => void }, token: typeof mockCancellationToken) => Promise<unknown>) => task({ report: vi.fn() }, mockCancellationToken)),
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

export const ProgressLocation = {
    SourceControl: 1,
    Window: 10,
    Notification: 15,
} as const;

export class ThemeColor {
    constructor(public id: string) { }
}

export class MarkdownString {
    value: string;
    isTrusted = false;
    supportHtml = false;
    supportThemeIcons = false;
    constructor(value = "", _supportThemeIcons = false) {
        this.value = value;
    }
}

export class Hover {
    contents: MarkdownString | MarkdownString[];
    range: unknown;
    constructor(contents: MarkdownString | MarkdownString[], range?: unknown) {
        this.contents = contents;
        this.range = range;
    }
}

export class Range {
    start: { line: number; character: number };
    end: { line: number; character: number };
    constructor(start: { line: number; character: number }, end: { line: number; character: number }) {
        this.start = start;
        this.end = end;
    }
}

export class Position {
    line: number;
    character: number;
    constructor(line: number, character: number) {
        this.line = line;
        this.character = character;
    }
}

export const ColorThemeKind = {
    Light: 1,
    Dark: 2,
    HighContrast: 3,
    HighContrastLight: 4,
} as const;

Object.assign(window, {
    activeColorTheme: { kind: ColorThemeKind.Dark },
});

export const languages = {
    registerHoverProvider: vi.fn(() => ({ dispose: vi.fn() })),
};

export const Uri = {
    parse: vi.fn((uri: string) => ({ toString: () => uri, fsPath: uri })),
    joinPath: vi.fn(),
};