import { defineConfig } from "vitest/config";
import path from "node:path";

export default defineConfig({
    test: {
        globals: true,
        alias: {
            vscode: path.resolve(__dirname, "test/unit/mocks/vscode.ts"),
        },
        coverage: {
            include: ["src/**/*.ts"],
            exclude: ["src/extension.ts"],
        },
    },
});