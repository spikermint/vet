import { defineConfig } from "vitest/config";
import path from "node:path";

export default defineConfig({
    test: {
        globals: true,
        exclude: ["test/e2e/**", "out-test/**", "dist/**", "node_modules/**"],
        alias: {
            vscode: path.resolve(__dirname, "test/unit/mocks/vscode.ts"),
        },
        coverage: {
            include: ["src/**/*.ts"],
            exclude: ["src/extension.ts"],
        },
    },
});