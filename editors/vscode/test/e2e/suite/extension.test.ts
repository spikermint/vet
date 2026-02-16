import * as vscode from "vscode";
import * as assert from "assert";
import * as path from "path";

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForDiagnostics(
    uri: vscode.Uri,
    timeout: number,
): Promise<vscode.Diagnostic[]> {
    const start = Date.now();
    while (Date.now() - start < timeout) {
        const diagnostics = vscode.languages.getDiagnostics(uri);
        if (diagnostics.length > 0) {
            return diagnostics;
        }
        await sleep(100);
    }
    return [];
}

suite("Vet Extension E2E", () => {
    // Navigate from dist/test/e2e/suite back to test/e2e/fixtures/workspace
    const fixturesPath = path.resolve(__dirname, "../../../test/e2e/fixtures/workspace");

    suiteSetup(async () => {
        // Extension ID matches package.json: publisher.name = "vet.vet"
        const ext = vscode.extensions.getExtension("vet.vet");
        if (ext && !ext.isActive) {
            await ext.activate();
        }
        // Allow LSP server to start
        await sleep(3000);
    });

    test("extension activates successfully", async () => {
        const ext = vscode.extensions.getExtension("vet.vet");
        assert.ok(ext, "Extension should be installed");
        assert.ok(ext.isActive, "Extension should be active");
    });

    test("restart command is registered", async () => {
        const commands = await vscode.commands.getCommands(true);
        assert.ok(
            commands.includes("vet.restart"),
            "vet.restart command should be registered",
        );
    });

    test("verifySecret command is registered", async () => {
        const commands = await vscode.commands.getCommands(true);
        const vetCommands = commands.filter((c) => c.startsWith("vet."));
        console.log("Registered vet commands:", vetCommands);
        assert.ok(
            commands.includes("vet.verifySecret"),
            `vet.verifySecret command should be registered. Found vet commands: ${vetCommands.join(", ")}`,
        );
    });

    test("ignoreInConfig command is registered", async () => {
        const commands = await vscode.commands.getCommands(true);
        assert.ok(
            commands.includes("vet.ignoreInConfig"),
            "vet.ignoreInConfig command should be registered",
        );
    });

    test("detects secrets in file", async () => {
        const docPath = path.join(fixturesPath, "has-secret.ts");
        const doc = await vscode.workspace.openTextDocument(docPath);
        await vscode.window.showTextDocument(doc);

        const diagnostics = await waitForDiagnostics(doc.uri, 10000);

        assert.ok(diagnostics.length > 0, "Should detect at least one secret");

        await vscode.commands.executeCommand("workbench.action.closeActiveEditor");
    });

    test("clean file has no diagnostics", async () => {
        const docPath = path.join(fixturesPath, "clean-file.ts");
        const doc = await vscode.workspace.openTextDocument(docPath);
        await vscode.window.showTextDocument(doc);

        // Give time for scanning
        await sleep(2000);

        const diagnostics = vscode.languages.getDiagnostics(doc.uri);
        assert.strictEqual(
            diagnostics.length,
            0,
            "Clean file should have no diagnostics",
        );

        await vscode.commands.executeCommand("workbench.action.closeActiveEditor");
    });
});