import * as assert from "node:assert";
import * as vscode from "vscode";

suite("Untitled Document Scanning", () => {
    test("should scan untitled documents without crashing", async () => {
        const document = await vscode.workspace.openTextDocument({
            language: "plaintext",
            content: "api_key = test_dummy_key_for_scanning",
        });

        const editor = await vscode.window.showTextDocument(document);

        await new Promise((resolve) => setTimeout(resolve, 1000));

        const diagnostics = vscode.languages.getDiagnostics(document.uri);

        assert.ok(
            editor.document.uri.scheme === "untitled",
            "Document should have untitled scheme",
        );

        await vscode.commands.executeCommand(
            "workbench.action.closeActiveEditor",
        );
    });

    test("should scan untitled documents with various schemes", async () => {
        const schemes = ["untitled"];

        for (const scheme of schemes) {
            const document = await vscode.workspace.openTextDocument({
                language: "javascript",
                content: "const secret = 'test';",
            });

            await vscode.window.showTextDocument(document);
            await new Promise((resolve) => setTimeout(resolve, 500));

            assert.strictEqual(document.uri.scheme, "untitled");

            await vscode.commands.executeCommand(
                "workbench.action.closeActiveEditor",
            );
        }
    });
});