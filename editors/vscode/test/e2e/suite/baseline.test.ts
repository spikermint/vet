import * as vscode from "vscode";
import * as assert from "assert";
import * as path from "path";
import * as fs from "fs";

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

async function getCodeActions(
	document: vscode.TextDocument,
	range: vscode.Range,
): Promise<vscode.CodeAction[]> {
	const actions = await vscode.commands.executeCommand<
		(vscode.Command | vscode.CodeAction)[]
	>("vscode.executeCodeActionProvider", document.uri, range);

	return (actions || []).filter(
		(action): action is vscode.CodeAction => "kind" in action,
	);
}

suite("Ignore in Config Feature E2E", () => {
	const fixturesPath = path.resolve(
		__dirname,
		"../../../test/e2e/fixtures/workspace",
	);

	suiteSetup(async () => {
		const ext = vscode.extensions.getExtension("vet.vet");
		if (ext && !ext.isActive) {
			await ext.activate();
		}
		await sleep(3000);
	});

	teardown(async () => {
		// Close all editors
		await vscode.commands.executeCommand("workbench.action.closeAllEditors");
	});

	test("ignoreInConfig command is registered", async () => {
		const commands = await vscode.commands.getCommands(true);
		assert.ok(
			commands.includes("vet.ignoreInConfig"),
			"vet.ignoreInConfig command should be registered",
		);
	});

	test("baseline-test file shows diagnostics", async () => {
		const docPath = path.join(fixturesPath, "baseline-test.ts");
		const doc = await vscode.workspace.openTextDocument(docPath);
		await vscode.window.showTextDocument(doc);

		const diagnostics = await waitForDiagnostics(doc.uri, 10000);

		assert.ok(
			diagnostics.length > 0,
			"Should detect secrets in baseline-test.ts",
		);
		assert.strictEqual(
			diagnostics[0].source,
			"vet",
			"Diagnostic should be from vet",
		);
	});

	test("code action 'Ignore in config' appears for vet diagnostics", async () => {
		const docPath = path.join(fixturesPath, "baseline-test.ts");
		const doc = await vscode.workspace.openTextDocument(docPath);
		await vscode.window.showTextDocument(doc);

		const diagnostics = await waitForDiagnostics(doc.uri, 10000);
		assert.ok(diagnostics.length > 0, "Should have diagnostics");

		const diagnostic = diagnostics[0];
		const actions = await getCodeActions(doc, diagnostic.range);

		const ignoreInConfigAction = actions.find((action) =>
			action.title.includes("Ignore in config"),
		);

		assert.ok(
			ignoreInConfigAction,
			"Should have 'Ignore in config' code action",
		);
		assert.strictEqual(
			ignoreInConfigAction.kind?.value,
			vscode.CodeActionKind.QuickFix.value,
			"Should be a QuickFix code action",
		);
	});

	test("code action has correct command and parameters", async () => {
		const docPath = path.join(fixturesPath, "baseline-test.ts");
		const doc = await vscode.workspace.openTextDocument(docPath);
		await vscode.window.showTextDocument(doc);

		const diagnostics = await waitForDiagnostics(doc.uri, 10000);
		assert.ok(diagnostics.length > 0, "Should have diagnostics");

		const diagnostic = diagnostics[0];
		const actions = await getCodeActions(doc, diagnostic.range);

		const ignoreInConfigAction = actions.find((action) =>
			action.title.includes("Ignore in config"),
		);

		assert.ok(ignoreInConfigAction, "Should have ignore in config action");
		assert.ok(ignoreInConfigAction.command, "Action should have a command");
		assert.strictEqual(
			ignoreInConfigAction.command.command,
			"vet.ignoreInConfig",
			"Command should be vet.ignoreInConfig",
		);

		const args = ignoreInConfigAction.command.arguments;
		assert.ok(args && args.length > 0, "Command should have arguments");

		const params = args[0] as Record<string, unknown>;
		assert.ok(params.fingerprint, "Should have fingerprint");
		assert.ok(params.patternId, "Should have patternId");
		assert.ok(params.uri, "Should have uri");
	});

	test("diagnostic has fingerprint in data", async () => {
		const docPath = path.join(fixturesPath, "baseline-test.ts");
		const doc = await vscode.workspace.openTextDocument(docPath);
		await vscode.window.showTextDocument(doc);

		const diagnostics = await waitForDiagnostics(doc.uri, 10000);
		assert.ok(diagnostics.length > 0, "Should have diagnostics");

		const diagnostic = diagnostics[0];

		// TypeScript doesn't know about the data field, so we need to cast
		const data = (diagnostic as unknown as { data?: Record<string, unknown> })
			.data;

		assert.ok(data, "Diagnostic should have data field");
		assert.ok(data.fingerprint, "Data should have fingerprint");
		assert.ok(
			typeof data.fingerprint === "string",
			"Fingerprint should be a string",
		);
		assert.ok(
			(data.fingerprint as string).startsWith("sha256:"),
			"Fingerprint should start with sha256:",
		);
	});

	test("multiple code actions appear for single diagnostic", async () => {
		const docPath = path.join(fixturesPath, "baseline-test.ts");
		const doc = await vscode.workspace.openTextDocument(docPath);
		await vscode.window.showTextDocument(doc);

		const diagnostics = await waitForDiagnostics(doc.uri, 10000);
		assert.ok(diagnostics.length > 0, "Should have diagnostics");

		const diagnostic = diagnostics[0];
		const actions = await getCodeActions(doc, diagnostic.range);

		// Should have both "Ignore on this line" and "Ignore in config" actions
		const ignoreLineAction = actions.find((action) =>
			action.title.includes("on this line"),
		);
		const ignoreInConfigAction = actions.find((action) =>
			action.title.includes("Ignore in config"),
		);

		assert.ok(ignoreLineAction, "Should have ignore on line action");
		assert.ok(ignoreInConfigAction, "Should have ignore in config action");
		assert.ok(
			actions.length >= 2,
			"Should have at least 2 code actions available",
		);
	});

	test("fingerprint format is correct", async () => {
		const docPath = path.join(fixturesPath, "baseline-test.ts");
		const doc = await vscode.workspace.openTextDocument(docPath);
		await vscode.window.showTextDocument(doc);

		const diagnostics = await waitForDiagnostics(doc.uri, 10000);
		assert.ok(diagnostics.length > 0, "Should have diagnostics");

		const diagnostic = diagnostics[0];
		const data = (diagnostic as unknown as { data?: Record<string, unknown> })
			.data;

		assert.ok(data?.fingerprint, "Should have fingerprint");
		const fingerprint = data.fingerprint as string;

		// Fingerprint should be sha256:xxxx (71 chars total: 7 + 64)
		assert.strictEqual(
			fingerprint.length,
			71,
			"Fingerprint should be 71 characters (sha256: + 64 hex chars)",
		);
		assert.ok(
			/^sha256:[0-9a-f]{64}$/.test(fingerprint),
			"Fingerprint should match pattern sha256:[64 hex chars]",
		);
	});

	test("different files produce different fingerprints for same secret", async () => {
		// Create a temporary second file with the same secret
		const secondFilePath = path.join(fixturesPath, "baseline-test-2.ts");
		const originalContent = fs.readFileSync(
			path.join(fixturesPath, "baseline-test.ts"),
			"utf8",
		);
		fs.writeFileSync(secondFilePath, originalContent);

		try {
			const doc1Path = path.join(fixturesPath, "baseline-test.ts");
			const doc1 = await vscode.workspace.openTextDocument(doc1Path);
			await vscode.window.showTextDocument(doc1);

			const diagnostics1 = await waitForDiagnostics(doc1.uri, 10000);
			assert.ok(diagnostics1.length > 0, "Should have diagnostics in file 1");

			await vscode.commands.executeCommand(
				"workbench.action.closeActiveEditor",
			);

			const doc2 = await vscode.workspace.openTextDocument(secondFilePath);
			await vscode.window.showTextDocument(doc2);

			const diagnostics2 = await waitForDiagnostics(doc2.uri, 10000);
			assert.ok(diagnostics2.length > 0, "Should have diagnostics in file 2");

			const data1 = (
				diagnostics1[0] as unknown as { data?: Record<string, unknown> }
			).data;
			const data2 = (
				diagnostics2[0] as unknown as { data?: Record<string, unknown> }
			).data;

			assert.ok(data1?.fingerprint, "File 1 should have fingerprint");
			assert.ok(data2?.fingerprint, "File 2 should have fingerprint");

			// Fingerprints should be different (different file paths)
			assert.notStrictEqual(
				data1.fingerprint,
				data2.fingerprint,
				"Different files should produce different fingerprints for same secret",
			);
		} finally {
			// Clean up temporary file
			if (fs.existsSync(secondFilePath)) {
				fs.unlinkSync(secondFilePath);
			}
		}
	});
});
