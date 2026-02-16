import { describe, it, expect, vi, beforeEach } from "vitest";
import { commands, window } from "vscode";
import { createVerifySecretCommand } from "../../../src/commands/verifySecret";

describe("createVerifySecretCommand", () => {
	let mockClient: {
		executeCommand: ReturnType<typeof vi.fn>;
	};
	let registeredCallback: (args: {
		findingId: string;
		patternId: string;
		uri: string;
	}) => Promise<void>;

	beforeEach(() => {
		vi.clearAllMocks();

		mockClient = {
			executeCommand: vi.fn().mockResolvedValue(null),
		};

		vi.mocked(commands.registerCommand).mockImplementation(
			(_command: string, callback: unknown) => {
				registeredCallback = callback as typeof registeredCallback;
				return { dispose: vi.fn() };
			},
		);
	});

	it("registers the vet.verifySecret command", () => {
		createVerifySecretCommand(mockClient as never);

		expect(commands.registerCommand).toHaveBeenCalledWith(
			"vet.verifySecret",
			expect.any(Function),
		);
	});

	it("returns a disposable", () => {
		const disposable = createVerifySecretCommand(mockClient as never);

		expect(disposable).toHaveProperty("dispose");
	});

	it("shows progress notification during verification", async () => {
		createVerifySecretCommand(mockClient as never);

		await registeredCallback({
			findingId: "test-id",
			patternId: "vcs/github-pat",
			uri: "file:///test.ts",
		});

		expect(window.withProgress).toHaveBeenCalledWith(
			expect.objectContaining({
				title: "Verifying vcs/github-pat...",
			}),
			expect.any(Function),
		);
	});

	it("calls client.executeCommand with correct arguments", async () => {
		createVerifySecretCommand(mockClient as never);

		const args = {
			findingId: "test-id",
			patternId: "vcs/github-pat",
			uri: "file:///test.ts",
		};

		await registeredCallback(args);

		expect(mockClient.executeCommand).toHaveBeenCalledWith(
			"vet.verifySecret",
			args,
		);
	});

	it("shows warning message for live secrets", async () => {
		mockClient.executeCommand.mockResolvedValue({
			status: "live",
			service: { provider: "GitHub", details: "user: test" },
		});

		createVerifySecretCommand(mockClient as never);

		await registeredCallback({
			findingId: "test-id",
			patternId: "vcs/github-pat",
			uri: "file:///test.ts",
		});

		expect(window.showErrorMessage).toHaveBeenCalledWith(
			"Secret is live: vcs/github-pat - user: test",
		);
	});

	it("shows info message for inactive secrets", async () => {
		mockClient.executeCommand.mockResolvedValue({
			status: "inactive",
			service: { provider: "GitHub", details: "key revoked" },
		});

		createVerifySecretCommand(mockClient as never);

		await registeredCallback({
			findingId: "test-id",
			patternId: "vcs/github-pat",
			uri: "file:///test.ts",
		});

		expect(window.showInformationMessage).toHaveBeenCalledWith(
			"Secret is inactive: vcs/github-pat - key revoked",
		);
	});

	it("shows info message for inconclusive results with details", async () => {
		mockClient.executeCommand.mockResolvedValue({
			status: "inconclusive",
			service: { provider: "GitHub", details: "rate limited" },
		});

		createVerifySecretCommand(mockClient as never);

		await registeredCallback({
			findingId: "test-id",
			patternId: "vcs/github-pat",
			uri: "file:///test.ts",
		});

		expect(window.showInformationMessage).toHaveBeenCalledWith(
			"Verification inconclusive: vcs/github-pat - rate limited",
		);
	});

	it("shows info message for inconclusive results without details", async () => {
		mockClient.executeCommand.mockResolvedValue({
			status: "inconclusive",
		});

		createVerifySecretCommand(mockClient as never);

		await registeredCallback({
			findingId: "test-id",
			patternId: "vcs/github-pat",
			uri: "file:///test.ts",
		});

		expect(window.showInformationMessage).toHaveBeenCalledWith(
			"Verification inconclusive: vcs/github-pat",
		);
	});

	it("shows message without details when service is missing", async () => {
		mockClient.executeCommand.mockResolvedValue({
			status: "live",
		});

		createVerifySecretCommand(mockClient as never);

		await registeredCallback({
			findingId: "test-id",
			patternId: "vcs/github-pat",
			uri: "file:///test.ts",
		});

		expect(window.showErrorMessage).toHaveBeenCalledWith(
			"Secret is live: vcs/github-pat",
		);
	});

	it("does nothing when result is null", async () => {
		mockClient.executeCommand.mockResolvedValue(null);

		createVerifySecretCommand(mockClient as never);

		await registeredCallback({
			findingId: "test-id",
			patternId: "vcs/github-pat",
			uri: "file:///test.ts",
		});

		expect(window.showErrorMessage).not.toHaveBeenCalled();
		expect(window.showInformationMessage).not.toHaveBeenCalled();
	});

	it("shows error message when verification fails", async () => {
		mockClient.executeCommand.mockRejectedValue(new Error("Network error"));

		createVerifySecretCommand(mockClient as never);

		await registeredCallback({
			findingId: "test-id",
			patternId: "vcs/github-pat",
			uri: "file:///test.ts",
		});

		expect(window.showErrorMessage).toHaveBeenCalledWith(
			"Verification failed: Network error",
		);
	});

	it("handles non-Error rejection", async () => {
		mockClient.executeCommand.mockRejectedValue("string error");

		createVerifySecretCommand(mockClient as never);

		await registeredCallback({
			findingId: "test-id",
			patternId: "vcs/github-pat",
			uri: "file:///test.ts",
		});

		expect(window.showErrorMessage).toHaveBeenCalledWith(
			"Verification failed: string error",
		);
	});
});
