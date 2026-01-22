import { type Disposable, commands } from "vscode";
import type { VetClient } from "../client/VetClient";

export function createRestartCommand(client: VetClient): Disposable {
    return commands.registerCommand("vet.restart", async () => {
        await client.restart();
    });
}