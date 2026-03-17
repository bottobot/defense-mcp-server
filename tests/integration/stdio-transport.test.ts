/**
 * Integration test: stdio transport end-to-end JSON-RPC message flow.
 *
 * Spawns the actual compiled server and communicates via JSON-RPC over stdio.
 * Requires `npm run build` before running.
 *
 * Run with: npm run test:integration
 */

import { describe, it, expect, afterAll } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import { join } from "node:path";

describe("stdio transport integration", () => {
  let server: ChildProcess;
  const responses: string[] = [];

  function sendJsonRpc(
    method: string,
    params: Record<string, unknown>,
    id: number,
  ): void {
    const msg = JSON.stringify({ jsonrpc: "2.0", method, params, id });
    server.stdin!.write(msg + "\n");
  }

  function waitForResponse(
    id: number,
    timeoutMs = 10000,
  ): Promise<Record<string, unknown>> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`Timeout waiting for response ${id}`)),
        timeoutMs,
      );

      const check = () => {
        for (const raw of responses) {
          try {
            const parsed = JSON.parse(raw);
            if (parsed.id === id) {
              clearTimeout(timer);
              resolve(parsed);
              return;
            }
          } catch {
            /* not JSON yet */
          }
        }
        setTimeout(check, 100);
      };
      check();
    });
  }

  it("should start and respond to initialize", async () => {
    server = spawn(
      "node",
      [join(__dirname, "../../build/index.js")],
      {
        stdio: ["pipe", "pipe", "pipe"],
        env: {
          ...process.env,
          DEFENSE_MCP_DRY_RUN: "true",
          DEFENSE_MCP_AUTO_INSTALL: "false",
        },
      },
    );

    let stdout = "";
    server.stdout!.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
      // Split by newlines to get individual JSON-RPC messages
      const lines = stdout.split("\n");
      stdout = lines.pop()!; // Keep incomplete line
      responses.push(...lines.filter((l) => l.trim()));
    });

    // Wait for server to start (it logs to stderr)
    await new Promise((resolve) => setTimeout(resolve, 3000));

    // Send initialize
    sendJsonRpc(
      "initialize",
      {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "test-client", version: "1.0.0" },
      },
      1,
    );

    const initResponse = await waitForResponse(1);
    expect(initResponse.result).toBeDefined();
    expect(
      (initResponse.result as Record<string, unknown>).serverInfo,
    ).toBeDefined();
    expect(
      (
        (initResponse.result as Record<string, unknown>)
          .serverInfo as Record<string, unknown>
      ).name,
    ).toBe("defense-mcp-server");
  }, 15000);

  afterAll(() => {
    if (server) {
      server.kill("SIGTERM");
    }
  });
});
