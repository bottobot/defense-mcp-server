// Legacy re-export stub — logic merged into integrity.ts (tool consolidation)
// Registered as "drift_integrity_check" to avoid collision with the canonical "integrity" tool
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerIntegrityTools } from "./integrity.js";

export function registerDriftDetectionTools(server: McpServer): void {
  // Proxy server.tool() to rename "integrity" → "drift_integrity_check",
  // preventing a duplicate-tool-name error when both integrity.ts and
  // drift-detection.ts are registered in index.ts.
  const proxy = new Proxy(server, {
    get(target, prop, receiver) {
      if (prop === "tool") {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        return (name: string, ...rest: any[]) =>
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          (target.tool as (...args: any[]) => unknown)(
            name === "integrity" ? "drift_integrity_check" : name,
            ...rest
          );
      }
      return Reflect.get(target, prop, receiver);
    },
  });
  registerIntegrityTools(proxy);
}
