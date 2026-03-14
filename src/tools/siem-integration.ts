// Legacy re-export stub — logic merged into logging.ts (tool consolidation)
// Registered as "siem_log_management" to avoid collision with the canonical "log_management" tool
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerLoggingTools } from "./logging.js";
export { validateSiemHost } from "./logging.js";

export function registerSiemIntegrationTools(server: McpServer): void {
  // Proxy server.tool() to rename "log_management" → "siem_log_management",
  // preventing a duplicate-tool-name error when both logging.ts and
  // siem-integration.ts are registered in index.ts.
  const proxy = new Proxy(server, {
    get(target, prop, receiver) {
      if (prop === "tool") {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        return (name: string, ...rest: any[]) =>
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          (target.tool as (...args: any[]) => unknown)(
            name === "log_management" ? "siem_log_management" : name,
            ...rest
          );
      }
      return Reflect.get(target, prop, receiver);
    },
  });
  registerLoggingTools(proxy);
}
