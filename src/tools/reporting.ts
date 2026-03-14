// Legacy re-export stub — logic merged into meta.ts (tool consolidation)
// Registered as "defense_report_mgmt" to avoid collision with the canonical "defense_mgmt" tool
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerMetaTools } from "./meta.js";

export function registerReportingTools(server: McpServer): void {
  // Proxy server.tool() to rename "defense_mgmt" → "defense_report_mgmt",
  // preventing a duplicate-tool-name error when both meta.ts and
  // reporting.ts are registered in index.ts.
  const proxy = new Proxy(server, {
    get(target, prop, receiver) {
      if (prop === "tool") {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        return (name: string, ...rest: any[]) =>
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          (target.tool as (...args: any[]) => unknown)(
            name === "defense_mgmt" ? "defense_report_mgmt" : name,
            ...rest
          );
      }
      return Reflect.get(target, prop, receiver);
    },
  });
  registerMetaTools(proxy);
}
