/**
 * tool-wrapper.ts — Middleware that intercepts `server.tool()` registrations
 * to inject pre-flight validation before tool handlers execute.
 *
 * This is the critical integration piece of the pre-flight validation system.
 * It creates a {@link Proxy} around {@link McpServer} that wraps every tool
 * handler with pre-flight checks while remaining transparent to the 29
 * existing tool registration files.
 *
 * ## Usage
 *
 * ```typescript
 * import { createPreflightServer } from './core/tool-wrapper.js';
 *
 * const rawServer = new McpServer({ name: '...', version: '...' });
 * const server = createPreflightServer(rawServer);
 *
 * registerFirewallTools(server);      // tools register on the proxy
 * await rawServer.connect(transport); // connect uses the real server
 * ```
 *
 * @module tool-wrapper
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { PreflightEngine, type PreflightResult } from "./preflight.js";
import { ToolRegistry } from "./tool-registry.js";
import { PrivilegeManager } from "./privilege-manager.js";
import { SudoGuard } from "./sudo-guard.js";
import { RateLimiter } from "./rate-limiter.js";

// ── Constants ────────────────────────────────────────────────────────────────

/**
 * Tools that always skip pre-flight because they manage the sudo session
 * itself.  These are checked before manifest lookup for reliability.
 */
const DEFAULT_BYPASS_TOOLS = new Set<string>([
  "sudo_session",
]);

// ── Types ────────────────────────────────────────────────────────────────────

/** Options for the pre-flight wrapper. */
export interface WrapperOptions {
  /** Additional tool names to bypass pre-flight. */
  additionalBypass?: string[];
  /**
   * Enable/disable pre-flight globally.
   * @default `true` (unless `DEFENSE_MCP_PREFLIGHT=false`)
   */
  enabled?: boolean;
  /**
   * Prepend status banners to successful responses that have warnings
   * or auto-installed dependencies.
   * @default `true` (unless `DEFENSE_MCP_PREFLIGHT_BANNERS=false`)
   */
  prependBanners?: boolean;
}

/** Internal context threaded through to the wrapped tool method. */
interface WrappedToolContext {
  enabled: boolean;
  prependBanners: boolean;
  bypassSet: Set<string>;
  preflightEngine: PreflightEngine;
  registry: ToolRegistry;
  /** CICD-024: Rate limiter for tool invocations */
  rateLimiter: RateLimiter;
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Create a proxied {@link McpServer} that wraps every `.tool()` registration
 * with pre-flight validation.
 *
 * The proxy intercepts only the `tool` property; all other methods and
 * properties pass through to the underlying server unchanged.  Tool handlers
 * registered through the proxy will:
 *
 * 1. Check if the tool is in the bypass list (sudo management tools)
 * 2. Run the {@link PreflightEngine} pipeline (dependencies + privileges)
 * 3. If pre-flight **fails**, return an actionable MCP error without calling
 *    the original handler
 * 4. If pre-flight **passes with warnings**, optionally prepend a status
 *    banner to the tool's response
 * 5. If pre-flight **passes cleanly**, call the original handler directly
 *
 * @param server  The original `McpServer` instance
 * @param options Configuration overrides
 * @returns A proxied `McpServer` — callers don't need to change their types
 */
export function createPreflightServer(
  server: McpServer,
  options: WrapperOptions = {},
): McpServer {
  const {
    enabled = process.env.DEFENSE_MCP_PREFLIGHT !== "false",
    prependBanners = process.env.DEFENSE_MCP_PREFLIGHT_BANNERS !== "false",
    additionalBypass = [],
  } = options;

  // Short-circuit: if disabled globally, return the raw server untouched
  if (!enabled) {
    console.error(
      "[preflight] Pre-flight validation DISABLED (DEFENSE_MCP_PREFLIGHT=false)",
    );
    return server;
  }

  const bypassSet = new Set([
    ...DEFAULT_BYPASS_TOOLS,
    ...additionalBypass,
  ]);

  // Eagerly initialise singletons so they're ready when tools register
  const preflightEngine = PreflightEngine.instance();
  const registry = ToolRegistry.instance();
  // CICD-024: Rate limiter — configurable via env vars
  const rateLimiter = RateLimiter.instance();

  const ctx: WrappedToolContext = {
    enabled,
    prependBanners,
    bypassSet,
    preflightEngine,
    registry,
    rateLimiter,
  };

  console.error(
    "[preflight] Pre-flight validation enabled — wrapping server.tool()",
  );

  // The Proxy intercepts property access on the server.  Only the `tool`
  // property is replaced; everything else (connect, resource, prompt, …)
  // passes through via Reflect.get.
  return new Proxy(server, {
    get(target: McpServer, prop: string | symbol, receiver: unknown) {
      if (prop === "tool") {
        return createWrappedToolMethod(target, ctx);
      }
      return Reflect.get(target, prop, receiver);
    },
  });
}

/**
 * Invalidate all pre-flight caches.
 *
 * Call this after events that change the system state, such as:
 * - `sudo_elevate` (privilege level changed)
 * - `sudo_drop` (privilege level changed)
 * - Successful dependency installation
 *
 * Typically called from `sudo-management.ts` tool handlers.
 */
export function invalidatePreflightCaches(): void {
  PreflightEngine.instance().clearCache();
  PrivilegeManager.instance().clearCache();
}

// ── Internals ────────────────────────────────────────────────────────────────

/**
 * Create a replacement `.tool()` method that wraps handlers with pre-flight.
 *
 * The MCP SDK `McpServer.tool()` has 6 overloads with 2–6 arguments.
 * In **all** overloads:
 *   - The **first** argument is always the tool name (`string`)
 *   - The **last** argument is always the handler (`Function`)
 *
 * This invariant lets us handle every overload uniformly:
 *   1. Read `args[0]` as the tool name
 *   2. Read `args[args.length - 1]` as the original handler
 *   3. Replace the handler with a pre-flight-wrapped version
 *   4. Forward all args to the real `server.tool()`
 */
function createWrappedToolMethod(
  server: McpServer,
  ctx: WrappedToolContext,
): (...args: unknown[]) => unknown {
  // Bind to preserve `this` context on the real McpServer
  const originalTool = (server.tool as Function).bind(server) as (
    ...args: unknown[]
  ) => unknown;

  return (...args: unknown[]): unknown => {
    // Sanity: need at least (name, handler)
    if (args.length < 2) {
      return originalTool(...args);
    }

    const toolName = args[0] as string;

    // ── Bypass check ─────────────────────────────────────────────────
    if (shouldBypassPreflight(toolName, ctx)) {
      return originalTool(...args);
    }

    // ── Wrap the handler ─────────────────────────────────────────────
    const originalHandler = args[args.length - 1] as (
      ...cbArgs: unknown[]
    ) => unknown;

    const wrappedHandler = createWrappedHandler(
      toolName,
      originalHandler,
      ctx,
    );

    // Reconstruct args with the wrapped handler in the last position
    const wrappedArgs = [...args];
    wrappedArgs[wrappedArgs.length - 1] = wrappedHandler;

    return originalTool(...wrappedArgs);
  };
}

/**
 * Create a wrapped handler that runs pre-flight before the original handler.
 *
 * **Error safety**: if the pre-flight engine itself throws an unexpected
 * error, we log to stderr and fall through to the original handler.
 * Pre-flight failures must **never** prevent a tool from running when
 * pre-flight is broken — only when pre-flight correctly identifies a
 * blocking issue (missing binary, missing sudo session, etc.).
 *
 * **Sudo elevation prompts**: When a tool fails due to missing privileges
 * (either at pre-flight or at runtime), the wrapper returns a structured
 * elevation prompt via {@link SudoGuard} instead of a generic error.
 * This ensures the AI client always knows to ask the user for their
 * password and call `sudo_elevate`.
 */
function createWrappedHandler(
  toolName: string,
  originalHandler: (...cbArgs: unknown[]) => unknown,
  ctx: WrappedToolContext,
): (...cbArgs: unknown[]) => Promise<unknown> {
  return async (...callbackArgs: unknown[]): Promise<unknown> => {
    // Extract params from callback args for safeguard checks.
    // MCP SDK tool handler signature: (params, extra) — params is always first.
    const toolParams =
      callbackArgs.length > 0 &&
      callbackArgs[0] != null &&
      typeof callbackArgs[0] === "object" &&
      !Array.isArray(callbackArgs[0])
        ? (callbackArgs[0] as Record<string, unknown>)
        : undefined;

    // ── CICD-024: Rate limit check ─────────────────────────────────────
    const rateLimitResult = ctx.rateLimiter.check(toolName);
    if (!rateLimitResult.allowed) {
      console.error(
        `[rate-limiter] Tool '${toolName}' rejected: ${rateLimitResult.reason}`,
      );
      return {
        content: [
          {
            type: "text" as const,
            text: `⚠ Rate limit exceeded\n\n${rateLimitResult.reason}`,
          },
        ],
        isError: true,
      };
    }

    // ── Run pre-flight with error safety ─────────────────────────────
    try {
      const result = await ctx.preflightEngine.runPreflight(
        toolName,
        toolParams,
      );

      if (!result.passed) {
        // ── Check if failure is sudo-related → return elevation prompt ──
        const hasSudoIssue = result.privileges.issues.some(
          (i) =>
            i.type === "sudo-required" ||
            i.type === "sudo-unavailable" ||
            i.type === "session-expired",
        );

        if (hasSudoIssue) {
          // Extract the sudo reason from the manifest or the first issue
          const manifest = ctx.registry.getManifest(toolName);
          const reason =
            manifest?.sudoReason ??
            result.privileges.issues[0]?.description;

          console.error(
            `[sudo-guard] Tool '${toolName}' requires elevation — returning prompt`,
          );
          return SudoGuard.createElevationPrompt(
            toolName,
            reason,
            ctx.preflightEngine.formatSummary(result),
          );
        }

        // Non-sudo failure — return the standard pre-flight error
        return {
          content: [
            {
              type: "text" as const,
              text: ctx.preflightEngine.formatSummary(result),
            },
          ],
          isError: true,
        };
      }

      // Pre-flight PASSED — call the original handler
      const toolResult = (await originalHandler(
        ...callbackArgs,
      )) as Record<string, unknown> | undefined;

      // ── Post-execution: Check for runtime permission errors ────────
      // This catches `conditional` sudo tools and edge cases where
      // pre-flight passed but the command still failed due to permissions.
      if (
        toolResult &&
        SudoGuard.isResponsePermissionError(toolResult)
      ) {
        const manifest = ctx.registry.getManifest(toolName);
        const reason =
          manifest?.sudoReason ??
          "The command failed due to insufficient privileges at runtime.";
        const originalText = SudoGuard.extractResponseText(toolResult);

        console.error(
          `[sudo-guard] Runtime permission error detected for '${toolName}' — returning elevation prompt`,
        );
        return SudoGuard.createElevationPrompt(
          toolName,
          reason,
          originalText,
        );
      }

      // Optionally prepend a status banner when there are notable items
      // (warnings about optional deps, auto-installed binaries, etc.)
      if (
        ctx.prependBanners &&
        hasNotableInfo(result) &&
        toolResult?.content &&
        Array.isArray(toolResult.content)
      ) {
        const statusMsg =
          ctx.preflightEngine.formatStatusMessage(result);
        if (statusMsg) {
          return {
            ...toolResult,
            content: [
              { type: "text" as const, text: statusMsg },
              ...(toolResult.content as unknown[]),
            ],
          };
        }
      }

      return toolResult;
    } catch (err) {
      // Pre-flight itself threw — log and fall through to original handler
      console.error(
        `[preflight] ⚠ Pre-flight failed unexpectedly for '${toolName}': ${
          err instanceof Error ? err.message : String(err)
        }`,
      );

      const toolResult = (await originalHandler(
        ...callbackArgs,
      )) as Record<string, unknown> | undefined;

      // Even when pre-flight is broken, still check for runtime permission errors
      if (
        toolResult &&
        SudoGuard.isResponsePermissionError(toolResult)
      ) {
        const manifest = ctx.registry.getManifest(toolName);
        const reason =
          manifest?.sudoReason ??
          "The command failed due to insufficient privileges.";
        const originalText = SudoGuard.extractResponseText(toolResult);

        console.error(
          `[sudo-guard] Runtime permission error detected for '${toolName}' (post-preflight-failure) — returning elevation prompt`,
        );
        return SudoGuard.createElevationPrompt(
          toolName,
          reason,
          originalText,
        );
      }

      return toolResult;
    }
  };
}

/**
 * Determine whether a tool should bypass pre-flight entirely.
 *
 * A tool bypasses pre-flight if:
 * 1. It's in the static {@link DEFAULT_BYPASS_TOOLS} set, OR
 * 2. Its manifest in the {@link ToolRegistry} has the `bypass-preflight` tag
 */
function shouldBypassPreflight(
  toolName: string,
  ctx: WrappedToolContext,
): boolean {
  // Fast-path: static bypass set
  if (ctx.bypassSet.has(toolName)) return true;

  // Check manifest tags (secondary defence — covers tools registered
  // in the registry with the tag but not in the static set)
  const manifest = ctx.registry.getManifest(toolName);
  if (manifest?.tags?.includes("bypass-preflight")) return true;

  return false;
}

/**
 * Check whether a passing {@link PreflightResult} has information worth
 * prepending to the tool output (warnings or auto-installed dependencies).
 *
 * When the result is clean (no warnings, no installs), returns `false`
 * so the tool's output is returned unmodified.
 */
function hasNotableInfo(result: PreflightResult): boolean {
  return (
    result.warnings.length > 0 ||
    result.dependencies.installed.length > 0
  );
}
