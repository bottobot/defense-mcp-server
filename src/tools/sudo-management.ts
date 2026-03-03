/**
 * Sudo privilege management tools for Kali Defense MCP Server.
 *
 * Registers 4 tools: sudo_elevate, sudo_status, sudo_drop, sudo_extend.
 *
 * These tools manage a secure in-process sudo session so that the user
 * only needs to provide their password once. All subsequent `sudo`
 * commands executed by other tools transparently receive the cached
 * credentials via stdin piping.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { SudoSession } from "../core/sudo-session.js";
import { getConfig } from "../core/config.js";
import {
  createTextContent,
  createErrorContent,
} from "../core/parsers.js";

// ── Registration entry point ───────────────────────────────────────────────

export function registerSudoManagementTools(server: McpServer): void {

  // ── 1. sudo_elevate ──────────────────────────────────────────────────────

  server.tool(
    "sudo_elevate",
    "Elevate privileges by providing the sudo password once. All subsequent tools that require sudo will use the cached credentials automatically. The password is stored securely in memory and auto-expires after the configured timeout.",
    {
      password: z
        .string()
        .min(1)
        .describe("The user's sudo password. Stored securely in a zeroable buffer and never logged."),
      timeout_minutes: z
        .number()
        .min(1)
        .max(480)
        .optional()
        .default(15)
        .describe("Session timeout in minutes (default: 15, max: 480). Session auto-expires after this duration."),
    },
    async ({ password, timeout_minutes }) => {
      try {
        const session = SudoSession.getInstance();

        // Check if already elevated
        if (session.isElevated()) {
          const status = session.getStatus();
          return {
            content: [
              createTextContent(
                `🔓 Already elevated as '${status.username}'.\n` +
                `Session expires at: ${status.expiresAt ?? "never"}\n` +
                `Remaining: ${status.remainingSeconds !== null ? `${status.remainingSeconds}s` : "∞"}\n\n` +
                `Use sudo_drop to end the current session before re-elevating.`
              ),
            ],
          };
        }

        const timeoutMs = timeout_minutes * 60 * 1000;

        // Apply config-level timeout override if set
        const config = getConfig();
        if (config.sudoSessionTimeout) {
          session.setDefaultTimeout(config.sudoSessionTimeout);
        }

        const result = await session.elevate(password, timeoutMs);

        if (result.success) {
          const status = session.getStatus();
          return {
            content: [
              createTextContent(
                `🔓 Privileges elevated successfully!\n\n` +
                `  User: ${status.username}\n` +
                `  Expires: ${status.expiresAt ?? "never (running as root)"}\n` +
                `  Timeout: ${timeout_minutes} minutes\n\n` +
                `All tools that require sudo will now work automatically.\n` +
                `Use sudo_status to check session state, or sudo_drop to end early.`
              ),
            ],
          };
        }

        return {
          content: [
            createErrorContent(
              `❌ Elevation failed: ${result.error}\n\n` +
              `Please verify:\n` +
              `  1. The password is correct\n` +
              `  2. Your user has sudo privileges (is in the sudoers file)\n` +
              `  3. sudo is installed and configured`
            ),
          ],
          isError: true,
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return {
          content: [createErrorContent(`Elevation error: ${msg}`)],
          isError: true,
        };
      }
    }
  );

  // ── 2. sudo_status ───────────────────────────────────────────────────────

  server.tool(
    "sudo_status",
    "Check the current sudo elevation status, including whether credentials are cached, the authenticated user, and remaining session time.",
    {},
    async () => {
      try {
        const session = SudoSession.getInstance();
        const status = session.getStatus();

        if (!status.elevated) {
          return {
            content: [
              createTextContent(
                `🔒 Not elevated — sudo credentials are not cached.\n\n` +
                `Use sudo_elevate to provide your password and enable\n` +
                `transparent sudo for all defensive security tools.`
              ),
            ],
          };
        }

        const sections: string[] = [];
        sections.push("🔓 Sudo Session Active");
        sections.push("=".repeat(40));
        sections.push(`  User: ${status.username}`);
        sections.push(`  Expires: ${status.expiresAt ?? "never (root)"}`);

        if (status.remainingSeconds !== null) {
          const mins = Math.floor(status.remainingSeconds / 60);
          const secs = status.remainingSeconds % 60;
          sections.push(`  Remaining: ${mins}m ${secs}s`);

          if (status.remainingSeconds < 120) {
            sections.push(`\n  ⚠️ Session expiring soon! Use sudo_elevate to re-authenticate.`);
          }
        } else {
          sections.push(`  Remaining: ∞ (running as root)`);
        }

        return { content: [createTextContent(sections.join("\n"))] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return {
          content: [createErrorContent(`Status check error: ${msg}`)],
          isError: true,
        };
      }
    }
  );

  // ── 3. sudo_drop ─────────────────────────────────────────────────────────

  server.tool(
    "sudo_drop",
    "Drop elevated privileges immediately. Zeroes the cached password from memory and invalidates the sudo session. Subsequent tools requiring sudo will fail until sudo_elevate is called again.",
    {},
    async () => {
      try {
        const session = SudoSession.getInstance();
        const wasElevated = session.isElevated();
        const prevStatus = session.getStatus();

        session.drop();

        if (wasElevated) {
          return {
            content: [
              createTextContent(
                `🔒 Privileges dropped successfully.\n\n` +
                `  Previous user: ${prevStatus.username}\n` +
                `  Password buffer: zeroed\n` +
                `  System sudo cache: invalidated\n\n` +
                `Tools requiring sudo will now fail until sudo_elevate is called again.`
              ),
            ],
          };
        }

        return {
          content: [
            createTextContent(
              `🔒 No active sudo session to drop.\n` +
              `The system is already in an unprivileged state.`
            ),
          ],
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return {
          content: [createErrorContent(`Drop error: ${msg}`)],
          isError: true,
        };
      }
    }
  );

  // ── 4. sudo_extend ────────────────────────────────────────────────────────

  server.tool(
    "sudo_extend",
    "Extend the current sudo session timeout. Resets the expiry timer so you don't have to re-authenticate. Requires an active sudo session (use sudo_elevate first).",
    {
      minutes: z
        .number()
        .min(1)
        .max(480)
        .optional()
        .default(15)
        .describe("Number of minutes to extend the session by (default: 15, max: 480)."),
    },
    async ({ minutes }) => {
      try {
        const session = SudoSession.getInstance();

        if (!session.isElevated()) {
          return {
            content: [
              createErrorContent(
                `🔒 No active sudo session to extend.\n\n` +
                `Use sudo_elevate to provide your password and start a session first.`
              ),
            ],
            isError: true,
          };
        }

        const extraMs = minutes * 60 * 1000;
        const success = session.extend(extraMs);

        if (!success) {
          return {
            content: [
              createErrorContent(
                `Failed to extend sudo session. The session may have expired.\n` +
                `Use sudo_elevate to re-authenticate.`
              ),
            ],
            isError: true,
          };
        }

        const status = session.getStatus();
        return {
          content: [
            createTextContent(
              `🔓 Session extended by ${minutes} minutes.\n\n` +
              `  User: ${status.username}\n` +
              `  New expiry: ${status.expiresAt ?? "never (root)"}\n` +
              `  Remaining: ${status.remainingSeconds !== null ? `${Math.floor(status.remainingSeconds / 60)}m ${status.remainingSeconds % 60}s` : "∞"}`
            ),
          ],
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return {
          content: [createErrorContent(`Extend error: ${msg}`)],
          isError: true,
        };
      }
    }
  );
}
