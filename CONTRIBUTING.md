# Contributing to defense-mcp-server

Thank you for your interest in contributing to the Defense MCP Server. This guide covers the conventions, patterns, and workflows you need to follow.

---

## Project Overview

MCP (Model Context Protocol) server providing **31 action-based** Linux security tools. TypeScript, ESM (`"type": "module"`), Node 18/20/22, Linux only.

**Runtime dependencies**: Only 2 — `@modelcontextprotocol/sdk` and `zod`. Everything else is a devDependency.

---

## Development Setup

```bash
git clone https://github.com/<org>/defense-mcp-server.git
cd defense-mcp-server
npm install
npm run build   # tsc → dist/
npm test        # Vitest
```

---

## Critical Rules

1. **Never use `console.log`** — stdout is the MCP stdio transport. Use `console.error` for debug logging.
2. **All imports must use `.js` extensions** — ESM Node16 resolution requires it even for `.ts` source files.
3. **`child_process` imports are ESLint-blocked** except in `executor.ts`, `spawn-safe.ts`, `command-allowlist.ts`. Use `executeCommand()` or `spawnSafe()` instead.
4. **Dry-run defaults to `true`** — tools must check `params.dry_run ?? getConfig().dryRun` before mutating.
5. **`shell: false` always** — enforced in both `executor.ts` and `spawn-safe.ts`.
6. **Config is cached 5 seconds** — call `invalidateConfigCache()` in tests after changing env vars.

---

## Adding a New Tool

Follow these 6 steps in order:

### Step 1: Create the tool file

Create `src/tools/my-tool.ts` exporting a `registerMyToolTools(server)` function using the **action-based pattern**:

```typescript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { createTextContent, createErrorContent } from "../core/parsers.js";
import { logChange, createChangeEntry } from "../core/changelog.js";
import { getConfig } from "../core/config.js";
import { validateFilePath, sanitizeArgs } from "../core/sanitizer.js";

export function registerMyToolTools(server: McpServer): void {
  server.tool(
    "my_tool",
    "Description of the tool",
    {
      action: z.enum(["action_one", "action_two"]).describe("Action to perform"),
      target: z.string().optional().describe("Target path or identifier"),
      dry_run: z.boolean().optional().default(true).describe("Dry-run mode"),
    },
    async (params) => {
      try {
        const config = getConfig();
        const isDryRun = params.dry_run ?? config.dryRun;

        // Validate inputs
        if (params.target) validateFilePath(params.target);

        // Dry-run check
        if (isDryRun) {
          return { content: [createTextContent(`[DRY RUN] Would perform ${params.action}`)] };
        }

        // Execute
        const result = await executeCommand({
          command: "my-binary",
          args: sanitizeArgs(["--flag", params.target ?? ""]),
          toolName: "my_tool",
        });

        // Log change
        logChange(createChangeEntry({
          tool: "my_tool",
          action: params.action,
          target: params.target ?? "system",
          dryRun: false,
          success: result.exitCode === 0,
        }));

        return { content: [createTextContent(result.stdout)] };
      } catch (error) {
        return {
          content: [createErrorContent(error instanceof Error ? error.message : String(error))],
          isError: true,
        };
      }
    },
  );
}
```

**Key pattern**: One tool per file with an `action` parameter using `z.enum([...])`. Do **not** create many small tools.

### Step 2: Declare dependencies

Add to `src/core/tool-dependencies.ts` — the `TOOL_DEPENDENCIES` array:

```typescript
{
  toolName: "my_tool",
  requiredBinaries: ["my-binary"],
  optionalBinaries: ["my-optional-binary"],
}
```

### Step 3: Add sudo overlay

Add to `src/core/tool-registry.ts` — the `SUDO_OVERLAYS` map:

```typescript
"my_tool": { needed: true, reason: "Requires root for system access", degradable: false },
```

### Step 4: Add binaries to the command allowlist

Add to `src/core/command-allowlist.ts` — the `ALLOWLIST_DEFINITIONS` array:

```typescript
{ name: "my-binary", candidatePaths: ["/usr/bin/my-binary", "/usr/sbin/my-binary"] },
```

### Step 5: Register in index.ts

Add to `src/index.ts` via `safeRegister()`:

```typescript
import { registerMyToolTools } from "./tools/my-tool.js";

// In the registration section:
safeRegister("my-tool", () => registerMyToolTools(wrappedServer));
```

### Step 6: Create tests

Create `tests/tools/my-tool.test.ts` using the mock server pattern:

```typescript
import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock all external dependencies BEFORE imports
vi.mock("../../src/core/executor.js", () => ({
  executeCommand: vi.fn(),
}));
vi.mock("../../src/core/config.js", () => ({
  getConfig: vi.fn(() => ({ dryRun: true })),
  invalidateConfigCache: vi.fn(),
}));
// ... mock other deps

import { registerMyToolTools } from "../../src/tools/my-tool.js";

function createMockServer() {
  const tools = new Map<string, { schema: unknown; handler: Function }>();
  return {
    tool: vi.fn((name: string, _desc: string, schema: unknown, handler: Function) => {
      tools.set(name, { schema, handler });
    }),
    getHandler: (name: string) => tools.get(name)?.handler,
    tools,
  };
}

describe("my_tool", () => {
  let server: ReturnType<typeof createMockServer>;
  let handler: Function;

  beforeEach(() => {
    vi.clearAllMocks();
    server = createMockServer();
    registerMyToolTools(server as any);
    handler = server.getHandler("my_tool")!;
  });

  it("registers the tool", () => {
    expect(server.tools.has("my_tool")).toBe(true);
  });

  it("returns dry-run output", async () => {
    const result = await handler({ action: "action_one", dry_run: true });
    expect(result.content[0].text).toContain("DRY RUN");
    expect(result.isError).toBeUndefined();
  });
});
```

---

## Tool Return Convention

All tools must return the standard MCP response format:

```typescript
// Success
{ content: [{ type: "text", text: "..." }] }

// Error
{ content: [{ type: "text", text: "Error: ..." }], isError: true }
```

Use `createTextContent()`, `createErrorContent()`, and `formatToolOutput()` from `parsers.ts`.

---

## Security Checklist

Before submitting a tool, verify:

- [ ] `executeCommand()` used with `toolName` parameter (rate limiting key)
- [ ] `validateFilePath()` / `validateToolPath()` called on all path inputs
- [ ] `sanitizeArgs()` called on all argument arrays
- [ ] `params.dry_run ?? getConfig().dryRun` checked before any mutation
- [ ] `logChange(createChangeEntry({...}))` called for every action
- [ ] `backupFile()` called before any system file modification
- [ ] No `child_process` imports (use `executeCommand()` / `spawnSafe()`)
- [ ] No `console.log` (use `console.error` for debug output)
- [ ] All imports use `.js` extensions
- [ ] Error responses use `sanitizeToolError()` to strip paths/stacks

---

## PAM File Safety

If your tool modifies PAM configuration files (`/etc/pam.d/*`):

- **Never use `sed`** — use `parsePamConfig()` / `serializePamConfig()` from `pam-utils.ts`
- Pre-write: `validatePamConfig()` (syntax) + `validatePamPolicySanity()` (policy)
- `writePamFile()` handles post-write verification automatically
- Use `backupPamFile()` / `restorePamFile()` for rollback
- Respect `PAM_SANITY_THRESHOLDS` constants

---

## Testing

| Command | Description |
|---------|-------------|
| `npm test` | Run all unit tests (Vitest) |
| `npm test -- tests/tools/my-tool.test.ts` | Run a single test file |
| `npm run build` | TypeScript compilation to `dist/` |
| `npm run lint:security` | ESLint security plugin only |
| `npm run test:integration` | Build + integration tests |

### Testing Conventions

- All external deps mocked via `vi.mock()` **before** imports — no real commands execute
- Mock server pattern: `createMockServer()` captures `.tool()` registrations, call handlers directly
- Mirror structure: `src/tools/foo.ts` → `tests/tools/foo.test.ts`
- Coverage targets: 70% lines/functions/statements, 60% branches
- `src/index.ts` is excluded from coverage

---

## Architecture

For detailed architecture documentation, see:

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — full system architecture including pre-flight validation
- [`docs/TOOLS-REFERENCE.md`](docs/TOOLS-REFERENCE.md) — complete tool reference (source of truth for tool counts)
- [`docs/SAFEGUARDS.md`](docs/SAFEGUARDS.md) — safeguards, rollback, and PAM safety
- [`docs/SPECIFICATION.md`](docs/SPECIFICATION.md) — server specification
- [`docs/STANDARDS.md`](docs/STANDARDS.md) — compliance standards mapping
- [`AGENTS.md`](AGENTS.md) — agent-facing coding rules and conventions

### Key Architectural Patterns

- **Action-based tools**: One tool per file with `z.enum([...])` action parameter
- **Pre-flight validation**: `createPreflightServer()` in `tool-wrapper.ts` wraps `McpServer` via JS Proxy — intercepts `.tool()` to inject dependency/privilege checks
- **Registration isolation**: `safeRegister()` in `index.ts` catches registration errors per-module. `sudo-management` must register first.
- **Singletons**: Module-scoped variables (not class statics) — tagged `SECURITY (CORE-021)`

---

## Environment Variables

| Variable | Default | Note |
|----------|---------|------|
| `DEFENSE_MCP_DRY_RUN` | `true` | Must set `false` to actually modify system |
| `DEFENSE_MCP_ALLOWED_DIRS` | `/tmp,/home,/var/log` | `/etc` excluded by design |
| `DEFENSE_MCP_COMMAND_TIMEOUT` | `120` (sec) | Per-tool: `DEFENSE_MCP_TIMEOUT_<TOOL>` |
| `DEFENSE_MCP_AUTO_INSTALL` | `false` | Auto-install missing tool binaries |
| `DEFENSE_MCP_PREFLIGHT` | `true` | Enable pre-flight dependency checks |

---

## Commit Guidelines

- Reference the tool module name in commit messages (e.g., `feat(firewall): add nftables chain support`)
- Include test updates in the same commit as the feature
- Run `npm test` and `npm run build` before pushing
