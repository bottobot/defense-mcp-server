#!/usr/bin/env node
/**
 * Phase 2 Security Audit — Hardening Deep Dive (v2 - correct tool names)
 * Calls defense-mcp-server tools via stdio transport.
 */
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";

const SERVER = "build/index.js";
let idCounter = 0;
function nextId() { return ++idCounter; }

function startServer() {
  const proc = spawn("node", [SERVER], {
    stdio: ["pipe", "pipe", "pipe"],
    cwd: process.cwd(),
    env: { ...process.env, DEFENSE_MCP_DRY_RUN: "true" },
  });
  const rl = createInterface({ input: proc.stdout });
  const pending = new Map();
  rl.on("line", (line) => {
    try {
      const msg = JSON.parse(line);
      if (msg.id && pending.has(msg.id)) {
        pending.get(msg.id)(msg);
        pending.delete(msg.id);
      }
    } catch {}
  });
  proc.stderr.on("data", () => {});
  function send(msg) {
    return new Promise((resolve, reject) => {
      const id = msg.id;
      if (id) pending.set(id, resolve);
      proc.stdin.write(JSON.stringify(msg) + "\n", (err) => {
        if (err) reject(err);
        if (!id) resolve(null);
      });
    });
  }
  function sendNotification(method) {
    proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", method }) + "\n");
  }
  function close() { proc.stdin.end(); proc.kill("SIGTERM"); }
  return { send, sendNotification, close };
}

async function callTool(client, name, args) {
  const id = nextId();
  const resp = await Promise.race([
    client.send({
      jsonrpc: "2.0", id, method: "tools/call",
      params: { name, arguments: args },
    }),
    new Promise((_, reject) => setTimeout(() => reject(new Error("TIMEOUT (120s)")), 120000)),
  ]);
  return resp;
}

async function main() {
  console.error("=== Phase 2 Security Audit — Hardening Deep Dive ===\n");
  const client = startServer();

  const initId = nextId();
  await client.send({
    jsonrpc: "2.0", id: initId, method: "initialize",
    params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "phase2-audit", version: "2.0.0" } },
  });
  client.sendNotification("notifications/initialized");
  await new Promise(r => setTimeout(r, 2000));

  // Correct tool names based on actual server registration
  const tools = [
    { name: "harden_kernel", args: { action: "sysctl_audit", category: "all" }, label: "1. Sysctl Parameter Audit" },
    { name: "harden_kernel", args: { action: "kernel_audit" }, label: "2. Kernel Security Features Audit" },
    { name: "harden_host", args: { action: "permissions_audit", scope: "all" }, label: "3. File Permissions Audit" },
    { name: "access_control", args: { action: "ssh_audit" }, label: "4. SSH Configuration Audit" },
    { name: "container_isolation", args: { action: "apparmor_status" }, label: "5. AppArmor/MAC Status" },
  ];

  const results = [];

  for (const tool of tools) {
    console.error(`\n>>> [${new Date().toISOString()}] Calling: ${tool.name} → ${JSON.stringify(tool.args)}`);
    try {
      const resp = await callTool(client, tool.name, tool.args);
      results.push({ ...tool, response: resp });
      const isErr = resp?.result?.isError;
      console.error(`<<< ${isErr ? "ERROR" : "Done"}: ${tool.name} → ${tool.args.action}`);
    } catch (err) {
      results.push({ ...tool, response: null, error: err.message });
      console.error(`<<< EXCEPTION: ${tool.name} — ${err.message}`);
    }
  }

  const output = results.map(r => ({
    tool: r.name,
    action: r.args.action,
    label: r.label,
    result: r.response?.result ?? null,
    error: r.error ?? (r.response?.error ?? null),
  }));

  console.log(JSON.stringify(output, null, 2));
  client.close();
  process.exit(0);
}

main().catch(err => { console.error("Fatal:", err); process.exit(1); });
