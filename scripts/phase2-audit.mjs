#!/usr/bin/env node
/**
 * Phase 2 Security Audit — Hardening Deep Dive
 * Calls defense-mcp-server tools via stdio transport.
 * Tools: harden_sysctl, harden_kernel, harden_permissions, access_ssh, container_apparmor
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
    } catch { /* ignore non-JSON lines */ }
  });

  proc.stderr.on("data", (data) => {
    const text = data.toString().trim();
    if (text) console.error(`[server] ${text}`);
  });

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

  function close() {
    proc.stdin.end();
    proc.kill("SIGTERM");
  }

  return { send, sendNotification, close };
}

async function callTool(client, name, args) {
  const id = nextId();
  const resp = await Promise.race([
    client.send({
      jsonrpc: "2.0",
      id,
      method: "tools/call",
      params: { name, arguments: args },
    }),
    new Promise((_, reject) => setTimeout(() => reject(new Error("TIMEOUT (120s)")), 120000)),
  ]);
  return resp;
}

async function main() {
  console.error("=== Phase 2 Security Audit — Hardening Deep Dive ===\n");
  const client = startServer();

  // Initialize MCP connection
  const initId = nextId();
  await client.send({
    jsonrpc: "2.0",
    id: initId,
    method: "initialize",
    params: {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "phase2-audit", version: "1.0.0" },
    },
  });
  client.sendNotification("notifications/initialized");

  // Wait for server readiness
  await new Promise(r => setTimeout(r, 2000));

  const tools = [
    { name: "harden_sysctl", args: { action: "audit" }, label: "Sysctl Audit" },
    { name: "harden_kernel", args: { action: "audit" }, label: "Kernel Security Audit" },
    { name: "harden_permissions", args: { action: "audit" }, label: "File Permissions Audit" },
    { name: "access_ssh", args: { action: "audit" }, label: "SSH Configuration Audit" },
    { name: "container_apparmor", args: { action: "status" }, label: "AppArmor Status" },
  ];

  const results = [];

  for (const tool of tools) {
    console.error(`\n>>> [${new Date().toISOString()}] Calling: ${tool.name} → ${JSON.stringify(tool.args)}`);
    try {
      const resp = await callTool(client, tool.name, tool.args);
      results.push({ ...tool, response: resp });
      console.error(`<<< Done: ${tool.name}`);
    } catch (err) {
      results.push({ ...tool, response: null, error: err.message });
      console.error(`<<< Error: ${tool.name} — ${err.message}`);
    }
  }

  // Output results as JSON to stdout
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

main().catch(err => {
  console.error("Fatal:", err);
  process.exit(1);
});
