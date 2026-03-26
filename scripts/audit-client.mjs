#!/usr/bin/env node
/**
 * MCP audit client — calls defense-mcp-server tools via stdio transport.
 * Usage: node scripts/audit-client.mjs
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

  proc.stderr.on("data", () => {}); // suppress stderr

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
  const resp = await client.send({
    jsonrpc: "2.0",
    id,
    method: "tools/call",
    params: { name, arguments: args },
  });
  return resp;
}

async function main() {
  const client = startServer();

  // Initialize
  const initId = nextId();
  await client.send({
    jsonrpc: "2.0",
    id: initId,
    method: "initialize",
    params: {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "audit-client", version: "1.0.0" },
    },
  });
  client.sendNotification("notifications/initialized");

  // Wait a moment for server to be ready
  await new Promise(r => setTimeout(r, 2000));

  const tools = [
    { name: "defense_mgmt", args: { action: "posture_score" }, label: "Security Posture Score" },
    { name: "compliance", args: { action: "cis_check", level: "1" }, label: "CIS Level 1 Compliance" },
    { name: "firewall", args: { action: "iptables_list" }, label: "Firewall Rules" },
    { name: "access_control", args: { action: "user_audit" }, label: "User Audit" },
    { name: "patch", args: { action: "update_audit" }, label: "Patch Update Audit" },
  ];

  const results = [];

  for (const tool of tools) {
    console.error(`\n>>> Calling: ${tool.name} → ${tool.args.action}`);
    try {
      const resp = await Promise.race([
        callTool(client, tool.name, tool.args),
        new Promise((_, reject) => setTimeout(() => reject(new Error("TIMEOUT")), 120000)),
      ]);
      results.push({ ...tool, response: resp });
      console.error(`<<< Done: ${tool.name}`);
    } catch (err) {
      results.push({ ...tool, response: null, error: err.message });
      console.error(`<<< Error: ${tool.name} — ${err.message}`);
    }
  }

  // Output results as JSON
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
