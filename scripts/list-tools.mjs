#!/usr/bin/env node
/**
 * List all registered MCP tools
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

async function main() {
  const client = startServer();
  const initId = nextId();
  await client.send({
    jsonrpc: "2.0", id: initId, method: "initialize",
    params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "list-tools", version: "1.0.0" } },
  });
  client.sendNotification("notifications/initialized");
  await new Promise(r => setTimeout(r, 2000));

  const listId = nextId();
  const resp = await client.send({
    jsonrpc: "2.0", id: listId, method: "tools/list", params: {},
  });

  const tools = resp?.result?.tools ?? [];
  console.log(`Total tools: ${tools.length}\n`);
  for (const t of tools) {
    console.log(`  ${t.name}`);
  }

  client.close();
  process.exit(0);
}

main().catch(err => { console.error("Fatal:", err); process.exit(1); });
