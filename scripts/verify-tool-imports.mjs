#!/usr/bin/env node
/**
 * verify-tool-imports.mjs
 *
 * CI lint rule: ensures every src/tools/*.ts file is imported by src/index.ts.
 * Exits with code 1 if any tool module is missing from the index.
 *
 * Usage:  node scripts/verify-tool-imports.mjs
 * Hook:   npm run verify:tools  (also runs as part of `npm test` via pretest)
 */

import { readdirSync, readFileSync } from "node:fs";
import { basename, join } from "node:path";

const TOOLS_DIR = "src/tools";
const INDEX_FILE = "src/index.ts";

// 1. Discover all .ts files in src/tools/
const toolFiles = readdirSync(TOOLS_DIR)
  .filter((f) => f.endsWith(".ts"))
  .sort();

if (toolFiles.length === 0) {
  console.error("❌  No .ts files found in src/tools/ — something is wrong.");
  process.exit(1);
}

// 2. Read src/index.ts
const indexContent = readFileSync(INDEX_FILE, "utf-8");

// 3. For each tool file, check that index.ts contains an import from it.
//    The import path in index.ts uses .js extension (ESM Node16 convention),
//    e.g. `import { ... } from "./tools/firewall.js";`
const missing = [];

for (const file of toolFiles) {
  const stem = basename(file, ".ts"); // e.g. "firewall"
  // Match either ./tools/<stem>.js or ./tools/<stem>.ts in import statements
  const importPattern = new RegExp(
    `from\\s+["']\\./tools/${stem}\\.(?:js|ts)["']`
  );
  if (!importPattern.test(indexContent)) {
    missing.push(file);
  }
}

// 4. Report results
console.log(
  `✔  Checked ${toolFiles.length} tool files against ${INDEX_FILE}`
);

if (missing.length > 0) {
  console.error("");
  console.error(
    `❌  ${missing.length} tool file(s) NOT imported by ${INDEX_FILE}:`
  );
  for (const f of missing) {
    console.error(`   - ${join(TOOLS_DIR, f)}`);
  }
  console.error("");
  console.error(
    "Each src/tools/*.ts file must be imported and registered in src/index.ts."
  );
  console.error(
    "See CONTRIBUTING.md § 'Adding a New Tool' for the registration workflow."
  );
  process.exit(1);
}

console.log("✔  All tool modules are imported by src/index.ts");
