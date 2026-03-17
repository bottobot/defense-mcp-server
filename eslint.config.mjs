/**
 * ESLint flat config with security-focused linting rules.
 *
 * Uses eslint-plugin-security to detect common security anti-patterns
 * such as eval(), non-literal RegExp, non-literal require(), etc.
 *
 * @see CICD-009
 */
import pluginSecurity from "eslint-plugin-security";

export default [
  // Security plugin recommended config
  pluginSecurity.configs.recommended,
  {
    files: ["src/**/*.ts", "src/**/*.js"],
    plugins: {
      security: pluginSecurity,
    },
    rules: {
      // All security plugin rules are included via recommended config above.
      // Override specific rules here if needed:
      // "security/detect-object-injection": "off",  // too many false positives
    },
  },
  // ── Restrict direct child_process imports ──────────────────────────────────
  // Only 3 files should directly import node:child_process. All other tool
  // files must use executor.ts or spawn-safe.ts to go through the command
  // allowlist. This prevents bypassing the allowlist.
  {
    files: ["src/**/*.ts"],
    ignores: [
      "src/core/command-allowlist.ts",
      "src/core/executor.ts",
      "src/core/spawn-safe.ts",
    ],
    rules: {
      "no-restricted-imports": ["error", {
        paths: [
          {
            name: "node:child_process",
            message: "Use executor.ts or spawn-safe.ts instead. Direct child_process bypasses the command allowlist.",
          },
          {
            name: "child_process",
            message: "Use executor.ts or spawn-safe.ts instead. Direct child_process bypasses the command allowlist.",
          },
        ],
      }],
    },
  },
  {
    // Ignore build output and test files for security linting
    ignores: ["build/**", "coverage/**", "node_modules/**"],
  },
];
