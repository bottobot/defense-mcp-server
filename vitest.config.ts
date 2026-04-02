import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        globals: true,
        environment: "node",
        // CONVENTION (CICD-016): All test files must use the *.test.ts naming pattern.
        // Test files live under tests/ mirroring the src/ directory structure.
        // Example: src/core/sanitizer.ts → tests/core/sanitizer.test.ts
        include: ["tests/**/*.test.ts"],
        exclude: ["tests/integration/**"],
        coverage: {
            provider: "v8",
            include: ["src/core/**/*.ts", "src/tools/**/*.ts"],
            exclude: ["src/index.ts"],
            reporter: ["text", "text-summary", "json", "json-summary"],
            thresholds: {
                // CI runners lack security binaries (iptables, auditd, etc.)
                // so many tool code paths are unreachable in that environment.
                // These thresholds reflect what's achievable without the binaries.
                lines: 72,
                functions: 72,
                branches: 59,
                statements: 71,
            },
        },
        testTimeout: 10000,
    },
});
