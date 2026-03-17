import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        globals: true,
        environment: "node",
        // CONVENTION (CICD-016): All test files must use the *.test.ts naming pattern.
        // Test files live under tests/ mirroring the src/ directory structure.
        // Example: src/core/sanitizer.ts → tests/core/sanitizer.test.ts
        include: ["tests/**/*.test.ts"],
        coverage: {
            provider: "v8",
            include: ["src/core/**/*.ts", "src/tools/**/*.ts"],
            exclude: ["src/index.ts"],
            reporter: ["text", "text-summary", "json"],
            thresholds: {
                // Raised toward 80% target — increase as more tests are added
                lines: 70,
                functions: 70,
                branches: 60,
                statements: 70,
            },
        },
        testTimeout: 10000,
    },
});
