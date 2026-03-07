import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        globals: true,
        environment: "node",
        include: ["tests/**/*.test.ts"],
        coverage: {
            provider: "v8",
            include: ["src/core/**/*.ts"],
            exclude: ["src/tools/**/*.ts", "src/index.ts"],
            reporter: ["text", "text-summary", "json"],
            thresholds: {
                // Start with achievable targets, increase over time
                lines: 50,
                functions: 50,
                branches: 40,
                statements: 50,
            },
        },
        testTimeout: 10000,
    },
});
