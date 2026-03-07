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
                // Raised toward 80% target — increase as more tests are added
                lines: 60,
                functions: 60,
                branches: 50,
                statements: 60,
            },
        },
        testTimeout: 10000,
    },
});
