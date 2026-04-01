import type { KnipConfig } from "knip";

const config: KnipConfig = {
  entry: ["src/index.ts"],
  project: ["src/**/*.ts"],
  ignore: ["build/**"],
  // Exported types are part of the public npm API — consumers may import them
  ignoreExportsUsedInFile: true,
  eslint: {
    config: ["eslint.config.mjs"],
  },
  vitest: {
    entry: ["tests/**/*.test.ts"],
  },
};

export default config;
