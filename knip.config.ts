import type { KnipConfig } from "knip";

const config: KnipConfig = {
  project: ["src/**/*.ts"],
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
