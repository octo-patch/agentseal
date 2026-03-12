import { defineConfig } from "tsup";

export default defineConfig([
  {
    entry: ["src/index.ts"],
    format: ["esm", "cjs"],
    dts: true,
    sourcemap: true,
    clean: true,
    splitting: false,
    treeshake: true,
  },
  {
    entry: ["bin/agentseal.ts"],
    format: ["esm"],
    outDir: "dist",
    banner: { js: "#!/usr/bin/env node" },
    sourcemap: false,
    clean: false,
  },
]);
