import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vite";

// Served from https://toiroakr.github.io/argent/ on GitHub Pages.
// Override with ARGENT_BASE=/ for local-style hosting.
export default defineConfig({
  base: process.env.ARGENT_BASE ?? "/argent/",
  resolve: {
    alias: {
      // Use core's TypeScript source directly so the web app builds without a
      // separate core build step (and gets HMR during dev).
      "@argent/core": fileURLToPath(
        new URL("../../packages/core/src/index.ts", import.meta.url),
      ),
    },
  },
});
