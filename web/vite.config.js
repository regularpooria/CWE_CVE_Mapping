import { defineConfig } from "vite";

export default defineConfig({
  // Relative base makes the same build work at the repository root or under
  // https://<user>.github.io/<repo>/ without a custom domain.
  base: "./",
  build: {
    outDir: "dist",
    emptyOutDir: true,
    target: "es2022",
  },
  server: {
    port: 5173,
  },
});
