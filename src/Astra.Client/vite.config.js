import { defineConfig } from "vite";

// The Astra analyst console is a Fable-compiled SPA. During `dotnet fable watch
// --run vite`, Fable emits .js next to the .fs sources and Vite serves them.
// API calls are proxied to the central brain in dev.
export default defineConfig({
  root: ".",
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.ASTRA_API_TARGET || "http://localhost:5170",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
