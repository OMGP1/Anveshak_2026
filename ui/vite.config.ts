import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Preserve the browser-facing Host so the API can enforce exact same-origin writes,
// including when Vite selects a free fallback port because another project uses 5173.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://127.0.0.1:8000", changeOrigin: false },
      "/ws": { target: "ws://127.0.0.1:8000", changeOrigin: false, ws: true },
    },
  },
  // react and recharts share one chunk, over vite's 500 kB default notice
  build: { outDir: "dist", chunkSizeWarningLimit: 700 },
});
