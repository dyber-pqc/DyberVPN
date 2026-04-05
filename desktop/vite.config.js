import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  build: {
    target: "esnext",
  },
  server: {
    port: 1420,
    strictPort: true,
    open: false,
    watch: {
      ignored: ["**/src-tauri/**"],
    },
  },
});
