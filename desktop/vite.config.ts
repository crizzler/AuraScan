import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  // The packaged shell loads dist/index.html over file://, so asset URLs must
  // be relative rather than rooted at the filesystem root.
  base: "./",
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5174
  },
  preview: {
    host: "127.0.0.1",
    port: 4174
  }
});
