import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  plugins: [react(), tailwindcss()],

  server: {
    // Listen on every interface so Caddy can reach us from another container.
    // Without this Vite only listens inside its own container.
    host: true,
    port: 5173,
    strictPort: true,

    // The browser talks to Caddy on port 8080, never to Vite on 5173. So the
    // hot-reload websocket has to be told to connect back to 8080. Leave this out
    // and hot reload just quietly stops working, with websocket errors in the
    // console.
    hmr: { clientPort: 8080 },

    // The project lives on the Windows filesystem and is mounted into a Linux
    // container, and file-change notifications don't make it across that boundary.
    // Checked this: editing this very file didn't restart Vite until polling was
    // turned on. Without it, edits are silently ignored and the page never
    // updates.
    //
    // The cost is a background loop checking files. node_modules is skipped by
    // default so it stays cheap. Drop this if the project ever moves inside WSL,
    // where the normal notifications work.
    watch: {
      usePolling: true,
      interval: 400,
      binaryInterval: 1000,
    },
  },

  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    css: false,
  },
})
