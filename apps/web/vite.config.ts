import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  plugins: [react(), tailwindcss()],

  server: {
    // Listen on all interfaces so Caddy can reach the dev server from another
    // container. Without this, Vite binds localhost inside its own namespace.
    host: true,
    port: 5173,
    strictPort: true,

    // The browser talks to Caddy on :8080, never to Vite on :5173 directly, so
    // the HMR websocket has to be told where to connect back to. Without this,
    // hot reload silently fails and you get a console full of ws errors.
    hmr: { clientPort: 8080 },

    // The repo lives on the Windows filesystem and is bind-mounted into a Linux
    // container, and inotify events do not cross that boundary for chokidar —
    // verified: editing this file produced no Vite restart, while uvicorn's
    // watchfiles did pick up its own change. Without polling, every edit is
    // silently ignored and the page just never updates.
    //
    // Cost is a background stat loop. node_modules is excluded by Vite's
    // defaults, so it stays cheap. Remove this if the repo ever moves into the
    // WSL 2 filesystem, where native events work.
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
