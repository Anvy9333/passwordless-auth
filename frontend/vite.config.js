// vite.config.ts
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import fs from 'fs'

export default defineConfig({
  plugins: [react()],
  server: {
    https: {
      key:  fs.readFileSync('../PKI/private/frontend.key'),
      cert: fs.readFileSync('../PKI/certs/frontend-chain.crt'),
    },
    port: 5173,
    proxy: {
      '/api': {
        target: 'https://localhost:4433',
        changeOrigin: true,

        secure: true,
      },
    },
  },
})
