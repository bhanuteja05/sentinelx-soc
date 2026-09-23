import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const backendProxyTarget =
  process.env.BACKEND_PROXY_TARGET ?? 'http://backend:8000'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': {
        target: backendProxyTarget,
        changeOrigin: true,
      },
    },
  },
})
