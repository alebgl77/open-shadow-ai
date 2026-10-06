import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'
import { literalWatchPolicy } from './tooling/watch-policy'

export default defineConfig({
  plugins: [react(), tailwindcss(), literalWatchPolicy()],
  build: { rollupOptions: { output: { manualChunks: { charts: ['recharts'], framework: ['react', 'react-dom', 'react-router-dom'] } } } },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
    },
  },
  server: {
    watch: { disableGlobbing: true },
    proxy: {
      '/api': {
        target: 'http://localhost:8443',
        changeOrigin: true,
      },
    },
  },
})
