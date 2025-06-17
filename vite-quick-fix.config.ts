import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Quick fix config for deployment with relaxed TypeScript checking
export default defineConfig({
  plugins: [react()],
  base: process.env.VITE_BASE_URL || '/',
  build: {
    outDir: 'dist',
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks: {
          'react-vendor': ['react', 'react-dom'],
          'leaflet-vendor': ['leaflet', 'react-leaflet'],
          'utils': ['papaparse']
        }
      }
    }
  },
  server: {
    port: 5173,
    host: true
  },
  esbuild: {
    // Relax TypeScript checking for quick deployment
    logOverride: { 'this-is-undefined-in-esm': 'silent' }
  },
  define: {
    'process.env.NODE_ENV': JSON.stringify('production')
  }
})