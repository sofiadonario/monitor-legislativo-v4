import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    react({
      // Disable React development features in production
      include: "**/*.{jsx,tsx}",
      babel: {
        plugins: []
      }
    })
  ],
  base: '/',
  envDir: './',
  define: {
    // Ensure development code is stripped in production
    __DEV__: false,
    'process.env.NODE_ENV': '"production"'
  },
  resolve: {
    alias: {
      'rollup': '@rollup/wasm-node'
    }
  },
  server: {
    port: 3000,
    open: true
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    target: 'es2015',
    rollupOptions: {
      output: {
        manualChunks: {
          'react-vendor': ['react', 'react-dom'],
          'leaflet-vendor': ['leaflet', 'react-leaflet'],
          'utils': ['papaparse']
        }
      }
    },
    minify: 'esbuild',
    chunkSizeWarningLimit: 1000
  },
  optimizeDeps: {
    include: ['react', 'react-dom', 'leaflet', 'react-leaflet']
  }
})