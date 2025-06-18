import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  base: process.env.NODE_ENV === 'production' ? '/monitor-legislativo-v4/' : '/',
  envDir: './',
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
    // Optimization for CDN delivery
    rollupOptions: {
      output: {
        manualChunks: {
          'react-vendor': ['react', 'react-dom'],
          'leaflet-vendor': ['leaflet', 'react-leaflet'],
          'utils': ['papaparse', 'html2canvas']
        },
        // Generate optimized asset names
        chunkFileNames: 'assets/js/[name]-[hash].js',
        entryFileNames: 'assets/js/[name]-[hash].js',
        assetFileNames: 'assets/[ext]/[name]-[hash].[ext]'
      }
    },
    // Disable minification completely for GUARANTEED working deployment
    minify: false,
    // Optimize chunk size
    chunkSizeWarningLimit: 1000,
    // Enable CSS code splitting
    cssCodeSplit: true,
    // Asset inlining threshold
    assetsInlineLimit: 4096
  },
  // Enable build optimizations
  optimizeDeps: {
    include: ['react', 'react-dom', 'leaflet', 'react-leaflet', '@rollup/wasm-node']
  }
})