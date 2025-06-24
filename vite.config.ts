import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  base: '/monitor-legislativo-v4/',
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
    // CSP-compliant build for GitHub Pages
    target: 'es2015',
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
    // Use terser minification (CSP-compliant, no eval)
    minify: 'terser',
    terserOptions: {
      compress: {
        drop_console: false, // Keep console.log for debugging
        drop_debugger: true,
        pure_funcs: ['console.debug'] // Remove only debug logs
      },
      mangle: {
        safari10: true // Ensure Safari compatibility
      },
      format: {
        comments: false // Remove comments
      }
    },
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
  },
  // CSP-compliant esbuild configuration
  esbuild: {
    // Ensure no eval() calls are generated
    target: 'es2015',
    // Keep legal comments
    legalComments: 'none'
  }
})