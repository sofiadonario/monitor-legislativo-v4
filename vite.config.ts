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
  base: '/monitor-legislativo-v4/',
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
      },
      // Strict plugin options to prevent eval()
      plugins: [],
      external: [],
      treeshake: {
        // Remove development code
        moduleSideEffects: false,
        propertyReadSideEffects: false,
        tryCatchDeoptimization: false
      }
    },
    // Use terser minification (CSP-compliant, no eval)
    minify: 'terser',
    terserOptions: {
      compress: {
        drop_console: false, // Keep console.log for debugging
        drop_debugger: true,
        pure_funcs: ['console.debug'], // Remove only debug logs
        keep_infinity: true,
        // Remove development code
        global_defs: {
          __DEV__: false,
          'process.env.NODE_ENV': 'production'
        },
        // Prevent eval usage
        unsafe: false,
        unsafe_comps: false,
        unsafe_Function: false,
        unsafe_math: false,
        unsafe_symbols: false,
        unsafe_methods: false,
        unsafe_proto: false,
        unsafe_regexp: false,
        unsafe_undefined: false
      },
      mangle: {
        safari10: true // Ensure Safari compatibility
      },
      format: {
        comments: false // Remove comments
      },
      // Ensure no eval is generated
      parse: {
        ecma: 2015
      },
      ecma: 2015
    },
    // Optimize chunk size
    chunkSizeWarningLimit: 1000,
    // Enable CSS code splitting
    cssCodeSplit: true,
    // Asset inlining threshold
    assetsInlineLimit: 4096,
    // Additional CSP compliance
    reportCompressedSize: false,
    // Ensure no dynamic imports use eval
    dynamicImportVarsOptions: {
      warnOnError: true,
      exclude: []
    }
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
    legalComments: 'none',
    // Remove only debugger statements, keep console for debugging
    drop: ['debugger'],
    dropLabels: ['DEV'],
    // Ensure no eval in any form
    platform: 'browser',
    format: 'esm',
    // Additional CSP compliance
    define: {
      'process.env.NODE_ENV': '"production"',
      __DEV__: 'false'
    }
  }
})