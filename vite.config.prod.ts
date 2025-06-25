import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';

// Production-optimized Vite configuration
export default defineConfig({
  plugins: [
    react({
      // Enable React refresh for development-like experience during preview
      include: "**/*.tsx",
      // Production optimizations
      babel: {
        plugins: [
          // Remove console.logs in production
          ["transform-remove-console", { "exclude": ["error", "warn"] }]
        ]
      }
    })
  ],
  
  // Build configuration
  build: {
    target: 'es2015',
    minify: 'terser',
    sourcemap: false, // Disable sourcemaps for production
    
    // Terser options for aggressive minification
    terserOptions: {
      compress: {
        drop_console: true,
        drop_debugger: true,
        pure_funcs: ['console.log', 'console.info'],
        passes: 2
      },
      mangle: {
        safari10: true
      },
      format: {
        comments: false
      }
    },
    
    // Rollup options for optimization
    rollupOptions: {
      output: {
        // Manual chunk splitting for better caching
        manualChunks: {
          // Core React libraries
          'react-core': ['react', 'react-dom'],
          
          // Map and visualization libraries
          'map-libs': ['leaflet'],
          
          // Utility libraries
          'utils': ['papaparse'],
          
          // Cache and analytics services
          'services': [
            './src/services/multiLayerCache.ts',
            './src/services/cacheAnalyticsService.ts',
            './src/services/cacheInvalidationService.ts'
          ]
        },
        
        // Chunk file naming for cache busting
        chunkFileNames: (chunkInfo) => {
          const facadeModuleId = chunkInfo.facadeModuleId ? chunkInfo.facadeModuleId.split('/').pop() : 'chunk';
          return `assets/${facadeModuleId}-[hash].js`;
        },
        
        // Asset file naming
        assetFileNames: (assetInfo) => {
          const info = assetInfo.name!.split('.');
          const ext = info[info.length - 1];
          if (/png|jpe?g|svg|gif|tiff|bmp|ico/i.test(ext)) {
            return `assets/images/[name]-[hash][extname]`;
          }
          if (/css/i.test(ext)) {
            return `assets/css/[name]-[hash][extname]`;
          }
          return `assets/[name]-[hash][extname]`;
        }
      }
    },
    
    // Chunk size warnings
    chunkSizeWarningLimit: 1000,
    
    // Output directory
    outDir: 'dist',
    emptyOutDir: true
  },
  
  // Development server configuration
  server: {
    port: 5173,
    host: true
  },
  
  // Preview server configuration
  preview: {
    port: 4173,
    host: true
  },
  
  // Path resolution
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
      '@components': resolve(__dirname, 'src/components'),
      '@services': resolve(__dirname, 'src/services'),
      '@hooks': resolve(__dirname, 'src/hooks'),
      '@types': resolve(__dirname, 'src/types'),
      '@styles': resolve(__dirname, 'src/styles'),
      '@config': resolve(__dirname, 'src/config'),
      '@pages': resolve(__dirname, 'src/pages')
    }
  },
  
  // Define globals for production
  define: {
    __DEV__: false,
    'process.env.NODE_ENV': JSON.stringify('production')
  },
  
  // CSS configuration
  css: {
    preprocessorOptions: {
      scss: {
        additionalData: `@import "@/styles/variables.scss";`
      }
    },
    postcss: {
      plugins: [
        require('autoprefixer'),
        require('cssnano')({
          preset: 'default'
        })
      ]
    }
  },
  
  // Optimization configuration
  optimizeDeps: {
    include: [
      'react',
      'react-dom',
      'leaflet',
      'papaparse'
    ],
    exclude: [
      // Exclude cache services from optimization to maintain tree-shaking
    ]
  },
  
  // PWA and asset optimization
  assetsInclude: ['**/*.woff', '**/*.woff2', '**/*.ttf'],
  
  // Base path for deployment
  base: process.env.VITE_BASE_PATH || '/',
  
  // Environment variables
  envPrefix: 'VITE_',
  
  // Experimental features
  experimental: {
    renderBuiltUrl(filename: string, { hostType }: { hostType: 'js' | 'css' | 'html' }) {
      if (hostType === 'js') {
        // Use CDN for JS files in production if CDN_URL is set
        return process.env.CDN_URL ? `${process.env.CDN_URL}/${filename}` : filename;
      }
      return filename;
    }
  }
});