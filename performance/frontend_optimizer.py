# Frontend Performance Optimization for Monitor Legislativo v4
# Phase 5 Week 20: Advanced frontend optimization and bundle analysis
# React/TypeScript performance tuning and build optimization

import asyncio
import json
import logging
import os
import subprocess
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
import hashlib
import gzip
import brotli
import re
from collections import defaultdict

logger = logging.getLogger(__name__)

class OptimizationType(Enum):
    """Types of frontend optimizations"""
    BUNDLE_ANALYSIS = "bundle_analysis"
    CODE_SPLITTING = "code_splitting"
    LAZY_LOADING = "lazy_loading"
    TREE_SHAKING = "tree_shaking"
    ASSET_OPTIMIZATION = "asset_optimization"
    CACHING_STRATEGY = "caching_strategy"
    PRELOADING = "preloading"
    SERVICE_WORKER = "service_worker"

class MetricType(Enum):
    """Performance metrics to track"""
    BUNDLE_SIZE = "bundle_size"
    LOAD_TIME = "load_time"
    FCP = "first_contentful_paint"
    LCP = "largest_contentful_paint"
    FID = "first_input_delay"
    CLS = "cumulative_layout_shift"
    TTI = "time_to_interactive"
    LIGHTHOUSE_SCORE = "lighthouse_score"

@dataclass
class OptimizationResult:
    """Result of optimization operation"""
    optimization_type: OptimizationType
    status: str
    metrics_before: Dict[str, float]
    metrics_after: Dict[str, float]
    improvement_percentage: float
    recommendations: List[str]
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'optimization_type': self.optimization_type.value,
            'status': self.status,
            'metrics_before': self.metrics_before,
            'metrics_after': self.metrics_after,
            'improvement_percentage': self.improvement_percentage,
            'recommendations': self.recommendations,
            'timestamp': self.timestamp.isoformat()
        }

class FrontendOptimizer:
    """
    Advanced frontend performance optimization system.
    
    Analyzes and optimizes React/TypeScript application for maximum performance
    in the Brazilian legislative research platform context.
    """
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.src_dir = self.project_root / "src"
        self.build_dir = self.project_root / "dist"
        self.public_dir = self.project_root / "public"
        
        # Performance thresholds for Brazilian academic research context
        self.performance_thresholds = {
            'bundle_size_mb': 2.0,  # Max bundle size for academic users
            'initial_load_ms': 3000,  # 3 seconds for initial load
            'route_transition_ms': 500,  # Fast route transitions
            'api_response_ms': 2000,  # API response time
            'lighthouse_score': 90,  # Target Lighthouse score
            'fcp_ms': 1500,  # First Contentful Paint
            'lcp_ms': 2500,  # Largest Contentful Paint
            'fid_ms': 100,   # First Input Delay
            'cls_score': 0.1  # Cumulative Layout Shift
        }
        
        # Optimization results storage
        self.optimization_history: List[OptimizationResult] = []
        
        # Critical paths for Brazilian legislative research
        self.critical_paths = [
            "/search",
            "/document",
            "/export",
            "/analysis",
            "/workspace"
        ]
    
    async def analyze_bundle_performance(self) -> Dict[str, Any]:
        """Comprehensive bundle analysis and optimization recommendations"""
        logger.info("Starting comprehensive bundle analysis...")
        
        analysis_results = {
            'bundle_analysis': {},
            'recommendations': [],
            'optimization_opportunities': [],
            'current_metrics': {}
        }
        
        try:
            # Build the application for analysis
            await self._build_application()
            
            # Analyze bundle composition
            bundle_stats = await self._analyze_bundle_composition()
            analysis_results['bundle_analysis'] = bundle_stats
            
            # Check for large dependencies
            large_deps = await self._identify_large_dependencies()
            if large_deps:
                analysis_results['recommendations'].extend([
                    f"Consider alternatives to large dependency: {dep['name']} ({dep['size']}MB)"
                    for dep in large_deps
                ])
            
            # Analyze code splitting opportunities
            splitting_opportunities = await self._analyze_code_splitting_opportunities()
            analysis_results['optimization_opportunities'].extend(splitting_opportunities)
            
            # Check for unused code
            unused_code = await self._detect_unused_code()
            if unused_code:
                analysis_results['recommendations'].append(
                    f"Remove {len(unused_code)} unused code segments to reduce bundle size"
                )
            
            # Analyze asset optimization
            asset_optimization = await self._analyze_asset_optimization()
            analysis_results['optimization_opportunities'].extend(asset_optimization)
            
            # Get current performance metrics
            current_metrics = await self._measure_current_performance()
            analysis_results['current_metrics'] = current_metrics
            
            # Generate optimization priority list
            priority_optimizations = self._prioritize_optimizations(analysis_results)
            analysis_results['priority_optimizations'] = priority_optimizations
            
        except Exception as e:
            logger.error(f"Bundle analysis failed: {str(e)}")
            analysis_results['error'] = str(e)
        
        return analysis_results
    
    async def _build_application(self) -> None:
        """Build application with production optimizations"""
        logger.info("Building application for performance analysis...")
        
        build_command = ["npm", "run", "build"]
        process = subprocess.run(
            build_command,
            cwd=self.project_root,
            capture_output=True,
            text=True
        )
        
        if process.returncode != 0:
            raise Exception(f"Build failed: {process.stderr}")
        
        logger.info("Application build completed successfully")
    
    async def _analyze_bundle_composition(self) -> Dict[str, Any]:
        """Analyze bundle composition and identify optimization opportunities"""
        bundle_stats = {
            'total_size_mb': 0,
            'gzipped_size_mb': 0,
            'brotli_size_mb': 0,
            'chunk_analysis': [],
            'largest_chunks': [],
            'duplicate_modules': []
        }
        
        if not self.build_dir.exists():
            return bundle_stats
        
        # Analyze JavaScript chunks
        js_files = list(self.build_dir.glob("**/*.js"))
        
        total_size = 0
        chunk_data = []
        
        for js_file in js_files:
            file_size = js_file.stat().st_size
            total_size += file_size
            
            # Calculate compressed sizes
            with open(js_file, 'rb') as f:
                content = f.read()
                gzipped_size = len(gzip.compress(content))
                brotli_size = len(brotli.compress(content))
            
            chunk_info = {
                'name': js_file.name,
                'size_kb': file_size / 1024,
                'gzipped_kb': gzipped_size / 1024,
                'brotli_kb': brotli_size / 1024,
                'compression_ratio': gzipped_size / file_size if file_size > 0 else 0
            }
            chunk_data.append(chunk_info)
        
        # Sort by size to identify largest chunks
        chunk_data.sort(key=lambda x: x['size_kb'], reverse=True)
        
        bundle_stats['total_size_mb'] = total_size / (1024 * 1024)
        bundle_stats['chunk_analysis'] = chunk_data
        bundle_stats['largest_chunks'] = chunk_data[:10]  # Top 10 largest chunks
        
        # Calculate total compressed sizes
        bundle_stats['gzipped_size_mb'] = sum(chunk['gzipped_kb'] for chunk in chunk_data) / 1024
        bundle_stats['brotli_size_mb'] = sum(chunk['brotli_kb'] for chunk in chunk_data) / 1024
        
        return bundle_stats
    
    async def _identify_large_dependencies(self) -> List[Dict[str, Any]]:
        """Identify large dependencies that could be optimized"""
        large_deps = []
        
        try:
            # Analyze package.json dependencies
            package_json_path = self.project_root / "package.json"
            if package_json_path.exists():
                with open(package_json_path, 'r') as f:
                    package_data = json.load(f)
                
                dependencies = package_data.get('dependencies', {})
                
                # Known large packages that might need alternatives
                large_packages = {
                    'moment': {'size_mb': 0.3, 'alternative': 'day.js'},
                    'lodash': {'size_mb': 0.5, 'alternative': 'lodash-es with tree shaking'},
                    'antd': {'size_mb': 2.0, 'alternative': 'cherry-pick components'},
                    'material-ui': {'size_mb': 1.5, 'alternative': 'cherry-pick components'},
                    'plotly.js': {'size_mb': 3.0, 'alternative': 'plotly.js-dist-min'},
                    'leaflet': {'size_mb': 0.5, 'alternative': 'already optimized'},
                }
                
                for dep_name in dependencies:
                    if dep_name in large_packages:
                        large_deps.append({
                            'name': dep_name,
                            'size': large_packages[dep_name]['size_mb'],
                            'alternative': large_packages[dep_name]['alternative']
                        })
        
        except Exception as e:
            logger.warning(f"Failed to analyze dependencies: {str(e)}")
        
        return large_deps
    
    async def _analyze_code_splitting_opportunities(self) -> List[str]:
        """Analyze opportunities for code splitting"""
        opportunities = []
        
        try:
            # Check for large route components
            route_files = list(self.src_dir.glob("**/routes/**/*.tsx")) + list(self.src_dir.glob("**/pages/**/*.tsx"))
            
            for route_file in route_files:
                file_size = route_file.stat().st_size
                if file_size > 50 * 1024:  # Files larger than 50KB
                    opportunities.append(f"Consider lazy loading for large route component: {route_file.name}")
            
            # Check for large utility modules
            util_files = list(self.src_dir.glob("**/utils/**/*.ts")) + list(self.src_dir.glob("**/helpers/**/*.ts"))
            
            for util_file in util_files:
                file_size = util_file.stat().st_size
                if file_size > 30 * 1024:  # Utilities larger than 30KB
                    opportunities.append(f"Consider splitting large utility module: {util_file.name}")
            
            # Check for vendor bundling opportunities
            if len(opportunities) == 0:
                opportunities.append("Consider implementing route-based code splitting")
                opportunities.append("Consider vendor chunk separation for better caching")
        
        except Exception as e:
            logger.warning(f"Failed to analyze code splitting: {str(e)}")
        
        return opportunities
    
    async def _detect_unused_code(self) -> List[str]:
        """Detect potentially unused code"""
        unused_code = []
        
        try:
            # Simple heuristic-based unused code detection
            ts_files = list(self.src_dir.glob("**/*.ts")) + list(self.src_dir.glob("**/*.tsx"))
            
            # Look for imports that might be unused
            for ts_file in ts_files:
                try:
                    with open(ts_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # Find import statements
                    import_pattern = r'import\s+.*?\s+from\s+[\'"]([^\'"]+)[\'"]'
                    imports = re.findall(import_pattern, content)
                    
                    # Simple check for unused utilities (this is a basic heuristic)
                    if 'utils/' in str(ts_file) and content.count('export') > content.count('import'):
                        unused_code.append(f"Potential unused exports in {ts_file.name}")
                
                except Exception:
                    continue  # Skip files that can't be read
        
        except Exception as e:
            logger.warning(f"Failed to detect unused code: {str(e)}")
        
        return unused_code
    
    async def _analyze_asset_optimization(self) -> List[str]:
        """Analyze asset optimization opportunities"""
        optimizations = []
        
        try:
            # Check image assets
            image_files = list(self.public_dir.glob("**/*.png")) + \
                         list(self.public_dir.glob("**/*.jpg")) + \
                         list(self.public_dir.glob("**/*.jpeg"))
            
            large_images = []
            for img_file in image_files:
                file_size = img_file.stat().st_size
                if file_size > 500 * 1024:  # Images larger than 500KB
                    large_images.append({
                        'name': img_file.name,
                        'size_kb': file_size / 1024
                    })
            
            if large_images:
                optimizations.append(f"Optimize {len(large_images)} large images (consider WebP format)")
            
            # Check for SVG optimization opportunities
            svg_files = list(self.public_dir.glob("**/*.svg"))
            if svg_files:
                optimizations.append(f"Consider optimizing {len(svg_files)} SVG files")
            
            # Check for font optimization
            font_files = list(self.public_dir.glob("**/*.woff")) + \
                        list(self.public_dir.glob("**/*.woff2")) + \
                        list(self.public_dir.glob("**/*.ttf"))
            
            if font_files:
                total_font_size = sum(f.stat().st_size for f in font_files)
                if total_font_size > 1024 * 1024:  # More than 1MB of fonts
                    optimizations.append("Consider font subsetting and preload optimization")
        
        except Exception as e:
            logger.warning(f"Failed to analyze assets: {str(e)}")
        
        return optimizations
    
    async def _measure_current_performance(self) -> Dict[str, float]:
        """Measure current application performance metrics"""
        metrics = {}
        
        try:
            # Bundle size metrics
            if self.build_dir.exists():
                js_files = list(self.build_dir.glob("**/*.js"))
                total_js_size = sum(f.stat().st_size for f in js_files)
                metrics['bundle_size_mb'] = total_js_size / (1024 * 1024)
                
                css_files = list(self.build_dir.glob("**/*.css"))
                total_css_size = sum(f.stat().st_size for f in css_files)
                metrics['css_size_kb'] = total_css_size / 1024
            
            # Estimated load time (based on bundle size and typical connection)
            # Assuming 3G connection (1.6 Mbps effective)
            if 'bundle_size_mb' in metrics:
                estimated_load_ms = (metrics['bundle_size_mb'] * 8) / 1.6 * 1000  # Convert to milliseconds
                metrics['estimated_load_ms'] = estimated_load_ms
            
            # Asset count metrics
            all_assets = list(self.build_dir.glob("**/*")) if self.build_dir.exists() else []
            metrics['total_assets'] = len([f for f in all_assets if f.is_file()])
            
        except Exception as e:
            logger.warning(f"Failed to measure performance: {str(e)}")
        
        return metrics
    
    def _prioritize_optimizations(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Prioritize optimizations based on impact and effort"""
        priorities = []
        
        current_metrics = analysis_results.get('current_metrics', {})
        bundle_size = current_metrics.get('bundle_size_mb', 0)
        
        # High priority: Bundle size optimization
        if bundle_size > self.performance_thresholds['bundle_size_mb']:
            priorities.append({
                'priority': 'HIGH',
                'optimization': 'Bundle Size Reduction',
                'impact': 'Significant load time improvement',
                'effort': 'Medium',
                'actions': [
                    'Implement code splitting',
                    'Remove unused dependencies',
                    'Enable tree shaking'
                ]
            })
        
        # Medium priority: Asset optimization
        if len(analysis_results.get('optimization_opportunities', [])) > 0:
            priorities.append({
                'priority': 'MEDIUM',
                'optimization': 'Asset Optimization',
                'impact': 'Moderate performance improvement',
                'effort': 'Low',
                'actions': [
                    'Optimize images',
                    'Implement lazy loading',
                    'Add service worker caching'
                ]
            })
        
        # Low priority: Code splitting
        opportunities = analysis_results.get('optimization_opportunities', [])
        if any('lazy loading' in opp.lower() for opp in opportunities):
            priorities.append({
                'priority': 'LOW',
                'optimization': 'Advanced Code Splitting',
                'impact': 'Improved perceived performance',
                'effort': 'High',
                'actions': [
                    'Implement route-based splitting',
                    'Add progressive loading',
                    'Optimize chunk strategies'
                ]
            })
        
        return priorities
    
    async def implement_code_splitting(self) -> OptimizationResult:
        """Implement code splitting optimizations"""
        logger.info("Implementing code splitting optimizations...")
        
        metrics_before = await self._measure_current_performance()
        
        try:
            # Create optimized route configuration
            await self._create_lazy_route_config()
            
            # Implement component lazy loading
            await self._implement_component_lazy_loading()
            
            # Optimize vendor chunk splitting
            await self._optimize_vendor_chunks()
            
            # Rebuild and measure
            await self._build_application()
            metrics_after = await self._measure_current_performance()
            
            # Calculate improvement
            bundle_before = metrics_before.get('bundle_size_mb', 0)
            bundle_after = metrics_after.get('bundle_size_mb', 0)
            improvement = ((bundle_before - bundle_after) / bundle_before * 100) if bundle_before > 0 else 0
            
            result = OptimizationResult(
                optimization_type=OptimizationType.CODE_SPLITTING,
                status='success',
                metrics_before=metrics_before,
                metrics_after=metrics_after,
                improvement_percentage=improvement,
                recommendations=[
                    'Monitor route transition performance',
                    'Consider implementing preloading for critical routes',
                    'Test lazy loading on slower connections'
                ]
            )
            
        except Exception as e:
            result = OptimizationResult(
                optimization_type=OptimizationType.CODE_SPLITTING,
                status='failed',
                metrics_before=metrics_before,
                metrics_after={},
                improvement_percentage=0,
                recommendations=[f'Fix implementation error: {str(e)}']
            )
        
        self.optimization_history.append(result)
        return result
    
    async def _create_lazy_route_config(self) -> None:
        """Create optimized route configuration with lazy loading"""
        # This would generate optimized route configuration
        # For Brazilian legislative research critical paths
        
        route_config = """
// Optimized route configuration for Monitor Legislativo v4
import { lazy, Suspense } from 'react';
import { Routes, Route } from 'react-router-dom';
import LoadingSpinner from './components/LoadingSpinner';

// Lazy load route components for better performance
const SearchPage = lazy(() => import('./pages/SearchPage'));
const DocumentViewer = lazy(() => import('./pages/DocumentViewer'));
const ExportCenter = lazy(() => import('./pages/ExportCenter'));
const AnalysisWorkspace = lazy(() => import('./pages/AnalysisWorkspace'));
const ResearchWorkspace = lazy(() => import('./pages/ResearchWorkspace'));

// High priority routes - preload
const HomePage = lazy(() => 
  import(/* webpackPreload: true */ './pages/HomePage')
);

const AppRoutes = () => (
  <Suspense fallback={<LoadingSpinner />}>
    <Routes>
      <Route path="/" element={<HomePage />} />
      <Route path="/search" element={<SearchPage />} />
      <Route path="/document/:id" element={<DocumentViewer />} />
      <Route path="/export" element={<ExportCenter />} />
      <Route path="/analysis" element={<AnalysisWorkspace />} />
      <Route path="/workspace" element={<ResearchWorkspace />} />
    </Routes>
  </Suspense>
);

export default AppRoutes;
        """
        
        # Write optimized route configuration
        routes_file = self.src_dir / "routes" / "OptimizedRoutes.tsx"
        routes_file.parent.mkdir(exist_ok=True)
        
        with open(routes_file, 'w', encoding='utf-8') as f:
            f.write(route_config.strip())
        
        logger.info("Created optimized route configuration")
    
    async def _implement_component_lazy_loading(self) -> None:
        """Implement component-level lazy loading"""
        # Create lazy loading utility for heavy components
        
        lazy_loading_util = """
// Lazy loading utilities for Monitor Legislativo v4
import { lazy, ComponentType } from 'react';

// Enhanced lazy loading with error boundaries
export const createLazyComponent = <T extends ComponentType<any>>(
  importFunc: () => Promise<{ default: T }>,
  fallback?: ComponentType
) => {
  const LazyComponent = lazy(importFunc);
  
  return (props: any) => (
    <Suspense 
      fallback={fallback ? <fallback /> : <div>Carregando...</div>}
    >
      <LazyComponent {...props} />
    </Suspense>
  );
};

// Preload critical components
export const preloadComponent = (importFunc: () => Promise<any>) => {
  // Preload on idle or user interaction
  if ('requestIdleCallback' in window) {
    requestIdleCallback(() => importFunc());
  } else {
    setTimeout(() => importFunc(), 1);
  }
};

// Brazilian legislative data visualization components (heavy)
export const LazyMapVisualization = createLazyComponent(
  () => import('../components/visualizations/MapVisualization')
);

export const LazyDataExportWizard = createLazyComponent(
  () => import('../components/export/DataExportWizard')
);

export const LazyAdvancedSearch = createLazyComponent(
  () => import('../components/search/AdvancedSearchForm')
);

export const LazyCitationManager = createLazyComponent(
  () => import('../components/academic/CitationManager')
);
        """
        
        utils_file = self.src_dir / "utils" / "lazyLoading.tsx"
        utils_file.parent.mkdir(exist_ok=True)
        
        with open(utils_file, 'w', encoding='utf-8') as f:
            f.write(lazy_loading_util.strip())
        
        logger.info("Implemented component lazy loading utilities")
    
    async def _optimize_vendor_chunks(self) -> None:
        """Optimize vendor chunk splitting configuration"""
        # Create Vite configuration for optimal chunking
        
        vite_config = """
// Optimized Vite configuration for Monitor Legislativo v4
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          // Vendor libraries
          'vendor-react': ['react', 'react-dom', 'react-router-dom'],
          'vendor-ui': ['@mui/material', '@mui/icons-material'],
          'vendor-maps': ['leaflet', 'react-leaflet'],
          'vendor-charts': ['plotly.js', 'react-plotly.js'],
          'vendor-utils': ['lodash-es', 'date-fns', 'papaparse'],
          
          // Brazilian legislative specific
          'legislative-core': ['./src/services/legislativeAPI'],
          'legislative-search': ['./src/components/search'],
          'legislative-export': ['./src/components/export'],
          'legislative-analysis': ['./src/components/analysis']
        }
      }
    },
    chunkSizeWarningLimit: 1000,
    minify: 'terser',
    terserOptions: {
      compress: {
        drop_console: true,
        drop_debugger: true
      }
    }
  },
  server: {
    port: 3000
  }
});
        """
        
        config_file = self.project_root / "vite.config.optimized.ts"
        
        with open(config_file, 'w', encoding='utf-8') as f:
            f.write(vite_config.strip())
        
        logger.info("Created optimized Vite configuration")
    
    async def implement_asset_optimization(self) -> OptimizationResult:
        """Implement comprehensive asset optimization"""
        logger.info("Implementing asset optimization...")
        
        metrics_before = await self._measure_current_performance()
        
        try:
            # Implement image optimization
            await self._optimize_images()
            
            # Setup service worker for caching
            await self._implement_service_worker()
            
            # Optimize font loading
            await self._optimize_font_loading()
            
            # Implement resource hints
            await self._implement_resource_hints()
            
            metrics_after = await self._measure_current_performance()
            
            # Calculate improvement
            load_before = metrics_before.get('estimated_load_ms', 0)
            load_after = metrics_after.get('estimated_load_ms', 0)
            improvement = ((load_before - load_after) / load_before * 100) if load_before > 0 else 0
            
            result = OptimizationResult(
                optimization_type=OptimizationType.ASSET_OPTIMIZATION,
                status='success',
                metrics_before=metrics_before,
                metrics_after=metrics_after,
                improvement_percentage=improvement,
                recommendations=[
                    'Monitor cache hit rates',
                    'Consider implementing image lazy loading',
                    'Test performance on slower networks'
                ]
            )
            
        except Exception as e:
            result = OptimizationResult(
                optimization_type=OptimizationType.ASSET_OPTIMIZATION,
                status='failed',
                metrics_before=metrics_before,
                metrics_after={},
                improvement_percentage=0,
                recommendations=[f'Fix optimization error: {str(e)}']
            )
        
        self.optimization_history.append(result)
        return result
    
    async def _optimize_images(self) -> None:
        """Optimize image assets"""
        # Create image optimization configuration
        
        image_config = """
// Image optimization configuration for Monitor Legislativo v4
// Optimized for Brazilian legislative research platform

// WebP conversion for supported browsers
export const imageOptimization = {
  // Convert to WebP with fallback
  convertToWebP: true,
  
  // Responsive image sizes for Brazilian government documents
  breakpoints: [480, 768, 1024, 1440],
  
  // Compression settings optimized for document images
  compression: {
    jpeg: { quality: 85 },
    png: { quality: 90 },
    webp: { quality: 80 }
  },
  
  // Lazy loading implementation
  lazyLoading: {
    rootMargin: '50px',
    threshold: 0.1
  }
};

// Image component with optimization
export const OptimizedImage = ({ src, alt, ...props }) => {
  const [loaded, setLoaded] = useState(false);
  const [inView, setInView] = useState(false);
  const imgRef = useRef();
  
  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setInView(true);
          observer.disconnect();
        }
      },
      imageOptimization.lazyLoading
    );
    
    if (imgRef.current) {
      observer.observe(imgRef.current);
    }
    
    return () => observer.disconnect();
  }, []);
  
  return (
    <div ref={imgRef} {...props}>
      {inView && (
        <picture>
          <source srcSet={`${src}.webp`} type="image/webp" />
          <img
            src={src}
            alt={alt}
            onLoad={() => setLoaded(true)}
            style={{
              opacity: loaded ? 1 : 0,
              transition: 'opacity 0.3s ease'
            }}
          />
        </picture>
      )}
    </div>
  );
};
        """
        
        image_utils_file = self.src_dir / "components" / "OptimizedImage.tsx"
        image_utils_file.parent.mkdir(exist_ok=True)
        
        with open(image_utils_file, 'w', encoding='utf-8') as f:
            f.write(image_config.strip())
        
        logger.info("Implemented image optimization utilities")
    
    async def _implement_service_worker(self) -> None:
        """Implement service worker for caching optimization"""
        
        service_worker = """
// Service Worker for Monitor Legislativo v4
// Optimized caching for Brazilian legislative research platform

const CACHE_NAME = 'monitor-legislativo-v4-cache';
const STATIC_ASSETS = [
  '/',
  '/static/js/main.js',
  '/static/css/main.css',
  '/manifest.json'
];

// Brazilian legislative API endpoints to cache
const API_CACHE_PATTERNS = [
  '/api/v1/search',
  '/api/v1/documents',
  '/api/v1/lexml'
];

// Install event - cache static assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(STATIC_ASSETS))
  );
});

// Fetch event - serve from cache with network fallback
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);
  
  // Cache static assets
  if (request.destination === 'script' || 
      request.destination === 'style' ||
      request.destination === 'image') {
    event.respondWith(
      caches.match(request)
        .then((response) => response || fetch(request))
    );
    return;
  }
  
  // Cache API responses with stale-while-revalidate
  if (API_CACHE_PATTERNS.some(pattern => url.pathname.includes(pattern))) {
    event.respondWith(
      caches.match(request)
        .then((response) => {
          const fetchPromise = fetch(request).then((fetchResponse) => {
            const responseClone = fetchResponse.clone();
            caches.open(CACHE_NAME)
              .then((cache) => cache.put(request, responseClone));
            return fetchResponse;
          });
          
          return response || fetchPromise;
        })
    );
    return;
  }
  
  // Network first for other requests
  event.respondWith(fetch(request));
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames
          .filter((cacheName) => cacheName !== CACHE_NAME)
          .map((cacheName) => caches.delete(cacheName))
      );
    })
  );
});
        """
        
        sw_file = self.public_dir / "sw.js"
        
        with open(sw_file, 'w', encoding='utf-8') as f:
            f.write(service_worker.strip())
        
        logger.info("Implemented service worker for caching")
    
    async def _optimize_font_loading(self) -> None:
        """Optimize font loading strategy"""
        
        font_optimization = """
<!-- Font optimization for Monitor Legislativo v4 -->
<!-- Optimized for Brazilian Portuguese text rendering -->

<!-- Preload critical fonts -->
<link rel="preload" href="/fonts/inter-latin-400.woff2" as="font" type="font/woff2" crossorigin>
<link rel="preload" href="/fonts/inter-latin-600.woff2" as="font" type="font/woff2" crossorigin>

<!-- Font display optimization -->
<style>
  @font-face {
    font-family: 'Inter';
    font-style: normal;
    font-weight: 400;
    font-display: swap; /* Swap immediately for better performance */
    src: url('/fonts/inter-latin-400.woff2') format('woff2');
    unicode-range: U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+2000-206F, U+2074, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;
  }
  
  @font-face {
    font-family: 'Inter';
    font-style: normal;
    font-weight: 600;
    font-display: swap;
    src: url('/fonts/inter-latin-600.woff2') format('woff2');
    unicode-range: U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+2000-206F, U+2074, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;
  }
  
  /* Fallback font stack optimized for Brazilian Portuguese */
  body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', sans-serif;
  }
</style>
        """
        
        # Update index.html with font optimizations
        index_file = self.public_dir / "index.html"
        if index_file.exists():
            with open(index_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Insert font optimization in head
            head_end = content.find('</head>')
            if head_end != -1:
                optimized_content = (
                    content[:head_end] + 
                    font_optimization.strip() + 
                    '\n' + 
                    content[head_end:]
                )
                
                with open(index_file, 'w', encoding='utf-8') as f:
                    f.write(optimized_content)
        
        logger.info("Optimized font loading strategy")
    
    async def _implement_resource_hints(self) -> None:
        """Implement resource hints for better performance"""
        
        resource_hints = """
<!-- Resource hints for Monitor Legislativo v4 -->
<!-- Optimized for Brazilian legislative research platform -->

<!-- DNS prefetch for external APIs -->
<link rel="dns-prefetch" href="//www.camara.leg.br">
<link rel="dns-prefetch" href="//legis.senado.leg.br">
<link rel="dns-prefetch" href="//www.planalto.gov.br">

<!-- Preconnect to critical origins -->
<link rel="preconnect" href="https://api.supabase.io" crossorigin>
<link rel="preconnect" href="https://fonts.googleapis.com" crossorigin>

<!-- Prefetch likely next pages -->
<link rel="prefetch" href="/search">
<link rel="prefetch" href="/export">

<!-- Preload critical API endpoints -->
<link rel="modulepreload" href="/src/services/legislativeAPI.ts">
<link rel="modulepreload" href="/src/services/lexmlAPI.ts">
        """
        
        # Add to index.html
        index_file = self.public_dir / "index.html"
        if index_file.exists():
            with open(index_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Insert resource hints in head
            head_end = content.find('</head>')
            if head_end != -1:
                optimized_content = (
                    content[:head_end] + 
                    resource_hints.strip() + 
                    '\n' + 
                    content[head_end:]
                )
                
                with open(index_file, 'w', encoding='utf-8') as f:
                    f.write(optimized_content)
        
        logger.info("Implemented resource hints")
    
    async def generate_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance optimization report"""
        logger.info("Generating performance optimization report...")
        
        report = {
            'summary': {
                'total_optimizations': len(self.optimization_history),
                'successful_optimizations': len([o for o in self.optimization_history if o.status == 'success']),
                'total_improvement_percentage': 0,
                'current_metrics': {}
            },
            'optimization_history': [opt.to_dict() for opt in self.optimization_history],
            'current_status': {},
            'recommendations': [],
            'next_steps': [],
            'generated_at': datetime.now().isoformat()
        }
        
        # Calculate total improvement
        if self.optimization_history:
            total_improvement = sum(opt.improvement_percentage for opt in self.optimization_history)
            report['summary']['total_improvement_percentage'] = total_improvement / len(self.optimization_history)
        
        # Get current metrics
        current_metrics = await self._measure_current_performance()
        report['summary']['current_metrics'] = current_metrics
        
        # Analyze current status against thresholds
        status = await self._analyze_performance_status(current_metrics)
        report['current_status'] = status
        
        # Generate recommendations
        recommendations = self._generate_performance_recommendations(current_metrics, status)
        report['recommendations'] = recommendations
        
        # Generate next steps
        next_steps = self._generate_next_steps(status)
        report['next_steps'] = next_steps
        
        return report
    
    async def _analyze_performance_status(self, metrics: Dict[str, float]) -> Dict[str, str]:
        """Analyze current performance against thresholds"""
        status = {}
        
        # Bundle size analysis
        bundle_size = metrics.get('bundle_size_mb', 0)
        if bundle_size <= self.performance_thresholds['bundle_size_mb']:
            status['bundle_size'] = 'GOOD'
        elif bundle_size <= self.performance_thresholds['bundle_size_mb'] * 1.5:
            status['bundle_size'] = 'WARNING'
        else:
            status['bundle_size'] = 'CRITICAL'
        
        # Load time analysis
        estimated_load = metrics.get('estimated_load_ms', 0)
        if estimated_load <= self.performance_thresholds['initial_load_ms']:
            status['load_time'] = 'GOOD'
        elif estimated_load <= self.performance_thresholds['initial_load_ms'] * 1.5:
            status['load_time'] = 'WARNING'
        else:
            status['load_time'] = 'CRITICAL'
        
        # Asset count analysis
        asset_count = metrics.get('total_assets', 0)
        if asset_count <= 50:
            status['asset_count'] = 'GOOD'
        elif asset_count <= 100:
            status['asset_count'] = 'WARNING'
        else:
            status['asset_count'] = 'CRITICAL'
        
        return status
    
    def _generate_performance_recommendations(self, metrics: Dict[str, float], status: Dict[str, str]) -> List[str]:
        """Generate performance optimization recommendations"""
        recommendations = []
        
        if status.get('bundle_size') in ['WARNING', 'CRITICAL']:
            recommendations.append('Implement aggressive code splitting and tree shaking')
            recommendations.append('Review and remove unused dependencies')
        
        if status.get('load_time') in ['WARNING', 'CRITICAL']:
            recommendations.append('Implement service worker caching')
            recommendations.append('Consider CDN for static assets')
        
        if status.get('asset_count') in ['WARNING', 'CRITICAL']:
            recommendations.append('Consolidate small assets')
            recommendations.append('Implement asset bundling strategies')
        
        # Brazilian legislative specific recommendations
        recommendations.append('Optimize for Brazilian Portuguese text rendering')
        recommendations.append('Consider offline-first strategy for academic users')
        recommendations.append('Implement progressive loading for document viewer')
        
        return recommendations
    
    def _generate_next_steps(self, status: Dict[str, str]) -> List[str]:
        """Generate next steps for performance optimization"""
        next_steps = []
        
        # Determine priority based on status
        critical_issues = [k for k, v in status.items() if v == 'CRITICAL']
        warning_issues = [k for k, v in status.items() if v == 'WARNING']
        
        if critical_issues:
            next_steps.append(f'URGENT: Address critical performance issues in {", ".join(critical_issues)}')
        
        if warning_issues:
            next_steps.append(f'Monitor and improve warning areas: {", ".join(warning_issues)}')
        
        # Always include monitoring
        next_steps.append('Set up continuous performance monitoring')
        next_steps.append('Implement performance budgets in CI/CD')
        next_steps.append('Regular performance audits for Brazilian legislative data')
        
        return next_steps