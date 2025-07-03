/**
 * API Configuration for Monitor Legislativo
 * Frontend to Railway Backend Integration
 */

// Environment configuration
const isDevelopment = import.meta.env.MODE === 'development';
const isProduction = import.meta.env.MODE === 'production';

// API Base URLs  
const API_URLS = {
  development: 'http://localhost:8000', // Local development backend
  production: 'https://backend-api-production-2392.up.railway.app', // Railway backend
  staging: import.meta.env.VITE_API_URL || 'https://monitor-legislativo-v4-production-7e46.up.railway.app'
};

// Get current API base URL
export const getApiBaseUrl = (): string => {
  if (isDevelopment) return API_URLS.development;
  if (isProduction) return API_URLS.production;
  return API_URLS.staging;
};

// API Endpoints
export const API_ENDPOINTS = {
  // Health and status
  health: '/health',
  status: '/api/docs',
  
  // Core data endpoints
  search: '/lexml/search',
  sources: '/api/v1/sources',
  
  // Geographic endpoints (Week 1)
  geographic: {
    search: '/api/v1/geographic/search',
    municipalities: '/api/v1/geographic/municipalities',
    states: '/api/v1/geographic/states',
    statistics: '/api/v1/geographic/statistics',
    health: '/api/v1/geographic/health'
  },
  
  // ML Analysis endpoints (Week 1)
  ml: {
    analyze: '/api/v1/ml/analyze',
    classify: '/api/v1/ml/classify',
    similarity: '/api/v1/ml/similarity',
    keywords: '/api/v1/ml/keywords',
    statistics: '/api/v1/ml/statistics',
    health: '/api/v1/ml/health'
  },
  
  // Advanced Geocoding endpoints (Week 2)
  geocoding: {
    forward: '/api/v1/geocoding/forward',
    reverse: '/api/v1/geocoding/reverse',
    validate: '/api/v1/geocoding/validate',
    municipalities: '/api/v1/geocoding/municipalities',
    precision: '/api/v1/geocoding/precision',
    batch: '/api/v1/geocoding/batch',
    statistics: '/api/v1/geocoding/statistics',
    health: '/api/v1/geocoding/health'
  },
  
  // Document Validation endpoints (Week 2)
  validation: {
    document: '/api/v1/validation/document',
    batch: '/api/v1/validation/batch',
    urn: '/api/v1/validation/urn',
    qualityReport: '/api/v1/validation/quality-report',
    rules: '/api/v1/validation/rules',
    statistics: '/api/v1/validation/statistics',
    health: '/api/v1/validation/health'
  },
  
  // AI Agents endpoints (Week 3)
  ai: {
    agents: '/api/v1/ai/agents',
    query: '/api/v1/ai/agents/{agent_id}/query',
    status: '/api/v1/ai/agents/{agent_id}/status',
    systemStatus: '/api/v1/ai/system/status',
    memorySearch: '/api/v1/ai/memory/search',
    memoryOptimize: '/api/v1/ai/memory/optimize',
    memoryPerformance: '/api/v1/ai/memory/performance/{agent_id}',
    memoryBackup: '/api/v1/ai/memory/backup/{agent_id}',
    roles: '/api/v1/ai/roles',
    health: '/api/v1/ai/health'
  },
  
  // AI Document Analysis endpoints (Week 4)
  aiAnalysis: {
    analyze: '/api/v1/ai-analysis/analyze',
    summarize: '/api/v1/ai-analysis/summarize',
    extractMetadata: '/api/v1/ai-analysis/extract-metadata',
    analyzeContent: '/api/v1/ai-analysis/analyze-content',
    discoverRelationships: '/api/v1/ai-analysis/discover-relationships',
    generateCitation: '/api/v1/ai-analysis/generate-citation',
    batchCitations: '/api/v1/ai-analysis/generate-citations-batch',
    citationStyles: '/api/v1/ai-analysis/citation-styles',
    analysisStatistics: '/api/v1/ai-analysis/analysis-statistics',
    citationStatistics: '/api/v1/ai-analysis/citation-statistics',
    health: '/api/v1/ai-analysis/health'
  },
  
  // Vocabulary endpoints (Sprint 1)
  vocabulary: {
    search: '/api/v1/vocabulary/search',
    concept: '/api/v1/vocabulary/concept',
    broader: '/api/v1/vocabulary/concept/{concept_uri}/broader',
    narrower: '/api/v1/vocabulary/concept/{concept_uri}/narrower',
    related: '/api/v1/vocabulary/concept/{concept_uri}/related',
    expandQuery: '/api/v1/vocabulary/expand-query',
    schemes: '/api/v1/vocabulary/schemes',
    scheme: '/api/v1/vocabulary/scheme',
    export: '/api/v1/vocabulary/export/skos-rdf',
    health: '/api/v1/vocabulary/health'
  },
  
  // Document Analysis endpoints (Sprint 2)
  documentAnalysis: {
    content: '/api/v1/ai-analysis/analyze',
    metadata: '/api/v1/ai-analysis/extract-metadata',
    crossReferences: '/api/v1/ai-analysis/discover-relationships',
    similarDocuments: '/api/v1/ml/similarity',
    qualityScore: '/api/v1/validation/document',
    citation: '/api/v1/ai-analysis/generate-citation',
    batchCitations: '/api/v1/ai-analysis/generate-citations-batch',
    citationStyles: '/api/v1/ai-analysis/citation-styles',
    comparison: '/api/v1/ai-analysis/compare-documents',
    health: '/api/v1/ai-analysis/health'
  },
  
  // Export endpoints
  export: '/api/v1/export',
  exportCSV: '/api/v1/export/csv',
  exportXLSX: '/api/v1/export/xlsx',
  
  // Cache management
  cacheClear: '/api/v1/cache/clear'
};

// Build full API URL
export const buildApiUrl = (endpoint: string, params?: Record<string, string>): string => {
  const baseUrl = getApiBaseUrl();
  let url = `${baseUrl}${endpoint}`;
  
  if (params) {
    const searchParams = new URLSearchParams(params);
    url += `?${searchParams.toString()}`;
  }
  
  return url;
};

// API Configuration
export const API_CONFIG = {
  baseUrl: getApiBaseUrl(),
  timeout: 30000, // 30 seconds
  retry: 3,
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'X-Client': 'monitor-legislativo-frontend',
    'X-Version': '4.0.0'
  }
};

// CORS configuration for development
export const CORS_CONFIG = {
  credentials: 'same-origin' as RequestCredentials,
  mode: 'cors' as RequestMode
};

console.log(`API Configuration initialized:`, {
  mode: import.meta.env.MODE,
  baseUrl: getApiBaseUrl(),
  isDevelopment,
  isProduction
});