const isDevelopment = false;
const isProduction = true;
const API_URLS = {
  // Local development backend
  production: "https://monitor-legislativo-v4-production.up.railway.app"
};
const getApiBaseUrl = () => {
  return API_URLS.production;
};
const API_ENDPOINTS = {
  // Document Validation endpoints (Week 2)
  validation: {
    document: "/api/v1/validation/document",
    batch: "/api/v1/validation/batch",
    urn: "/api/v1/validation/urn",
    qualityReport: "/api/v1/validation/quality-report",
    rules: "/api/v1/validation/rules",
    statistics: "/api/v1/validation/statistics",
    health: "/api/v1/validation/health"
  },
  // AI Agents endpoints (Week 3)
  ai: {
    agents: "/api/v1/ai/agents",
    query: "/api/v1/ai/agents/{agent_id}/query",
    status: "/api/v1/ai/agents/{agent_id}/status",
    systemStatus: "/api/v1/ai/system/status",
    memorySearch: "/api/v1/ai/memory/search",
    memoryOptimize: "/api/v1/ai/memory/optimize",
    memoryPerformance: "/api/v1/ai/memory/performance/{agent_id}",
    memoryBackup: "/api/v1/ai/memory/backup/{agent_id}",
    roles: "/api/v1/ai/roles",
    health: "/api/v1/ai/health"
  },
  // AI Document Analysis endpoints (Week 4)
  aiAnalysis: {
    analyze: "/api/v1/ai-analysis/analyze",
    summarize: "/api/v1/ai-analysis/summarize",
    extractMetadata: "/api/v1/ai-analysis/extract-metadata",
    analyzeContent: "/api/v1/ai-analysis/analyze-content",
    discoverRelationships: "/api/v1/ai-analysis/discover-relationships",
    generateCitation: "/api/v1/ai-analysis/generate-citation",
    batchCitations: "/api/v1/ai-analysis/generate-citations-batch",
    citationStyles: "/api/v1/ai-analysis/citation-styles",
    analysisStatistics: "/api/v1/ai-analysis/analysis-statistics",
    citationStatistics: "/api/v1/ai-analysis/citation-statistics",
    health: "/api/v1/ai-analysis/health"
  }
};
const buildApiUrl = (endpoint, params) => {
  const baseUrl = getApiBaseUrl();
  let url = `${baseUrl}${endpoint}`;
  return url;
};
const API_CONFIG = {
  baseUrl: getApiBaseUrl(),
  timeout: 3e4,
  headers: {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "X-Client": "monitor-legislativo-frontend",
    "X-Version": "4.0.0"
  }
};
const CORS_CONFIG = {
  credentials: "same-origin",
  mode: "cors"
};
console.log(`API Configuration initialized:`, {
  mode: "production",
  baseUrl: getApiBaseUrl(),
  isDevelopment,
  isProduction
});
export {
  API_CONFIG as A,
  CORS_CONFIG as C,
  API_ENDPOINTS as a,
  buildApiUrl as b,
  getApiBaseUrl as g
};
