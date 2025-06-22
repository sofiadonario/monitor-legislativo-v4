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
  production: import.meta.env.VITE_API_URL || 'https://monitor-legislativo-v4-production.up.railway.app', // Railway backend
  staging: import.meta.env.VITE_API_URL || 'https://monitor-legislativo-v4-production.up.railway.app'
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
  
  // Data endpoints
  search: '/api/v1/search',
  sources: '/api/v1/sources',
  
  // Export endpoints (coming soon)
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