/**
 * R-Shiny Configuration for Monitor Legislativo
 * Integration with Railway R-Shiny Analytics Service
 */

// Environment configuration
const isDevelopment = import.meta.env.MODE === 'development';
const isProduction = import.meta.env.MODE === 'production';

// R-Shiny Service URLs
const RSHINY_URLS = {
  development: 'http://localhost:3838', // Local R-Shiny development
  production: 'https://monitor-legislativo-unified-production.up.railway.app', // Production R-Shiny on Railway
  staging: import.meta.env.VITE_RSHINY_URL || 'https://monitor-legislativo-unified-production.up.railway.app'
};

// Get current R-Shiny base URL
export const getRShinyBaseUrl = (): string => {
  if (isDevelopment) return RSHINY_URLS.development;
  if (isProduction) return RSHINY_URLS.production;
  return RSHINY_URLS.staging;
};

// R-Shiny Configuration
export const RSHINY_CONFIG = {
  baseUrl: getRShinyBaseUrl(),
  timeout: 60000, // 60 seconds for R-Shiny apps
  retryAttempts: 2,
  healthCheckInterval: 30000, // 30 seconds
  headers: {
    'X-Client': 'monitor-legislativo-frontend',
    'X-Version': '4.0.0'
  }
};

// R-Shiny Endpoints
export const RSHINY_ENDPOINTS = {
  health: '/health',
  analytics: '/analytics',
  dashboard: '/dashboard',
  maps: '/maps',
  exports: '/exports',
  api: '/api'
};

// Build R-Shiny URL
export const buildRShinyUrl = (endpoint: string = ''): string => {
  const baseUrl = getRShinyBaseUrl();
  return `${baseUrl}${endpoint}`;
};

console.log(`R-Shiny Configuration initialized:`, {
  mode: import.meta.env.MODE,
  baseUrl: getRShinyBaseUrl(),
  isDevelopment,
  isProduction
});