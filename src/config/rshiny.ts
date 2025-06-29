// R Shiny Integration Configuration

export interface RShinyConfig {
  // Base configuration
  baseUrl: string;
  apiEndpoint: string;
  healthEndpoint: string;
  
  // Security settings
  allowedOrigins: string[];
  sandbox: string;
  allowFullscreen: boolean;
  
  // Connection settings
  sessionTimeout: number;
  retryAttempts: number;
  retryDelay: number;
  heartbeatInterval: number;
  
  // Data sync settings
  syncFiltersDelay: number;
  syncDocumentsDelay: number;
  maxQueueSize: number;
  
  // Performance settings
  enableWebSocket: boolean;
  enablePolling: boolean;
  pollingInterval: number;
  loadTimeout: number;
}

// Default configuration for different environments
const getDefaultConfig = (): RShinyConfig => ({
  baseUrl: process.env.REACT_APP_RSHINY_URL || 'http://localhost:3838',
  apiEndpoint: '/api/sync',
  healthEndpoint: '/health',
  
  // Security: restrictive iframe sandbox settings
  allowedOrigins: [
    'http://localhost:3838',
    'https://shinyapps.io',
    process.env.REACT_APP_RSHINY_URL || ''
  ].filter(Boolean),
  sandbox: 'allow-same-origin allow-scripts allow-forms allow-popups allow-pointer-lock',
  allowFullscreen: true,
  
  // Connection settings - optimized for budget efficiency
  sessionTimeout: 30000, // 30 seconds
  retryAttempts: 3,
  retryDelay: 5000, // 5 seconds
  heartbeatInterval: 30000, // 30 seconds
  
  // Data sync settings - debounced for efficiency
  syncFiltersDelay: 1000, // 1 second
  syncDocumentsDelay: 2000, // 2 seconds
  maxQueueSize: 50,
  
  // Performance settings - polling-first for budget
  enableWebSocket: false, // Disabled for budget efficiency
  enablePolling: true,
  pollingInterval: 10000, // 10 seconds
  loadTimeout: 15000 // 15 seconds
});

// Development configuration
const developmentConfig: Partial<RShinyConfig> = {
  baseUrl: 'http://localhost:3838',
  allowedOrigins: ['http://localhost:3838', 'http://localhost:3000'],
  sandbox: 'allow-same-origin allow-scripts allow-forms allow-popups allow-pointer-lock allow-downloads',
  sessionTimeout: 60000, // 1 minute for development
  heartbeatInterval: 15000, // 15 seconds
  pollingInterval: 5000, // 5 seconds for faster dev feedback
  loadTimeout: 30000 // 30 seconds for development
};

// Production configuration
const productionConfig: Partial<RShinyConfig> = {
  // Use environment variable for production URL
  baseUrl: process.env.REACT_APP_RSHINY_URL || process.env.VITE_RSHINY_URL || 'https://monitor-legislativo-rshiny-production.up.railway.app',
  allowedOrigins: [
    'http://localhost:3838',
    'https://*.shinyapps.io',
    'https://sofiadonario.github.io',
    'https://sofiadonario.github.io/monitor-legislativo-v4',
    'https://monitor-legislativo-rshiny-production.up.railway.app',
    'https://*.up.railway.app'
  ],
  // More restrictive sandbox for production
  sandbox: 'allow-same-origin allow-scripts allow-forms allow-popups',
  sessionTimeout: 45000, // 45 seconds
  retryAttempts: 5,
  retryDelay: 3000, // 3 seconds
  heartbeatInterval: 30000, // 30 seconds
  pollingInterval: 15000, // 15 seconds for production efficiency
  maxQueueSize: 30,
  loadTimeout: 20000 // 20 seconds
};

// Testing configuration
const testConfig: Partial<RShinyConfig> = {
  baseUrl: 'http://localhost:3838',
  allowedOrigins: ['http://localhost:3838'],
  sandbox: 'allow-same-origin allow-scripts',
  sessionTimeout: 10000, // 10 seconds for faster tests
  retryAttempts: 1,
  retryDelay: 1000, // 1 second
  heartbeatInterval: 5000, // 5 seconds
  pollingInterval: 2000, // 2 seconds
  loadTimeout: 5000 // 5 seconds
};

// Get configuration based on environment
const getEnvironmentConfig = (): Partial<RShinyConfig> => {
  const env = process.env.NODE_ENV || 'development';
  
  switch (env) {
    case 'production':
      return productionConfig;
    case 'test':
      return testConfig;
    case 'development':
    default:
      return developmentConfig;
  }
};

// Create final configuration
export const rShinyConfig: RShinyConfig = {
  ...getDefaultConfig(),
  ...getEnvironmentConfig()
};

// Validation function
export const validateRShinyConfig = (config: RShinyConfig): { valid: boolean; errors: string[] } => {
  const errors: string[] = [];
  
  // Validate URL
  try {
    new URL(config.baseUrl);
  } catch {
    errors.push('Invalid baseUrl: must be a valid URL');
  }
  
  // Validate allowed origins
  config.allowedOrigins.forEach((origin, index) => {
    if (origin) {
      try {
        new URL(origin);
      } catch {
        errors.push(`Invalid allowedOrigins[${index}]: must be a valid URL`);
      }
    }
  });
  
  // Validate timeouts
  if (config.sessionTimeout < 5000) {
    errors.push('sessionTimeout must be at least 5000ms');
  }
  
  if (config.loadTimeout < 5000) {
    errors.push('loadTimeout must be at least 5000ms');
  }
  
  if (config.retryAttempts < 1 || config.retryAttempts > 10) {
    errors.push('retryAttempts must be between 1 and 10');
  }
  
  if (config.maxQueueSize < 1 || config.maxQueueSize > 100) {
    errors.push('maxQueueSize must be between 1 and 100');
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
};

// Helper function to check if origin is allowed
export const isOriginAllowed = (origin: string): boolean => {
  return rShinyConfig.allowedOrigins.some(allowedOrigin => {
    if (allowedOrigin === origin) return true;
    
    // Support wildcard subdomains
    if (allowedOrigin.startsWith('*.')) {
      const domain = allowedOrigin.slice(2);
      return origin.endsWith(`.${domain}`) || origin === domain;
    }
    
    return false;
  });
};

// Helper function to get iframe security attributes
export const getIframeSecurityAttributes = () => ({
  sandbox: rShinyConfig.sandbox,
  allowFullScreen: rShinyConfig.allowFullscreen,
  // Additional security headers
  referrerPolicy: 'strict-origin-when-cross-origin' as const,
  loading: 'lazy' as const
});

// Function to build R Shiny URL with security parameters
export const buildRShinyUrl = (sessionId: string, additionalParams: Record<string, string> = {}): string => {
  const url = new URL(rShinyConfig.baseUrl);
  
  // Add session ID
  url.searchParams.set('session', sessionId);
  url.searchParams.set('source', 'react');
  url.searchParams.set('timestamp', Date.now().toString());
  
  // Add additional parameters
  Object.entries(additionalParams).forEach(([key, value]) => {
    url.searchParams.set(key, value);
  });
  
  return url.toString();
};

// Function to validate and sanitize sync data
export const sanitizeSyncData = (data: any): any => {
  if (typeof data !== 'object' || data === null) {
    return {};
  }
  
  // Remove potentially dangerous properties
  const sanitized = { ...data };
  delete sanitized.__proto__;
  delete sanitized.constructor;
  
  // Recursively sanitize nested objects
  Object.keys(sanitized).forEach(key => {
    if (typeof sanitized[key] === 'object' && sanitized[key] !== null) {
      sanitized[key] = sanitizeSyncData(sanitized[key]);
    }
  });
  
  return sanitized;
};

// Export configuration for debugging (development only)
if (process.env.NODE_ENV === 'development') {
  console.log('R Shiny Configuration:', rShinyConfig);
  
  const validation = validateRShinyConfig(rShinyConfig);
  if (!validation.valid) {
    console.warn('R Shiny Configuration Issues:', validation.errors);
  }
}

export default rShinyConfig;