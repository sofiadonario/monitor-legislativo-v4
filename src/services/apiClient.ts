// API Client with caching and error handling
import { SearchFilters } from '../types/types';
import { getApiBaseUrl, API_CONFIG } from '../config/api';

interface CacheEntry<T> {
  data: T;
  timestamp: number;
}

interface ApiConfig {
  baseUrl: string;
  version: string;
  timeout?: number;
  retries?: number;
  cacheEnabled?: boolean;
  cacheTTL?: number;
}

export class ApiClient {
  private config: Required<ApiConfig>;
  private cache: Map<string, CacheEntry<any>> = new Map();
  
  constructor(config: ApiConfig) {
    this.config = {
      baseUrl: config.baseUrl,
      version: config.version,
      timeout: config.timeout ?? 30000,
      retries: config.retries ?? 3,
      cacheEnabled: config.cacheEnabled ?? true,
      cacheTTL: config.cacheTTL ?? 300000 // 5 minutes
    };
  }
  
  private getCacheKey(endpoint: string, params?: any): string {
    return `${endpoint}:${JSON.stringify(params || {})}`;
  }
  
  private getFromCache<T>(key: string): T | null {
    if (!this.config.cacheEnabled) return null;
    
    const entry = this.cache.get(key);
    if (!entry) return null;
    
    const now = Date.now();
    if (now - entry.timestamp > this.config.cacheTTL) {
      this.cache.delete(key);
      return null;
    }
    
    return entry.data as T;
  }
  
  private saveToCache<T>(key: string, data: T): void {
    if (!this.config.cacheEnabled) return;
    
    this.cache.set(key, {
      data,
      timestamp: Date.now()
    });
  }
  
  private async fetchWithRetry(
    url: string,
    options: RequestInit,
    retries: number = this.config.retries
  ): Promise<Response> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);
    
    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      
      if (response.ok) {
        return response;
      }
      
      // Don't retry on client errors (4xx)
      if (response.status >= 400 && response.status < 500) {
        throw new ApiError(
          `API Error: ${response.status} ${response.statusText}`,
          response.status
        );
      }
      
      // Retry on server errors (5xx)
      if (retries > 0 && response.status >= 500) {
        await this.delay(1000 * (this.config.retries - retries + 1));
        return this.fetchWithRetry(url, options, retries - 1);
      }
      
      throw new ApiError(
        `API Error: ${response.status} ${response.statusText}`,
        response.status
      );
    } catch (error) {
      clearTimeout(timeoutId);
      
      if (error instanceof ApiError) {
        throw error;
      }
      
      if (error instanceof Error) {
        if (error.name === 'AbortError') {
          throw new ApiError('Request timeout', 0);
        }
        
        // Network error - retry
        if (retries > 0) {
          await this.delay(1000 * (this.config.retries - retries + 1));
          return this.fetchWithRetry(url, options, retries - 1);
        }
      }
      
      throw new ApiError('Network error', 0);
    }
  }
  
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
  
  async get<T>(endpoint: string, params?: Record<string, any>): Promise<T> {
    const cacheKey = this.getCacheKey(endpoint, params);
    const cached = this.getFromCache<T>(cacheKey);
    
    if (cached !== null) {
      return cached;
    }
    
    const queryString = params ? `?${new URLSearchParams(params).toString()}` : '';
    const url = `${this.config.baseUrl}/api/${this.config.version}${endpoint}${queryString}`;
    
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      }
    });
    
    const data = await response.json();
    this.saveToCache(cacheKey, data);
    
    return data;
  }
  
  async post<T>(endpoint: string, body: any): Promise<T> {
    const url = `${this.config.baseUrl}/api/${this.config.version}${endpoint}`;
    
    const response = await this.fetchWithRetry(url, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body)
    });
    
    return response.json();
  }
  
  clearCache(): void {
    this.cache.clear();
  }
  
  clearCacheForEndpoint(endpoint: string): void {
    const keysToDelete: string[] = [];
    
    for (const key of this.cache.keys()) {
      if (key.startsWith(endpoint + ':')) {
        keysToDelete.push(key);
      }
    }
    
    keysToDelete.forEach(key => this.cache.delete(key));
  }
}

export class ApiError extends Error {
  constructor(message: string, public statusCode: number) {
    super(message);
    this.name = 'ApiError';
  }
}

// Create singleton instance
const apiClient = new ApiClient({
  baseUrl: getApiBaseUrl(),
  version: 'v1',
  timeout: API_CONFIG.timeout,
  cacheEnabled: import.meta.env.VITE_CACHE_ENABLED !== 'false',
  cacheTTL: Number(import.meta.env.VITE_CACHE_TTL) || 300000
});

export default apiClient;