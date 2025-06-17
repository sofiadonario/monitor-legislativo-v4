/**
 * Cached Fetch Utility for Monitor Legislativo
 * Implements intelligent fetch with caching, retry, and fallback strategies
 */

import React from 'react';
import { localCache, cacheUtils } from './localCache';

interface FetchOptions extends RequestInit {
  cache?: 'default' | 'no-store' | 'reload' | 'no-cache' | 'force-cache' | 'only-if-cached';
  ttl?: number;
  retry?: number;
  timeout?: number;
  fallbackToCache?: boolean;
}

interface CacheConfig {
  '/api/v1/search': { ttl: 900000, priority: 'high' };  // 15 minutes
  '/api/v1/proposals': { ttl: 7200000, priority: 'high' };  // 2 hours
  '/api/v1/sources': { ttl: 86400000, priority: 'low' };  // 24 hours
  '/api/v1/geography': { ttl: 2592000000, priority: 'low' };  // 30 days
  '/api/v1/export': { ttl: 1800000, priority: 'medium' };  // 30 minutes
}

const CACHE_CONFIG: Partial<CacheConfig> = {
  '/api/v1/search': { ttl: 900000, priority: 'high' },
  '/api/v1/proposals': { ttl: 7200000, priority: 'high' },
  '/api/v1/sources': { ttl: 86400000, priority: 'low' },
  '/api/v1/geography': { ttl: 2592000000, priority: 'low' },
  '/api/v1/export': { ttl: 1800000, priority: 'medium' }
};

class CachedFetch {
  private abortControllers: Map<string, AbortController> = new Map();
  private pendingRequests: Map<string, Promise<any>> = new Map();

  /**
   * Enhanced fetch with caching support
   */
  async fetch<T = any>(url: string, options: FetchOptions = {}): Promise<T> {
    const {
      ttl,
      retry = 3,
      timeout = 30000,
      fallbackToCache = true,
      ...fetchOptions
    } = options;

    // Generate cache key
    const cacheKey = this.generateCacheKey(url, fetchOptions);

    // Check if request is already pending (dedupe)
    const pending = this.pendingRequests.get(cacheKey);
    if (pending) {
      return pending;
    }

    // Try cache first for GET requests
    if (!fetchOptions.method || fetchOptions.method === 'GET') {
      const cached = localCache.get<T>(cacheKey);
      if (cached !== null) {
        // Check if we have X-Cache header support
        if ('headers' in cached && (cached as any).headers?.['X-Cache']) {
          console.log(`Cache HIT: ${url}`);
        }
        return cached;
      }
    }

    // Create abort controller for timeout
    const abortController = new AbortController();
    this.abortControllers.set(cacheKey, abortController);

    // Set timeout
    const timeoutId = setTimeout(() => {
      abortController.abort();
    }, timeout);

    // Create fetch promise
    const fetchPromise = this.fetchWithRetry(url, {
      ...fetchOptions,
      signal: abortController.signal
    }, retry)
      .then(async response => {
        clearTimeout(timeoutId);
        
        // Check cache headers
        const cacheStatus = response.headers.get('X-Cache') || 'MISS';
        const cacheTime = response.headers.get('X-Cache-Time');
        
        console.log(`API ${cacheStatus}: ${url}`);

        // Parse response
        const data = await response.json();

        // Cache successful responses
        if (response.ok && (!fetchOptions.method || fetchOptions.method === 'GET')) {
          const cacheTTL = ttl || this.getTTLForURL(url);
          localCache.set(cacheKey, data, cacheTTL);
          
          // Also set stale cache for fallback
          localCache.set(`stale_${cacheKey}`, data, cacheTTL * 2);
        }

        return data;
      })
      .catch(async error => {
        clearTimeout(timeoutId);
        
        // Try fallback to cache if enabled
        if (fallbackToCache && (!fetchOptions.method || fetchOptions.method === 'GET')) {
          // Try regular cache first
          const cached = localCache.get<T>(cacheKey);
          if (cached !== null) {
            console.warn(`Using cached data due to error: ${url}`);
            return cached;
          }

          // Try stale cache
          const stale = localCache.get<T>(`stale_${cacheKey}`);
          if (stale !== null) {
            console.warn(`Using stale cache due to error: ${url}`);
            return stale;
          }
        }

        throw error;
      })
      .finally(() => {
        this.abortControllers.delete(cacheKey);
        this.pendingRequests.delete(cacheKey);
      });

    // Store pending request
    this.pendingRequests.set(cacheKey, fetchPromise);

    return fetchPromise;
  }

  /**
   * Fetch with retry logic
   */
  private async fetchWithRetry(
    url: string,
    options: RequestInit,
    retries: number
  ): Promise<Response> {
    let lastError: Error | null = null;

    for (let i = 0; i <= retries; i++) {
      try {
        const response = await fetch(url, options);
        
        // Retry on 5xx errors
        if (response.status >= 500 && i < retries) {
          await this.delay(Math.min(1000 * Math.pow(2, i), 10000)); // Exponential backoff
          continue;
        }

        return response;
      } catch (error) {
        lastError = error as Error;
        
        // Don't retry on abort
        if (error instanceof Error && error.name === 'AbortError') {
          throw error;
        }

        // Retry with backoff
        if (i < retries) {
          await this.delay(Math.min(1000 * Math.pow(2, i), 10000));
          continue;
        }
      }
    }

    throw lastError || new Error('Fetch failed');
  }

  /**
   * Generate cache key from URL and options
   */
  private generateCacheKey(url: string, options: RequestInit): string {
    const key = {
      url,
      method: options.method || 'GET',
      body: options.body ? JSON.stringify(options.body) : undefined
    };

    return cacheUtils.generateKey('fetch', key);
  }

  /**
   * Get TTL for URL based on configuration
   */
  private getTTLForURL(url: string): number {
    // Check exact match
    const urlPath = new URL(url, window.location.origin).pathname;
    const config = CACHE_CONFIG[urlPath as keyof CacheConfig];
    if (config) {
      return config.ttl;
    }

    // Check pattern match
    for (const [pattern, config] of Object.entries(CACHE_CONFIG)) {
      if (urlPath.startsWith(pattern)) {
        return config.ttl;
      }
    }

    // Default TTL
    return 900000; // 15 minutes
  }

  /**
   * Delay helper
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Cancel pending request
   */
  cancel(url: string): void {
    const cacheKey = this.generateCacheKey(url, {});
    const controller = this.abortControllers.get(cacheKey);
    if (controller) {
      controller.abort();
    }
  }

  /**
   * Prefetch URLs
   */
  async prefetch(urls: string[]): Promise<void> {
    const promises = urls.map(url => 
      this.fetch(url, { fallbackToCache: true }).catch(() => {
        // Silently fail prefetch
      })
    );

    await Promise.all(promises);
  }

  /**
   * Clear cache for specific patterns
   */
  clearCache(pattern?: string): void {
    if (pattern) {
      const keys = Object.keys(localStorage)
        .filter(key => key.includes(pattern));
      keys.forEach(key => localStorage.removeItem(key));
    } else {
      cacheUtils.clearAPICache();
    }
  }

  /**
   * Get cache statistics
   */
  getCacheStats() {
    return localCache.getStats();
  }
}

// Export singleton instance
export const cachedFetch = new CachedFetch();

// Export convenience functions
export const fetchJSON = <T = any>(url: string, options?: FetchOptions): Promise<T> => 
  cachedFetch.fetch<T>(url, options);

export const prefetchURLs = (urls: string[]): Promise<void> => 
  cachedFetch.prefetch(urls);

export const cancelRequest = (url: string): void => 
  cachedFetch.cancel(url);

// React hook for cached fetch
export function useCachedFetch<T = any>(url: string | null, options?: FetchOptions) {
  const [data, setData] = React.useState<T | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<Error | null>(null);

  React.useEffect(() => {
    if (!url) return;

    let cancelled = false;

    const fetchData = async () => {
      setLoading(true);
      setError(null);

      try {
        const result = await cachedFetch.fetch<T>(url, options);
        if (!cancelled) {
          setData(result);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err as Error);
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    fetchData();

    return () => {
      cancelled = true;
      cachedFetch.cancel(url);
    };
  }, [url]);

  return { data, loading, error, refetch: () => cachedFetch.fetch<T>(url!, options) };
}

// Prefetch common endpoints on app load
export const warmCache = async () => {
  const commonEndpoints = [
    '/api/v1/sources',
    '/api/v1/geography/states',
    '/api/v1/document-types'
  ];

  await prefetchURLs(commonEndpoints);
};