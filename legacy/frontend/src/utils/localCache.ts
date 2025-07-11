/**
 * Local Cache Utility for Monitor Legislativo
 * Implements browser-based caching with localStorage
 */

interface CacheItem<T> {
  value: T;
  expires: number;
  version: string;
  size?: number;
}

interface CacheStats {
  hits: number;
  misses: number;
  itemCount: number;
  totalSize: number;
}

export class LocalCache {
  private readonly prefix: string = 'legislativo_';
  private readonly maxAge: number = 3600000; // 1 hour default
  private readonly maxSize: number = 5 * 1024 * 1024; // 5MB max
  private readonly version: string = '1.0.0';
  private stats: CacheStats = {
    hits: 0,
    misses: 0,
    itemCount: 0,
    totalSize: 0
  };

  constructor(options?: {
    prefix?: string;
    maxAge?: number;
    maxSize?: number;
    version?: string;
  }) {
    if (options?.prefix) this.prefix = options.prefix;
    if (options?.maxAge) this.maxAge = options.maxAge;
    if (options?.maxSize) this.maxSize = options.maxSize;
    if (options?.version) this.version = options.version;
    
    // Initialize stats
    this.updateStats();
    
    // Clean up on initialization
    this.cleanup();
  }

  /**
   * Set item in cache
   */
  set<T>(key: string, value: T, ttl: number = this.maxAge): boolean {
    try {
      const item: CacheItem<T> = {
        value,
        expires: Date.now() + ttl,
        version: this.version,
        size: this.estimateSize(value)
      };
      
      const serialized = JSON.stringify(item);
      const fullKey = this.prefix + key;
      
      // Check size before storing
      if (serialized.length > this.maxSize) {
        console.warn(`Cache item too large: ${key}`);
        return false;
      }
      
      // Check if we need to make space
      const currentSize = this.getTotalSize();
      if (currentSize + serialized.length > this.maxSize) {
        this.evictOldest(serialized.length);
      }
      
      localStorage.setItem(fullKey, serialized);
      this.updateStats();
      
      return true;
    } catch (e) {
      if (e instanceof Error && e.name === 'QuotaExceededError') {
        console.warn('LocalStorage quota exceeded, cleaning up...');
        this.cleanup();
        
        // Try once more after cleanup
        try {
          const item: CacheItem<T> = {
            value,
            expires: Date.now() + ttl,
            version: this.version
          };
          localStorage.setItem(this.prefix + key, JSON.stringify(item));
          return true;
        } catch {
          return false;
        }
      }
      
      console.error('Cache set error:', e);
      return false;
    }
  }

  /**
   * Get item from cache
   */
  get<T>(key: string): T | null {
    try {
      const fullKey = this.prefix + key;
      const item = localStorage.getItem(fullKey);
      
      if (!item) {
        this.stats.misses++;
        return null;
      }
      
      const data: CacheItem<T> = JSON.parse(item);
      
      // Check expiration
      if (data.expires < Date.now()) {
        localStorage.removeItem(fullKey);
        this.stats.misses++;
        this.updateStats();
        return null;
      }
      
      // Check version
      if (data.version !== this.version) {
        localStorage.removeItem(fullKey);
        this.stats.misses++;
        this.updateStats();
        return null;
      }
      
      this.stats.hits++;
      return data.value;
    } catch (e) {
      console.error('Cache get error:', e);
      this.stats.misses++;
      return null;
    }
  }

  /**
   * Get or fetch pattern
   */
  async getOrFetch<T>(
    key: string,
    fetchFn: () => Promise<T>,
    ttl: number = this.maxAge
  ): Promise<T> {
    // Try cache first
    const cached = this.get<T>(key);
    if (cached !== null) {
      return cached;
    }
    
    // Fetch fresh data
    try {
      const data = await fetchFn();
      this.set(key, data, ttl);
      return data;
    } catch (error) {
      // Try stale cache as fallback
      const staleKey = `stale_${key}`;
      const stale = this.get<T>(staleKey);
      if (stale !== null) {
        console.warn('Using stale cache for:', key);
        return stale;
      }
      
      throw error;
    }
  }

  /**
   * Remove item from cache
   */
  remove(key: string): void {
    localStorage.removeItem(this.prefix + key);
    this.updateStats();
  }

  /**
   * Clear all cache items with this prefix
   */
  clear(): void {
    const keys = this.getAllKeys();
    keys.forEach(key => localStorage.removeItem(key));
    this.updateStats();
  }

  /**
   * Clean up expired items
   */
  cleanup(): void {
    const now = Date.now();
    const keys = this.getAllKeys();
    
    keys.forEach(key => {
      try {
        const item = localStorage.getItem(key);
        if (item) {
          const data: CacheItem<any> = JSON.parse(item);
          if (data.expires < now || data.version !== this.version) {
            localStorage.removeItem(key);
          }
        }
      } catch (e) {
        // Invalid item, remove it
        localStorage.removeItem(key);
      }
    });
    
    this.updateStats();
  }

  /**
   * Get cache statistics
   */
  getStats(): CacheStats & { hitRate: number } {
    const total = this.stats.hits + this.stats.misses;
    const hitRate = total > 0 ? (this.stats.hits / total) * 100 : 0;
    
    return {
      ...this.stats,
      hitRate
    };
  }

  /**
   * Batch operations
   */
  async getBatch<T>(keys: string[]): Promise<Map<string, T | null>> {
    const results = new Map<string, T | null>();
    
    keys.forEach(key => {
      results.set(key, this.get<T>(key));
    });
    
    return results;
  }

  setBatch<T>(items: Map<string, { value: T; ttl?: number }>): void {
    items.forEach((item, key) => {
      this.set(key, item.value, item.ttl || this.maxAge);
    });
  }

  /**
   * Cache warming
   */
  async warm(keys: string[], fetchFn: (key: string) => Promise<any>): Promise<void> {
    const promises = keys.map(async key => {
      const cached = this.get(key);
      if (cached === null) {
        try {
          const data = await fetchFn(key);
          this.set(key, data);
        } catch (e) {
          console.error(`Failed to warm cache for key: ${key}`, e);
        }
      }
    });
    
    await Promise.all(promises);
  }

  /**
   * Private helper methods
   */
  private getAllKeys(): string[] {
    return Object.keys(localStorage).filter(key => key.startsWith(this.prefix));
  }

  private getTotalSize(): number {
    let total = 0;
    this.getAllKeys().forEach(key => {
      const item = localStorage.getItem(key);
      if (item) {
        total += item.length;
      }
    });
    return total;
  }

  private estimateSize(value: any): number {
    try {
      return JSON.stringify(value).length;
    } catch {
      return 0;
    }
  }

  private evictOldest(requiredSpace: number): void {
    const items: Array<{ key: string; expires: number; size: number }> = [];
    
    this.getAllKeys().forEach(key => {
      try {
        const item = localStorage.getItem(key);
        if (item) {
          const data = JSON.parse(item);
          items.push({
            key,
            expires: data.expires || 0,
            size: item.length
          });
        }
      } catch {
        // Invalid item, remove it
        localStorage.removeItem(key);
      }
    });
    
    // Sort by expiration time (oldest first)
    items.sort((a, b) => a.expires - b.expires);
    
    let freedSpace = 0;
    for (const item of items) {
      if (freedSpace >= requiredSpace) break;
      
      localStorage.removeItem(item.key);
      freedSpace += item.size;
    }
  }

  private updateStats(): void {
    const keys = this.getAllKeys();
    this.stats.itemCount = keys.length;
    this.stats.totalSize = this.getTotalSize();
  }
}

// Export singleton instance
export const localCache = new LocalCache({
  prefix: 'legislativo_',
  maxAge: 3600000, // 1 hour
  maxSize: 5 * 1024 * 1024, // 5MB
  version: '1.0.0'
});

// Export cache utilities
export const cacheUtils = {
  /**
   * Generate cache key from parameters
   */
  generateKey(prefix: string, params: Record<string, any>): string {
    const sorted = Object.keys(params)
      .sort()
      .map(key => `${key}:${params[key]}`)
      .join('_');
    return `${prefix}_${sorted}`;
  },

  /**
   * Cache API response
   */
  async cacheAPIResponse<T>(
    url: string,
    options?: RequestInit,
    ttl: number = 900000 // 15 minutes
  ): Promise<T> {
    const cacheKey = cacheUtils.generateKey('api', { url, method: options?.method || 'GET' });
    
    return localCache.getOrFetch(
      cacheKey,
      async () => {
        const response = await fetch(url, options);
        if (!response.ok) {
          throw new Error(`API error: ${response.statusText}`);
        }
        return response.json();
      },
      ttl
    );
  },

  /**
   * Clear API cache
   */
  clearAPICache(): void {
    const keys = Object.keys(localStorage)
      .filter(key => key.startsWith('legislativo_api_'));
    
    keys.forEach(key => localStorage.removeItem(key));
  }
};