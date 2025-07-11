/**
 * Frontend Multi-Tier Caching Service
 * Implements browser-level caching for LexML API responses
 */

interface CacheItem<T> {
  data: T;
  timestamp: number;
  expiresAt: number;
  accessCount: number;
  lastAccessed: number;
}

interface CacheStats {
  totalItems: number;
  memoryUsage: number;
  hitRate: number;
  missRate: number;
  evictions: number;
}

export class CacheService {
  private memoryCache = new Map<string, CacheItem<any>>();
  private stats = {
    hits: 0,
    misses: 0,
    evictions: 0,
    totalRequests: 0
  };
  
  // Cache configuration
  private readonly config = {
    // TTLs in milliseconds
    searchResults: 5 * 60 * 1000,        // 5 minutes
    documentContent: 30 * 60 * 1000,     // 30 minutes
    suggestions: 10 * 60 * 1000,         // 10 minutes
    healthStatus: 2 * 60 * 1000,         // 2 minutes
    crossReferences: 60 * 60 * 1000,     // 1 hour
    relatedDocuments: 20 * 60 * 1000,    // 20 minutes
    
    // Memory limits
    maxMemoryItems: 1000,
    maxItemSizeBytes: 1024 * 1024, // 1MB per item
    
    // Persistence
    persistToLocalStorage: true,
    localStoragePrefix: 'lexmlCache_'
  };

  constructor() {
    // Load persisted cache on initialization
    this.loadFromLocalStorage();
    
    // Setup periodic cleanup
    setInterval(() => this.cleanup(), 60000); // Every minute
    
    // Setup storage event listener for cross-tab cache sync
    if (typeof window !== 'undefined') {
      window.addEventListener('storage', this.handleStorageEvent.bind(this));
    }
  }

  /**
   * Get item from cache with automatic expiration check
   */
  get<T>(key: string): T | null {
    this.stats.totalRequests++;
    
    const item = this.memoryCache.get(key);
    
    if (!item) {
      this.stats.misses++;
      return this.getFromLocalStorage<T>(key);
    }
    
    // Check expiration
    if (Date.now() > item.expiresAt) {
      this.memoryCache.delete(key);
      this.removeFromLocalStorage(key);
      this.stats.misses++;
      return null;
    }
    
    // Update access statistics
    item.accessCount++;
    item.lastAccessed = Date.now();
    this.stats.hits++;
    
    return item.data as T;
  }

  /**
   * Set item in cache with TTL
   */
  set<T>(key: string, data: T, ttlMs?: number): void {
    const now = Date.now();
    const ttl = ttlMs || this.getTTLForKey(key);
    
    const item: CacheItem<T> = {
      data,
      timestamp: now,
      expiresAt: now + ttl,
      accessCount: 0,
      lastAccessed: now
    };
    
    // Check memory limits
    if (this.memoryCache.size >= this.config.maxMemoryItems) {
      this.evictLeastRecentlyUsed();
    }
    
    // Check item size (rough estimation)
    const itemSize = this.estimateSize(data);
    if (itemSize > this.config.maxItemSizeBytes) {
      console.warn(`Cache item too large (${itemSize} bytes), skipping cache for key: ${key}`);
      return;
    }
    
    this.memoryCache.set(key, item);
    
    // Persist to localStorage if enabled
    if (this.config.persistToLocalStorage) {
      this.saveToLocalStorage(key, item);
    }
  }

  /**
   * Remove item from all cache layers
   */
  delete(key: string): void {
    this.memoryCache.delete(key);
    this.removeFromLocalStorage(key);
  }

  /**
   * Clear entire cache
   */
  clear(): void {
    this.memoryCache.clear();
    this.clearLocalStorage();
    this.stats = { hits: 0, misses: 0, evictions: 0, totalRequests: 0 };
  }

  /**
   * Get cache statistics
   */
  getStats(): CacheStats {
    const hitRate = this.stats.totalRequests > 0 
      ? (this.stats.hits / this.stats.totalRequests) * 100 
      : 0;
    
    const missRate = 100 - hitRate;
    
    return {
      totalItems: this.memoryCache.size,
      memoryUsage: this.estimateMemoryUsage(),
      hitRate: Number(hitRate.toFixed(2)),
      missRate: Number(missRate.toFixed(2)),
      evictions: this.stats.evictions
    };
  }

  /**
   * Create cache key for search requests
   */
  createSearchKey(query: string, filters: any, startRecord: number, maxRecords: number): string {
    const filterStr = JSON.stringify(filters || {});
    return `search:${query}:${filterStr}:${startRecord}:${maxRecords}`;
  }

  /**
   * Create cache key for document content
   */
  createDocumentKey(urn: string): string {
    return `document:${urn}`;
  }

  /**
   * Create cache key for suggestions
   */
  createSuggestionsKey(term: string, field?: string): string {
    return field ? `suggestions:${field}:${term}` : `suggestions:${term}`;
  }

  /**
   * Create cache key for cross-references
   */
  createCrossReferencesKey(urn: string): string {
    return `crossref:${urn}`;
  }

  /**
   * Create cache key for related documents
   */
  createRelatedDocumentsKey(urn: string, maxResults: number): string {
    return `related:${urn}:${maxResults}`;
  }

  /**
   * Prefetch and cache common queries
   */
  async prefetchCommonQueries(): Promise<void> {
    const commonQueries = [
      'transporte',
      'mobilidade urbana',
      'trânsito',
      'transporte público'
    ];
    
    // This would normally call the API, but since we're in the frontend,
    // we'll mark these as "warm" cache entries
    commonQueries.forEach(query => {
      const key = this.createSearchKey(query, {}, 1, 50);
      // Set a placeholder that indicates this query should be prioritized
      this.set(key, { prefetched: true, query }, this.config.searchResults);
    });
  }

  // Private methods

  private getTTLForKey(key: string): number {
    if (key.startsWith('search:')) return this.config.searchResults;
    if (key.startsWith('document:')) return this.config.documentContent;
    if (key.startsWith('suggestions:')) return this.config.suggestions;
    if (key.startsWith('health:')) return this.config.healthStatus;
    if (key.startsWith('crossref:')) return this.config.crossReferences;
    if (key.startsWith('related:')) return this.config.relatedDocuments;
    
    return this.config.searchResults; // Default
  }

  private evictLeastRecentlyUsed(): void {
    let oldestKey = '';
    let oldestTime = Date.now();
    
    for (const [key, item] of this.memoryCache.entries()) {
      if (item.lastAccessed < oldestTime) {
        oldestTime = item.lastAccessed;
        oldestKey = key;
      }
    }
    
    if (oldestKey) {
      this.memoryCache.delete(oldestKey);
      this.removeFromLocalStorage(oldestKey);
      this.stats.evictions++;
    }
  }

  private cleanup(): void {
    const now = Date.now();
    const keysToDelete: string[] = [];
    
    for (const [key, item] of this.memoryCache.entries()) {
      if (now > item.expiresAt) {
        keysToDelete.push(key);
      }
    }
    
    keysToDelete.forEach(key => {
      this.memoryCache.delete(key);
      this.removeFromLocalStorage(key);
    });
  }

  private estimateSize(data: any): number {
    return JSON.stringify(data).length * 2; // Rough UTF-16 estimation
  }

  private estimateMemoryUsage(): number {
    let totalSize = 0;
    for (const [key, item] of this.memoryCache.entries()) {
      totalSize += this.estimateSize(key) + this.estimateSize(item);
    }
    return totalSize;
  }

  // LocalStorage persistence methods

  private saveToLocalStorage<T>(key: string, item: CacheItem<T>): void {
    if (typeof window === 'undefined') return;
    
    try {
      const storageKey = this.config.localStoragePrefix + key;
      localStorage.setItem(storageKey, JSON.stringify(item));
    } catch (error) {
      console.warn('Failed to save to localStorage:', error);
    }
  }

  private getFromLocalStorage<T>(key: string): T | null {
    if (typeof window === 'undefined') return null;
    
    try {
      const storageKey = this.config.localStoragePrefix + key;
      const stored = localStorage.getItem(storageKey);
      
      if (!stored) return null;
      
      const item: CacheItem<T> = JSON.parse(stored);
      
      // Check expiration
      if (Date.now() > item.expiresAt) {
        localStorage.removeItem(storageKey);
        return null;
      }
      
      // Move to memory cache for faster access
      this.memoryCache.set(key, item);
      this.stats.hits++;
      
      return item.data;
    } catch (error) {
      console.warn('Failed to read from localStorage:', error);
      return null;
    }
  }

  private removeFromLocalStorage(key: string): void {
    if (typeof window === 'undefined') return;
    
    try {
      const storageKey = this.config.localStoragePrefix + key;
      localStorage.removeItem(storageKey);
    } catch (error) {
      console.warn('Failed to remove from localStorage:', error);
    }
  }

  private loadFromLocalStorage(): void {
    if (typeof window === 'undefined') return;
    
    try {
      const prefix = this.config.localStoragePrefix;
      
      for (let i = 0; i < localStorage.length; i++) {
        const fullKey = localStorage.key(i);
        if (!fullKey || !fullKey.startsWith(prefix)) continue;
        
        const key = fullKey.substring(prefix.length);
        const stored = localStorage.getItem(fullKey);
        
        if (stored) {
          const item: CacheItem<any> = JSON.parse(stored);
          
          // Check if expired
          if (Date.now() <= item.expiresAt) {
            this.memoryCache.set(key, item);
          } else {
            localStorage.removeItem(fullKey);
          }
        }
      }
    } catch (error) {
      console.warn('Failed to load from localStorage:', error);
    }
  }

  private clearLocalStorage(): void {
    if (typeof window === 'undefined') return;
    
    try {
      const prefix = this.config.localStoragePrefix;
      const keysToRemove: string[] = [];
      
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && key.startsWith(prefix)) {
          keysToRemove.push(key);
        }
      }
      
      keysToRemove.forEach(key => localStorage.removeItem(key));
    } catch (error) {
      console.warn('Failed to clear localStorage:', error);
    }
  }

  private handleStorageEvent(event: StorageEvent): void {
    if (!event.key || !event.key.startsWith(this.config.localStoragePrefix)) return;
    
    const key = event.key.substring(this.config.localStoragePrefix.length);
    
    if (event.newValue === null) {
      // Item was removed
      this.memoryCache.delete(key);
    } else {
      try {
        // Item was added/updated
        const item: CacheItem<any> = JSON.parse(event.newValue);
        if (Date.now() <= item.expiresAt) {
          this.memoryCache.set(key, item);
        }
      } catch (error) {
        console.warn('Failed to sync storage event:', error);
      }
    }
  }
}

// Create singleton instance
export const cacheService = new CacheService();

// Export utility functions
export const getCachedSearchResults = (query: string, filters: any, startRecord: number, maxRecords: number) => {
  const key = cacheService.createSearchKey(query, filters, startRecord, maxRecords);
  return cacheService.get(key);
};

export const setCachedSearchResults = (query: string, filters: any, startRecord: number, maxRecords: number, data: any) => {
  const key = cacheService.createSearchKey(query, filters, startRecord, maxRecords);
  cacheService.set(key, data);
};

export const getCachedDocument = (urn: string) => {
  const key = cacheService.createDocumentKey(urn);
  return cacheService.get(key);
};

export const setCachedDocument = (urn: string, data: any) => {
  const key = cacheService.createDocumentKey(urn);
  cacheService.set(key, data);
};

export const getCachedSuggestions = (term: string, field?: string) => {
  const key = cacheService.createSuggestionsKey(term, field);
  return cacheService.get(key);
};

export const setCachedSuggestions = (term: string, data: any, field?: string) => {
  const key = cacheService.createSuggestionsKey(term, field);
  cacheService.set(key, data);
};