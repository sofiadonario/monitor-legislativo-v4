import { LegislativeDocument, SearchFilters } from '../types';

// Cache configuration interface
interface CacheConfig {
  // Memory cache settings
  memoryMaxSize: number;
  memoryTTL: number;
  
  // Local storage settings
  localStorageMaxSize: number;
  localStorageTTL: number;
  
  // Session storage settings
  sessionStorageMaxSize: number;
  sessionStorageTTL: number;
  
  // Redis cache settings (when available)
  redisEnabled: boolean;
  redisTTL: number;
  redisMaxSize: number;
  
  // Performance settings
  compressionEnabled: boolean;
  backgroundRefreshEnabled: boolean;
  prefetchEnabled: boolean;
}

// Cache entry structure
interface CacheEntry<T = any> {
  data: T;
  timestamp: number;
  ttl: number;
  accessCount: number;
  lastAccessed: number;
  compressed?: boolean;
  size: number;
  key: string;
}

// Cache statistics
interface CacheStats {
  memoryHits: number;
  memoryMisses: number;
  localStorageHits: number;
  localStorageMisses: number;
  sessionStorageHits: number;
  sessionStorageMisses: number;
  redisHits: number;
  redisMisses: number;
  totalRequests: number;
  hitRate: number;
  averageResponseTime: number;
  cacheEfficiency: number;
}

// Cache layer types
type CacheLayer = 'memory' | 'session' | 'local' | 'redis';

class MultiLayerCacheService {
  private config: CacheConfig;
  private memoryCache: Map<string, CacheEntry>;
  private stats: CacheStats;
  private compressionWorker?: Worker;
  private refreshQueue: Set<string>;
  private prefetchQueue: Set<string>;

  constructor(config: Partial<CacheConfig> = {}) {
    this.config = {
      // Memory cache (fastest, smallest)
      memoryMaxSize: 50 * 1024 * 1024, // 50MB
      memoryTTL: 5 * 60 * 1000, // 5 minutes
      
      // Session storage (per-session)
      sessionStorageMaxSize: 10 * 1024 * 1024, // 10MB
      sessionStorageTTL: 30 * 60 * 1000, // 30 minutes
      
      // Local storage (persistent)
      localStorageMaxSize: 25 * 1024 * 1024, // 25MB
      localStorageTTL: 24 * 60 * 60 * 1000, // 24 hours
      
      // Redis cache (server-side when available)
      redisEnabled: false,
      redisTTL: 60 * 60 * 1000, // 1 hour
      redisMaxSize: 100 * 1024 * 1024, // 100MB
      
      // Performance features
      compressionEnabled: true,
      backgroundRefreshEnabled: true,
      prefetchEnabled: true,
      
      ...config
    };

    this.memoryCache = new Map();
    this.refreshQueue = new Set();
    this.prefetchQueue = new Set();
    
    this.stats = {
      memoryHits: 0,
      memoryMisses: 0,
      localStorageHits: 0,
      localStorageMisses: 0,
      sessionStorageHits: 0,
      sessionStorageMisses: 0,
      redisHits: 0,
      redisMisses: 0,
      totalRequests: 0,
      hitRate: 0,
      averageResponseTime: 0,
      cacheEfficiency: 0
    };

    // Initialize compression worker if available
    this.initializeCompressionWorker();
    
    // Start background maintenance
    this.startMaintenanceTasks();
  }

  private initializeCompressionWorker(): void {
    if (!this.config.compressionEnabled || typeof Worker === 'undefined') {
      return;
    }

    // Disable compression worker on GitHub Pages due to CSP restrictions
    if (window.location.hostname.includes('github.io')) {
      this.config.compressionEnabled = false;
      return;
    }

    try {
      // Create inline worker for compression
      const compressionCode = `
        self.onmessage = function(e) {
          const { action, data, id } = e.data;
          
          if (action === 'compress') {
            try {
              const compressed = LZString.compress(JSON.stringify(data));
              self.postMessage({ id, result: compressed, success: true });
            } catch (error) {
              self.postMessage({ id, error: error.message, success: false });
            }
          } else if (action === 'decompress') {
            try {
              const decompressed = JSON.parse(LZString.decompress(data));
              self.postMessage({ id, result: decompressed, success: true });
            } catch (error) {
              self.postMessage({ id, error: error.message, success: false });
            }
          }
        };
      `;
      
      const blob = new Blob([compressionCode], { type: 'application/javascript' });
      this.compressionWorker = new Worker(URL.createObjectURL(blob));
    } catch (error) {
      console.warn('Failed to initialize compression worker:', error);
      this.config.compressionEnabled = false;
    }
  }

  private startMaintenanceTasks(): void {
    // Clean expired entries every 5 minutes
    setInterval(() => {
      this.cleanExpiredEntries();
    }, 5 * 60 * 1000);

    // Update statistics every minute
    setInterval(() => {
      this.updateStatistics();
    }, 60 * 1000);

    // Process background refresh queue every 30 seconds
    if (this.config.backgroundRefreshEnabled) {
      setInterval(() => {
        this.processRefreshQueue();
      }, 30 * 1000);
    }

    // Process prefetch queue every 10 seconds
    if (this.config.prefetchEnabled) {
      setInterval(() => {
        this.processPrefetchQueue();
      }, 10 * 1000);
    }
  }

  /**
   * Get data from cache with multi-layer fallback
   */
  async get<T>(key: string, fallbackFn?: () => Promise<T>): Promise<T | null> {
    const startTime = Date.now();
    this.stats.totalRequests++;

    try {
      // Layer 1: Memory cache (fastest)
      const memoryResult = await this.getFromMemory<T>(key);
      if (memoryResult !== null) {
        this.stats.memoryHits++;
        this.updateAccessStats(key, 'memory', Date.now() - startTime);
        return memoryResult;
      }
      this.stats.memoryMisses++;

      // Layer 2: Session storage
      const sessionResult = await this.getFromSessionStorage<T>(key);
      if (sessionResult !== null) {
        this.stats.sessionStorageHits++;
        // Promote to memory cache
        await this.setInMemory(key, sessionResult, this.config.memoryTTL);
        this.updateAccessStats(key, 'session', Date.now() - startTime);
        return sessionResult;
      }
      this.stats.sessionStorageMisses++;

      // Layer 3: Local storage
      const localResult = await this.getFromLocalStorage<T>(key);
      if (localResult !== null) {
        this.stats.localStorageHits++;
        // Promote to higher cache layers
        await this.setInMemory(key, localResult, this.config.memoryTTL);
        await this.setInSessionStorage(key, localResult, this.config.sessionStorageTTL);
        this.updateAccessStats(key, 'local', Date.now() - startTime);
        return localResult;
      }
      this.stats.localStorageMisses++;

      // Layer 4: Redis cache (if available)
      if (this.config.redisEnabled) {
        const redisResult = await this.getFromRedis<T>(key);
        if (redisResult !== null) {
          this.stats.redisHits++;
          // Promote to all cache layers
          await this.setInMemory(key, redisResult, this.config.memoryTTL);
          await this.setInSessionStorage(key, redisResult, this.config.sessionStorageTTL);
          await this.setInLocalStorage(key, redisResult, this.config.localStorageTTL);
          this.updateAccessStats(key, 'redis', Date.now() - startTime);
          return redisResult;
        }
        this.stats.redisMisses++;
      }

      // Cache miss - use fallback function if provided
      if (fallbackFn) {
        const result = await fallbackFn();
        if (result !== null) {
          await this.set(key, result);
          this.scheduleBackgroundRefresh(key, fallbackFn);
        }
        return result;
      }

      return null;
    } catch (error) {
      console.error('Cache get error:', error);
      return fallbackFn ? await fallbackFn() : null;
    }
  }

  /**
   * Set data in all appropriate cache layers
   */
  async set<T>(key: string, data: T, customTTL?: number): Promise<void> {
    try {
      const ttl = customTTL || this.config.memoryTTL;
      
      // Set in all cache layers
      await Promise.all([
        this.setInMemory(key, data, ttl),
        this.setInSessionStorage(key, data, this.config.sessionStorageTTL),
        this.setInLocalStorage(key, data, this.config.localStorageTTL),
        ...(this.config.redisEnabled ? [this.setInRedis(key, data, this.config.redisTTL)] : [])
      ]);
    } catch (error) {
      console.error('Cache set error:', error);
    }
  }

  /**
   * Delete from all cache layers
   */
  async delete(key: string): Promise<void> {
    try {
      await Promise.all([
        this.deleteFromMemory(key),
        this.deleteFromSessionStorage(key),
        this.deleteFromLocalStorage(key),
        ...(this.config.redisEnabled ? [this.deleteFromRedis(key)] : [])
      ]);
    } catch (error) {
      console.error('Cache delete error:', error);
    }
  }

  /**
   * Clear all cache layers
   */
  async clear(): Promise<void> {
    try {
      await Promise.all([
        this.clearMemory(),
        this.clearSessionStorage(),
        this.clearLocalStorage(),
        ...(this.config.redisEnabled ? [this.clearRedis()] : [])
      ]);
      
      this.refreshQueue.clear();
      this.prefetchQueue.clear();
    } catch (error) {
      console.error('Cache clear error:', error);
    }
  }

  // Memory cache operations
  private async getFromMemory<T>(key: string): Promise<T | null> {
    const entry = this.memoryCache.get(key);
    if (!entry) return null;
    
    if (Date.now() > entry.timestamp + entry.ttl) {
      this.memoryCache.delete(key);
      return null;
    }
    
    entry.accessCount++;
    entry.lastAccessed = Date.now();
    return entry.data;
  }

  private async setInMemory<T>(key: string, data: T, ttl: number): Promise<void> {
    const size = this.calculateDataSize(data);
    
    // Check if we need to evict entries
    await this.ensureMemorySpace(size);
    
    const entry: CacheEntry<T> = {
      data,
      timestamp: Date.now(),
      ttl,
      accessCount: 1,
      lastAccessed: Date.now(),
      size,
      key
    };
    
    this.memoryCache.set(key, entry);
  }

  private async deleteFromMemory(key: string): Promise<void> {
    this.memoryCache.delete(key);
  }

  private async clearMemory(): Promise<void> {
    this.memoryCache.clear();
  }

  // Session storage operations
  private async getFromSessionStorage<T>(key: string): Promise<T | null> {
    try {
      const item = sessionStorage.getItem(`mlc_${key}`);
      if (!item) return null;
      
      const entry: CacheEntry<T> = JSON.parse(item);
      if (Date.now() > entry.timestamp + entry.ttl) {
        sessionStorage.removeItem(`mlc_${key}`);
        return null;
      }
      
      return entry.compressed 
        ? await this.decompress(entry.data)
        : entry.data;
    } catch (error) {
      console.warn('Session storage get error:', error);
      return null;
    }
  }

  private async setInSessionStorage<T>(key: string, data: T, ttl: number): Promise<void> {
    try {
      const compressed = this.config.compressionEnabled 
        ? await this.compress(data)
        : data;
      
      const entry: CacheEntry = {
        data: compressed,
        timestamp: Date.now(),
        ttl,
        accessCount: 1,
        lastAccessed: Date.now(),
        compressed: this.config.compressionEnabled,
        size: this.calculateDataSize(compressed),
        key
      };
      
      sessionStorage.setItem(`mlc_${key}`, JSON.stringify(entry));
    } catch (error) {
      console.warn('Session storage set error:', error);
    }
  }

  private async deleteFromSessionStorage(key: string): Promise<void> {
    try {
      sessionStorage.removeItem(`mlc_${key}`);
    } catch (error) {
      console.warn('Session storage delete error:', error);
    }
  }

  private async clearSessionStorage(): Promise<void> {
    try {
      // Remove only our cache entries
      const keys = Object.keys(sessionStorage);
      keys.forEach(key => {
        if (key.startsWith('mlc_')) {
          sessionStorage.removeItem(key);
        }
      });
    } catch (error) {
      console.warn('Session storage clear error:', error);
    }
  }

  // Local storage operations
  private async getFromLocalStorage<T>(key: string): Promise<T | null> {
    try {
      const item = localStorage.getItem(`mlc_${key}`);
      if (!item) return null;
      
      const entry: CacheEntry<T> = JSON.parse(item);
      if (Date.now() > entry.timestamp + entry.ttl) {
        localStorage.removeItem(`mlc_${key}`);
        return null;
      }
      
      return entry.compressed 
        ? await this.decompress(entry.data)
        : entry.data;
    } catch (error) {
      console.warn('Local storage get error:', error);
      return null;
    }
  }

  private async setInLocalStorage<T>(key: string, data: T, ttl: number): Promise<void> {
    try {
      const compressed = this.config.compressionEnabled 
        ? await this.compress(data)
        : data;
      
      const entry: CacheEntry = {
        data: compressed,
        timestamp: Date.now(),
        ttl,
        accessCount: 1,
        lastAccessed: Date.now(),
        compressed: this.config.compressionEnabled,
        size: this.calculateDataSize(compressed),
        key
      };
      
      localStorage.setItem(`mlc_${key}`, JSON.stringify(entry));
    } catch (error) {
      console.warn('Local storage set error:', error);
    }
  }

  private async deleteFromLocalStorage(key: string): Promise<void> {
    try {
      localStorage.removeItem(`mlc_${key}`);
    } catch (error) {
      console.warn('Local storage delete error:', error);
    }
  }

  private async clearLocalStorage(): Promise<void> {
    try {
      // Remove only our cache entries
      const keys = Object.keys(localStorage);
      keys.forEach(key => {
        if (key.startsWith('mlc_')) {
          localStorage.removeItem(key);
        }
      });
    } catch (error) {
      console.warn('Local storage clear error:', error);
    }
  }

  // Redis operations (placeholders for backend integration)
  private async getFromRedis<T>(key: string): Promise<T | null> {
    // This would integrate with backend Redis cache
    // For now, return null (Redis not available in frontend)
    return null;
  }

  private async setInRedis<T>(key: string, data: T, ttl: number): Promise<void> {
    // This would integrate with backend Redis cache
    // For now, do nothing
  }

  private async deleteFromRedis(key: string): Promise<void> {
    // This would integrate with backend Redis cache
  }

  private async clearRedis(): Promise<void> {
    // This would integrate with backend Redis cache
  }

  // Utility methods
  private calculateDataSize(data: any): number {
    return new Blob([JSON.stringify(data)]).size;
  }

  private async ensureMemorySpace(requiredSize: number): Promise<void> {
    const currentSize = Array.from(this.memoryCache.values())
      .reduce((total, entry) => total + entry.size, 0);
    
    if (currentSize + requiredSize <= this.config.memoryMaxSize) {
      return;
    }
    
    // LRU eviction
    const entries = Array.from(this.memoryCache.entries())
      .sort(([, a], [, b]) => a.lastAccessed - b.lastAccessed);
    
    let freedSpace = 0;
    for (const [key, entry] of entries) {
      this.memoryCache.delete(key);
      freedSpace += entry.size;
      
      if (freedSpace >= requiredSize) {
        break;
      }
    }
  }

  private async compress(data: any): Promise<any> {
    if (!this.config.compressionEnabled || !this.compressionWorker) {
      return data;
    }
    
    return new Promise((resolve) => {
      const id = Math.random().toString(36);
      
      const handler = (e: MessageEvent) => {
        if (e.data.id === id) {
          this.compressionWorker!.removeEventListener('message', handler);
          resolve(e.data.success ? e.data.result : data);
        }
      };
      
      this.compressionWorker.addEventListener('message', handler);
      this.compressionWorker.postMessage({ action: 'compress', data, id });
      
      // Fallback timeout
      setTimeout(() => resolve(data), 1000);
    });
  }

  private async decompress(data: any): Promise<any> {
    if (!this.config.compressionEnabled || !this.compressionWorker) {
      return data;
    }
    
    return new Promise((resolve) => {
      const id = Math.random().toString(36);
      
      const handler = (e: MessageEvent) => {
        if (e.data.id === id) {
          this.compressionWorker!.removeEventListener('message', handler);
          resolve(e.data.success ? e.data.result : data);
        }
      };
      
      this.compressionWorker.addEventListener('message', handler);
      this.compressionWorker.postMessage({ action: 'decompress', data, id });
      
      // Fallback timeout
      setTimeout(() => resolve(data), 1000);
    });
  }

  private cleanExpiredEntries(): void {
    const now = Date.now();
    
    // Clean memory cache
    for (const [key, entry] of this.memoryCache.entries()) {
      if (now > entry.timestamp + entry.ttl) {
        this.memoryCache.delete(key);
      }
    }
  }

  private updateStatistics(): void {
    const totalHits = this.stats.memoryHits + this.stats.sessionStorageHits + 
                     this.stats.localStorageHits + this.stats.redisHits;
    
    this.stats.hitRate = this.stats.totalRequests > 0 
      ? (totalHits / this.stats.totalRequests) * 100 
      : 0;
    
    this.stats.cacheEfficiency = this.calculateCacheEfficiency();
  }

  private calculateCacheEfficiency(): number {
    // Weight faster cache layers higher
    const weightedHits = 
      (this.stats.memoryHits * 4) +
      (this.stats.sessionStorageHits * 3) +
      (this.stats.localStorageHits * 2) +
      (this.stats.redisHits * 1);
    
    const maxPossibleScore = this.stats.totalRequests * 4;
    return maxPossibleScore > 0 ? (weightedHits / maxPossibleScore) * 100 : 0;
  }

  private updateAccessStats(key: string, layer: CacheLayer, responseTime: number): void {
    // Update response time moving average
    this.stats.averageResponseTime = 
      (this.stats.averageResponseTime * 0.9) + (responseTime * 0.1);
  }

  private scheduleBackgroundRefresh<T>(key: string, fallbackFn: () => Promise<T>): void {
    if (this.config.backgroundRefreshEnabled) {
      this.refreshQueue.add(key);
    }
  }

  private async processRefreshQueue(): Promise<void> {
    // Process a few items from refresh queue
    const items = Array.from(this.refreshQueue).slice(0, 3);
    this.refreshQueue = new Set(Array.from(this.refreshQueue).slice(3));
    
    for (const key of items) {
      // Background refresh logic would go here
      // For now, just remove from queue
    }
  }

  private async processPrefetchQueue(): Promise<void> {
    // Process prefetch queue
    const items = Array.from(this.prefetchQueue).slice(0, 2);
    this.prefetchQueue = new Set(Array.from(this.prefetchQueue).slice(2));
    
    for (const key of items) {
      // Prefetch logic would go here
    }
  }

  /**
   * Get cache statistics
   */
  getStats(): CacheStats {
    this.updateStatistics();
    return { ...this.stats };
  }

  /**
   * Get cache size information
   */
  getCacheSizes(): Record<CacheLayer, number> {
    const memorySize = Array.from(this.memoryCache.values())
      .reduce((total, entry) => total + entry.size, 0);
    
    return {
      memory: memorySize,
      session: 0, // Would calculate from sessionStorage
      local: 0,   // Would calculate from localStorage  
      redis: 0    // Would get from backend
    };
  }

  /**
   * Cleanup resources
   */
  dispose(): void {
    if (this.compressionWorker) {
      this.compressionWorker.terminate();
    }
    
    this.memoryCache.clear();
    this.refreshQueue.clear();
    this.prefetchQueue.clear();
  }
}

// Create singleton instance
export const multiLayerCache = new MultiLayerCacheService({
  compressionEnabled: true,
  backgroundRefreshEnabled: true,
  prefetchEnabled: true
});

export default MultiLayerCacheService;