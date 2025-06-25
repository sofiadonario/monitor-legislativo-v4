import { multiLayerCache } from './multiLayerCache';
import { legislativeDataService } from './legislativeDataService';

// Cache invalidation events
export type CacheInvalidationEvent = 
  | 'new_document' 
  | 'document_updated' 
  | 'search_criteria_changed'
  | 'collection_completed'
  | 'manual_refresh'
  | 'time_based'
  | 'error_threshold_reached';

// Background refresh configuration
interface BackgroundRefreshConfig {
  enabled: boolean;
  interval: number; // milliseconds
  maxConcurrent: number;
  errorThreshold: number;
  retryAttempts: number;
}

// Cache dependency tracking
interface CacheDependency {
  key: string;
  dependsOn: string[];
  lastUpdated: number;
  refreshStrategy: 'eager' | 'lazy' | 'scheduled';
}

class CacheInvalidationService {
  private static instance: CacheInvalidationService;
  private backgroundRefreshConfig: BackgroundRefreshConfig;
  private dependencies: Map<string, CacheDependency> = new Map();
  private refreshQueue: Set<string> = new Set();
  private activeRefreshes: Set<string> = new Set();
  private refreshIntervalId?: number;
  private errorCounts: Map<string, number> = new Map();

  private constructor() {
    this.backgroundRefreshConfig = {
      enabled: true,
      interval: 30 * 1000, // 30 seconds
      maxConcurrent: 3,
      errorThreshold: 5,
      retryAttempts: 3
    };

    this.initializeDependencies();
    this.startBackgroundRefresh();
  }

  static getInstance(): CacheInvalidationService {
    if (!CacheInvalidationService.instance) {
      CacheInvalidationService.instance = new CacheInvalidationService();
    }
    return CacheInvalidationService.instance;
  }

  private initializeDependencies(): void {
    // Define cache dependencies
    const dependencies: CacheDependency[] = [
      {
        key: 'legislative_docs_*',
        dependsOn: ['csv_data'],
        lastUpdated: Date.now(),
        refreshStrategy: 'eager'
      },
      {
        key: 'search_results_*',
        dependsOn: ['legislative_docs_*'],
        lastUpdated: Date.now(),
        refreshStrategy: 'lazy'
      },
      {
        key: 'document_id_*',
        dependsOn: ['legislative_docs_*'],
        lastUpdated: Date.now(),
        refreshStrategy: 'lazy'
      },
      {
        key: 'collection_status',
        dependsOn: [],
        lastUpdated: Date.now(),
        refreshStrategy: 'scheduled'
      },
      {
        key: 'latest_collection',
        dependsOn: ['collection_status'],
        lastUpdated: Date.now(),
        refreshStrategy: 'scheduled'
      }
    ];

    dependencies.forEach(dep => {
      this.dependencies.set(dep.key, dep);
    });
  }

  /**
   * Invalidate cache based on specific events
   */
  async invalidateOnEvent(event: CacheInvalidationEvent, metadata?: any): Promise<void> {
    console.log(`🔄 Cache invalidation triggered by event: ${event}`);
    
    switch (event) {
      case 'new_document':
      case 'document_updated':
        await this.invalidateDocumentCaches();
        break;
        
      case 'collection_completed':
        await this.invalidateCollectionCaches();
        await this.scheduleDocumentRefresh();
        break;
        
      case 'search_criteria_changed':
        await this.invalidateSearchCaches();
        break;
        
      case 'manual_refresh':
        await this.invalidateAllCaches();
        await this.scheduleImmediateRefresh();
        break;
        
      case 'time_based':
        await this.performTimeBasedInvalidation();
        break;
        
      case 'error_threshold_reached':
        await this.handleErrorThresholdReached(metadata?.key);
        break;
    }
  }

  /**
   * Intelligent cache invalidation based on dependencies
   */
  private async invalidateDocumentCaches(): Promise<void> {
    const affectedKeys = [
      'legislative_docs_*',
      'search_results_*',
      'document_id_*'
    ];

    for (const keyPattern of affectedKeys) {
      await this.invalidateByPattern(keyPattern);
      await this.scheduleRefresh(keyPattern);
    }
  }

  private async invalidateCollectionCaches(): Promise<void> {
    const affectedKeys = [
      'collection_status',
      'latest_collection'
    ];

    for (const key of affectedKeys) {
      await multiLayerCache.delete(key);
      await this.scheduleRefresh(key);
    }
  }

  private async invalidateSearchCaches(): Promise<void> {
    await this.invalidateByPattern('search_results_*');
  }

  private async invalidateAllCaches(): Promise<void> {
    await multiLayerCache.clear();
    this.dependencies.forEach((_, key) => {
      this.scheduleRefresh(key);
    });
  }

  /**
   * Pattern-based cache invalidation (simplified for now)
   */
  private async invalidateByPattern(pattern: string): Promise<void> {
    // Since multiLayerCache doesn't support pattern deletion,
    // we'll clear all and mark for refresh
    console.log(`🧹 Invalidating cache pattern: ${pattern}`);
    
    if (pattern.includes('*')) {
      // For patterns, clear all caches (limitation of current implementation)
      await multiLayerCache.clear();
    } else {
      // For specific keys
      await multiLayerCache.delete(pattern);
    }
  }

  /**
   * Background refresh scheduling
   */
  private scheduleRefresh(keyPattern: string): void {
    this.refreshQueue.add(keyPattern);
    console.log(`📅 Scheduled refresh for: ${keyPattern}`);
  }

  private async scheduleDocumentRefresh(): Promise<void> {
    this.scheduleRefresh('legislative_docs_*');
  }

  private async scheduleImmediateRefresh(): Promise<void> {
    // Process refresh queue immediately
    await this.processRefreshQueue();
  }

  /**
   * Time-based invalidation
   */
  private async performTimeBasedInvalidation(): Promise<void> {
    const now = Date.now();
    const staleThreshold = 60 * 60 * 1000; // 1 hour

    for (const [key, dependency] of this.dependencies.entries()) {
      if (now - dependency.lastUpdated > staleThreshold) {
        console.log(`⏰ Time-based invalidation for: ${key}`);
        await this.invalidateByPattern(key);
        this.scheduleRefresh(key);
      }
    }
  }

  /**
   * Background refresh processing
   */
  private startBackgroundRefresh(): void {
    if (!this.backgroundRefreshConfig.enabled) {
      return;
    }

    this.refreshIntervalId = window.setInterval(async () => {
      await this.processRefreshQueue();
    }, this.backgroundRefreshConfig.interval);

    console.log('🔄 Background refresh service started');
  }

  private async processRefreshQueue(): Promise<void> {
    if (this.activeRefreshes.size >= this.backgroundRefreshConfig.maxConcurrent) {
      console.log('⏸️ Background refresh queue full, skipping');
      return;
    }

    const itemsToProcess = Array.from(this.refreshQueue)
      .slice(0, this.backgroundRefreshConfig.maxConcurrent - this.activeRefreshes.size);

    for (const keyPattern of itemsToProcess) {
      this.refreshQueue.delete(keyPattern);
      this.activeRefreshes.add(keyPattern);

      this.performBackgroundRefresh(keyPattern)
        .finally(() => {
          this.activeRefreshes.delete(keyPattern);
        });
    }
  }

  private async performBackgroundRefresh(keyPattern: string): Promise<void> {
    try {
      console.log(`🔄 Background refresh starting for: ${keyPattern}`);

      switch (keyPattern) {
        case 'legislative_docs_*':
          // Refresh base document cache
          await legislativeDataService.forceRefreshDocuments();
          break;
          
        case 'collection_status':
          await legislativeDataService.fetchCollectionStatus();
          break;
          
        case 'latest_collection':
          await legislativeDataService.fetchLatestCollection();
          break;
          
        default:
          console.log(`No refresh handler for pattern: ${keyPattern}`);
      }

      // Update last refreshed time
      const dependency = this.dependencies.get(keyPattern);
      if (dependency) {
        dependency.lastUpdated = Date.now();
      }

      // Reset error count on success
      this.errorCounts.delete(keyPattern);
      
      console.log(`✅ Background refresh completed for: ${keyPattern}`);
      
    } catch (error) {
      console.error(`❌ Background refresh failed for ${keyPattern}:`, error);
      
      // Track errors
      const errorCount = (this.errorCounts.get(keyPattern) || 0) + 1;
      this.errorCounts.set(keyPattern, errorCount);
      
      // Check error threshold
      if (errorCount >= this.backgroundRefreshConfig.errorThreshold) {
        await this.handleErrorThresholdReached(keyPattern);
      } else if (errorCount <= this.backgroundRefreshConfig.retryAttempts) {
        // Reschedule with exponential backoff
        setTimeout(() => {
          this.scheduleRefresh(keyPattern);
        }, Math.pow(2, errorCount) * 1000);
      }
    }
  }

  /**
   * Error handling
   */
  private async handleErrorThresholdReached(keyPattern?: string): Promise<void> {
    console.warn(`🚨 Error threshold reached for: ${keyPattern}`);
    
    if (keyPattern) {
      // Disable background refresh for this pattern temporarily
      this.refreshQueue.delete(keyPattern);
      
      // Schedule a recovery attempt in 5 minutes
      setTimeout(() => {
        this.errorCounts.delete(keyPattern);
        this.scheduleRefresh(keyPattern);
        console.log(`🔄 Recovery attempt scheduled for: ${keyPattern}`);
      }, 5 * 60 * 1000);
    }
  }

  /**
   * Cache preloading strategies
   */
  async preloadCriticalData(): Promise<void> {
    console.log('🚀 Preloading critical cache data...');
    
    try {
      // Preload most common searches
      const commonSearchTerms = ['transporte', 'mobilidade', 'trânsito'];
      
      const preloadPromises = commonSearchTerms.map(async (term) => {
        await legislativeDataService.searchDocuments(term);
      });

      // Preload base documents with no filters
      preloadPromises.push(legislativeDataService.fetchDocuments());
      
      // Preload collection status
      preloadPromises.push(legislativeDataService.fetchCollectionStatus());

      await Promise.allSettled(preloadPromises);
      console.log('✅ Critical data preloading completed');
      
    } catch (error) {
      console.error('❌ Critical data preloading failed:', error);
    }
  }

  /**
   * Configuration management
   */
  updateRefreshConfig(config: Partial<BackgroundRefreshConfig>): void {
    this.backgroundRefreshConfig = {
      ...this.backgroundRefreshConfig,
      ...config
    };
    
    // Restart background refresh if interval changed
    if (config.interval && this.refreshIntervalId) {
      clearInterval(this.refreshIntervalId);
      this.startBackgroundRefresh();
    }
  }

  /**
   * Get cache invalidation statistics
   */
  getInvalidationStats() {
    return {
      activeRefreshes: this.activeRefreshes.size,
      queuedRefreshes: this.refreshQueue.size,
      errorCounts: Object.fromEntries(this.errorCounts),
      dependencies: Array.from(this.dependencies.keys()),
      config: this.backgroundRefreshConfig
    };
  }

  /**
   * Manual cache management
   */
  async forceClearAll(): Promise<void> {
    await this.invalidateOnEvent('manual_refresh');
  }

  async forceRefreshPattern(pattern: string): Promise<void> {
    await this.invalidateByPattern(pattern);
    this.scheduleRefresh(pattern);
  }

  /**
   * Cleanup resources
   */
  dispose(): void {
    if (this.refreshIntervalId) {
      clearInterval(this.refreshIntervalId);
    }
    
    this.refreshQueue.clear();
    this.activeRefreshes.clear();
    this.errorCounts.clear();
    
    console.log('🧹 Cache invalidation service disposed');
  }
}

// Export singleton instance
export const cacheInvalidationService = CacheInvalidationService.getInstance();

export default CacheInvalidationService;