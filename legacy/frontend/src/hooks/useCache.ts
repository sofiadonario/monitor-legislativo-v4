import { useState, useEffect, useCallback } from 'react';
import { multiLayerCache } from '../services/multiLayerCache';
import { cacheInvalidationService } from '../services/cacheInvalidationService';
import { cacheAnalyticsService } from '../services/cacheAnalyticsService';
import { legislativeDataService } from '../services/legislativeDataService';

// Cache performance metrics interface
interface CacheMetrics {
  hitRate: number;
  averageResponseTime: number;
  cacheEfficiency: number;
  totalRequests: number;
  memoryHits: number;
  sessionStorageHits: number;
  localStorageHits: number;
  redisHits: number;
}

// Cache size information interface
interface CacheSizeInfo {
  memory: number;
  session: number;
  local: number;
  redis: number;
  totalSize: number;
  formatted: {
    memory: string;
    session: string;
    local: string;
    redis: string;
    total: string;
  };
}

// Cache invalidation stats interface
interface InvalidationStats {
  activeRefreshes: number;
  queuedRefreshes: number;
  errorCounts: Record<string, number>;
  dependencies: string[];
  config: any;
}

// Analytics data interfaces
interface PerformanceTrend {
  metric: string;
  trend: 'improving' | 'declining' | 'stable';
  changePercentage: number;
  confidence: number;
  recommendation?: string;
}

interface CacheHealthAssessment {
  overallScore: number;
  healthStatus: 'excellent' | 'good' | 'fair' | 'poor' | 'critical';
  issues: string[];
  recommendations: string[];
  trends: PerformanceTrend[];
}

interface PerformanceSummary {
  current: {
    hitRate: number;
    responseTime: number;
    efficiency: number;
    memoryUsage: number;
  };
  averages: {
    hitRate: number;
    responseTime: number;
    efficiency: number;
    memoryUsage: number;
  };
  changes?: {
    hitRate: number;
    responseTime: number;
    efficiency: number;
    memoryUsage: number;
  };
  dataPoints: number;
  timeRange: string;
}

// Combined cache status interface
interface CacheStatus {
  metrics: CacheMetrics;
  sizes: CacheSizeInfo;
  invalidation: InvalidationStats;
  health: CacheHealthAssessment;
  performance: PerformanceSummary | null;
  isHealthy: boolean;
  lastUpdated: number;
}

export function useCache() {
  const [cacheStatus, setCacheStatus] = useState<CacheStatus | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Format bytes to human readable format
  const formatBytes = useCallback((bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }, []);

  // Fetch cache status
  const fetchCacheStatus = useCallback(async () => {
    try {
      setIsLoading(true);
      setError(null);

      const [metrics, sizes, invalidationStats, health, performance] = await Promise.all([
        multiLayerCache.getStats(),
        multiLayerCache.getCacheSizes(),
        cacheInvalidationService.getInvalidationStats(),
        cacheAnalyticsService.assessCacheHealth(),
        cacheAnalyticsService.getPerformanceSummary('day')
      ]);

      const totalSize = sizes.memory + sizes.session + sizes.local + sizes.redis;

      const formattedSizes: CacheSizeInfo = {
        ...sizes,
        totalSize,
        formatted: {
          memory: formatBytes(sizes.memory),
          session: formatBytes(sizes.session),
          local: formatBytes(sizes.local),
          redis: formatBytes(sizes.redis),
          total: formatBytes(totalSize)
        }
      };

      // Determine cache health from analytics assessment
      const isHealthy = health.healthStatus === 'excellent' || health.healthStatus === 'good';

      setCacheStatus({
        metrics,
        sizes: formattedSizes,
        invalidation: invalidationStats,
        health,
        performance,
        isHealthy,
        lastUpdated: Date.now()
      });

    } catch (err) {
      console.error('Failed to fetch cache status:', err);
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setIsLoading(false);
    }
  }, [formatBytes]);

  // Cache management functions
  const clearCache = useCallback(async (type?: 'all' | 'documents' | 'search' | 'collections') => {
    try {
      await legislativeDataService.invalidateCache(type);
      await cacheInvalidationService.invalidateOnEvent('manual_refresh');
      await fetchCacheStatus(); // Refresh status after clearing
      console.log(`Cache cleared: ${type || 'all'}`);
    } catch (err) {
      console.error('Failed to clear cache:', err);
      setError(err instanceof Error ? err.message : 'Failed to clear cache');
    }
  }, [fetchCacheStatus]);

  const preloadCache = useCallback(async () => {
    try {
      await cacheInvalidationService.preloadCriticalData();
      await fetchCacheStatus(); // Refresh status after preloading
      console.log('Cache preloading completed');
    } catch (err) {
      console.error('Failed to preload cache:', err);
      setError(err instanceof Error ? err.message : 'Failed to preload cache');
    }
  }, [fetchCacheStatus]);

  const forceRefresh = useCallback(async (pattern?: string) => {
    try {
      if (pattern) {
        await cacheInvalidationService.forceRefreshPattern(pattern);
      } else {
        await cacheInvalidationService.forceClearAll();
      }
      await fetchCacheStatus(); // Refresh status after forcing refresh
      console.log(`Force refresh completed: ${pattern || 'all'}`);
    } catch (err) {
      console.error('Failed to force refresh:', err);
      setError(err instanceof Error ? err.message : 'Failed to force refresh');
    }
  }, [fetchCacheStatus]);

  // Start analytics collection and auto-refresh cache status
  useEffect(() => {
    // Start analytics data collection
    cacheAnalyticsService.startDataCollection();
    
    // Initial status fetch
    fetchCacheStatus();

    // Set up periodic status updates
    const intervalId = setInterval(fetchCacheStatus, 30000); // Every 30 seconds

    return () => {
      clearInterval(intervalId);
      // Note: Don't stop analytics collection here as it should persist across component unmounts
    };
  }, [fetchCacheStatus]);

  // Cache performance indicators
  const getCacheHealthColor = useCallback((isHealthy: boolean) => {
    return isHealthy ? '#4caf50' : '#f44336'; // Green for healthy, red for unhealthy
  }, []);

  const getCacheHealthText = useCallback((isHealthy: boolean) => {
    return isHealthy ? 'Healthy' : 'Needs Attention';
  }, []);

  const getHitRateColor = useCallback((hitRate: number) => {
    if (hitRate >= 70) return '#4caf50'; // Green
    if (hitRate >= 50) return '#ff9800'; // Orange
    return '#f44336'; // Red
  }, []);

  const getResponseTimeColor = useCallback((responseTime: number) => {
    if (responseTime <= 200) return '#4caf50'; // Green
    if (responseTime <= 500) return '#ff9800'; // Orange
    return '#f44336'; // Red
  }, []);

  // Analytics functions
  const getHistoricalData = useCallback((timeRange?: 'hour' | 'day' | 'week') => {
    return cacheAnalyticsService.getHistoricalData(timeRange);
  }, []);

  const exportAnalytics = useCallback((format: 'json' | 'csv' = 'json') => {
    return cacheAnalyticsService.exportData(format);
  }, []);

  const clearAnalytics = useCallback(() => {
    cacheAnalyticsService.clearAnalyticsData();
  }, []);

  const getAnalyticsConfig = useCallback(() => {
    return cacheAnalyticsService.getConfig();
  }, []);

  const updateAnalyticsConfig = useCallback((config: any) => {
    cacheAnalyticsService.updateConfig(config);
  }, []);

  return {
    // Data
    cacheStatus,
    isLoading,
    error,

    // Actions
    clearCache,
    preloadCache,
    forceRefresh,
    refreshStatus: fetchCacheStatus,

    // Analytics
    getHistoricalData,
    exportAnalytics,
    clearAnalytics,
    getAnalyticsConfig,
    updateAnalyticsConfig,

    // Utilities
    getCacheHealthColor,
    getCacheHealthText,
    getHitRateColor,
    getResponseTimeColor,
    formatBytes
  };
}

export default useCache;