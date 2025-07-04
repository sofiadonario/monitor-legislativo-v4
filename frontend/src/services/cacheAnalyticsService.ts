import { multiLayerCache } from './multiLayerCache';
import { cacheInvalidationService } from './cacheInvalidationService';

// Analytics data point interface
interface CacheDataPoint {
  timestamp: number;
  hitRate: number;
  averageResponseTime: number;
  cacheEfficiency: number;
  totalRequests: number;
  memoryUsage: number;
  sessionUsage: number;
  localUsage: number;
  redisUsage: number;
  totalSize: number;
  activeRefreshes: number;
  queuedRefreshes: number;
  errorCount: number;
}

// Performance trend analysis
interface PerformanceTrend {
  metric: keyof CacheDataPoint;
  trend: 'improving' | 'declining' | 'stable';
  changePercentage: number;
  confidence: number;
  recommendation?: string;
}

// Cache health assessment
interface CacheHealthAssessment {
  overallScore: number; // 0-100
  healthStatus: 'excellent' | 'good' | 'fair' | 'poor' | 'critical';
  issues: string[];
  recommendations: string[];
  trends: PerformanceTrend[];
}

// Analytics configuration
interface AnalyticsConfig {
  dataRetentionDays: number;
  samplingInterval: number; // milliseconds
  trendAnalysisWindow: number; // number of data points
  alertThresholds: {
    hitRateMin: number;
    responseTimeMax: number;
    errorRateMax: number;
    memoryUsageMax: number;
  };
}

class CacheAnalyticsService {
  private static instance: CacheAnalyticsService;
  private dataPoints: CacheDataPoint[] = [];
  private config: AnalyticsConfig;
  private samplingIntervalId?: number;
  private isCollecting: boolean = false;

  private constructor() {
    this.config = {
      dataRetentionDays: 7,
      samplingInterval: 60000, // 1 minute
      trendAnalysisWindow: 20, // 20 data points
      alertThresholds: {
        hitRateMin: 30,
        responseTimeMax: 1000,
        errorRateMax: 10,
        memoryUsageMax: 80 * 1024 * 1024 // 80MB
      }
    };

    this.loadStoredData();
  }

  static getInstance(): CacheAnalyticsService {
    if (!CacheAnalyticsService.instance) {
      CacheAnalyticsService.instance = new CacheAnalyticsService();
    }
    return CacheAnalyticsService.instance;
  }

  /**
   * Start collecting analytics data
   */
  startDataCollection(): void {
    if (this.isCollecting) {
      console.log('Cache analytics already collecting');
      return;
    }

    this.isCollecting = true;
    console.log('🔬 Starting cache analytics data collection');

    // Collect initial data point
    this.collectDataPoint();

    // Set up periodic collection
    this.samplingIntervalId = window.setInterval(() => {
      this.collectDataPoint();
    }, this.config.samplingInterval);

    // Clean up old data periodically
    setInterval(() => {
      this.cleanupOldData();
    }, 60 * 60 * 1000); // Every hour
  }

  /**
   * Stop collecting analytics data
   */
  stopDataCollection(): void {
    if (!this.isCollecting) {
      return;
    }

    this.isCollecting = false;
    
    if (this.samplingIntervalId) {
      clearInterval(this.samplingIntervalId);
      this.samplingIntervalId = undefined;
    }

    console.log('⏹️ Stopped cache analytics data collection');
  }

  /**
   * Collect a single data point
   */
  private async collectDataPoint(): Promise<void> {
    try {
      const [stats, sizes, invalidationStats] = await Promise.all([
        multiLayerCache.getStats(),
        multiLayerCache.getCacheSizes(),
        cacheInvalidationService.getInvalidationStats()
      ]);

      const errorCount = Object.values(invalidationStats.errorCounts)
        .reduce((sum, count) => sum + count, 0);

      const dataPoint: CacheDataPoint = {
        timestamp: Date.now(),
        hitRate: stats.hitRate,
        averageResponseTime: stats.averageResponseTime,
        cacheEfficiency: stats.cacheEfficiency,
        totalRequests: stats.totalRequests,
        memoryUsage: sizes.memory,
        sessionUsage: sizes.session,
        localUsage: sizes.local,
        redisUsage: sizes.redis,
        totalSize: sizes.memory + sizes.session + sizes.local + sizes.redis,
        activeRefreshes: invalidationStats.activeRefreshes,
        queuedRefreshes: invalidationStats.queuedRefreshes,
        errorCount
      };

      this.dataPoints.push(dataPoint);
      this.saveDataToStorage();

      // Log significant changes
      this.detectSignificantChanges(dataPoint);

    } catch (error) {
      console.error('Failed to collect cache analytics data:', error);
    }
  }

  /**
   * Detect significant changes in cache performance
   */
  private detectSignificantChanges(currentPoint: CacheDataPoint): void {
    if (this.dataPoints.length < 2) return;

    const previousPoint = this.dataPoints[this.dataPoints.length - 2];
    
    // Check for significant hit rate drops
    if (currentPoint.hitRate < previousPoint.hitRate - 20) {
      console.warn(`📉 Significant hit rate drop: ${previousPoint.hitRate.toFixed(1)}% → ${currentPoint.hitRate.toFixed(1)}%`);
    }

    // Check for response time spikes
    if (currentPoint.averageResponseTime > previousPoint.averageResponseTime * 2) {
      console.warn(`🐌 Response time spike: ${previousPoint.averageResponseTime.toFixed(0)}ms → ${currentPoint.averageResponseTime.toFixed(0)}ms`);
    }

    // Check for memory usage spikes
    if (currentPoint.memoryUsage > this.config.alertThresholds.memoryUsageMax) {
      console.warn(`💾 High memory usage: ${(currentPoint.memoryUsage / 1024 / 1024).toFixed(1)}MB`);
    }

    // Check for error spikes
    if (currentPoint.errorCount > previousPoint.errorCount + 5) {
      console.warn(`🚨 Error count spike: ${previousPoint.errorCount} → ${currentPoint.errorCount}`);
    }
  }

  /**
   * Analyze performance trends
   */
  analyzePerformanceTrends(): PerformanceTrend[] {
    if (this.dataPoints.length < this.config.trendAnalysisWindow) {
      return [];
    }

    const recentPoints = this.dataPoints.slice(-this.config.trendAnalysisWindow);
    const midPoint = Math.floor(recentPoints.length / 2);
    const firstHalf = recentPoints.slice(0, midPoint);
    const secondHalf = recentPoints.slice(midPoint);

    const trends: PerformanceTrend[] = [];

    // Analyze hit rate trend
    trends.push(this.calculateTrend('hitRate', firstHalf, secondHalf));
    
    // Analyze response time trend
    trends.push(this.calculateTrend('averageResponseTime', firstHalf, secondHalf, true)); // lower is better
    
    // Analyze efficiency trend
    trends.push(this.calculateTrend('cacheEfficiency', firstHalf, secondHalf));
    
    // Analyze memory usage trend
    trends.push(this.calculateTrend('memoryUsage', firstHalf, secondHalf, true)); // lower is better

    return trends;
  }

  /**
   * Calculate trend for a specific metric
   */
  private calculateTrend(
    metric: keyof CacheDataPoint,
    firstHalf: CacheDataPoint[],
    secondHalf: CacheDataPoint[],
    lowerIsBetter: boolean = false
  ): PerformanceTrend {
    const firstAvg = firstHalf.reduce((sum, point) => sum + (point[metric] as number), 0) / firstHalf.length;
    const secondAvg = secondHalf.reduce((sum, point) => sum + (point[metric] as number), 0) / secondHalf.length;
    
    const changePercentage = ((secondAvg - firstAvg) / firstAvg) * 100;
    const absChange = Math.abs(changePercentage);
    
    let trend: 'improving' | 'declining' | 'stable';
    if (absChange < 5) {
      trend = 'stable';
    } else if (lowerIsBetter) {
      trend = changePercentage < 0 ? 'improving' : 'declining';
    } else {
      trend = changePercentage > 0 ? 'improving' : 'declining';
    }

    // Calculate confidence based on data consistency
    const firstStdDev = this.calculateStandardDeviation(firstHalf.map(p => p[metric] as number));
    const secondStdDev = this.calculateStandardDeviation(secondHalf.map(p => p[metric] as number));
    const avgStdDev = (firstStdDev + secondStdDev) / 2;
    const confidence = Math.max(0, 100 - (avgStdDev / Math.abs(secondAvg - firstAvg)) * 100);

    return {
      metric,
      trend,
      changePercentage,
      confidence: Math.min(100, confidence),
      recommendation: this.generateTrendRecommendation(metric, trend, changePercentage)
    };
  }

  /**
   * Calculate standard deviation
   */
  private calculateStandardDeviation(values: number[]): number {
    const avg = values.reduce((sum, val) => sum + val, 0) / values.length;
    const squaredDiffs = values.map(val => Math.pow(val - avg, 2));
    const avgSquaredDiff = squaredDiffs.reduce((sum, diff) => sum + diff, 0) / squaredDiffs.length;
    return Math.sqrt(avgSquaredDiff);
  }

  /**
   * Generate trend-based recommendations
   */
  private generateTrendRecommendation(
    metric: keyof CacheDataPoint,
    trend: 'improving' | 'declining' | 'stable',
    changePercentage: number
  ): string | undefined {
    if (trend === 'stable') return undefined;

    const recommendations: Record<string, Record<string, string>> = {
      hitRate: {
        declining: 'Consider preloading frequently accessed data or reviewing cache invalidation strategy',
        improving: 'Continue current caching strategy - performance is improving'
      },
      averageResponseTime: {
        declining: 'Investigate slow cache operations, consider optimizing cache layers or compression',
        improving: 'Response times are improving - current optimizations are working'
      },
      cacheEfficiency: {
        declining: 'Review cache hit patterns and consider adjusting cache sizes or TTL values',
        improving: 'Cache efficiency is improving - maintain current configuration'
      },
      memoryUsage: {
        declining: 'Memory usage is increasing - consider reducing cache sizes or implementing more aggressive eviction',
        improving: 'Memory usage is optimizing well'
      }
    };

    return recommendations[metric]?.[trend] || undefined;
  }

  /**
   * Assess overall cache health
   */
  assessCacheHealth(): CacheHealthAssessment {
    if (this.dataPoints.length === 0) {
      return {
        overallScore: 0,
        healthStatus: 'critical',
        issues: ['No analytics data available'],
        recommendations: ['Start cache analytics data collection'],
        trends: []
      };
    }

    const latestData = this.dataPoints[this.dataPoints.length - 1];
    const trends = this.analyzePerformanceTrends();
    
    let score = 100;
    const issues: string[] = [];
    const recommendations: string[] = [];

    // Assess hit rate
    if (latestData.hitRate < this.config.alertThresholds.hitRateMin) {
      score -= 30;
      issues.push(`Low hit rate: ${latestData.hitRate.toFixed(1)}%`);
      recommendations.push('Increase cache TTL or preload frequently accessed data');
    }

    // Assess response time
    if (latestData.averageResponseTime > this.config.alertThresholds.responseTimeMax) {
      score -= 25;
      issues.push(`High response time: ${latestData.averageResponseTime.toFixed(0)}ms`);
      recommendations.push('Optimize cache operations or reduce data compression');
    }

    // Assess memory usage
    if (latestData.memoryUsage > this.config.alertThresholds.memoryUsageMax) {
      score -= 20;
      issues.push(`High memory usage: ${(latestData.memoryUsage / 1024 / 1024).toFixed(1)}MB`);
      recommendations.push('Reduce memory cache size or implement more aggressive eviction');
    }

    // Assess error rate
    const recentErrorRate = latestData.errorCount / Math.max(1, latestData.totalRequests) * 100;
    if (recentErrorRate > this.config.alertThresholds.errorRateMax) {
      score -= 15;
      issues.push(`High error rate: ${recentErrorRate.toFixed(1)}%`);
      recommendations.push('Investigate cache operation failures and improve error handling');
    }

    // Assess declining trends
    const decliningTrends = trends.filter(t => t.trend === 'declining' && t.confidence > 70);
    if (decliningTrends.length > 0) {
      score -= decliningTrends.length * 10;
      issues.push(`${decliningTrends.length} declining performance trend(s)`);
      recommendations.push('Review declining metrics and implement optimizations');
    }

    score = Math.max(0, score);

    let healthStatus: CacheHealthAssessment['healthStatus'];
    if (score >= 90) healthStatus = 'excellent';
    else if (score >= 75) healthStatus = 'good';
    else if (score >= 60) healthStatus = 'fair';
    else if (score >= 40) healthStatus = 'poor';
    else healthStatus = 'critical';

    return {
      overallScore: score,
      healthStatus,
      issues,
      recommendations,
      trends
    };
  }

  /**
   * Get historical data for charts
   */
  getHistoricalData(timeRange?: 'hour' | 'day' | 'week'): CacheDataPoint[] {
    const now = Date.now();
    let cutoffTime: number;

    switch (timeRange) {
      case 'hour':
        cutoffTime = now - (60 * 60 * 1000);
        break;
      case 'day':
        cutoffTime = now - (24 * 60 * 60 * 1000);
        break;
      case 'week':
        cutoffTime = now - (7 * 24 * 60 * 60 * 1000);
        break;
      default:
        return this.dataPoints;
    }

    return this.dataPoints.filter(point => point.timestamp >= cutoffTime);
  }

  /**
   * Get performance summary
   */
  getPerformanceSummary(timeRange?: 'hour' | 'day' | 'week') {
    const data = this.getHistoricalData(timeRange);
    
    if (data.length === 0) {
      return null;
    }

    const latest = data[data.length - 1];
    const first = data[0];

    return {
      current: {
        hitRate: latest.hitRate,
        responseTime: latest.averageResponseTime,
        efficiency: latest.cacheEfficiency,
        memoryUsage: latest.memoryUsage
      },
      averages: {
        hitRate: data.reduce((sum, p) => sum + p.hitRate, 0) / data.length,
        responseTime: data.reduce((sum, p) => sum + p.averageResponseTime, 0) / data.length,
        efficiency: data.reduce((sum, p) => sum + p.cacheEfficiency, 0) / data.length,
        memoryUsage: data.reduce((sum, p) => sum + p.memoryUsage, 0) / data.length
      },
      changes: timeRange && data.length > 1 ? {
        hitRate: latest.hitRate - first.hitRate,
        responseTime: latest.averageResponseTime - first.averageResponseTime,
        efficiency: latest.cacheEfficiency - first.cacheEfficiency,
        memoryUsage: latest.memoryUsage - first.memoryUsage
      } : undefined,
      dataPoints: data.length,
      timeRange: timeRange || 'all'
    };
  }

  /**
   * Clean up old data
   */
  private cleanupOldData(): void {
    const cutoffTime = Date.now() - (this.config.dataRetentionDays * 24 * 60 * 60 * 1000);
    const initialLength = this.dataPoints.length;
    
    this.dataPoints = this.dataPoints.filter(point => point.timestamp >= cutoffTime);
    
    if (this.dataPoints.length !== initialLength) {
      console.log(`🧹 Cleaned up ${initialLength - this.dataPoints.length} old analytics data points`);
      this.saveDataToStorage();
    }
  }

  /**
   * Load stored analytics data
   */
  private loadStoredData(): void {
    try {
      const stored = localStorage.getItem('cache_analytics_data');
      if (stored) {
        this.dataPoints = JSON.parse(stored);
        console.log(`📊 Loaded ${this.dataPoints.length} analytics data points from storage`);
      }
    } catch (error) {
      console.warn('Failed to load stored analytics data:', error);
      this.dataPoints = [];
    }
  }

  /**
   * Save analytics data to storage
   */
  private saveDataToStorage(): void {
    try {
      localStorage.setItem('cache_analytics_data', JSON.stringify(this.dataPoints));
    } catch (error) {
      console.warn('Failed to save analytics data to storage:', error);
    }
  }

  /**
   * Export analytics data
   */
  exportData(format: 'json' | 'csv' = 'json'): string {
    if (format === 'csv') {
      const headers = Object.keys(this.dataPoints[0] || {}).join(',');
      const rows = this.dataPoints.map(point => 
        Object.values(point).map(value => 
          typeof value === 'string' ? `"${value}"` : value
        ).join(',')
      );
      return [headers, ...rows].join('\n');
    }
    
    return JSON.stringify(this.dataPoints, null, 2);
  }

  /**
   * Clear all analytics data
   */
  clearAnalyticsData(): void {
    this.dataPoints = [];
    localStorage.removeItem('cache_analytics_data');
    console.log('🗑️ Cleared all analytics data');
  }

  /**
   * Get analytics configuration
   */
  getConfig(): AnalyticsConfig {
    return { ...this.config };
  }

  /**
   * Update analytics configuration
   */
  updateConfig(newConfig: Partial<AnalyticsConfig>): void {
    this.config = { ...this.config, ...newConfig };
    
    // Restart data collection if interval changed
    if (newConfig.samplingInterval && this.isCollecting) {
      this.stopDataCollection();
      this.startDataCollection();
    }
  }

  /**
   * Cleanup resources
   */
  dispose(): void {
    this.stopDataCollection();
    this.saveDataToStorage();
    console.log('🧹 Cache analytics service disposed');
  }
}

// Export singleton instance
export const cacheAnalyticsService = CacheAnalyticsService.getInstance();

export default CacheAnalyticsService;