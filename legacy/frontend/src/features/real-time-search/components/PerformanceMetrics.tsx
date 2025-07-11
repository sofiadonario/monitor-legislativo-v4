/**
 * Performance Metrics Dashboard Component
 * Real-time monitoring of LexML API performance, cache efficiency, and user experience metrics
 */

import React, { useState, useEffect, useRef } from 'react';
import { lexmlAPI } from '../services/LexMLAPIService';
import { cacheService } from '../services/CacheService';

interface PerformanceMetrics {
  api: {
    responseTime: number;
    successRate: number;
    requestsPerMinute: number;
    errorRate: number;
    availability: number;
  };
  cache: {
    hitRate: number;
    missRate: number;
    memoryUsage: number;
    totalItems: number;
    evictions: number;
  };
  circuit: {
    status: 'CLOSED' | 'OPEN' | 'HALF_OPEN';
    failureCount: number;
    lastFailure?: Date;
    nextAttempt?: Date;
  };
  user: {
    averageSearchTime: number;
    searchesPerSession: number;
    documentViewsPerSession: number;
    bounceRate: number;
  };
}

interface MetricTrend {
  timestamp: number;
  value: number;
}

interface PerformanceMetricsProps {
  className?: string;
  refreshInterval?: number;
  showDetails?: boolean;
  compact?: boolean;
}

export const PerformanceMetrics: React.FC<PerformanceMetricsProps> = ({
  className = '',
  refreshInterval = 30000, // 30 seconds
  showDetails = false,
  compact = false
}) => {
  const [metrics, setMetrics] = useState<PerformanceMetrics | null>(null);
  const [trends, setTrends] = useState<Record<string, MetricTrend[]>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  const intervalRef = useRef<NodeJS.Timeout | null>(null);

  // Performance metrics collection
  useEffect(() => {
    const collectMetrics = async () => {
      try {
        setLoading(true);
        
        // Collect API health metrics
        const apiHealth = await lexmlAPI.getHealthStatus();
        
        // Collect cache statistics
        const cacheStats = cacheService.getStats();
        
        // Collect circuit breaker status
        const circuitStatus = await getCircuitBreakerStatus();
        
        // Collect user experience metrics
        const userMetrics = getUserExperienceMetrics();
        
        const newMetrics: PerformanceMetrics = {
          api: {
            responseTime: apiHealth?.response_time_ms || 0,
            successRate: apiHealth?.success_rate || 0,
            requestsPerMinute: calculateRequestsPerMinute(),
            errorRate: calculateErrorRate(),
            availability: apiHealth?.is_healthy ? 100 : 0
          },
          cache: {
            hitRate: cacheStats.hitRate,
            missRate: cacheStats.missRate,
            memoryUsage: cacheStats.memoryUsage,
            totalItems: cacheStats.totalItems,
            evictions: cacheStats.evictions
          },
          circuit: circuitStatus,
          user: userMetrics
        };
        
        setMetrics(newMetrics);
        updateTrends(newMetrics);
        setLastUpdate(new Date());
        setError(null);
        
      } catch (err) {
        console.error('Failed to collect performance metrics:', err);
        setError('Failed to collect metrics');
      } finally {
        setLoading(false);
      }
    };

    // Initial collection
    collectMetrics();
    
    // Set up interval
    intervalRef.current = setInterval(collectMetrics, refreshInterval);
    
    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [refreshInterval]);

  const updateTrends = (newMetrics: PerformanceMetrics) => {
    const timestamp = Date.now();
    const maxTrendPoints = 20;
    
    setTrends(prev => {
      const updated = { ...prev };
      
      // Update API response time trend
      if (!updated.apiResponseTime) updated.apiResponseTime = [];
      updated.apiResponseTime.push({ timestamp, value: newMetrics.api.responseTime });
      if (updated.apiResponseTime.length > maxTrendPoints) {
        updated.apiResponseTime.shift();
      }
      
      // Update cache hit rate trend
      if (!updated.cacheHitRate) updated.cacheHitRate = [];
      updated.cacheHitRate.push({ timestamp, value: newMetrics.cache.hitRate });
      if (updated.cacheHitRate.length > maxTrendPoints) {
        updated.cacheHitRate.shift();
      }
      
      return updated;
    });
  };

  const getCircuitBreakerStatus = async () => {
    try {
      const response = await fetch('/api/lexml/circuit-breaker/status');
      if (response.ok) {
        return await response.json();
      }
    } catch (err) {
      console.warn('Circuit breaker status unavailable');
    }
    
    return {
      status: 'CLOSED' as const,
      failureCount: 0
    };
  };

  const getUserExperienceMetrics = () => {
    const sessionData = getSessionMetrics();
    
    return {
      averageSearchTime: sessionData.averageSearchTime || 0,
      searchesPerSession: sessionData.searchCount || 0,
      documentViewsPerSession: sessionData.documentViews || 0,
      bounceRate: calculateBounceRate()
    };
  };

  const getSessionMetrics = () => {
    try {
      const stored = sessionStorage.getItem('lexml_session_metrics');
      return stored ? JSON.parse(stored) : {};
    } catch {
      return {};
    }
  };

  const calculateRequestsPerMinute = () => {
    // Get request count from last minute
    const stored = localStorage.getItem('lexml_request_log');
    if (!stored) return 0;
    
    try {
      const log = JSON.parse(stored);
      const oneMinuteAgo = Date.now() - 60000;
      return log.filter((timestamp: number) => timestamp > oneMinuteAgo).length;
    } catch {
      return 0;
    }
  };

  const calculateErrorRate = () => {
    const stored = localStorage.getItem('lexml_error_log');
    if (!stored) return 0;
    
    try {
      const errors = JSON.parse(stored);
      const oneHourAgo = Date.now() - 3600000;
      const recentErrors = errors.filter((timestamp: number) => timestamp > oneHourAgo);
      const totalRequests = calculateRequestsPerMinute() * 60; // Rough estimate
      
      return totalRequests > 0 ? (recentErrors.length / totalRequests) * 100 : 0;
    } catch {
      return 0;
    }
  };

  const calculateBounceRate = () => {
    const session = getSessionMetrics();
    if (!session.searchCount) return 0;
    
    // Consider it a bounce if user searched but didn't view any documents
    return session.documentViews === 0 && session.searchCount > 0 ? 100 : 0;
  };

  const getStatusColor = (value: number, thresholds: { good: number; warning: number }) => {
    if (value >= thresholds.good) return 'text-green-600';
    if (value >= thresholds.warning) return 'text-yellow-600';
    return 'text-red-600';
  };

  const getStatusEmoji = (value: number, thresholds: { good: number; warning: number }) => {
    if (value >= thresholds.good) return '🟢';
    if (value >= thresholds.warning) return '🟡';
    return '🔴';
  };

  const formatResponseTime = (ms: number) => {
    if (ms < 1000) return `${ms.toFixed(0)}ms`;
    return `${(ms / 1000).toFixed(1)}s`;
  };

  const formatMemoryUsage = (mb: number) => {
    if (mb < 1) return `${(mb * 1024).toFixed(0)}KB`;
    return `${mb.toFixed(1)}MB`;
  };

  if (loading && !metrics) {
    return (
      <div className={`flex items-center gap-2 ${className}`}>
        <div className="animate-spin h-4 w-4 border-2 border-blue-500 border-t-transparent rounded-full"></div>
        <span className="text-sm text-gray-600">Loading metrics...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className={`flex items-center gap-2 ${className}`}>
        <span className="text-red-500">❌</span>
        <span className="text-sm text-red-600">{error}</span>
      </div>
    );
  }

  if (!metrics) return null;

  if (compact) {
    return (
      <div className={`flex items-center gap-4 ${className}`}>
        <div className="flex items-center gap-1">
          <span>{getStatusEmoji(metrics.api.responseTime < 500 ? 100 : 0, { good: 80, warning: 60 })}</span>
          <span className="text-xs text-gray-600">
            API: {formatResponseTime(metrics.api.responseTime)}
          </span>
        </div>
        
        <div className="flex items-center gap-1">
          <span>{getStatusEmoji(metrics.cache.hitRate, { good: 80, warning: 60 })}</span>
          <span className="text-xs text-gray-600">
            Cache: {metrics.cache.hitRate.toFixed(0)}%
          </span>
        </div>
        
        <div className="flex items-center gap-1">
          <span className={metrics.circuit.status === 'CLOSED' ? '🟢' : metrics.circuit.status === 'HALF_OPEN' ? '🟡' : '🔴'}>
          </span>
          <span className="text-xs text-gray-600">
            Circuit: {metrics.circuit.status}
          </span>
        </div>
      </div>
    );
  }

  return (
    <div className={`bg-white border border-gray-200 rounded-lg p-6 ${className}`}>
      <div className="flex items-center justify-between mb-6">
        <h3 className="text-lg font-semibold text-gray-900">Performance Metrics</h3>
        <div className="flex items-center gap-2">
          {lastUpdate && (
            <span className="text-xs text-gray-500">
              Last updated: {lastUpdate.toLocaleTimeString()}
            </span>
          )}
          <button
            onClick={() => window.location.reload()}
            className="text-xs text-blue-600 hover:text-blue-800"
          >
            Refresh
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* API Performance */}
        <div className="space-y-3">
          <h4 className="font-medium text-gray-900 flex items-center gap-2">
            🌐 API Performance
          </h4>
          
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Response Time:</span>
              <span className={`text-sm font-medium ${getStatusColor(
                metrics.api.responseTime < 500 ? 100 : 0, 
                { good: 80, warning: 60 }
              )}`}>
                {formatResponseTime(metrics.api.responseTime)}
              </span>
            </div>
            
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Success Rate:</span>
              <span className={`text-sm font-medium ${getStatusColor(metrics.api.successRate, { good: 95, warning: 90 })}`}>
                {metrics.api.successRate.toFixed(1)}%
              </span>
            </div>
            
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Requests/min:</span>
              <span className="text-sm text-gray-700">
                {metrics.api.requestsPerMinute}
              </span>
            </div>
            
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Error Rate:</span>
              <span className={`text-sm font-medium ${getStatusColor(100 - metrics.api.errorRate, { good: 95, warning: 90 })}`}>
                {metrics.api.errorRate.toFixed(1)}%
              </span>
            </div>
          </div>
        </div>

        {/* Cache Performance */}
        <div className="space-y-3">
          <h4 className="font-medium text-gray-900 flex items-center gap-2">
            🚀 Cache Performance
          </h4>
          
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Hit Rate:</span>
              <span className={`text-sm font-medium ${getStatusColor(metrics.cache.hitRate, { good: 80, warning: 60 })}`}>
                {metrics.cache.hitRate.toFixed(1)}%
              </span>
            </div>
            
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Memory Usage:</span>
              <span className="text-sm text-gray-700">
                {formatMemoryUsage(metrics.cache.memoryUsage)}
              </span>
            </div>
            
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Total Items:</span>
              <span className="text-sm text-gray-700">
                {metrics.cache.totalItems}
              </span>
            </div>
            
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Evictions:</span>
              <span className="text-sm text-gray-700">
                {metrics.cache.evictions}
              </span>
            </div>
          </div>
        </div>

        {/* Circuit Breaker Status */}
        <div className="space-y-3">
          <h4 className="font-medium text-gray-900 flex items-center gap-2">
            🛡️ Circuit Breaker
          </h4>
          
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Status:</span>
              <span className={`text-sm font-medium ${
                metrics.circuit.status === 'CLOSED' ? 'text-green-600' : 
                metrics.circuit.status === 'HALF_OPEN' ? 'text-yellow-600' : 'text-red-600'
              }`}>
                {metrics.circuit.status}
              </span>
            </div>
            
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Failures:</span>
              <span className="text-sm text-gray-700">
                {metrics.circuit.failureCount}
              </span>
            </div>
            
            {metrics.circuit.lastFailure && (
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Last Failure:</span>
                <span className="text-xs text-gray-500">
                  {metrics.circuit.lastFailure.toLocaleTimeString()}
                </span>
              </div>
            )}
          </div>
        </div>

        {/* User Experience */}
        <div className="space-y-3">
          <h4 className="font-medium text-gray-900 flex items-center gap-2">
            👤 User Experience
          </h4>
          
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Avg Search Time:</span>
              <span className="text-sm text-gray-700">
                {formatResponseTime(metrics.user.averageSearchTime)}
              </span>
            </div>
            
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Searches/Session:</span>
              <span className="text-sm text-gray-700">
                {metrics.user.searchesPerSession}
              </span>
            </div>
            
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Document Views:</span>
              <span className="text-sm text-gray-700">
                {metrics.user.documentViewsPerSession}
              </span>
            </div>
            
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Bounce Rate:</span>
              <span className={`text-sm font-medium ${getStatusColor(100 - metrics.user.bounceRate, { good: 80, warning: 60 })}`}>
                {metrics.user.bounceRate.toFixed(0)}%
              </span>
            </div>
          </div>
        </div>
      </div>

      {showDetails && (
        <div className="mt-6 pt-6 border-t border-gray-200">
          <h4 className="font-medium text-gray-900 mb-4">Performance Trends</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* API Response Time Trend */}
            {trends.apiResponseTime && trends.apiResponseTime.length > 1 && (
              <div className="bg-gray-50 rounded-lg p-4">
                <h5 className="text-sm font-medium text-gray-700 mb-2">API Response Time Trend</h5>
                <div className="h-16 flex items-end gap-1">
                  {trends.apiResponseTime.map((point, index) => {
                    const height = Math.max(2, (point.value / 1000) * 60); // Scale to 60px max
                    return (
                      <div
                        key={index}
                        className="bg-blue-500 rounded-t"
                        style={{ 
                          height: `${Math.min(height, 60)}px`,
                          width: `${100 / trends.apiResponseTime.length}%`
                        }}
                        title={`${formatResponseTime(point.value)} at ${new Date(point.timestamp).toLocaleTimeString()}`}
                      />
                    );
                  })}
                </div>
              </div>
            )}

            {/* Cache Hit Rate Trend */}
            {trends.cacheHitRate && trends.cacheHitRate.length > 1 && (
              <div className="bg-gray-50 rounded-lg p-4">
                <h5 className="text-sm font-medium text-gray-700 mb-2">Cache Hit Rate Trend</h5>
                <div className="h-16 flex items-end gap-1">
                  {trends.cacheHitRate.map((point, index) => {
                    const height = Math.max(2, (point.value / 100) * 60); // Scale to 60px max
                    return (
                      <div
                        key={index}
                        className="bg-green-500 rounded-t"
                        style={{ 
                          height: `${height}px`,
                          width: `${100 / trends.cacheHitRate.length}%`
                        }}
                        title={`${point.value.toFixed(1)}% at ${new Date(point.timestamp).toLocaleTimeString()}`}
                      />
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default PerformanceMetrics;