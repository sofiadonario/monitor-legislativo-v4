/**
 * Cache Status Indicator Component
 * Displays cache performance and health status
 */

import React, { useState, useEffect } from 'react';
import { cacheService } from '../services/CacheService';

interface CacheStatusIndicatorProps {
  className?: string;
  showDetails?: boolean;
}

export const CacheStatusIndicator: React.FC<CacheStatusIndicatorProps> = ({
  className = '',
  showDetails = false
}) => {
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showFullStats, setShowFullStats] = useState(false);

  useEffect(() => {
    const loadStats = async () => {
      try {
        setLoading(true);
        const cacheStats = cacheService.getStats();
        setStats(cacheStats);
        setError(null);
      } catch (err) {
        console.error('Failed to load cache stats:', err);
        setError('Failed to load cache stats');
      } finally {
        setLoading(false);
      }
    };

    loadStats();
    
    // Refresh stats every 30 seconds
    const interval = setInterval(loadStats, 30000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className={`flex items-center gap-2 ${className}`}>
        <div className="animate-spin h-4 w-4 border-2 border-blue-500 border-t-transparent rounded-full"></div>
        <span className="text-sm text-gray-600">Loading cache status...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className={`flex items-center gap-2 ${className}`}>
        <span className="text-red-500">🔴</span>
        <span className="text-sm text-red-600">{error}</span>
      </div>
    );
  }

  if (!stats) return null;

  const getHitRateColor = (rate: number) => {
    if (rate >= 80) return 'text-green-600';
    if (rate >= 60) return 'text-yellow-600';
    return 'text-red-600';
  };

  const getHitRateEmoji = (rate: number) => {
    if (rate >= 80) return '🟢';
    if (rate >= 60) return '🟡';
    return '🔴';
  };

  return (
    <div className={`${className}`}>
      {/* Compact Status */}
      <div 
        className="flex items-center gap-2 cursor-pointer hover:bg-gray-50 px-2 py-1 rounded"
        onClick={() => setShowFullStats(!showFullStats)}
      >
        <span>{getHitRateEmoji(stats.hitRate)}</span>
        <span className="text-sm font-medium text-gray-700">
          Cache: {stats.hitRate}%
        </span>
        {showDetails && (
          <span className="text-xs text-gray-500">
            ({stats.totalItems} items, {stats.memoryUsage}MB)
          </span>
        )}
        {showDetails && (
          <span className="text-xs text-gray-400">
            {showFullStats ? '▼' : '▶'}
          </span>
        )}
      </div>

      {/* Detailed Stats Panel */}
      {showFullStats && showDetails && (
        <div className="absolute z-50 mt-2 p-4 bg-white border border-gray-200 rounded-lg shadow-lg min-w-80">
          <h3 className="text-sm font-semibold text-gray-900 mb-3">Cache Performance</h3>
          
          <div className="space-y-3">
            {/* Hit Rate */}
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Hit Rate:</span>
              <span className={`text-sm font-medium ${getHitRateColor(stats.hitRate)}`}>
                {stats.hitRate}%
              </span>
            </div>

            {/* Miss Rate */}
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Miss Rate:</span>
              <span className="text-sm text-gray-500">
                {stats.missRate}%
              </span>
            </div>

            {/* Memory Usage */}
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Memory Usage:</span>
              <span className="text-sm text-gray-700">
                {stats.memoryUsage}MB
              </span>
            </div>

            {/* Total Items */}
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Cached Items:</span>
              <span className="text-sm text-gray-700">
                {stats.totalItems}
              </span>
            </div>

            {/* Evictions */}
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Evictions:</span>
              <span className="text-sm text-gray-700">
                {stats.evictions}
              </span>
            </div>
          </div>

          {/* Actions */}
          <div className="mt-4 pt-3 border-t border-gray-200">
            <div className="flex gap-2">
              <button
                onClick={() => {
                  cacheService.clear();
                  setShowFullStats(false);
                }}
                className="px-3 py-1 text-xs bg-red-100 text-red-700 rounded hover:bg-red-200"
              >
                Clear Cache
              </button>
              <button
                onClick={() => cacheService.prefetchCommonQueries()}
                className="px-3 py-1 text-xs bg-blue-100 text-blue-700 rounded hover:bg-blue-200"
              >
                Prefetch Common
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default CacheStatusIndicator;