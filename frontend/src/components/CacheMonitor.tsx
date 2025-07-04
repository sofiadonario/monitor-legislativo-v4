import React, { useState } from 'react';
import useCache from '../hooks/useCache';
import './CacheMonitor.css';

interface CacheMonitorProps {
  className?: string;
  showDetailedView?: boolean;
}

const CacheMonitor: React.FC<CacheMonitorProps> = ({ 
  className = '',
  showDetailedView = false 
}) => {
  const {
    cacheStatus,
    isLoading,
    error,
    clearCache,
    preloadCache,
    forceRefresh,
    refreshStatus,
    getCacheHealthColor,
    getCacheHealthText,
    getHitRateColor,
    getResponseTimeColor
  } = useCache();

  const [isExpanded, setIsExpanded] = useState(showDetailedView);
  const [activeAction, setActiveAction] = useState<string | null>(null);

  const handleAction = async (action: string, ...args: any[]) => {
    setActiveAction(action);
    try {
      switch (action) {
        case 'clear-all':
          await clearCache('all');
          break;
        case 'clear-documents':
          await clearCache('documents');
          break;
        case 'clear-search':
          await clearCache('search');
          break;
        case 'clear-collections':
          await clearCache('collections');
          break;
        case 'preload':
          await preloadCache();
          break;
        case 'force-refresh':
          await forceRefresh();
          break;
        case 'refresh-status':
          await refreshStatus();
          break;
      }
    } finally {
      setActiveAction(null);
    }
  };

  if (isLoading) {
    return (
      <div className={`cache-monitor loading ${className}`}>
        <div className="loading-spinner"></div>
        <span>Loading cache status...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className={`cache-monitor error ${className}`}>
        <div className="error-icon">⚠️</div>
        <div className="error-message">
          <h4>Cache Monitor Error</h4>
          <p>{error}</p>
          <button 
            onClick={() => refreshStatus()}
            className="retry-button"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  if (!cacheStatus) {
    return (
      <div className={`cache-monitor no-data ${className}`}>
        <div className="no-data-icon">📊</div>
        <span>No cache data available</span>
      </div>
    );
  }

  const { metrics, sizes, invalidation, isHealthy, lastUpdated } = cacheStatus;

  return (
    <div className={`cache-monitor ${isHealthy ? 'healthy' : 'unhealthy'} ${className}`}>
      {/* Header */}
      <div className="cache-monitor-header">
        <div className="status-indicator">
          <div 
            className="status-dot"
            style={{ backgroundColor: getCacheHealthColor(isHealthy) }}
          ></div>
          <h3>Cache Status: {getCacheHealthText(isHealthy)}</h3>
        </div>
        
        <div className="header-actions">
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="expand-button"
            aria-label={isExpanded ? 'Collapse' : 'Expand'}
          >
            {isExpanded ? '▼' : '▶'}
          </button>
          
          <button
            onClick={() => handleAction('refresh-status')}
            className="refresh-button"
            disabled={activeAction === 'refresh-status'}
          >
            🔄
          </button>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="cache-metrics-summary">
        <div className="metric">
          <span className="metric-label">Hit Rate</span>
          <span 
            className="metric-value"
            style={{ color: getHitRateColor(metrics.hitRate) }}
          >
            {metrics.hitRate.toFixed(1)}%
          </span>
        </div>
        
        <div className="metric">
          <span className="metric-label">Avg Response</span>
          <span 
            className="metric-value"
            style={{ color: getResponseTimeColor(metrics.averageResponseTime) }}
          >
            {metrics.averageResponseTime.toFixed(0)}ms
          </span>
        </div>
        
        <div className="metric">
          <span className="metric-label">Total Size</span>
          <span className="metric-value">
            {sizes.formatted.total}
          </span>
        </div>
        
        <div className="metric">
          <span className="metric-label">Efficiency</span>
          <span className="metric-value">
            {metrics.cacheEfficiency.toFixed(1)}%
          </span>
        </div>
      </div>

      {/* Expanded Details */}
      {isExpanded && (
        <div className="cache-monitor-details">
          {/* Detailed Metrics */}
          <div className="metrics-section">
            <h4>Performance Metrics</h4>
            <div className="metrics-grid">
              <div className="metric-item">
                <span>Total Requests</span>
                <span>{metrics.totalRequests.toLocaleString()}</span>
              </div>
              <div className="metric-item">
                <span>Memory Hits</span>
                <span>{metrics.memoryHits.toLocaleString()}</span>
              </div>
              <div className="metric-item">
                <span>Session Hits</span>
                <span>{metrics.sessionStorageHits.toLocaleString()}</span>
              </div>
              <div className="metric-item">
                <span>Local Storage Hits</span>
                <span>{metrics.localStorageHits.toLocaleString()}</span>
              </div>
              <div className="metric-item">
                <span>Redis Hits</span>
                <span>{metrics.redisHits.toLocaleString()}</span>
              </div>
            </div>
          </div>

          {/* Storage Usage */}
          <div className="storage-section">
            <h4>Storage Usage</h4>
            <div className="storage-breakdown">
              <div className="storage-item">
                <span>Memory Cache</span>
                <div className="storage-bar">
                  <div 
                    className="storage-fill memory"
                    style={{ width: `${(sizes.memory / sizes.totalSize) * 100}%` }}
                  ></div>
                </div>
                <span>{sizes.formatted.memory}</span>
              </div>
              
              <div className="storage-item">
                <span>Session Storage</span>
                <div className="storage-bar">
                  <div 
                    className="storage-fill session"
                    style={{ width: `${(sizes.session / sizes.totalSize) * 100}%` }}
                  ></div>
                </div>
                <span>{sizes.formatted.session}</span>
              </div>
              
              <div className="storage-item">
                <span>Local Storage</span>
                <div className="storage-bar">
                  <div 
                    className="storage-fill local"
                    style={{ width: `${(sizes.local / sizes.totalSize) * 100}%` }}
                  ></div>
                </div>
                <span>{sizes.formatted.local}</span>
              </div>
              
              <div className="storage-item">
                <span>Redis Cache</span>
                <div className="storage-bar">
                  <div 
                    className="storage-fill redis"
                    style={{ width: `${(sizes.redis / sizes.totalSize) * 100}%` }}
                  ></div>
                </div>
                <span>{sizes.formatted.redis}</span>
              </div>
            </div>
          </div>

          {/* Background Operations */}
          <div className="operations-section">
            <h4>Background Operations</h4>
            <div className="operations-info">
              <div className="operation-stat">
                <span>Active Refreshes</span>
                <span className={invalidation.activeRefreshes > 5 ? 'warning' : ''}>
                  {invalidation.activeRefreshes}
                </span>
              </div>
              <div className="operation-stat">
                <span>Queued Refreshes</span>
                <span>{invalidation.queuedRefreshes}</span>
              </div>
              <div className="operation-stat">
                <span>Dependencies</span>
                <span>{invalidation.dependencies.length}</span>
              </div>
            </div>

            {Object.keys(invalidation.errorCounts).length > 0 && (
              <div className="error-counts">
                <h5>Error Counts</h5>
                {Object.entries(invalidation.errorCounts).map(([key, count]) => (
                  <div key={key} className="error-item">
                    <span>{key}</span>
                    <span className="error-count">{count}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Cache Actions */}
          <div className="actions-section">
            <h4>Cache Management</h4>
            <div className="action-buttons">
              <button
                onClick={() => handleAction('preload')}
                disabled={activeAction === 'preload'}
                className="action-button preload"
              >
                {activeAction === 'preload' ? '⏳' : '🚀'} Preload Cache
              </button>
              
              <button
                onClick={() => handleAction('force-refresh')}
                disabled={activeAction === 'force-refresh'}
                className="action-button refresh"
              >
                {activeAction === 'force-refresh' ? '⏳' : '🔄'} Force Refresh
              </button>
              
              <button
                onClick={() => handleAction('clear-documents')}
                disabled={activeAction === 'clear-documents'}
                className="action-button clear"
              >
                {activeAction === 'clear-documents' ? '⏳' : '📄'} Clear Documents
              </button>
              
              <button
                onClick={() => handleAction('clear-search')}
                disabled={activeAction === 'clear-search'}
                className="action-button clear"
              >
                {activeAction === 'clear-search' ? '⏳' : '🔍'} Clear Search
              </button>
              
              <button
                onClick={() => handleAction('clear-all')}
                disabled={activeAction === 'clear-all'}
                className="action-button clear-all"
              >
                {activeAction === 'clear-all' ? '⏳' : '🗑️'} Clear All
              </button>
            </div>
          </div>

          {/* Last Updated */}
          <div className="timestamp">
            Last updated: {new Date(lastUpdated).toLocaleTimeString()}
          </div>
        </div>
      )}
    </div>
  );
};

export default CacheMonitor;