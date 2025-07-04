import React, { useEffect, useState } from 'react';
import { CollectionLog, CollectionStatus as CollectionStatusType } from '../types';
import { legislativeDataService } from '../services/legislativeDataService';
import '../styles/components/CollectionStatus.css';

interface CollectionStatusProps {
  className?: string;
  compact?: boolean;
}

export const CollectionStatus: React.FC<CollectionStatusProps> = ({ className = '', compact = false }) => {
  const [latestCollection, setLatestCollection] = useState<CollectionLog | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshInterval] = useState(30000); // 30 seconds

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        setIsLoading(true);
        const collection = await legislativeDataService.fetchLatestCollection();
        setLatestCollection(collection);
        setError(null);
      } catch (err) {
        setError('Failed to fetch collection status');
        console.error('Collection status error:', err);
      } finally {
        setIsLoading(false);
      }
    };

    fetchStatus();
    const interval = setInterval(fetchStatus, refreshInterval);

    return () => clearInterval(interval);
  }, [refreshInterval]);

  const getStatusColor = (status: CollectionStatusType): string => {
    switch (status) {
      case 'completed': return '#28a745';
      case 'running': return '#17a2b8';
      case 'pending': return '#ffc107';
      case 'failed': return '#dc3545';
      default: return '#6c757d';
    }
  };

  const getStatusIcon = (status: CollectionStatusType): string => {
    switch (status) {
      case 'completed': return '✓';
      case 'running': return '⟳';
      case 'pending': return '⏳';
      case 'failed': return '✗';
      default: return '?';
    }
  };

  const formatTime = (ms: number): string => {
    if (ms < 1000) return `${ms}ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
    return `${(ms / 60000).toFixed(1)}min`;
  };

  const formatDate = (dateString: string): string => {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 1) return 'just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffMins < 1440) return `${Math.floor(diffMins / 60)}h ago`;
    return date.toLocaleDateString();
  };

  if (isLoading && !latestCollection) {
    return (
      <div className={`collection-status ${className}`}>
        <div className="status-loading">Loading collection status...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className={`collection-status ${className}`}>
        <div className="status-error">{error}</div>
      </div>
    );
  }

  if (!latestCollection) {
    return (
      <div className={`collection-status ${className}`}>
        <div className="status-empty">No collection data available</div>
      </div>
    );
  }

  if (compact) {
    return (
      <div className={`collection-status collection-status-compact ${className}`}>
        <span 
          className="status-indicator" 
          style={{ backgroundColor: getStatusColor(latestCollection.status) }}
          title={`Status: ${latestCollection.status}`}
        >
          {getStatusIcon(latestCollection.status)}
        </span>
        <span className="status-text">
          {latestCollection.status === 'running' ? 'Collecting...' : `Last: ${formatDate(latestCollection.startedAt)}`}
        </span>
        {latestCollection.recordsCollected > 0 && (
          <span className="status-count">{latestCollection.recordsCollected} docs</span>
        )}
      </div>
    );
  }

  return (
    <div className={`collection-status ${className}`}>
      <div className="status-header">
        <h3>Data Collection Status</h3>
        <span 
          className="status-badge" 
          style={{ backgroundColor: getStatusColor(latestCollection.status) }}
        >
          {getStatusIcon(latestCollection.status)} {latestCollection.status}
        </span>
      </div>
      
      <div className="status-details">
        <div className="status-row">
          <span className="status-label">Search Term:</span>
          <span className="status-value">{latestCollection.searchTerm}</span>
        </div>
        
        <div className="status-row">
          <span className="status-label">Started:</span>
          <span className="status-value">{formatDate(latestCollection.startedAt)}</span>
        </div>
        
        {latestCollection.completedAt && (
          <div className="status-row">
            <span className="status-label">Duration:</span>
            <span className="status-value">{formatTime(latestCollection.executionTimeMs)}</span>
          </div>
        )}
        
        <div className="status-metrics">
          <div className="metric">
            <span className="metric-value">{latestCollection.recordsCollected}</span>
            <span className="metric-label">Total</span>
          </div>
          <div className="metric">
            <span className="metric-value">{latestCollection.recordsNew}</span>
            <span className="metric-label">New</span>
          </div>
          <div className="metric">
            <span className="metric-value">{latestCollection.recordsUpdated}</span>
            <span className="metric-label">Updated</span>
          </div>
          <div className="metric">
            <span className="metric-value">{latestCollection.recordsSkipped}</span>
            <span className="metric-label">Skipped</span>
          </div>
        </div>
        
        {latestCollection.sourcesUsed.length > 0 && (
          <div className="status-row">
            <span className="status-label">Sources:</span>
            <span className="status-value">{latestCollection.sourcesUsed.join(', ')}</span>
          </div>
        )}
        
        {latestCollection.errorMessage && (
          <div className="status-error-message">
            <strong>Error:</strong> {latestCollection.errorMessage}
          </div>
        )}
      </div>
    </div>
  );
};