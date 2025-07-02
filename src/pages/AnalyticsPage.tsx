import React, { useEffect, useMemo, useState } from 'react';
import RShinyEmbed from '../components/RShinyEmbed';
import { LoadingSpinner } from '../components/LoadingSpinner';
import { useRShinySync } from '../hooks/useRShinySync';
import { buildRShinyUrl } from '../config/rshiny';
import { LegislativeDocument, SearchFilters } from '../types';
import '../styles/pages/AnalyticsPage.css';

interface AnalyticsPageProps {
  documents?: LegislativeDocument[];
  filters?: SearchFilters;
  selectedState?: string;
  selectedMunicipality?: string;
  onFiltersChange?: (filters: SearchFilters) => void;
}

const AnalyticsPage: React.FC<AnalyticsPageProps> = ({
  documents = [],
  filters = {},
  selectedState,
  selectedMunicipality,
  onFiltersChange
}) => {
  const [rShinyUrl, setRShinyUrl] = useState<string>('');
  const [isInitializing, setIsInitializing] = useState(true);
  const [showFallback, setShowFallback] = useState(false);

  const {
    connectionStatus,
    syncFilters,
    syncDocuments,
    syncSelection,
    forceSync,
    getRShinyUrl,
    getSessionId,
    isConnected,
    isLoading,
    hasError,
    hasPendingSync
  } = useRShinySync({
    autoSync: false, // Disable auto sync to prevent resource exhaustion
    syncFiltersDelay: 5000, // Increase delay to 5 seconds
    syncDocumentsDelay: 10000 // Increase delay to 10 seconds
  });

  // Initialize Analytics - use local data first, R Shiny as enhancement
  useEffect(() => {
    const initializeAnalytics = async () => {
      setIsInitializing(true);
      
      try {
        // Always show local analytics, don't depend on R Shiny connection
        if (documents.length > 0) {
          setShowFallback(true); // Use fallback which shows local analytics
          setIsInitializing(false);
          return;
        }
        
        // Try R Shiny as enhancement if available
        const sessionId = getSessionId();
        const url = buildRShinyUrl(sessionId, {
          documentsCount: documents.length.toString(),
          selectedState: selectedState || '',
          selectedMunicipality: selectedMunicipality || ''
        });
        
        setRShinyUrl(url);
        setIsInitializing(false);
      } catch (error) {
        console.error('Failed to initialize analytics:', error);
        setShowFallback(true);
        setIsInitializing(false);
      }
    };

    initializeAnalytics();
  }, [getRShinyUrl, getSessionId, forceSync, filters, documents, selectedState, selectedMunicipality]);

  // Only sync manually when R Shiny is actually connected
  // Removed automatic sync to prevent resource exhaustion

  const handleRShinyLoad = () => {
    console.log('R Shiny application loaded successfully');
  };

  const handleRShinyError = (error: string) => {
    console.error('R Shiny application error:', error);
    setShowFallback(true);
  };

  const handleRetryConnection = () => {
    setShowFallback(false);
    setIsInitializing(true);
    // Re-trigger initialization
    window.location.reload();
  };

  const summaryStats = useMemo(() => {
    const statesCount = new Set(documents.map(doc => doc.state).filter(Boolean)).size;
    const documentTypesCount = new Set(documents.map(doc => doc.type).filter(Boolean)).size;
    const dateRange = documents.length > 0 ? {
      earliest: new Date(Math.min(...documents.map(doc => new Date(doc.date).getTime()))),
      latest: new Date(Math.max(...documents.map(doc => new Date(doc.date).getTime())))
    } : null;

    // Enhanced analytics
    const documentsByType = documents.reduce((acc, doc) => {
      acc[doc.type] = (acc[doc.type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const documentsByState = documents.reduce((acc, doc) => {
      if (doc.state) {
        acc[doc.state] = (acc[doc.state] || 0) + 1;
      }
      return acc;
    }, {} as Record<string, number>);

    const documentsByStatus = documents.reduce((acc, doc) => {
      acc[doc.status] = (acc[doc.status] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const topStates = Object.entries(documentsByState)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 5);

    const topTypes = Object.entries(documentsByType)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 5);

    return {
      totalDocuments: documents.length,
      statesCount,
      documentTypesCount,
      dateRange,
      documentsByType,
      documentsByState,
      documentsByStatus,
      topStates,
      topTypes
    };
  }, [documents]);

  if (isInitializing) {
    return (
      <div className="analytics-page analytics-loading">
        <LoadingSpinner message="Initializing R Shiny Analytics..." />
        <div className="loading-details">
          <p>Setting up analytics workspace...</p>
          <p>Synchronizing {documents.length} documents</p>
        </div>
      </div>
    );
  }

  if (showFallback) {
    return (
      <div className="analytics-page analytics-fallback">
        <div className="fallback-content">
          <div className="fallback-header">
            <h2>📊 Analytics Dashboard</h2>
            <div className="fallback-status">
              <span className="status-online">Local Analytics - {summaryStats.totalDocuments} Documents</span>
            </div>
          </div>
          
          <div className="fallback-summary">
            <h3>Data Summary</h3>
            <div className="summary-grid">
              <div className="summary-item">
                <span className="summary-value">{summaryStats.totalDocuments}</span>
                <span className="summary-label">Documents</span>
              </div>
              <div className="summary-item">
                <span className="summary-value">{summaryStats.statesCount}</span>
                <span className="summary-label">States</span>
              </div>
              <div className="summary-item">
                <span className="summary-value">{summaryStats.documentTypesCount}</span>
                <span className="summary-label">Document Types</span>
              </div>
              {summaryStats.dateRange && (
                <div className="summary-item">
                  <span className="summary-value">
                    {summaryStats.dateRange.earliest.getFullYear()} - {summaryStats.dateRange.latest.getFullYear()}
                  </span>
                  <span className="summary-label">Date Range</span>
                </div>
              )}
            </div>
          </div>

          <div className="analytics-charts">
            <div className="chart-section">
              <h4>📊 Top 5 States by Document Count</h4>
              <div className="chart-bars">
                {summaryStats.topStates.map(([state, count]) => (
                  <div key={state} className="chart-bar">
                    <span className="bar-label">{state}</span>
                    <div className="bar-container">
                      <div 
                        className="bar-fill" 
                        style={{ 
                          width: `${(count / summaryStats.topStates[0][1]) * 100}%` 
                        }}
                      ></div>
                      <span className="bar-value">{count}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="chart-section">
              <h4>📄 Document Types Distribution</h4>
              <div className="chart-bars">
                {summaryStats.topTypes.map(([type, count]) => (
                  <div key={type} className="chart-bar">
                    <span className="bar-label">{type.replace('_', ' ')}</span>
                    <div className="bar-container">
                      <div 
                        className="bar-fill bar-fill-secondary" 
                        style={{ 
                          width: `${(count / summaryStats.topTypes[0][1]) * 100}%` 
                        }}
                      ></div>
                      <span className="bar-value">{count}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="chart-section">
              <h4>⚖️ Document Status Overview</h4>
              <div className="status-grid">
                {Object.entries(summaryStats.documentsByStatus).map(([status, count]) => (
                  <div key={status} className="status-item">
                    <span className="status-count">{count}</span>
                    <span className="status-label">{status.replace('_', ' ')}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="fallback-message">
            <p>The R Shiny analytics application is running locally but cannot be accessed from GitHub Pages due to browser security restrictions (HTTPS → HTTP blocking).</p>
            
            <h4>📋 How to Access R Shiny Analytics:</h4>
            <div className="access-instructions">
              <div className="instruction-item">
                <strong>Option 1: Direct Access</strong>
                <p>Open R Shiny directly in a new tab:</p>
                <a 
                  href="http://localhost:3838" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="external-btn"
                >
                  🔗 Open R Shiny Dashboard
                </a>
                <p className="login-info">Login: <code>admin</code> / <code>admin123</code></p>
              </div>
              
              <div className="instruction-item">
                <strong>Option 2: Local Development</strong>
                <p>Run the React app locally to enable full integration:</p>
                <code>npm run dev</code>
                <p>Then visit: <a href="http://localhost:3000/monitor-legislativo-v4/" target="_blank">http://localhost:3000/monitor-legislativo-v4/</a></p>
              </div>
            </div>
            
            <div className="fallback-actions">
              <button onClick={handleRetryConnection} className="retry-btn">
                🔄 Test Connection Again
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="analytics-page">
      <div className="analytics-header">
        <h2>📊 Advanced Analytics</h2>
        <div className="analytics-status">
          <div className={`connection-indicator ${isConnected ? 'connected' : 'disconnected'}`}>
            <span className="status-dot"></span>
            {isConnected ? 'Connected' : 'Disconnected'}
          </div>
          
          {isLoading && (
            <div className="sync-indicator">
              <span className="sync-spinner">⟳</span>
              Syncing...
            </div>
          )}
          
          {hasPendingSync && (
            <div className="queue-indicator">
              <span className="queue-count">{connectionStatus.queueSize}</span>
              Queued
            </div>
          )}
          
          {hasError && (
            <div className="error-indicator" title={connectionStatus.error || 'Unknown error'}>
              ⚠️ Sync Error
            </div>
          )}
        </div>
      </div>

      <div className="analytics-summary">
        <div className="summary-item">
          <span className="summary-value">{summaryStats.totalDocuments}</span>
          <span className="summary-label">Documents Loaded</span>
        </div>
        <div className="summary-item">
          <span className="summary-value">{summaryStats.statesCount}</span>
          <span className="summary-label">States</span>
        </div>
        {selectedState && (
          <div className="summary-item selected">
            <span className="summary-value">{selectedState}</span>
            <span className="summary-label">Selected State</span>
          </div>
        )}
        {selectedMunicipality && (
          <div className="summary-item selected">
            <span className="summary-value">{selectedMunicipality}</span>
            <span className="summary-label">Selected Municipality</span>
          </div>
        )}
      </div>

      <div className="analytics-content">
        <RShinyEmbed
          url={rShinyUrl}
          title="Legislative Analytics Dashboard"
          height="calc(100vh - 200px)"
          onLoad={handleRShinyLoad}
          onError={handleRShinyError}
          className="main-analytics-embed"
          allowFullscreen={true}
        />
      </div>

      <div className="analytics-footer">
        <div className="sync-info">
          {connectionStatus.lastSyncTime && (
            <span className="last-sync">
              Last sync: {new Date(connectionStatus.lastSyncTime).toLocaleTimeString()}
            </span>
          )}
        </div>
        
        <div className="analytics-controls">
          <button 
            onClick={() => forceSync(filters, documents, selectedState, selectedMunicipality)}
            disabled={isLoading}
            className="force-sync-btn"
          >
            {isLoading ? '⟳ Syncing...' : '🔄 Force Sync'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default AnalyticsPage;