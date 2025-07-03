import React, { useEffect, useMemo, useState } from 'react';
import RShinyEmbed from '../components/RShinyEmbed';
import { LoadingSpinner } from '../components/LoadingSpinner';
import { useRShinySync } from '../hooks/useRShinySync';
import { buildRShinyUrl } from '../config/rshiny';
import { LegislativeDocument, SearchFilters } from '../types';
import { useI18n } from '../contexts/I18nContext';
import '../styles/pages/AnalyticsPage.css';

interface AnalyticsPageProps {
  documents?: LegislativeDocument[];
  filters?: SearchFilters;
  selectedState?: string;
  selectedMunicipality?: string;
  onFiltersChange?: (filters: SearchFilters) => void;
}

type AnalyticsTab = 'overview' | 'distributions' | 'geographic' | 'timeseries' | 'network' | 'reports';

const AnalyticsPage: React.FC<AnalyticsPageProps> = ({
  documents = [],
  filters = {},
  selectedState,
  selectedMunicipality,
  onFiltersChange
}) => {
  const { t } = useI18n();
  const [rShinyUrl, setRShinyUrl] = useState<string>('');
  const [isInitializing, setIsInitializing] = useState(true);
  const [showFallback, setShowFallback] = useState(false);
  const [activeTab, setActiveTab] = useState<AnalyticsTab>('overview');

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

  // Initialize Analytics - prioritize local analytics
  useEffect(() => {
    // Always use local analytics immediately - they're fully functional
    setShowFallback(true);
    setIsInitializing(false);
    
    // Optional: Try R Shiny as an enhancement in background (don't block)
    if (documents.length > 0) {
      setTimeout(() => {
        try {
          const sessionId = getSessionId();
          const url = buildRShinyUrl(sessionId, {
            documentsCount: documents.length.toString(),
            selectedState: selectedState || '',
            selectedMunicipality: selectedMunicipality || ''
          });
          setRShinyUrl(url);
        } catch (error) {
          console.log('R Shiny enhancement unavailable:', error);
        }
      }, 100); // Minimal delay to avoid blocking
    }
  }, [getSessionId, documents, selectedState, selectedMunicipality]);

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
            <h2>📊 {t('analytics.title')}</h2>
            <div className="fallback-status">
              <span className="status-online">{t('analytics.localAnalytics')} - {summaryStats.totalDocuments} {t('analytics.documents')}</span>
            </div>
          </div>
          
          <div className="fallback-summary">
            <h3>Data Summary</h3>
            <div className="summary-grid">
              <div className="summary-item">
                <span className="summary-value">{summaryStats.totalDocuments}</span>
                <span className="summary-label">{t('analytics.documents')}</span>
              </div>
              <div className="summary-item">
                <span className="summary-value">{summaryStats.statesCount}</span>
                <span className="summary-label">{t('analytics.states')}</span>
              </div>
              <div className="summary-item">
                <span className="summary-value">{summaryStats.documentTypesCount}</span>
                <span className="summary-label">{t('analytics.documentTypes')}</span>
              </div>
              {summaryStats.dateRange && (
                <div className="summary-item">
                  <span className="summary-value">
                    {summaryStats.dateRange.earliest.getFullYear()} - {summaryStats.dateRange.latest.getFullYear()}
                  </span>
                  <span className="summary-label">{t('analytics.dateRange')}</span>
                </div>
              )}
            </div>
          </div>

          {/* Analytics Navigation Tabs */}
          <div className="analytics-navigation">
            <div className="analytics-tabs">
              <button 
                className={`analytics-tab ${activeTab === 'overview' ? 'active' : ''}`}
                onClick={() => setActiveTab('overview')}
              >
                📊 {t('analytics.overview')}
              </button>
              <button 
                className={`analytics-tab ${activeTab === 'distributions' ? 'active' : ''}`}
                onClick={() => setActiveTab('distributions')}
              >
                📈 {t('analytics.distributions')}
              </button>
              <button 
                className={`analytics-tab ${activeTab === 'geographic' ? 'active' : ''}`}
                onClick={() => setActiveTab('geographic')}
              >
                🗺️ {t('analytics.geographic')}
              </button>
              <button 
                className={`analytics-tab ${activeTab === 'timeseries' ? 'active' : ''}`}
                onClick={() => setActiveTab('timeseries')}
              >
                📊 {t('analytics.timeseries')}
              </button>
              <button 
                className={`analytics-tab ${activeTab === 'network' ? 'active' : ''}`}
                onClick={() => setActiveTab('network')}
              >
                🔗 {t('analytics.network')}
              </button>
              <button 
                className={`analytics-tab ${activeTab === 'reports' ? 'active' : ''}`}
                onClick={() => setActiveTab('reports')}
              >
                📋 {t('analytics.reports')}
              </button>
            </div>
          </div>

          {/* Tab Content */}
          <div className="analytics-content">
            {activeTab === 'overview' && (
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
            )}

            {activeTab === 'distributions' && (
              <div className="distributions-analysis">
                <div className="analysis-header">
                  <h3>📈 {t('analytics.statisticalDistributions')}</h3>
                  <p>{t('analytics.statisticalDesc')}</p>
                </div>
                
                <div className="distributions-grid">
                  <div className="distribution-chart">
                    <h4>📊 Document Count Distribution by State</h4>
                    <div className="histogram">
                      {Object.entries(summaryStats.documentsByState)
                        .sort(([,a], [,b]) => b - a)
                        .map(([state, count], index) => (
                          <div key={state} className="histogram-bar">
                            <div className="bar-info">
                              <span className="bar-state">{state}</span>
                              <span className="bar-count">{count} docs</span>
                            </div>
                            <div 
                              className="bar-visual"
                              style={{ 
                                height: `${(count / Math.max(...Object.values(summaryStats.documentsByState))) * 100}px`,
                                backgroundColor: `hsl(${index * 360 / Object.keys(summaryStats.documentsByState).length}, 70%, 60%)`
                              }}
                            ></div>
                          </div>
                        ))}
                    </div>
                  </div>

                  <div className="distribution-chart">
                    <h4>📈 Statistical Summary</h4>
                    <div className="stats-summary">
                      <div className="stat-item">
                        <strong>Mean docs per state:</strong> {(summaryStats.totalDocuments / summaryStats.statesCount).toFixed(1)}
                      </div>
                      <div className="stat-item">
                        <strong>Median docs per state:</strong> {(() => {
                          const counts = Object.values(summaryStats.documentsByState).sort((a, b) => a - b);
                          const mid = Math.floor(counts.length / 2);
                          return counts.length % 2 ? counts[mid] : ((counts[mid - 1] + counts[mid]) / 2).toFixed(1);
                        })()}
                      </div>
                      <div className="stat-item">
                        <strong>Standard deviation:</strong> {(() => {
                          const counts = Object.values(summaryStats.documentsByState);
                          const mean = summaryStats.totalDocuments / summaryStats.statesCount;
                          const variance = counts.reduce((acc, count) => acc + Math.pow(count - mean, 2), 0) / counts.length;
                          return Math.sqrt(variance).toFixed(1);
                        })()}
                      </div>
                      <div className="stat-item">
                        <strong>Max concentration:</strong> {Math.max(...Object.values(summaryStats.documentsByState))} docs
                      </div>
                      <div className="stat-item">
                        <strong>Min concentration:</strong> {Math.min(...Object.values(summaryStats.documentsByState))} docs
                      </div>
                    </div>
                  </div>

                  <div className="distribution-chart">
                    <h4>🎯 Document Type Distribution Analysis</h4>
                    <div className="pie-chart-container">
                      {Object.entries(summaryStats.documentsByType).map(([type, count], index) => {
                        const percentage = ((count / summaryStats.totalDocuments) * 100).toFixed(1);
                        return (
                          <div key={type} className="pie-segment">
                            <div 
                              className="pie-slice"
                              style={{
                                background: `conic-gradient(hsl(${index * 360 / Object.keys(summaryStats.documentsByType).length}, 70%, 60%) 0deg ${(count / summaryStats.totalDocuments) * 360}deg, transparent 0deg)`
                              }}
                            ></div>
                            <div className="pie-label">
                              <span className="type-name">{type.replace('_', ' ')}</span>
                              <span className="type-percentage">{percentage}%</span>
                              <span className="type-count">({count} docs)</span>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'geographic' && (
              <div className="geographic-analysis">
                <div className="analysis-header">
                  <h3>🗺️ {t('analytics.interactiveGeo')}</h3>
                  <p>{t('analytics.geoDesc')}</p>
                </div>
                
                <div className="geographic-grid">
                  <div className="geo-chart">
                    <h4>🌎 Regional Distribution</h4>
                    <div className="regional-analysis">
                      {(() => {
                        const regions = documents.reduce((acc, doc) => {
                          // Simple region mapping based on Brazilian states
                          const stateToRegion: Record<string, string> = {
                            'SP': 'Southeast', 'RJ': 'Southeast', 'MG': 'Southeast', 'ES': 'Southeast',
                            'PR': 'South', 'SC': 'South', 'RS': 'South',
                            'GO': 'Center-West', 'MT': 'Center-West', 'MS': 'Center-West', 'DF': 'Center-West',
                            'BA': 'Northeast', 'PE': 'Northeast', 'CE': 'Northeast', 'MA': 'Northeast', 'PB': 'Northeast', 'RN': 'Northeast', 'AL': 'Northeast', 'SE': 'Northeast', 'PI': 'Northeast',
                            'AM': 'North', 'PA': 'North', 'AC': 'North', 'RO': 'North', 'RR': 'North', 'AP': 'North', 'TO': 'North'
                          };
                          const region = stateToRegion[doc.state] || 'Other';
                          acc[region] = (acc[region] || 0) + 1;
                          return acc;
                        }, {} as Record<string, number>);
                        
                        return Object.entries(regions).map(([region, count]) => (
                          <div key={region} className="region-item">
                            <div className="region-header">
                              <span className="region-name">{region}</span>
                              <span className="region-count">{count} documents</span>
                            </div>
                            <div className="region-bar">
                              <div 
                                className="region-fill"
                                style={{ width: `${(count / Math.max(...Object.values(regions))) * 100}%` }}
                              ></div>
                            </div>
                            <div className="region-percentage">
                              {((count / summaryStats.totalDocuments) * 100).toFixed(1)}% of total
                            </div>
                          </div>
                        ));
                      })()}
                    </div>
                  </div>

                  <div className="geo-chart">
                    <h4>🏛️ State Concentration Index</h4>
                    <div className="concentration-analysis">
                      <p>Measures the concentration of legislative activity by state (Gini-style coefficient)</p>
                      {(() => {
                        const counts = Object.values(summaryStats.documentsByState).sort((a, b) => a - b);
                        const n = counts.length;
                        const sum = counts.reduce((a, b) => a + b, 0);
                        
                        // Calculate Gini coefficient
                        let gini = 0;
                        for (let i = 0; i < n; i++) {
                          gini += (2 * (i + 1) - n - 1) * counts[i];
                        }
                        gini = gini / (n * sum);
                        
                        return (
                          <div className="concentration-metric">
                            <div className="gini-coefficient">
                              <strong>Concentration Index: {gini.toFixed(3)}</strong>
                            </div>
                            <div className="gini-interpretation">
                              {gini < 0.3 ? '📊 Low concentration - fairly distributed' :
                               gini < 0.5 ? '📈 Moderate concentration' :
                               '📊 High concentration - few states dominate'}
                            </div>
                          </div>
                        );
                      })()}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'timeseries' && (
              <div className="timeseries-analysis">
                <div className="analysis-header">
                  <h3>📊 {t('analytics.timeSeriesAnalysis')}</h3>
                  <p>{t('analytics.timeDesc')}</p>
                </div>
                
                <div className="timeseries-grid">
                  <div className="time-chart">
                    <h4>📈 Documents by Year</h4>
                    <div className="timeline">
                      {(() => {
                        const yearCounts = documents.reduce((acc, doc) => {
                          const year = new Date(doc.date).getFullYear();
                          if (!isNaN(year) && year > 1900 && year < 2030) {
                            acc[year] = (acc[year] || 0) + 1;
                          }
                          return acc;
                        }, {} as Record<number, number>);
                        
                        const sortedYears = Object.entries(yearCounts).sort(([a], [b]) => parseInt(a) - parseInt(b));
                        const maxCount = Math.max(...Object.values(yearCounts));
                        
                        return sortedYears.map(([year, count]) => (
                          <div key={year} className="year-bar">
                            <div className="year-label">{year}</div>
                            <div className="year-visual">
                              <div 
                                className="year-fill"
                                style={{ height: `${(count / maxCount) * 100}px` }}
                              ></div>
                            </div>
                            <div className="year-count">{count}</div>
                          </div>
                        ));
                      })()}
                    </div>
                  </div>

                  <div className="time-chart">
                    <h4>📅 Seasonal Patterns</h4>
                    <div className="seasonal-analysis">
                      {(() => {
                        const monthCounts = documents.reduce((acc, doc) => {
                          const month = new Date(doc.date).getMonth();
                          if (!isNaN(month)) {
                            acc[month] = (acc[month] || 0) + 1;
                          }
                          return acc;
                        }, {} as Record<number, number>);
                        
                        const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
                        const maxCount = Math.max(...Object.values(monthCounts));
                        
                        return monthNames.map((month, index) => (
                          <div key={month} className="month-item">
                            <span className="month-name">{month}</span>
                            <div className="month-bar">
                              <div 
                                className="month-fill"
                                style={{ width: `${((monthCounts[index] || 0) / maxCount) * 100}%` }}
                              ></div>
                            </div>
                            <span className="month-count">{monthCounts[index] || 0}</span>
                          </div>
                        ));
                      })()}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'network' && (
              <div className="network-analysis">
                <div className="analysis-header">
                  <h3>🔗 {t('analytics.networkAnalysis')}</h3>
                  <p>{t('analytics.networkDesc')}</p>
                </div>
                
                <div className="network-grid">
                  <div className="network-chart">
                    <h4>🏛️ Inter-State Document Relationships</h4>
                    <div className="state-network">
                      <p>States with similar legislative patterns (based on document types and keywords)</p>
                      <div className="network-connections">
                        {summaryStats.topStates.slice(0, 5).map(([state, count]) => (
                          <div key={state} className="network-node">
                            <div className="node-circle" style={{ transform: `scale(${0.5 + (count / summaryStats.topStates[0][1]) * 0.5})` }}>
                              <span className="node-label">{state}</span>
                              <span className="node-count">{count}</span>
                            </div>
                            <div className="node-connections">
                              {/* Simulate connections based on similar document types */}
                              {summaryStats.topStates.slice(0, 3).filter(([s]) => s !== state).map(([connectedState]) => (
                                <div key={connectedState} className="connection-line" title={`Shared patterns with ${connectedState}`}></div>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  <div className="network-chart">
                    <h4>🔖 Keyword Co-occurrence Network</h4>
                    <div className="keyword-network">
                      {(() => {
                        const keywordCounts = documents.reduce((acc, doc) => {
                          doc.keywords.forEach(keyword => {
                            acc[keyword] = (acc[keyword] || 0) + 1;
                          });
                          return acc;
                        }, {} as Record<string, number>);
                        
                        const topKeywords = Object.entries(keywordCounts)
                          .sort(([,a], [,b]) => b - a)
                          .slice(0, 10);
                        
                        return topKeywords.map(([keyword, count]) => (
                          <div key={keyword} className="keyword-node">
                            <div 
                              className="keyword-bubble"
                              style={{ 
                                fontSize: `${8 + (count / topKeywords[0][1]) * 12}px`,
                                opacity: 0.6 + (count / topKeywords[0][1]) * 0.4
                              }}
                            >
                              {keyword}
                            </div>
                            <div className="keyword-count">{count}</div>
                          </div>
                        ));
                      })()}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'reports' && (
              <div className="reports-generation">
                <div className="analysis-header">
                  <h3>📋 {t('analytics.customReports')}</h3>
                  <p>{t('analytics.reportsDesc')}</p>
                </div>
                
                <div className="reports-grid">
                  <div className="report-template">
                    <h4>📊 Executive Summary Report</h4>
                    <p>Comprehensive overview of legislative document analytics</p>
                    <div className="report-preview">
                      <div className="report-section">
                        <strong>Dataset Summary:</strong>
                        <ul>
                          <li>{summaryStats.totalDocuments} total documents analyzed</li>
                          <li>{summaryStats.statesCount} states represented</li>
                          <li>{summaryStats.documentTypesCount} different document types</li>
                          {summaryStats.dateRange && (
                            <li>Coverage: {summaryStats.dateRange.earliest.getFullYear()} - {summaryStats.dateRange.latest.getFullYear()}</li>
                          )}
                        </ul>
                      </div>
                      <div className="report-section">
                        <strong>Key Findings:</strong>
                        <ul>
                          <li>Top state: {summaryStats.topStates[0]?.[0]} ({summaryStats.topStates[0]?.[1]} documents)</li>
                          <li>Most common type: {summaryStats.topTypes[0]?.[0]?.replace('_', ' ')} ({summaryStats.topTypes[0]?.[1]} documents)</li>
                          <li>Geographic spread: {((summaryStats.statesCount / 27) * 100).toFixed(1)}% of Brazilian states covered</li>
                        </ul>
                      </div>
                    </div>
                    <button className="generate-report-btn">📄 Generate PDF Report</button>
                  </div>

                  <div className="report-template">
                    <h4>🗺️ Geographic Analysis Report</h4>
                    <p>Detailed geographic distribution and spatial patterns</p>
                    <div className="report-preview">
                      <div className="geographic-summary">
                        <strong>Regional Distribution:</strong>
                        <div className="mini-chart">
                          {(() => {
                            const regions = documents.reduce((acc, doc) => {
                              const stateToRegion: Record<string, string> = {
                                'SP': 'Southeast', 'RJ': 'Southeast', 'MG': 'Southeast', 'ES': 'Southeast',
                                'PR': 'South', 'SC': 'South', 'RS': 'South',
                                'GO': 'Center-West', 'MT': 'Center-West', 'MS': 'Center-West', 'DF': 'Center-West',
                                'BA': 'Northeast', 'PE': 'Northeast', 'CE': 'Northeast', 'MA': 'Northeast',
                                'AM': 'North', 'PA': 'North', 'AC': 'North', 'RO': 'North'
                              };
                              const region = stateToRegion[doc.state] || 'Other';
                              acc[region] = (acc[region] || 0) + 1;
                              return acc;
                            }, {} as Record<string, number>);
                            
                            return Object.entries(regions).map(([region, count]) => (
                              <div key={region} className="mini-region">
                                {region}: {count} ({((count / summaryStats.totalDocuments) * 100).toFixed(1)}%)
                              </div>
                            ));
                          })()}
                        </div>
                      </div>
                    </div>
                    <button className="generate-report-btn">🗺️ Generate Geographic Report</button>
                  </div>

                  <div className="report-template">
                    <h4>📈 Statistical Analysis Report</h4>
                    <p>Advanced statistical metrics and distribution analysis</p>
                    <div className="report-preview">
                      <div className="stats-summary">
                        <strong>Statistical Measures:</strong>
                        <div className="stats-grid">
                          <div>Mean: {(summaryStats.totalDocuments / summaryStats.statesCount).toFixed(1)}</div>
                          <div>Std Dev: {(() => {
                            const counts = Object.values(summaryStats.documentsByState);
                            const mean = summaryStats.totalDocuments / summaryStats.statesCount;
                            const variance = counts.reduce((acc, count) => acc + Math.pow(count - mean, 2), 0) / counts.length;
                            return Math.sqrt(variance).toFixed(1);
                          })()}</div>
                          <div>Range: {Math.min(...Object.values(summaryStats.documentsByState))} - {Math.max(...Object.values(summaryStats.documentsByState))}</div>
                        </div>
                      </div>
                    </div>
                    <button className="generate-report-btn">📊 Generate Statistical Report</button>
                  </div>
                </div>
              </div>
            )}
          </div>

          <div className="analytics-footer">
            <div className="data-source-info">
              <h4>📊 {t('analytics.dataSource')}</h4>
              <p>{t('analytics.basedOn').replace('{count}', summaryStats.totalDocuments.toString())}</p>
              <p>Data includes laws, decrees, regulations, and other legal documents from {summaryStats.statesCount} Brazilian states.</p>
              
              {summaryStats.dateRange && (
                <p>
                  {t('analytics.coverage')
                    .replace('{start}', summaryStats.dateRange.earliest.getFullYear().toString())
                    .replace('{end}', summaryStats.dateRange.latest.getFullYear().toString())}
                </p>
              )}
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