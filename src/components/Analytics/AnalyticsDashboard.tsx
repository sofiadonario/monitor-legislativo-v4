/**
 * Analytics Dashboard
 * Comprehensive analytics dashboard with real-time metrics and AI insights
 */
import React, { useState, useEffect, useMemo } from 'react';
import { 
  AnalyticsReport, 
  ReportType, 
  UserAnalytics,
  TrendAnalysis,
  analyticsService 
} from '../../services/analyticsService';
import { 
  AIInsight, 
  KnowledgeGraph, 
  PredictiveModel,
  aiInsightsService 
} from '../../services/aiInsightsService';
import { LegislativeDocument } from '../../types';

interface AnalyticsDashboardProps {
  userId: string;
  documents?: LegislativeDocument[];
  onReportGenerate?: (report: AnalyticsReport) => void;
  onInsightAction?: (insight: AIInsight, action: string) => void;
  enableRealTime?: boolean;
  showAIInsights?: boolean;
}

export const AnalyticsDashboard: React.FC<AnalyticsDashboardProps> = ({
  userId,
  documents = [],
  onReportGenerate,
  onInsightAction,
  enableRealTime = true,
  showAIInsights = true
}) => {
  // State management
  const [activeTab, setActiveTab] = useState<'overview' | 'reports' | 'insights' | 'trends' | 'models'>('overview');
  const [realTimeData, setRealTimeData] = useState<any>(null);
  const [reports, setReports] = useState<AnalyticsReport[]>([]);
  const [aiInsights, setAIInsights] = useState<AIInsight[]>([]);
  const [userAnalytics, setUserAnalytics] = useState<UserAnalytics | null>(null);
  const [trends, setTrends] = useState<TrendAnalysis[]>([]);
  const [knowledgeGraph, setKnowledgeGraph] = useState<KnowledgeGraph | null>(null);
  const [predictiveModels, setPredictiveModels] = useState<PredictiveModel[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [selectedPeriod, setSelectedPeriod] = useState<'7d' | '30d' | '90d' | '1y'>('30d');
  const [selectedReportType, setSelectedReportType] = useState<ReportType>('usage_summary');

  // Real-time data polling
  useEffect(() => {
    if (enableRealTime) {
      const interval = setInterval(() => {
        loadRealTimeData();
      }, 5000);
      return () => clearInterval(interval);
    }
  }, [enableRealTime]);

  // Initial data loading
  useEffect(() => {
    loadInitialData();
  }, [userId, selectedPeriod]);

  /**
   * Load initial dashboard data
   */
  const loadInitialData = async (): Promise<void> => {
    setIsLoading(true);
    try {
      const period = getPeriodDates(selectedPeriod);
      
      // Load user analytics
      const analytics = await analyticsService.analyzeUserBehavior(userId, period);
      setUserAnalytics(analytics);

      // Load AI insights if enabled
      if (showAIInsights && documents.length > 0) {
        const insights = await aiInsightsService.generateDocumentInsights(documents, {
          temporalContext: period
        });
        setAIInsights(insights);
      }

      // Load real-time data
      if (enableRealTime) {
        loadRealTimeData();
      }
    } catch (error) {
      console.error('Failed to load initial data:', error);
    } finally {
      setIsLoading(false);
    }
  };

  /**
   * Load real-time dashboard data
   */
  const loadRealTimeData = async (): Promise<void> => {
    try {
      const realTime = analyticsService.getRealTimeDashboard();
      setRealTimeData(realTime);
    } catch (error) {
      console.error('Failed to load real-time data:', error);
    }
  };

  /**
   * Generate analytics report
   */
  const generateReport = async (): Promise<void> => {
    setIsLoading(true);
    try {
      const period = getPeriodDates(selectedPeriod);
      const report = await analyticsService.generateReport(
        selectedReportType,
        period,
        userId
      );
      
      setReports(prev => [report, ...prev]);
      
      if (onReportGenerate) {
        onReportGenerate(report);
      }
    } catch (error) {
      console.error('Failed to generate report:', error);
    } finally {
      setIsLoading(false);
    }
  };

  /**
   * Generate trend analysis
   */
  const generateTrendAnalysis = async (trendType: any): Promise<void> => {
    try {
      const period = getPeriodDates(selectedPeriod);
      const trend = await analyticsService.analyzeTrends(trendType, period);
      setTrends(prev => [trend, ...prev]);
    } catch (error) {
      console.error('Failed to generate trend analysis:', error);
    }
  };

  /**
   * Build knowledge graph
   */
  const buildKnowledgeGraph = async (): Promise<void> => {
    if (documents.length === 0) return;
    
    setIsLoading(true);
    try {
      const graph = await aiInsightsService.buildKnowledgeGraph(documents);
      setKnowledgeGraph(graph);
    } catch (error) {
      console.error('Failed to build knowledge graph:', error);
    } finally {
      setIsLoading(false);
    }
  };

  /**
   * Handle insight action
   */
  const handleInsightAction = (insight: AIInsight, action: string): void => {
    if (onInsightAction) {
      onInsightAction(insight, action);
    }
    
    // Update insight based on action
    setAIInsights(prev => prev.map(i => 
      i.id === insight.id 
        ? { ...i, /* update based on action */ }
        : i
    ));
  };

  /**
   * Get period dates
   */
  const getPeriodDates = (period: string): { start: Date; end: Date } => {
    const end = new Date();
    const start = new Date();
    
    switch (period) {
      case '7d':
        start.setDate(end.getDate() - 7);
        break;
      case '30d':
        start.setDate(end.getDate() - 30);
        break;
      case '90d':
        start.setDate(end.getDate() - 90);
        break;
      case '1y':
        start.setFullYear(end.getFullYear() - 1);
        break;
    }
    
    return { start, end };
  };

  /**
   * Format numbers for display
   */
  const formatNumber = (num: number): string => {
    if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
    if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
    return num.toString();
  };

  /**
   * Get insight priority color
   */
  const getInsightPriorityColor = (priority: string): string => {
    const colors = {
      low: '#10b981',
      medium: '#f59e0b',
      high: '#ef4444',
      critical: '#dc2626'
    };
    return colors[priority as keyof typeof colors] || '#6b7280';
  };

  /**
   * Get insight type icon
   */
  const getInsightTypeIcon = (type: string): string => {
    const icons = {
      research_opportunity: '🔍',
      trend_prediction: '📈',
      anomaly_detection: '⚠️',
      gap_analysis: '🕳️',
      correlation_discovery: '🔗',
      pattern_recognition: '🧩',
      sentiment_shift: '💭',
      impact_assessment: '💥',
      regulatory_prediction: '⚖️',
      policy_recommendation: '📋',
      risk_identification: '🚨',
      knowledge_synthesis: '🧠'
    };
    return icons[type as keyof typeof icons] || '💡';
  };

  return (
    <div className="analytics-dashboard">
      {/* Header */}
      <div className="dashboard-header">
        <div className="header-content">
          <h1>Analytics Dashboard</h1>
          <p>Comprehensive analytics and AI-powered insights for your research</p>
        </div>
        
        <div className="header-controls">
          <select
            value={selectedPeriod}
            onChange={(e) => setSelectedPeriod(e.target.value as any)}
            className="period-selector"
          >
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
            <option value="90d">Last 90 days</option>
            <option value="1y">Last year</option>
          </select>
          
          <button
            onClick={() => loadInitialData()}
            className="refresh-btn"
            disabled={isLoading}
          >
            🔄 Refresh
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="dashboard-tabs">
        <button
          className={`tab ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveTab('overview')}
        >
          📊 Overview
        </button>
        <button
          className={`tab ${activeTab === 'reports' ? 'active' : ''}`}
          onClick={() => setActiveTab('reports')}
        >
          📈 Reports
        </button>
        {showAIInsights && (
          <button
            className={`tab ${activeTab === 'insights' ? 'active' : ''}`}
            onClick={() => setActiveTab('insights')}
          >
            🧠 AI Insights
          </button>
        )}
        <button
          className={`tab ${activeTab === 'trends' ? 'active' : ''}`}
          onClick={() => setActiveTab('trends')}
        >
          📈 Trends
        </button>
        <button
          className={`tab ${activeTab === 'models' ? 'active' : ''}`}
          onClick={() => setActiveTab('models')}
        >
          🤖 Models
        </button>
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && (
        <div className="overview-panel">
          {/* Real-time Metrics */}
          {enableRealTime && realTimeData && (
            <div className="real-time-section">
              <h2>Real-time Metrics</h2>
              <div className="metrics-grid">
                <div className="metric-card">
                  <div className="metric-value">{realTimeData.currentUsers}</div>
                  <div className="metric-label">Active Users</div>
                  <div className="metric-change">👥 Online Now</div>
                </div>
                <div className="metric-card">
                  <div className="metric-value">{realTimeData.searchesPerMinute}</div>
                  <div className="metric-label">Searches/min</div>
                  <div className="metric-change">🔍 Live Activity</div>
                </div>
                <div className="metric-card">
                  <div className="metric-value">{realTimeData.documentsAccessed}</div>
                  <div className="metric-label">Documents/min</div>
                  <div className="metric-change">📄 Access Rate</div>
                </div>
                <div className="metric-card">
                  <div className="metric-value">{realTimeData.collaborativeSessions}</div>
                  <div className="metric-label">Active Sessions</div>
                  <div className="metric-change">🤝 Collaboration</div>
                </div>
              </div>
            </div>
          )}

          {/* User Analytics Summary */}
          {userAnalytics && (
            <div className="user-analytics-section">
              <h2>Your Research Analytics</h2>
              <div className="analytics-grid">
                <div className="analytics-card">
                  <h3>Session Activity</h3>
                  <div className="session-metrics">
                    <div className="metric">
                      <span className="metric-label">Total Sessions:</span>
                      <span className="metric-value">{userAnalytics.sessionMetrics.totalSessions}</span>
                    </div>
                    <div className="metric">
                      <span className="metric-label">Avg Duration:</span>
                      <span className="metric-value">{Math.round(userAnalytics.sessionMetrics.averageSessionDuration)}m</span>
                    </div>
                    <div className="metric">
                      <span className="metric-label">Total Time:</span>
                      <span className="metric-value">{Math.round(userAnalytics.sessionMetrics.totalTimeSpent / 60)}h</span>
                    </div>
                  </div>
                </div>

                <div className="analytics-card">
                  <h3>Search Behavior</h3>
                  <div className="search-metrics">
                    <div className="metric">
                      <span className="metric-label">Total Searches:</span>
                      <span className="metric-value">{userAnalytics.searchBehavior.totalSearches}</span>
                    </div>
                    <div className="metric">
                      <span className="metric-label">Unique Queries:</span>
                      <span className="metric-value">{userAnalytics.searchBehavior.uniqueQueries}</span>
                    </div>
                    <div className="metric">
                      <span className="metric-label">Click Rate:</span>
                      <span className="metric-value">{(userAnalytics.searchBehavior.resultClickRate * 100).toFixed(1)}%</span>
                    </div>
                  </div>
                </div>

                <div className="analytics-card">
                  <h3>Content Interaction</h3>
                  <div className="content-metrics">
                    <div className="metric">
                      <span className="metric-label">Documents Viewed:</span>
                      <span className="metric-value">{userAnalytics.contentInteraction.documentsViewed}</span>
                    </div>
                    <div className="metric">
                      <span className="metric-label">Avg Read Time:</span>
                      <span className="metric-value">{Math.round(userAnalytics.contentInteraction.averageReadTime)}m</span>
                    </div>
                    <div className="metric">
                      <span className="metric-label">Downloads:</span>
                      <span className="metric-value">{userAnalytics.contentInteraction.documentsDownloaded}</span>
                    </div>
                  </div>
                </div>

                <div className="analytics-card">
                  <h3>Collaboration</h3>
                  <div className="collaboration-metrics">
                    <div className="metric">
                      <span className="metric-label">Sessions:</span>
                      <span className="metric-value">{userAnalytics.collaborationActivity.sessionsParticipated}</span>
                    </div>
                    <div className="metric">
                      <span className="metric-label">Annotations:</span>
                      <span className="metric-value">{userAnalytics.collaborationActivity.annotationsCreated}</span>
                    </div>
                    <div className="metric">
                      <span className="metric-label">Score:</span>
                      <span className="metric-value">{userAnalytics.collaborationActivity.collaborationScore.toFixed(1)}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Top Insights Preview */}
          {showAIInsights && aiInsights.length > 0 && (
            <div className="insights-preview">
              <h2>Key AI Insights</h2>
              <div className="insights-grid">
                {aiInsights.slice(0, 3).map((insight) => (
                  <div key={insight.id} className="insight-card preview">
                    <div className="insight-header">
                      <span className="insight-icon">{getInsightTypeIcon(insight.type)}</span>
                      <span className="insight-title">{insight.title}</span>
                      <span 
                        className="insight-priority"
                        style={{ backgroundColor: getInsightPriorityColor(insight.priority) }}
                      >
                        {insight.priority}
                      </span>
                    </div>
                    <div className="insight-description">{insight.description}</div>
                    <div className="insight-confidence">
                      Confidence: {(insight.confidence * 100).toFixed(0)}%
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Reports Tab */}
      {activeTab === 'reports' && (
        <div className="reports-panel">
          <div className="reports-header">
            <h2>Analytics Reports</h2>
            <div className="report-controls">
              <select
                value={selectedReportType}
                onChange={(e) => setSelectedReportType(e.target.value as ReportType)}
                className="report-type-selector"
              >
                <option value="usage_summary">Usage Summary</option>
                <option value="search_analytics">Search Analytics</option>
                <option value="document_trends">Document Trends</option>
                <option value="user_behavior">User Behavior</option>
                <option value="collaboration_metrics">Collaboration Metrics</option>
                <option value="research_insights">Research Insights</option>
                <option value="performance_analysis">Performance Analysis</option>
              </select>
              <button
                onClick={generateReport}
                className="generate-report-btn"
                disabled={isLoading}
              >
                {isLoading ? 'Generating...' : '📊 Generate Report'}
              </button>
            </div>
          </div>

          <div className="reports-list">
            {reports.length === 0 ? (
              <div className="empty-reports">
                <p>No reports generated yet. Create your first analytics report!</p>
              </div>
            ) : (
              reports.map((report) => (
                <div key={report.id} className="report-card">
                  <div className="report-header">
                    <h3>{report.title}</h3>
                    <div className="report-meta">
                      <span className="report-type">{report.type}</span>
                      <span className="report-date">
                        {report.generatedAt.toLocaleDateString()}
                      </span>
                    </div>
                  </div>
                  <div className="report-description">{report.description}</div>
                  <div className="report-stats">
                    <span>{report.insights.length} insights</span>
                    <span>{report.recommendations.length} recommendations</span>
                    <span>{report.visualizations.length} visualizations</span>
                  </div>
                  <div className="report-actions">
                    <button className="view-report-btn">👁️ View</button>
                    <button className="export-report-btn">📤 Export</button>
                    <button className="share-report-btn">🔗 Share</button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* AI Insights Tab */}
      {activeTab === 'insights' && showAIInsights && (
        <div className="insights-panel">
          <div className="insights-header">
            <h2>AI-Powered Insights</h2>
            <div className="insights-controls">
              <button
                onClick={buildKnowledgeGraph}
                className="build-graph-btn"
                disabled={isLoading || documents.length === 0}
              >
                🕸️ Build Knowledge Graph
              </button>
            </div>
          </div>

          <div className="insights-list">
            {aiInsights.length === 0 ? (
              <div className="empty-insights">
                <p>No AI insights available. Add documents to generate insights!</p>
              </div>
            ) : (
              aiInsights.map((insight) => (
                <div key={insight.id} className="insight-card">
                  <div className="insight-header">
                    <div className="insight-meta">
                      <span className="insight-icon">{getInsightTypeIcon(insight.type)}</span>
                      <span className="insight-type">{insight.type.replace('_', ' ')}</span>
                      <span 
                        className="insight-priority"
                        style={{ backgroundColor: getInsightPriorityColor(insight.priority) }}
                      >
                        {insight.priority}
                      </span>
                    </div>
                    <div className="insight-confidence">
                      {(insight.confidence * 100).toFixed(0)}% confidence
                    </div>
                  </div>

                  <div className="insight-content">
                    <h3>{insight.title}</h3>
                    <p>{insight.description}</p>
                  </div>

                  {insight.implications.length > 0 && (
                    <div className="insight-implications">
                      <h4>Implications:</h4>
                      <ul>
                        {insight.implications.map((implication) => (
                          <li key={implication.id}>
                            <strong>{implication.type}:</strong> {implication.description}
                            <span className={`impact-level ${implication.impact}`}>
                              {implication.impact} impact
                            </span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {insight.suggestions.length > 0 && (
                    <div className="insight-suggestions">
                      <h4>Suggestions:</h4>
                      <div className="suggestions-list">
                        {insight.suggestions.map((suggestion) => (
                          <div key={suggestion.id} className="suggestion-item">
                            <div className="suggestion-header">
                              <span className="suggestion-title">{suggestion.title}</span>
                              <span className={`suggestion-priority ${suggestion.priority}`}>
                                {suggestion.priority}
                              </span>
                            </div>
                            <div className="suggestion-description">{suggestion.description}</div>
                            <div className="suggestion-meta">
                              <span>Effort: {suggestion.effort}</span>
                              <span>Timeline: {suggestion.timeline}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="insight-actions">
                    <button
                      onClick={() => handleInsightAction(insight, 'accept')}
                      className="action-btn accept"
                    >
                      ✅ Accept
                    </button>
                    <button
                      onClick={() => handleInsightAction(insight, 'investigate')}
                      className="action-btn investigate"
                    >
                      🔍 Investigate
                    </button>
                    <button
                      onClick={() => handleInsightAction(insight, 'dismiss')}
                      className="action-btn dismiss"
                    >
                      ❌ Dismiss
                    </button>
                  </div>

                  <div className="insight-metadata">
                    <span>Source: {insight.source}</span>
                    <span>Category: {insight.category}</span>
                    <span>Generated: {insight.timestamp.toLocaleString()}</span>
                  </div>
                </div>
              ))
            )}
          </div>

          {/* Knowledge Graph Visualization */}
          {knowledgeGraph && (
            <div className="knowledge-graph-section">
              <h3>Knowledge Graph</h3>
              <div className="graph-stats">
                <span>{knowledgeGraph.nodes.length} nodes</span>
                <span>{knowledgeGraph.edges.length} connections</span>
                <span>{knowledgeGraph.clusters.length} clusters</span>
                <span>Density: {(knowledgeGraph.metrics.density * 100).toFixed(1)}%</span>
              </div>
              <div className="graph-visualization">
                {/* Graph visualization would be implemented here using D3.js or similar */}
                <div className="graph-placeholder">
                  <p>🕸️ Interactive knowledge graph visualization</p>
                  <p>Nodes: Documents, Entities, Concepts</p>
                  <p>Edges: Citations, Relationships, Dependencies</p>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Trends Tab */}
      {activeTab === 'trends' && (
        <div className="trends-panel">
          <div className="trends-header">
            <h2>Trend Analysis</h2>
            <div className="trend-controls">
              <button
                onClick={() => generateTrendAnalysis('usage_trend')}
                className="trend-btn"
              >
                📈 Usage Trends
              </button>
              <button
                onClick={() => generateTrendAnalysis('search_trend')}
                className="trend-btn"
              >
                🔍 Search Trends
              </button>
              <button
                onClick={() => generateTrendAnalysis('content_trend')}
                className="trend-btn"
              >
                📄 Content Trends
              </button>
            </div>
          </div>

          <div className="trends-list">
            {trends.length === 0 ? (
              <div className="empty-trends">
                <p>No trend analysis available. Generate your first trend report!</p>
              </div>
            ) : (
              trends.map((trend) => (
                <div key={trend.id} className="trend-card">
                  <div className="trend-header">
                    <h3>{trend.title}</h3>
                    <div className="trend-meta">
                      <span className={`trend-direction ${trend.direction}`}>
                        {trend.direction === 'upward' && '📈'}
                        {trend.direction === 'downward' && '📉'}
                        {trend.direction === 'cyclical' && '🔄'}
                        {trend.direction === 'volatile' && '⚡'}
                        {trend.direction}
                      </span>
                      <span className={`trend-strength ${trend.strength}`}>
                        {trend.strength} strength
                      </span>
                    </div>
                  </div>
                  <div className="trend-description">{trend.description}</div>
                  <div className="trend-stats">
                    <span>Significance: {(trend.significance * 100).toFixed(1)}%</span>
                    <span>Data Points: {trend.dataPoints.length}</span>
                    <span>Forecast: {trend.forecast.length} periods</span>
                  </div>
                  <div className="trend-implications">
                    <h4>Implications:</h4>
                    <ul>
                      {trend.implications.map((implication, index) => (
                        <li key={index}>{implication}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* Models Tab */}
      {activeTab === 'models' && (
        <div className="models-panel">
          <div className="models-header">
            <h2>Predictive Models</h2>
            <button className="build-model-btn">🤖 Build New Model</button>
          </div>

          <div className="models-list">
            {predictiveModels.length === 0 ? (
              <div className="empty-models">
                <p>No predictive models built yet. Create your first AI model!</p>
              </div>
            ) : (
              predictiveModels.map((model) => (
                <div key={model.id} className="model-card">
                  <div className="model-header">
                    <h3>{model.name}</h3>
                    <div className="model-meta">
                      <span className="model-type">{model.type}</span>
                      <span className="model-algorithm">{model.algorithm}</span>
                    </div>
                  </div>
                  <div className="model-description">{model.description}</div>
                  <div className="model-metrics">
                    <div className="metric">
                      <span className="metric-label">Accuracy:</span>
                      <span className="metric-value">{(model.accuracy * 100).toFixed(1)}%</span>
                    </div>
                    <div className="metric">
                      <span className="metric-label">Confidence:</span>
                      <span className="metric-value">{(model.confidence * 100).toFixed(1)}%</span>
                    </div>
                    <div className="metric">
                      <span className="metric-label">Features:</span>
                      <span className="metric-value">{model.features.length}</span>
                    </div>
                    <div className="metric">
                      <span className="metric-label">Predictions:</span>
                      <span className="metric-value">{model.predictions.length}</span>
                    </div>
                  </div>
                  <div className="model-actions">
                    <button className="model-btn">📊 View Details</button>
                    <button className="model-btn">🔄 Retrain</button>
                    <button className="model-btn">📤 Export</button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
};