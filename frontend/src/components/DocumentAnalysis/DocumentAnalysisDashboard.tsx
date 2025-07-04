/**
 * Document Analysis Dashboard
 * Comprehensive dashboard for visualizing document analysis results with charts and metrics
 */
import React, { useState, useEffect, useMemo } from 'react';
import { LegislativeDocument } from '../../types';
import { DocumentAnalysis, documentAnalysisEngine } from '../../services/documentAnalysisEngine';
import { legalAnalysisService, RegulatoryImpactAssessment } from '../../services/legalAnalysisService';

interface DocumentAnalysisDashboardProps {
  documents?: LegislativeDocument[];
  analysis?: DocumentAnalysis[];
  onAnalysisUpdate?: (analysis: DocumentAnalysis) => void;
  showAdvancedMetrics?: boolean;
  enableComparison?: boolean;
}

export const DocumentAnalysisDashboard: React.FC<DocumentAnalysisDashboardProps> = ({
  documents = [],
  analysis: initialAnalysis = [],
  onAnalysisUpdate,
  showAdvancedMetrics = true,
  enableComparison = true
}) => {
  // State management
  const [analysisResults, setAnalysisResults] = useState<DocumentAnalysis[]>(initialAnalysis);
  const [selectedDocument, setSelectedDocument] = useState<LegislativeDocument | null>(null);
  const [selectedAnalysis, setSelectedAnalysis] = useState<DocumentAnalysis | null>(null);
  const [impactAssessment, setImpactAssessment] = useState<RegulatoryImpactAssessment | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'complexity' | 'sentiment' | 'quality' | 'legal' | 'impact' | 'comparison'>('overview');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [comparisonMode, setComparisonMode] = useState(false);
  const [selectedForComparison, setSelectedForComparison] = useState<DocumentAnalysis[]>([]);

  // Analysis options
  const [analysisOptions, setAnalysisOptions] = useState({
    includeNLP: true,
    includeSentiment: true,
    includeComplexity: true,
    includeLegal: true,
    includeRegulatory: true,
    includeTopicModeling: true
  });

  /**
   * Analyze documents that don't have analysis yet
   */
  useEffect(() => {
    const documentsToAnalyze = documents.filter(doc => 
      !analysisResults.find(analysis => analysis.documentId === doc.id)
    );

    if (documentsToAnalyze.length > 0) {
      analyzeDocuments(documentsToAnalyze);
    }
  }, [documents]);

  /**
   * Analyze multiple documents
   */
  const analyzeDocuments = async (docs: LegislativeDocument[]) => {
    setIsAnalyzing(true);
    try {
      const results = await documentAnalysisEngine.batchAnalyzeDocuments(
        docs,
        {
          maxConcurrent: 3,
          progressCallback: (completed, total) => {
            console.log(`Analysis progress: ${completed}/${total}`);
          }
        }
      );
      
      setAnalysisResults(prev => [...prev, ...results]);
      
      if (onAnalysisUpdate) {
        results.forEach(result => onAnalysisUpdate(result));
      }
    } catch (error) {
      console.error('Batch analysis failed:', error);
    } finally {
      setIsAnalyzing(false);
    }
  };

  /**
   * Handle document selection
   */
  const handleDocumentSelect = async (document: LegislativeDocument) => {
    setSelectedDocument(document);
    
    const analysis = analysisResults.find(a => a.documentId === document.id);
    if (analysis) {
      setSelectedAnalysis(analysis);
      
      // Load impact assessment if needed
      if (analysisOptions.includeRegulatory) {
        try {
          const assessment = await legalAnalysisService.conductRegulatoryImpactAssessment(document);
          setImpactAssessment(assessment);
        } catch (error) {
          console.error('Impact assessment failed:', error);
        }
      }
    }
  };

  /**
   * Aggregate metrics from all analyses
   */
  const aggregateMetrics = useMemo(() => {
    if (analysisResults.length === 0) return null;

    const totalDocuments = analysisResults.length;
    const avgComplexity = analysisResults.reduce((sum, a) => sum + a.complexityAnalysis.overall.complexityScore, 0) / totalDocuments;
    const avgQuality = analysisResults.reduce((sum, a) => sum + a.qualityScore.overall, 0) / totalDocuments;
    const avgConfidence = analysisResults.reduce((sum, a) => sum + a.analysisConfidence, 0) / totalDocuments;
    
    const complexityDistribution = analysisResults.reduce((dist, a) => {
      const category = a.complexityAnalysis.overall.category;
      dist[category] = (dist[category] || 0) + 1;
      return dist;
    }, {} as Record<string, number>);

    const sentimentDistribution = analysisResults.reduce((dist, a) => {
      const polarity = a.sentimentAnalysis.overall.polarity;
      dist[polarity] = (dist[polarity] || 0) + 1;
      return dist;
    }, {} as Record<string, number>);

    const documentTypeDistribution = analysisResults.reduce((dist, a) => {
      const type = a.document.type;
      dist[type] = (dist[type] || 0) + 1;
      return dist;
    }, {} as Record<string, number>);

    return {
      totalDocuments,
      avgComplexity,
      avgQuality,
      avgConfidence,
      complexityDistribution,
      sentimentDistribution,
      documentTypeDistribution
    };
  }, [analysisResults]);

  /**
   * Get complexity color
   */
  const getComplexityColor = (category: string): string => {
    switch (category) {
      case 'simple': return '#22c55e';
      case 'moderate': return '#eab308';
      case 'complex': return '#f97316';
      case 'very_complex': return '#ef4444';
      default: return '#6b7280';
    }
  };

  /**
   * Get sentiment color
   */
  const getSentimentColor = (polarity: string): string => {
    switch (polarity) {
      case 'positive': return '#22c55e';
      case 'negative': return '#ef4444';
      case 'neutral': return '#6b7280';
      default: return '#6b7280';
    }
  };

  /**
   * Render metric card
   */
  const renderMetricCard = (title: string, value: string | number, subtitle?: string, color?: string) => (
    <div className="metric-card">
      <h4>{title}</h4>
      <div className="metric-value" style={{ color }}>
        {typeof value === 'number' ? value.toFixed(1) : value}
      </div>
      {subtitle && <div className="metric-subtitle">{subtitle}</div>}
    </div>
  );

  /**
   * Render distribution chart
   */
  const renderDistributionChart = (title: string, data: Record<string, number>, colorMap?: (key: string) => string) => (
    <div className="distribution-chart">
      <h4>{title}</h4>
      <div className="chart-bars">
        {Object.entries(data).map(([key, value]) => {
          const percentage = (value / Object.values(data).reduce((sum, v) => sum + v, 0)) * 100;
          return (
            <div key={key} className="chart-bar">
              <div className="bar-label">{key}</div>
              <div className="bar-container">
                <div 
                  className="bar-fill" 
                  style={{ 
                    width: `${percentage}%`,
                    backgroundColor: colorMap ? colorMap(key) : '#3b82f6'
                  }}
                ></div>
              </div>
              <div className="bar-value">{value} ({percentage.toFixed(1)}%)</div>
            </div>
          );
        })}
      </div>
    </div>
  );

  /**
   * Handle comparison mode toggle
   */
  const toggleComparisonMode = () => {
    setComparisonMode(!comparisonMode);
    setSelectedForComparison([]);
  };

  /**
   * Toggle analysis selection for comparison
   */
  const toggleAnalysisForComparison = (analysis: DocumentAnalysis) => {
    setSelectedForComparison(prev => {
      const isSelected = prev.find(a => a.analysisId === analysis.analysisId);
      if (isSelected) {
        return prev.filter(a => a.analysisId !== analysis.analysisId);
      } else if (prev.length < 3) {
        return [...prev, analysis];
      }
      return prev;
    });
  };

  /**
   * Render comparison results
   */
  const renderComparisonResults = () => {
    if (selectedForComparison.length < 2) {
      return <div className="comparison-message">Select at least 2 documents to compare</div>;
    }

    const comparisons = [];
    for (let i = 0; i < selectedForComparison.length; i++) {
      for (let j = i + 1; j < selectedForComparison.length; j++) {
        const comparison = documentAnalysisEngine.compareAnalyses(
          selectedForComparison[i],
          selectedForComparison[j]
        );
        comparisons.push({
          docA: selectedForComparison[i].document.title,
          docB: selectedForComparison[j].document.title,
          ...comparison
        });
      }
    }

    return (
      <div className="comparison-results">
        {comparisons.map((comparison, index) => (
          <div key={index} className="comparison-item">
            <h4>{comparison.docA} vs {comparison.docB}</h4>
            <div className="comparison-similarity">
              Similarity: {(comparison.similarity * 100).toFixed(1)}%
            </div>
            <div className="comparison-differences">
              {comparison.differences.map((diff, diffIndex) => (
                <div key={diffIndex} className="difference-item">
                  <span className="difference-aspect">{diff.aspect}:</span>
                  <span className="difference-value">{diff.difference.toFixed(1)}</span>
                  <span className="difference-description">({diff.description})</span>
                </div>
              ))}
            </div>
            <div className="comparison-recommendations">
              <h5>Recommendations:</h5>
              <ul>
                {comparison.recommendations.map((rec, recIndex) => (
                  <li key={recIndex}>{rec}</li>
                ))}
              </ul>
            </div>
          </div>
        ))}
      </div>
    );
  };

  return (
    <div className="document-analysis-dashboard">
      {/* Header */}
      <div className="dashboard-header">
        <h2>Document Analysis Dashboard</h2>
        <div className="header-controls">
          {enableComparison && (
            <button
              onClick={toggleComparisonMode}
              className={`comparison-toggle ${comparisonMode ? 'active' : ''}`}
            >
              {comparisonMode ? '❌ Exit Comparison' : '🔄 Compare Documents'}
            </button>
          )}
          <div className="analysis-status">
            {isAnalyzing ? (
              <span className="analyzing">⏳ Analyzing documents...</span>
            ) : (
              <span className="ready">✅ {analysisResults.length} documents analyzed</span>
            )}
          </div>
        </div>
      </div>

      {/* Analysis Options */}
      <div className="analysis-options">
        <h3>Analysis Configuration</h3>
        <div className="options-grid">
          <label>
            <input
              type="checkbox"
              checked={analysisOptions.includeNLP}
              onChange={(e) => setAnalysisOptions(prev => ({ ...prev, includeNLP: e.target.checked }))}
            />
            NLP Analysis
          </label>
          <label>
            <input
              type="checkbox"
              checked={analysisOptions.includeSentiment}
              onChange={(e) => setAnalysisOptions(prev => ({ ...prev, includeSentiment: e.target.checked }))}
            />
            Sentiment Analysis
          </label>
          <label>
            <input
              type="checkbox"
              checked={analysisOptions.includeComplexity}
              onChange={(e) => setAnalysisOptions(prev => ({ ...prev, includeComplexity: e.target.checked }))}
            />
            Complexity Analysis
          </label>
          <label>
            <input
              type="checkbox"
              checked={analysisOptions.includeLegal}
              onChange={(e) => setAnalysisOptions(prev => ({ ...prev, includeLegal: e.target.checked }))}
            />
            Legal Analysis
          </label>
          <label>
            <input
              type="checkbox"
              checked={analysisOptions.includeRegulatory}
              onChange={(e) => setAnalysisOptions(prev => ({ ...prev, includeRegulatory: e.target.checked }))}
            />
            Regulatory Analysis
          </label>
          <label>
            <input
              type="checkbox"
              checked={analysisOptions.includeTopicModeling}
              onChange={(e) => setAnalysisOptions(prev => ({ ...prev, includeTopicModeling: e.target.checked }))}
            />
            Topic Modeling
          </label>
        </div>
      </div>

      {/* Documents List */}
      <div className="documents-section">
        <h3>Documents</h3>
        <div className="documents-grid">
          {documents.map((document) => {
            const analysis = analysisResults.find(a => a.documentId === document.id);
            const isSelectedForComparison = selectedForComparison.find(a => a.documentId === document.id);
            
            return (
              <div
                key={document.id}
                className={`document-card ${selectedDocument?.id === document.id ? 'selected' : ''} ${isSelectedForComparison ? 'comparison-selected' : ''}`}
                onClick={() => !comparisonMode ? handleDocumentSelect(document) : analysis && toggleAnalysisForComparison(analysis)}
              >
                <div className="document-header">
                  <h4>{document.title}</h4>
                  {comparisonMode && (
                    <div className="comparison-checkbox">
                      <input
                        type="checkbox"
                        checked={!!isSelectedForComparison}
                        readOnly
                      />
                    </div>
                  )}
                </div>
                <div className="document-meta">
                  <span className="document-type">{document.type}</span>
                  <span className="document-date">{document.date}</span>
                  <span className="document-author">{document.author}</span>
                </div>
                {analysis && (
                  <div className="document-metrics">
                    <div className="metric">
                      <span className="metric-label">Complexity:</span>
                      <span 
                        className="metric-value"
                        style={{ color: getComplexityColor(analysis.complexityAnalysis.overall.category) }}
                      >
                        {analysis.complexityAnalysis.overall.category}
                      </span>
                    </div>
                    <div className="metric">
                      <span className="metric-label">Quality:</span>
                      <span className="metric-value">
                        {(analysis.qualityScore.overall * 100).toFixed(0)}%
                      </span>
                    </div>
                    <div className="metric">
                      <span className="metric-label">Sentiment:</span>
                      <span 
                        className="metric-value"
                        style={{ color: getSentimentColor(analysis.sentimentAnalysis.overall.polarity) }}
                      >
                        {analysis.sentimentAnalysis.overall.polarity}
                      </span>
                    </div>
                  </div>
                )}
                {!analysis && !isAnalyzing && (
                  <div className="analysis-status pending">⏳ Pending analysis</div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Aggregate Overview */}
      {aggregateMetrics && !comparisonMode && (
        <div className="aggregate-overview">
          <h3>Overview Metrics</h3>
          <div className="metrics-grid">
            {renderMetricCard('Total Documents', aggregateMetrics.totalDocuments)}
            {renderMetricCard('Average Complexity', aggregateMetrics.avgComplexity, 'out of 100')}
            {renderMetricCard('Average Quality', `${(aggregateMetrics.avgQuality * 100).toFixed(1)}%`)}
            {renderMetricCard('Analysis Confidence', `${(aggregateMetrics.avgConfidence * 100).toFixed(1)}%`)}
          </div>
          
          <div className="distributions-grid">
            {renderDistributionChart(
              'Complexity Distribution',
              aggregateMetrics.complexityDistribution,
              getComplexityColor
            )}
            {renderDistributionChart(
              'Sentiment Distribution',
              aggregateMetrics.sentimentDistribution,
              getSentimentColor
            )}
            {renderDistributionChart(
              'Document Type Distribution',
              aggregateMetrics.documentTypeDistribution
            )}
          </div>
        </div>
      )}

      {/* Comparison Mode */}
      {comparisonMode && (
        <div className="comparison-section">
          <h3>Document Comparison</h3>
          <div className="comparison-controls">
            <div className="selected-count">
              Selected: {selectedForComparison.length}/3 documents
            </div>
          </div>
          {renderComparisonResults()}
        </div>
      )}

      {/* Detailed Analysis */}
      {selectedAnalysis && !comparisonMode && (
        <div className="detailed-analysis">
          {/* Navigation Tabs */}
          <div className="analysis-tabs">
            <button
              className={`tab ${activeTab === 'overview' ? 'active' : ''}`}
              onClick={() => setActiveTab('overview')}
            >
              📊 Overview
            </button>
            <button
              className={`tab ${activeTab === 'complexity' ? 'active' : ''}`}
              onClick={() => setActiveTab('complexity')}
            >
              🧩 Complexity
            </button>
            <button
              className={`tab ${activeTab === 'sentiment' ? 'active' : ''}`}
              onClick={() => setActiveTab('sentiment')}
            >
              😊 Sentiment
            </button>
            <button
              className={`tab ${activeTab === 'quality' ? 'active' : ''}`}
              onClick={() => setActiveTab('quality')}
            >
              ⭐ Quality
            </button>
            {selectedAnalysis.legalAnalysis && (
              <button
                className={`tab ${activeTab === 'legal' ? 'active' : ''}`}
                onClick={() => setActiveTab('legal')}
              >
                ⚖️ Legal
              </button>
            )}
            {impactAssessment && (
              <button
                className={`tab ${activeTab === 'impact' ? 'active' : ''}`}
                onClick={() => setActiveTab('impact')}
              >
                📈 Impact
              </button>
            )}
          </div>

          {/* Tab Content */}
          <div className="tab-content">
            {/* Overview Tab */}
            {activeTab === 'overview' && (
              <div className="overview-tab">
                <h3>Analysis Overview: {selectedAnalysis.document.title}</h3>
                <div className="overview-metrics">
                  {renderMetricCard(
                    'Complexity Score',
                    selectedAnalysis.complexityAnalysis.overall.complexityScore,
                    selectedAnalysis.complexityAnalysis.overall.category,
                    getComplexityColor(selectedAnalysis.complexityAnalysis.overall.category)
                  )}
                  {renderMetricCard(
                    'Quality Score',
                    `${(selectedAnalysis.qualityScore.overall * 100).toFixed(1)}%`
                  )}
                  {renderMetricCard(
                    'Sentiment',
                    selectedAnalysis.sentimentAnalysis.overall.polarity,
                    `${(selectedAnalysis.sentimentAnalysis.overall.intensity * 100).toFixed(1)}% intensity`,
                    getSentimentColor(selectedAnalysis.sentimentAnalysis.overall.polarity)
                  )}
                  {renderMetricCard(
                    'Analysis Confidence',
                    `${(selectedAnalysis.analysisConfidence * 100).toFixed(1)}%`
                  )}
                </div>

                <div className="nlp-overview">
                  <h4>Document Statistics</h4>
                  <div className="stats-grid">
                    <div className="stat">
                      <span className="stat-label">Words:</span>
                      <span className="stat-value">{selectedAnalysis.nlpAnalysis.wordCount}</span>
                    </div>
                    <div className="stat">
                      <span className="stat-label">Sentences:</span>
                      <span className="stat-value">{selectedAnalysis.nlpAnalysis.sentenceCount}</span>
                    </div>
                    <div className="stat">
                      <span className="stat-label">Paragraphs:</span>
                      <span className="stat-value">{selectedAnalysis.nlpAnalysis.paragraphCount}</span>
                    </div>
                    <div className="stat">
                      <span className="stat-label">Avg Words/Sentence:</span>
                      <span className="stat-value">{selectedAnalysis.nlpAnalysis.avgWordsPerSentence.toFixed(1)}</span>
                    </div>
                  </div>
                </div>

                <div className="readability-overview">
                  <h4>Readability Metrics</h4>
                  <div className="readability-grid">
                    <div className="readability-metric">
                      <span className="metric-name">Flesch-Kincaid:</span>
                      <span className="metric-score">{selectedAnalysis.readabilityMetrics.fleschKincaid.gradeLevel.toFixed(1)}</span>
                      <span className="metric-interpretation">{selectedAnalysis.readabilityMetrics.fleschKincaid.interpretation}</span>
                    </div>
                    <div className="readability-metric">
                      <span className="metric-name">Brazilian Index:</span>
                      <span className="metric-score">{selectedAnalysis.readabilityMetrics.brasileiroIndex.score.toFixed(1)}</span>
                      <span className="metric-interpretation">{selectedAnalysis.readabilityMetrics.brasileiroIndex.level}</span>
                    </div>
                    <div className="readability-metric">
                      <span className="metric-name">Target Audience:</span>
                      <span className="metric-score">{selectedAnalysis.readabilityMetrics.targetAudience.primary}</span>
                      <span className="metric-interpretation">{selectedAnalysis.readabilityMetrics.targetAudience.educationLevel}</span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Complexity Tab */}
            {activeTab === 'complexity' && (
              <div className="complexity-tab">
                <h3>Complexity Analysis</h3>
                <div className="complexity-overview">
                  <div className="complexity-score-circle">
                    <div className="score-value">{selectedAnalysis.complexityAnalysis.overall.complexityScore}</div>
                    <div className="score-label">{selectedAnalysis.complexityAnalysis.overall.category}</div>
                  </div>
                  <div className="primary-factors">
                    <h4>Primary Factors:</h4>
                    <ul>
                      {selectedAnalysis.complexityAnalysis.overall.primaryFactors.map((factor, index) => (
                        <li key={index}>{factor}</li>
                      ))}
                    </ul>
                  </div>
                </div>

                <div className="complexity-dimensions">
                  <div className="dimension">
                    <h4>Lexical Complexity</h4>
                    <div className="dimension-metrics">
                      <div className="metric">
                        <span>Vocabulary Diversity:</span>
                        <span>{(selectedAnalysis.complexityAnalysis.lexicalComplexity.vocabularyDiversity * 100).toFixed(1)}%</span>
                      </div>
                      <div className="metric">
                        <span>Average Word Length:</span>
                        <span>{selectedAnalysis.complexityAnalysis.lexicalComplexity.averageWordLength.toFixed(1)}</span>
                      </div>
                      <div className="metric">
                        <span>Technical Term Density:</span>
                        <span>{(selectedAnalysis.complexityAnalysis.lexicalComplexity.technicalTermDensity * 100).toFixed(1)}%</span>
                      </div>
                    </div>
                  </div>

                  <div className="dimension">
                    <h4>Syntactic Complexity</h4>
                    <div className="dimension-metrics">
                      <div className="metric">
                        <span>Average Sentence Length:</span>
                        <span>{selectedAnalysis.complexityAnalysis.syntacticComplexity.averageSentenceLength.toFixed(1)}</span>
                      </div>
                      <div className="metric">
                        <span>Dependency Depth:</span>
                        <span>{selectedAnalysis.complexityAnalysis.syntacticComplexity.dependencyDepth}</span>
                      </div>
                      <div className="metric">
                        <span>Subordination Ratio:</span>
                        <span>{(selectedAnalysis.complexityAnalysis.syntacticComplexity.subordinationRatio * 100).toFixed(1)}%</span>
                      </div>
                    </div>
                  </div>

                  <div className="dimension">
                    <h4>Legal Complexity</h4>
                    <div className="dimension-metrics">
                      <div className="metric">
                        <span>Regulatory Layers:</span>
                        <span>{selectedAnalysis.complexityAnalysis.legalComplexity.regulatoryLayers}</span>
                      </div>
                      <div className="metric">
                        <span>Cross References:</span>
                        <span>{selectedAnalysis.complexityAnalysis.legalComplexity.crossReferences}</span>
                      </div>
                      <div className="metric">
                        <span>Conditional Statements:</span>
                        <span>{selectedAnalysis.complexityAnalysis.legalComplexity.conditionalStatements}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Sentiment Tab */}
            {activeTab === 'sentiment' && (
              <div className="sentiment-tab">
                <h3>Sentiment Analysis</h3>
                <div className="sentiment-overview">
                  <div className="overall-sentiment">
                    <div className="sentiment-indicator">
                      <div 
                        className={`sentiment-circle ${selectedAnalysis.sentimentAnalysis.overall.polarity}`}
                        style={{ backgroundColor: getSentimentColor(selectedAnalysis.sentimentAnalysis.overall.polarity) }}
                      >
                        {selectedAnalysis.sentimentAnalysis.overall.polarity}
                      </div>
                    </div>
                    <div className="sentiment-details">
                      <div className="sentiment-metric">
                        <span>Intensity:</span>
                        <span>{(selectedAnalysis.sentimentAnalysis.overall.intensity * 100).toFixed(1)}%</span>
                      </div>
                      <div className="sentiment-metric">
                        <span>Confidence:</span>
                        <span>{(selectedAnalysis.sentimentAnalysis.overall.confidence * 100).toFixed(1)}%</span>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="legal-tone">
                  <h4>Legal Tone Analysis</h4>
                  <div className="tone-metrics">
                    {Object.entries(selectedAnalysis.sentimentAnalysis.legalTone).map(([tone, score]) => (
                      <div key={tone} className="tone-metric">
                        <span className="tone-label">{tone.charAt(0).toUpperCase() + tone.slice(1)}:</span>
                        <div className="tone-bar">
                          <div 
                            className="tone-fill"
                            style={{ width: `${score * 100}%` }}
                          ></div>
                        </div>
                        <span className="tone-value">{(score * 100).toFixed(0)}%</span>
                      </div>
                    ))}
                  </div>
                </div>

                {selectedAnalysis.sentimentAnalysis.stakeholderImpact.length > 0 && (
                  <div className="stakeholder-impact">
                    <h4>Stakeholder Impact</h4>
                    <div className="stakeholder-list">
                      {selectedAnalysis.sentimentAnalysis.stakeholderImpact.map((impact, index) => (
                        <div key={index} className="stakeholder-item">
                          <div className="stakeholder-header">
                            <span className="stakeholder-name">{impact.stakeholder}</span>
                            <span 
                              className={`impact-badge ${impact.impact}`}
                              style={{ backgroundColor: getSentimentColor(impact.impact) }}
                            >
                              {impact.impact}
                            </span>
                          </div>
                          <div className="impact-intensity">
                            Intensity: {(impact.intensity * 100).toFixed(1)}%
                          </div>
                          <div className="impact-reasoning">{impact.reasoning}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Quality Tab */}
            {activeTab === 'quality' && (
              <div className="quality-tab">
                <h3>Quality Assessment</h3>
                <div className="quality-overview">
                  <div className="overall-quality">
                    <div className="quality-score">
                      {(selectedAnalysis.qualityScore.overall * 100).toFixed(1)}
                    </div>
                    <div className="quality-label">Overall Quality Score</div>
                  </div>
                </div>

                <div className="quality-dimensions">
                  {Object.entries(selectedAnalysis.qualityScore.dimensions).map(([dimension, score]) => (
                    <div key={dimension} className="quality-dimension">
                      <div className="dimension-header">
                        <span className="dimension-name">{dimension.charAt(0).toUpperCase() + dimension.slice(1)}</span>
                        <span className="dimension-score">{(score * 100).toFixed(1)}%</span>
                      </div>
                      <div className="dimension-bar">
                        <div 
                          className="dimension-fill"
                          style={{ 
                            width: `${score * 100}%`,
                            backgroundColor: score > 0.8 ? '#22c55e' : score > 0.6 ? '#eab308' : '#ef4444'
                          }}
                        ></div>
                      </div>
                    </div>
                  ))}
                </div>

                {selectedAnalysis.qualityScore.issues.length > 0 && (
                  <div className="quality-issues">
                    <h4>Quality Issues</h4>
                    <div className="issues-list">
                      {selectedAnalysis.qualityScore.issues.map((issue, index) => (
                        <div key={index} className={`issue-item ${issue.severity}`}>
                          <div className="issue-header">
                            <span className="issue-type">{issue.type}</span>
                            <span className="issue-severity">{issue.severity}</span>
                          </div>
                          <div className="issue-description">{issue.description}</div>
                          <div className="issue-location">Location: {issue.location}</div>
                          <div className="issue-suggestion">Suggestion: {issue.suggestion}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="quality-recommendations">
                  <h4>Recommendations</h4>
                  <ul>
                    {selectedAnalysis.qualityScore.recommendations.map((recommendation, index) => (
                      <li key={index}>{recommendation}</li>
                    ))}
                  </ul>
                </div>
              </div>
            )}

            {/* Legal Tab */}
            {activeTab === 'legal' && selectedAnalysis.legalAnalysis && (
              <div className="legal-tab">
                <h3>Legal Analysis</h3>
                <div className="legal-overview">
                  <div className="document-type">
                    <h4>Document Classification</h4>
                    <div className="classification-result">
                      <span className="predicted-type">{selectedAnalysis.legalAnalysis.documentType.predicted}</span>
                      <span className="confidence">
                        ({(selectedAnalysis.legalAnalysis.documentType.confidence * 100).toFixed(1)}% confidence)
                      </span>
                    </div>
                  </div>

                  <div className="authority-analysis">
                    <h4>Authority Analysis</h4>
                    <div className="authority-details">
                      <div className="authority-metric">
                        <span>Issuing Body:</span>
                        <span>{selectedAnalysis.legalAnalysis.authority.issuingBody}</span>
                      </div>
                      <div className="authority-metric">
                        <span>Authority Level:</span>
                        <span>{selectedAnalysis.legalAnalysis.authority.authorityLevel}</span>
                      </div>
                      <div className="authority-metric">
                        <span>Legitimacy Score:</span>
                        <span>{(selectedAnalysis.legalAnalysis.authority.legitimacy * 100).toFixed(1)}%</span>
                      </div>
                      <div className="authority-metric">
                        <span>Jurisdiction:</span>
                        <span>{selectedAnalysis.legalAnalysis.authority.jurisdiction.join(', ')}</span>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="legal-structure">
                  <h4>Legal Structure</h4>
                  <div className="structure-features">
                    <div className="feature">
                      <span>Has Articles:</span>
                      <span>{selectedAnalysis.legalAnalysis.legalStructure.hasArticles ? '✅' : '❌'}</span>
                    </div>
                    <div className="feature">
                      <span>Has Paragraphs:</span>
                      <span>{selectedAnalysis.legalAnalysis.legalStructure.hasParagraphs ? '✅' : '❌'}</span>
                    </div>
                    <div className="feature">
                      <span>Has Chapters:</span>
                      <span>{selectedAnalysis.legalAnalysis.legalStructure.hasChapters ? '✅' : '❌'}</span>
                    </div>
                    <div className="feature">
                      <span>Citation Format:</span>
                      <span>{selectedAnalysis.legalAnalysis.legalStructure.citationFormat}</span>
                    </div>
                  </div>
                </div>

                {selectedAnalysis.legalAnalysis.legalLanguageFeatures.modalVerbs.length > 0 && (
                  <div className="legal-language">
                    <h4>Legal Language Features</h4>
                    <div className="modal-verbs">
                      <h5>Modal Verbs</h5>
                      <div className="verbs-list">
                        {selectedAnalysis.legalAnalysis.legalLanguageFeatures.modalVerbs.map((verb, index) => (
                          <div key={index} className="verb-item">
                            <span className="verb-text">{verb.verb}</span>
                            <span className="verb-frequency">({verb.frequency})</span>
                            <span className="verb-function">{verb.function}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="legal-terms">
                      <h5>Legal Terms</h5>
                      <div className="terms-list">
                        {selectedAnalysis.legalAnalysis.legalLanguageFeatures.legalTerms.map((term, index) => (
                          <div key={index} className="term-item">
                            <span className="term-text">{term.term}</span>
                            <span className="term-frequency">({term.frequency})</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Impact Tab */}
            {activeTab === 'impact' && impactAssessment && (
              <div className="impact-tab">
                <h3>Regulatory Impact Assessment</h3>
                <div className="impact-overview">
                  <div className="overall-impact">
                    <div className="impact-score">{impactAssessment.overallImpact.score}</div>
                    <div className="impact-category">{impactAssessment.overallImpact.category}</div>
                    <div className="impact-confidence">
                      {(impactAssessment.overallImpact.confidence * 100).toFixed(1)}% confidence
                    </div>
                  </div>

                  <div className="impact-drivers">
                    <h4>Primary Drivers</h4>
                    <ul>
                      {impactAssessment.overallImpact.primaryDrivers.map((driver, index) => (
                        <li key={index}>{driver}</li>
                      ))}
                    </ul>
                  </div>
                </div>

                <div className="sectoral-impacts">
                  <h4>Sectoral Impacts</h4>
                  <div className="sectors-list">
                    {impactAssessment.sectoralImpacts.map((impact, index) => (
                      <div key={index} className="sector-impact">
                        <div className="sector-header">
                          <span className="sector-name">{impact.sector}</span>
                          <span className={`impact-type ${impact.impactType}`}>{impact.impactType}</span>
                          <span className={`impact-magnitude ${impact.magnitude}`}>{impact.magnitude}</span>
                        </div>
                        <div className="sector-description">{impact.description}</div>
                        <div className="sector-details">
                          <span>Timeframe: {impact.timeframe}</span>
                          <span>Certainty: {impact.certainty}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="economic-impact">
                  <h4>Economic Impact</h4>
                  <div className="economic-metrics">
                    <div className="cost-benefit">
                      <div className="cost-section">
                        <h5>Direct Costs</h5>
                        <div className="cost-item">
                          <span>One-time:</span>
                          <span>R$ {impactAssessment.economicImpact.directCosts.oneTime.toLocaleString()}</span>
                        </div>
                        <div className="cost-item">
                          <span>Recurring:</span>
                          <span>R$ {impactAssessment.economicImpact.directCosts.recurring.toLocaleString()}</span>
                        </div>
                      </div>
                      <div className="benefit-section">
                        <h5>Benefits</h5>
                        {impactAssessment.economicImpact.benefits.quantifiable.map((benefit, index) => (
                          <div key={index} className="benefit-item">
                            <span>{benefit.category}:</span>
                            <span>R$ {benefit.amount.toLocaleString()}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div className="net-impact">
                      <h5>Net Impact</h5>
                      <div className={`net-value ${impactAssessment.economicImpact.netImpact > 0 ? 'positive' : 'negative'}`}>
                        R$ {impactAssessment.economicImpact.netImpact.toLocaleString()}
                      </div>
                    </div>
                  </div>
                </div>

                {impactAssessment.recommendations.length > 0 && (
                  <div className="impact-recommendations">
                    <h4>Policy Recommendations</h4>
                    <div className="recommendations-list">
                      {impactAssessment.recommendations.map((rec, index) => (
                        <div key={index} className="recommendation-item">
                          <div className="rec-header">
                            <span className="rec-category">{rec.category}</span>
                            <span className={`rec-priority ${rec.priority}`}>{rec.priority} priority</span>
                          </div>
                          <div className="rec-text">{rec.recommendation}</div>
                          <div className="rec-details">
                            <div className="rec-rationale">
                              <strong>Rationale:</strong> {rec.rationale}
                            </div>
                            <div className="rec-outcome">
                              <strong>Expected Outcome:</strong> {rec.expectedOutcome}
                            </div>
                            <div className="rec-meta">
                              <span>Cost: R$ {rec.cost.toLocaleString()}</span>
                              <span>Timeframe: {rec.timeframe}</span>
                              <span>Responsibility: {rec.responsibility}</span>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};