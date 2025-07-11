/**
 * Document Comparison Interface
 * Main component for comparing legislative documents with advanced analysis
 */
import React, { useState, useCallback, useEffect } from 'react';
import { LegislativeDocument } from '../../types';
import { documentComparisonService, DocumentComparison, DocumentDifference } from '../../services/documentComparisonService';

interface DocumentComparisonInterfaceProps {
  onComparisonComplete?: (comparison: DocumentComparison) => void;
  initialDocumentA?: LegislativeDocument;
  initialDocumentB?: LegislativeDocument;
  showAdvancedOptions?: boolean;
  enableExport?: boolean;
}

export const DocumentComparisonInterface: React.FC<DocumentComparisonInterfaceProps> = ({
  onComparisonComplete,
  initialDocumentA,
  initialDocumentB,
  showAdvancedOptions = true,
  enableExport = true
}) => {
  // State management
  const [documentA, setDocumentA] = useState<LegislativeDocument | null>(initialDocumentA || null);
  const [documentB, setDocumentB] = useState<LegislativeDocument | null>(initialDocumentB || null);
  const [comparison, setComparison] = useState<DocumentComparison | null>(null);
  const [isComparing, setIsComparing] = useState(false);
  const [activeView, setActiveView] = useState<'overview' | 'differences' | 'semantic' | 'legal' | 'export'>('overview');
  const [selectedDifference, setSelectedDifference] = useState<DocumentDifference | null>(null);
  
  // Comparison options
  const [comparisonOptions, setComparisonOptions] = useState({
    comparisonType: 'comprehensive' as 'textual' | 'semantic' | 'structural' | 'legal' | 'comprehensive',
    includeSemanticAnalysis: true,
    includeLegalAnalysis: true,
    algorithm: 'myers' as 'myers' | 'patience' | 'histogram' | 'minimal',
    contextLines: 3,
    ignoreWhitespace: false,
    ignoreCase: false
  });

  // Filter states
  const [differenceFilters, setDifferenceFilters] = useState({
    severity: 'all' as 'all' | 'critical' | 'major' | 'moderate' | 'minor',
    category: 'all' as 'all' | 'content' | 'structure' | 'metadata' | 'legal',
    type: 'all' as 'all' | 'addition' | 'deletion' | 'modification' | 'move'
  });

  /**
   * Handle document comparison
   */
  const handleCompareDocuments = useCallback(async () => {
    if (!documentA || !documentB) return;
    
    setIsComparing(true);
    try {
      const comparisonResult = await documentComparisonService.compareDocuments(
        documentA,
        documentB,
        comparisonOptions
      );
      
      setComparison(comparisonResult);
      if (onComparisonComplete) {
        onComparisonComplete(comparisonResult);
      }
    } catch (error) {
      console.error('Document comparison failed:', error);
    } finally {
      setIsComparing(false);
    }
  }, [documentA, documentB, comparisonOptions, onComparisonComplete]);

  /**
   * Filter differences based on current filters
   */
  const filteredDifferences = comparison?.differences.filter(diff => {
    if (differenceFilters.severity !== 'all' && diff.severity !== differenceFilters.severity) return false;
    if (differenceFilters.category !== 'all' && diff.category !== differenceFilters.category) return false;
    if (differenceFilters.type !== 'all' && diff.type !== differenceFilters.type) return false;
    return true;
  }) || [];

  /**
   * Generate export data
   */
  const handleExport = useCallback((format: 'unifiedDiff' | 'sideBySide' | 'redline' | 'summary' | 'legalMemo' | 'changeLog') => {
    if (!comparison) return;
    
    const exportData = comparison.exportFormats[format];
    const blob = new Blob([exportData], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `comparison_${format}_${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [comparison]);

  /**
   * Get severity color
   */
  const getSeverityColor = (severity: DocumentDifference['severity']): string => {
    switch (severity) {
      case 'critical': return '#dc2626';
      case 'major': return '#ea580c';
      case 'moderate': return '#d97706';
      case 'minor': return '#65a30d';
      default: return '#6b7280';
    }
  };

  /**
   * Get category icon
   */
  const getCategoryIcon = (category: DocumentDifference['category']): string => {
    switch (category) {
      case 'content': return '📝';
      case 'structure': return '🏗️';
      case 'metadata': return '📋';
      case 'legal': return '⚖️';
      default: return '📄';
    }
  };

  return (
    <div className="document-comparison-interface">
      {/* Header */}
      <div className="comparison-header">
        <h2>Document Comparison</h2>
        {comparison && (
          <div className="comparison-metrics">
            <div className="metric">
              <span className="metric-label">Similarity:</span>
              <span className="metric-value">{(comparison.similarity * 100).toFixed(1)}%</span>
            </div>
            <div className="metric">
              <span className="metric-label">Differences:</span>
              <span className="metric-value">{comparison.differences.length}</span>
            </div>
            <div className="metric">
              <span className="metric-label">Type:</span>
              <span className="metric-value">{comparison.comparisonType}</span>
            </div>
          </div>
        )}
      </div>

      {/* Document Selection */}
      <div className="document-selection">
        <div className="document-selector">
          <h3>Document A</h3>
          {documentA ? (
            <div className="selected-document">
              <div className="document-info">
                <h4>{documentA.title}</h4>
                <p>{documentA.type} • {documentA.date} • {documentA.author}</p>
                <p className="document-summary">{documentA.summary}</p>
              </div>
              <button 
                onClick={() => setDocumentA(null)}
                className="remove-document-btn"
              >
                ❌ Remove
              </button>
            </div>
          ) : (
            <div className="document-placeholder">
              <p>Select first document to compare</p>
              <button className="select-document-btn">📄 Select Document A</button>
            </div>
          )}
        </div>

        <div className="comparison-arrow">⇄</div>

        <div className="document-selector">
          <h3>Document B</h3>
          {documentB ? (
            <div className="selected-document">
              <div className="document-info">
                <h4>{documentB.title}</h4>
                <p>{documentB.type} • {documentB.date} • {documentB.author}</p>
                <p className="document-summary">{documentB.summary}</p>
              </div>
              <button 
                onClick={() => setDocumentB(null)}
                className="remove-document-btn"
              >
                ❌ Remove
              </button>
            </div>
          ) : (
            <div className="document-placeholder">
              <p>Select second document to compare</p>
              <button className="select-document-btn">📄 Select Document B</button>
            </div>
          )}
        </div>
      </div>

      {/* Comparison Options */}
      {showAdvancedOptions && (
        <div className="comparison-options">
          <h3>Comparison Options</h3>
          <div className="options-grid">
            <div className="option-group">
              <label>Comparison Type:</label>
              <select
                value={comparisonOptions.comparisonType}
                onChange={(e) => setComparisonOptions(prev => ({
                  ...prev,
                  comparisonType: e.target.value as any
                }))}
              >
                <option value="comprehensive">Comprehensive</option>
                <option value="textual">Textual Only</option>
                <option value="semantic">Semantic Only</option>
                <option value="structural">Structural Only</option>
                <option value="legal">Legal Only</option>
              </select>
            </div>

            <div className="option-group">
              <label>Algorithm:</label>
              <select
                value={comparisonOptions.algorithm}
                onChange={(e) => setComparisonOptions(prev => ({
                  ...prev,
                  algorithm: e.target.value as any
                }))}
              >
                <option value="myers">Myers (Balanced)</option>
                <option value="patience">Patience (Precise)</option>
                <option value="histogram">Histogram (Fast)</option>
                <option value="minimal">Minimal (Compact)</option>
              </select>
            </div>

            <div className="option-group">
              <label>Context Lines:</label>
              <input
                type="number"
                min="0"
                max="10"
                value={comparisonOptions.contextLines}
                onChange={(e) => setComparisonOptions(prev => ({
                  ...prev,
                  contextLines: parseInt(e.target.value)
                }))}
              />
            </div>

            <div className="option-group">
              <label>
                <input
                  type="checkbox"
                  checked={comparisonOptions.includeSemanticAnalysis}
                  onChange={(e) => setComparisonOptions(prev => ({
                    ...prev,
                    includeSemanticAnalysis: e.target.checked
                  }))}
                />
                Semantic Analysis
              </label>
            </div>

            <div className="option-group">
              <label>
                <input
                  type="checkbox"
                  checked={comparisonOptions.includeLegalAnalysis}
                  onChange={(e) => setComparisonOptions(prev => ({
                    ...prev,
                    includeLegalAnalysis: e.target.checked
                  }))}
                />
                Legal Analysis
              </label>
            </div>

            <div className="option-group">
              <label>
                <input
                  type="checkbox"
                  checked={comparisonOptions.ignoreWhitespace}
                  onChange={(e) => setComparisonOptions(prev => ({
                    ...prev,
                    ignoreWhitespace: e.target.checked
                  }))}
                />
                Ignore Whitespace
              </label>
            </div>

            <div className="option-group">
              <label>
                <input
                  type="checkbox"
                  checked={comparisonOptions.ignoreCase}
                  onChange={(e) => setComparisonOptions(prev => ({
                    ...prev,
                    ignoreCase: e.target.checked
                  }))}
                />
                Ignore Case
              </label>
            </div>
          </div>
        </div>
      )}

      {/* Compare Button */}
      <div className="comparison-actions">
        <button
          onClick={handleCompareDocuments}
          disabled={!documentA || !documentB || isComparing}
          className="compare-btn"
        >
          {isComparing ? '⏳ Comparing...' : '🔍 Compare Documents'}
        </button>
      </div>

      {/* Comparison Results */}
      {comparison && (
        <div className="comparison-results">
          {/* Navigation Tabs */}
          <div className="result-tabs">
            <button
              className={`tab ${activeView === 'overview' ? 'active' : ''}`}
              onClick={() => setActiveView('overview')}
            >
              📊 Overview
            </button>
            <button
              className={`tab ${activeView === 'differences' ? 'active' : ''}`}
              onClick={() => setActiveView('differences')}
            >
              📝 Differences ({filteredDifferences.length})
            </button>
            {comparison.semanticAnalysis && (
              <button
                className={`tab ${activeView === 'semantic' ? 'active' : ''}`}
                onClick={() => setActiveView('semantic')}
              >
                🧠 Semantic
              </button>
            )}
            {comparison.legalAnalysis && (
              <button
                className={`tab ${activeView === 'legal' ? 'active' : ''}`}
                onClick={() => setActiveView('legal')}
              >
                ⚖️ Legal
              </button>
            )}
            {enableExport && (
              <button
                className={`tab ${activeView === 'export' ? 'active' : ''}`}
                onClick={() => setActiveView('export')}
              >
                📤 Export
              </button>
            )}
          </div>

          {/* Overview Tab */}
          {activeView === 'overview' && (
            <div className="overview-panel">
              <div className="overview-metrics">
                <div className="metric-card">
                  <h4>Overall Similarity</h4>
                  <div className="similarity-circle">
                    <span className="similarity-percentage">
                      {(comparison.similarity * 100).toFixed(1)}%
                    </span>
                  </div>
                </div>

                <div className="metric-card">
                  <h4>Total Differences</h4>
                  <div className="difference-breakdown">
                    <div className="breakdown-item critical">
                      <span className="count">
                        {comparison.differences.filter(d => d.severity === 'critical').length}
                      </span>
                      <span className="label">Critical</span>
                    </div>
                    <div className="breakdown-item major">
                      <span className="count">
                        {comparison.differences.filter(d => d.severity === 'major').length}
                      </span>
                      <span className="label">Major</span>
                    </div>
                    <div className="breakdown-item moderate">
                      <span className="count">
                        {comparison.differences.filter(d => d.severity === 'moderate').length}
                      </span>
                      <span className="label">Moderate</span>
                    </div>
                    <div className="breakdown-item minor">
                      <span className="count">
                        {comparison.differences.filter(d => d.severity === 'minor').length}
                      </span>
                      <span className="label">Minor</span>
                    </div>
                  </div>
                </div>

                <div className="metric-card">
                  <h4>Comparison Timeline</h4>
                  <div className="timeline">
                    {comparison.timeline.events.map((event, index) => (
                      <div key={index} className="timeline-event">
                        <div className="event-date">{event.date.toLocaleDateString()}</div>
                        <div className="event-description">{event.description}</div>
                        <div className={`event-significance ${event.significance}`}>
                          {event.significance}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Semantic Overview */}
              {comparison.semanticAnalysis && (
                <div className="semantic-overview">
                  <h4>Semantic Analysis Summary</h4>
                  <div className="semantic-metrics">
                    <div className="semantic-metric">
                      <span className="metric-label">Conceptual Similarity:</span>
                      <span className="metric-value">
                        {(comparison.semanticAnalysis.conceptualSimilarity * 100).toFixed(1)}%
                      </span>
                    </div>
                    <div className="semantic-metric">
                      <span className="metric-label">Topic Overlap:</span>
                      <span className="metric-value">
                        {(comparison.semanticAnalysis.topicOverlap * 100).toFixed(1)}%
                      </span>
                    </div>
                    <div className="semantic-metric">
                      <span className="metric-label">Intent Alignment:</span>
                      <span className="metric-value">
                        {(comparison.semanticAnalysis.intentAlignment * 100).toFixed(1)}%
                      </span>
                    </div>
                  </div>

                  <div className="keyword-analysis">
                    <div className="keyword-group">
                      <h5>Common Keywords ({comparison.semanticAnalysis.keywordAnalysis.common.length})</h5>
                      <div className="keyword-list">
                        {comparison.semanticAnalysis.keywordAnalysis.common.slice(0, 10).map((keyword, index) => (
                          <span key={index} className="keyword common">{keyword}</span>
                        ))}
                      </div>
                    </div>
                    <div className="keyword-group">
                      <h5>Unique to A ({comparison.semanticAnalysis.keywordAnalysis.uniqueToA.length})</h5>
                      <div className="keyword-list">
                        {comparison.semanticAnalysis.keywordAnalysis.uniqueToA.slice(0, 10).map((keyword, index) => (
                          <span key={index} className="keyword unique-a">{keyword}</span>
                        ))}
                      </div>
                    </div>
                    <div className="keyword-group">
                      <h5>Unique to B ({comparison.semanticAnalysis.keywordAnalysis.uniqueToB.length})</h5>
                      <div className="keyword-list">
                        {comparison.semanticAnalysis.keywordAnalysis.uniqueToB.slice(0, 10).map((keyword, index) => (
                          <span key={index} className="keyword unique-b">{keyword}</span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Differences Tab */}
          {activeView === 'differences' && (
            <div className="differences-panel">
              {/* Difference Filters */}
              <div className="difference-filters">
                <div className="filter-group">
                  <label>Severity:</label>
                  <select
                    value={differenceFilters.severity}
                    onChange={(e) => setDifferenceFilters(prev => ({
                      ...prev,
                      severity: e.target.value as any
                    }))}
                  >
                    <option value="all">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="major">Major</option>
                    <option value="moderate">Moderate</option>
                    <option value="minor">Minor</option>
                  </select>
                </div>

                <div className="filter-group">
                  <label>Category:</label>
                  <select
                    value={differenceFilters.category}
                    onChange={(e) => setDifferenceFilters(prev => ({
                      ...prev,
                      category: e.target.value as any
                    }))}
                  >
                    <option value="all">All Categories</option>
                    <option value="content">Content</option>
                    <option value="structure">Structure</option>
                    <option value="metadata">Metadata</option>
                    <option value="legal">Legal</option>
                  </select>
                </div>

                <div className="filter-group">
                  <label>Type:</label>
                  <select
                    value={differenceFilters.type}
                    onChange={(e) => setDifferenceFilters(prev => ({
                      ...prev,
                      type: e.target.value as any
                    }))}
                  >
                    <option value="all">All Types</option>
                    <option value="addition">Additions</option>
                    <option value="deletion">Deletions</option>
                    <option value="modification">Modifications</option>
                    <option value="move">Moves</option>
                  </select>
                </div>
              </div>

              {/* Differences List */}
              <div className="differences-list">
                {filteredDifferences.map((difference) => (
                  <div
                    key={difference.id}
                    className={`difference-item ${selectedDifference?.id === difference.id ? 'selected' : ''}`}
                    onClick={() => setSelectedDifference(difference)}
                  >
                    <div className="difference-header">
                      <div className="difference-meta">
                        <span className="category-icon">{getCategoryIcon(difference.category)}</span>
                        <span className="difference-type">{difference.type}</span>
                        <span
                          className="severity-badge"
                          style={{ backgroundColor: getSeverityColor(difference.severity) }}
                        >
                          {difference.severity}
                        </span>
                        <span className="category-badge">{difference.category}</span>
                      </div>
                      <div className="confidence-score">
                        {(difference.confidence * 100).toFixed(0)}% confidence
                      </div>
                    </div>

                    <div className="difference-explanation">
                      {difference.explanation}
                    </div>

                    {difference.originalText && difference.newText && (
                      <div className="difference-content">
                        <div className="text-comparison">
                          <div className="original-text">
                            <span className="text-label">Original:</span>
                            <span className="text-content">{difference.originalText}</span>
                          </div>
                          <div className="new-text">
                            <span className="text-label">New:</span>
                            <span className="text-content">{difference.newText}</span>
                          </div>
                        </div>
                      </div>
                    )}

                    {difference.legalImplications && difference.legalImplications.length > 0 && (
                      <div className="legal-implications">
                        <span className="implications-label">Legal Implications:</span>
                        <ul>
                          {difference.legalImplications.map((implication, index) => (
                            <li key={index}>{implication}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                ))}

                {filteredDifferences.length === 0 && (
                  <div className="no-differences">
                    <p>No differences found matching the current filters.</p>
                  </div>
                )}
              </div>

              {/* Selected Difference Detail */}
              {selectedDifference && (
                <div className="difference-detail">
                  <h4>Difference Details</h4>
                  <div className="detail-content">
                    <div className="detail-section">
                      <h5>Context</h5>
                      <pre className="context-text">{selectedDifference.context}</pre>
                    </div>
                    {selectedDifference.position.documentA && (
                      <div className="detail-section">
                        <h5>Position in Document A</h5>
                        <p>Line {selectedDifference.position.documentA.line}</p>
                      </div>
                    )}
                    {selectedDifference.position.documentB && (
                      <div className="detail-section">
                        <h5>Position in Document B</h5>
                        <p>Line {selectedDifference.position.documentB.line}</p>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Semantic Tab */}
          {activeView === 'semantic' && comparison.semanticAnalysis && (
            <div className="semantic-panel">
              <div className="semantic-sections">
                <div className="semantic-section">
                  <h4>Scope Comparison</h4>
                  <div className="scope-metrics">
                    <div className="scope-metric">
                      <span className="metric-label">Broadening:</span>
                      <div className="metric-bar">
                        <div 
                          className="metric-fill broadening"
                          style={{ width: `${comparison.semanticAnalysis.scopeComparison.broadening * 100}%` }}
                        ></div>
                      </div>
                      <span className="metric-value">
                        {(comparison.semanticAnalysis.scopeComparison.broadening * 100).toFixed(1)}%
                      </span>
                    </div>
                    <div className="scope-metric">
                      <span className="metric-label">Narrowing:</span>
                      <div className="metric-bar">
                        <div 
                          className="metric-fill narrowing"
                          style={{ width: `${comparison.semanticAnalysis.scopeComparison.narrowing * 100}%` }}
                        ></div>
                      </div>
                      <span className="metric-value">
                        {(comparison.semanticAnalysis.scopeComparison.narrowing * 100).toFixed(1)}%
                      </span>
                    </div>
                    <div className="scope-metric">
                      <span className="metric-label">Unchanged:</span>
                      <div className="metric-bar">
                        <div 
                          className="metric-fill unchanged"
                          style={{ width: `${comparison.semanticAnalysis.scopeComparison.unchanged * 100}%` }}
                        ></div>
                      </div>
                      <span className="metric-value">
                        {(comparison.semanticAnalysis.scopeComparison.unchanged * 100).toFixed(1)}%
                      </span>
                    </div>
                  </div>
                </div>

                <div className="semantic-section">
                  <h4>Semantic Shifts</h4>
                  {comparison.semanticAnalysis.semanticShifts.length > 0 ? (
                    <div className="semantic-shifts">
                      {comparison.semanticAnalysis.semanticShifts.map((shift, index) => (
                        <div key={index} className="semantic-shift">
                          <div className="shift-header">
                            <span className="shift-concept">{shift.concept}</span>
                            <span className={`shift-impact ${shift.impact}`}>{shift.impact} impact</span>
                          </div>
                          <div className="shift-type">{shift.shift}</div>
                          <div className="shift-description">{shift.description}</div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p>No significant semantic shifts detected.</p>
                  )}
                </div>

                <div className="semantic-section">
                  <h4>Modified Keywords</h4>
                  {comparison.semanticAnalysis.keywordAnalysis.modified.length > 0 ? (
                    <div className="modified-keywords">
                      {comparison.semanticAnalysis.keywordAnalysis.modified.map((modification, index) => (
                        <div key={index} className="keyword-modification">
                          <span className="keyword-from">{modification.from}</span>
                          <span className="modification-arrow">→</span>
                          <span className="keyword-to">{modification.to}</span>
                          <span className="modification-reason">({modification.reason})</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p>No keyword modifications detected.</p>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Legal Tab */}
          {activeView === 'legal' && comparison.legalAnalysis && (
            <div className="legal-panel">
              <div className="legal-sections">
                <div className="legal-section">
                  <h4>Jurisdiction & Authority</h4>
                  <div className="legal-metrics">
                    <div className="legal-metric">
                      <span className="metric-label">Jurisdiction Alignment:</span>
                      <span className="metric-value">
                        {(comparison.legalAnalysis.jurisdictionAlignment * 100).toFixed(1)}%
                      </span>
                    </div>
                    <div className="legal-metric">
                      <span className="metric-label">Authority Consistency:</span>
                      <span className="metric-value">
                        {(comparison.legalAnalysis.authorityConsistency * 100).toFixed(1)}%
                      </span>
                    </div>
                  </div>
                </div>

                <div className="legal-section">
                  <h4>Regulatory Impact</h4>
                  <div className="regulatory-impact">
                    <div className="impact-category">
                      <h5>New Obligations ({comparison.legalAnalysis.regulatoryImpact.newObligations.length})</h5>
                      <ul>
                        {comparison.legalAnalysis.regulatoryImpact.newObligations.map((obligation, index) => (
                          <li key={index}>{obligation}</li>
                        ))}
                      </ul>
                    </div>
                    <div className="impact-category">
                      <h5>Removed Obligations ({comparison.legalAnalysis.regulatoryImpact.removedObligations.length})</h5>
                      <ul>
                        {comparison.legalAnalysis.regulatoryImpact.removedObligations.map((obligation, index) => (
                          <li key={index}>{obligation}</li>
                        ))}
                      </ul>
                    </div>
                    <div className="impact-category">
                      <h5>Modified Obligations ({comparison.legalAnalysis.regulatoryImpact.modifiedObligations.length})</h5>
                      <ul>
                        {comparison.legalAnalysis.regulatoryImpact.modifiedObligations.map((modification, index) => (
                          <li key={index}>
                            <strong>From:</strong> {modification.original} <br />
                            <strong>To:</strong> {modification.modified} <br />
                            <strong>Impact:</strong> {modification.impact}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>

                <div className="legal-section">
                  <h4>Compliance Implications</h4>
                  {comparison.legalAnalysis.complianceImplications.length > 0 ? (
                    <div className="compliance-implications">
                      {comparison.legalAnalysis.complianceImplications.map((implication, index) => (
                        <div key={index} className="compliance-implication">
                          <div className="implication-header">
                            <span className="implication-area">{implication.area}</span>
                            <span className={`implication-severity ${implication.severity}`}>
                              {implication.severity}
                            </span>
                          </div>
                          <div className="implication-description">{implication.implication}</div>
                          <div className="affected-parties">
                            <strong>Affected parties:</strong> {implication.affectedParties.join(', ')}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p>No specific compliance implications identified.</p>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Export Tab */}
          {activeView === 'export' && enableExport && (
            <div className="export-panel">
              <h4>Export Comparison Results</h4>
              <div className="export-options">
                <div className="export-option">
                  <h5>📄 Unified Diff</h5>
                  <p>Traditional diff format showing line-by-line changes</p>
                  <button onClick={() => handleExport('unifiedDiff')} className="export-btn">
                    Download Unified Diff
                  </button>
                </div>

                <div className="export-option">
                  <h5>📋 Side-by-Side</h5>
                  <p>Side-by-side comparison format</p>
                  <button onClick={() => handleExport('sideBySide')} className="export-btn">
                    Download Side-by-Side
                  </button>
                </div>

                <div className="export-option">
                  <h5>🖍️ Redline</h5>
                  <p>Redline format with tracked changes</p>
                  <button onClick={() => handleExport('redline')} className="export-btn">
                    Download Redline
                  </button>
                </div>

                <div className="export-option">
                  <h5>📊 Summary Report</h5>
                  <p>Executive summary of comparison results</p>
                  <button onClick={() => handleExport('summary')} className="export-btn">
                    Download Summary
                  </button>
                </div>

                <div className="export-option">
                  <h5>⚖️ Legal Memo</h5>
                  <p>Legal memorandum analyzing document differences</p>
                  <button onClick={() => handleExport('legalMemo')} className="export-btn">
                    Download Legal Memo
                  </button>
                </div>

                <div className="export-option">
                  <h5>📝 Change Log</h5>
                  <p>Detailed log of all changes and modifications</p>
                  <button onClick={() => handleExport('changeLog')} className="export-btn">
                    Download Change Log
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};