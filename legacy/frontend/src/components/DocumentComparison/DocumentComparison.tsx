/**
 * DocumentComparison Component
 * Side-by-side document comparison with difference highlighting
 */
import React, { useState, useEffect } from 'react';
import { DocumentContent, ComparisonResult, Difference } from '../../types';
import { documentAnalysisService } from '../../services/documentAnalysisService';
import './DocumentComparison.css';

interface DocumentComparisonProps {
  urns: string[];
  onClose?: () => void;
  showMetadata?: boolean;
  showSummary?: boolean;
}

export const DocumentComparison: React.FC<DocumentComparisonProps> = ({
  urns,
  onClose,
  showMetadata = true,
  showSummary = true
}) => {
  const [documents, setDocuments] = useState<DocumentContent[]>([]);
  const [comparison, setComparison] = useState<ComparisonResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<'side-by-side' | 'unified' | 'metadata'>('side-by-side');
  const [showDifferencesOnly, setShowDifferencesOnly] = useState(false);
  const [activeDifference, setActiveDifference] = useState<number | null>(null);
  const [fontSize, setFontSize] = useState<'small' | 'medium' | 'large'>('medium');

  useEffect(() => {
    if (urns.length >= 2) {
      loadDocumentsAndComparison();
    }
  }, [urns]);

  const loadDocumentsAndComparison = async () => {
    try {
      setLoading(true);
      setError(null);

      // Load documents in parallel
      const documentPromises = urns.map(urn => 
        documentAnalysisService.getDocumentContent(urn)
      );

      const [documentsResult, comparisonResult] = await Promise.allSettled([
        Promise.all(documentPromises),
        documentAnalysisService.compareDocuments(urns)
      ]);

      if (documentsResult.status === 'fulfilled') {
        const validDocs = documentsResult.value.filter(doc => doc !== null) as DocumentContent[];
        setDocuments(validDocs);
      } else {
        throw new Error('Failed to load documents');
      }

      if (comparisonResult.status === 'fulfilled' && comparisonResult.value) {
        setComparison(comparisonResult.value);
      } else {
        console.warn('Failed to load comparison analysis:', comparisonResult.status === 'rejected' ? comparisonResult.reason : 'Unknown error');
      }

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load documents');
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString: string) => {
    try {
      return new Date(dateString).toLocaleDateString('pt-BR', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
      });
    } catch {
      return dateString;
    }
  };

  const getSimilarityColor = (similarity: number) => {
    if (similarity >= 0.8) return '#10b981';
    if (similarity >= 0.6) return '#f59e0b';
    if (similarity >= 0.4) return '#ef4444';
    return '#6b7280';
  };

  const getDifferenceTypeColor = (significance: string) => {
    const colors = {
      high: '#ef4444',
      medium: '#f59e0b',
      low: '#6b7280'
    };
    return colors[significance as keyof typeof colors] || '#6b7280';
  };

  const scrollToDifference = (index: number) => {
    setActiveDifference(index);
    const element = document.getElementById(`difference-${index}`);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  };

  const highlightDifferences = (content: string, differences: Difference[], docIndex: number) => {
    if (!showDifferencesOnly || differences.length === 0) {
      return content;
    }

    // This is a simplified implementation
    // In a real system, you'd use proper diff algorithms like Myers' diff
    let highlightedContent = content;
    differences.forEach((diff, index) => {
      const value = docIndex === 0 ? diff.document1Value : diff.document2Value;
      if (value && value.length > 3) {
        const regex = new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
        highlightedContent = highlightedContent.replace(
          regex,
          `<mark id="difference-${index}" class="difference-highlight ${diff.significance}">${value}</mark>`
        );
      }
    });

    return highlightedContent;
  };

  if (loading) {
    return (
      <div className="document-comparison__loading">
        <div className="document-comparison__spinner"></div>
        <p>Loading documents for comparison...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="document-comparison__error">
        <h3>Error Loading Documents</h3>
        <p>{error}</p>
        <button onClick={loadDocumentsAndComparison} className="document-comparison__retry-btn">
          Try Again
        </button>
      </div>
    );
  }

  if (documents.length < 2) {
    return (
      <div className="document-comparison__insufficient">
        <h3>Insufficient Documents</h3>
        <p>At least 2 documents are required for comparison.</p>
        <p>Found: {documents.length} valid documents</p>
      </div>
    );
  }

  return (
    <div className={`document-comparison font-size-${fontSize}`}>
      {onClose && (
        <div className="document-comparison__header">
          <button onClick={onClose} className="document-comparison__close-btn">
            ← Back to Search
          </button>
          <h2>Document Comparison</h2>
        </div>
      )}

      <div className="document-comparison__toolbar">
        <div className="document-comparison__view-controls">
          <label>View Mode:</label>
          <div className="document-comparison__view-buttons">
            <button
              onClick={() => setViewMode('side-by-side')}
              className={`document-comparison__view-btn ${viewMode === 'side-by-side' ? 'active' : ''}`}
            >
              Side by Side
            </button>
            <button
              onClick={() => setViewMode('unified')}
              className={`document-comparison__view-btn ${viewMode === 'unified' ? 'active' : ''}`}
            >
              Unified View
            </button>
            {showMetadata && (
              <button
                onClick={() => setViewMode('metadata')}
                className={`document-comparison__view-btn ${viewMode === 'metadata' ? 'active' : ''}`}
              >
                Metadata Only
              </button>
            )}
          </div>
        </div>

        <div className="document-comparison__options">
          <label>
            <input
              type="checkbox"
              checked={showDifferencesOnly}
              onChange={(e) => setShowDifferencesOnly(e.target.checked)}
            />
            Highlight Differences
          </label>

          <div className="document-comparison__font-controls">
            <label>Font Size:</label>
            <select
              value={fontSize}
              onChange={(e) => setFontSize(e.target.value as any)}
              className="document-comparison__select"
            >
              <option value="small">Small</option>
              <option value="medium">Medium</option>
              <option value="large">Large</option>
            </select>
          </div>
        </div>
      </div>

      {/* Comparison Summary */}
      {showSummary && comparison && (
        <div className="document-comparison__summary">
          <h3>Comparison Analysis</h3>
          <div className="document-comparison__metrics">
            <div className="document-comparison__metric">
              <span className="document-comparison__metric-label">Overall Similarity:</span>
              <span
                className="document-comparison__metric-value"
                style={{ color: getSimilarityColor(comparison.similarities.overallSimilarity) }}
              >
                {Math.round(comparison.similarities.overallSimilarity * 100)}%
              </span>
            </div>
            <div className="document-comparison__metric">
              <span className="document-comparison__metric-label">Content Similarity:</span>
              <span
                className="document-comparison__metric-value"
                style={{ color: getSimilarityColor(comparison.similarities.contentSimilarity) }}
              >
                {Math.round(comparison.similarities.contentSimilarity * 100)}%
              </span>
            </div>
            <div className="document-comparison__metric">
              <span className="document-comparison__metric-label">Structure Similarity:</span>
              <span
                className="document-comparison__metric-value"
                style={{ color: getSimilarityColor(comparison.similarities.structureSimilarity) }}
              >
                {Math.round(comparison.similarities.structureSimilarity * 100)}%
              </span>
            </div>
            <div className="document-comparison__metric">
              <span className="document-comparison__metric-label">Differences Found:</span>
              <span className="document-comparison__metric-value">
                {comparison.differences.length}
              </span>
            </div>
          </div>

          {comparison.differences.length > 0 && (
            <div className="document-comparison__differences-nav">
              <h4>Key Differences:</h4>
              <div className="document-comparison__differences-list">
                {comparison.differences.slice(0, 10).map((diff, index) => (
                  <button
                    key={index}
                    onClick={() => scrollToDifference(index)}
                    className={`document-comparison__difference-item ${
                      activeDifference === index ? 'active' : ''
                    }`}
                    style={{ borderLeftColor: getDifferenceTypeColor(diff.significance) }}
                  >
                    <span className="document-comparison__difference-type">
                      {diff.type.toUpperCase()}
                    </span>
                    <span className="document-comparison__difference-field">
                      {diff.field}
                    </span>
                    <span
                      className="document-comparison__difference-significance"
                      style={{ color: getDifferenceTypeColor(diff.significance) }}
                    >
                      {diff.significance}
                    </span>
                  </button>
                ))}
                {comparison.differences.length > 10 && (
                  <p className="document-comparison__differences-more">
                    +{comparison.differences.length - 10} more differences
                  </p>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      <div className="document-comparison__content">
        {viewMode === 'metadata' ? (
          <div className="document-comparison__metadata-view">
            <div className="document-comparison__metadata-comparison">
              {documents.map((doc, index) => (
                <div key={doc.urn} className="document-comparison__metadata-panel">
                  <h3>Document {index + 1}</h3>
                  <div className="document-comparison__metadata-grid">
                    <div className="document-comparison__metadata-item">
                      <strong>Title:</strong>
                      <span>{doc.metadata.title}</span>
                    </div>
                    <div className="document-comparison__metadata-item">
                      <strong>Type:</strong>
                      <span>{doc.metadata.type}</span>
                    </div>
                    <div className="document-comparison__metadata-item">
                      <strong>Authority:</strong>
                      <span>{doc.metadata.authority}</span>
                    </div>
                    <div className="document-comparison__metadata-item">
                      <strong>Publication Date:</strong>
                      <span>{formatDate(doc.metadata.publicationDate)}</span>
                    </div>
                    <div className="document-comparison__metadata-item">
                      <strong>Status:</strong>
                      <span className={`document-comparison__status document-comparison__status--${doc.metadata.status}`}>
                        {doc.metadata.status.replace('_', ' ')}
                      </span>
                    </div>
                    <div className="document-comparison__metadata-item">
                      <strong>Keywords:</strong>
                      <div className="document-comparison__keywords">
                        {doc.metadata.keywords.map(keyword => (
                          <span key={keyword} className="document-comparison__keyword">
                            {keyword}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : viewMode === 'side-by-side' ? (
          <div className="document-comparison__side-by-side">
            {documents.map((doc, index) => (
              <div key={doc.urn} className="document-comparison__document-panel">
                <div className="document-comparison__document-header">
                  <h3>Document {index + 1}</h3>
                  <h4>{doc.title}</h4>
                  <p className="document-comparison__document-urn">{doc.urn}</p>
                </div>
                <div className="document-comparison__document-content">
                  <div
                    dangerouslySetInnerHTML={{
                      __html: showDifferencesOnly && comparison
                        ? highlightDifferences(doc.content, comparison.differences, index)
                        : doc.content
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="document-comparison__unified">
            <div className="document-comparison__unified-content">
              {documents.map((doc, index) => (
                <div key={doc.urn} className="document-comparison__unified-section">
                  <div className="document-comparison__unified-header">
                    <h3>Document {index + 1}: {doc.title}</h3>
                  </div>
                  <div
                    className="document-comparison__unified-body"
                    dangerouslySetInnerHTML={{
                      __html: showDifferencesOnly && comparison
                        ? highlightDifferences(doc.content, comparison.differences, index)
                        : doc.content
                    }}
                  />
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Insights Summary */}
      {showSummary && comparison?.summary && (
        <div className="document-comparison__insights">
          <h3>Analysis Insights</h3>
          
          {comparison.summary.primaryDifferences.length > 0 && (
            <div className="document-comparison__insight-section">
              <h4>Primary Differences</h4>
              <ul>
                {comparison.summary.primaryDifferences.map((diff, index) => (
                  <li key={index}>{diff}</li>
                ))}
              </ul>
            </div>
          )}

          {comparison.summary.keyInsights.length > 0 && (
            <div className="document-comparison__insight-section">
              <h4>Key Insights</h4>
              <ul>
                {comparison.summary.keyInsights.map((insight, index) => (
                  <li key={index}>{insight}</li>
                ))}
              </ul>
            </div>
          )}

          {comparison.summary.recommendations.length > 0 && (
            <div className="document-comparison__insight-section">
              <h4>Recommendations</h4>
              <ul>
                {comparison.summary.recommendations.map((rec, index) => (
                  <li key={index}>{rec}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
};