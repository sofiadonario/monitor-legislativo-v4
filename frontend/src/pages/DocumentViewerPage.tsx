/**
 * DocumentViewerPage
 * Integrated document analysis page with all Sprint 2 components
 */
import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import { DocumentViewer } from '../components/DocumentViewer';
import { CrossReferenceViewer } from '../components/CrossReferenceViewer';
import { DocumentComparison } from '../components/DocumentComparison';
import { CitationGenerator } from '../components/CitationGenerator';
import { DocumentContent } from '../types';
import { documentAnalysisService } from '../services/documentAnalysisService';
import './DocumentViewerPage.css';

type ViewMode = 'document' | 'references' | 'comparison' | 'citation';

export const DocumentViewerPage: React.FC = () => {
  const { urn } = useParams<{ urn: string }>();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  
  const [viewMode, setViewMode] = useState<ViewMode>('document');
  const [document, setDocument] = useState<DocumentContent | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [comparisonUrns, setComparisonUrns] = useState<string[]>([]);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  // Get comparison URNs from URL params
  const compareWith = searchParams.get('compare');
  const initialViewMode = searchParams.get('view') as ViewMode || 'document';

  useEffect(() => {
    if (compareWith) {
      const urns = compareWith.split(',').filter(Boolean);
      setComparisonUrns(urns);
      if (urns.length > 0) {
        setViewMode('comparison');
      }
    }
    setViewMode(initialViewMode);
  }, [compareWith, initialViewMode]);

  useEffect(() => {
    if (urn) {
      loadDocument();
    }
  }, [urn]);

  const loadDocument = async () => {
    if (!urn) return;

    try {
      setLoading(true);
      setError(null);
      const doc = await documentAnalysisService.getDocumentContent(urn);
      if (doc) {
        setDocument(doc);
      } else {
        setError('Document not found');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load document');
    } finally {
      setLoading(false);
    }
  };

  const handleViewModeChange = (mode: ViewMode) => {
    setViewMode(mode);
    const newSearchParams = new URLSearchParams(searchParams);
    newSearchParams.set('view', mode);
    setSearchParams(newSearchParams);
  };

  const handleDocumentSelect = (selectedUrn: string) => {
    navigate(`/document/${encodeURIComponent(selectedUrn)}`);
  };

  const handleCompareDocuments = (urns: string[]) => {
    setComparisonUrns(urns);
    const newSearchParams = new URLSearchParams(searchParams);
    if (urns.length > 0) {
      newSearchParams.set('compare', urns.join(','));
      newSearchParams.set('view', 'comparison');
    } else {
      newSearchParams.delete('compare');
      newSearchParams.set('view', 'document');
    }
    setSearchParams(newSearchParams);
    setViewMode(urns.length > 0 ? 'comparison' : 'document');
  };

  const handleBackToSearch = () => {
    navigate('/advanced-search');
  };

  const getActiveTabClass = (mode: ViewMode) => {
    return `document-viewer-page__tab ${viewMode === mode ? 'active' : ''}`;
  };

  if (!urn) {
    return (
      <div className="document-viewer-page__error">
        <h2>Invalid Document</h2>
        <p>No document URN provided.</p>
        <button onClick={handleBackToSearch}>
          ← Back to Search
        </button>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="document-viewer-page__loading">
        <div className="document-viewer-page__spinner"></div>
        <p>Loading document analysis tools...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="document-viewer-page__error">
        <h2>Error Loading Document</h2>
        <p>{error}</p>
        <div className="document-viewer-page__error-actions">
          <button onClick={loadDocument}>
            Try Again
          </button>
          <button onClick={handleBackToSearch}>
            ← Back to Search
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="document-viewer-page">
      <div className="document-viewer-page__header">
        <div className="document-viewer-page__title-section">
          <button 
            onClick={handleBackToSearch}
            className="document-viewer-page__back-btn"
          >
            ← Back to Search
          </button>
          <div className="document-viewer-page__title-info">
            <h1>Document Analysis</h1>
            {document && (
              <p className="document-viewer-page__document-title">
                {document.title}
              </p>
            )}
          </div>
        </div>

        <div className="document-viewer-page__header-actions">
          <button
            onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
            className="document-viewer-page__sidebar-toggle"
            title={sidebarCollapsed ? 'Show sidebar' : 'Hide sidebar'}
          >
            {sidebarCollapsed ? '→' : '←'}
          </button>
        </div>
      </div>

      <div className="document-viewer-page__container">
        {/* Sidebar with navigation */}
        <div className={`document-viewer-page__sidebar ${sidebarCollapsed ? 'collapsed' : ''}`}>
          <nav className="document-viewer-page__nav">
            <h3>Analysis Tools</h3>
            <div className="document-viewer-page__tabs">
              <button
                onClick={() => handleViewModeChange('document')}
                className={getActiveTabClass('document')}
              >
                📄 Document View
              </button>
              <button
                onClick={() => handleViewModeChange('references')}
                className={getActiveTabClass('references')}
              >
                🔗 Cross References
              </button>
              <button
                onClick={() => handleViewModeChange('comparison')}
                className={getActiveTabClass('comparison')}
                disabled={comparisonUrns.length === 0}
              >
                📊 Document Comparison
                {comparisonUrns.length > 0 && (
                  <span className="document-viewer-page__tab-badge">
                    {comparisonUrns.length + 1}
                  </span>
                )}
              </button>
              <button
                onClick={() => handleViewModeChange('citation')}
                className={getActiveTabClass('citation')}
              >
                📝 Citation Generator
              </button>
            </div>
          </nav>

          {/* Quick Actions */}
          <div className="document-viewer-page__quick-actions">
            <h4>Quick Actions</h4>
            <div className="document-viewer-page__action-buttons">
              <button
                onClick={() => handleViewModeChange('citation')}
                className="document-viewer-page__action-btn"
              >
                📋 Generate Citation
              </button>
              <button
                onClick={() => {
                  if (urn) {
                    handleCompareDocuments([urn]);
                  }
                }}
                className="document-viewer-page__action-btn"
                disabled={!urn}
              >
                🔍 Find Similar
              </button>
            </div>
          </div>

          {/* Document Info */}
          {document && !sidebarCollapsed && (
            <div className="document-viewer-page__document-info">
              <h4>Document Info</h4>
              <div className="document-viewer-page__info-grid">
                <div className="document-viewer-page__info-item">
                  <strong>Type:</strong>
                  <span>{document.metadata.type}</span>
                </div>
                <div className="document-viewer-page__info-item">
                  <strong>Authority:</strong>
                  <span>{document.metadata.authority}</span>
                </div>
                <div className="document-viewer-page__info-item">
                  <strong>Status:</strong>
                  <span className={`document-viewer-page__status document-viewer-page__status--${document.metadata.status}`}>
                    {document.metadata.status.replace('_', ' ')}
                  </span>
                </div>
                <div className="document-viewer-page__info-item">
                  <strong>Publication:</strong>
                  <span>{new Date(document.metadata.publicationDate).toLocaleDateString('pt-BR')}</span>
                </div>
                {document.metadata.qualityScore && (
                  <div className="document-viewer-page__info-item">
                    <strong>Quality Score:</strong>
                    <span className="document-viewer-page__quality-score">
                      {Math.round(document.metadata.qualityScore.overall * 100)}%
                    </span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Main content area */}
        <div className="document-viewer-page__main">
          {viewMode === 'document' && (
            <DocumentViewer
              urn={urn}
              showMetadata={false}
              showQualityScore={true}
            />
          )}

          {viewMode === 'references' && (
            <CrossReferenceViewer
              urn={urn}
              onDocumentSelect={handleDocumentSelect}
              showSimilarDocuments={true}
              maxReferences={100}
            />
          )}

          {viewMode === 'comparison' && (
            <div className="document-viewer-page__comparison">
              {comparisonUrns.length > 0 ? (
                <DocumentComparison
                  urns={[urn, ...comparisonUrns]}
                  showMetadata={true}
                  showSummary={true}
                />
              ) : (
                <div className="document-viewer-page__comparison-placeholder">
                  <h3>Document Comparison</h3>
                  <p>No documents selected for comparison.</p>
                  <p>Use the Cross References view to find similar documents, or return to search to select documents for comparison.</p>
                  <div className="document-viewer-page__comparison-actions">
                    <button
                      onClick={() => handleViewModeChange('references')}
                      className="document-viewer-page__action-btn"
                    >
                      🔗 Find Related Documents
                    </button>
                    <button
                      onClick={handleBackToSearch}
                      className="document-viewer-page__action-btn"
                    >
                      🔍 Back to Search
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          {viewMode === 'citation' && (
            <div className="document-viewer-page__citation">
              <CitationGenerator
                urn={urn}
                urns={comparisonUrns.length > 0 ? [urn, ...comparisonUrns] : undefined}
                defaultFormat="ABNT"
                showAllFormats={true}
              />
            </div>
          )}
        </div>
      </div>
    </div>
  );
};