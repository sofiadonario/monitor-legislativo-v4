/**
 * DocumentViewer Component
 * Academic-style document viewer with formatting, annotations, and metadata display
 */
import React, { useState, useEffect } from 'react';
import { DocumentContent, DocumentMetadata, QualityScore } from '../../types';
import { documentAnalysisService } from '../../services/documentAnalysisService';
import './DocumentViewer.css';

interface DocumentViewerProps {
  urn: string;
  onClose?: () => void;
  showMetadata?: boolean;
  showQualityScore?: boolean;
}

export const DocumentViewer: React.FC<DocumentViewerProps> = ({
  urn,
  onClose,
  showMetadata = true,
  showQualityScore = true
}) => {
  const [document, setDocument] = useState<DocumentContent | null>(null);
  const [metadata, setMetadata] = useState<DocumentMetadata | null>(null);
  const [qualityScore, setQualityScore] = useState<QualityScore | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<'formatted' | 'html' | 'plain'>('formatted');
  const [fontSize, setFontSize] = useState<'small' | 'medium' | 'large'>('medium');
  const [showToc, setShowToc] = useState(true);
  const [activeSection, setActiveSection] = useState<string | null>(null);

  useEffect(() => {
    if (urn) {
      loadDocument();
    }
  }, [urn]);

  const loadDocument = async () => {
    try {
      setLoading(true);
      setError(null);

      const [docContent, docMetadata, docQuality] = await Promise.allSettled([
        documentAnalysisService.getDocumentContent(urn),
        showMetadata ? documentAnalysisService.getDocumentMetadata(urn) : Promise.resolve(null),
        showQualityScore ? documentAnalysisService.getQualityScore(urn) : Promise.resolve(null)
      ]);

      if (docContent.status === 'fulfilled' && docContent.value) {
        setDocument(docContent.value);
      } else {
        throw new Error('Document not found');
      }

      if (docMetadata.status === 'fulfilled') {
        setMetadata(docMetadata.value);
      }

      if (docQuality.status === 'fulfilled') {
        setQualityScore(docQuality.value);
      }

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load document');
    } finally {
      setLoading(false);
    }
  };

  const handleSectionClick = (sectionId: string) => {
    setActiveSection(sectionId);
    const element = window.document.getElementById(`section-${sectionId}`);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
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

  const getQualityColor = (score: number) => {
    if (score >= 0.8) return '#10b981'; // green
    if (score >= 0.6) return '#f59e0b'; // yellow
    return '#ef4444'; // red
  };

  if (loading) {
    return (
      <div className="document-viewer__loading">
        <div className="document-viewer__spinner"></div>
        <p>Loading document...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="document-viewer__error">
        <h3>Error Loading Document</h3>
        <p>{error}</p>
        <button onClick={loadDocument} className="document-viewer__retry-btn">
          Try Again
        </button>
      </div>
    );
  }

  if (!document) {
    return (
      <div className="document-viewer__not-found">
        <h3>Document Not Found</h3>
        <p>The requested document could not be found.</p>
      </div>
    );
  }

  return (
    <div className={`document-viewer font-size-${fontSize}`}>
      {onClose && (
        <div className="document-viewer__header">
          <button onClick={onClose} className="document-viewer__close-btn">
            ← Back to Search
          </button>
        </div>
      )}

      <div className="document-viewer__toolbar">
        <div className="document-viewer__view-controls">
          <label>View:</label>
          <select
            value={viewMode}
            onChange={(e) => setViewMode(e.target.value as any)}
            className="document-viewer__select"
          >
            <option value="formatted">Formatted</option>
            <option value="html">HTML Source</option>
            <option value="plain">Plain Text</option>
          </select>
        </div>

        <div className="document-viewer__font-controls">
          <label>Font Size:</label>
          <select
            value={fontSize}
            onChange={(e) => setFontSize(e.target.value as any)}
            className="document-viewer__select"
          >
            <option value="small">Small</option>
            <option value="medium">Medium</option>
            <option value="large">Large</option>
          </select>
        </div>

        <div className="document-viewer__layout-controls">
          <label>
            <input
              type="checkbox"
              checked={showToc}
              onChange={(e) => setShowToc(e.target.checked)}
            />
            Show Table of Contents
          </label>
        </div>
      </div>

      <div className="document-viewer__container">
        {/* Sidebar with metadata and TOC */}
        {(showToc || showMetadata) && (
          <div className="document-viewer__sidebar">
            {/* Document Metadata */}
            {showMetadata && (metadata || document.metadata) && (
              <div className="document-viewer__metadata">
                <h3>Document Information</h3>
                <div className="document-viewer__metadata-grid">
                  <div className="document-viewer__metadata-item">
                    <strong>Title:</strong>
                    <span>{(metadata || document.metadata).title}</span>
                  </div>
                  <div className="document-viewer__metadata-item">
                    <strong>Type:</strong>
                    <span>{(metadata || document.metadata).type}</span>
                  </div>
                  <div className="document-viewer__metadata-item">
                    <strong>Authority:</strong>
                    <span>{(metadata || document.metadata).authority}</span>
                  </div>
                  <div className="document-viewer__metadata-item">
                    <strong>Publication Date:</strong>
                    <span>{formatDate((metadata || document.metadata).publicationDate)}</span>
                  </div>
                  {(metadata || document.metadata).effectiveDate && (
                    <div className="document-viewer__metadata-item">
                      <strong>Effective Date:</strong>
                      <span>{formatDate((metadata || document.metadata).effectiveDate!)}</span>
                    </div>
                  )}
                  <div className="document-viewer__metadata-item">
                    <strong>Status:</strong>
                    <span className={`document-viewer__status document-viewer__status--${(metadata || document.metadata).status}`}>
                      {(metadata || document.metadata).status.replace('_', ' ')}
                    </span>
                  </div>
                  <div className="document-viewer__metadata-item">
                    <strong>Language:</strong>
                    <span>{(metadata || document.metadata).language}</span>
                  </div>
                  <div className="document-viewer__metadata-item">
                    <strong>Jurisdiction:</strong>
                    <span>{(metadata || document.metadata).jurisdiction}</span>
                  </div>
                  <div className="document-viewer__metadata-item">
                    <strong>Source:</strong>
                    <span>{(metadata || document.metadata).source}</span>
                  </div>
                </div>

                {/* Keywords */}
                {(metadata || document.metadata).keywords.length > 0 && (
                  <div className="document-viewer__keywords">
                    <strong>Keywords:</strong>
                    <div className="document-viewer__keyword-list">
                      {(metadata || document.metadata).keywords.map(keyword => (
                        <span key={keyword} className="document-viewer__keyword">
                          {keyword}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Subjects */}
                {(metadata || document.metadata).subject.length > 0 && (
                  <div className="document-viewer__subjects">
                    <strong>Subjects:</strong>
                    <div className="document-viewer__subject-list">
                      {(metadata || document.metadata).subject.map(subject => (
                        <span key={subject} className="document-viewer__subject">
                          {subject}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Quality Score */}
            {showQualityScore && (qualityScore || document.metadata?.qualityScore) && (
              <div className="document-viewer__quality">
                <h3>Quality Assessment</h3>
                <div className="document-viewer__quality-overall">
                  <div className="document-viewer__quality-score">
                    <div 
                      className="document-viewer__quality-bar"
                      style={{ 
                        width: `${((qualityScore || document.metadata.qualityScore).overall * 100)}%`,
                        backgroundColor: getQualityColor((qualityScore || document.metadata.qualityScore).overall)
                      }}
                    ></div>
                  </div>
                  <span>{Math.round((qualityScore || document.metadata.qualityScore).overall * 100)}%</span>
                </div>
                
                <div className="document-viewer__quality-details">
                  <div className="document-viewer__quality-metric">
                    <span>Completeness:</span>
                    <span>{Math.round((qualityScore || document.metadata.qualityScore).completeness * 100)}%</span>
                  </div>
                  <div className="document-viewer__quality-metric">
                    <span>Accuracy:</span>
                    <span>{Math.round((qualityScore || document.metadata.qualityScore).accuracy * 100)}%</span>
                  </div>
                  <div className="document-viewer__quality-metric">
                    <span>Consistency:</span>
                    <span>{Math.round((qualityScore || document.metadata.qualityScore).consistency * 100)}%</span>
                  </div>
                  <div className="document-viewer__quality-metric">
                    <span>Timeliness:</span>
                    <span>{Math.round((qualityScore || document.metadata.qualityScore).timeliness * 100)}%</span>
                  </div>
                </div>

                {(qualityScore || document.metadata.qualityScore).details.warnings.length > 0 && (
                  <div className="document-viewer__quality-warnings">
                    <strong>Warnings:</strong>
                    <ul>
                      {(qualityScore || document.metadata.qualityScore).details.warnings.map((warning, index) => (
                        <li key={index}>{warning}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}

            {/* Table of Contents */}
            {showToc && document.sections.length > 0 && (
              <div className="document-viewer__toc">
                <h3>Table of Contents</h3>
                <nav className="document-viewer__toc-nav">
                  {document.sections.map(section => (
                    <button
                      key={section.id}
                      onClick={() => handleSectionClick(section.id)}
                      className={`document-viewer__toc-item level-${section.level} ${
                        activeSection === section.id ? 'active' : ''
                      }`}
                    >
                      {section.title}
                    </button>
                  ))}
                </nav>
              </div>
            )}
          </div>
        )}

        {/* Main content area */}
        <div className="document-viewer__content">
          <div className="document-viewer__document">
            {/* Document title */}
            <header className="document-viewer__document-header">
              <h1 className="document-viewer__document-title">{document.title}</h1>
              <div className="document-viewer__document-urn">
                <strong>URN:</strong> {document.urn}
              </div>
            </header>

            {/* Document content based on view mode */}
            <main className="document-viewer__document-body">
              {viewMode === 'formatted' && (
                <div className="document-viewer__formatted-content">
                  {document.sections.length > 0 ? (
                    document.sections.map(section => (
                      <section
                        key={section.id}
                        id={`section-${section.id}`}
                        className={`document-viewer__section level-${section.level}`}
                      >
                        <h2 className={`document-viewer__section-title h${Math.min(section.level + 1, 6)}`}>
                          {section.title}
                        </h2>
                        <div
                          className="document-viewer__section-content"
                          dangerouslySetInnerHTML={{ __html: section.content }}
                        />
                        {section.references.length > 0 && (
                          <div className="document-viewer__section-references">
                            <h4>References:</h4>
                            <ul>
                              {section.references.map((ref, index) => (
                                <li key={index}>{ref}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </section>
                    ))
                  ) : (
                    <div
                      className="document-viewer__full-content"
                      dangerouslySetInnerHTML={{ __html: document.content }}
                    />
                  )}
                </div>
              )}

              {viewMode === 'html' && document.htmlContent && (
                <div className="document-viewer__html-content">
                  <pre>
                    <code>{document.htmlContent}</code>
                  </pre>
                </div>
              )}

              {viewMode === 'plain' && (
                <div className="document-viewer__plain-content">
                  <pre>{document.plainText}</pre>
                </div>
              )}
            </main>

            {/* Document attachments */}
            {document.attachments.length > 0 && (
              <aside className="document-viewer__attachments">
                <h3>Attachments</h3>
                <div className="document-viewer__attachment-list">
                  {document.attachments.map(attachment => (
                    <div key={attachment.id} className="document-viewer__attachment">
                      <div className="document-viewer__attachment-info">
                        <strong>{attachment.name}</strong>
                        <span className="document-viewer__attachment-type">
                          {attachment.type} ({(attachment.size / 1024).toFixed(1)}KB)
                        </span>
                        {attachment.description && (
                          <p className="document-viewer__attachment-description">
                            {attachment.description}
                          </p>
                        )}
                      </div>
                      <a
                        href={attachment.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="document-viewer__attachment-link"
                      >
                        Download
                      </a>
                    </div>
                  ))}
                </div>
              </aside>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};