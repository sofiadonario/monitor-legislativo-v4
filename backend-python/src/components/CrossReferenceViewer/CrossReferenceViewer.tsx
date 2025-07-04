/**
 * CrossReferenceViewer Component
 * Visualize document relationships and cross-references
 */
import React, { useState, useEffect } from 'react';
import { CrossReference, CrossReferenceType, SimilarDocument } from '../../types';
import { documentAnalysisService } from '../../services/documentAnalysisService';
import './CrossReferenceViewer.css';

interface CrossReferenceViewerProps {
  urn: string;
  onDocumentSelect?: (urn: string) => void;
  showSimilarDocuments?: boolean;
  maxReferences?: number;
}

export const CrossReferenceViewer: React.FC<CrossReferenceViewerProps> = ({
  urn,
  onDocumentSelect,
  showSimilarDocuments = true,
  maxReferences = 50
}) => {
  const [crossReferences, setCrossReferences] = useState<CrossReference[]>([]);
  const [similarDocuments, setSimilarDocuments] = useState<SimilarDocument[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'references' | 'similar'>('references');
  const [filterType, setFilterType] = useState<CrossReferenceType | 'all'>('all');
  const [sortBy, setSortBy] = useState<'strength' | 'type' | 'alphabetical'>('strength');
  const [viewMode, setViewMode] = useState<'list' | 'network'>('list');

  useEffect(() => {
    if (urn) {
      loadRelationships();
    }
  }, [urn]);

  const loadRelationships = async () => {
    try {
      setLoading(true);
      setError(null);

      const [referencesResult, similarResult] = await Promise.allSettled([
        documentAnalysisService.getCrossReferences(urn),
        showSimilarDocuments ? documentAnalysisService.getSimilarDocuments(urn, 20) : Promise.resolve([])
      ]);

      if (referencesResult.status === 'fulfilled') {
        setCrossReferences(referencesResult.value.slice(0, maxReferences));
      } else {
        console.warn('Failed to load cross references:', referencesResult.reason);
        setCrossReferences([]);
      }

      if (similarResult.status === 'fulfilled') {
        setSimilarDocuments(similarResult.value);
      } else {
        console.warn('Failed to load similar documents:', similarResult.reason);
        setSimilarDocuments([]);
      }

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load relationships');
    } finally {
      setLoading(false);
    }
  };

  const getFilteredReferences = () => {
    let filtered = crossReferences;
    
    if (filterType !== 'all') {
      filtered = filtered.filter(ref => ref.type === filterType);
    }
    
    return filtered.sort((a, b) => {
      switch (sortBy) {
        case 'strength':
          return b.strength - a.strength;
        case 'type':
          return a.type.localeCompare(b.type);
        case 'alphabetical':
          return a.description.localeCompare(b.description);
        default:
          return 0;
      }
    });
  };

  const getReferenceTypeColor = (type: CrossReferenceType) => {
    const colors = {
      citation: '#4299e1',
      amendment: '#ed8936',
      repeal: '#e53e3e',
      reference: '#38a169',
      implementation: '#805ad5',
      supersedes: '#d69e2e',
      related: '#718096'
    };
    return colors[type] || '#718096';
  };

  const getReferenceTypeIcon = (type: CrossReferenceType) => {
    const icons = {
      citation: '📋',
      amendment: '✏️',
      repeal: '🚫',
      reference: '🔗',
      implementation: '⚙️',
      supersedes: '↗️',
      related: '🔄'
    };
    return icons[type] || '🔗';
  };

  const getStrengthLabel = (strength: number) => {
    if (strength >= 0.8) return 'Strong';
    if (strength >= 0.6) return 'Medium';
    if (strength >= 0.4) return 'Weak';
    return 'Very Weak';
  };

  const getSimilarityColor = (similarity: number) => {
    if (similarity >= 0.8) return '#10b981';
    if (similarity >= 0.6) return '#f59e0b';
    if (similarity >= 0.4) return '#ef4444';
    return '#6b7280';
  };

  const handleDocumentClick = (documentUrn: string) => {
    if (onDocumentSelect) {
      onDocumentSelect(documentUrn);
    }
  };

  if (loading) {
    return (
      <div className="cross-reference-viewer__loading">
        <div className="cross-reference-viewer__spinner"></div>
        <p>Loading document relationships...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="cross-reference-viewer__error">
        <h3>Error Loading Relationships</h3>
        <p>{error}</p>
        <button onClick={loadRelationships} className="cross-reference-viewer__retry-btn">
          Try Again
        </button>
      </div>
    );
  }

  const filteredReferences = getFilteredReferences();

  return (
    <div className="cross-reference-viewer">
      <div className="cross-reference-viewer__header">
        <h3>Document Relationships</h3>
        <div className="cross-reference-viewer__tabs">
          <button
            onClick={() => setActiveTab('references')}
            className={`cross-reference-viewer__tab ${activeTab === 'references' ? 'active' : ''}`}
          >
            Cross References ({crossReferences.length})
          </button>
          {showSimilarDocuments && (
            <button
              onClick={() => setActiveTab('similar')}
              className={`cross-reference-viewer__tab ${activeTab === 'similar' ? 'active' : ''}`}
            >
              Similar Documents ({similarDocuments.length})
            </button>
          )}
        </div>
      </div>

      <div className="cross-reference-viewer__controls">
        {activeTab === 'references' && (
          <>
            <div className="cross-reference-viewer__filter-group">
              <label>Filter by Type:</label>
              <select
                value={filterType}
                onChange={(e) => setFilterType(e.target.value as CrossReferenceType | 'all')}
                className="cross-reference-viewer__select"
              >
                <option value="all">All Types</option>
                <option value="citation">Citations</option>
                <option value="amendment">Amendments</option>
                <option value="repeal">Repeals</option>
                <option value="reference">References</option>
                <option value="implementation">Implementations</option>
                <option value="supersedes">Supersedes</option>
                <option value="related">Related</option>
              </select>
            </div>

            <div className="cross-reference-viewer__filter-group">
              <label>Sort by:</label>
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as any)}
                className="cross-reference-viewer__select"
              >
                <option value="strength">Relationship Strength</option>
                <option value="type">Reference Type</option>
                <option value="alphabetical">Alphabetical</option>
              </select>
            </div>

            <div className="cross-reference-viewer__view-toggle">
              <button
                onClick={() => setViewMode('list')}
                className={`cross-reference-viewer__view-btn ${viewMode === 'list' ? 'active' : ''}`}
              >
                List View
              </button>
              <button
                onClick={() => setViewMode('network')}
                className={`cross-reference-viewer__view-btn ${viewMode === 'network' ? 'active' : ''}`}
              >
                Network View
              </button>
            </div>
          </>
        )}
      </div>

      <div className="cross-reference-viewer__content">
        {activeTab === 'references' && (
          <div className="cross-reference-viewer__references">
            {viewMode === 'list' ? (
              <div className="cross-reference-viewer__list">
                {filteredReferences.length > 0 ? (
                  filteredReferences.map(reference => (
                    <div
                      key={reference.id}
                      className="cross-reference-viewer__reference-item"
                    >
                      <div className="cross-reference-viewer__reference-header">
                        <div className="cross-reference-viewer__reference-type">
                          <span
                            className="cross-reference-viewer__type-icon"
                            style={{ color: getReferenceTypeColor(reference.type) }}
                          >
                            {getReferenceTypeIcon(reference.type)}
                          </span>
                          <span
                            className="cross-reference-viewer__type-label"
                            style={{ color: getReferenceTypeColor(reference.type) }}
                          >
                            {reference.type.replace('_', ' ').toUpperCase()}
                          </span>
                        </div>
                        <div className="cross-reference-viewer__strength">
                          <span className="cross-reference-viewer__strength-label">
                            {getStrengthLabel(reference.strength)}
                          </span>
                          <div className="cross-reference-viewer__strength-bar">
                            <div
                              className="cross-reference-viewer__strength-fill"
                              style={{
                                width: `${reference.strength * 100}%`,
                                backgroundColor: getReferenceTypeColor(reference.type)
                              }}
                            ></div>
                          </div>
                        </div>
                      </div>

                      <div className="cross-reference-viewer__reference-content">
                        <p className="cross-reference-viewer__description">
                          {reference.description}
                        </p>
                        
                        {reference.context && (
                          <div className="cross-reference-viewer__context">
                            <strong>Context:</strong> {reference.context}
                          </div>
                        )}

                        <div className="cross-reference-viewer__reference-urns">
                          <div className="cross-reference-viewer__urn-item">
                            <strong>Source:</strong>
                            <button
                              onClick={() => handleDocumentClick(reference.sourceUrn)}
                              className="cross-reference-viewer__urn-link"
                              title={reference.sourceUrn}
                            >
                              {reference.sourceUrn.split(':').pop() || reference.sourceUrn}
                            </button>
                          </div>
                          <div className="cross-reference-viewer__urn-item">
                            <strong>Target:</strong>
                            <button
                              onClick={() => handleDocumentClick(reference.targetUrn)}
                              className="cross-reference-viewer__urn-link"
                              title={reference.targetUrn}
                            >
                              {reference.targetUrn.split(':').pop() || reference.targetUrn}
                            </button>
                          </div>
                        </div>

                        {reference.bidirectional && (
                          <div className="cross-reference-viewer__bidirectional">
                            ↔️ Bidirectional relationship
                          </div>
                        )}
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="cross-reference-viewer__empty">
                    <h4>No Cross References Found</h4>
                    <p>
                      {filterType === 'all' 
                        ? 'This document has no cross-references to other documents.'
                        : `No ${filterType} relationships found. Try a different filter.`
                      }
                    </p>
                  </div>
                )}
              </div>
            ) : (
              <div className="cross-reference-viewer__network">
                <div className="cross-reference-viewer__network-placeholder">
                  <h4>Network Visualization</h4>
                  <p>Interactive network diagram will be implemented here.</p>
                  <p>This will show relationships as a force-directed graph.</p>
                  <div className="cross-reference-viewer__network-legend">
                    <h5>Legend:</h5>
                    {['citation', 'amendment', 'repeal', 'reference', 'implementation', 'supersedes', 'related'].map(type => (
                      <div key={type} className="cross-reference-viewer__legend-item">
                        <span
                          className="cross-reference-viewer__legend-color"
                          style={{ backgroundColor: getReferenceTypeColor(type as CrossReferenceType) }}
                        ></span>
                        {type.charAt(0).toUpperCase() + type.slice(1)}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'similar' && (
          <div className="cross-reference-viewer__similar">
            {similarDocuments.length > 0 ? (
              <div className="cross-reference-viewer__similar-list">
                {similarDocuments.map(similar => (
                  <div
                    key={similar.urn}
                    className="cross-reference-viewer__similar-item"
                  >
                    <div className="cross-reference-viewer__similar-header">
                      <button
                        onClick={() => handleDocumentClick(similar.urn)}
                        className="cross-reference-viewer__similar-title"
                      >
                        {similar.title}
                      </button>
                      <div className="cross-reference-viewer__similarity-score">
                        <span
                          className="cross-reference-viewer__similarity-percentage"
                          style={{ color: getSimilarityColor(similar.similarity) }}
                        >
                          {Math.round(similar.similarity * 100)}%
                        </span>
                        <div className="cross-reference-viewer__similarity-bar">
                          <div
                            className="cross-reference-viewer__similarity-fill"
                            style={{
                              width: `${similar.similarity * 100}%`,
                              backgroundColor: getSimilarityColor(similar.similarity)
                            }}
                          ></div>
                        </div>
                      </div>
                    </div>

                    <div className="cross-reference-viewer__similar-content">
                      <div className="cross-reference-viewer__match-type">
                        <strong>Match Type:</strong> {similar.matchType}
                      </div>
                      
                      {similar.explanation && (
                        <p className="cross-reference-viewer__explanation">
                          {similar.explanation}
                        </p>
                      )}

                      {similar.commonElements.length > 0 && (
                        <div className="cross-reference-viewer__common-elements">
                          <strong>Common Elements:</strong>
                          <div className="cross-reference-viewer__elements-list">
                            {similar.commonElements.slice(0, 5).map((element, index) => (
                              <span key={index} className="cross-reference-viewer__element">
                                {element}
                              </span>
                            ))}
                            {similar.commonElements.length > 5 && (
                              <span className="cross-reference-viewer__element-more">
                                +{similar.commonElements.length - 5} more
                              </span>
                            )}
                          </div>
                        </div>
                      )}

                      <div className="cross-reference-viewer__similar-urn">
                        <strong>URN:</strong>
                        <code>{similar.urn}</code>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="cross-reference-viewer__empty">
                <h4>No Similar Documents Found</h4>
                <p>No documents with similar content or structure were found.</p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};