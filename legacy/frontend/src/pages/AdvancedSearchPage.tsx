/**
 * AdvancedSearchPage Component
 * Comprehensive academic search interface with vocabulary integration
 */
import React, { useState, useEffect } from 'react';
import { SearchFilters, LegislativeDocument, Concept } from '../types';
import { VocabularyBrowser } from '../components/VocabularyBrowser';
import { AdvancedSearch } from '../components/AdvancedSearch';
import { SearchSuggestions } from '../components/SearchSuggestions';
import { LoadingSpinner } from '../components/LoadingSpinner';
import { ErrorBoundary } from '../components/ErrorBoundary';
import './AdvancedSearchPage.css';

// Import search service (we'll use the existing LexML search)
import { apiClient } from '../services/apiClient';

const AdvancedSearchPage: React.FC = () => {
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<LegislativeDocument[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedConcept, setSelectedConcept] = useState<Concept | null>(null);
  const [showVocabularyPanel, setShowVocabularyPanel] = useState(true);
  const [currentFilters, setCurrentFilters] = useState<SearchFilters>({
    searchTerm: '',
    documentTypes: [],
    states: [],
    municipalities: [],
    chambers: [],
    keywords: [],
    dateFrom: undefined,
    dateTo: undefined
  });
  const [resultStats, setResultStats] = useState({
    total: 0,
    searchTime: 0,
    queryUsed: ''
  });

  useEffect(() => {
    // Update current filters when search query changes
    setCurrentFilters(prev => ({ ...prev, searchTerm: searchQuery }));
  }, [searchQuery]);

  const performSearch = async (filters: SearchFilters) => {
    try {
      setLoading(true);
      setError(null);
      
      const startTime = Date.now();
      
      // Use the main search term for LexML search
      const searchTerm = filters.searchTerm || searchQuery;
      
      if (!searchTerm.trim()) {
        setError('Please enter a search term');
        return;
      }

      // Prepare search parameters
      const searchParams = new URLSearchParams({
        q: searchTerm,
        limit: '50'
      });

      // Add filters if specified
      if (filters.documentTypes.length > 0) {
        searchParams.append('tipos', filters.documentTypes.join(','));
      }
      
      if (filters.states.length > 0) {
        searchParams.append('estados', filters.states.join(','));
      }

      // Perform the search using the LexML endpoint
      const response = await apiClient.get(`/lexml/search?${searchParams.toString()}`);
      
      const searchTime = Date.now() - startTime;
      
      if (response.data && response.data.documents) {
        setSearchResults(response.data.documents);
        setResultStats({
          total: response.data.documents.length,
          searchTime,
          queryUsed: searchTerm
        });
      } else {
        setSearchResults([]);
        setResultStats({
          total: 0,
          searchTime,
          queryUsed: searchTerm
        });
      }

      // Update current filters
      setCurrentFilters(filters);
      
    } catch (err) {
      console.error('Search error:', err);
      setError('Search failed. Please try again.');
      setSearchResults([]);
    } finally {
      setLoading(false);
    }
  };

  const performCQLSearch = async (cqlQuery: string) => {
    try {
      setLoading(true);
      setError(null);
      
      const startTime = Date.now();
      
      // For CQL search, we'll convert it to a basic search for now
      // In a real implementation, this would be sent as a CQL query to a proper endpoint
      const basicQuery = cqlQuery.replace(/dc\.\w+\s*=\s*/g, '').replace(/"/g, '');
      
      const searchParams = new URLSearchParams({
        q: basicQuery,
        limit: '50',
        cql: 'true' // Flag to indicate this was a CQL query
      });

      const response = await apiClient.get(`/lexml/search?${searchParams.toString()}`);
      const searchTime = Date.now() - startTime;
      
      if (response.data && response.data.documents) {
        setSearchResults(response.data.documents);
        setResultStats({
          total: response.data.documents.length,
          searchTime,
          queryUsed: cqlQuery
        });
      } else {
        setSearchResults([]);
        setResultStats({
          total: 0,
          searchTime,
          queryUsed: cqlQuery
        });
      }
      
    } catch (err) {
      console.error('CQL Search error:', err);
      setError('CQL search failed. Please check your query syntax.');
      setSearchResults([]);
    } finally {
      setLoading(false);
    }
  };

  const handleConceptSelect = (concept: Concept) => {
    setSelectedConcept(concept);
    const conceptLabel = concept.prefLabel.pt || concept.prefLabel.en || concept.uri;
    setSearchQuery(conceptLabel);
  };

  const handleSuggestionSearch = (query: string) => {
    setSearchQuery(query);
    const filters: SearchFilters = {
      ...currentFilters,
      searchTerm: query
    };
    performSearch(filters);
  };

  const toggleVocabularyPanel = () => {
    setShowVocabularyPanel(!showVocabularyPanel);
  };

  return (
    <ErrorBoundary>
      <div className="advanced-search-page">
        <div className="advanced-search-page__header">
          <div className="advanced-search-page__title-section">
            <h1>Advanced Legislative Search</h1>
            <p>Comprehensive research interface with vocabulary-aware search capabilities</p>
          </div>
          
          <div className="advanced-search-page__controls">
            <button
              onClick={toggleVocabularyPanel}
              className={`advanced-search-page__vocab-toggle ${showVocabularyPanel ? 'active' : ''}`}
            >
              {showVocabularyPanel ? 'Hide' : 'Show'} Vocabulary
            </button>
          </div>
        </div>

        <div className="advanced-search-page__content">
          {/* Main Search Interface */}
          <div className="advanced-search-page__search-section">
            <div className="advanced-search-page__search-input">
              <SearchSuggestions
                query={searchQuery}
                onQueryChange={setSearchQuery}
                onSearch={handleSuggestionSearch}
                placeholder="Search legislative documents with intelligent suggestions..."
                showExpansion={true}
                showHistory={true}
              />
            </div>

            <div className="advanced-search-page__advanced-form">
              <AdvancedSearch
                onSearch={performSearch}
                onCQLSearch={performCQLSearch}
                initialFilters={currentFilters}
              />
            </div>
          </div>

          {/* Layout Container */}
          <div className={`advanced-search-page__layout ${showVocabularyPanel ? 'with-vocabulary' : 'full-width'}`}>
            
            {/* Vocabulary Panel */}
            {showVocabularyPanel && (
              <div className="advanced-search-page__vocabulary-panel">
                <VocabularyBrowser
                  onConceptSelect={handleConceptSelect}
                  selectedConceptUri={selectedConcept?.uri}
                />
              </div>
            )}

            {/* Results Panel */}
            <div className="advanced-search-page__results-panel">
              {/* Search Status */}
              {(loading || searchResults.length > 0 || error) && (
                <div className="advanced-search-page__status">
                  {loading && (
                    <div className="advanced-search-page__loading">
                      <LoadingSpinner size="medium" />
                      <span>Searching legislative documents...</span>
                    </div>
                  )}
                  
                  {!loading && !error && searchResults.length > 0 && (
                    <div className="advanced-search-page__stats">
                      <span className="advanced-search-page__result-count">
                        Found {resultStats.total} documents
                      </span>
                      <span className="advanced-search-page__search-time">
                        in {resultStats.searchTime}ms
                      </span>
                      <span className="advanced-search-page__query">
                        for "{resultStats.queryUsed}"
                      </span>
                    </div>
                  )}
                  
                  {error && (
                    <div className="advanced-search-page__error">
                      <span className="advanced-search-page__error-icon">⚠</span>
                      {error}
                    </div>
                  )}
                </div>
              )}

              {/* Selected Concept Info */}
              {selectedConcept && (
                <div className="advanced-search-page__concept-info">
                  <h3>Selected Concept</h3>
                  <div className="advanced-search-page__concept-details">
                    <strong>{selectedConcept.prefLabel.pt || selectedConcept.prefLabel.en}</strong>
                    {selectedConcept.definition.pt && (
                      <p>{selectedConcept.definition.pt}</p>
                    )}
                    <div className="advanced-search-page__concept-meta">
                      <span>Scheme: {selectedConcept.conceptScheme}</span>
                      {selectedConcept.notation && (
                        <span>Code: {selectedConcept.notation}</span>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* Search Results */}
              {!loading && !error && searchResults.length > 0 && (
                <div className="advanced-search-page__results">
                  <h3>Search Results</h3>
                  <div className="advanced-search-page__results-list">
                    {searchResults.map((document, index) => (
                      <div key={document.id || index} className="advanced-search-page__result-item">
                        <div className="advanced-search-page__result-header">
                          <h4 className="advanced-search-page__result-title">
                            {document.title}
                          </h4>
                          <div className="advanced-search-page__result-meta">
                            <span className="advanced-search-page__result-type">
                              {document.type}
                            </span>
                            <span className="advanced-search-page__result-date">
                              {new Date(document.date).toLocaleDateString()}
                            </span>
                          </div>
                        </div>
                        
                        <div className="advanced-search-page__result-content">
                          <p className="advanced-search-page__result-summary">
                            {document.summary}
                          </p>
                          
                          {document.keywords && document.keywords.length > 0 && (
                            <div className="advanced-search-page__result-keywords">
                              {document.keywords.slice(0, 5).map((keyword, idx) => (
                                <span key={idx} className="advanced-search-page__keyword">
                                  {keyword}
                                </span>
                              ))}
                            </div>
                          )}
                          
                          <div className="advanced-search-page__result-actions">
                            <a 
                              href={document.url} 
                              target="_blank" 
                              rel="noopener noreferrer"
                              className="advanced-search-page__result-link"
                            >
                              View Document
                            </a>
                            {document.citation && (
                              <button className="advanced-search-page__citation-btn">
                                Copy Citation
                              </button>
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* No Results State */}
              {!loading && !error && searchResults.length === 0 && resultStats.queryUsed && (
                <div className="advanced-search-page__no-results">
                  <h3>No Documents Found</h3>
                  <p>No legislative documents match your search criteria.</p>
                  <div className="advanced-search-page__suggestions">
                    <h4>Try:</h4>
                    <ul>
                      <li>Using different keywords or synonyms</li>
                      <li>Browsing the vocabulary for related concepts</li>
                      <li>Expanding your search with broader terms</li>
                      <li>Checking your spelling</li>
                      <li>Using the search templates for common queries</li>
                    </ul>
                  </div>
                </div>
              )}

              {/* Initial State */}
              {!loading && !error && searchResults.length === 0 && !resultStats.queryUsed && (
                <div className="advanced-search-page__initial-state">
                  <h3>Welcome to Advanced Legislative Search</h3>
                  <p>Use the sophisticated search tools above to find legislative documents:</p>
                  <div className="advanced-search-page__features">
                    <div className="advanced-search-page__feature">
                      <h4>🔍 Intelligent Search</h4>
                      <p>Get smart suggestions and auto-completion as you type</p>
                    </div>
                    <div className="advanced-search-page__feature">
                      <h4>📚 Vocabulary Browser</h4>
                      <p>Explore controlled vocabularies and concept relationships</p>
                    </div>
                    <div className="advanced-search-page__feature">
                      <h4>⚙️ Advanced Filters</h4>
                      <p>Use document types, geographic filters, and date ranges</p>
                    </div>
                    <div className="advanced-search-page__feature">
                      <h4>💾 Search Templates</h4>
                      <p>Start with pre-configured searches for common scenarios</p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </ErrorBoundary>
  );
};

export default AdvancedSearchPage;