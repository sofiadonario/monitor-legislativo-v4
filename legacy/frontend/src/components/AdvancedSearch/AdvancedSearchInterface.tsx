/**
 * AdvancedSearchInterface Component
 * Sophisticated search interface with semantic queries, filters, and real-time suggestions
 */
import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { DocumentType } from '../../types';
import { advancedSearchService, AdvancedSearchParams, SearchResponse, SemanticQuery } from '../../services/advancedSearchService';

interface AdvancedSearchInterfaceProps {
  onSearchResults?: (response: SearchResponse) => void;
  onQueryChange?: (query: string) => void;
  initialQuery?: string;
  enableSemanticExpansion?: boolean;
  transportFocus?: boolean;
}

export const AdvancedSearchInterface: React.FC<AdvancedSearchInterfaceProps> = ({
  onSearchResults,
  onQueryChange,
  initialQuery = '',
  enableSemanticExpansion = true,
  transportFocus = true
}) => {
  // Search state
  const [query, setQuery] = useState(initialQuery);
  const [isSearching, setIsSearching] = useState(false);
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [semanticQuery, setSemanticQuery] = useState<SemanticQuery>();
  
  // Filter state
  const [showFilters, setShowFilters] = useState(false);
  const [selectedDocumentTypes, setSelectedDocumentTypes] = useState<DocumentType[]>([]);
  const [dateRange, setDateRange] = useState<{ start: string; end: string }>({
    start: '',
    end: ''
  });
  const [selectedStates, setSelectedStates] = useState<string[]>([]);
  const [selectedAuthors, setSelectedAuthors] = useState<string[]>([]);
  const [urgencyLevel, setUrgencyLevel] = useState<'low' | 'medium' | 'high' | 'urgent' | ''>('');
  
  // Search configuration
  const [searchMode, setSearchMode] = useState<'exact' | 'fuzzy' | 'semantic' | 'hybrid'>('hybrid');
  const [sortBy, setSortBy] = useState<'relevance' | 'date' | 'popularity' | 'authority'>('relevance');
  const [resultLimit, setResultLimit] = useState(20);

  // Available options
  const documentTypes: DocumentType[] = ['lei', 'decreto', 'portaria', 'resolucao', 'instrucao_normativa', 'projeto_lei', 'medida_provisoria'];
  const brazilianStates = ['AC', 'AL', 'AP', 'AM', 'BA', 'CE', 'DF', 'ES', 'GO', 'MA', 'MT', 'MS', 'MG', 'PA', 'PB', 'PR', 'PE', 'PI', 'RJ', 'RN', 'RS', 'RO', 'RR', 'SC', 'SP', 'SE', 'TO'];

  // Query analysis
  const queryAnalysis = useMemo(() => {
    if (!query.trim()) return null;
    return advancedSearchService.analyzeQuery(query);
  }, [query]);

  // Handle query changes with debounced suggestions
  useEffect(() => {
    if (onQueryChange) {
      onQueryChange(query);
    }

    const timer = setTimeout(async () => {
      if (query.length > 1) {
        const newSuggestions = await advancedSearchService.getSearchSuggestions(query, 6);
        setSuggestions(newSuggestions);
      } else {
        setSuggestions([]);
      }
    }, 300);

    return () => clearTimeout(timer);
  }, [query, onQueryChange]);

  // Build semantic query when enabled
  useEffect(() => {
    if (enableSemanticExpansion && query.length > 2) {
      const timer = setTimeout(async () => {
        const semantic = await advancedSearchService.buildSemanticQuery(query, transportFocus);
        setSemanticQuery(semantic);
      }, 500);

      return () => clearTimeout(timer);
    }
  }, [query, enableSemanticExpansion, transportFocus]);

  // Handle search execution
  const handleSearch = useCallback(async () => {
    if (!query.trim() || isSearching) return;

    setIsSearching(true);
    setShowSuggestions(false);

    try {
      const searchParams: AdvancedSearchParams = {
        query,
        enableSemanticExpansion,
        transportFocus,
        filters: {
          documentTypes: selectedDocumentTypes.length > 0 ? selectedDocumentTypes : undefined,
          dateRange: dateRange.start && dateRange.end ? {
            start: new Date(dateRange.start),
            end: new Date(dateRange.end)
          } : undefined,
          states: selectedStates.length > 0 ? selectedStates : undefined,
          authors: selectedAuthors.length > 0 ? selectedAuthors : undefined,
          urgencyLevel: urgencyLevel || undefined
        },
        searchMode,
        resultLimit,
        sortBy,
        includeRelated: true
      };

      const response = await advancedSearchService.search(searchParams);
      
      if (onSearchResults) {
        onSearchResults(response);
      }

    } catch (error) {
      console.error('Search failed:', error);
    } finally {
      setIsSearching(false);
    }
  }, [
    query, enableSemanticExpansion, transportFocus, selectedDocumentTypes, dateRange,
    selectedStates, selectedAuthors, urgencyLevel, searchMode, resultLimit, sortBy,
    isSearching, onSearchResults
  ]);

  // Handle suggestion selection
  const handleSuggestionClick = (suggestion: string) => {
    setQuery(suggestion);
    setShowSuggestions(false);
  };

  // Handle Enter key
  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleSearch();
    } else if (e.key === 'Escape') {
      setShowSuggestions(false);
    }
  };

  // Clear all filters
  const clearFilters = () => {
    setSelectedDocumentTypes([]);
    setDateRange({ start: '', end: '' });
    setSelectedStates([]);
    setSelectedAuthors([]);
    setUrgencyLevel('');
  };

  return (
    <div className="advanced-search-interface">
      {/* Main Search Input */}
      <div className="search-input-container">
        <div className="search-input-wrapper">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyPress}
            onFocus={() => setShowSuggestions(true)}
            placeholder="Search Brazilian transport legislation..."
            className="search-input"
            disabled={isSearching}
          />
          
          <button
            onClick={handleSearch}
            disabled={!query.trim() || isSearching}
            className="search-button"
          >
            {isSearching ? '🔍' : '🔎'}
          </button>

          <button
            onClick={() => setShowFilters(!showFilters)}
            className={`filters-toggle ${showFilters ? 'active' : ''}`}
          >
            ⚙️ Filters
          </button>
        </div>

        {/* Search Suggestions */}
        {showSuggestions && suggestions.length > 0 && (
          <div className="search-suggestions">
            {suggestions.map((suggestion, index) => (
              <div
                key={index}
                className="suggestion-item"
                onClick={() => handleSuggestionClick(suggestion)}
              >
                <span className="suggestion-icon">💡</span>
                <span className="suggestion-text">{suggestion}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Semantic Query Preview */}
      {enableSemanticExpansion && semanticQuery && query.length > 2 && (
        <div className="semantic-preview">
          <div className="semantic-header">
            <span className="semantic-icon">🧠</span>
            <span className="semantic-title">Semantic Expansion</span>
            <span className="semantic-confidence">
              {Math.round(semanticQuery.confidence * 100)}% confidence
            </span>
          </div>
          
          {semanticQuery.expandedTerms.length > 1 && (
            <div className="semantic-terms">
              <span className="terms-label">Expanded terms:</span>
              <div className="terms-list">
                {semanticQuery.expandedTerms.slice(1, 6).map((term, index) => (
                  <span key={index} className="semantic-term">{term}</span>
                ))}
                {semanticQuery.expandedTerms.length > 6 && (
                  <span className="terms-more">+{semanticQuery.expandedTerms.length - 6} more</span>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Query Analysis */}
      {queryAnalysis && (
        <div className="query-analysis">
          <div className="analysis-item">
            <span className="analysis-label">Complexity:</span>
            <span className={`complexity-badge ${queryAnalysis.complexity}`}>
              {queryAnalysis.complexity}
            </span>
          </div>
          
          <div className="analysis-item">
            <span className="analysis-label">Transport relevance:</span>
            <span className="relevance-score">
              {Math.round(queryAnalysis.transportRelevance * 100)}%
            </span>
          </div>

          {queryAnalysis.suggestions.length > 0 && (
            <div className="analysis-suggestions">
              <span className="suggestions-label">💡 Suggestions:</span>
              <ul>
                {queryAnalysis.suggestions.map((suggestion, index) => (
                  <li key={index}>{suggestion}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Advanced Filters */}
      {showFilters && (
        <div className="advanced-filters">
          <div className="filters-header">
            <h3>Advanced Filters</h3>
            <button onClick={clearFilters} className="clear-filters-btn">
              Clear All
            </button>
          </div>

          <div className="filters-grid">
            {/* Document Types */}
            <div className="filter-group">
              <label className="filter-label">Document Types</label>
              <div className="checkbox-grid">
                {documentTypes.map(type => (
                  <label key={type} className="checkbox-item">
                    <input
                      type="checkbox"
                      checked={selectedDocumentTypes.includes(type)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setSelectedDocumentTypes([...selectedDocumentTypes, type]);
                        } else {
                          setSelectedDocumentTypes(selectedDocumentTypes.filter(t => t !== type));
                        }
                      }}
                    />
                    {type.replace('_', ' ').toUpperCase()}
                  </label>
                ))}
              </div>
            </div>

            {/* Date Range */}
            <div className="filter-group">
              <label className="filter-label">Date Range</label>
              <div className="date-inputs">
                <input
                  type="date"
                  value={dateRange.start}
                  onChange={(e) => setDateRange({ ...dateRange, start: e.target.value })}
                  className="date-input"
                />
                <span className="date-separator">to</span>
                <input
                  type="date"
                  value={dateRange.end}
                  onChange={(e) => setDateRange({ ...dateRange, end: e.target.value })}
                  className="date-input"
                />
              </div>
            </div>

            {/* States */}
            <div className="filter-group">
              <label className="filter-label">States</label>
              <div className="multi-select">
                <select
                  multiple
                  value={selectedStates}
                  onChange={(e) => {
                    const values = Array.from(e.target.selectedOptions, option => option.value);
                    setSelectedStates(values);
                  }}
                  className="states-select"
                >
                  {brazilianStates.map(state => (
                    <option key={state} value={state}>{state}</option>
                  ))}
                </select>
              </div>
            </div>

            {/* Search Configuration */}
            <div className="filter-group">
              <label className="filter-label">Search Mode</label>
              <select
                value={searchMode}
                onChange={(e) => setSearchMode(e.target.value as any)}
                className="mode-select"
              >
                <option value="hybrid">Hybrid (Recommended)</option>
                <option value="semantic">Semantic Only</option>
                <option value="exact">Exact Match</option>
                <option value="fuzzy">Fuzzy Match</option>
              </select>
            </div>

            <div className="filter-group">
              <label className="filter-label">Sort By</label>
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as any)}
                className="sort-select"
              >
                <option value="relevance">Relevance</option>
                <option value="date">Date</option>
                <option value="popularity">Popularity</option>
                <option value="authority">Authority</option>
              </select>
            </div>

            <div className="filter-group">
              <label className="filter-label">Results per page</label>
              <select
                value={resultLimit}
                onChange={(e) => setResultLimit(parseInt(e.target.value))}
                className="limit-select"
              >
                <option value={10}>10</option>
                <option value={20}>20</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
              </select>
            </div>
          </div>
        </div>
      )}

      {/* Search Configuration */}
      <div className="search-config">
        <div className="config-toggles">
          <label className="toggle-item">
            <input
              type="checkbox"
              checked={enableSemanticExpansion}
              onChange={(e) => {
                // Note: This would need to be passed up to parent component
                console.log('Semantic expansion toggle:', e.target.checked);
              }}
            />
            Enable semantic expansion
          </label>
          
          <label className="toggle-item">
            <input
              type="checkbox"
              checked={transportFocus}
              onChange={(e) => {
                // Note: This would need to be passed up to parent component
                console.log('Transport focus toggle:', e.target.checked);
              }}
            />
            Focus on transport domain
          </label>
        </div>
      </div>
    </div>
  );
};

// CSS styles (to be injected)
const searchStyles = `
.advanced-search-interface {
  background: #ffffff;
  border-radius: 8px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  padding: 1.5rem;
  margin-bottom: 1rem;
}

.search-input-container {
  position: relative;
  margin-bottom: 1rem;
}

.search-input-wrapper {
  display: flex;
  gap: 0.5rem;
  align-items: center;
}

.search-input {
  flex: 1;
  padding: 0.75rem 1rem;
  border: 2px solid #e2e8f0;
  border-radius: 6px;
  font-size: 1rem;
  transition: border-color 0.2s;
}

.search-input:focus {
  outline: none;
  border-color: #4299e1;
}

.search-button,
.filters-toggle {
  padding: 0.75rem 1rem;
  border: none;
  border-radius: 6px;
  font-size: 1rem;
  cursor: pointer;
  transition: all 0.2s;
}

.search-button {
  background-color: #4299e1;
  color: #ffffff;
}

.search-button:hover:not(:disabled) {
  background-color: #3182ce;
}

.search-button:disabled {
  background-color: #a0aec0;
  cursor: not-allowed;
}

.filters-toggle {
  background-color: #f7fafc;
  color: #4a5568;
  border: 1px solid #e2e8f0;
}

.filters-toggle:hover {
  background-color: #edf2f7;
}

.filters-toggle.active {
  background-color: #ebf8ff;
  border-color: #4299e1;
  color: #2b6cb0;
}

.search-suggestions {
  position: absolute;
  top: 100%;
  left: 0;
  right: 0;
  background: #ffffff;
  border: 1px solid #e2e8f0;
  border-radius: 6px;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
  z-index: 10;
  max-height: 300px;
  overflow-y: auto;
}

.suggestion-item {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.75rem 1rem;
  cursor: pointer;
  transition: background-color 0.2s;
}

.suggestion-item:hover {
  background-color: #f7fafc;
}

.suggestion-icon {
  font-size: 0.875rem;
}

.suggestion-text {
  font-size: 0.875rem;
  color: #4a5568;
}

.semantic-preview {
  background: #f0fff4;
  border-left: 4px solid #48bb78;
  border-radius: 4px;
  padding: 1rem;
  margin-bottom: 1rem;
}

.semantic-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 0.75rem;
}

.semantic-icon {
  font-size: 1rem;
}

.semantic-title {
  font-weight: 600;
  color: #2d3748;
}

.semantic-confidence {
  margin-left: auto;
  font-size: 0.875rem;
  color: #48bb78;
  font-weight: 500;
}

.semantic-terms {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  flex-wrap: wrap;
}

.terms-label {
  font-size: 0.875rem;
  color: #4a5568;
  font-weight: 500;
}

.terms-list {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.semantic-term {
  background-color: #c6f6d5;
  color: #22543d;
  padding: 0.25rem 0.5rem;
  border-radius: 3px;
  font-size: 0.75rem;
  font-weight: 500;
}

.terms-more {
  color: #718096;
  font-size: 0.75rem;
  font-style: italic;
}

.query-analysis {
  background: #fffaf0;
  border-left: 4px solid #f6ad55;
  border-radius: 4px;
  padding: 1rem;
  margin-bottom: 1rem;
  display: flex;
  flex-wrap: wrap;
  gap: 1rem;
  align-items: center;
}

.analysis-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.analysis-label {
  font-size: 0.875rem;
  color: #4a5568;
  font-weight: 500;
}

.complexity-badge {
  padding: 0.25rem 0.5rem;
  border-radius: 3px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
}

.complexity-badge.simple {
  background-color: #c6f6d5;
  color: #22543d;
}

.complexity-badge.medium {
  background-color: #fef5e7;
  color: #744210;
}

.complexity-badge.complex {
  background-color: #fed7d7;
  color: #742a2a;
}

.relevance-score {
  font-weight: 600;
  color: #2d3748;
}

.analysis-suggestions {
  flex: 1 1 100%;
  margin-top: 0.5rem;
}

.suggestions-label {
  font-size: 0.875rem;
  color: #4a5568;
  font-weight: 500;
}

.analysis-suggestions ul {
  margin: 0.5rem 0 0 1rem;
  padding: 0;
}

.analysis-suggestions li {
  font-size: 0.875rem;
  color: #718096;
  margin-bottom: 0.25rem;
}

.advanced-filters {
  background: #f7fafc;
  border: 1px solid #e2e8f0;
  border-radius: 6px;
  padding: 1.5rem;
  margin-bottom: 1rem;
}

.filters-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1.5rem;
}

.filters-header h3 {
  color: #2d3748;
  font-size: 1.125rem;
  margin: 0;
}

.clear-filters-btn {
  background-color: #fed7d7;
  color: #742a2a;
  border: none;
  padding: 0.5rem 1rem;
  border-radius: 4px;
  font-size: 0.875rem;
  cursor: pointer;
  transition: background-color 0.2s;
}

.clear-filters-btn:hover {
  background-color: #feb2b2;
}

.filters-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 1.5rem;
}

.filter-group {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.filter-label {
  font-size: 0.875rem;
  font-weight: 600;
  color: #2d3748;
}

.checkbox-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 0.5rem;
}

.checkbox-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.875rem;
  color: #4a5568;
  cursor: pointer;
}

.date-inputs {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.date-input {
  flex: 1;
  padding: 0.5rem;
  border: 1px solid #e2e8f0;
  border-radius: 4px;
  font-size: 0.875rem;
}

.date-separator {
  font-size: 0.875rem;
  color: #718096;
}

.multi-select {
  position: relative;
}

.states-select {
  width: 100%;
  padding: 0.5rem;
  border: 1px solid #e2e8f0;
  border-radius: 4px;
  font-size: 0.875rem;
  min-height: 100px;
}

.mode-select,
.sort-select,
.limit-select {
  width: 100%;
  padding: 0.5rem;
  border: 1px solid #e2e8f0;
  border-radius: 4px;
  font-size: 0.875rem;
  background: #ffffff;
}

.search-config {
  border-top: 1px solid #e2e8f0;
  padding-top: 1rem;
}

.config-toggles {
  display: flex;
  gap: 2rem;
  flex-wrap: wrap;
}

.toggle-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.875rem;
  color: #4a5568;
  cursor: pointer;
}
`;

// Inject styles
if (typeof document !== 'undefined') {
  const styleElement = document.createElement('style');
  styleElement.textContent = searchStyles;
  document.head.appendChild(styleElement);
}