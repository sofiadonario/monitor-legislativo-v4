import React, { useState, useRef, useEffect, useMemo } from 'react';
import { SearchFilters, LegislativeDocument, DocumentType } from '../types';
import '../styles/components/EnhancedSearch.css';

interface EnhancedSearchProps {
  filters: SearchFilters;
  onFiltersChange: (filters: SearchFilters) => void;
  documents: LegislativeDocument[];
  selectedState?: string;
  onClearSelection: () => void;
}

interface SearchSuggestion {
  text: string;
  type: 'keyword' | 'title' | 'author' | 'recent';
  count?: number;
}

const BRAZILIAN_STATES = [
  'AC', 'AL', 'AP', 'AM', 'BA', 'CE', 'DF', 'ES', 'GO', 'MA', 'MT', 'MS', 'MG',
  'PA', 'PB', 'PR', 'PE', 'PI', 'RJ', 'RN', 'RS', 'RO', 'RR', 'SC', 'SP', 'SE', 'TO'
];

export const EnhancedSearch: React.FC<EnhancedSearchProps> = ({
  filters,
  onFiltersChange,
  documents,
  selectedState,
  onClearSelection
}) => {
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [selectedSuggestionIndex, setSelectedSuggestionIndex] = useState(-1);
  const [searchHistory, setSearchHistory] = useState<string[]>([]);
  const [showAdvanced, setShowAdvanced] = useState(false);
  
  const searchInputRef = useRef<HTMLInputElement>(null);
  const suggestionsRef = useRef<HTMLDivElement>(null);

  // Load search history from localStorage
  useEffect(() => {
    const history = localStorage.getItem('searchHistory');
    if (history) {
      setSearchHistory(JSON.parse(history));
    }
  }, []);

  // Generate faceted counts
  const facets = useMemo(() => {
    const typeCounts = new Map<DocumentType, number>();
    const stateCounts = new Map<string, number>();
    const chamberCounts = new Map<string, number>();
    const keywordCounts = new Map<string, number>();

    documents.forEach(doc => {
      typeCounts.set(doc.type, (typeCounts.get(doc.type) || 0) + 1);
      if (doc.state) stateCounts.set(doc.state, (stateCounts.get(doc.state) || 0) + 1);
      if (doc.chamber) chamberCounts.set(doc.chamber, (chamberCounts.get(doc.chamber) || 0) + 1);
      doc.keywords.forEach(keyword => {
        keywordCounts.set(keyword, (keywordCounts.get(keyword) || 0) + 1);
      });
    });

    return { typeCounts, stateCounts, chamberCounts, keywordCounts };
  }, [documents]);

  // Generate search suggestions
  const suggestions = useMemo(() => {
    if (!filters.searchTerm || filters.searchTerm.length < 2) return [];

    const term = filters.searchTerm.toLowerCase();
    const results: SearchSuggestion[] = [];

    // Keywords
    Array.from(facets.keywordCounts.entries())
      .filter(([keyword]) => keyword.toLowerCase().includes(term))
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .forEach(([keyword, count]) => {
        results.push({ text: keyword, type: 'keyword', count });
      });

    // Document titles
    documents
      .filter(doc => doc.title.toLowerCase().includes(term))
      .slice(0, 3)
      .forEach(doc => {
        results.push({ text: doc.title, type: 'title' });
      });

    // Recent searches
    searchHistory
      .filter(search => search.toLowerCase().includes(term) && search !== filters.searchTerm)
      .slice(0, 2)
      .forEach(search => {
        results.push({ text: search, type: 'recent' });
      });

    return results;
  }, [filters.searchTerm, facets, documents, searchHistory]);

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    onFiltersChange({ ...filters, searchTerm: value });
    setShowSuggestions(true);
    setSelectedSuggestionIndex(-1);
  };

  const handleSearchSubmit = (searchTerm?: string) => {
    const term = searchTerm || filters.searchTerm;
    if (term.trim()) {
      // Add to search history
      const newHistory = [term, ...searchHistory.filter(h => h !== term)].slice(0, 10);
      setSearchHistory(newHistory);
      localStorage.setItem('searchHistory', JSON.stringify(newHistory));
    }
    setShowSuggestions(false);
  };

  const selectSuggestion = (suggestion: SearchSuggestion) => {
    onFiltersChange({ ...filters, searchTerm: suggestion.text });
    handleSearchSubmit(suggestion.text);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (!showSuggestions || suggestions.length === 0) return;

    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        setSelectedSuggestionIndex(prev => 
          prev < suggestions.length - 1 ? prev + 1 : 0
        );
        break;
      case 'ArrowUp':
        e.preventDefault();
        setSelectedSuggestionIndex(prev => 
          prev > 0 ? prev - 1 : suggestions.length - 1
        );
        break;
      case 'Enter':
        e.preventDefault();
        if (selectedSuggestionIndex >= 0) {
          selectSuggestion(suggestions[selectedSuggestionIndex]);
        } else {
          handleSearchSubmit();
        }
        break;
      case 'Escape':
        setShowSuggestions(false);
        setSelectedSuggestionIndex(-1);
        break;
    }
  };

  const handleDocumentTypeChange = (type: DocumentType) => {
    const newTypes = filters.documentTypes.includes(type)
      ? filters.documentTypes.filter(t => t !== type)
      : [...filters.documentTypes, type];
    
    onFiltersChange({ ...filters, documentTypes: newTypes });
  };

  const handleStateChange = (state: string) => {
    const newStates = filters.states.includes(state)
      ? filters.states.filter(s => s !== state)
      : [...filters.states, state];
    
    onFiltersChange({ ...filters, states: newStates });
  };

  const handleChamberChange = (chamber: string) => {
    const newChambers = filters.chambers.includes(chamber)
      ? filters.chambers.filter(c => c !== chamber)
      : [...filters.chambers, chamber];
    
    onFiltersChange({ ...filters, chambers: newChambers });
  };

  const handleKeywordToggle = (keyword: string) => {
    const newKeywords = filters.keywords.includes(keyword)
      ? filters.keywords.filter(k => k !== keyword)
      : [...filters.keywords, keyword];
    
    onFiltersChange({ ...filters, keywords: newKeywords });
  };

  const clearFilters = () => {
    onFiltersChange({
      searchTerm: '',
      documentTypes: [],
      states: [],
      municipalities: [],
      keywords: [],
      dateFrom: undefined,
      dateTo: undefined
    });
  };

  const hasActiveFilters = filters.documentTypes.length > 0 || 
    filters.states.length > 0 || 
    filters.keywords.length > 0 ||
    filters.dateFrom || 
    filters.dateTo ||
    filters.searchTerm.trim();

  // Click outside to close suggestions
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (suggestionsRef.current && !suggestionsRef.current.contains(e.target as Node) &&
          searchInputRef.current && !searchInputRef.current.contains(e.target as Node)) {
        setShowSuggestions(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <div className="enhanced-search">
      {/* Search Input */}
      <div className="search-section">
        <h3>Buscar Documentos</h3>
        <div className="search-input-container">
          <input
            ref={searchInputRef}
            type="text"
            placeholder="Digite palavras-chave, título ou autor..."
            value={filters.searchTerm}
            onChange={handleSearchChange}
            onKeyDown={handleKeyDown}
            onFocus={() => filters.searchTerm && setShowSuggestions(true)}
            className="search-input"
            aria-label="Buscar documentos"
          />
          <button 
            className="search-button"
            onClick={() => onFiltersChange({ ...filters })}
            aria-label="Buscar"
          >
            🔍
          </button>
          
          {showSuggestions && suggestions.length > 0 && (
            <div ref={suggestionsRef} className="search-suggestions">
              {suggestions.map((suggestion, index) => (
                <div
                  key={index}
                  className={`suggestion-item ${index === selectedSuggestionIndex ? 'selected' : ''}`}
                  onClick={() => selectSuggestion(suggestion)}
                >
                  <span className={`suggestion-icon ${suggestion.type}`}>
                    {suggestion.type === 'keyword' && '🏷️'}
                    {suggestion.type === 'title' && '📄'}
                    {suggestion.type === 'author' && '👤'}
                    {suggestion.type === 'recent' && '🕐'}
                  </span>
                  <span className="suggestion-text">{suggestion.text}</span>
                  {suggestion.count && (
                    <span className="suggestion-count">({suggestion.count})</span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Quick Filters */}
      <div className="quick-filters">
        <h4>Filtros Rápidos</h4>
        <div className="filter-chips">
          {Array.from(facets.keywordCounts.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 8)
            .map(([keyword, count]) => (
              <button
                key={keyword}
                className={`filter-chip ${filters.keywords.includes(keyword) ? 'selected' : ''}`}
                onClick={() => handleKeywordToggle(keyword)}
              >
                {keyword} ({count})
              </button>
            ))}
        </div>
      </div>

      {/* Advanced Filters Toggle */}
      <button
        className="advanced-toggle"
        onClick={() => setShowAdvanced(!showAdvanced)}
        aria-expanded={showAdvanced}
      >
        {showAdvanced ? '▼' : '▶'} Filtros Avançados
      </button>

      {showAdvanced && (
        <div className="advanced-filters">
          {/* Date Range */}
          <div className="filter-section">
            <h4>Período</h4>
            <div className="date-range">
              <input
                type="date"
                value={filters.dateFrom ? filters.dateFrom.toISOString().split('T')[0] : ''}
                onChange={(e) => onFiltersChange({
                  ...filters,
                  dateFrom: e.target.value ? new Date(e.target.value) : undefined
                })}
                aria-label="Data inicial"
              />
              <span>até</span>
              <input
                type="date"
                value={filters.dateTo ? filters.dateTo.toISOString().split('T')[0] : ''}
                onChange={(e) => onFiltersChange({
                  ...filters,
                  dateTo: e.target.value ? new Date(e.target.value) : undefined
                })}
                aria-label="Data final"
              />
            </div>
          </div>

          {/* Document Types */}
          <div className="filter-section">
            <h4>Tipos de Documento</h4>
            <div className="checkbox-group">
              {Array.from(facets.typeCounts.entries())
                .sort((a, b) => b[1] - a[1])
                .map(([type, count]) => (
                  <label key={type} className="checkbox-item">
                    <input
                      type="checkbox"
                      checked={filters.documentTypes.includes(type)}
                      onChange={() => handleDocumentTypeChange(type)}
                    />
                    <span className="checkbox-label">
                      {type} ({count})
                    </span>
                  </label>
                ))}
            </div>
          </div>

          {/* Legislative Chambers */}
          <div className="filter-section">
            <h4>Origem Legislativa</h4>
            <div className="checkbox-group">
              {Array.from(facets.chamberCounts.entries())
                .sort((a, b) => b[1] - a[1])
                .map(([chamber, count]) => (
                  <label key={chamber} className="checkbox-item">
                    <input
                      type="checkbox"
                      checked={filters.chambers.includes(chamber)}
                      onChange={() => handleChamberChange(chamber)}
                    />
                    <span className="checkbox-label">
                      {chamber} ({count})
                    </span>
                  </label>
                ))}
            </div>
          </div>

          {/* States */}
          <div className="filter-section">
            <h4>Estados</h4>
            <div className="states-grid">
              {BRAZILIAN_STATES.map(state => {
                const count = facets.stateCounts.get(state) || 0;
                if (count === 0) return null;
                
                return (
                  <label key={state} className="state-item">
                    <input
                      type="checkbox"
                      checked={filters.states.includes(state)}
                      onChange={() => handleStateChange(state)}
                    />
                    <span>{state} ({count})</span>
                  </label>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Active Filters */}
      {hasActiveFilters && (
        <div className="active-filters">
          <div className="active-filters-header">
            <span>Filtros ativos:</span>
            <button className="clear-all" onClick={clearFilters}>
              Limpar todos
            </button>
          </div>
          
          <div className="filter-tags">
            {filters.searchTerm && (
              <span className="filter-tag">
                Busca: "{filters.searchTerm}"
                <button onClick={() => onFiltersChange({ ...filters, searchTerm: '' })}>×</button>
              </span>
            )}
            
            {filters.documentTypes.map(type => (
              <span key={type} className="filter-tag">
                {type}
                <button onClick={() => handleDocumentTypeChange(type)}>×</button>
              </span>
            ))}
            
            {filters.states.map(state => (
              <span key={state} className="filter-tag">
                {state}
                <button onClick={() => handleStateChange(state)}>×</button>
              </span>
            ))}
            
            {filters.chambers.map(chamber => (
              <span key={chamber} className="filter-tag">
                {chamber}
                <button onClick={() => handleChamberChange(chamber)}>×</button>
              </span>
            ))}
            
            {filters.keywords.map(keyword => (
              <span key={keyword} className="filter-tag">
                {keyword}
                <button onClick={() => handleKeywordToggle(keyword)}>×</button>
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Selected State */}
      {selectedState && (
        <div className="selected-state">
          <span>Estado selecionado: {selectedState}</span>
          <button onClick={onClearSelection}>Limpar seleção</button>
        </div>
      )}
    </div>
  );
};