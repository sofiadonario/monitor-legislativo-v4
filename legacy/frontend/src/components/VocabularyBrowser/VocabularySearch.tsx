/**
 * VocabularySearch Component
 * Search interface for concepts with suggestions and filters
 */
import React, { useState, useEffect, useCallback, useRef } from 'react';
import { vocabularyService } from '../../services/vocabularyService';
import { ConceptSearchResult, Concept } from '../../types';
import { LoadingSpinner } from '../LoadingSpinner';

interface VocabularySearchProps {
  conceptScheme?: string;
  onConceptSelect: (concept: Concept) => void;
  onSearchResults?: (results: ConceptSearchResult[]) => void;
  searchQuery: string;
  onSearchQueryChange: (query: string) => void;
  placeholder?: string;
}

export const VocabularySearch: React.FC<VocabularySearchProps> = ({
  conceptScheme,
  onConceptSelect,
  onSearchResults,
  searchQuery,
  onSearchQueryChange,
  placeholder = 'Search concepts...'
}) => {
  const [searchResults, setSearchResults] = useState<ConceptSearchResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [showResults, setShowResults] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(-1);
  const [language, setLanguage] = useState('pt');
  
  const searchInputRef = useRef<HTMLInputElement>(null);
  const resultsRef = useRef<HTMLDivElement>(null);
  const searchTimeoutRef = useRef<NodeJS.Timeout>();

  // Debounced search effect
  useEffect(() => {
    if (searchTimeoutRef.current) {
      clearTimeout(searchTimeoutRef.current);
    }

    if (searchQuery.trim().length >= 2) {
      searchTimeoutRef.current = setTimeout(() => {
        performSearch(searchQuery);
      }, 300);
    } else {
      setSearchResults([]);
      setShowResults(false);
      if (onSearchResults) {
        onSearchResults([]);
      }
    }

    return () => {
      if (searchTimeoutRef.current) {
        clearTimeout(searchTimeoutRef.current);
      }
    };
  }, [searchQuery, conceptScheme, language]);

  const performSearch = useCallback(async (query: string) => {
    if (!query.trim()) return;

    try {
      setLoading(true);
      const results = await vocabularyService.searchConcepts(
        query,
        language,
        20,
        conceptScheme
      );
      
      setSearchResults(results);
      setShowResults(true);
      setSelectedIndex(-1);
      
      if (onSearchResults) {
        onSearchResults(results);
      }
    } catch (error) {
      console.error('Search failed:', error);
      setSearchResults([]);
      setShowResults(false);
    } finally {
      setLoading(false);
    }
  }, [conceptScheme, language, onSearchResults]);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    onSearchQueryChange(value);
  };

  const handleInputKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (!showResults || searchResults.length === 0) return;

    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        setSelectedIndex(prev => 
          prev < searchResults.length - 1 ? prev + 1 : 0
        );
        break;
      case 'ArrowUp':
        e.preventDefault();
        setSelectedIndex(prev => 
          prev > 0 ? prev - 1 : searchResults.length - 1
        );
        break;
      case 'Enter':
        e.preventDefault();
        if (selectedIndex >= 0 && selectedIndex < searchResults.length) {
          handleResultSelect(searchResults[selectedIndex]);
        }
        break;
      case 'Escape':
        setShowResults(false);
        setSelectedIndex(-1);
        break;
    }
  };

  const handleResultSelect = (result: ConceptSearchResult) => {
    onConceptSelect(result.concept);
    onSearchQueryChange('');
    setShowResults(false);
    setSelectedIndex(-1);
    
    if (searchInputRef.current) {
      searchInputRef.current.blur();
    }
  };

  const handleInputFocus = () => {
    if (searchResults.length > 0) {
      setShowResults(true);
    }
  };

  const handleInputBlur = (e: React.FocusEvent<HTMLInputElement>) => {
    // Delay hiding results to allow clicking on them
    setTimeout(() => {
      if (!resultsRef.current?.contains(document.activeElement)) {
        setShowResults(false);
        setSelectedIndex(-1);
      }
    }, 200);
  };

  const renderSearchResult = (result: ConceptSearchResult, index: number) => {
    const isSelected = index === selectedIndex;
    const concept = result.concept;
    
    return (
      <div
        key={concept.uri}
        className={`vocabulary-search__result ${isSelected ? 'selected' : ''}`}
        onClick={() => handleResultSelect(result)}
        onMouseEnter={() => setSelectedIndex(index)}
      >
        <div className="vocabulary-search__result-main">
          <div className="vocabulary-search__result-label">
            {concept.prefLabel.pt || concept.prefLabel.en || concept.uri}
            {concept.notation && (
              <span className="vocabulary-search__result-notation">
                ({concept.notation})
              </span>
            )}
          </div>
          <div className="vocabulary-search__result-meta">
            <span className="vocabulary-search__result-scheme">
              {concept.conceptScheme}
            </span>
            <span className="vocabulary-search__result-score">
              Score: {Math.round(result.score * 100)}%
            </span>
            <span className="vocabulary-search__result-match">
              {result.matchType}
            </span>
          </div>
        </div>
        
        {concept.definition.pt || concept.definition.en ? (
          <div className="vocabulary-search__result-definition">
            {concept.definition.pt || concept.definition.en}
          </div>
        ) : null}
        
        {result.context && (
          <div className="vocabulary-search__result-context">
            Matched: <em>{result.matchedLabel}</em>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="vocabulary-search">
      <div className="vocabulary-search__input-container">
        <input
          ref={searchInputRef}
          type="text"
          value={searchQuery}
          onChange={handleInputChange}
          onKeyDown={handleInputKeyDown}
          onFocus={handleInputFocus}
          onBlur={handleInputBlur}
          placeholder={placeholder}
          className="vocabulary-search__input"
          aria-label="Search concepts"
          aria-expanded={showResults}
          aria-haspopup="listbox"
          role="combobox"
          autoComplete="off"
        />
        
        <div className="vocabulary-search__controls">
          <select
            value={language}
            onChange={(e) => setLanguage(e.target.value)}
            className="vocabulary-search__language-select"
            title="Search language"
          >
            <option value="pt">PT</option>
            <option value="en">EN</option>
          </select>
          
          {loading && (
            <div className="vocabulary-search__loading">
              <LoadingSpinner size="small" />
            </div>
          )}
        </div>
      </div>

      {showResults && (
        <div 
          ref={resultsRef}
          className="vocabulary-search__results"
          role="listbox"
          aria-label="Search results"
        >
          {searchResults.length > 0 ? (
            <>
              <div className="vocabulary-search__results-header">
                {searchResults.length} result{searchResults.length !== 1 ? 's' : ''} found
              </div>
              {searchResults.map((result, index) => renderSearchResult(result, index))}
            </>
          ) : (
            <div className="vocabulary-search__no-results">
              {loading ? 'Searching...' : 'No concepts found'}
            </div>
          )}
        </div>
      )}
    </div>
  );
};