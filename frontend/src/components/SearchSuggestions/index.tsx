/**
 * SearchSuggestions Component
 * Intelligent search suggestions with vocabulary expansion and auto-completion
 */
import React, { useState, useEffect, useCallback, useRef } from 'react';
import { vocabularyService } from '../../services/vocabularyService';
import { ConceptSearchResult, QueryExpansion } from '../../types';
import { VocabularyExpansion } from './VocabularyExpansion';
import { SearchHistory } from './SearchHistory';
import './SearchSuggestions.css';

interface SearchSuggestionsProps {
  query: string;
  onQueryChange: (query: string) => void;
  onSearch: (query: string) => void;
  onSuggestionSelect?: (suggestion: string) => void;
  placeholder?: string;
  showExpansion?: boolean;
  showHistory?: boolean;
  className?: string;
}

interface Suggestion {
  id: string;
  text: string;
  type: 'concept' | 'history' | 'completion';
  source?: string;
  score?: number;
  concept?: ConceptSearchResult;
}

export const SearchSuggestions: React.FC<SearchSuggestionsProps> = ({
  query,
  onQueryChange,
  onSearch,
  onSuggestionSelect,
  placeholder = 'Search legislative documents...',
  showExpansion = true,
  showHistory = true,
  className = ''
}) => {
  const [suggestions, setSuggestions] = useState<Suggestion[]>([]);
  const [loading, setLoading] = useState(false);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(-1);
  const [expansionData, setExpansionData] = useState<QueryExpansion | null>(null);
  const [showExpansionPanel, setShowExpansionPanel] = useState(false);
  
  const inputRef = useRef<HTMLInputElement>(null);
  const suggestionsRef = useRef<HTMLDivElement>(null);
  const debounceRef = useRef<NodeJS.Timeout>();

  // Debounced suggestion loading
  useEffect(() => {
    if (debounceRef.current) {
      clearTimeout(debounceRef.current);
    }

    if (query.trim().length >= 2) {
      debounceRef.current = setTimeout(() => {
        loadSuggestions(query);
      }, 300);
    } else {
      setSuggestions([]);
      setShowSuggestions(false);
      setExpansionData(null);
    }

    return () => {
      if (debounceRef.current) {
        clearTimeout(debounceRef.current);
      }
    };
  }, [query]);

  const loadSuggestions = useCallback(async (searchQuery: string) => {
    if (!searchQuery.trim()) return;

    try {
      setLoading(true);
      const allSuggestions: Suggestion[] = [];

      // Load concept suggestions from vocabulary
      const conceptResults = await vocabularyService.searchConcepts(
        searchQuery, 
        'pt', 
        8
      );

      conceptResults.forEach((result, index) => {
        const concept = result.concept;
        const preferredLabel = concept.prefLabel.pt || concept.prefLabel.en || concept.uri;
        
        allSuggestions.push({
          id: `concept-${index}`,
          text: preferredLabel,
          type: 'concept',
          source: concept.conceptScheme,
          score: result.score,
          concept: result
        });
      });

      // Load search history if enabled
      if (showHistory) {
        const historyItems = getSearchHistory().filter(item =>
          item.toLowerCase().includes(searchQuery.toLowerCase())
        ).slice(0, 5);

        historyItems.forEach((item, index) => {
          allSuggestions.push({
            id: `history-${index}`,
            text: item,
            type: 'history'
          });
        });
      }

      // Generate text completions based on common patterns
      const completions = generateCompletions(searchQuery);
      completions.forEach((completion, index) => {
        allSuggestions.push({
          id: `completion-${index}`,
          text: completion,
          type: 'completion'
        });
      });

      // Sort suggestions by relevance
      const sortedSuggestions = allSuggestions.sort((a, b) => {
        // Prioritize concept matches, then history, then completions
        const typeOrder = { concept: 0, history: 1, completion: 2 };
        if (a.type !== b.type) {
          return typeOrder[a.type] - typeOrder[b.type];
        }
        // Within same type, sort by score (concepts) or alphabetically
        if (a.score && b.score) {
          return b.score - a.score;
        }
        return a.text.localeCompare(b.text);
      });

      setSuggestions(sortedSuggestions.slice(0, 12));
      setShowSuggestions(true);
      setSelectedIndex(-1);

      // Load vocabulary expansion if enabled
      if (showExpansion) {
        loadVocabularyExpansion(searchQuery);
      }

    } catch (error) {
      console.error('Error loading suggestions:', error);
      setSuggestions([]);
    } finally {
      setLoading(false);
    }
  }, [showHistory, showExpansion]);

  const loadVocabularyExpansion = async (searchQuery: string) => {
    try {
      const expansion = await vocabularyService.expandQuery(searchQuery);
      setExpansionData(expansion);
    } catch (error) {
      console.error('Error loading vocabulary expansion:', error);
      setExpansionData(null);
    }
  };

  const generateCompletions = (query: string): string[] => {
    const completions: string[] = [];
    const lowerQuery = query.toLowerCase();

    // Common search patterns for legislative documents
    const patterns = [
      'transporte público',
      'transporte urbano',
      'mobilidade urbana',
      'código de trânsito',
      'lei municipal',
      'decreto federal',
      'resolução ANTT',
      'portaria ANAC',
      'infraestrutura rodoviária',
      'transporte escolar',
      'acessibilidade transporte',
      'segurança viária',
      'emissões veiculares',
      'combustíveis alternativos'
    ];

    patterns.forEach(pattern => {
      if (pattern.toLowerCase().includes(lowerQuery) && pattern !== query) {
        completions.push(pattern);
      }
    });

    return completions.slice(0, 3);
  };

  const getSearchHistory = (): string[] => {
    try {
      const history = localStorage.getItem('search-history');
      return history ? JSON.parse(history) : [];
    } catch {
      return [];
    }
  };

  const addToSearchHistory = (searchQuery: string) => {
    try {
      const history = getSearchHistory();
      const updatedHistory = [
        searchQuery,
        ...history.filter(item => item !== searchQuery)
      ].slice(0, 20); // Keep only last 20 searches
      
      localStorage.setItem('search-history', JSON.stringify(updatedHistory));
    } catch (error) {
      console.error('Error saving search history:', error);
    }
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    onQueryChange(value);
  };

  const handleInputKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (!showSuggestions || suggestions.length === 0) {
      if (e.key === 'Enter') {
        handleSearch();
      }
      return;
    }

    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        setSelectedIndex(prev => 
          prev < suggestions.length - 1 ? prev + 1 : 0
        );
        break;
      case 'ArrowUp':
        e.preventDefault();
        setSelectedIndex(prev => 
          prev > 0 ? prev - 1 : suggestions.length - 1
        );
        break;
      case 'Enter':
        e.preventDefault();
        if (selectedIndex >= 0 && selectedIndex < suggestions.length) {
          handleSuggestionSelect(suggestions[selectedIndex]);
        } else {
          handleSearch();
        }
        break;
      case 'Escape':
        setShowSuggestions(false);
        setSelectedIndex(-1);
        break;
      case 'Tab':
        if (selectedIndex >= 0 && selectedIndex < suggestions.length) {
          e.preventDefault();
          handleSuggestionSelect(suggestions[selectedIndex]);
        }
        break;
    }
  };

  const handleSuggestionSelect = (suggestion: Suggestion) => {
    onQueryChange(suggestion.text);
    setShowSuggestions(false);
    setSelectedIndex(-1);
    
    if (onSuggestionSelect) {
      onSuggestionSelect(suggestion.text);
    }
    
    // Automatically search when selecting a suggestion
    setTimeout(() => {
      handleSearch(suggestion.text);
    }, 100);
  };

  const handleSearch = (searchQuery?: string) => {
    const finalQuery = searchQuery || query;
    if (finalQuery.trim()) {
      addToSearchHistory(finalQuery.trim());
      onSearch(finalQuery.trim());
      setShowSuggestions(false);
    }
  };

  const handleInputFocus = () => {
    if (suggestions.length > 0) {
      setShowSuggestions(true);
    }
  };

  const handleInputBlur = (e: React.FocusEvent<HTMLInputElement>) => {
    // Delay hiding suggestions to allow clicking on them
    setTimeout(() => {
      if (!suggestionsRef.current?.contains(document.activeElement)) {
        setShowSuggestions(false);
        setSelectedIndex(-1);
      }
    }, 200);
  };

  const renderSuggestion = (suggestion: Suggestion, index: number) => {
    const isSelected = index === selectedIndex;
    
    return (
      <div
        key={suggestion.id}
        className={`search-suggestions__item ${isSelected ? 'selected' : ''} ${suggestion.type}`}
        onClick={() => handleSuggestionSelect(suggestion)}
        onMouseEnter={() => setSelectedIndex(index)}
      >
        <div className="search-suggestions__item-content">
          <div className="search-suggestions__item-text">
            {suggestion.text}
          </div>
          <div className="search-suggestions__item-meta">
            {suggestion.type === 'concept' && (
              <>
                <span className="search-suggestions__type">Concept</span>
                {suggestion.source && (
                  <span className="search-suggestions__source">{suggestion.source}</span>
                )}
                {suggestion.score && (
                  <span className="search-suggestions__score">
                    {Math.round(suggestion.score * 100)}%
                  </span>
                )}
              </>
            )}
            {suggestion.type === 'history' && (
              <span className="search-suggestions__type">Recent search</span>
            )}
            {suggestion.type === 'completion' && (
              <span className="search-suggestions__type">Suggested</span>
            )}
          </div>
        </div>
        
        {suggestion.concept?.concept.definition.pt && (
          <div className="search-suggestions__definition">
            {suggestion.concept.concept.definition.pt}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className={`search-suggestions ${className}`}>
      <div className="search-suggestions__input-container">
        <input
          ref={inputRef}
          type="text"
          value={query}
          onChange={handleInputChange}
          onKeyDown={handleInputKeyDown}
          onFocus={handleInputFocus}
          onBlur={handleInputBlur}
          placeholder={placeholder}
          className="search-suggestions__input"
          aria-label="Search legislative documents"
          aria-expanded={showSuggestions}
          aria-haspopup="listbox"
          role="combobox"
          autoComplete="off"
        />
        
        <div className="search-suggestions__actions">
          {showExpansion && expansionData && (
            <button
              onClick={() => setShowExpansionPanel(!showExpansionPanel)}
              className="search-suggestions__expand-btn"
              title="Show vocabulary expansion"
            >
              <span>+</span>
            </button>
          )}
          
          <button
            onClick={() => handleSearch()}
            className="search-suggestions__search-btn"
            disabled={!query.trim()}
          >
            Search
          </button>
        </div>
        
        {loading && (
          <div className="search-suggestions__loading">
            <div className="search-suggestions__spinner"></div>
          </div>
        )}
      </div>

      {showSuggestions && suggestions.length > 0 && (
        <div 
          ref={suggestionsRef}
          className="search-suggestions__dropdown"
          role="listbox"
          aria-label="Search suggestions"
        >
          <div className="search-suggestions__header">
            {suggestions.length} suggestion{suggestions.length !== 1 ? 's' : ''} found
          </div>
          {suggestions.map((suggestion, index) => renderSuggestion(suggestion, index))}
        </div>
      )}

      {showExpansionPanel && expansionData && (
        <div className="search-suggestions__expansion-panel">
          <VocabularyExpansion
            expansion={expansionData}
            onTermSelect={(term) => {
              onQueryChange(term);
              setShowExpansionPanel(false);
            }}
            onClose={() => setShowExpansionPanel(false)}
          />
        </div>
      )}

      {showHistory && (
        <SearchHistory
          onHistorySelect={(term) => {
            onQueryChange(term);
            handleSearch(term);
          }}
        />
      )}
    </div>
  );
};