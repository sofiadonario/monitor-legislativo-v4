/**
 * LexML Search Bar Component
 * Advanced search interface with auto-suggestions and CQL support
 */

import React, { useState, useRef, useEffect } from 'react';
import { SearchSuggestion } from '../types/lexml-api.types';
import { lexmlAPI } from '../services/LexMLAPIService';

interface LexMLSearchBarProps {
  onSearch: (query: string) => void;
  onCQLSearch?: (cqlQuery: string) => void;
  placeholder?: string;
  initialValue?: string;
  isLoading?: boolean;
  showAdvanced?: boolean;
  className?: string;
}

export const LexMLSearchBar: React.FC<LexMLSearchBarProps> = ({
  onSearch,
  onCQLSearch,
  placeholder = "Search Brazilian legislation...",
  initialValue = '',
  isLoading = false,
  showAdvanced = true,
  className = ''
}) => {
  const [query, setQuery] = useState(initialValue);
  const [suggestions, setSuggestions] = useState<SearchSuggestion[]>([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [isCQLMode, setIsCQLMode] = useState(false);
  const [cqlValid, setCQLValid] = useState<boolean | null>(null);
  
  const inputRef = useRef<HTMLInputElement>(null);
  const suggestionsRef = useRef<HTMLDivElement>(null);
  const debounceRef = useRef<NodeJS.Timeout | null>(null);

  // Handle input change with debounced suggestions
  const handleInputChange = (value: string) => {
    setQuery(value);
    
    // Clear previous debounce
    if (debounceRef.current) {
      clearTimeout(debounceRef.current);
    }
    
    // Get suggestions after 300ms
    if (value.length >= 2) {
      debounceRef.current = setTimeout(async () => {
        try {
          const newSuggestions = await lexmlAPI.getSuggestions(value);
          setSuggestions(newSuggestions);
          setShowSuggestions(true);
        } catch (error) {
          console.error('Suggestions error:', error);
          setSuggestions([]);
        }
      }, 300);
    } else {
      setSuggestions([]);
      setShowSuggestions(false);
    }

    // Validate CQL if in CQL mode
    if (isCQLMode && value.trim()) {
      validateCQL(value);
    }
  };

  // Validate CQL query
  const validateCQL = async (cqlQuery: string) => {
    try {
      const result = await lexmlAPI.parseCQLQuery(cqlQuery);
      setCQLValid(result.isValid);
    } catch (error) {
      setCQLValid(false);
    }
  };

  // Handle search submission
  const handleSearch = () => {
    const trimmedQuery = query.trim();
    if (!trimmedQuery) return;

    if (isCQLMode && onCQLSearch) {
      onCQLSearch(trimmedQuery);
    } else {
      onSearch(trimmedQuery);
    }
    
    setShowSuggestions(false);
  };

  // Handle suggestion selection
  const handleSuggestionSelect = (suggestion: SearchSuggestion) => {
    if (suggestion.cql_query) {
      setQuery(suggestion.cql_query);
      setIsCQLMode(true);
      if (onCQLSearch) {
        onCQLSearch(suggestion.cql_query);
      }
    } else {
      setQuery(suggestion.text);
      onSearch(suggestion.text);
    }
    setShowSuggestions(false);
    inputRef.current?.focus();
  };

  // Handle keyboard navigation
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleSearch();
    } else if (e.key === 'Escape') {
      setShowSuggestions(false);
      inputRef.current?.blur();
    }
  };

  // Close suggestions when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        suggestionsRef.current &&
        !suggestionsRef.current.contains(event.target as Node) &&
        !inputRef.current?.contains(event.target as Node)
      ) {
        setShowSuggestions(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Cleanup debounce on unmount
  useEffect(() => {
    return () => {
      if (debounceRef.current) {
        clearTimeout(debounceRef.current);
      }
    };
  }, []);

  const getSuggestionIcon = (type: string): string => {
    const icons: Record<string, string> = {
      'tipoDocumento': '📋',
      'autoridade': '🏛️',
      'localidade': '📍',
      'subject': '🏷️',
      'urn': '🔗',
      'cql': '⚡',
      'history': '🕒',
      'skos': '📚'
    };
    return icons[type] || '🔍';
  };

  const getSuggestionColor = (type: string): string => {
    const colors: Record<string, string> = {
      'tipoDocumento': 'bg-blue-50 text-blue-700',
      'autoridade': 'bg-purple-50 text-purple-700',
      'localidade': 'bg-green-50 text-green-700',
      'subject': 'bg-yellow-50 text-yellow-700',
      'urn': 'bg-gray-50 text-gray-700',
      'cql': 'bg-red-50 text-red-700',
      'history': 'bg-indigo-50 text-indigo-700',
      'skos': 'bg-pink-50 text-pink-700'
    };
    return colors[type] || 'bg-gray-50 text-gray-700';
  };

  return (
    <div className={`relative w-full ${className}`}>
      {/* Search Input */}
      <div className="relative">
        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
          <svg className="h-5 w-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
        </div>
        
        <input
          ref={inputRef}
          type="text"
          value={query}
          onChange={(e) => handleInputChange(e.target.value)}
          onKeyDown={handleKeyDown}
          onFocus={() => suggestions.length > 0 && setShowSuggestions(true)}
          placeholder={isCQLMode ? "Enter CQL query (e.g., tipoDocumento exact \"Lei\")" : placeholder}
          className={`
            w-full pl-10 pr-20 py-3 border rounded-lg
            focus:ring-2 focus:ring-blue-500 focus:border-blue-500
            ${isCQLMode ? 'bg-red-50 border-red-200' : 'bg-white border-gray-300'}
            ${isCQLMode && cqlValid === false ? 'border-red-500' : ''}
            ${isCQLMode && cqlValid === true ? 'border-green-500' : ''}
            transition-colors duration-200
          `}
          disabled={isLoading}
        />

        {/* CQL Mode Toggle */}
        {showAdvanced && (
          <button
            type="button"
            onClick={() => {
              setIsCQLMode(!isCQLMode);
              setCQLValid(null);
              if (!isCQLMode) {
                setQuery('');
              }
            }}
            className={`
              absolute inset-y-0 right-12 px-2 flex items-center
              text-xs font-medium rounded-r-none
              ${isCQLMode 
                ? 'text-red-600 bg-red-100 hover:bg-red-200' 
                : 'text-gray-500 hover:text-gray-700'
              }
              transition-colors duration-200
            `}
            title={isCQLMode ? "Switch to simple search" : "Switch to CQL mode"}
          >
            {isCQLMode ? 'CQL' : 'ABC'}
          </button>
        )}

        {/* Search Button */}
        <button
          type="button"
          onClick={handleSearch}
          disabled={isLoading || !query.trim()}
          className="
            absolute inset-y-0 right-0 px-4 flex items-center
            bg-blue-600 text-white rounded-r-lg
            hover:bg-blue-700 focus:ring-2 focus:ring-blue-500
            disabled:bg-gray-400 disabled:cursor-not-allowed
            transition-colors duration-200
          "
        >
          {isLoading ? (
            <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
          ) : (
            <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
          )}
        </button>
      </div>

      {/* CQL Validation Message */}
      {isCQLMode && query.trim() && cqlValid !== null && (
        <div className={`mt-1 text-xs ${cqlValid ? 'text-green-600' : 'text-red-600'}`}>
          {cqlValid ? '✓ Valid CQL query' : '✗ Invalid CQL syntax'}
        </div>
      )}

      {/* Suggestions Dropdown */}
      {showSuggestions && suggestions.length > 0 && (
        <div
          ref={suggestionsRef}
          className="absolute z-50 w-full mt-1 bg-white border border-gray-300 rounded-lg shadow-lg max-h-96 overflow-y-auto"
        >
          <div className="p-2">
            <div className="text-xs text-gray-500 mb-2">
              Search suggestions from LexML Brasil:
            </div>
            {suggestions.map((suggestion, index) => (
              <button
                key={index}
                onClick={() => handleSuggestionSelect(suggestion)}
                className="
                  w-full text-left px-3 py-2 rounded-md
                  hover:bg-gray-50 focus:bg-gray-50
                  flex items-center gap-3
                  transition-colors duration-150
                "
              >
                <span className="text-lg">{getSuggestionIcon(suggestion.type)}</span>
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-gray-900 truncate">
                    {suggestion.text}
                  </div>
                  {suggestion.metadata.document_count && (
                    <div className="text-xs text-gray-500">
                      {suggestion.metadata.document_count.toLocaleString()} documents
                    </div>
                  )}
                </div>
                <span className={`
                  px-2 py-1 text-xs rounded-full
                  ${getSuggestionColor(suggestion.type)}
                `}>
                  {suggestion.type}
                </span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Help Text */}
      <div className="mt-2 text-xs text-gray-500">
        {isCQLMode ? (
          <span>
            CQL mode: Use academic queries like <code>tipoDocumento exact "Lei" AND autoridade exact "federal"</code>
          </span>
        ) : (
          <span>
            Search across titles, descriptions, and subjects. Use quotes for exact phrases.
          </span>
        )}
      </div>
    </div>
  );
};

export default LexMLSearchBar;