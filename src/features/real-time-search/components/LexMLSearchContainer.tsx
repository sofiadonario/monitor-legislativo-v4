/**
 * LexML Search Container - Main Component
 * Integrates all real-time search features with LexML Brasil API
 */

import React, { useState, useCallback } from 'react';
import { LexMLDocument, SearchFilters } from '../types/lexml-api.types';
import { useLexMLSearch } from '../hooks/useLexMLSearch';
import LexMLSearchBar from './LexMLSearchBar';
import LexMLFilters from './LexMLFilters';
import SearchResults from './SearchResults';
import DataSourceIndicator from './DataSourceIndicator';
import DocumentViewer from './DocumentViewer';

interface LexMLSearchContainerProps {
  className?: string;
  defaultQuery?: string;
  onDocumentSelect?: (document: LexMLDocument) => void;
}

export const LexMLSearchContainer: React.FC<LexMLSearchContainerProps> = ({
  className = '',
  defaultQuery = '',
  onDocumentSelect
}) => {
  const [filtersCollapsed, setFiltersCollapsed] = useState(true);
  const [selectedDocument, setSelectedDocument] = useState<LexMLDocument | null>(null);

  // Initialize LexML search hook
  const {
    searchState,
    searchDocuments,
    searchWithCQL,
    loadMoreResults,
    clearResults,
    setFilters,
    apiHealth,
    refreshHealth
  } = useLexMLSearch({
    debounceMs: 500,
    autoSearch: false,
    minQueryLength: 3,
    defaultMaxRecords: 50
  });

  // Handle search from search bar
  const handleSearch = useCallback(async (query: string) => {
    await searchDocuments(query, searchState.filters);
  }, [searchDocuments, searchState.filters]);

  // Handle CQL search
  const handleCQLSearch = useCallback(async (cqlQuery: string) => {
    await searchWithCQL(cqlQuery);
  }, [searchWithCQL]);

  // Handle filter changes
  const handleFiltersChange = useCallback((newFilters: Partial<SearchFilters>) => {
    setFilters(newFilters);
  }, [setFilters]);

  // Handle document selection
  const handleDocumentClick = useCallback((document: LexMLDocument) => {
    setSelectedDocument(document);
    onDocumentSelect?.(document);
  }, [onDocumentSelect]);

  // Quick search shortcuts
  const quickSearches = [
    { label: 'Transport Laws', query: 'tipoDocumento exact "Lei" AND (title any "transporte" OR description any "transporte")' },
    { label: 'Federal Decrees', query: 'tipoDocumento exact "Decreto" AND autoridade exact "federal"' },
    { label: 'Recent Legislation', query: 'date >= "2020"' },
    { label: 'São Paulo Laws', query: 'localidade any "sao.paulo"' },
    { label: 'Urban Mobility', query: 'title any "mobilidade urbana" OR description any "mobilidade urbana"' }
  ];

  return (
    <div className={`max-w-7xl mx-auto p-4 space-y-6 ${className}`}>
      {/* Header */}
      <div className="text-center">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">
          LexML Brasil Legal Search
        </h1>
        <p className="text-gray-600 max-w-2xl mx-auto">
          Real-time access to Brazil's complete legislative database. Search millions of laws, 
          decrees, and legal documents with advanced academic research tools.
        </p>
      </div>

      {/* API Health Status */}
      {apiHealth && (
        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span className={`text-lg ${apiHealth.is_healthy ? '🟢' : '🔴'}`}>
                {apiHealth.is_healthy ? '✅' : '❌'}
              </span>
              <div>
                <span className="text-sm font-medium text-gray-700">
                  API Status: {apiHealth.is_healthy ? 'Healthy' : 'Unavailable'}
                </span>
                <div className="text-xs text-gray-500">
                  Response time: {apiHealth.response_time_ms.toFixed(0)}ms | 
                  Success rate: {apiHealth.success_rate.toFixed(1)}%
                </div>
              </div>
            </div>
            <button
              onClick={refreshHealth}
              className="text-sm text-blue-600 hover:text-blue-800"
            >
              Refresh Status
            </button>
          </div>
        </div>
      )}

      {/* Search Interface */}
      <div className="bg-white border border-gray-200 rounded-lg p-6">
        <LexMLSearchBar
          onSearch={handleSearch}
          onCQLSearch={handleCQLSearch}
          initialValue={defaultQuery}
          isLoading={searchState.isLoading}
          showAdvanced={true}
          className="mb-6"
        />

        {/* Quick Search Buttons */}
        <div className="mb-6">
          <h3 className="text-sm font-medium text-gray-700 mb-3">Quick Searches:</h3>
          <div className="flex flex-wrap gap-2">
            {quickSearches.map((search, index) => (
              <button
                key={index}
                onClick={() => handleCQLSearch(search.query)}
                className="
                  px-3 py-2 text-sm bg-gray-100 text-gray-700 rounded-lg
                  hover:bg-gray-200 focus:ring-2 focus:ring-blue-500
                  transition-colors duration-200
                "
              >
                {search.label}
              </button>
            ))}
          </div>
        </div>

        {/* Search Stats */}
        {(searchState.query || searchState.results.length > 0) && (
          <div className="mb-4 p-3 bg-gray-50 rounded-lg">
            <div className="flex items-center justify-between text-sm">
              <span className="text-gray-600">
                {searchState.query && `Query: "${searchState.query}"`}
              </span>
              <div className="flex items-center gap-4">
                {searchState.searchTime > 0 && (
                  <span className="text-gray-500">
                    ⚡ {searchState.searchTime.toFixed(0)}ms
                  </span>
                )}
                <button
                  onClick={clearResults}
                  className="text-red-600 hover:text-red-800"
                >
                  Clear
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Filters */}
      <LexMLFilters
        filters={searchState.filters}
        onFiltersChange={handleFiltersChange}
        isCollapsed={filtersCollapsed}
        onToggleCollapse={() => setFiltersCollapsed(!filtersCollapsed)}
      />

      {/* Search Results */}
      <SearchResults
        documents={searchState.results}
        dataSource={searchState.dataSource}
        apiStatus={searchState.apiStatus}
        searchTime={searchState.searchTime}
        resultCount={searchState.resultCount}
        totalAvailable={searchState.totalAvailable}
        isLoading={searchState.isLoading}
        hasNextPage={searchState.hasNextPage}
        onLoadMore={loadMoreResults}
        onDocumentClick={handleDocumentClick}
      />

      {/* Document Viewer Modal */}
      {selectedDocument && (
        <DocumentViewer
          document={selectedDocument}
          onClose={() => setSelectedDocument(null)}
        />
      )}
    </div>
  );
};

export default LexMLSearchContainer;