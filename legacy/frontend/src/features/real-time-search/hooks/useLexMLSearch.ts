/**
 * React hook for LexML Brasil search with real-time API integration
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { 
  SearchState, 
  LexMLSearchRequest, 
  LexMLDocument, 
  SearchFilters, 
  DataSource,
  APIHealthStatus 
} from '../types/lexml-api.types';
import { lexmlAPI } from '../services/LexMLAPIService';

interface UseLexMLSearchOptions {
  debounceMs?: number;
  autoSearch?: boolean;
  minQueryLength?: number;
  defaultMaxRecords?: number;
}

interface UseLexMLSearchReturn {
  searchState: SearchState;
  searchDocuments: (query: string, filters?: Partial<SearchFilters>) => Promise<void>;
  searchWithCQL: (cqlQuery: string) => Promise<void>;
  loadMoreResults: () => Promise<void>;
  clearResults: () => void;
  setFilters: (filters: Partial<SearchFilters>) => void;
  apiHealth: APIHealthStatus | null;
  refreshHealth: () => Promise<void>;
}

const defaultFilters: SearchFilters = {
  tipoDocumento: [],
  autoridade: [],
  localidade: [],
  subject: []
};

export function useLexMLSearch(options: UseLexMLSearchOptions = {}): UseLexMLSearchReturn {
  const {
    debounceMs = 500,
    autoSearch = false,
    minQueryLength = 3,
    defaultMaxRecords = 50
  } = options;

  // Search state
  const [searchState, setSearchState] = useState<SearchState>({
    query: '',
    results: [],
    isLoading: false,
    resultCount: 0,
    totalAvailable: 0,
    searchTime: 0,
    dataSource: 'live-api',
    apiStatus: 'connected',
    filters: defaultFilters,
    currentPage: 1,
    hasNextPage: false
  });

  // API health state
  const [apiHealth, setApiHealth] = useState<APIHealthStatus | null>(null);

  // Refs for cleanup and debouncing
  const debounceTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  /**
   * Update search state helper
   */
  const updateSearchState = useCallback((updates: Partial<SearchState>) => {
    setSearchState(prev => ({ ...prev, ...updates }));
  }, []);

  /**
   * Perform search with LexML API
   */
  const performSearch = useCallback(async (
    query: string, 
    filters: Partial<SearchFilters> = {},
    loadMore: boolean = false
  ) => {
    // Cancel previous request
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }

    // Don't search if query is too short (unless it's a filter-only search)
    if (!query.trim() && Object.keys(filters).length === 0) {
      updateSearchState({
        results: [],
        resultCount: 0,
        totalAvailable: 0,
        isLoading: false
      });
      return;
    }

    if (query.trim() && query.trim().length < minQueryLength) {
      return;
    }

    // Update loading state
    updateSearchState({
      isLoading: true,
      query: query.trim()
    });

    try {
      const startRecord = loadMore ? searchState.results.length + 1 : 1;
      
      const searchRequest: Partial<LexMLSearchRequest> = {
        query: query.trim() || undefined,
        filters: {
          ...defaultFilters,
          ...searchState.filters,
          ...filters
        },
        start_record: startRecord,
        max_records: defaultMaxRecords,
        include_content: false
      };

      const response = await lexmlAPI.searchDocuments(searchRequest);

      // Update search state with results
      const newResults = loadMore 
        ? [...searchState.results, ...response.documents]
        : response.documents;

      updateSearchState({
        results: newResults,
        resultCount: response.total_found || response.documents.length,
        totalAvailable: response.total_found === undefined ? 'unlimited' : response.total_found,
        searchTime: response.search_time_ms,
        dataSource: response.data_source,
        apiStatus: response.api_status === 'error' ? 'error' : 
                  response.data_source === 'csv-fallback' ? 'fallback' : 'connected',
        isLoading: false,
        currentPage: Math.ceil(newResults.length / defaultMaxRecords),
        hasNextPage: response.next_start_record !== undefined && response.next_start_record !== null,
        filters: { ...defaultFilters, ...searchState.filters, ...filters }
      });

    } catch (error) {
      console.error('Search error:', error);
      updateSearchState({
        isLoading: false,
        apiStatus: 'error',
        results: loadMore ? searchState.results : [],
        resultCount: loadMore ? searchState.resultCount : 0
      });
    }
  }, [searchState.results, searchState.filters, minQueryLength, defaultMaxRecords, updateSearchState]);

  /**
   * Debounced search function
   */
  const debouncedSearch = useCallback((query: string, filters?: Partial<SearchFilters>) => {
    if (debounceTimeoutRef.current) {
      clearTimeout(debounceTimeoutRef.current);
    }

    debounceTimeoutRef.current = setTimeout(() => {
      performSearch(query, filters);
    }, debounceMs);
  }, [performSearch, debounceMs]);

  /**
   * Public search function
   */
  const searchDocuments = useCallback(async (query: string, filters?: Partial<SearchFilters>) => {
    if (autoSearch) {
      debouncedSearch(query, filters);
    } else {
      await performSearch(query, filters);
    }
  }, [autoSearch, debouncedSearch, performSearch]);

  /**
   * Search with direct CQL query
   */
  const searchWithCQL = useCallback(async (cqlQuery: string) => {
    updateSearchState({ isLoading: true });

    try {
      const searchRequest: Partial<LexMLSearchRequest> = {
        cql_query: cqlQuery,
        start_record: 1,
        max_records: defaultMaxRecords,
        include_content: false,
        filters: defaultFilters
      };

      const response = await lexmlAPI.searchDocuments(searchRequest);

      updateSearchState({
        results: response.documents,
        resultCount: response.total_found || response.documents.length,
        totalAvailable: response.total_found === undefined ? 'unlimited' : response.total_found,
        searchTime: response.search_time_ms,
        dataSource: response.data_source,
        apiStatus: response.api_status === 'error' ? 'error' : 
                  response.data_source === 'csv-fallback' ? 'fallback' : 'connected',
        isLoading: false,
        currentPage: 1,
        hasNextPage: response.next_start_record !== undefined,
        query: `CQL: ${cqlQuery}`
      });

    } catch (error) {
      console.error('CQL search error:', error);
      updateSearchState({
        isLoading: false,
        apiStatus: 'error'
      });
    }
  }, [defaultMaxRecords, updateSearchState]);

  /**
   * Load more results (pagination)
   */
  const loadMoreResults = useCallback(async () => {
    if (!searchState.hasNextPage || searchState.isLoading) {
      return;
    }

    await performSearch(searchState.query, searchState.filters, true);
  }, [searchState.hasNextPage, searchState.isLoading, searchState.query, searchState.filters, performSearch]);

  /**
   * Clear search results
   */
  const clearResults = useCallback(() => {
    if (debounceTimeoutRef.current) {
      clearTimeout(debounceTimeoutRef.current);
    }
    
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }

    updateSearchState({
      query: '',
      results: [],
      resultCount: 0,
      totalAvailable: 0,
      searchTime: 0,
      isLoading: false,
      currentPage: 1,
      hasNextPage: false,
      filters: defaultFilters
    });
  }, [updateSearchState]);

  /**
   * Update search filters
   */
  const setFilters = useCallback((filters: Partial<SearchFilters>) => {
    const newFilters = { ...searchState.filters, ...filters };
    updateSearchState({ filters: newFilters });
    
    // Re-search with new filters if we have a query
    if (searchState.query.trim()) {
      if (autoSearch) {
        debouncedSearch(searchState.query, newFilters);
      }
    }
  }, [searchState.filters, searchState.query, autoSearch, debouncedSearch, updateSearchState]);

  /**
   * Refresh API health status
   */
  const refreshHealth = useCallback(async () => {
    try {
      const health = await lexmlAPI.getHealthStatus();
      setApiHealth(health);
    } catch (error) {
      console.error('Health check error:', error);
      setApiHealth(null);
    }
  }, []);

  /**
   * Initial health check
   */
  useEffect(() => {
    refreshHealth();
    
    // Set up periodic health checks (every 5 minutes)
    const healthInterval = setInterval(refreshHealth, 5 * 60 * 1000);
    
    return () => {
      clearInterval(healthInterval);
    };
  }, [refreshHealth]);

  /**
   * Cleanup on unmount
   */
  useEffect(() => {
    return () => {
      if (debounceTimeoutRef.current) {
        clearTimeout(debounceTimeoutRef.current);
      }
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, []);

  return {
    searchState,
    searchDocuments,
    searchWithCQL,
    loadMoreResults,
    clearResults,
    setFilters,
    apiHealth,
    refreshHealth
  };
}