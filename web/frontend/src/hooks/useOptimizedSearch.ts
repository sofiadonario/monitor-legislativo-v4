/**
 * Optimized Search Hook
 * Implements debouncing, caching, and virtual scrolling for high-performance search
 */

import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { useQuery, useInfiniteQuery, useQueryClient } from 'react-query';
import { useVirtual } from 'react-virtual';
import { debounce } from '../utils/performance';
import { searchPropositions, SearchParams, SearchResult } from '../services/api';

interface UseOptimizedSearchOptions {
  debounceMs?: number;
  pageSize?: number;
  enableVirtualization?: boolean;
  enableInfiniteScroll?: boolean;
  cacheTime?: number;
  staleTime?: number;
}

interface UseOptimizedSearchResult {
  // Search state
  query: string;
  setQuery: (query: string) => void;
  filters: SearchParams['filters'];
  setFilters: (filters: SearchParams['filters']) => void;
  
  // Results
  results: SearchResult['results'];
  totalCount: number;
  isLoading: boolean;
  isError: boolean;
  error: Error | null;
  
  // Pagination
  page: number;
  totalPages: number;
  hasNextPage: boolean;
  hasPreviousPage: boolean;
  goToPage: (page: number) => void;
  goToNextPage: () => void;
  goToPreviousPage: () => void;
  
  // Infinite scroll
  fetchNextPage?: () => void;
  isFetchingNextPage?: boolean;
  
  // Virtual scrolling
  virtualItems?: any;
  totalSize?: number;
  
  // Actions
  refetch: () => void;
  reset: () => void;
}

export function useOptimizedSearch(options: UseOptimizedSearchOptions = {}): UseOptimizedSearchResult {
  const {
    debounceMs = 300,
    pageSize = 25,
    enableVirtualization = false,
    enableInfiniteScroll = false,
    cacheTime = 10 * 60 * 1000, // 10 minutes
    staleTime = 5 * 60 * 1000, // 5 minutes
  } = options;

  const queryClient = useQueryClient();
  const parentRef = useRef<HTMLDivElement>(null);

  // Search state
  const [query, setQuery] = useState('');
  const [debouncedQuery, setDebouncedQuery] = useState('');
  const [filters, setFilters] = useState<SearchParams['filters']>({});
  const [page, setPage] = useState(1);

  // Debounce search query
  const debouncedSetQuery = useMemo(
    () => debounce((value: string) => setDebouncedQuery(value), debounceMs),
    [debounceMs]
  );

  useEffect(() => {
    debouncedSetQuery(query);
  }, [query, debouncedSetQuery]);

  // Reset page when query or filters change
  useEffect(() => {
    setPage(1);
  }, [debouncedQuery, filters]);

  // Build query key
  const queryKey = useMemo(
    () => ['search', debouncedQuery, filters, enableInfiniteScroll ? 'infinite' : page, pageSize],
    [debouncedQuery, filters, page, pageSize, enableInfiniteScroll]
  );

  // Regular paginated search
  const paginatedQuery = useQuery(
    queryKey,
    () => searchPropositions({
      query: debouncedQuery,
      filters,
      page,
      pageSize,
    }),
    {
      enabled: !enableInfiniteScroll && (!!debouncedQuery || Object.keys(filters).length > 0),
      keepPreviousData: true,
      cacheTime,
      staleTime,
      onSuccess: (data) => {
        // Prefetch adjacent pages for smoother navigation
        if (data.page > 1) {
          queryClient.prefetchQuery(
            ['search', debouncedQuery, filters, page - 1, pageSize],
            () => searchPropositions({
              query: debouncedQuery,
              filters,
              page: page - 1,
              pageSize,
            })
          );
        }
        
        if (data.page < data.totalPages) {
          queryClient.prefetchQuery(
            ['search', debouncedQuery, filters, page + 1, pageSize],
            () => searchPropositions({
              query: debouncedQuery,
              filters,
              page: page + 1,
              pageSize,
            })
          );
        }
      },
    }
  );

  // Infinite scroll search
  const infiniteQuery = useInfiniteQuery(
    queryKey,
    ({ pageParam = 1 }) => searchPropositions({
      query: debouncedQuery,
      filters,
      page: pageParam,
      pageSize,
    }),
    {
      enabled: enableInfiniteScroll && (!!debouncedQuery || Object.keys(filters).length > 0),
      getNextPageParam: (lastPage) => {
        if (lastPage.page < lastPage.totalPages) {
          return lastPage.page + 1;
        }
        return undefined;
      },
      cacheTime,
      staleTime,
    }
  );

  // Flatten results for infinite scroll
  const infiniteResults = useMemo(() => {
    if (!infiniteQuery.data) return [];
    return infiniteQuery.data.pages.flatMap(page => page.results);
  }, [infiniteQuery.data]);

  // Virtual scrolling setup
  const rowVirtualizer = useVirtual({
    size: enableInfiniteScroll ? infiniteResults.length : (paginatedQuery.data?.results.length || 0),
    parentRef,
    estimateSize: useCallback(() => 120, []), // Estimated row height
    overscan: 5,
  });

  // Determine which query to use
  const activeQuery = enableInfiniteScroll ? infiniteQuery : paginatedQuery;
  const results = enableInfiniteScroll ? infiniteResults : (paginatedQuery.data?.results || []);
  const totalCount = enableInfiniteScroll 
    ? infiniteQuery.data?.pages[0]?.totalCount || 0
    : paginatedQuery.data?.totalCount || 0;

  // Pagination helpers
  const totalPages = Math.ceil(totalCount / pageSize);
  const hasNextPage = page < totalPages;
  const hasPreviousPage = page > 1;

  const goToPage = useCallback((newPage: number) => {
    if (newPage >= 1 && newPage <= totalPages) {
      setPage(newPage);
    }
  }, [totalPages]);

  const goToNextPage = useCallback(() => {
    if (hasNextPage) {
      setPage(p => p + 1);
    }
  }, [hasNextPage]);

  const goToPreviousPage = useCallback(() => {
    if (hasPreviousPage) {
      setPage(p => p - 1);
    }
  }, [hasPreviousPage]);

  // Reset search
  const reset = useCallback(() => {
    setQuery('');
    setDebouncedQuery('');
    setFilters({});
    setPage(1);
    queryClient.removeQueries(['search']);
  }, [queryClient]);

  // Build result object
  const result: UseOptimizedSearchResult = {
    // Search state
    query,
    setQuery,
    filters,
    setFilters,
    
    // Results
    results,
    totalCount,
    isLoading: activeQuery.isLoading,
    isError: activeQuery.isError,
    error: activeQuery.error as Error | null,
    
    // Pagination
    page,
    totalPages,
    hasNextPage,
    hasPreviousPage,
    goToPage,
    goToNextPage,
    goToPreviousPage,
    
    // Actions
    refetch: activeQuery.refetch,
    reset,
  };

  // Add infinite scroll properties if enabled
  if (enableInfiniteScroll) {
    result.fetchNextPage = infiniteQuery.fetchNextPage;
    result.isFetchingNextPage = infiniteQuery.isFetchingNextPage;
  }

  // Add virtual scrolling properties if enabled
  if (enableVirtualization) {
    result.virtualItems = rowVirtualizer.virtualItems;
    result.totalSize = rowVirtualizer.totalSize;
  }

  return result;
}

// Companion hook for search suggestions
export function useSearchSuggestions(query: string, options: { debounceMs?: number } = {}) {
  const { debounceMs = 150 } = options;
  const [debouncedQuery, setDebouncedQuery] = useState('');

  const debouncedSetQuery = useMemo(
    () => debounce((value: string) => setDebouncedQuery(value), debounceMs),
    [debounceMs]
  );

  useEffect(() => {
    debouncedSetQuery(query);
  }, [query, debouncedSetQuery]);

  const { data, isLoading } = useQuery(
    ['suggestions', debouncedQuery],
    () => searchPropositions({
      query: debouncedQuery,
      filters: {},
      page: 1,
      pageSize: 5,
    }),
    {
      enabled: debouncedQuery.length >= 2,
      staleTime: 60 * 1000, // 1 minute
      select: (data) => data.results.map(r => ({
        id: r.id,
        title: r.title,
        type: r.type,
      })),
    }
  );

  return {
    suggestions: data || [],
    isLoading,
  };
}