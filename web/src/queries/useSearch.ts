/**
 * React Query hooks for Search API
 * Integrates with Monitor Legislativo R Plumber API
 */

import { useQuery } from '@tanstack/react-query';
import { apiWithParams } from '../api/client';
import type { SearchResponse, SearchParams } from '../types/api';

/**
 * Full-text search across legislative documents
 *
 * @param params - Search parameters
 * @returns React Query result with search data
 *
 * @example
 * ```tsx
 * const { data, isLoading, error } = useSearch({
 *   q: 'mobilidade urbana',
 *   scope: 'federal',
 *   page: 1,
 *   page_size: 25
 * });
 * ```
 */
export function useSearch(params: SearchParams) {
  return useQuery({
    queryKey: ['search', params],
    queryFn: () =>
      apiWithParams<SearchResponse>('/api/v1/search', {
        q: params.q,
        scope: params.scope,
        date_from: params.date_from,
        date_to: params.date_to,
        page: params.page || 1,
        page_size: params.page_size || 25,
        sort: params.sort || 'relevance',
      }),
    enabled: params.q.trim().length > 0,
    staleTime: 5 * 60 * 1000, // 5 minutes
    gcTime: 10 * 60 * 1000, // 10 minutes (formerly cacheTime)
  });
}

/**
 * Simple search hook with just query string
 * Convenience wrapper for basic searches
 *
 * @param q - Search query
 * @returns React Query result with search data
 *
 * @example
 * ```tsx
 * const { data, isLoading } = useSimpleSearch('transporte público');
 * ```
 */
export function useSimpleSearch(q: string) {
  return useSearch({ q });
}
