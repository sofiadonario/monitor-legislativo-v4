/**
 * React Query hooks for Map/Choropleth API
 */

import { useQuery } from '@tanstack/react-query';
import { apiWithParams } from '../api/client';
import type { ChoroplethResponse, ChoroplethParams } from '../types/api';

/**
 * Fetch choropleth map data for Brazilian states
 *
 * @param params - Choropleth parameters
 * @returns React Query result with map data
 *
 * @example
 * ```tsx
 * // Raw document counts
 * const { data } = useChoropleth({ metric: 'n_docs', year: 2023 });
 *
 * // Bills per 100k population
 * const { data } = useChoropleth({ metric: 'bills_per_100k', year: 2023 });
 * ```
 */
export function useChoropleth(params: ChoroplethParams = {}) {
  return useQuery({
    queryKey: ['choropleth', params],
    queryFn: () =>
      apiWithParams<ChoroplethResponse>('/api/v1/map/choropleth', {
        geo: params.geo || 'estado',
        metric: params.metric || 'n_docs',
        year: params.year,
      }),
    staleTime: 30 * 60 * 1000, // 30 minutes
    gcTime: 60 * 60 * 1000, // 1 hour
  });
}
