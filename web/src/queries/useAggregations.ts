/**
 * React Query hooks for Aggregation API
 */

import { useQuery } from '@tanstack/react-query';
import { apiWithParams } from '../api/client';
import type { AggregationResponse, AggregationParams } from '../types/api';

/**
 * Fetch aggregated document counts
 *
 * @param params - Aggregation parameters
 * @returns React Query result with aggregation data
 *
 * @example
 * ```tsx
 * const { data } = useAggregations({ group_by: 'year' });
 * const { data } = useAggregations({ group_by: 'state', date_from: '2020-01-01' });
 * ```
 */
export function useAggregations(params: AggregationParams) {
  return useQuery({
    queryKey: ['aggregations', params],
    queryFn: () =>
      apiWithParams<AggregationResponse>('/api/v1/agg/counts', {
        group_by: params.group_by,
        date_from: params.date_from,
        date_to: params.date_to,
      }),
    staleTime: 10 * 60 * 1000, // 10 minutes
    gcTime: 30 * 60 * 1000, // 30 minutes
  });
}
