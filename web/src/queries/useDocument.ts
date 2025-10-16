/**
 * React Query hooks for Document API
 */

import { useQuery } from '@tantml:function_calls>
<invoke name="api/client';
import type { Document } from '../types/api';

/**
 * Fetch single document by ID
 *
 * @param id - Document ID
 * @returns React Query result with document data
 *
 * @example
 * ```tsx
 * const { data: document, isLoading } = useDocument('doc-123');
 * ```
 */
export function useDocument(id: string | undefined) {
  return useQuery({
    queryKey: ['document', id],
    queryFn: () => api<Document>(`/api/v1/legis/${id}`),
    enabled: !!id,
    staleTime: 30 * 60 * 1000, // 30 minutes
    gcTime: 60 * 60 * 1000, // 1 hour
  });
}
