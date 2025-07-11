/**
 * Legislative Data Service
 * Handles legislative document search and data retrieval
 */

import { apiClient, ApiResponse } from './apiClient';
import { API_ENDPOINTS } from '../config/api';

export interface LegislativeDocument {
  id: string;
  title: string;
  content: string;
  urn: string;
  date: string;
  type: string;
  jurisdiction: string;
  status: string;
  metadata?: Record<string, any>;
}

export interface SearchParams {
  query?: string;
  limit?: number;
  offset?: number;
  jurisdiction?: string;
  type?: string;
  startDate?: string;
  endDate?: string;
}

export class LegislativeDataService {
  
  async searchDocuments(params: SearchParams): Promise<ApiResponse<LegislativeDocument[]>> {
    try {
      const searchParams: Record<string, string> = {};
      
      if (params.query) searchParams.query = params.query;
      if (params.limit) searchParams.limit = params.limit.toString();
      if (params.offset) searchParams.offset = params.offset.toString();
      if (params.jurisdiction) searchParams.jurisdiction = params.jurisdiction;
      if (params.type) searchParams.type = params.type;
      if (params.startDate) searchParams.start_date = params.startDate;
      if (params.endDate) searchParams.end_date = params.endDate;
      
      return await apiClient.get<LegislativeDocument[]>(API_ENDPOINTS.search, searchParams);
    } catch (error) {
      console.error('Search failed:', error);
      return {
        status: 0,
        success: false,
        error: error instanceof Error ? error.message : 'Search failed'
      };
    }
  }

  async getDocument(id: string): Promise<ApiResponse<LegislativeDocument>> {
    return await apiClient.get<LegislativeDocument>(`/api/v1/documents/${id}`);
  }

  async getDocumentMetadata(id: string): Promise<ApiResponse<Record<string, any>>> {
    return await apiClient.get<Record<string, any>>(`/api/v1/documents/${id}/metadata`);
  }

  async searchSimilarDocuments(documentId: string, limit: number = 10): Promise<ApiResponse<LegislativeDocument[]>> {
    return await apiClient.get<LegislativeDocument[]>(
      API_ENDPOINTS.ml.similarity,
      { document_id: documentId, limit: limit.toString() }
    );
  }

  async exportSearchResults(params: SearchParams, format: 'csv' | 'xlsx' = 'csv'): Promise<ApiResponse<Blob>> {
    const endpoint = format === 'csv' ? API_ENDPOINTS.exportCSV : API_ENDPOINTS.exportXLSX;
    
    const searchParams: Record<string, string> = {};
    if (params.query) searchParams.query = params.query;
    if (params.limit) searchParams.limit = params.limit.toString();
    if (params.jurisdiction) searchParams.jurisdiction = params.jurisdiction;
    if (params.type) searchParams.type = params.type;
    if (params.startDate) searchParams.start_date = params.startDate;
    if (params.endDate) searchParams.end_date = params.endDate;
    
    return await apiClient.get<Blob>(endpoint, searchParams);
  }

  // Quick search for testing
  async quickSearch(query: string): Promise<ApiResponse<LegislativeDocument[]>> {
    return this.searchDocuments({ query, limit: 10 });
  }
}

// Export singleton instance
export const legislativeDataService = new LegislativeDataService();
export default legislativeDataService;