/**
 * Processed Data Service
 * Handles API calls for processed legislative documents from Supabase
 */

export interface ProcessedDocument {
  id: number;
  search_term: string;
  date_searched: string;
  url: string;
  title: string;
  urn: string;
  urn_type: string;
  country: string;
  state: string;
  municipality: string;
  justice: string;
  region: string;
  court_class: string;
  document_type_full: string;
  promulgation_date: string;
  document_description: string;
  created_at: string;
  updated_at: string;
}

export interface ProcessedDataStats {
  total_documents: number;
  recent_documents: number;
  documents_by_year: Record<string, number>;
  data_source: string;
}

export interface ProcessedDataCategories {
  document_types: Record<string, number>;
  states: Record<string, number>;
  urn_types: Record<string, number>;
  search_terms: Record<string, number>;
}

export interface ProcessedDataResponse {
  status: string;
  data: ProcessedDocument[];
  count: number;
  offset: number;
  limit: number;
}

import { getApiBaseUrl } from '../config/api';

const API_BASE_URL = `${getApiBaseUrl()}/api/v1`;

class ProcessedDataService {
  
  /**
   * Fetch processed documents with pagination and filters
   */
  async getProcessedDocuments(params: {
    limit?: number;
    offset?: number;
    search_term?: string;
    document_type?: string;
    state?: string;
    urn_type?: string;
  } = {}): Promise<ProcessedDataResponse> {
    const queryParams = new URLSearchParams();
    
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        queryParams.append(key, value.toString());
      }
    });
    
    const response = await fetch(`${API_BASE_URL}/processed-documents?${queryParams}`);
    
    if (!response.ok) {
      throw new Error(`Failed to fetch processed documents: ${response.statusText}`);
    }
    
    return response.json();
  }

  /**
   * Get document categories for analytics
   */
  async getCategories(): Promise<{ status: string; categories: ProcessedDataCategories; total_documents: number; last_updated: string }> {
    const response = await fetch(`${API_BASE_URL}/processed-documents/categories`);
    
    if (!response.ok) {
      throw new Error(`Failed to fetch categories: ${response.statusText}`);
    }
    
    return response.json();
  }

  /**
   * Get document statistics
   */
  async getStats(): Promise<{ status: string; stats: ProcessedDataStats; generated_at: string }> {
    const response = await fetch(`${API_BASE_URL}/processed-documents/stats`);
    
    if (!response.ok) {
      throw new Error(`Failed to fetch stats: ${response.statusText}`);
    }
    
    return response.json();
  }

  /**
   * Search processed documents
   */
  async searchDocuments(query: string, limit: number = 50): Promise<{
    status: string;
    query: string;
    results: ProcessedDocument[];
    count: number;
  }> {
    const response = await fetch(`${API_BASE_URL}/processed-documents/search?q=${encodeURIComponent(query)}&limit=${limit}`);
    
    if (!response.ok) {
      throw new Error(`Failed to search documents: ${response.statusText}`);
    }
    
    return response.json();
  }

  /**
   * Get a specific document by ID
   */
  async getDocument(id: number): Promise<{ status: string; document: ProcessedDocument }> {
    const response = await fetch(`${API_BASE_URL}/processed-documents/${id}`);
    
    if (!response.ok) {
      throw new Error(`Failed to fetch document: ${response.statusText}`);
    }
    
    return response.json();
  }

  /**
   * Get top document types
   */
  async getTopDocumentTypes(limit: number = 10): Promise<Array<{ name: string; count: number }>> {
    const categoriesData = await this.getCategories();
    const documentTypes = categoriesData.categories.document_types;
    
    return Object.entries(documentTypes)
      .sort(([, a], [, b]) => b - a)
      .slice(0, limit)
      .map(([name, count]) => ({ name, count }));
  }

  /**
   * Get top states by document count
   */
  async getTopStates(limit: number = 10): Promise<Array<{ name: string; count: number }>> {
    const categoriesData = await this.getCategories();
    const states = categoriesData.categories.states;
    
    return Object.entries(states)
      .sort(([, a], [, b]) => b - a)
      .slice(0, limit)
      .map(([name, count]) => ({ name, count }));
  }

  /**
   * Get documents by year for trending analysis
   */
  async getDocumentsByYear(): Promise<Array<{ year: string; count: number }>> {
    const statsData = await this.getStats();
    const documentsByYear = statsData.stats.documents_by_year;
    
    return Object.entries(documentsByYear)
      .sort(([a], [b]) => parseInt(b) - parseInt(a))
      .map(([year, count]) => ({ year, count }));
  }

  /**
   * Export processed documents to CSV
   */
  async exportToCSV(filters: {
    search_term?: string;
    document_type?: string;
    state?: string;
    urn_type?: string;
  } = {}): Promise<string> {
    // Get all documents matching filters
    const allDocuments: ProcessedDocument[] = [];
    let offset = 0;
    const limit = 1000;
    
    while (true) {
      const response = await this.getProcessedDocuments({
        ...filters,
        limit,
        offset
      });
      
      allDocuments.push(...response.data);
      
      if (response.data.length < limit) {
        break; // No more data
      }
      
      offset += limit;
    }
    
    // Convert to CSV
    if (allDocuments.length === 0) {
      return 'No data found matching your criteria.';
    }
    
    const headers = Object.keys(allDocuments[0]);
    const csvContent = [
      headers.join(','),
      ...allDocuments.map(doc => 
        headers.map(header => {
          const value = doc[header as keyof ProcessedDocument] || '';
          // Escape quotes and commas
          return `"${value.toString().replace(/"/g, '""')}"`;
        }).join(',')
      )
    ].join('\n');
    
    return csvContent;
  }

  /**
   * Get summary statistics for dashboard
   */
  async getSummaryStats(): Promise<{
    totalDocuments: number;
    documentTypes: number;
    statesCovered: number;
    recentDocuments: number;
    topSearchTerms: Array<{ term: string; count: number }>;
  }> {
    const [statsData, categoriesData] = await Promise.all([
      this.getStats(),
      this.getCategories()
    ]);
    
    const topSearchTerms = Object.entries(categoriesData.categories.search_terms)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 5)
      .map(([term, count]) => ({ term, count }));
    
    return {
      totalDocuments: statsData.stats.total_documents,
      documentTypes: Object.keys(categoriesData.categories.document_types).length,
      statesCovered: Object.keys(categoriesData.categories.states).length,
      recentDocuments: statsData.stats.recent_documents,
      topSearchTerms
    };
  }
}

// Export singleton instance
export const processedDataService = new ProcessedDataService(); 