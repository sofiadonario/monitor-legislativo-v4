import { getCSVData, loadCSVLegislativeData } from '../data/csv-legislative-data';
import { mockLegislativeData } from '../data/mock-legislative-data';
import { LegislativeDocument, SearchFilters } from '../types';
import apiClient, { ApiError } from './apiClient';

// Check if we're in development/testing mode
const isDevelopment = import.meta.env.MODE === 'development';
const isTestEnvironment = import.meta.env.MODE === 'test';
const useMockData = import.meta.env.VITE_USE_MOCK_DATA === 'true';

export class LegislativeDataService {
  private static instance: LegislativeDataService;
  private csvDataCache: LegislativeDocument[] | null = null;
  
  private constructor() {}
  
  static getInstance(): LegislativeDataService {
    if (!LegislativeDataService.instance) {
      LegislativeDataService.instance = new LegislativeDataService();
    }
    return LegislativeDataService.instance;
  }
  
  private async getFallbackData(): Promise<{ documents: LegislativeDocument[], usingFallback: true }> {
    // Get full CSV data (889 rows) - this is loaded automatically when module imports
    const csvData = getCSVData();
    
    if (csvData.length > 0) {
      console.log(`Using ${csvData.length} documents from CSV dataset`);
      // Combine CSV data with mock data for even richer demo experience
      const combinedData = [...csvData, ...mockLegislativeData];
      return { documents: combinedData, usingFallback: true };
    }
    
    // If CSV data not available, try to load it
    if (!this.csvDataCache) {
      try {
        console.log('Attempting to load CSV legislative data...');
        this.csvDataCache = await loadCSVLegislativeData();
        if (this.csvDataCache.length > 0) {
          console.log(`Loaded ${this.csvDataCache.length} documents from CSV`);
          // Combine with mock data
          return { documents: [...this.csvDataCache, ...mockLegislativeData], usingFallback: true };
        }
      } catch (error) {
        console.warn('Failed to load CSV data, using mock data only:', error);
      }
    }
    
    // Final fallback to mock data only
    return { documents: mockLegislativeData, usingFallback: true };
  }
  
  async fetchDocuments(filters?: SearchFilters): Promise<{ documents: LegislativeDocument[], usingFallback: boolean }> {
    if (useMockData) {
      // Use CSV + mock data for demo mode
      console.log('Demo mode: Using CSV + mock data for demonstration');
      const fallbackData = await this.getFallbackData();
      return { documents: this.filterMockData(fallbackData.documents, filters), usingFallback: true };
    }
    
    try {
      // Real API call
      const params = this.buildQueryParams(filters);
      const data = await apiClient.get<any[]>('/documents', params);
      return { documents: this.transformApiResponse(data), usingFallback: false };
    } catch (error) {
      console.warn('API not available, falling back to CSV + mock data:', error);
      
      // Fallback to CSV + mock data if API fails (for academic/demo purposes)
      const fallbackData = await this.getFallbackData();
      return { documents: this.filterMockData(fallbackData.documents, filters), usingFallback: true };
    }
  }
  
  async fetchDocumentById(id: string): Promise<LegislativeDocument | null> {
    if (useMockData) {
      const fallbackData = await this.getFallbackData();
      return fallbackData.documents.find(doc => doc.id === id) || null;
    }
    
    try {
      const data = await apiClient.get<any>(`/documents/${id}`);
      return this.transformApiDocument(data);
    } catch (error) {
      if (error instanceof ApiError && error.statusCode === 404) {
        return null;
      }
      
      console.warn('API not available, falling back to CSV + mock data:', error);
      
      // Fallback to CSV + mock data if API fails (for academic/demo purposes)
      const fallbackData = await this.getFallbackData();
      return fallbackData.documents.find(doc => doc.id === id) || null;
    }
  }
  
  async searchDocuments(searchTerm: string): Promise<LegislativeDocument[]> {
    if (useMockData) {
      const fallbackData = await this.getFallbackData();
      const lowerSearchTerm = searchTerm.toLowerCase();
      return fallbackData.documents.filter(doc => 
        doc.title.toLowerCase().includes(lowerSearchTerm) ||
        doc.summary.toLowerCase().includes(lowerSearchTerm) ||
        doc.keywords.some(keyword => keyword.toLowerCase().includes(lowerSearchTerm))
      );
    }
    
    try {
      const data = await apiClient.get<any[]>('/documents/search', { q: searchTerm });
      return this.transformApiResponse(data);
    } catch (error) {
      console.warn('Search API not available, falling back to CSV + mock data:', error);
      
      // Fallback to CSV + mock data search if API fails
      const fallbackData = await this.getFallbackData();
      const lowerSearchTerm = searchTerm.toLowerCase();
      return fallbackData.documents.filter(doc => 
        doc.title.toLowerCase().includes(lowerSearchTerm) ||
        doc.summary.toLowerCase().includes(lowerSearchTerm) ||
        doc.keywords.some(keyword => keyword.toLowerCase().includes(lowerSearchTerm))
      );
    }
  }
  
  private filterMockData(data: LegislativeDocument[], filters?: SearchFilters): LegislativeDocument[] {
    if (!filters) return data;
    
    return data.filter(doc => {
      if (filters.searchTerm && 
          !doc.title.toLowerCase().includes(filters.searchTerm.toLowerCase()) &&
          !doc.summary.toLowerCase().includes(filters.searchTerm.toLowerCase()) &&
          !doc.keywords.some(keyword => keyword.toLowerCase().includes(filters.searchTerm.toLowerCase()))) {
        return false;
      }
      
      if (filters.documentTypes.length > 0 && !filters.documentTypes.includes(doc.type)) {
        return false;
      }
      
      if (filters.states.length > 0 && doc.state && !filters.states.includes(doc.state)) {
        return false;
      }
      
      if (filters.municipalities.length > 0 && doc.municipality && !filters.municipalities.includes(doc.municipality)) {
        return false;
      }
      
      if (filters.chambers.length > 0 && doc.chamber && !filters.chambers.includes(doc.chamber)) {
        return false;
      }
      
      if (filters.dateFrom && new Date(doc.date) < filters.dateFrom) {
        return false;
      }
      
      if (filters.dateTo && new Date(doc.date) > filters.dateTo) {
        return false;
      }
      
      return true;
    });
  }
  
  private buildQueryParams(filters?: SearchFilters): Record<string, string> {
    if (!filters) return {};
    
    const params: Record<string, string> = {};
    
    if (filters.searchTerm) params.search = filters.searchTerm;
    if (filters.documentTypes.length > 0) params.types = filters.documentTypes.join(',');
    if (filters.states.length > 0) params.states = filters.states.join(',');
    if (filters.municipalities.length > 0) params.municipalities = filters.municipalities.join(',');
    if (filters.chambers.length > 0) params.chambers = filters.chambers.join(',');
    if (filters.dateFrom) params.date_from = filters.dateFrom.toISOString();
    if (filters.dateTo) params.date_to = filters.dateTo.toISOString();
    if (filters.keywords.length > 0) params.keywords = filters.keywords.join(',');
    
    return params;
  }
  
  private transformApiResponse(data: any[]): LegislativeDocument[] {
    return data.map(item => this.transformApiDocument(item));
  }
  
  private transformApiDocument(item: any): LegislativeDocument {
    return {
      id: item.id || item._id,
      title: item.title,
      summary: item.summary || item.description,
      type: item.type || item.document_type,
      date: new Date(item.date || item.created_at),
      keywords: item.keywords || item.tags || [],
      state: item.state || item.estado,
      municipality: item.municipality || item.municipio,
      url: item.url || item.link,
      status: item.status || 'em_tramitacao',
      author: item.author || item.autor,
      chamber: item.chamber || item.camara
    };
  }
}

// Export singleton instance
export const legislativeDataService = LegislativeDataService.getInstance();