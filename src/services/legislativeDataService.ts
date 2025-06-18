import { LegislativeDocument, SearchFilters } from '../types';
import { mockLegislativeData } from '../data/mock-legislative-data';
import apiClient, { ApiError } from './apiClient';

// Check if we're in development/testing mode
const isDevelopment = import.meta.env.MODE === 'development';
const isTestEnvironment = import.meta.env.MODE === 'test';
const useMockData = import.meta.env.VITE_USE_MOCK_DATA === 'true';

export class LegislativeDataService {
  private static instance: LegislativeDataService;
  
  private constructor() {}
  
  static getInstance(): LegislativeDataService {
    if (!LegislativeDataService.instance) {
      LegislativeDataService.instance = new LegislativeDataService();
    }
    return LegislativeDataService.instance;
  }
  
  async fetchDocuments(filters?: SearchFilters): Promise<LegislativeDocument[]> {
    if (useMockData) {
      // Use mock data for development/testing
      console.log('Using mock data for development/testing');
      return this.filterMockData(mockLegislativeData, filters);
    }
    
    try {
      // Real API call
      const params = this.buildQueryParams(filters);
      const data = await apiClient.get<any[]>('/documents', params);
      return this.transformApiResponse(data);
    } catch (error) {
      console.warn('API not available, falling back to mock data:', error);
      
      // Always fallback to mock data if API fails (for academic/demo purposes)
      return this.filterMockData(mockLegislativeData, filters);
    }
  }
  
  async fetchDocumentById(id: string): Promise<LegislativeDocument | null> {
    if (useMockData) {
      return mockLegislativeData.find(doc => doc.id === id) || null;
    }
    
    try {
      const data = await apiClient.get<any>(`/documents/${id}`);
      return this.transformApiDocument(data);
    } catch (error) {
      if (error instanceof ApiError && error.statusCode === 404) {
        return null;
      }
      
      console.warn('API not available, falling back to mock data:', error);
      
      // Always fallback to mock data if API fails (for academic/demo purposes)
      return mockLegislativeData.find(doc => doc.id === id) || null;
    }
  }
  
  async searchDocuments(searchTerm: string): Promise<LegislativeDocument[]> {
    if (useMockData) {
      const lowerSearchTerm = searchTerm.toLowerCase();
      return mockLegislativeData.filter(doc => 
        doc.title.toLowerCase().includes(lowerSearchTerm) ||
        doc.summary.toLowerCase().includes(lowerSearchTerm) ||
        doc.keywords.some(keyword => keyword.toLowerCase().includes(lowerSearchTerm))
      );
    }
    
    try {
      const data = await apiClient.get<any[]>('/documents/search', { q: searchTerm });
      return this.transformApiResponse(data);
    } catch (error) {
      console.warn('Search API not available, falling back to mock data:', error);
      
      // Always fallback to mock data search if API fails
      const lowerSearchTerm = searchTerm.toLowerCase();
      return mockLegislativeData.filter(doc => 
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