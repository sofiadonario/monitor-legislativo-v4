import { loadCSVLegislativeData } from '../data/csv-legislative-data';
import { LegislativeDocument, SearchFilters } from '../types';
import apiClient from './apiClient';

// Force CSV-only mode - no mock data
const forceCSVOnly = true;

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
  
  private async getLocalCsvData(): Promise<{ documents: LegislativeDocument[], usingFallback: boolean }> {
    if (this.csvDataCache) {
      console.log('Using cached CSV data.');
      return { documents: this.csvDataCache, usingFallback: true };
    }

    try {
      console.log('Attempting to load CSV legislative data...');
      const csvDocs = await loadCSVLegislativeData();
      if (csvDocs.length > 0) {
        console.log(`Loaded ${csvDocs.length} documents from CSV`);
        this.csvDataCache = csvDocs;
        return { documents: csvDocs, usingFallback: true };
      }
      // If CSV is empty, it's a failure condition
      throw new Error('CSV file was loaded but contained no documents.');
    } catch (error) {
      console.error('Critical error: Failed to load or parse CSV data.', error);
      // Return empty array and let the UI handle the error state
      return { documents: [], usingFallback: true };
    }
  }
  
  async fetchDocuments(filters?: SearchFilters): Promise<{ documents: LegislativeDocument[], usingFallback: boolean }> {
    if (forceCSVOnly) {
      console.log('Force CSV-only mode. Using local CSV file exclusively.');
      const localData = await this.getLocalCsvData();
      return { documents: this.filterLocalData(localData.documents, filters), usingFallback: localData.usingFallback };
    }
    
    try {
      console.log('Attempting to fetch documents from API...');
      const params = this.buildQueryParams(filters);
      const data = await apiClient.get<any[]>('/documents', params);
      console.log(`Successfully fetched ${data.length} documents from API.`);
      return { documents: this.transformApiResponse(data), usingFallback: false };
    } catch (error) {
      console.warn('API fetch failed, falling back to local CSV data:', error);
      const localData = await this.getLocalCsvData();
      return { documents: this.filterLocalData(localData.documents, filters), usingFallback: localData.usingFallback };
    }
  }
  
  async fetchDocumentById(id: string): Promise<LegislativeDocument | null> {
    const allDocs = await this.fetchDocuments();
    return allDocs.documents.find(doc => doc.id === id) || null;
  }
  
  async searchDocuments(searchTerm: string): Promise<LegislativeDocument[]> {
    const allDocs = await this.fetchDocuments();
    const lowerSearchTerm = searchTerm.toLowerCase();
    return allDocs.documents.filter(doc => 
      doc.title.toLowerCase().includes(lowerSearchTerm) ||
      doc.summary.toLowerCase().includes(lowerSearchTerm) ||
      (doc.keywords && doc.keywords.some(keyword => keyword.toLowerCase().includes(lowerSearchTerm)))
    );
  }
  
  private filterLocalData(data: LegislativeDocument[], filters?: SearchFilters): LegislativeDocument[] {
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