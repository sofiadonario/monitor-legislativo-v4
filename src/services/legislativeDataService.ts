import { loadCSVLegislativeData } from '../data/csv-legislative-data';
import { LegislativeDocument, SearchFilters, DocumentType, DocumentStatus } from '../types';
import apiClient from './apiClient';

// Check environment variables for data source configuration
const forceCSVOnly = import.meta.env.VITE_FORCE_CSV_ONLY === 'true';

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
    if (this.csvDataCache && this.csvDataCache.length > 0) {
      console.log('Using cached real CSV data.');
      return { documents: this.csvDataCache, usingFallback: true };
    }

    try {
      console.log('Attempting to load real CSV legislative data...');
      const csvDocs = await loadCSVLegislativeData();
      if (csvDocs && Array.isArray(csvDocs) && csvDocs.length > 0) {
        console.log(`Loaded ${csvDocs.length} real documents from CSV`);
        this.csvDataCache = csvDocs;
        return { documents: csvDocs, usingFallback: true };
      }
      throw new Error('CSV file was loaded but contained no documents or invalid data.');
    } catch (error) {
      console.error('Critical error: Failed to load or parse real CSV data.', error);
      console.error('🚨 NO MOCK FALLBACK: Academic integrity requires real data sources only');
      // NO MOCK FALLBACK - return empty array to force proper error handling
      throw new Error(`Cannot load legislative data: ${error instanceof Error ? error.message : 'Unknown CSV error'}. Real data source required.`);
    }
  }
  
  async fetchDocuments(filters?: SearchFilters): Promise<{ documents: LegislativeDocument[], usingFallback: boolean }> {
    if (forceCSVOnly) {
      console.log('Force CSV-only mode. Using real CSV data exclusively.');
      try {
        const localData = await this.getLocalCsvData();
        return { documents: this.filterLocalData(localData.documents, filters), usingFallback: localData.usingFallback };
      } catch (error) {
        console.error('Failed to load CSV data in CSV-only mode:', error);
        throw error; // Don't hide CSV loading errors
      }
    }
    
    try {
      console.log('Attempting to fetch documents from real government APIs...');
      const params = this.buildQueryParams(filters);
      const response = await apiClient.get<any>('/search', params);
      const documents = this.transformSearchResponse(response);
      
      if (documents.length === 0) {
        console.warn('API returned no results, falling back to real CSV data');
        const localData = await this.getLocalCsvData();
        return { documents: this.filterLocalData(localData.documents, filters), usingFallback: localData.usingFallback };
      }
      
      console.log(`Successfully fetched ${documents.length} real documents from API.`);
      return { documents: documents, usingFallback: false };
    } catch (error) {
      console.warn('API fetch failed, attempting fallback to real CSV data:', error);
      try {
        const localData = await this.getLocalCsvData();
        return { documents: this.filterLocalData(localData.documents, filters), usingFallback: localData.usingFallback };
      } catch (csvError) {
        console.error('Both API and CSV data sources failed:', { apiError: error, csvError });
        throw new Error('Unable to load legislative data from any real source (API or CSV). Please check data availability.');
      }
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
    
    if (filters.searchTerm) params.q = filters.searchTerm;
    if (filters.states.length > 0) params.states = filters.states.join(',');
    if (filters.dateFrom) params.start_date = this.formatDate(filters.dateFrom);
    if (filters.dateTo) params.end_date = this.formatDate(filters.dateTo);
    
    // Add default sources (can be made configurable later)
    params.sources = 'CAMARA,SENADO,PLANALTO';
    
    return params;
  }
  
  private formatDate(date: Date): string {
    return date.toISOString().split('T')[0]; // YYYY-MM-DD format
  }
  
  private transformSearchResponse(response: any): LegislativeDocument[] {
    if (!response.results || !Array.isArray(response.results)) {
      return [];
    }
    return response.results.map((item: any) => this.transformProposition(item));
  }
  
  private transformProposition(prop: any): LegislativeDocument {
    // Map backend Proposition to frontend LegislativeDocument
    const documentTypeMap: Record<string, DocumentType> = {
      'PL': 'projeto_lei',
      'PLP': 'projeto_lei',
      'PEC': 'projeto_lei',
      'MPV': 'medida_provisoria',
      'PLV': 'projeto_lei',
      'PDL': 'decreto',
      'PRC': 'resolucao',
      'DECRETO': 'decreto',
      'PORTARIA': 'portaria',
      'RESOLUCAO': 'resolucao',
      'INSTRUCAO_NORMATIVA': 'instrucao_normativa',
      'LEI': 'lei'
    };
    
    const statusMap: Record<string, DocumentStatus> = {
      'ACTIVE': 'em_tramitacao',
      'APPROVED': 'aprovado',
      'REJECTED': 'rejeitado',
      'ARCHIVED': 'arquivado',
      'WITHDRAWN': 'arquivado',
      'PUBLISHED': 'sancionado'
    };
    
    // Extract state from authors if available
    let state = '';
    if (prop.authors && Array.isArray(prop.authors) && prop.authors.length > 0) {
      state = prop.authors[0].state || '';
    }
    
    return {
      id: prop.id,
      title: prop.title,
      summary: prop.summary || '',
      type: documentTypeMap[prop.type] || 'projeto_lei',
      date: prop.publication_date || prop.date || new Date().toISOString(),
      keywords: prop.keywords || [],
      state: state,
      municipality: prop.municipality || '',
      url: prop.url || '',
      status: statusMap[prop.status] || 'em_tramitacao',
      author: prop.authors?.[0]?.name || '',
      chamber: prop.source === 'CAMARA' ? 'Câmara dos Deputados' : prop.source === 'SENADO' ? 'Senado Federal' : '',
      number: prop.number,
      source: prop.source,
      citation: prop.citation
    };
  }
}

// Export singleton instance
export const legislativeDataService = LegislativeDataService.getInstance();