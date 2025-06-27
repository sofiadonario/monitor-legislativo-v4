import { API_CONFIG } from '../config/api';

export interface Concept {
  uri: string;
  pref_label: Record<string, string>;
  alt_labels: Record<string, string[]>;
  definition: Record<string, string>;
  concept_scheme?: string;
  broader: string[];
  narrower: string[];
  related: string[];
  notation?: string;
}

export interface SearchResult {
  concept: Concept;
  match_type: string;
  score: number;
  matched_label: string;
  context?: string;
}

export interface ConceptHierarchy {
  concept: Concept;
  path: string[];
  children: Concept[];
  parent?: Concept;
  siblings: Concept[];
  depth: number;
  is_root: boolean;
  is_leaf: boolean;
}

export interface QueryExpansion {
  original: string[];
  narrower: string[];
  broader: string[];
  related: string[];
  synonyms: string[];
}

export interface SchemeOverview {
  scheme: string;
  total_concepts: number;
  max_depth: number;
  root_concepts: Array<{
    uri: string;
    label: string;
    children_count: number;
  }>;
  top_level_categories: number;
}

class VocabularyService {
  private baseUrl: string;

  constructor() {
    this.baseUrl = `${API_CONFIG.baseUrl}/api/v1/vocabulary`;
  }

  async searchConcepts(
    query: string,
    lang: string = 'pt',
    limit: number = 20,
    conceptScheme?: string
  ): Promise<SearchResult[]> {
    try {
      const params = new URLSearchParams({
        query,
        lang,
        limit: limit.toString(),
      });

      if (conceptScheme) {
        params.append('concept_scheme', conceptScheme);
      }

      const response = await fetch(`${this.baseUrl}/search?${params}`, {
        method: 'GET',
      });

      if (!response.ok) {
        throw new Error(`Concept search failed: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error searching concepts:', error);
      throw error;
    }
  }

  async getConceptHierarchy(conceptUri: string): Promise<ConceptHierarchy> {
    try {
      const encodedUri = encodeURIComponent(conceptUri);
      const response = await fetch(`${this.baseUrl}/concept/${encodedUri}`, {
        method: 'GET',
      });

      if (!response.ok) {
        throw new Error(`Failed to get concept hierarchy: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error getting concept hierarchy:', error);
      throw error;
    }
  }

  async getBroaderConcepts(conceptUri: string, transitive: boolean = false): Promise<Concept[]> {
    try {
      const encodedUri = encodeURIComponent(conceptUri);
      const params = new URLSearchParams({
        transitive: transitive.toString(),
      });

      const response = await fetch(`${this.baseUrl}/concept/${encodedUri}/broader?${params}`, {
        method: 'GET',
      });

      if (!response.ok) {
        throw new Error(`Failed to get broader concepts: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error getting broader concepts:', error);
      throw error;
    }
  }

  async getNarrowerConcepts(conceptUri: string, transitive: boolean = false): Promise<Concept[]> {
    try {
      const encodedUri = encodeURIComponent(conceptUri);
      const params = new URLSearchParams({
        transitive: transitive.toString(),
      });

      const response = await fetch(`${this.baseUrl}/concept/${encodedUri}/narrower?${params}`, {
        method: 'GET',
      });

      if (!response.ok) {
        throw new Error(`Failed to get narrower concepts: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error getting narrower concepts:', error);
      throw error;
    }
  }

  async getRelatedConcepts(conceptUri: string): Promise<Concept[]> {
    try {
      const encodedUri = encodeURIComponent(conceptUri);
      const response = await fetch(`${this.baseUrl}/concept/${encodedUri}/related`, {
        method: 'GET',
      });

      if (!response.ok) {
        throw new Error(`Failed to get related concepts: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error getting related concepts:', error);
      throw error;
    }
  }

  async expandQuery(
    query: string,
    expansionTypes: string[] = ['narrower', 'broader', 'related', 'synonyms'],
    maxExpansions: number = 10
  ): Promise<QueryExpansion> {
    try {
      const params = new URLSearchParams({
        query,
        max_expansions: maxExpansions.toString(),
      });

      expansionTypes.forEach(type => {
        params.append('expansion_types', type);
      });

      const response = await fetch(`${this.baseUrl}/expand-query?${params}`, {
        method: 'POST',
      });

      if (!response.ok) {
        throw new Error(`Query expansion failed: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error expanding query:', error);
      throw error;
    }
  }

  async getAllConceptSchemes(): Promise<SchemeOverview[]> {
    try {
      const response = await fetch(`${this.baseUrl}/schemes`, {
        method: 'GET',
      });

      if (!response.ok) {
        throw new Error(`Failed to get concept schemes: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error getting concept schemes:', error);
      throw error;
    }
  }

  async getConceptSchemeOverview(schemeName: string): Promise<SchemeOverview> {
    try {
      const response = await fetch(`${this.baseUrl}/scheme/${schemeName}`, {
        method: 'GET',
      });

      if (!response.ok) {
        throw new Error(`Failed to get scheme overview: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error getting concept scheme overview:', error);
      throw error;
    }
  }

  async exportSkosRdf(conceptScheme?: string): Promise<{
    format: string;
    scheme: string;
    exported_at: string;
    data: string;
  }> {
    try {
      const params = new URLSearchParams();
      if (conceptScheme) {
        params.append('concept_scheme', conceptScheme);
      }

      const response = await fetch(`${this.baseUrl}/export/skos-rdf?${params}`, {
        method: 'GET',
      });

      if (!response.ok) {
        throw new Error(`SKOS export failed: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error exporting SKOS RDF:', error);
      throw error;
    }
  }

  async getServiceHealth(): Promise<any> {
    try {
      const response = await fetch(`${this.baseUrl}/health`, {
        method: 'GET',
      });

      if (!response.ok) {
        throw new Error(`Health check failed: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error getting service health:', error);
      throw error;
    }
  }

  // Helper method to get concept label in preferred language
  getConceptLabel(concept: Concept, lang: string = 'pt'): string {
    return concept.pref_label[lang] || concept.pref_label['pt'] || concept.uri;
  }

  // Helper method to get concept definition in preferred language
  getConceptDefinition(concept: Concept, lang: string = 'pt'): string {
    return concept.definition[lang] || concept.definition['pt'] || '';
  }

  // Helper method to get alternative labels in preferred language
  getAlternativeLabels(concept: Concept, lang: string = 'pt'): string[] {
    return concept.alt_labels[lang] || concept.alt_labels['pt'] || [];
  }
}

export const vocabularyService = new VocabularyService();