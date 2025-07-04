/**
 * Vocabulary Service for SKOS API Integration
 * Provides methods to interact with the vocabulary management API
 */
import { API_ENDPOINTS, buildApiUrl, API_CONFIG } from '../config/api';
import {
  Concept,
  ConceptSearchResult,
  ConceptHierarchy,
  QueryExpansion,
  ConceptSchemeOverview,
  VocabularyHealth
} from '../types';

export class VocabularyService {
  private baseUrl: string;
  private headers: Record<string, string>;

  constructor() {
    this.baseUrl = API_CONFIG.baseUrl;
    this.headers = API_CONFIG.headers;
  }

  /**
   * Search for concepts with fuzzy matching and ranking
   */
  async searchConcepts(
    query: string,
    lang: string = 'pt',
    limit: number = 20,
    conceptScheme?: string
  ): Promise<ConceptSearchResult[]> {
    const params: Record<string, string> = {
      query,
      lang,
      limit: limit.toString()
    };

    if (conceptScheme) {
      params.concept_scheme = conceptScheme;
    }

    const url = buildApiUrl(API_ENDPOINTS.vocabulary.search, params);

    try {
      const response = await fetch(url, {
        method: 'GET',
        headers: this.headers,
        signal: AbortSignal.timeout(API_CONFIG.timeout)
      });

      if (!response.ok) {
        throw new Error(`Vocabulary search failed: ${response.status}`);
      }

      const data = await response.json();
      return this.transformSearchResults(data);
    } catch (error) {
      console.error('Error searching concepts:', error);
      throw new Error(`Failed to search concepts: ${error}`);
    }
  }

  /**
   * Get hierarchical information for a concept
   */
  async getConceptHierarchy(conceptUri: string): Promise<ConceptHierarchy | null> {
    const encodedUri = encodeURIComponent(conceptUri);
    const url = buildApiUrl(`${API_ENDPOINTS.vocabulary.concept}/${encodedUri}`);

    try {
      const response = await fetch(url, {
        method: 'GET',
        headers: this.headers,
        signal: AbortSignal.timeout(API_CONFIG.timeout)
      });

      if (response.status === 404) {
        return null;
      }

      if (!response.ok) {
        throw new Error(`Failed to get concept hierarchy: ${response.status}`);
      }

      const data = await response.json();
      return this.transformHierarchyData(data);
    } catch (error) {
      console.error('Error getting concept hierarchy:', error);
      throw new Error(`Failed to get concept hierarchy: ${error}`);
    }
  }

  /**
   * Get broader concepts (direct or transitive)
   */
  async getBroaderConcepts(conceptUri: string, transitive: boolean = false): Promise<Concept[]> {
    const encodedUri = encodeURIComponent(conceptUri);
    const params = { transitive: transitive.toString() };
    const url = buildApiUrl(
      API_ENDPOINTS.vocabulary.broader.replace('{concept_uri}', encodedUri),
      params
    );

    try {
      const response = await fetch(url, {
        method: 'GET',
        headers: this.headers,
        signal: AbortSignal.timeout(API_CONFIG.timeout)
      });

      if (!response.ok) {
        throw new Error(`Failed to get broader concepts: ${response.status}`);
      }

      const data = await response.json();
      return this.transformConceptsArray(data);
    } catch (error) {
      console.error('Error getting broader concepts:', error);
      throw new Error(`Failed to get broader concepts: ${error}`);
    }
  }

  /**
   * Get narrower concepts (direct or transitive)
   */
  async getNarrowerConcepts(conceptUri: string, transitive: boolean = false): Promise<Concept[]> {
    const encodedUri = encodeURIComponent(conceptUri);
    const params = { transitive: transitive.toString() };
    const url = buildApiUrl(
      API_ENDPOINTS.vocabulary.narrower.replace('{concept_uri}', encodedUri),
      params
    );

    try {
      const response = await fetch(url, {
        method: 'GET',
        headers: this.headers,
        signal: AbortSignal.timeout(API_CONFIG.timeout)
      });

      if (!response.ok) {
        throw new Error(`Failed to get narrower concepts: ${response.status}`);
      }

      const data = await response.json();
      return this.transformConceptsArray(data);
    } catch (error) {
      console.error('Error getting narrower concepts:', error);
      throw new Error(`Failed to get narrower concepts: ${error}`);
    }
  }

  /**
   * Get related concepts
   */
  async getRelatedConcepts(conceptUri: string): Promise<Concept[]> {
    const encodedUri = encodeURIComponent(conceptUri);
    const url = buildApiUrl(
      API_ENDPOINTS.vocabulary.related.replace('{concept_uri}', encodedUri)
    );

    try {
      const response = await fetch(url, {
        method: 'GET',
        headers: this.headers,
        signal: AbortSignal.timeout(API_CONFIG.timeout)
      });

      if (!response.ok) {
        throw new Error(`Failed to get related concepts: ${response.status}`);
      }

      const data = await response.json();
      return this.transformConceptsArray(data);
    } catch (error) {
      console.error('Error getting related concepts:', error);
      throw new Error(`Failed to get related concepts: ${error}`);
    }
  }

  /**
   * Expand query using vocabulary relationships
   */
  async expandQuery(
    query: string,
    expansionTypes: string[] = ['narrower', 'broader', 'related', 'synonyms'],
    maxExpansions: number = 10
  ): Promise<QueryExpansion> {
    const url = buildApiUrl(API_ENDPOINTS.vocabulary.expandQuery);

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          ...this.headers,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          query,
          expansion_types: expansionTypes,
          max_expansions: maxExpansions
        }),
        signal: AbortSignal.timeout(API_CONFIG.timeout)
      });

      if (!response.ok) {
        throw new Error(`Failed to expand query: ${response.status}`);
      }

      const data = await response.json();
      return {
        original: data.original || [],
        narrower: data.narrower || [],
        broader: data.broader || [],
        related: data.related || [],
        synonyms: data.synonyms || []
      };
    } catch (error) {
      console.error('Error expanding query:', error);
      throw new Error(`Failed to expand query: ${error}`);
    }
  }

  /**
   * Get all concept schemes overview
   */
  async getAllConceptSchemes(): Promise<ConceptSchemeOverview[]> {
    const url = buildApiUrl(API_ENDPOINTS.vocabulary.schemes);

    try {
      const response = await fetch(url, {
        method: 'GET',
        headers: this.headers,
        signal: AbortSignal.timeout(API_CONFIG.timeout)
      });

      if (!response.ok) {
        throw new Error(`Failed to get concept schemes: ${response.status}`);
      }

      const data = await response.json();
      return this.transformSchemesArray(data);
    } catch (error) {
      console.error('Error getting concept schemes:', error);
      throw new Error(`Failed to get concept schemes: ${error}`);
    }
  }

  /**
   * Get specific concept scheme overview
   */
  async getConceptSchemeOverview(schemeName: string): Promise<ConceptSchemeOverview | null> {
    const url = buildApiUrl(`${API_ENDPOINTS.vocabulary.scheme}/${schemeName}`);

    try {
      const response = await fetch(url, {
        method: 'GET',
        headers: this.headers,
        signal: AbortSignal.timeout(API_CONFIG.timeout)
      });

      if (response.status === 404) {
        return null;
      }

      if (!response.ok) {
        throw new Error(`Failed to get scheme overview: ${response.status}`);
      }

      const data = await response.json();
      return this.transformSchemeData(data);
    } catch (error) {
      console.error('Error getting scheme overview:', error);
      throw new Error(`Failed to get scheme overview: ${error}`);
    }
  }

  /**
   * Get vocabulary service health status
   */
  async getVocabularyHealth(): Promise<VocabularyHealth> {
    const url = buildApiUrl(API_ENDPOINTS.vocabulary.health);

    try {
      const response = await fetch(url, {
        method: 'GET',
        headers: this.headers,
        signal: AbortSignal.timeout(API_CONFIG.timeout)
      });

      if (!response.ok) {
        throw new Error(`Failed to get vocabulary health: ${response.status}`);
      }

      const data = await response.json();
      return {
        status: data.status || 'unknown',
        service: data.service || 'vocabulary_management',
        components: data.components || {},
        dataCoverage: {
          totalConcepts: data.data_coverage?.total_concepts || 0,
          conceptSchemes: data.data_coverage?.concept_schemes || 0,
          languagesSupported: data.data_coverage?.languages_supported || [],
          relationshipTypes: data.data_coverage?.relationship_types || []
        },
        performance: {
          labelIndexSize: data.performance?.label_index_size || 0,
          averageHierarchyDepth: data.performance?.average_hierarchy_depth || 0
        }
      };
    } catch (error) {
      console.error('Error getting vocabulary health:', error);
      throw new Error(`Failed to get vocabulary health: ${error}`);
    }
  }

  // Private transformation methods
  private transformSearchResults(data: any[]): ConceptSearchResult[] {
    return data.map(item => ({
      concept: this.transformConcept(item.concept),
      matchType: item.match_type || item.matchType || '',
      score: item.score || 0,
      matchedLabel: item.matched_label || item.matchedLabel || '',
      context: item.context
    }));
  }

  private transformHierarchyData(data: any): ConceptHierarchy {
    return {
      concept: this.transformConcept(data.concept),
      path: data.path || [],
      children: (data.children || []).map((child: any) => this.transformConcept(child)),
      parent: data.parent ? this.transformConcept(data.parent) : undefined,
      siblings: (data.siblings || []).map((sibling: any) => this.transformConcept(sibling)),
      depth: data.depth || 0,
      isRoot: data.is_root || data.isRoot || false,
      isLeaf: data.is_leaf || data.isLeaf || false
    };
  }

  private transformConceptsArray(data: any[]): Concept[] {
    return data.map(item => this.transformConcept(item));
  }

  private transformConcept(data: any): Concept {
    return {
      uri: data.uri || '',
      prefLabel: data.pref_label || data.prefLabel || {},
      altLabels: data.alt_labels || data.altLabels || {},
      definition: data.definition || {},
      conceptScheme: data.concept_scheme || data.conceptScheme,
      broader: data.broader || [],
      narrower: data.narrower || [],
      related: data.related || [],
      notation: data.notation
    };
  }

  private transformSchemesArray(data: any[]): ConceptSchemeOverview[] {
    return data.map(item => this.transformSchemeData(item));
  }

  private transformSchemeData(data: any): ConceptSchemeOverview {
    return {
      scheme: data.scheme || '',
      totalConcepts: data.total_concepts || data.totalConcepts || 0,
      maxDepth: data.max_depth || data.maxDepth || 0,
      rootConcepts: data.root_concepts || data.rootConcepts || [],
      topLevelCategories: data.top_level_categories || data.topLevelCategories || 0
    };
  }
}

// Export singleton instance
export const vocabularyService = new VocabularyService();