/**
 * Knowledge Graph Service - Frontend interface for legislative knowledge graph
 * Integrates with the backend knowledge graph API for entity extraction and relationship mapping
 */

import { API_BASE_URL } from '../config/api';
import { LegislativeDocument } from '../types';

// Types matching backend API
export enum EntityType {
  PERSON = 'person',
  ORGANIZATION = 'organization',
  LOCATION = 'location',
  LAW = 'law',
  REGULATION = 'regulation',
  CONCEPT = 'concept',
  DATE = 'date',
  MONETARY = 'monetary',
  TRANSPORT_MODE = 'transport_mode',
  AGENCY = 'agency'
}

export enum RelationshipType {
  CITES = 'cites',
  MENTIONS = 'mentions',
  RELATES_TO = 'relates_to',
  MODIFIES = 'modifies',
  IMPLEMENTS = 'implements',
  SUPERSEDES = 'supersedes',
  INFLUENCES = 'influences',
  GOVERNS = 'governs',
  LOCATED_IN = 'located_in',
  REGULATED_BY = 'regulated_by'
}

export enum GraphMetricType {
  CENTRALITY = 'centrality',
  CLUSTERING = 'clustering',
  CONNECTIVITY = 'connectivity',
  INFLUENCE = 'influence'
}

export interface Entity {
  id: string;
  name: string;
  type: EntityType;
  mentions: number;
  confidence: number;
  context: string[];
  properties: Record<string, any>;
  document_ids: string[];
}

export interface Relationship {
  id: string;
  source_entity_id: string;
  target_entity_id: string;
  type: RelationshipType;
  confidence: number;
  context: string;
  document_id: string;
  properties: Record<string, any>;
}

export interface GraphCluster {
  id: string;
  name: string;
  entities: string[];
  coherence_score: number;
  topics: string[];
  summary: string;
}

export interface GraphInsight {
  id: string;
  type: string;
  description: string;
  entities: string[];
  relationships: string[];
  significance: number;
  evidence: Record<string, any>;
}

export interface DocumentInput {
  id: string;
  title: string;
  content: string;
  date?: string;
  source?: string;
  metadata?: Record<string, any>;
}

export interface EntityExtractionRequest {
  documents: DocumentInput[];
  entity_types?: EntityType[];
  min_confidence?: number;
  extract_relationships?: boolean;
}

export interface GraphAnalysisRequest {
  entities?: string[];
  analysis_types?: GraphMetricType[];
  include_clusters?: boolean;
  include_insights?: boolean;
}

export interface KnowledgeGraphResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  processing_time?: number;
  stats?: Record<string, any>;
}

export interface EntityExtractionResult {
  entities: Entity[];
  relationships: Relationship[];
  total_entities: number;
  total_relationships: number;
}

export interface GraphAnalysisResult {
  analysis: Record<string, any>;
  clusters: GraphCluster[];
  insights: GraphInsight[];
}

export interface GraphVisualizationData {
  nodes: Array<{
    id: string;
    data: Record<string, any>;
  }>;
  edges: Array<{
    source: string;
    target: string;
    data: Record<string, any>;
  }>;
  stats: {
    total_nodes: number;
    total_edges: number;
    displayed_nodes: number;
    displayed_edges: number;
  };
}

export interface GraphHealthStatus {
  status: string;
  networkx_available: boolean;
  entities_count: number;
  relationships_count: number;
  clusters_count: number;
  insights_count: number;
  graph_nodes: number;
  graph_edges: number;
}

/**
 * Knowledge Graph Service Class
 */
class KnowledgeGraphService {
  private baseUrl: string;

  constructor() {
    this.baseUrl = `${API_BASE_URL}/api/v1/knowledge-graph`;
  }

  /**
   * Convert LegislativeDocument to DocumentInput format
   */
  private convertToDocumentInput(document: LegislativeDocument): DocumentInput {
    return {
      id: document.id,
      title: document.title,
      content: document.summary || document.content || '',
      date: document.date,
      source: document.source,
      metadata: {
        type: document.type,
        author: document.author,
        urn: document.urn
      }
    };
  }

  /**
   * Extract entities from legislative documents
   */
  async extractEntities(
    documents: LegislativeDocument[],
    options: {
      entityTypes?: EntityType[];
      minConfidence?: number;
      extractRelationships?: boolean;
    } = {}
  ): Promise<KnowledgeGraphResponse<EntityExtractionResult>> {
    try {
      const documentInputs = documents.map(doc => this.convertToDocumentInput(doc));
      
      const request: EntityExtractionRequest = {
        documents: documentInputs,
        entity_types: options.entityTypes,
        min_confidence: options.minConfidence ?? 0.5,
        extract_relationships: options.extractRelationships ?? true
      };

      const response = await fetch(`${this.baseUrl}/extract-entities`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(request),
      });

      if (!response.ok) {
        throw new Error(`Entity extraction failed: ${response.statusText}`);
      }

      const result: KnowledgeGraphResponse<EntityExtractionResult> = await response.json();
      
      // Log extraction statistics
      if (result.success && result.data && result.stats) {
        console.log('Entity Extraction Results:', {
          'Documents Processed': result.stats.documents_processed,
          'Entities Found': result.data.total_entities,
          'Relationships Found': result.data.total_relationships,
          'Entities per Document': result.stats.entities_per_document?.toFixed(2),
          'Processing Time': `${result.processing_time?.toFixed(2)}s`
        });
      }

      return result;
    } catch (error) {
      console.error('Entity extraction failed:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      };
    }
  }

  /**
   * Perform graph analysis operations
   */
  async analyzeGraph(
    options: {
      entities?: string[];
      analysisTypes?: GraphMetricType[];
      includeClusters?: boolean;
      includeInsights?: boolean;
    } = {}
  ): Promise<KnowledgeGraphResponse<GraphAnalysisResult>> {
    try {
      const request: GraphAnalysisRequest = {
        entities: options.entities,
        analysis_types: options.analysisTypes,
        include_clusters: options.includeClusters ?? true,
        include_insights: options.includeInsights ?? true
      };

      const response = await fetch(`${this.baseUrl}/analyze-graph`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(request),
      });

      if (!response.ok) {
        throw new Error(`Graph analysis failed: ${response.statusText}`);
      }

      const result: KnowledgeGraphResponse<GraphAnalysisResult> = await response.json();
      
      // Log analysis results
      if (result.success && result.data) {
        console.log('Graph Analysis Results:', {
          'Clusters Found': result.data.clusters.length,
          'Insights Generated': result.data.insights.length,
          'Processing Time': `${result.processing_time?.toFixed(2)}s`
        });
      }

      return result;
    } catch (error) {
      console.error('Graph analysis failed:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      };
    }
  }

  /**
   * Get graph data for visualization
   */
  async getVisualizationData(maxNodes: number = 100): Promise<KnowledgeGraphResponse<GraphVisualizationData>> {
    try {
      const response = await fetch(`${this.baseUrl}/visualization-data?max_nodes=${maxNodes}`);
      
      if (!response.ok) {
        throw new Error(`Failed to get visualization data: ${response.statusText}`);
      }

      const result: KnowledgeGraphResponse<GraphVisualizationData> = await response.json();
      
      if (result.success && result.data) {
        console.log('Graph Visualization Data:', {
          'Nodes': result.data.stats.displayed_nodes,
          'Edges': result.data.stats.displayed_edges,
          'Total Nodes': result.data.stats.total_nodes,
          'Total Edges': result.data.stats.total_edges
        });
      }

      return result;
    } catch (error) {
      console.error('Failed to get visualization data:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      };
    }
  }

  /**
   * Get knowledge graph health status
   */
  async getHealthStatus(): Promise<GraphHealthStatus | null> {
    try {
      const response = await fetch(`${this.baseUrl}/health`);
      
      if (!response.ok) {
        throw new Error(`Health check failed: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Knowledge graph health check failed:', error);
      return null;
    }
  }

  /**
   * Build knowledge graph from documents (combines extraction and analysis)
   */
  async buildKnowledgeGraph(
    documents: LegislativeDocument[],
    options: {
      entityTypes?: EntityType[];
      minConfidence?: number;
      analysisTypes?: GraphMetricType[];
      maxVisualizationNodes?: number;
    } = {}
  ): Promise<{
    entities: KnowledgeGraphResponse<EntityExtractionResult>;
    analysis: KnowledgeGraphResponse<GraphAnalysisResult>;
    visualization: KnowledgeGraphResponse<GraphVisualizationData>;
  }> {
    console.log(`Building knowledge graph from ${documents.length} documents...`);
    
    // Step 1: Extract entities and relationships
    const entities = await this.extractEntities(documents, {
      entityTypes: options.entityTypes,
      minConfidence: options.minConfidence,
      extractRelationships: true
    });

    // Step 2: Analyze the graph
    const analysis = await this.analyzeGraph({
      analysisTypes: options.analysisTypes,
      includeClusters: true,
      includeInsights: true
    });

    // Step 3: Get visualization data
    const visualization = await this.getVisualizationData(options.maxVisualizationNodes);

    return {
      entities,
      analysis,
      visualization
    };
  }

  /**
   * Search entities by name or type
   */
  async searchEntities(
    query: string,
    entityType?: EntityType,
    minConfidence: number = 0.5
  ): Promise<Entity[]> {
    // This would need to be implemented on the backend
    // For now, return empty array
    console.log(`Searching entities with query: "${query}", type: ${entityType}`);
    return [];
  }

  /**
   * Get entities by document ID
   */
  async getEntitiesByDocument(documentId: string): Promise<Entity[]> {
    // This would need to be implemented on the backend
    // For now, return empty array
    console.log(`Getting entities for document: ${documentId}`);
    return [];
  }

  /**
   * Get relationships for specific entities
   */
  async getEntityRelationships(entityIds: string[]): Promise<Relationship[]> {
    // This would need to be implemented on the backend
    // For now, return empty array
    console.log(`Getting relationships for entities: ${entityIds.join(', ')}`);
    return [];
  }

  /**
   * Find shortest path between two entities
   */
  async findShortestPath(sourceEntityId: string, targetEntityId: string): Promise<{
    path: string[];
    relationships: Relationship[];
    distance: number;
  } | null> {
    // This would need to be implemented on the backend
    console.log(`Finding path from ${sourceEntityId} to ${targetEntityId}`);
    return null;
  }

  /**
   * Get influential entities (high centrality)
   */
  async getInfluentialEntities(limit: number = 10): Promise<Array<{
    entity: Entity;
    centrality_score: number;
    influence_metrics: Record<string, number>;
  }>> {
    // This would need to be implemented on the backend
    console.log(`Getting top ${limit} influential entities`);
    return [];
  }

  /**
   * Get entity clusters
   */
  async getClusters(): Promise<GraphCluster[]> {
    const analysisResult = await this.analyzeGraph({
      includeClusters: true,
      includeInsights: false
    });

    if (analysisResult.success && analysisResult.data) {
      return analysisResult.data.clusters;
    }

    return [];
  }

  /**
   * Get graph insights
   */
  async getInsights(): Promise<GraphInsight[]> {
    const analysisResult = await this.analyzeGraph({
      includeClusters: false,
      includeInsights: true
    });

    if (analysisResult.success && analysisResult.data) {
      return analysisResult.data.insights;
    }

    return [];
  }

  /**
   * Check if knowledge graph is available and healthy
   */
  async isAvailable(): Promise<boolean> {
    const health = await this.getHealthStatus();
    return health?.status === 'healthy' && health?.networkx_available === true;
  }

  /**
   * Get graph statistics
   */
  async getGraphStatistics(): Promise<{
    nodeCount: number;
    edgeCount: number;
    entityTypes: Record<EntityType, number>;
    relationshipTypes: Record<RelationshipType, number>;
    density: number;
    components: number;
  } | null> {
    const health = await this.getHealthStatus();
    if (!health) return null;

    // This would need additional backend endpoints for detailed statistics
    return {
      nodeCount: health.graph_nodes,
      edgeCount: health.graph_edges,
      entityTypes: {} as Record<EntityType, number>,
      relationshipTypes: {} as Record<RelationshipType, number>,
      density: 0,
      components: 0
    };
  }

  /**
   * Export knowledge graph data
   */
  async exportGraph(format: 'json' | 'gexf' | 'graphml' = 'json'): Promise<Blob | null> {
    try {
      const visualizationData = await this.getVisualizationData(1000); // Get more nodes for export
      
      if (!visualizationData.success || !visualizationData.data) {
        return null;
      }

      const data = visualizationData.data;
      
      if (format === 'json') {
        const jsonData = JSON.stringify(data, null, 2);
        return new Blob([jsonData], { type: 'application/json' });
      }

      // Other formats would need backend implementation
      console.warn(`Export format ${format} not yet implemented`);
      return null;

    } catch (error) {
      console.error('Graph export failed:', error);
      return null;
    }
  }
}

// Create and export singleton instance
export const knowledgeGraphService = new KnowledgeGraphService();

// Export types and service
export default knowledgeGraphService;