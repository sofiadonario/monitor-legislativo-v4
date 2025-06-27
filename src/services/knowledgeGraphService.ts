import { API_CONFIG } from '../config/api';

export interface GraphNode {
  id: string;
  name: string;
  type: string;
  size: number;
  centrality: number;
  metadata: any;
}

export interface GraphEdge {
  source: string;
  target: string;
  weight: number;
  type: string;
  confidence: number;
  metadata: any;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  statistics: {
    nodes: number;
    edges: number;
    density: number;
    connected_components: number;
    node_types: Record<string, number>;
    relationship_types: Record<string, number>;
    top_central_nodes: Array<{
      id: string;
      name: string;
      centrality: number;
    }>;
  };
}

export interface EntityData {
  name: string;
  type: string;
  confidence: number;
  context: string;
  positions: number[];
  metadata: any;
}

export interface EntitySummary {
  total_entities: number;
  by_type: Record<string, number>;
  top_entities: Array<{
    name: string;
    type: string;
    count: number;
  }>;
  confidence_stats: {
    mean: number;
    min: number;
    max: number;
  };
}

export interface KnowledgeGraphResponse {
  success: boolean;
  message?: string;
  data: GraphData;
  query: string;
  document_count: number;
}

export interface EntityExtractionResponse {
  success: boolean;
  data: {
    entities: EntityData[];
    summary: EntitySummary;
    document_count: number;
  };
  query: string;
}

export interface NodeDetailsResponse {
  success: boolean;
  data: {
    node: {
      id: string;
      name: string;
      type: string;
      properties: any;
      neighbor_count: number;
      neighbors: Array<{
        id: string;
        name: string;
        type: string;
        relationship: string;
        weight: number;
        confidence: number;
      }>;
    };
  };
}

export interface NodeSearchResponse {
  success: boolean;
  data: {
    nodes: Array<{
      id: string;
      name: string;
      type: string;
      centrality: number;
      document_count: number;
      relevance_score: number;
    }>;
    total: number;
    query: string;
  };
}

export interface PathResponse {
  success: boolean;
  data: {
    path: Array<{
      id: string;
      name: string;
      type: string;
      step: number;
      edge_to_next?: {
        relationship: string;
        weight: number;
        confidence: number;
      };
    }>;
    length: number;
    source: string;
    target: string;
  };
}

export interface SubgraphResponse {
  success: boolean;
  data: {
    nodes: Array<{
      id: string;
      name: string;
      type: string;
      centrality: number;
      is_center: boolean;
      metadata: any;
    }>;
    edges: Array<{
      source: string;
      target: string;
      relationship: string;
      weight: number;
      confidence: number;
    }>;
    center_node: string;
    radius: number;
    total_nodes: number;
    total_edges: number;
  };
}

class KnowledgeGraphService {
  private baseUrl: string;

  constructor() {
    this.baseUrl = `${API_CONFIG.baseUrl}/api/v1/knowledge-graph`;
  }

  async buildKnowledgeGraph(
    query: string, 
    maxDocuments: number = 50, 
    sources: string = 'lexml'
  ): Promise<KnowledgeGraphResponse> {
    const url = new URL(`${this.baseUrl}/build`);
    url.searchParams.append('query', query);
    url.searchParams.append('max_documents', maxDocuments.toString());
    url.searchParams.append('sources', sources);

    const response = await fetch(url.toString(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
    }

    return response.json();
  }

  async getGraphStatistics(): Promise<{ success: boolean; data: any }> {
    const url = `${this.baseUrl}/statistics`;

    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
    }

    return response.json();
  }

  async exportGraphData(): Promise<{ success: boolean; data: GraphData }> {
    const url = `${this.baseUrl}/export`;

    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
    }

    return response.json();
  }

  async extractEntities(
    query: string, 
    maxDocuments: number = 10
  ): Promise<EntityExtractionResponse> {
    const url = new URL(`${this.baseUrl}/entities/extract`);
    url.searchParams.append('query', query);
    url.searchParams.append('max_documents', maxDocuments.toString());

    const response = await fetch(url.toString(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
    }

    return response.json();
  }

  async getNodeDetails(nodeId: string): Promise<NodeDetailsResponse> {
    const url = `${this.baseUrl}/nodes/${encodeURIComponent(nodeId)}`;

    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
    }

    return response.json();
  }

  async searchNodes(
    query: string, 
    nodeType?: string, 
    limit: number = 20
  ): Promise<NodeSearchResponse> {
    const url = new URL(`${this.baseUrl}/search/nodes`);
    url.searchParams.append('q', query);
    if (nodeType) {
      url.searchParams.append('node_type', nodeType);
    }
    url.searchParams.append('limit', limit.toString());

    const response = await fetch(url.toString(), {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
    }

    return response.json();
  }

  async findShortestPath(
    sourceId: string, 
    targetId: string
  ): Promise<PathResponse> {
    const url = `${this.baseUrl}/path/${encodeURIComponent(sourceId)}/${encodeURIComponent(targetId)}`;

    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
    }

    return response.json();
  }

  async getSubgraph(
    centerNode: string, 
    radius: number = 2, 
    maxNodes: number = 50
  ): Promise<SubgraphResponse> {
    const url = new URL(`${this.baseUrl}/subgraph`);
    url.searchParams.append('center_node', centerNode);
    url.searchParams.append('radius', radius.toString());
    url.searchParams.append('max_nodes', maxNodes.toString());

    const response = await fetch(url.toString(), {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
    }

    return response.json();
  }
}

export const knowledgeGraphService = new KnowledgeGraphService();