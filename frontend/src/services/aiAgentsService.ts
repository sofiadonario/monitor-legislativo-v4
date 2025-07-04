/**
 * AI Agents Service - Frontend interface for production-ready AI agents
 * Integrates with the backend AI agents API for Brazilian legislative research
 */

import { API_BASE_URL } from '../config/api';

// Types matching backend API
export enum AgentRole {
  RESEARCH_ASSISTANT = 'research_assistant',
  DOCUMENT_ANALYZER = 'document_analyzer',
  CITATION_GENERATOR = 'citation_generator', 
  LEGAL_ADVISOR = 'legal_advisor',
  TREND_ANALYST = 'trend_analyst',
  COMPARATIVE_ANALYST = 'comparative_analyst'
}

export enum AnalysisType {
  SUMMARY = 'summary',
  LEGAL_ANALYSIS = 'legal_analysis',
  TREND_ANALYSIS = 'trend_analysis',
  IMPACT_ASSESSMENT = 'impact_assessment',
  COMPARATIVE_ANALYSIS = 'comparative_analysis',
  CITATION_GENERATION = 'citation_generation'
}

export interface DocumentAnalysisRequest {
  document_content: string;
  document_id: string;
  analysis_type: AnalysisType;
  thread_id: string;
  agent_role: AgentRole;
  include_citations: boolean;
  use_semantic_cache: boolean;
}

export interface CitationRequest {
  document_title: string;
  authors: string[];
  publication_date: string;
  document_urn: string;
  source: string;
  url: string;
  citation_style: string;
}

export interface DocumentAnalysis {
  document_id: string;
  summary: string;
  key_concepts: string[];
  legal_references: string[];
  geographic_scope: string[];
  confidence_score: number;
  processing_cost?: number;
  analysis_type: string;
  timestamp?: string;
}

export interface AgentResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  cost_info?: {
    processing_cost_usd?: number;
    total_cost_usd: number;
    total_api_calls: number;
  };
  cache_info?: {
    cache_hit_rate: string;
    cache_hits?: string;
    cache_misses?: string;
  };
}

export interface AgentHealthStatus {
  agent_manager_available: boolean;
  redis_connected: boolean;
  semantic_cache_enabled: boolean;
  cost_monitoring_active: boolean;
  active_threads: number;
  cache_hit_rate: number;
  total_api_calls: number;
  total_cost_usd: number;
}

export interface ThreadInfo {
  thread_id: string;
  interactions: number;
  last_activity?: number;
}

export interface ThreadsResponse {
  active_threads: number;
  threads: ThreadInfo[];
}

/**
 * AI Agents Service Class
 */
class AIAgentsService {
  private baseUrl: string;
  private currentThreadId: string;

  constructor() {
    this.baseUrl = `${API_BASE_URL}/api/v1/ai-agents`;
    this.currentThreadId = this.generateThreadId();
  }

  /**
   * Generate a unique thread ID for conversation tracking
   */
  private generateThreadId(): string {
    return `thread_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Get or create a thread ID for the current session
   */
  getThreadId(): string {
    if (!this.currentThreadId) {
      this.currentThreadId = this.generateThreadId();
    }
    return this.currentThreadId;
  }

  /**
   * Start a new conversation thread
   */
  startNewThread(): string {
    this.currentThreadId = this.generateThreadId();
    return this.currentThreadId;
  }

  /**
   * Analyze a document using AI with dual-memory architecture
   */
  async analyzeDocument(
    documentContent: string,
    documentId: string,
    analysisType: AnalysisType = AnalysisType.SUMMARY,
    agentRole: AgentRole = AgentRole.DOCUMENT_ANALYZER,
    options: {
      threadId?: string;
      includeCitations?: boolean;
      useSemanticCache?: boolean;
    } = {}
  ): Promise<AgentResponse<DocumentAnalysis>> {
    try {
      const request: DocumentAnalysisRequest = {
        document_content: documentContent,
        document_id: documentId,
        analysis_type: analysisType,
        thread_id: options.threadId || this.getThreadId(),
        agent_role: agentRole,
        include_citations: options.includeCitations ?? true,
        use_semantic_cache: options.useSemanticCache ?? true
      };

      const response = await fetch(`${this.baseUrl}/analyze-document`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(request),
      });

      if (!response.ok) {
        throw new Error(`AI analysis failed: ${response.statusText}`);
      }

      const result: AgentResponse<DocumentAnalysis> = await response.json();
      
      // Log cost information for transparency
      if (result.cost_info) {
        console.log('AI Analysis Cost:', {
          'Processing Cost': `$${result.cost_info.processing_cost_usd?.toFixed(4) || '0.0000'}`,
          'Total Cost': `$${result.cost_info.total_cost_usd.toFixed(4)}`,
          'API Calls': result.cost_info.total_api_calls,
          'Cache Hit Rate': result.cache_info?.cache_hit_rate || 'N/A'
        });
      }

      return result;
    } catch (error) {
      console.error('Document analysis failed:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      };
    }
  }

  /**
   * Generate academic citation using AI
   */
  async generateCitation(
    title: string,
    authors: string[],
    publicationDate: string,
    urn: string,
    source: string,
    url: string,
    citationStyle: string = 'ABNT'
  ): Promise<AgentResponse<{ citation: string }>> {
    try {
      const request: CitationRequest = {
        document_title: title,
        authors,
        publication_date: publicationDate,
        document_urn: urn,
        source,
        url,
        citation_style: citationStyle
      };

      const response = await fetch(`${this.baseUrl}/generate-citation`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(request),
      });

      if (!response.ok) {
        throw new Error(`Citation generation failed: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Citation generation failed:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      };
    }
  }

  /**
   * Get AI agent system health status
   */
  async getHealthStatus(): Promise<AgentHealthStatus | null> {
    try {
      const response = await fetch(`${this.baseUrl}/health`);
      
      if (!response.ok) {
        throw new Error(`Health check failed: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('AI agents health check failed:', error);
      return null;
    }
  }

  /**
   * Get list of active conversation threads
   */
  async getActiveThreads(): Promise<ThreadsResponse | null> {
    try {
      const response = await fetch(`${this.baseUrl}/memory/threads`);
      
      if (!response.ok) {
        throw new Error(`Failed to get threads: ${response.statusText}`);
      }

      const result: AgentResponse<ThreadsResponse> = await response.json();
      return result.success ? result.data! : null;
    } catch (error) {
      console.error('Failed to get active threads:', error);
      return null;
    }
  }

  /**
   * Clear semantic cache (for testing/maintenance)
   */
  async clearCache(): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseUrl}/clear-cache`, {
        method: 'POST',
      });
      
      if (!response.ok) {
        throw new Error(`Cache clearing failed: ${response.statusText}`);
      }

      const result: AgentResponse<{ cleared_entries: number }> = await response.json();
      if (result.success && result.data) {
        console.log(`Cleared ${result.data.cleared_entries} cache entries`);
        return true;
      }
      return false;
    } catch (error) {
      console.error('Cache clearing failed:', error);
      return false;
    }
  }

  /**
   * Analyze multiple documents in batch
   */
  async batchAnalyzeDocuments(
    documents: Array<{
      content: string;
      id: string;
      analysisType?: AnalysisType;
    }>,
    agentRole: AgentRole = AgentRole.DOCUMENT_ANALYZER,
    options: {
      threadId?: string;
      useSemanticCache?: boolean;
    } = {}
  ): Promise<AgentResponse<DocumentAnalysis>[]> {
    const threadId = options.threadId || this.getThreadId();
    const results: AgentResponse<DocumentAnalysis>[] = [];

    // Process documents sequentially to maintain conversation context
    for (const doc of documents) {
      const result = await this.analyzeDocument(
        doc.content,
        doc.id,
        doc.analysisType || AnalysisType.SUMMARY,
        agentRole,
        {
          threadId,
          useSemanticCache: options.useSemanticCache
        }
      );
      results.push(result);

      // Small delay to avoid overwhelming the API
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    return results;
  }

  /**
   * Specialized method for legal document analysis
   */
  async analyzeLegalDocument(
    documentContent: string,
    documentId: string,
    options: {
      threadId?: string;
      focusArea?: 'transport' | 'environmental' | 'regulatory' | 'general';
    } = {}
  ): Promise<AgentResponse<DocumentAnalysis>> {
    return this.analyzeDocument(
      documentContent,
      documentId,
      AnalysisType.LEGAL_ANALYSIS,
      AgentRole.LEGAL_ADVISOR,
      {
        threadId: options.threadId,
        includeCitations: true,
        useSemanticCache: true
      }
    );
  }

  /**
   * Specialized method for trend analysis
   */
  async analyzeTrends(
    documents: Array<{ content: string; id: string; date?: string }>,
    options: {
      threadId?: string;
      timeRange?: 'monthly' | 'quarterly' | 'yearly';
    } = {}
  ): Promise<AgentResponse<DocumentAnalysis>[]> {
    return this.batchAnalyzeDocuments(
      documents.map(doc => ({
        content: doc.content,
        id: doc.id,
        analysisType: AnalysisType.TREND_ANALYSIS
      })),
      AgentRole.TREND_ANALYST,
      {
        threadId: options.threadId,
        useSemanticCache: true
      }
    );
  }

  /**
   * Generate citations for multiple documents
   */
  async batchGenerateCitations(
    documents: Array<{
      title: string;
      authors: string[];
      date: string;
      urn: string;
      source: string;
      url: string;
    }>,
    citationStyle: string = 'ABNT'
  ): Promise<Array<AgentResponse<{ citation: string }>>> {
    const results: Array<AgentResponse<{ citation: string }>> = [];

    for (const doc of documents) {
      const result = await this.generateCitation(
        doc.title,
        doc.authors,
        doc.date,
        doc.urn,
        doc.source,
        doc.url,
        citationStyle
      );
      results.push(result);

      // Small delay between requests
      await new Promise(resolve => setTimeout(resolve, 50));
    }

    return results;
  }

  /**
   * Check if AI agents are available and healthy
   */
  async isAvailable(): Promise<boolean> {
    const health = await this.getHealthStatus();
    return health?.agent_manager_available ?? false;
  }

  /**
   * Get cost efficiency metrics
   */
  async getCostEfficiencyMetrics(): Promise<{
    cacheHitRate: number;
    totalCostUSD: number;
    totalAPICalls: number;
    costPerCall: number;
    estimatedSavings: number;
  } | null> {
    const health = await this.getHealthStatus();
    if (!health) return null;

    const costPerCall = health.total_api_calls > 0 ? health.total_cost_usd / health.total_api_calls : 0;
    const estimatedSavings = health.total_cost_usd * health.cache_hit_rate; // Estimated savings from caching

    return {
      cacheHitRate: health.cache_hit_rate,
      totalCostUSD: health.total_cost_usd,
      totalAPICalls: health.total_api_calls,
      costPerCall,
      estimatedSavings
    };
  }
}

// Create and export singleton instance
export const aiAgentsService = new AIAgentsService();

// Export types and service
export default aiAgentsService;