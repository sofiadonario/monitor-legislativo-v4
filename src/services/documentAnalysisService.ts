/**
 * AI Document Analysis Service
 * Frontend service for AI-powered document analysis and citation generation
 */

import apiClient from './apiClient';
import { API_ENDPOINTS } from '../config/api';

export interface DocumentAnalysisRequest {
  document_data: Record<string, any>;
  analysis_type?: string;
  include_ai_enhancements?: boolean;
}

export interface DocumentSummary {
  document_id: string;
  title: string;
  summary_text: string;
  key_points: string[];
  main_concepts: string[];
  legal_references: string[];
  geographic_scope?: string;
  transport_relevance?: string;
  academic_impact: string;
  confidence_score: number;
  processing_time_ms: number;
  cost_cents: number;
}

export interface MetadataExtraction {
  document_id: string;
  extracted_metadata: Record<string, any>;
  confidence_scores: Record<string, number>;
  enhancements_applied: string[];
  processing_time_ms: number;
  cost_cents: number;
}

export interface ContentAnalysis {
  document_id: string;
  text_statistics: Record<string, any>;
  readability_score: number;
  complexity_level: string;
  language_quality: string;
  structure_analysis: Record<string, any>;
  terminology_analysis: Record<string, number>;
  anomalies_detected: string[];
  processing_time_ms: number;
  cost_cents: number;
}

export interface RelationshipDiscovery {
  document_id: string;
  related_documents: Record<string, any>[];
  legal_connections: Record<string, string[]>;
  thematic_relationships: Record<string, any>[];
  confidence_scores: Record<string, number>;
  processing_time_ms: number;
  cost_cents: number;
}

export interface ComprehensiveAnalysis {
  document_id: string;
  analysis_timestamp: string;
  summary?: DocumentSummary;
  metadata?: MetadataExtraction;
  content?: ContentAnalysis;
  relationships?: RelationshipDiscovery;
  analysis_statistics: Record<string, any>;
}

export interface CitationRequest {
  document_data: Record<string, any>;
  citation_style?: string;
  include_url?: boolean;
  include_access_date?: boolean;
  academic_level?: string;
  research_context?: string;
}

export interface CitationResult {
  citation_text: string;
  citation_style: string;
  document_id: string;
  validation_status: string;
  quality_score: number;
  ai_enhancements: string[];
  quality_metrics: Record<string, number>;
  suggestions: string[];
  processing_time_ms: number;
  cost_cents: number;
  from_cache: boolean;
}

export interface BatchCitationRequest {
  citations: CitationRequest[];
}

export interface BatchCitationResponse {
  total_citations: number;
  successful_citations: number;
  failed_citations: number;
  citations: CitationResult[];
  batch_statistics: Record<string, any>;
}

export interface CitationStyle {
  id: string;
  name: string;
  description: string;
}

export class DocumentAnalysisService {
  /**
   * Perform comprehensive document analysis
   */
  async analyzeDocument(request: DocumentAnalysisRequest): Promise<ComprehensiveAnalysis> {
    return apiClient.post(API_ENDPOINTS.aiAnalysis.analyze, request);
  }

  /**
   * Generate document summary
   */
  async summarizeDocument(documentData: Record<string, any>): Promise<DocumentSummary> {
    return apiClient.post(API_ENDPOINTS.aiAnalysis.summarize, documentData);
  }

  /**
   * Extract enhanced metadata
   */
  async extractMetadata(documentData: Record<string, any>): Promise<MetadataExtraction> {
    return apiClient.post(API_ENDPOINTS.aiAnalysis.extractMetadata, documentData);
  }

  /**
   * Analyze document content
   */
  async analyzeContent(documentData: Record<string, any>): Promise<ContentAnalysis> {
    return apiClient.post(API_ENDPOINTS.aiAnalysis.analyzeContent, documentData);
  }

  /**
   * Discover document relationships
   */
  async discoverRelationships(documentData: Record<string, any>): Promise<RelationshipDiscovery> {
    return apiClient.post(API_ENDPOINTS.aiAnalysis.discoverRelationships, documentData);
  }

  /**
   * Generate academic citation
   */
  async generateCitation(request: CitationRequest): Promise<CitationResult> {
    return apiClient.post(API_ENDPOINTS.aiAnalysis.generateCitation, request);
  }

  /**
   * Generate multiple citations in batch
   */
  async generateCitationsBatch(request: BatchCitationRequest): Promise<BatchCitationResponse> {
    return apiClient.post(API_ENDPOINTS.aiAnalysis.batchCitations, request);
  }

  /**
   * Get supported citation styles
   */
  async getCitationStyles(): Promise<{
    supported_styles: CitationStyle[];
    default_style: string;
    total_styles: number;
  }> {
    return apiClient.get(API_ENDPOINTS.aiAnalysis.citationStyles);
  }

  /**
   * Get analysis engine statistics
   */
  async getAnalysisStatistics(): Promise<{
    status: string;
    analysis_statistics: Record<string, any>;
  }> {
    return apiClient.get(API_ENDPOINTS.aiAnalysis.analysisStatistics);
  }

  /**
   * Get citation generator statistics
   */
  async getCitationStatistics(): Promise<{
    status: string;
    citation_statistics: Record<string, any>;
  }> {
    return apiClient.get(API_ENDPOINTS.aiAnalysis.citationStatistics);
  }

  /**
   * Check AI document analysis service health
   */
  async checkHealth(): Promise<{
    status: string;
    ai_document_analysis_available: boolean;
    analysis_engine_status?: string;
    citation_generator_status?: string;
    features_available?: string[];
    supported_citation_styles?: number;
    message?: string;
    error?: string;
  }> {
    return apiClient.get(API_ENDPOINTS.aiAnalysis.health);
  }

  /**
   * Helper method to generate ABNT citation
   */
  async generateABNTCitation(documentData: Record<string, any>, researchContext?: string): Promise<CitationResult> {
    return this.generateCitation({
      document_data: documentData,
      citation_style: 'abnt',
      include_url: true,
      include_access_date: true,
      academic_level: 'graduate',
      research_context: researchContext
    });
  }

  /**
   * Helper method to generate APA citation
   */
  async generateAPACitation(documentData: Record<string, any>, researchContext?: string): Promise<CitationResult> {
    return this.generateCitation({
      document_data: documentData,
      citation_style: 'apa',
      include_url: true,
      include_access_date: true,
      academic_level: 'graduate',
      research_context: researchContext
    });
  }

  /**
   * Helper method for quick document analysis
   */
  async quickAnalysis(documentData: Record<string, any>): Promise<{
    summary: DocumentSummary;
    metadata: MetadataExtraction;
    citation: CitationResult;
  }> {
    const [summary, metadata, citation] = await Promise.all([
      this.summarizeDocument(documentData),
      this.extractMetadata(documentData),
      this.generateABNTCitation(documentData)
    ]);

    return { summary, metadata, citation };
  }

  /**
   * Helper method for batch citation generation with different styles
   */
  async generateMultiStyleCitations(documentData: Record<string, any>): Promise<{
    abnt: CitationResult;
    apa: CitationResult;
    chicago: CitationResult;
    vancouver: CitationResult;
  }> {
    const styles = ['abnt', 'apa', 'chicago', 'vancouver'];
    const requests: CitationRequest[] = styles.map(style => ({
      document_data: documentData,
      citation_style: style,
      include_url: true,
      include_access_date: true,
      academic_level: 'graduate'
    }));

    const batchResult = await this.generateCitationsBatch({ citations: requests });
    
    const result: any = {};
    batchResult.citations.forEach((citation, index) => {
      result[styles[index]] = citation;
    });

    return result;
  }
}

export const documentAnalysisService = new DocumentAnalysisService();