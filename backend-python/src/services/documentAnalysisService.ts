/**
 * Document Analysis Service
 * Provides comprehensive document analysis capabilities including content extraction,
 * cross-reference discovery, similarity analysis, and citation generation
 */
import { API_ENDPOINTS, buildApiUrl, API_CONFIG } from '../config/api';
import {
  DocumentContent,
  DocumentMetadata,
  CrossReference,
  SimilarDocument,
  QualityScore,
  Citation,
  CitationFormat,
  ComparisonResult
} from '../types';

export class DocumentAnalysisService {
  private baseUrl: string;
  private headers: Record<string, string>;

  constructor() {
    this.baseUrl = API_CONFIG.baseUrl;
    this.headers = API_CONFIG.headers;
  }

  /**
   * Get full document content with sections and metadata
   */
  async getDocumentContent(urn: string): Promise<DocumentContent | null> {
    try {
      const url = buildApiUrl(API_ENDPOINTS.documentAnalysis.content, { urn });

      const response = await fetch(url, {
        method: 'GET',
        headers: this.headers,
        signal: AbortSignal.timeout(API_CONFIG.timeout)
      });

      if (response.status === 404) {
        return null;
      }

      if (!response.ok) {
        throw new Error(`Failed to get document content: ${response.status}`);
      }

      const data = await response.json();
      return this.transformDocumentContent(data);
    } catch (error) {
      console.error('Error getting document content:', error);
      throw new Error(`Failed to get document content: ${error}`);
    }
  }

  /**
   * Get enhanced document metadata with quality scores
   */
  async getDocumentMetadata(urn: string): Promise<DocumentMetadata | null> {
    try {
      const url = buildApiUrl(API_ENDPOINTS.documentAnalysis.metadata, { urn });

      const response = await fetch(url, {
        method: 'GET',
        headers: this.headers,
        signal: AbortSignal.timeout(API_CONFIG.timeout)
      });

      if (response.status === 404) {
        return null;
      }

      if (!response.ok) {
        throw new Error(`Failed to get document metadata: ${response.status}`);
      }

      const data = await response.json();
      return this.transformDocumentMetadata(data);
    } catch (error) {
      console.error('Error getting document metadata:', error);
      throw new Error(`Failed to get document metadata: ${error}`);
    }
  }

  /**
   * Discover cross-references and relationships between documents
   */
  async getCrossReferences(urn: string): Promise<CrossReference[]> {
    try {
      const url = buildApiUrl(API_ENDPOINTS.documentAnalysis.crossReferences, { urn });

      const response = await fetch(url, {
        method: 'GET',
        headers: this.headers,
        signal: AbortSignal.timeout(API_CONFIG.timeout)
      });

      if (!response.ok) {
        throw new Error(`Failed to get cross references: ${response.status}`);
      }

      const data = await response.json();
      return this.transformCrossReferences(data);
    } catch (error) {
      console.error('Error getting cross references:', error);
      throw new Error(`Failed to get cross references: ${error}`);
    }
  }

  /**
   * Find similar documents using ML analysis
   */
  async getSimilarDocuments(urn: string, limit: number = 10): Promise<SimilarDocument[]> {
    try {
      const url = buildApiUrl(API_ENDPOINTS.documentAnalysis.similarDocuments, { 
        urn, 
        limit: limit.toString() 
      });

      const response = await fetch(url, {
        method: 'GET',
        headers: this.headers,
        signal: AbortSignal.timeout(API_CONFIG.timeout)
      });

      if (!response.ok) {
        throw new Error(`Failed to get similar documents: ${response.status}`);
      }

      const data = await response.json();
      return this.transformSimilarDocuments(data);
    } catch (error) {
      console.error('Error getting similar documents:', error);
      throw new Error(`Failed to get similar documents: ${error}`);
    }
  }

  /**
   * Get document quality score and validation results
   */
  async getQualityScore(urn: string): Promise<QualityScore | null> {
    try {
      const url = buildApiUrl(API_ENDPOINTS.documentAnalysis.qualityScore, { urn });

      const response = await fetch(url, {
        method: 'GET',
        headers: this.headers,
        signal: AbortSignal.timeout(API_CONFIG.timeout)
      });

      if (response.status === 404) {
        return null;
      }

      if (!response.ok) {
        throw new Error(`Failed to get quality score: ${response.status}`);
      }

      const data = await response.json();
      return this.transformQualityScore(data);
    } catch (error) {
      console.error('Error getting quality score:', error);
      throw new Error(`Failed to get quality score: ${error}`);
    }
  }

  /**
   * Generate academic citation in specified format
   */
  async generateCitation(urn: string, format: CitationFormat): Promise<Citation | null> {
    try {
      const url = buildApiUrl(API_ENDPOINTS.documentAnalysis.citation);

      const response = await fetch(url, {
        method: 'POST',
        headers: {
          ...this.headers,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          urn,
          style: format.toLowerCase()
        }),
        signal: AbortSignal.timeout(API_CONFIG.timeout)
      });

      if (response.status === 404) {
        return null;
      }

      if (!response.ok) {
        throw new Error(`Failed to generate citation: ${response.status}`);
      }

      const data = await response.json();
      return this.transformCitation(data, format);
    } catch (error) {
      console.error('Error generating citation:', error);
      throw new Error(`Failed to generate citation: ${error}`);
    }
  }

  /**
   * Generate citations for multiple documents
   */
  async generateBatchCitations(urns: string[], format: CitationFormat): Promise<Citation[]> {
    try {
      const url = buildApiUrl(API_ENDPOINTS.documentAnalysis.batchCitations);

      const response = await fetch(url, {
        method: 'POST',
        headers: {
          ...this.headers,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          urns,
          style: format.toLowerCase()
        }),
        signal: AbortSignal.timeout(API_CONFIG.timeout)
      });

      if (!response.ok) {
        throw new Error(`Failed to generate batch citations: ${response.status}`);
      }

      const data = await response.json();
      return data.map((item: any) => this.transformCitation(item, format));
    } catch (error) {
      console.error('Error generating batch citations:', error);
      throw new Error(`Failed to generate batch citations: ${error}`);
    }
  }

  /**
   * Get available citation styles
   */
  async getCitationStyles(): Promise<CitationFormat[]> {
    try {
      const url = buildApiUrl(API_ENDPOINTS.documentAnalysis.citationStyles);

      const response = await fetch(url, {
        method: 'GET',
        headers: this.headers,
        signal: AbortSignal.timeout(API_CONFIG.timeout)
      });

      if (!response.ok) {
        throw new Error(`Failed to get citation styles: ${response.status}`);
      }

      const data = await response.json();
      return data.styles || ['ABNT', 'APA', 'Chicago', 'Vancouver', 'MLA', 'IEEE'];
    } catch (error) {
      console.error('Error getting citation styles:', error);
      // Return default styles if API fails
      return ['ABNT', 'APA', 'Chicago', 'Vancouver', 'MLA', 'IEEE'];
    }
  }

  /**
   * Compare multiple documents
   */
  async compareDocuments(urns: string[]): Promise<ComparisonResult | null> {
    if (urns.length < 2) {
      throw new Error('At least 2 documents are required for comparison');
    }

    try {
      const url = buildApiUrl(API_ENDPOINTS.documentAnalysis.comparison);

      const response = await fetch(url, {
        method: 'POST',
        headers: {
          ...this.headers,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          urns
        }),
        signal: AbortSignal.timeout(API_CONFIG.timeout)
      });

      if (!response.ok) {
        throw new Error(`Failed to compare documents: ${response.status}`);
      }

      const data = await response.json();
      return this.transformComparisonResult(data);
    } catch (error) {
      console.error('Error comparing documents:', error);
      throw new Error(`Failed to compare documents: ${error}`);
    }
  }

  /**
   * Get service health status
   */
  async getServiceHealth(): Promise<any> {
    try {
      const url = buildApiUrl(API_ENDPOINTS.documentAnalysis.health);

      const response = await fetch(url, {
        method: 'GET',
        headers: this.headers,
        signal: AbortSignal.timeout(API_CONFIG.timeout)
      });

      if (!response.ok) {
        throw new Error(`Failed to get service health: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error getting service health:', error);
      throw new Error(`Failed to get service health: ${error}`);
    }
  }

  // Private transformation methods
  private transformDocumentContent(data: any): DocumentContent {
    return {
      urn: data.urn || '',
      title: data.title || '',
      content: data.content || '',
      htmlContent: data.html_content || data.htmlContent,
      plainText: data.plain_text || data.plainText || '',
      metadata: this.transformDocumentMetadata(data.metadata || {}),
      sections: (data.sections || []).map(this.transformDocumentSection),
      attachments: (data.attachments || []).map(this.transformAttachment)
    };
  }

  private transformDocumentMetadata(data: any): DocumentMetadata {
    return {
      urn: data.urn || '',
      title: data.title || '',
      type: data.type || 'lei',
      authority: data.authority || '',
      publicationDate: data.publication_date || data.publicationDate || '',
      effectiveDate: data.effective_date || data.effectiveDate,
      status: data.status || 'em_tramitacao',
      subject: data.subject || [],
      keywords: data.keywords || [],
      language: data.language || 'pt',
      jurisdiction: data.jurisdiction || '',
      source: data.source || '',
      lastModified: data.last_modified || data.lastModified || new Date().toISOString(),
      version: data.version || '1.0',
      qualityScore: this.transformQualityScore(data.quality_score || data.qualityScore || {})
    };
  }

  private transformDocumentSection(data: any): any {
    return {
      id: data.id || '',
      title: data.title || '',
      content: data.content || '',
      level: data.level || 1,
      order: data.order || 0,
      type: data.type || 'section',
      references: data.references || []
    };
  }

  private transformAttachment(data: any): any {
    return {
      id: data.id || '',
      name: data.name || '',
      type: data.type || '',
      size: data.size || 0,
      url: data.url || '',
      description: data.description
    };
  }

  private transformQualityScore(data: any): QualityScore {
    return {
      overall: data.overall || 0,
      completeness: data.completeness || 0,
      accuracy: data.accuracy || 0,
      consistency: data.consistency || 0,
      timeliness: data.timeliness || 0,
      details: {
        missingFields: data.details?.missing_fields || data.details?.missingFields || [],
        validationErrors: data.details?.validation_errors || data.details?.validationErrors || [],
        warnings: data.details?.warnings || [],
        lastValidated: data.details?.last_validated || data.details?.lastValidated || new Date().toISOString()
      }
    };
  }

  private transformCrossReferences(data: any[]): CrossReference[] {
    return data.map(item => ({
      id: item.id || '',
      sourceUrn: item.source_urn || item.sourceUrn || '',
      targetUrn: item.target_urn || item.targetUrn || '',
      type: item.type || 'reference',
      description: item.description || '',
      context: item.context || '',
      bidirectional: item.bidirectional || false,
      strength: item.strength || 0.5
    }));
  }

  private transformSimilarDocuments(data: any[]): SimilarDocument[] {
    return data.map(item => ({
      urn: item.urn || '',
      title: item.title || '',
      similarity: item.similarity || 0,
      matchType: item.match_type || item.matchType || 'content',
      commonElements: item.common_elements || item.commonElements || [],
      explanation: item.explanation || ''
    }));
  }

  private transformCitation(data: any, format: CitationFormat): Citation {
    return {
      format,
      text: data.citation || data.text || '',
      bibtex: data.bibtex,
      ris: data.ris,
      endnote: data.endnote,
      metadata: {
        authors: data.metadata?.authors || [],
        title: data.metadata?.title || '',
        publisher: data.metadata?.publisher || '',
        publicationDate: data.metadata?.publication_date || data.metadata?.publicationDate || '',
        url: data.metadata?.url || '',
        accessDate: data.metadata?.access_date || data.metadata?.accessDate || new Date().toISOString(),
        doi: data.metadata?.doi,
        isbn: data.metadata?.isbn
      }
    };
  }

  private transformComparisonResult(data: any): ComparisonResult {
    return {
      documents: (data.documents || []).map((doc: any) => this.transformDocumentMetadata(doc)),
      similarities: {
        contentSimilarity: data.similarities?.content_similarity || data.similarities?.contentSimilarity || 0,
        structureSimilarity: data.similarities?.structure_similarity || data.similarities?.structureSimilarity || 0,
        metadataSimilarity: data.similarities?.metadata_similarity || data.similarities?.metadataSimilarity || 0,
        overallSimilarity: data.similarities?.overall_similarity || data.similarities?.overallSimilarity || 0,
        commonSections: data.similarities?.common_sections || data.similarities?.commonSections || 0,
        uniqueSections: data.similarities?.unique_sections || data.similarities?.uniqueSections || { doc1: 0, doc2: 0 }
      },
      differences: (data.differences || []).map((diff: any) => ({
        type: diff.type || 'content',
        field: diff.field || '',
        document1Value: diff.document1_value || diff.document1Value || '',
        document2Value: diff.document2_value || diff.document2Value || '',
        significance: diff.significance || 'medium',
        description: diff.description || ''
      })),
      summary: {
        primaryDifferences: data.summary?.primary_differences || data.summary?.primaryDifferences || [],
        keyInsights: data.summary?.key_insights || data.summary?.keyInsights || [],
        recommendations: data.summary?.recommendations || []
      }
    };
  }
}

// Export singleton instance
export const documentAnalysisService = new DocumentAnalysisService();