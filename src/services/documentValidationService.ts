/**
 * Document Validation Service
 * Frontend service for document validation and quality assessment
 */

import apiClient from './apiClient';
import { API_ENDPOINTS } from '../config/api';

export interface DocumentValidationRequest {
  document: Record<string, any>;
  include_recommendations?: boolean;
}

export interface ValidationRule {
  rule_name: string;
  level: string;
  passed: boolean;
  message: string;
  details?: Record<string, any>;
}

export interface QualityMetrics {
  completeness_score: number;
  format_score: number;
  consistency_score: number;
  overall_score: number;
  total_rules: number;
  passed_rules: number;
  warnings: number;
  errors: number;
}

export interface DocumentValidationResult {
  document_id: string;
  document_type: string;
  validation_timestamp: string;
  is_valid: boolean;
  quality_metrics: QualityMetrics;
  validation_rules: ValidationRule[];
  recommendations: string[];
  processing_time_ms: number;
}

export interface BatchValidationRequest {
  documents: Record<string, any>[];
  include_recommendations?: boolean;
}

export interface BatchValidationResult {
  total_documents: number;
  valid_documents: number;
  invalid_documents: number;
  validation_results: DocumentValidationResult[];
  processing_summary: Record<string, any>;
}

export interface URNValidationRequest {
  urn: string;
}

export interface URNValidationResult {
  urn: string;
  is_valid: boolean;
  message: string;
  details: Record<string, any>;
  normalized_urn?: string;
}

export interface ValidationRuleInfo {
  rule_name: string;
  description: string;
  level: string;
  category: string;
}

export interface QualityReport {
  report_timestamp: string;
  documents_analyzed: number;
  quality_summary: {
    average_quality_score: number;
    documents_by_quality: {
      excellent: number;
      good: number;
      fair: number;
      poor: number;
    };
    common_issues: string[];
  };
  validation_trends: {
    improvement_areas: string[];
    quality_trend: string;
  };
}

export class DocumentValidationService {
  /**
   * Validate a single document
   */
  async validateDocument(request: DocumentValidationRequest): Promise<DocumentValidationResult> {
    return apiClient.post(API_ENDPOINTS.validation.document, request);
  }

  /**
   * Validate multiple documents in batch
   */
  async validateDocumentsBatch(request: BatchValidationRequest): Promise<BatchValidationResult> {
    return apiClient.post(API_ENDPOINTS.validation.batch, request);
  }

  /**
   * Validate URN format
   */
  async validateURN(request: URNValidationRequest): Promise<URNValidationResult> {
    return apiClient.post(API_ENDPOINTS.validation.urn, request);
  }

  /**
   * Get quality report
   */
  async getQualityReport(documentIds?: string): Promise<QualityReport> {
    const params = documentIds ? { document_ids: documentIds } : undefined;
    return apiClient.get(API_ENDPOINTS.validation.qualityReport, params);
  }

  /**
   * Get available validation rules
   */
  async getValidationRules(): Promise<{
    validation_rules: ValidationRuleInfo[];
    validation_levels: Array<{
      level: string;
      description: string;
    }>;
  }> {
    return apiClient.get(API_ENDPOINTS.validation.rules);
  }

  /**
   * Get validation statistics
   */
  async getValidationStatistics(): Promise<{
    status: string;
    statistics: Record<string, any>;
    features: Record<string, boolean>;
  }> {
    return apiClient.get(API_ENDPOINTS.validation.statistics);
  }

  /**
   * Check document validation service health
   */
  async checkHealth(): Promise<{
    status: string;
    validator_available: boolean;
    features_available?: string[];
    supported_document_types?: string[];
    message?: string;
    error?: string;
  }> {
    return apiClient.get(API_ENDPOINTS.validation.health);
  }

  /**
   * Helper method to validate document with recommendations
   */
  async validateWithRecommendations(document: Record<string, any>): Promise<DocumentValidationResult> {
    return this.validateDocument({
      document,
      include_recommendations: true
    });
  }

  /**
   * Helper method to get quality assessment
   */
  async getQualityAssessment(document: Record<string, any>): Promise<{
    validation: DocumentValidationResult;
    qualityLevel: 'excellent' | 'good' | 'fair' | 'poor';
    improvementAreas: string[];
  }> {
    const validation = await this.validateWithRecommendations(document);
    
    let qualityLevel: 'excellent' | 'good' | 'fair' | 'poor';
    const score = validation.quality_metrics.overall_score;
    
    if (score >= 0.9) qualityLevel = 'excellent';
    else if (score >= 0.7) qualityLevel = 'good';
    else if (score >= 0.5) qualityLevel = 'fair';
    else qualityLevel = 'poor';

    const improvementAreas = validation.validation_rules
      .filter(rule => !rule.passed && rule.level === 'warning')
      .map(rule => rule.rule_name);

    return {
      validation,
      qualityLevel,
      improvementAreas
    };
  }

  /**
   * Helper method to validate Brazilian legislative URN
   */
  async validateBrazilianLegislativeURN(urn: string): Promise<{
    validation: URNValidationResult;
    documentType?: string;
    authority?: string;
    suggestions?: string[];
  }> {
    const validation = await this.validateURN({ urn });
    
    // Extract additional information
    let documentType: string | undefined;
    let authority: string | undefined;
    
    if (urn.includes('urn:lex:br:')) {
      const parts = urn.split(':');
      if (parts.length >= 5) {
        authority = parts[3];
        documentType = parts[4];
      }
    }

    const suggestions: string[] = [];
    if (!validation.is_valid) {
      suggestions.push('Ensure URN follows format: urn:lex:br:authority:type:date:number');
      if (!urn.startsWith('urn:lex:br:')) {
        suggestions.push('URN must start with "urn:lex:br:" for Brazilian documents');
      }
    }

    return {
      validation,
      documentType,
      authority,
      suggestions
    };
  }

  /**
   * Helper method for batch validation with progress tracking
   */
  async validateBatchWithProgress(
    documents: Record<string, any>[],
    onProgress?: (processed: number, total: number) => void
  ): Promise<BatchValidationResult> {
    const batchSize = 10; // Process in smaller batches for progress updates
    const results: DocumentValidationResult[] = [];
    let processed = 0;

    for (let i = 0; i < documents.length; i += batchSize) {
      const batch = documents.slice(i, i + batchSize);
      const batchResult = await this.validateDocumentsBatch({
        documents: batch,
        include_recommendations: true
      });
      
      results.push(...batchResult.validation_results);
      processed += batch.length;
      
      if (onProgress) {
        onProgress(processed, documents.length);
      }
    }

    // Calculate final statistics
    const validDocuments = results.filter(r => r.is_valid).length;
    const invalidDocuments = results.length - validDocuments;
    
    const avgProcessingTime = results.reduce((sum, r) => sum + r.processing_time_ms, 0) / results.length;
    const avgQualityScore = results.reduce((sum, r) => sum + r.quality_metrics.overall_score, 0) / results.length;

    return {
      total_documents: results.length,
      valid_documents: validDocuments,
      invalid_documents: invalidDocuments,
      validation_results: results,
      processing_summary: {
        average_processing_time_ms: avgProcessingTime,
        average_quality_score: avgQualityScore,
        total_errors: results.reduce((sum, r) => sum + r.quality_metrics.errors, 0),
        total_warnings: results.reduce((sum, r) => sum + r.quality_metrics.warnings, 0)
      }
    };
  }

  /**
   * Helper method to get validation insights
   */
  async getValidationInsights(): Promise<{
    rules: ValidationRuleInfo[];
    qualityReport: QualityReport;
    statistics: Record<string, any>;
    recommendations: string[];
  }> {
    const [rulesData, qualityReport, statistics] = await Promise.all([
      this.getValidationRules(),
      this.getQualityReport(),
      this.getValidationStatistics()
    ]);

    const recommendations = [
      'Focus on improving metadata completeness for better document discoverability',
      'Ensure URN formats follow Brazilian legislative standards',
      'Add transport-specific metadata for domain relevance',
      'Validate date formats for consistency',
      'Include proper keywords for enhanced searchability'
    ];

    return {
      rules: rulesData.validation_rules,
      qualityReport,
      statistics: statistics.statistics,
      recommendations
    };
  }
}

export const documentValidationService = new DocumentValidationService();