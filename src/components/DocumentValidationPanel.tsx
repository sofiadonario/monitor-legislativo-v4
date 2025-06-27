/**
 * Document Validation Panel Component
 * Frontend interface for document validation and quality assessment
 */

import React, { useState, useEffect } from 'react';
import { documentValidationService, DocumentValidationResult, QualityMetrics, ValidationRule } from '../services/documentValidationService';
import { LoadingSpinner } from './LoadingSpinner';

interface DocumentValidationPanelProps {
  documents?: Array<Record<string, any>>;
  onValidationComplete?: (results: DocumentValidationResult[]) => void;
  className?: string;
}

const DocumentValidationPanel: React.FC<DocumentValidationPanelProps> = ({
  documents = [],
  onValidationComplete,
  className = ''
}) => {
  const [validationResults, setValidationResults] = useState<DocumentValidationResult[]>([]);
  const [isValidating, setIsValidating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedDocument, setSelectedDocument] = useState<Record<string, any> | null>(null);
  const [validationProgress, setValidationProgress] = useState({ processed: 0, total: 0 });
  const [serviceHealth, setServiceHealth] = useState<any>(null);

  useEffect(() => {
    checkServiceHealth();
  }, []);

  useEffect(() => {
    if (documents.length > 0 && documents.length <= 10) {
      // Auto-validate if there are few documents
      validateDocuments();
    }
  }, [documents]);

  const checkServiceHealth = async () => {
    try {
      const health = await documentValidationService.checkHealth();
      setServiceHealth(health);
    } catch (err) {
      console.warn('Could not check validation service health:', err);
    }
  };

  const validateDocuments = async () => {
    if (documents.length === 0) return;

    setIsValidating(true);
    setError(null);
    setValidationProgress({ processed: 0, total: documents.length });

    try {
      const results = await documentValidationService.validateBatchWithProgress(
        documents,
        (processed, total) => {
          setValidationProgress({ processed, total });
        }
      );

      setValidationResults(results.validation_results);
      
      if (onValidationComplete) {
        onValidationComplete(results.validation_results);
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Validation failed';
      setError(errorMessage);
    } finally {
      setIsValidating(false);
      setValidationProgress({ processed: 0, total: 0 });
    }
  };

  const validateSingleDocument = async (document: Record<string, any>) => {
    setIsValidating(true);
    setError(null);

    try {
      const result = await documentValidationService.validateWithRecommendations(document);
      
      // Update results array
      setValidationResults(prev => {
        const existingIndex = prev.findIndex(r => r.document_id === result.document_id);
        if (existingIndex >= 0) {
          const updated = [...prev];
          updated[existingIndex] = result;
          return updated;
        }
        return [...prev, result];
      });

      setSelectedDocument(document);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Validation failed';
      setError(errorMessage);
    } finally {
      setIsValidating(false);
    }
  };

  const getQualityLevel = (score: number): string => {
    if (score >= 0.9) return 'excellent';
    if (score >= 0.7) return 'good';
    if (score >= 0.5) return 'fair';
    return 'poor';
  };

  const getQualityColor = (score: number): string => {
    if (score >= 0.9) return '#22c55e'; // green
    if (score >= 0.7) return '#3b82f6'; // blue
    if (score >= 0.5) return '#f59e0b'; // amber
    return '#ef4444'; // red
  };

  const renderQualityMetrics = (metrics: QualityMetrics) => (
    <div className="quality-metrics">
      <div className="metric-item">
        <span className="metric-label">Overall Quality:</span>
        <div className="metric-bar">
          <div 
            className="metric-fill" 
            style={{ 
              width: `${metrics.overall_score * 100}%`,
              backgroundColor: getQualityColor(metrics.overall_score)
            }}
          />
        </div>
        <span className="metric-value">{(metrics.overall_score * 100).toFixed(0)}%</span>
      </div>
      
      <div className="metric-item">
        <span className="metric-label">Completeness:</span>
        <div className="metric-bar">
          <div 
            className="metric-fill" 
            style={{ 
              width: `${metrics.completeness_score * 100}%`,
              backgroundColor: getQualityColor(metrics.completeness_score)
            }}
          />
        </div>
        <span className="metric-value">{(metrics.completeness_score * 100).toFixed(0)}%</span>
      </div>

      <div className="metric-item">
        <span className="metric-label">Format:</span>
        <div className="metric-bar">
          <div 
            className="metric-fill" 
            style={{ 
              width: `${metrics.format_score * 100}%`,
              backgroundColor: getQualityColor(metrics.format_score)
            }}
          />
        </div>
        <span className="metric-value">{(metrics.format_score * 100).toFixed(0)}%</span>
      </div>

      <div className="metric-item">
        <span className="metric-label">Consistency:</span>
        <div className="metric-bar">
          <div 
            className="metric-fill" 
            style={{ 
              width: `${metrics.consistency_score * 100}%`,
              backgroundColor: getQualityColor(metrics.consistency_score)
            }}
          />
        </div>
        <span className="metric-value">{(metrics.consistency_score * 100).toFixed(0)}%</span>
      </div>

      <div className="metric-summary">
        <span>Rules: {metrics.passed_rules}/{metrics.total_rules}</span>
        {metrics.errors > 0 && <span className="errors">Errors: {metrics.errors}</span>}
        {metrics.warnings > 0 && <span className="warnings">Warnings: {metrics.warnings}</span>}
      </div>
    </div>
  );

  const renderValidationRules = (rules: ValidationRule[]) => (
    <div className="validation-rules">
      {rules.map((rule, index) => (
        <div key={index} className={`rule-item ${rule.level} ${rule.passed ? 'passed' : 'failed'}`}>
          <div className="rule-header">
            <span className={`rule-icon ${rule.passed ? 'success' : 'failure'}`}>
              {rule.passed ? '✓' : '✗'}
            </span>
            <span className="rule-name">{rule.rule_name}</span>
            <span className={`rule-level ${rule.level}`}>{rule.level}</span>
          </div>
          <div className="rule-message">{rule.message}</div>
          {rule.details && (
            <div className="rule-details">
              <pre>{JSON.stringify(rule.details, null, 2)}</pre>
            </div>
          )}
        </div>
      ))}
    </div>
  );

  const renderValidationResult = (result: DocumentValidationResult) => (
    <div key={result.document_id} className="validation-result">
      <div className="result-header">
        <h4>{result.document_id}</h4>
        <span className={`validity-badge ${result.is_valid ? 'valid' : 'invalid'}`}>
          {result.is_valid ? '✓ Valid' : '✗ Invalid'}
        </span>
        <span className={`quality-badge ${getQualityLevel(result.quality_metrics.overall_score)}`}>
          {getQualityLevel(result.quality_metrics.overall_score)}
        </span>
      </div>

      {renderQualityMetrics(result.quality_metrics)}

      <div className="validation-details">
        <div className="section">
          <h5>Validation Rules</h5>
          {renderValidationRules(result.validation_rules)}
        </div>

        {result.recommendations.length > 0 && (
          <div className="section">
            <h5>Recommendations</h5>
            <ul className="recommendations">
              {result.recommendations.map((rec, index) => (
                <li key={index}>{rec}</li>
              ))}
            </ul>
          </div>
        )}

        <div className="result-metadata">
          <small>
            Document Type: {result.document_type} | 
            Processing Time: {result.processing_time_ms.toFixed(0)}ms | 
            Validated: {new Date(result.validation_timestamp).toLocaleString()}
          </small>
        </div>
      </div>
    </div>
  );

  const renderSummaryStats = () => {
    if (validationResults.length === 0) return null;

    const validCount = validationResults.filter(r => r.is_valid).length;
    const avgQuality = validationResults.reduce((sum, r) => sum + r.quality_metrics.overall_score, 0) / validationResults.length;
    const totalErrors = validationResults.reduce((sum, r) => sum + r.quality_metrics.errors, 0);
    const totalWarnings = validationResults.reduce((sum, r) => sum + r.quality_metrics.warnings, 0);

    return (
      <div className="validation-summary">
        <h3>Validation Summary</h3>
        <div className="summary-stats">
          <div className="stat-item">
            <span className="stat-value">{validCount}/{validationResults.length}</span>
            <span className="stat-label">Valid Documents</span>
          </div>
          <div className="stat-item">
            <span className="stat-value">{(avgQuality * 100).toFixed(0)}%</span>
            <span className="stat-label">Avg Quality</span>
          </div>
          <div className="stat-item">
            <span className="stat-value">{totalErrors}</span>
            <span className="stat-label">Total Errors</span>
          </div>
          <div className="stat-item">
            <span className="stat-value">{totalWarnings}</span>
            <span className="stat-label">Total Warnings</span>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className={`document-validation-panel ${className}`}>
      <div className="panel-header">
        <h3>🛡️ Document Validation</h3>
        
        {serviceHealth && (
          <div className="service-status">
            <span className={`status-indicator ${serviceHealth.status}`}></span>
            <small>{serviceHealth.validator_available ? 'Service Available' : 'Service Unavailable'}</small>
          </div>
        )}
      </div>

      {documents.length > 0 && (
        <div className="validation-controls">
          <button
            onClick={validateDocuments}
            disabled={isValidating}
            className="validate-button primary"
          >
            {isValidating ? <LoadingSpinner size="small" /> : '🔍 Validate All Documents'}
          </button>

          {documents.length === 1 && (
            <button
              onClick={() => validateSingleDocument(documents[0])}
              disabled={isValidating}
              className="validate-button secondary"
            >
              {isValidating ? <LoadingSpinner size="small" /> : '🔍 Validate Document'}
            </button>
          )}

          <div className="document-count">
            {documents.length} document{documents.length !== 1 ? 's' : ''} ready for validation
          </div>
        </div>
      )}

      {isValidating && validationProgress.total > 0 && (
        <div className="validation-progress">
          <div className="progress-bar">
            <div 
              className="progress-fill"
              style={{ width: `${(validationProgress.processed / validationProgress.total) * 100}%` }}
            />
          </div>
          <div className="progress-text">
            Validating {validationProgress.processed}/{validationProgress.total} documents...
          </div>
        </div>
      )}

      {error && (
        <div className="error-message">
          <strong>Validation Error:</strong> {error}
          <button onClick={() => setError(null)} className="close-error">×</button>
        </div>
      )}

      {renderSummaryStats()}

      <div className="validation-results">
        {validationResults.map(renderValidationResult)}
      </div>

      {documents.length === 0 && !isValidating && (
        <div className="empty-state">
          <p>📄 Select documents to validate their quality and compliance.</p>
          <p>The validation framework checks:</p>
          <ul>
            <li>URN format compliance with Brazilian standards</li>
            <li>Metadata completeness and accuracy</li>
            <li>Document structure and formatting</li>
            <li>Transport domain relevance (if applicable)</li>
          </ul>
        </div>
      )}
    </div>
  );
};

export default DocumentValidationPanel;