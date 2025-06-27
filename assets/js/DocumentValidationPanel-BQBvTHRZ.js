import { j as jsxRuntimeExports, L as LoadingSpinner } from "./index-BYGq6Ng0.js";
import { r as reactExports } from "./leaflet-vendor-BcXhkSxI.js";
import { a as apiClient_default } from "./Dashboard-Da8AjoJY.js";
import { a as API_ENDPOINTS } from "./api-DW14Y_8v.js";
import "./react-vendor-CSPBeBBz.js";
var __async$1 = (__this, __arguments, generator) => {
  return new Promise((resolve, reject) => {
    var fulfilled = (value) => {
      try {
        step(generator.next(value));
      } catch (e) {
        reject(e);
      }
    };
    var rejected = (value) => {
      try {
        step(generator.throw(value));
      } catch (e) {
        reject(e);
      }
    };
    var step = (x) => x.done ? resolve(x.value) : Promise.resolve(x.value).then(fulfilled, rejected);
    step((generator = generator.apply(__this, __arguments)).next());
  });
};
class DocumentValidationService {
  /**
   * Validate a single document
   */
  validateDocument(request) {
    return __async$1(this, null, function* () {
      return apiClient_default.post(API_ENDPOINTS.validation.document, request);
    });
  }
  /**
   * Validate multiple documents in batch
   */
  validateDocumentsBatch(request) {
    return __async$1(this, null, function* () {
      return apiClient_default.post(API_ENDPOINTS.validation.batch, request);
    });
  }
  /**
   * Validate URN format
   */
  validateURN(request) {
    return __async$1(this, null, function* () {
      return apiClient_default.post(API_ENDPOINTS.validation.urn, request);
    });
  }
  /**
   * Get quality report
   */
  getQualityReport(documentIds) {
    return __async$1(this, null, function* () {
      const params = documentIds ? { document_ids: documentIds } : void 0;
      return apiClient_default.get(API_ENDPOINTS.validation.qualityReport, params);
    });
  }
  /**
   * Get available validation rules
   */
  getValidationRules() {
    return __async$1(this, null, function* () {
      return apiClient_default.get(API_ENDPOINTS.validation.rules);
    });
  }
  /**
   * Get validation statistics
   */
  getValidationStatistics() {
    return __async$1(this, null, function* () {
      return apiClient_default.get(API_ENDPOINTS.validation.statistics);
    });
  }
  /**
   * Check document validation service health
   */
  checkHealth() {
    return __async$1(this, null, function* () {
      return apiClient_default.get(API_ENDPOINTS.validation.health);
    });
  }
  /**
   * Helper method to validate document with recommendations
   */
  validateWithRecommendations(document) {
    return __async$1(this, null, function* () {
      return this.validateDocument({
        document,
        include_recommendations: true
      });
    });
  }
  /**
   * Helper method to get quality assessment
   */
  getQualityAssessment(document) {
    return __async$1(this, null, function* () {
      const validation = yield this.validateWithRecommendations(document);
      let qualityLevel;
      const score = validation.quality_metrics.overall_score;
      if (score >= 0.9) qualityLevel = "excellent";
      else if (score >= 0.7) qualityLevel = "good";
      else if (score >= 0.5) qualityLevel = "fair";
      else qualityLevel = "poor";
      const improvementAreas = validation.validation_rules.filter((rule) => !rule.passed && rule.level === "warning").map((rule) => rule.rule_name);
      return {
        validation,
        qualityLevel,
        improvementAreas
      };
    });
  }
  /**
   * Helper method to validate Brazilian legislative URN
   */
  validateBrazilianLegislativeURN(urn) {
    return __async$1(this, null, function* () {
      const validation = yield this.validateURN({ urn });
      let documentType;
      let authority;
      if (urn.includes("urn:lex:br:")) {
        const parts = urn.split(":");
        if (parts.length >= 5) {
          authority = parts[3];
          documentType = parts[4];
        }
      }
      const suggestions = [];
      if (!validation.is_valid) {
        suggestions.push("Ensure URN follows format: urn:lex:br:authority:type:date:number");
        if (!urn.startsWith("urn:lex:br:")) {
          suggestions.push('URN must start with "urn:lex:br:" for Brazilian documents');
        }
      }
      return {
        validation,
        documentType,
        authority,
        suggestions
      };
    });
  }
  /**
   * Helper method for batch validation with progress tracking
   */
  validateBatchWithProgress(documents, onProgress) {
    return __async$1(this, null, function* () {
      const batchSize = 10;
      const results = [];
      let processed = 0;
      for (let i = 0; i < documents.length; i += batchSize) {
        const batch = documents.slice(i, i + batchSize);
        const batchResult = yield this.validateDocumentsBatch({
          documents: batch,
          include_recommendations: true
        });
        results.push(...batchResult.validation_results);
        processed += batch.length;
        if (onProgress) {
          onProgress(processed, documents.length);
        }
      }
      const validDocuments = results.filter((r) => r.is_valid).length;
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
    });
  }
  /**
   * Helper method to get validation insights
   */
  getValidationInsights() {
    return __async$1(this, null, function* () {
      const [rulesData, qualityReport, statistics] = yield Promise.all([
        this.getValidationRules(),
        this.getQualityReport(),
        this.getValidationStatistics()
      ]);
      const recommendations = [
        "Focus on improving metadata completeness for better document discoverability",
        "Ensure URN formats follow Brazilian legislative standards",
        "Add transport-specific metadata for domain relevance",
        "Validate date formats for consistency",
        "Include proper keywords for enhanced searchability"
      ];
      return {
        rules: rulesData.validation_rules,
        qualityReport,
        statistics: statistics.statistics,
        recommendations
      };
    });
  }
}
const documentValidationService = new DocumentValidationService();
var __async = (__this, __arguments, generator) => {
  return new Promise((resolve, reject) => {
    var fulfilled = (value) => {
      try {
        step(generator.next(value));
      } catch (e) {
        reject(e);
      }
    };
    var rejected = (value) => {
      try {
        step(generator.throw(value));
      } catch (e) {
        reject(e);
      }
    };
    var step = (x) => x.done ? resolve(x.value) : Promise.resolve(x.value).then(fulfilled, rejected);
    step((generator = generator.apply(__this, __arguments)).next());
  });
};
const DocumentValidationPanel = ({
  documents = [],
  onValidationComplete,
  className = ""
}) => {
  const [validationResults, setValidationResults] = reactExports.useState([]);
  const [isValidating, setIsValidating] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const [selectedDocument, setSelectedDocument] = reactExports.useState(null);
  const [validationProgress, setValidationProgress] = reactExports.useState({ processed: 0, total: 0 });
  const [serviceHealth, setServiceHealth] = reactExports.useState(null);
  reactExports.useEffect(() => {
    checkServiceHealth();
  }, []);
  reactExports.useEffect(() => {
    if (documents.length > 0 && documents.length <= 10) {
      validateDocuments();
    }
  }, [documents]);
  const checkServiceHealth = () => __async(null, null, function* () {
    try {
      const health = yield documentValidationService.checkHealth();
      setServiceHealth(health);
    } catch (err) {
      console.warn("Could not check validation service health:", err);
    }
  });
  const validateDocuments = () => __async(null, null, function* () {
    if (documents.length === 0) return;
    setIsValidating(true);
    setError(null);
    setValidationProgress({ processed: 0, total: documents.length });
    try {
      const results = yield documentValidationService.validateBatchWithProgress(
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
      const errorMessage = err instanceof Error ? err.message : "Validation failed";
      setError(errorMessage);
    } finally {
      setIsValidating(false);
      setValidationProgress({ processed: 0, total: 0 });
    }
  });
  const validateSingleDocument = (document) => __async(null, null, function* () {
    setIsValidating(true);
    setError(null);
    try {
      const result = yield documentValidationService.validateWithRecommendations(document);
      setValidationResults((prev) => {
        const existingIndex = prev.findIndex((r) => r.document_id === result.document_id);
        if (existingIndex >= 0) {
          const updated = [...prev];
          updated[existingIndex] = result;
          return updated;
        }
        return [...prev, result];
      });
      setSelectedDocument(document);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : "Validation failed";
      setError(errorMessage);
    } finally {
      setIsValidating(false);
    }
  });
  const getQualityLevel = (score) => {
    if (score >= 0.9) return "excellent";
    if (score >= 0.7) return "good";
    if (score >= 0.5) return "fair";
    return "poor";
  };
  const getQualityColor = (score) => {
    if (score >= 0.9) return "#22c55e";
    if (score >= 0.7) return "#3b82f6";
    if (score >= 0.5) return "#f59e0b";
    return "#ef4444";
  };
  const renderQualityMetrics = (metrics) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "quality-metrics", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "metric-item", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "metric-label", children: "Overall Quality:" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "metric-bar", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        "div",
        {
          className: "metric-fill",
          style: {
            width: `${metrics.overall_score * 100}%`,
            backgroundColor: getQualityColor(metrics.overall_score)
          }
        }
      ) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "metric-value", children: [
        (metrics.overall_score * 100).toFixed(0),
        "%"
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "metric-item", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "metric-label", children: "Completeness:" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "metric-bar", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        "div",
        {
          className: "metric-fill",
          style: {
            width: `${metrics.completeness_score * 100}%`,
            backgroundColor: getQualityColor(metrics.completeness_score)
          }
        }
      ) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "metric-value", children: [
        (metrics.completeness_score * 100).toFixed(0),
        "%"
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "metric-item", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "metric-label", children: "Format:" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "metric-bar", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        "div",
        {
          className: "metric-fill",
          style: {
            width: `${metrics.format_score * 100}%`,
            backgroundColor: getQualityColor(metrics.format_score)
          }
        }
      ) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "metric-value", children: [
        (metrics.format_score * 100).toFixed(0),
        "%"
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "metric-item", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "metric-label", children: "Consistency:" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "metric-bar", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        "div",
        {
          className: "metric-fill",
          style: {
            width: `${metrics.consistency_score * 100}%`,
            backgroundColor: getQualityColor(metrics.consistency_score)
          }
        }
      ) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "metric-value", children: [
        (metrics.consistency_score * 100).toFixed(0),
        "%"
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "metric-summary", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        "Rules: ",
        metrics.passed_rules,
        "/",
        metrics.total_rules
      ] }),
      metrics.errors > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "errors", children: [
        "Errors: ",
        metrics.errors
      ] }),
      metrics.warnings > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "warnings", children: [
        "Warnings: ",
        metrics.warnings
      ] })
    ] })
  ] });
  const renderValidationRules = (rules) => /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "validation-rules", children: rules.map((rule, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `rule-item ${rule.level} ${rule.passed ? "passed" : "failed"}`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rule-header", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `rule-icon ${rule.passed ? "success" : "failure"}`, children: rule.passed ? "✓" : "✗" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "rule-name", children: rule.rule_name }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `rule-level ${rule.level}`, children: rule.level })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rule-message", children: rule.message }),
    rule.details && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rule-details", children: /* @__PURE__ */ jsxRuntimeExports.jsx("pre", { children: JSON.stringify(rule.details, null, 2) }) })
  ] }, index)) });
  const renderValidationResult = (result) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "validation-result", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "result-header", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { children: result.document_id }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `validity-badge ${result.is_valid ? "valid" : "invalid"}`, children: result.is_valid ? "✓ Valid" : "✗ Invalid" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `quality-badge ${getQualityLevel(result.quality_metrics.overall_score)}`, children: getQualityLevel(result.quality_metrics.overall_score) })
    ] }),
    renderQualityMetrics(result.quality_metrics),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "validation-details", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "section", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h5", { children: "Validation Rules" }),
        renderValidationRules(result.validation_rules)
      ] }),
      result.recommendations.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "section", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h5", { children: "Recommendations" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "recommendations", children: result.recommendations.map((rec, index) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: rec }, index)) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "result-metadata", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("small", { children: [
        "Document Type: ",
        result.document_type,
        " | Processing Time: ",
        result.processing_time_ms.toFixed(0),
        "ms | Validated: ",
        new Date(result.validation_timestamp).toLocaleString()
      ] }) })
    ] })
  ] }, result.document_id);
  const renderSummaryStats = () => {
    if (validationResults.length === 0) return null;
    const validCount = validationResults.filter((r) => r.is_valid).length;
    const avgQuality = validationResults.reduce((sum, r) => sum + r.quality_metrics.overall_score, 0) / validationResults.length;
    const totalErrors = validationResults.reduce((sum, r) => sum + r.quality_metrics.errors, 0);
    const totalWarnings = validationResults.reduce((sum, r) => sum + r.quality_metrics.warnings, 0);
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "validation-summary", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "Validation Summary" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "summary-stats", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "stat-item", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "stat-value", children: [
            validCount,
            "/",
            validationResults.length
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "stat-label", children: "Valid Documents" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "stat-item", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "stat-value", children: [
            (avgQuality * 100).toFixed(0),
            "%"
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "stat-label", children: "Avg Quality" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "stat-item", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "stat-value", children: totalErrors }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "stat-label", children: "Total Errors" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "stat-item", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "stat-value", children: totalWarnings }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "stat-label", children: "Total Warnings" })
        ] })
      ] })
    ] });
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `document-validation-panel ${className}`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "panel-header", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "🛡️ Document Validation" }),
      serviceHealth && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "service-status", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `status-indicator ${serviceHealth.status}` }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("small", { children: serviceHealth.validator_available ? "Service Available" : "Service Unavailable" })
      ] })
    ] }),
    documents.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "validation-controls", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          onClick: validateDocuments,
          disabled: isValidating,
          className: "validate-button primary",
          children: isValidating ? /* @__PURE__ */ jsxRuntimeExports.jsx(LoadingSpinner, { size: "small" }) : "🔍 Validate All Documents"
        }
      ),
      documents.length === 1 && /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          onClick: () => validateSingleDocument(documents[0]),
          disabled: isValidating,
          className: "validate-button secondary",
          children: isValidating ? /* @__PURE__ */ jsxRuntimeExports.jsx(LoadingSpinner, { size: "small" }) : "🔍 Validate Document"
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "document-count", children: [
        documents.length,
        " document",
        documents.length !== 1 ? "s" : "",
        " ready for validation"
      ] })
    ] }),
    isValidating && validationProgress.total > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "validation-progress", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "progress-bar", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        "div",
        {
          className: "progress-fill",
          style: { width: `${validationProgress.processed / validationProgress.total * 100}%` }
        }
      ) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "progress-text", children: [
        "Validating ",
        validationProgress.processed,
        "/",
        validationProgress.total,
        " documents..."
      ] })
    ] }),
    error && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "error-message", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Validation Error:" }),
      " ",
      error,
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { onClick: () => setError(null), className: "close-error", children: "×" })
    ] }),
    renderSummaryStats(),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "validation-results", children: validationResults.map(renderValidationResult) }),
    documents.length === 0 && !isValidating && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "empty-state", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "📄 Select documents to validate their quality and compliance." }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "The validation framework checks:" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("ul", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: "URN format compliance with Brazilian standards" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: "Metadata completeness and accuracy" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: "Document structure and formatting" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: "Transport domain relevance (if applicable)" })
      ] })
    ] })
  ] });
};
var DocumentValidationPanel_default = DocumentValidationPanel;
export {
  DocumentValidationPanel_default as default
};
