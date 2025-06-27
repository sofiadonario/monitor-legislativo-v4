"""
Document Validation API Endpoints
=================================

FastAPI endpoints for document validation based on lexml-coleta-validador patterns.
Provides comprehensive validation, quality metrics, and data integrity monitoring.

Features:
- Single document validation
- Batch document validation  
- Quality metrics and scoring
- URN format validation
- Schema compliance checking
- Health monitoring and statistics
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
import logging
import sys
from pathlib import Path

# Import document validation components
sys.path.append(str(Path(__file__).parent.parent.parent / "core"))

try:
    from validation.document_validator import (
        DocumentValidator, 
        ValidationResult, 
        ValidationRule,
        QualityMetrics,
        ValidationLevel,
        DocumentType
    )
    VALIDATION_AVAILABLE = True
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.warning(f"Document validation not available: {e}")
    VALIDATION_AVAILABLE = False
    
    # Mock classes for when validation is not available
    class DocumentValidator:
        def __init__(self): pass
        def validate_document(self, doc): return None
        def batch_validate_documents(self, docs): return []
        def get_validation_statistics(self): return {}
    
    class ValidationResult:
        def __init__(self, **kwargs): pass
    
    class ValidationRule:
        def __init__(self, **kwargs): pass
    
    class QualityMetrics:
        def __init__(self, **kwargs): pass
    
    class ValidationLevel:
        ERROR = "error"
        WARNING = "warning"
        INFO = "info"
        SUCCESS = "success"
    
    class DocumentType:
        LEI = "lei"
        DECRETO = "decreto"
        OUTROS = "outros"

logger = logging.getLogger(__name__)

# Global document validator instance
_document_validator: Optional[DocumentValidator] = None


async def get_document_validator() -> DocumentValidator:
    """Dependency to get initialized document validator"""
    global _document_validator
    if _document_validator is None and VALIDATION_AVAILABLE:
        _document_validator = DocumentValidator()
        logger.info("Document validator initialized")
    elif not VALIDATION_AVAILABLE:
        logger.warning("Document validation not available - using mock validator")
        _document_validator = DocumentValidator()
    return _document_validator


# Request/Response Models
class DocumentValidationRequest(BaseModel):
    """Request model for document validation"""
    document: Dict[str, Any] = Field(..., description="Document data to validate")
    include_recommendations: bool = Field(True, description="Include validation recommendations")


class ValidationRuleResponse(BaseModel):
    """Response model for validation rules"""
    rule_name: str
    level: str
    passed: bool
    message: str
    details: Optional[Dict[str, Any]] = None


class QualityMetricsResponse(BaseModel):
    """Response model for quality metrics"""
    completeness_score: float
    format_score: float
    consistency_score: float
    overall_score: float
    total_rules: int
    passed_rules: int
    warnings: int
    errors: int


class DocumentValidationResponse(BaseModel):
    """Response model for document validation"""
    document_id: str
    document_type: str
    validation_timestamp: str
    is_valid: bool
    quality_metrics: QualityMetricsResponse
    validation_rules: List[ValidationRuleResponse]
    recommendations: List[str]
    processing_time_ms: float


class BatchValidationRequest(BaseModel):
    """Request model for batch validation"""
    documents: List[Dict[str, Any]] = Field(..., description="List of documents to validate", max_items=100)
    include_recommendations: bool = Field(True, description="Include validation recommendations")


class BatchValidationResponse(BaseModel):
    """Response model for batch validation"""
    total_documents: int
    valid_documents: int
    invalid_documents: int
    validation_results: List[DocumentValidationResponse]
    processing_summary: Dict[str, Any]


class URNValidationRequest(BaseModel):
    """Request model for URN validation"""
    urn: str = Field(..., description="URN to validate")


class URNValidationResponse(BaseModel):
    """Response model for URN validation"""
    urn: str
    is_valid: bool
    message: str
    details: Dict[str, Any]
    normalized_urn: Optional[str] = None


# Create router
router = APIRouter(prefix="/api/v1/validation", tags=["Document Validation"])


@router.post("/document", response_model=DocumentValidationResponse)
async def validate_document(
    request: DocumentValidationRequest,
    validator: DocumentValidator = Depends(get_document_validator)
):
    """
    Validate a single document for compliance and quality
    
    Args:
        request: Document validation request
        
    Returns:
        Comprehensive validation result with quality metrics
    """
    if not VALIDATION_AVAILABLE:
        raise HTTPException(status_code=503, detail="Document validation service not available")
    
    try:
        result = validator.validate_document(request.document)
        
        # Convert to response format
        quality_metrics = QualityMetricsResponse(
            completeness_score=result.quality_metrics.completeness_score,
            format_score=result.quality_metrics.format_score,
            consistency_score=result.quality_metrics.consistency_score,
            overall_score=result.quality_metrics.overall_score,
            total_rules=result.quality_metrics.total_rules,
            passed_rules=result.quality_metrics.passed_rules,
            warnings=result.quality_metrics.warnings,
            errors=result.quality_metrics.errors
        )
        
        validation_rules = [
            ValidationRuleResponse(
                rule_name=rule.rule_name,
                level=rule.level.value,
                passed=rule.passed,
                message=rule.message,
                details=rule.details
            )
            for rule in result.validation_rules
        ]
        
        return DocumentValidationResponse(
            document_id=result.document_id,
            document_type=result.document_type.value,
            validation_timestamp=result.validation_timestamp,
            is_valid=result.is_valid,
            quality_metrics=quality_metrics,
            validation_rules=validation_rules,
            recommendations=result.recommendations if request.include_recommendations else [],
            processing_time_ms=result.processing_time_ms
        )
        
    except Exception as e:
        logger.error(f"Document validation failed: {e}")
        raise HTTPException(status_code=500, detail="Document validation failed")


@router.post("/batch", response_model=BatchValidationResponse)
async def validate_documents_batch(
    request: BatchValidationRequest,
    background_tasks: BackgroundTasks,
    validator: DocumentValidator = Depends(get_document_validator)
):
    """
    Validate multiple documents in batch
    
    Args:
        request: Batch validation request
        background_tasks: Background task manager
        
    Returns:
        Batch validation results with summary statistics
    """
    if not VALIDATION_AVAILABLE:
        raise HTTPException(status_code=503, detail="Document validation service not available")
    
    try:
        results = validator.batch_validate_documents(request.documents)
        
        # Convert results to response format
        validation_responses = []
        valid_count = 0
        
        for result in results:
            quality_metrics = QualityMetricsResponse(
                completeness_score=result.quality_metrics.completeness_score,
                format_score=result.quality_metrics.format_score,
                consistency_score=result.quality_metrics.consistency_score,
                overall_score=result.quality_metrics.overall_score,
                total_rules=result.quality_metrics.total_rules,
                passed_rules=result.quality_metrics.passed_rules,
                warnings=result.quality_metrics.warnings,
                errors=result.quality_metrics.errors
            )
            
            validation_rules = [
                ValidationRuleResponse(
                    rule_name=rule.rule_name,
                    level=rule.level.value,
                    passed=rule.passed,
                    message=rule.message,
                    details=rule.details
                )
                for rule in result.validation_rules
            ]
            
            validation_responses.append(DocumentValidationResponse(
                document_id=result.document_id,
                document_type=result.document_type.value,
                validation_timestamp=result.validation_timestamp,
                is_valid=result.is_valid,
                quality_metrics=quality_metrics,
                validation_rules=validation_rules,
                recommendations=result.recommendations if request.include_recommendations else [],
                processing_time_ms=result.processing_time_ms
            ))
            
            if result.is_valid:
                valid_count += 1
        
        # Calculate summary statistics
        total_documents = len(results)
        invalid_count = total_documents - valid_count
        avg_processing_time = sum(r.processing_time_ms for r in results) / max(total_documents, 1)
        avg_quality_score = sum(r.quality_metrics.overall_score for r in results) / max(total_documents, 1)
        
        processing_summary = {
            "average_processing_time_ms": avg_processing_time,
            "average_quality_score": avg_quality_score,
            "total_errors": sum(r.quality_metrics.errors for r in results),
            "total_warnings": sum(r.quality_metrics.warnings for r in results)
        }
        
        return BatchValidationResponse(
            total_documents=total_documents,
            valid_documents=valid_count,
            invalid_documents=invalid_count,
            validation_results=validation_responses,
            processing_summary=processing_summary
        )
        
    except Exception as e:
        logger.error(f"Batch validation failed: {e}")
        raise HTTPException(status_code=500, detail="Batch validation failed")


@router.post("/urn", response_model=URNValidationResponse)
async def validate_urn(
    request: URNValidationRequest,
    validator: DocumentValidator = Depends(get_document_validator)
):
    """
    Validate URN format according to Brazilian legislative standards
    
    Args:
        request: URN validation request
        
    Returns:
        URN validation result with normalization suggestion
    """
    if not VALIDATION_AVAILABLE:
        raise HTTPException(status_code=503, detail="Document validation service not available")
    
    try:
        # Use URN validator directly
        is_valid, message, details = validator.urn_validator.validate_urn_format(request.urn)
        normalized_urn = validator.urn_validator.normalize_urn(request.urn)
        
        return URNValidationResponse(
            urn=request.urn,
            is_valid=is_valid,
            message=message,
            details=details,
            normalized_urn=normalized_urn if normalized_urn != request.urn else None
        )
        
    except Exception as e:
        logger.error(f"URN validation failed: {e}")
        raise HTTPException(status_code=500, detail="URN validation failed")


@router.get("/quality-report")
async def get_quality_report(
    document_ids: Optional[str] = None,
    validator: DocumentValidator = Depends(get_document_validator)
):
    """
    Get quality report for documents
    
    Args:
        document_ids: Comma-separated list of document IDs (optional)
        
    Returns:
        Quality report with aggregated metrics
    """
    try:
        # This would typically query a database for stored validation results
        # For now, return a sample report structure
        
        return {
            "report_timestamp": "2024-12-27T10:00:00Z",
            "documents_analyzed": 0,
            "quality_summary": {
                "average_quality_score": 0.0,
                "documents_by_quality": {
                    "excellent": 0,  # > 0.9
                    "good": 0,       # 0.7-0.9
                    "fair": 0,       # 0.5-0.7
                    "poor": 0        # < 0.5
                },
                "common_issues": []
            },
            "validation_trends": {
                "improvement_areas": [],
                "quality_trend": "stable"
            }
        }
        
    except Exception as e:
        logger.error(f"Quality report generation failed: {e}")
        raise HTTPException(status_code=500, detail="Quality report generation failed")


@router.get("/rules")
async def get_validation_rules():
    """
    Get available validation rules and their descriptions
    
    Returns:
        List of validation rules with descriptions and severity levels
    """
    return {
        "validation_rules": [
            {
                "rule_name": "urn_present",
                "description": "Checks if document has a URN",
                "level": "error",
                "category": "identification"
            },
            {
                "rule_name": "urn_format",
                "description": "Validates URN format against Brazilian standards",
                "level": "error",
                "category": "identification"
            },
            {
                "rule_name": "required_fields",
                "description": "Checks presence of required metadata fields",
                "level": "error",
                "category": "metadata"
            },
            {
                "rule_name": "recommended_fields",
                "description": "Checks presence of recommended metadata fields",
                "level": "warning",
                "category": "metadata"
            },
            {
                "rule_name": "title_length",
                "description": "Validates document title length",
                "level": "warning",
                "category": "content"
            },
            {
                "rule_name": "date_format",
                "description": "Validates date format (YYYY-MM-DD)",
                "level": "error",
                "category": "metadata"
            },
            {
                "rule_name": "content_length",
                "description": "Validates document content length",
                "level": "warning",
                "category": "content"
            },
            {
                "rule_name": "transport_metadata",
                "description": "Transport-specific metadata validation",
                "level": "info",
                "category": "domain"
            }
        ],
        "validation_levels": [
            {"level": "error", "description": "Critical issues that prevent processing"},
            {"level": "warning", "description": "Issues that may affect quality"},
            {"level": "info", "description": "Informational notes for improvement"},
            {"level": "success", "description": "Validation passed successfully"}
        ]
    }


@router.get("/statistics")
async def get_validation_statistics(
    validator: DocumentValidator = Depends(get_document_validator)
):
    """
    Get validator statistics and capabilities
    
    Returns:
        Validator statistics and configuration information
    """
    try:
        if VALIDATION_AVAILABLE:
            stats = validator.get_validation_statistics()
        else:
            stats = {
                "validator_version": "mock",
                "supported_document_types": [],
                "capabilities": {},
                "validation_rules": {}
            }
        
        return {
            "status": "operational" if VALIDATION_AVAILABLE else "unavailable",
            "statistics": stats,
            "features": {
                "document_validation": VALIDATION_AVAILABLE,
                "batch_processing": VALIDATION_AVAILABLE,
                "urn_validation": VALIDATION_AVAILABLE,
                "quality_metrics": VALIDATION_AVAILABLE,
                "transport_domain_validation": VALIDATION_AVAILABLE
            }
        }
        
    except Exception as e:
        logger.error(f"Statistics retrieval failed: {e}")
        return {
            "status": "error",
            "error": str(e)
        }


@router.get("/health")
async def validation_health_check():
    """
    Health check endpoint for document validation service
    
    Returns:
        Service health status and capabilities
    """
    try:
        validator = await get_document_validator()
        
        return {
            "status": "healthy" if VALIDATION_AVAILABLE else "degraded",
            "validator_available": VALIDATION_AVAILABLE,
            "features_available": [
                "document_validation",
                "batch_processing", 
                "urn_validation",
                "quality_metrics"
            ] if VALIDATION_AVAILABLE else [],
            "supported_document_types": [
                "lei", "decreto", "portaria", "resolucao", 
                "medida_provisoria", "projeto_lei"
            ] if VALIDATION_AVAILABLE else []
        }
        
    except Exception as e:
        logger.error(f"Validation health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e)
        }