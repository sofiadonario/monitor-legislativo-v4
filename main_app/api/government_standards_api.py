"""
Government Standards API Router
FastAPI endpoints for Brazilian government document standards validation
"""
from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
import logging
from datetime import datetime

from core.data_processing.government_standards import (
    GovernmentStandardsProcessor,
    DigitizationLevel,
    DataQualityScore,
    ValidationResult
)
from core.models.legislative_data import LegislativeDocument

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/standards", tags=["Government Standards"])

# Global processor instance
standards_processor: Optional[GovernmentStandardsProcessor] = None

async def get_standards_processor() -> GovernmentStandardsProcessor:
    """Get or create government standards processor instance."""
    global standards_processor
    if standards_processor is None:
        standards_processor = GovernmentStandardsProcessor()
    return standards_processor

# Pydantic models for API
class DocumentInput(BaseModel):
    id: str
    title: str
    summary: str
    data_evento: Optional[str] = None
    tipo_documento: Optional[str] = None
    fonte: Optional[str] = None
    autor: Optional[str] = None
    autoridade: Optional[str] = None
    urn: Optional[str] = None
    url: Optional[str] = None
    content: Optional[str] = None

class ValidationResultResponse(BaseModel):
    document_id: str
    overall_score: float
    quality_level: str
    digitization_level: int
    digitization_level_name: str
    compliance_percentage: float
    issues: List[str]
    recommendations: List[str]
    validation_timestamp: str
    metadata_completeness: float
    structure_compliance: float
    semantic_richness: float
    rule_results: Dict[str, Any]

class ProcessingRecommendationResponse(BaseModel):
    type: str
    description: Optional[str] = None
    current_level: Optional[str] = None
    target_level: Optional[str] = None
    recommended_pipeline: Optional[str] = None
    priority: str
    completeness: Optional[float] = None
    compliance: Optional[float] = None

class PipelineResponse(BaseModel):
    pipeline_id: str
    name: str
    description: str
    stages: List[str]
    validation_checkpoints: List[str]
    target_level: int
    target_level_name: str

class ValidationRuleResponse(BaseModel):
    rule_id: str
    name: str
    description: str
    category: str
    required_level: int
    required_level_name: str
    weight: float

def convert_digitization_level_name(level: DigitizationLevel) -> str:
    """Convert digitization level enum to readable name."""
    level_names = {
        DigitizationLevel.LEVEL_1_PAPER_SCAN: "Paper Scan",
        DigitizationLevel.LEVEL_2_OCR_TEXT: "OCR Text",
        DigitizationLevel.LEVEL_3_STRUCTURED: "Structured Data",
        DigitizationLevel.LEVEL_4_SEMANTIC: "Semantic Markup",
        DigitizationLevel.LEVEL_5_LINKED_DATA: "Linked Data"
    }
    return level_names.get(level, "Unknown")

def convert_validation_result(result: ValidationResult) -> ValidationResultResponse:
    """Convert ValidationResult to response model."""
    return ValidationResultResponse(
        document_id=result.document_id,
        overall_score=result.overall_score,
        quality_level=result.quality_level.value,
        digitization_level=result.digitization_level.value,
        digitization_level_name=convert_digitization_level_name(result.digitization_level),
        compliance_percentage=result.compliance_percentage,
        issues=result.issues,
        recommendations=result.recommendations,
        validation_timestamp=result.validation_timestamp.isoformat(),
        metadata_completeness=result.metadata_completeness,
        structure_compliance=result.structure_compliance,
        semantic_richness=result.semantic_richness,
        rule_results=result.rule_results
    )

@router.post("/validate", response_model=ValidationResultResponse)
async def validate_document(
    document: DocumentInput,
    target_level: int = Query(3, description="Target digitization level (1-5)")
):
    """Validate document against Brazilian government standards."""
    try:
        processor = await get_standards_processor()
        
        # Validate target level
        if target_level not in range(1, 6):
            raise HTTPException(status_code=400, detail="Target level must be between 1 and 5")
        
        target_enum = DigitizationLevel(target_level)
        
        # Convert input to LegislativeDocument
        legislative_doc = LegislativeDocument(
            id=document.id,
            title=document.title,
            summary=document.summary,
            data_evento=document.data_evento or "",
            tipo_documento=document.tipo_documento or "",
            fonte=document.fonte or ""
        )
        
        # Add optional fields if provided
        if document.autor:
            setattr(legislative_doc, 'autor', document.autor)
        if document.autoridade:
            setattr(legislative_doc, 'autoridade', document.autoridade)
        if document.urn:
            setattr(legislative_doc, 'urn', document.urn)
        if document.url:
            setattr(legislative_doc, 'url', document.url)
        if document.content:
            setattr(legislative_doc, 'content', document.content)
        
        # Perform validation
        result = await processor.validate_document(legislative_doc, target_enum)
        
        return convert_validation_result(result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error validating document: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Document validation failed: {str(e)}")

@router.post("/validate-batch", response_model=List[ValidationResultResponse])
async def validate_documents_batch(
    documents: List[DocumentInput],
    target_level: int = Query(3, description="Target digitization level (1-5)")
):
    """Validate multiple documents against Brazilian government standards."""
    try:
        processor = await get_standards_processor()
        
        # Validate target level
        if target_level not in range(1, 6):
            raise HTTPException(status_code=400, detail="Target level must be between 1 and 5")
        
        target_enum = DigitizationLevel(target_level)
        
        results = []
        for doc_input in documents:
            try:
                # Convert to LegislativeDocument
                legislative_doc = LegislativeDocument(
                    id=doc_input.id,
                    title=doc_input.title,
                    summary=doc_input.summary,
                    data_evento=doc_input.data_evento or "",
                    tipo_documento=doc_input.tipo_documento or "",
                    fonte=doc_input.fonte or ""
                )
                
                # Add optional fields
                if doc_input.autor:
                    setattr(legislative_doc, 'autor', doc_input.autor)
                if doc_input.autoridade:
                    setattr(legislative_doc, 'autoridade', doc_input.autoridade)
                if doc_input.urn:
                    setattr(legislative_doc, 'urn', doc_input.urn)
                if doc_input.url:
                    setattr(legislative_doc, 'url', doc_input.url)
                if doc_input.content:
                    setattr(legislative_doc, 'content', doc_input.content)
                
                # Validate document
                result = await processor.validate_document(legislative_doc, target_enum)
                results.append(convert_validation_result(result))
                
            except Exception as e:
                logger.warning(f"Failed to validate document {doc_input.id}: {str(e)}")
                # Create error result
                error_result = ValidationResultResponse(
                    document_id=doc_input.id,
                    overall_score=0.0,
                    quality_level="critical",
                    digitization_level=1,
                    digitization_level_name="Paper Scan",
                    compliance_percentage=0.0,
                    issues=[f"Validation error: {str(e)}"],
                    recommendations=["Fix document format and retry validation"],
                    validation_timestamp=datetime.now().isoformat(),
                    metadata_completeness=0.0,
                    structure_compliance=0.0,
                    semantic_richness=0.0,
                    rule_results={}
                )
                results.append(error_result)
        
        return results
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in batch validation: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Batch validation failed: {str(e)}")

@router.post("/process-pipeline/{pipeline_id}", response_model=ValidationResultResponse)
async def process_with_pipeline(pipeline_id: str, document: DocumentInput):
    """Process document through a specific validation pipeline."""
    try:
        processor = await get_standards_processor()
        
        # Check if pipeline exists
        if pipeline_id not in processor.pipelines:
            available_pipelines = list(processor.pipelines.keys())
            raise HTTPException(
                status_code=404, 
                detail=f"Pipeline not found: {pipeline_id}. Available: {available_pipelines}"
            )
        
        # Convert to LegislativeDocument
        legislative_doc = LegislativeDocument(
            id=document.id,
            title=document.title,
            summary=document.summary,
            data_evento=document.data_evento or "",
            tipo_documento=document.tipo_documento or "",
            fonte=document.fonte or ""
        )
        
        # Add optional fields
        if document.autor:
            setattr(legislative_doc, 'autor', document.autor)
        if document.autoridade:
            setattr(legislative_doc, 'autoridade', document.autoridade)
        if document.urn:
            setattr(legislative_doc, 'urn', document.urn)
        if document.url:
            setattr(legislative_doc, 'url', document.url)
        if document.content:
            setattr(legislative_doc, 'content', document.content)
        
        # Process with pipeline
        result = await processor.process_with_pipeline(legislative_doc, pipeline_id)
        
        return convert_validation_result(result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing with pipeline: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Pipeline processing failed: {str(e)}")

@router.post("/recommendations", response_model=List[ProcessingRecommendationResponse])
async def get_processing_recommendations(validation_result: Dict[str, Any]):
    """Get processing recommendations based on validation results."""
    try:
        processor = await get_standards_processor()
        
        # Convert dict back to ValidationResult object (simplified)
        # In a real implementation, you might want to validate the structure
        result = ValidationResult(
            document_id=validation_result["document_id"],
            overall_score=validation_result["overall_score"],
            quality_level=DataQualityScore(validation_result["quality_level"]),
            digitization_level=DigitizationLevel(validation_result["digitization_level"]),
            rule_results=validation_result["rule_results"],
            compliance_percentage=validation_result["compliance_percentage"],
            issues=validation_result["issues"],
            recommendations=validation_result["recommendations"],
            validation_timestamp=datetime.fromisoformat(validation_result["validation_timestamp"]),
            metadata_completeness=validation_result["metadata_completeness"],
            structure_compliance=validation_result["structure_compliance"],
            semantic_richness=validation_result["semantic_richness"]
        )
        
        # Get recommendations
        recommendations = processor.get_processing_recommendations(result)
        
        # Convert to response format
        response_recommendations = []
        for rec in recommendations:
            response_recommendations.append(ProcessingRecommendationResponse(
                type=rec["type"],
                description=rec.get("description"),
                current_level=rec.get("current_level"),
                target_level=rec.get("target_level"),
                recommended_pipeline=rec.get("recommended_pipeline"),
                priority=rec["priority"],
                completeness=rec.get("completeness"),
                compliance=rec.get("compliance")
            ))
        
        return response_recommendations
        
    except Exception as e:
        logger.error(f"Error getting recommendations: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get recommendations: {str(e)}")

@router.get("/pipelines", response_model=List[PipelineResponse])
async def get_available_pipelines():
    """Get list of available processing pipelines."""
    try:
        processor = await get_standards_processor()
        
        pipeline_responses = []
        for pipeline_id, pipeline in processor.pipelines.items():
            pipeline_responses.append(PipelineResponse(
                pipeline_id=pipeline.pipeline_id,
                name=pipeline.name,
                description=pipeline.description,
                stages=pipeline.stages,
                validation_checkpoints=pipeline.validation_checkpoints,
                target_level=pipeline.target_level.value,
                target_level_name=convert_digitization_level_name(pipeline.target_level)
            ))
        
        return pipeline_responses
        
    except Exception as e:
        logger.error(f"Error getting pipelines: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get pipelines: {str(e)}")

@router.get("/rules", response_model=List[ValidationRuleResponse])
async def get_validation_rules():
    """Get list of all validation rules."""
    try:
        processor = await get_standards_processor()
        
        rule_responses = []
        for rule_id, rule in processor.validation_rules.items():
            rule_responses.append(ValidationRuleResponse(
                rule_id=rule.rule_id,
                name=rule.name,
                description=rule.description,
                category=rule.category,
                required_level=rule.required_level.value,
                required_level_name=convert_digitization_level_name(rule.required_level),
                weight=rule.weight
            ))
        
        return rule_responses
        
    except Exception as e:
        logger.error(f"Error getting validation rules: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get validation rules: {str(e)}")

@router.get("/levels")
async def get_digitization_levels():
    """Get information about digitization maturity levels."""
    try:
        levels = []
        for level in DigitizationLevel:
            levels.append({
                "level": level.value,
                "name": convert_digitization_level_name(level),
                "description": level.name.replace("_", " ").title()
            })
        
        return {
            "digitization_levels": levels,
            "total_levels": len(levels),
            "model": "5-level Brazilian government digitization maturity model"
        }
        
    except Exception as e:
        logger.error(f"Error getting digitization levels: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get digitization levels: {str(e)}")

@router.get("/quality-levels")
async def get_quality_levels():
    """Get information about data quality scoring levels."""
    try:
        quality_levels = []
        for quality in DataQualityScore:
            quality_levels.append({
                "level": quality.value,
                "description": quality.name.replace("_", " ").title()
            })
        
        return {
            "quality_levels": quality_levels,
            "scoring_ranges": {
                "excellent": "90-100%",
                "good": "70-89%",
                "fair": "50-69%",
                "poor": "30-49%",
                "critical": "0-29%"
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting quality levels: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get quality levels: {str(e)}")

@router.get("/health")
async def get_standards_service_health():
    """Get government standards service health status."""
    try:
        processor = await get_standards_processor()
        
        return {
            "status": "healthy",
            "service": "government_standards",
            "components": {
                "validation_rules": "loaded",
                "processing_pipelines": "initialized",
                "digitization_model": "5_level_maturity",
                "quality_scoring": "operational"
            },
            "coverage": {
                "validation_rules": len(processor.validation_rules),
                "processing_pipelines": len(processor.pipelines),
                "digitization_levels": 5,
                "quality_levels": 5
            },
            "standards_compliance": {
                "brazilian_government": "compliant",
                "lexml_urn": "supported",
                "abnt_metadata": "supported",
                "okfn_brasil": "based_on"
            }
        }
        
    except Exception as e:
        logger.error(f"Standards service health check failed: {str(e)}")
        return {
            "status": "unhealthy",
            "service": "government_standards",
            "error": str(e)
        }