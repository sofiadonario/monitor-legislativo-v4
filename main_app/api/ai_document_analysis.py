"""
AI Document Analysis API Endpoints
==================================

FastAPI endpoints for AI-powered document analysis and citation generation.
Provides intelligent document summarization, metadata extraction, content analysis,
and academic citation generation for Brazilian legislative documents.

Features:
- AI-powered document summarization with academic focus
- Intelligent metadata extraction and enhancement
- Comprehensive content analysis and quality metrics
- Document relationship discovery
- AI-enhanced citation generation with multiple styles
- Cost-optimized processing with semantic caching
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
import logging
import sys
from pathlib import Path

# Import AI document analysis components
sys.path.append(str(Path(__file__).parent.parent.parent / "core"))

try:
    from ai.document_analyzer import (
        DocumentAnalysisEngine,
        DocumentSummary,
        MetadataExtraction,
        ContentAnalysis,
        RelationshipDiscovery
    )
    from ai.citation_generator import (
        AICitationGenerator,
        CitationRequest,
        CitationResult
    )
    from cache.redis_config import get_redis_client
    AI_DOCUMENT_ANALYSIS_AVAILABLE = True
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.warning(f"AI document analysis not available: {e}")
    AI_DOCUMENT_ANALYSIS_AVAILABLE = False
    
    # Mock classes for when AI document analysis is not available
    class DocumentAnalysisEngine:
        def __init__(self, *args, **kwargs): pass
        async def analyze_document_comprehensive(self, doc): return {}
        async def generate_document_summary(self, doc): return None
        async def extract_enhanced_metadata(self, doc): return None
        async def analyze_document_content(self, doc): return None
        async def discover_document_relationships(self, doc): return None
        async def get_analysis_statistics(self): return {}
    
    class AICitationGenerator:
        def __init__(self, *args, **kwargs): pass
        async def generate_citation(self, request): return None
        async def get_supported_styles(self): return []
        async def batch_generate_citations(self, requests): return []
        async def get_citation_statistics(self): return {}
    
    class DocumentSummary:
        def __init__(self, **kwargs): pass
    
    class MetadataExtraction:
        def __init__(self, **kwargs): pass
    
    class ContentAnalysis:
        def __init__(self, **kwargs): pass
    
    class RelationshipDiscovery:
        def __init__(self, **kwargs): pass
    
    class CitationRequest:
        def __init__(self, **kwargs): pass
    
    class CitationResult:
        def __init__(self, **kwargs): pass

logger = logging.getLogger(__name__)

# Global instances
_analysis_engine: Optional[DocumentAnalysisEngine] = None
_citation_generator: Optional[AICitationGenerator] = None


async def get_analysis_engine() -> DocumentAnalysisEngine:
    """Dependency to get initialized document analysis engine"""
    global _analysis_engine
    
    if not AI_DOCUMENT_ANALYSIS_AVAILABLE:
        raise HTTPException(status_code=503, detail="AI document analysis service not available")
    
    if _analysis_engine is None:
        try:
            redis_client = await get_redis_client()
            _analysis_engine = DocumentAnalysisEngine(redis_client)
            logger.info("Document analysis engine initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize document analysis engine: {e}")
            raise HTTPException(status_code=503, detail="Document analysis engine initialization failed")
    
    return _analysis_engine


async def get_citation_generator() -> AICitationGenerator:
    """Dependency to get initialized citation generator"""
    global _citation_generator
    
    if not AI_DOCUMENT_ANALYSIS_AVAILABLE:
        raise HTTPException(status_code=503, detail="AI citation generator service not available")
    
    if _citation_generator is None:
        try:
            redis_client = await get_redis_client()
            _citation_generator = AICitationGenerator(redis_client)
            logger.info("AI citation generator initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize citation generator: {e}")
            raise HTTPException(status_code=503, detail="Citation generator initialization failed")
    
    return _citation_generator


# Request/Response Models
class DocumentAnalysisRequest(BaseModel):
    """Request model for document analysis"""
    document_data: Dict[str, Any] = Field(..., description="Document data with content and metadata")
    analysis_type: str = Field("comprehensive", description="Type of analysis (comprehensive, summary, metadata, content, relationships)")
    include_ai_enhancements: bool = Field(True, description="Include AI-powered enhancements")


class DocumentSummaryResponse(BaseModel):
    """Response model for document summary"""
    document_id: str
    title: str
    summary_text: str
    key_points: List[str]
    main_concepts: List[str]
    legal_references: List[str]
    geographic_scope: Optional[str]
    transport_relevance: Optional[str]
    academic_impact: str
    confidence_score: float
    processing_time_ms: float
    cost_cents: float


class MetadataExtractionResponse(BaseModel):
    """Response model for metadata extraction"""
    document_id: str
    extracted_metadata: Dict[str, Any]
    confidence_scores: Dict[str, float]
    enhancements_applied: List[str]
    processing_time_ms: float
    cost_cents: float


class ContentAnalysisResponse(BaseModel):
    """Response model for content analysis"""
    document_id: str
    text_statistics: Dict[str, Any]
    readability_score: float
    complexity_level: str
    language_quality: str
    structure_analysis: Dict[str, Any]
    terminology_analysis: Dict[str, float]
    anomalies_detected: List[str]
    processing_time_ms: float
    cost_cents: float


class RelationshipDiscoveryResponse(BaseModel):
    """Response model for relationship discovery"""
    document_id: str
    related_documents: List[Dict[str, Any]]
    legal_connections: Dict[str, List[str]]
    thematic_relationships: List[Dict[str, Any]]
    confidence_scores: Dict[str, float]
    processing_time_ms: float
    cost_cents: float


class ComprehensiveAnalysisResponse(BaseModel):
    """Response model for comprehensive document analysis"""
    document_id: str
    analysis_timestamp: str
    summary: Optional[DocumentSummaryResponse]
    metadata: Optional[MetadataExtractionResponse]
    content: Optional[ContentAnalysisResponse]
    relationships: Optional[RelationshipDiscoveryResponse]
    analysis_statistics: Dict[str, Any]


class CitationGenerationRequest(BaseModel):
    """Request model for citation generation"""
    document_data: Dict[str, Any] = Field(..., description="Document data for citation")
    citation_style: str = Field("abnt", description="Citation style (abnt, apa, chicago, vancouver)")
    include_url: bool = Field(True, description="Include URL in citation")
    include_access_date: bool = Field(True, description="Include access date")
    academic_level: str = Field("graduate", description="Academic level (undergraduate, graduate, postgraduate)")
    research_context: Optional[str] = Field(None, description="Research context for enhanced citations")


class CitationGenerationResponse(BaseModel):
    """Response model for citation generation"""
    citation_text: str
    citation_style: str
    document_id: str
    validation_status: str
    quality_score: float
    ai_enhancements: List[str]
    quality_metrics: Dict[str, float]
    suggestions: List[str]
    processing_time_ms: float
    cost_cents: float
    from_cache: bool


class BatchCitationRequest(BaseModel):
    """Request model for batch citation generation"""
    citations: List[CitationGenerationRequest] = Field(..., description="List of citation requests", max_items=50)


class BatchCitationResponse(BaseModel):
    """Response model for batch citation generation"""
    total_citations: int
    successful_citations: int
    failed_citations: int
    citations: List[CitationGenerationResponse]
    batch_statistics: Dict[str, Any]


# Create router
router = APIRouter(prefix="/api/v1/ai-analysis", tags=["AI Document Analysis"])


@router.post("/analyze", response_model=ComprehensiveAnalysisResponse)
async def analyze_document(
    request: DocumentAnalysisRequest,
    analysis_engine: DocumentAnalysisEngine = Depends(get_analysis_engine)
):
    """
    Perform AI-powered comprehensive document analysis
    
    Args:
        request: Document analysis request
        
    Returns:
        Comprehensive analysis results
    """
    if not AI_DOCUMENT_ANALYSIS_AVAILABLE:
        raise HTTPException(status_code=503, detail="AI document analysis service not available")
    
    try:
        if request.analysis_type == "comprehensive":
            result = await analysis_engine.analyze_document_comprehensive(request.document_data)
            
            return ComprehensiveAnalysisResponse(
                document_id=result["document_id"],
                analysis_timestamp=result["analysis_timestamp"],
                summary=result.get("summary"),
                metadata=result.get("metadata"),
                content=result.get("content"),
                relationships=result.get("relationships"),
                analysis_statistics=result["analysis_statistics"]
            )
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported analysis type: {request.analysis_type}")
        
    except Exception as e:
        logger.error(f"Document analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Document analysis failed: {str(e)}")


@router.post("/summarize", response_model=DocumentSummaryResponse)
async def summarize_document(
    document_data: Dict[str, Any],
    analysis_engine: DocumentAnalysisEngine = Depends(get_analysis_engine)
):
    """
    Generate AI-powered document summary
    
    Args:
        document_data: Document data with content
        
    Returns:
        Document summary with key insights
    """
    try:
        summary = await analysis_engine.generate_document_summary(document_data)
        
        return DocumentSummaryResponse(
            document_id=summary.document_id,
            title=summary.title,
            summary_text=summary.summary_text,
            key_points=summary.key_points,
            main_concepts=summary.main_concepts,
            legal_references=summary.legal_references,
            geographic_scope=summary.geographic_scope,
            transport_relevance=summary.transport_relevance,
            academic_impact=summary.academic_impact,
            confidence_score=summary.confidence_score,
            processing_time_ms=summary.processing_time_ms,
            cost_cents=summary.cost_cents
        )
        
    except Exception as e:
        logger.error(f"Document summarization failed: {e}")
        raise HTTPException(status_code=500, detail=f"Document summarization failed: {str(e)}")


@router.post("/extract-metadata", response_model=MetadataExtractionResponse)
async def extract_metadata(
    document_data: Dict[str, Any],
    analysis_engine: DocumentAnalysisEngine = Depends(get_analysis_engine)
):
    """
    Extract and enhance document metadata using AI
    
    Args:
        document_data: Document data for metadata extraction
        
    Returns:
        Enhanced metadata with confidence scores
    """
    try:
        metadata = await analysis_engine.extract_enhanced_metadata(document_data)
        
        return MetadataExtractionResponse(
            document_id=metadata.document_id,
            extracted_metadata={
                "title": metadata.extracted_title,
                "document_type": metadata.document_type,
                "issuing_authority": metadata.issuing_authority,
                "publication_date": metadata.publication_date,
                "effective_date": metadata.effective_date,
                "legal_basis": metadata.legal_basis,
                "subject_areas": metadata.subject_areas,
                "keywords": metadata.keywords,
                "geographic_mentions": metadata.geographic_mentions,
                "entities_mentioned": metadata.entities_mentioned,
                "transport_modes": metadata.transport_modes,
                "regulatory_level": metadata.regulatory_level
            },
            confidence_scores=metadata.confidence_scores,
            enhancements_applied=["AI-powered extraction", "Pattern-based validation"],
            processing_time_ms=metadata.processing_time_ms,
            cost_cents=metadata.cost_cents
        )
        
    except Exception as e:
        logger.error(f"Metadata extraction failed: {e}")
        raise HTTPException(status_code=500, detail=f"Metadata extraction failed: {str(e)}")


@router.post("/analyze-content", response_model=ContentAnalysisResponse)
async def analyze_content(
    document_data: Dict[str, Any],
    analysis_engine: DocumentAnalysisEngine = Depends(get_analysis_engine)
):
    """
    Perform comprehensive content analysis
    
    Args:
        document_data: Document data for content analysis
        
    Returns:
        Content analysis with quality metrics
    """
    try:
        analysis = await analysis_engine.analyze_document_content(document_data)
        
        return ContentAnalysisResponse(
            document_id=analysis.document_id,
            text_statistics=analysis.text_statistics,
            readability_score=analysis.readability_score,
            complexity_level=analysis.complexity_level,
            language_quality=analysis.language_quality,
            structure_analysis=analysis.structure_analysis,
            terminology_analysis={
                "legal_terminology_density": analysis.legal_terminology_density,
                "technical_terminology_density": analysis.technical_terminology_density
            },
            anomalies_detected=analysis.anomalies_detected,
            processing_time_ms=analysis.processing_time_ms,
            cost_cents=analysis.cost_cents
        )
        
    except Exception as e:
        logger.error(f"Content analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Content analysis failed: {str(e)}")


@router.post("/discover-relationships", response_model=RelationshipDiscoveryResponse)
async def discover_relationships(
    document_data: Dict[str, Any],
    analysis_engine: DocumentAnalysisEngine = Depends(get_analysis_engine)
):
    """
    Discover document relationships and connections
    
    Args:
        document_data: Document data for relationship discovery
        
    Returns:
        Document relationships and legal connections
    """
    try:
        relationships = await analysis_engine.discover_document_relationships(document_data)
        
        return RelationshipDiscoveryResponse(
            document_id=relationships.document_id,
            related_documents=relationships.related_documents,
            legal_connections={
                "legal_precedents": relationships.legal_precedents,
                "superseded_documents": relationships.superseded_documents,
                "implementing_regulations": relationships.implementing_regulations,
                "cited_authorities": relationships.cited_authorities
            },
            thematic_relationships=relationships.thematic_connections,
            confidence_scores=relationships.confidence_scores,
            processing_time_ms=relationships.processing_time_ms,
            cost_cents=relationships.cost_cents
        )
        
    except Exception as e:
        logger.error(f"Relationship discovery failed: {e}")
        raise HTTPException(status_code=500, detail=f"Relationship discovery failed: {str(e)}")


@router.post("/generate-citation", response_model=CitationGenerationResponse)
async def generate_citation(
    request: CitationGenerationRequest,
    citation_generator: AICitationGenerator = Depends(get_citation_generator)
):
    """
    Generate AI-enhanced academic citation
    
    Args:
        request: Citation generation request
        
    Returns:
        Generated citation with quality metrics
    """
    try:
        citation_request = CitationRequest(
            document_data=request.document_data,
            citation_style=request.citation_style,
            include_url=request.include_url,
            include_access_date=request.include_access_date,
            academic_level=request.academic_level,
            research_context=request.research_context
        )
        
        result = await citation_generator.generate_citation(citation_request)
        
        return CitationGenerationResponse(
            citation_text=result.citation_text,
            citation_style=result.citation_style,
            document_id=result.document_id,
            validation_status=result.validation_status,
            quality_score=result.quality_score,
            ai_enhancements=result.ai_enhancements,
            quality_metrics={
                "metadata_completeness": result.metadata_completeness,
                "formatting_accuracy": result.formatting_accuracy,
                "academic_compliance": result.academic_compliance
            },
            suggestions=result.suggestions,
            processing_time_ms=result.processing_time_ms,
            cost_cents=result.cost_cents,
            from_cache=result.from_cache
        )
        
    except Exception as e:
        logger.error(f"Citation generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Citation generation failed: {str(e)}")


@router.post("/generate-citations-batch", response_model=BatchCitationResponse)
async def generate_citations_batch(
    request: BatchCitationRequest,
    background_tasks: BackgroundTasks,
    citation_generator: AICitationGenerator = Depends(get_citation_generator)
):
    """
    Generate multiple citations in batch
    
    Args:
        request: Batch citation request
        background_tasks: Background task manager
        
    Returns:
        Batch citation results
    """
    try:
        # Convert to citation requests
        citation_requests = []
        for cite_req in request.citations:
            citation_requests.append(CitationRequest(
                document_data=cite_req.document_data,
                citation_style=cite_req.citation_style,
                include_url=cite_req.include_url,
                include_access_date=cite_req.include_access_date,
                academic_level=cite_req.academic_level,
                research_context=cite_req.research_context
            ))
        
        # Generate citations
        results = await citation_generator.batch_generate_citations(citation_requests)
        
        # Convert results
        citation_responses = []
        successful_count = 0
        failed_count = 0
        total_cost = 0.0
        
        for result in results:
            if result.validation_status != "error":
                successful_count += 1
            else:
                failed_count += 1
            
            total_cost += result.cost_cents
            
            citation_responses.append(CitationGenerationResponse(
                citation_text=result.citation_text,
                citation_style=result.citation_style,
                document_id=result.document_id,
                validation_status=result.validation_status,
                quality_score=result.quality_score,
                ai_enhancements=result.ai_enhancements,
                quality_metrics={
                    "metadata_completeness": result.metadata_completeness,
                    "formatting_accuracy": result.formatting_accuracy,
                    "academic_compliance": result.academic_compliance
                },
                suggestions=result.suggestions,
                processing_time_ms=result.processing_time_ms,
                cost_cents=result.cost_cents,
                from_cache=result.from_cache
            ))
        
        return BatchCitationResponse(
            total_citations=len(results),
            successful_citations=successful_count,
            failed_citations=failed_count,
            citations=citation_responses,
            batch_statistics={
                "total_cost_cents": total_cost,
                "average_quality_score": sum(r.quality_score for r in results) / len(results),
                "cache_hit_rate": sum(1 for r in results if r.from_cache) / len(results) * 100
            }
        )
        
    except Exception as e:
        logger.error(f"Batch citation generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Batch citation generation failed: {str(e)}")


@router.get("/citation-styles")
async def get_citation_styles(
    citation_generator: AICitationGenerator = Depends(get_citation_generator)
):
    """
    Get supported citation styles
    
    Returns:
        List of supported citation styles with descriptions
    """
    try:
        styles = await citation_generator.get_supported_styles()
        
        return {
            "supported_styles": styles,
            "default_style": "abnt",
            "total_styles": len(styles)
        }
        
    except Exception as e:
        logger.error(f"Citation styles retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Citation styles retrieval failed: {str(e)}")


@router.get("/analysis-statistics")
async def get_analysis_statistics(
    analysis_engine: DocumentAnalysisEngine = Depends(get_analysis_engine)
):
    """
    Get document analysis engine statistics
    
    Returns:
        Analysis engine performance and usage statistics
    """
    try:
        stats = await analysis_engine.get_analysis_statistics()
        
        return {
            "status": "success",
            "analysis_statistics": stats
        }
        
    except Exception as e:
        logger.error(f"Analysis statistics retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis statistics retrieval failed: {str(e)}")


@router.get("/citation-statistics")
async def get_citation_statistics(
    citation_generator: AICitationGenerator = Depends(get_citation_generator)
):
    """
    Get citation generator statistics
    
    Returns:
        Citation generator performance and usage statistics
    """
    try:
        stats = await citation_generator.get_citation_statistics()
        
        return {
            "status": "success",
            "citation_statistics": stats
        }
        
    except Exception as e:
        logger.error(f"Citation statistics retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Citation statistics retrieval failed: {str(e)}")


@router.get("/health")
async def ai_analysis_health_check():
    """
    Health check endpoint for AI document analysis service
    
    Returns:
        Service health status and capabilities
    """
    try:
        if not AI_DOCUMENT_ANALYSIS_AVAILABLE:
            return {
                "status": "unavailable",
                "ai_document_analysis_available": False,
                "message": "AI document analysis service not available"
            }
        
        # Try to get engines
        try:
            analysis_engine = await get_analysis_engine()
            citation_generator = await get_citation_generator()
            
            analysis_stats = await analysis_engine.get_analysis_statistics()
            citation_stats = await citation_generator.get_citation_statistics()
            
            return {
                "status": "healthy",
                "ai_document_analysis_available": True,
                "analysis_engine_status": analysis_stats["engine_status"],
                "citation_generator_status": citation_stats["generator_status"],
                "features_available": [
                    "comprehensive_document_analysis",
                    "ai_powered_summarization",
                    "intelligent_metadata_extraction",
                    "content_analysis_and_quality_metrics",
                    "document_relationship_discovery",
                    "ai_enhanced_citation_generation",
                    "multiple_citation_styles",
                    "batch_processing",
                    "cost_optimization"
                ],
                "supported_citation_styles": citation_stats["supported_styles"]
            }
            
        except Exception as e:
            return {
                "status": "degraded",
                "ai_document_analysis_available": True,
                "error": str(e),
                "message": "AI document analysis service experiencing issues"
            }
        
    except Exception as e:
        logger.error(f"AI analysis health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e)
        }