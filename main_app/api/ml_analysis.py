"""
ML Text Analysis API Endpoints
=============================

FastAPI endpoints for machine learning text analysis of Brazilian legislative documents.
Provides document classification, similarity analysis, and keyword extraction.

Features:
- Transport legislation classification
- Document similarity detection
- Keyword extraction and categorization
- Text statistics and complexity analysis
- Batch document analysis
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
import logging
import sys
from pathlib import Path

# Import ML analysis components
sys.path.append(str(Path(__file__).parent.parent.parent / "core"))
from ml.text_analyzer import TextAnalysisEngine, DocumentAnalysis, TextStats

logger = logging.getLogger(__name__)

# Global ML analysis engine
_ml_engine: Optional[TextAnalysisEngine] = None


async def get_ml_engine() -> TextAnalysisEngine:
    """Dependency to get initialized ML analysis engine"""
    global _ml_engine
    if _ml_engine is None:
        _ml_engine = TextAnalysisEngine()
        
        # Initialize with sample documents if available
        try:
            from pathlib import Path
            sys.path.append(str(Path(__file__).parent.parent.parent / 'src' / 'data'))
            from real_legislative_data import realLegislativeData
            
            # Convert to analysis format
            documents = []
            for doc in realLegislativeData[:100]:  # Use first 100 for initialization
                documents.append({
                    'id': doc.get('urn', ''),
                    'title': doc.get('title', ''),
                    'content': doc.get('summary', ''),
                    'keywords': doc.get('keywords', [])
                })
            
            await _ml_engine.initialize_with_documents(documents)
            logger.info("ML engine initialized with sample documents")
            
        except Exception as e:
            logger.warning(f"ML engine initialization with documents failed: {e}")
    
    return _ml_engine


# Request/Response Models
class DocumentAnalysisRequest(BaseModel):
    """Request model for document analysis"""
    title: str = Field(..., description="Document title")
    content: str = Field(..., description="Document content")
    doc_id: Optional[str] = Field(None, description="Optional document ID")


class DocumentAnalysisResponse(BaseModel):
    """Response model for document analysis"""
    transport_score: float = Field(..., description="Transport relevance score (0-1)")
    category: str = Field(..., description="Document category")
    keywords: List[str] = Field(..., description="Extracted keywords")
    similarity_scores: Dict[str, float] = Field(..., description="Similar document scores")
    cluster_id: Optional[int] = Field(None, description="Cluster ID if available")
    confidence: float = Field(..., description="Overall confidence score")


class TextStatsResponse(BaseModel):
    """Response model for text statistics"""
    word_count: int
    sentence_count: int
    avg_word_length: float
    complexity_score: float
    transport_keywords_found: int


class BatchAnalysisRequest(BaseModel):
    """Request model for batch analysis"""
    documents: List[Dict[str, Any]] = Field(..., description="List of documents to analyze")


class BatchAnalysisResponse(BaseModel):
    """Response model for batch analysis"""
    analyses: List[DocumentAnalysisResponse]
    total_documents: int
    transport_documents: int
    average_transport_score: float


class SimilarityRequest(BaseModel):
    """Request model for similarity search"""
    text: str = Field(..., description="Text to find similar documents for")
    top_k: int = Field(5, ge=1, le=20, description="Number of similar documents to return")


class SimilarityResponse(BaseModel):
    """Response model for similarity search"""
    similar_documents: List[Dict[str, Any]]
    query_analysis: DocumentAnalysisResponse


# Create router
router = APIRouter(prefix="/api/v1/ml", tags=["ML Analysis"])


@router.post("/analyze", response_model=DocumentAnalysisResponse)
async def analyze_document(
    request: DocumentAnalysisRequest,
    engine: TextAnalysisEngine = Depends(get_ml_engine)
):
    """
    Analyze a single document for transport relevance and extract insights
    
    Args:
        request: Document analysis request with title and content
        
    Returns:
        Comprehensive analysis including transport classification and keywords
    """
    try:
        analysis = engine.analyze_document(
            title=request.title,
            content=request.content,
            doc_id=request.doc_id or ""
        )
        
        return DocumentAnalysisResponse(
            transport_score=analysis.transport_score,
            category=analysis.category,
            keywords=analysis.keywords,
            similarity_scores=analysis.similarity_scores,
            cluster_id=analysis.cluster_id,
            confidence=analysis.confidence
        )
        
    except Exception as e:
        logger.error(f"Document analysis failed: {e}")
        raise HTTPException(status_code=500, detail="Document analysis failed")


@router.post("/analyze/batch", response_model=BatchAnalysisResponse)
async def analyze_documents_batch(
    request: BatchAnalysisRequest,
    background_tasks: BackgroundTasks,
    engine: TextAnalysisEngine = Depends(get_ml_engine)
):
    """
    Analyze multiple documents in batch for efficiency
    
    Args:
        request: Batch analysis request with list of documents
        background_tasks: Background task manager for async processing
        
    Returns:
        Batch analysis results with summary statistics
    """
    try:
        # Perform batch analysis
        analyses = engine.batch_analyze_documents(request.documents)
        
        # Calculate summary statistics
        total_documents = len(analyses)
        transport_documents = sum(1 for a in analyses if a.category in ["transport", "transport-related"])
        average_transport_score = sum(a.transport_score for a in analyses) / max(total_documents, 1)
        
        # Convert to response format
        analysis_responses = []
        for analysis in analyses:
            analysis_responses.append(DocumentAnalysisResponse(
                transport_score=analysis.transport_score,
                category=analysis.category,
                keywords=analysis.keywords,
                similarity_scores=analysis.similarity_scores,
                cluster_id=analysis.cluster_id,
                confidence=analysis.confidence
            ))
        
        return BatchAnalysisResponse(
            analyses=analysis_responses,
            total_documents=total_documents,
            transport_documents=transport_documents,
            average_transport_score=average_transport_score
        )
        
    except Exception as e:
        logger.error(f"Batch analysis failed: {e}")
        raise HTTPException(status_code=500, detail="Batch analysis failed")


@router.post("/similarity", response_model=SimilarityResponse)
async def find_similar_documents(
    request: SimilarityRequest,
    engine: TextAnalysisEngine = Depends(get_ml_engine)
):
    """
    Find documents similar to the provided text
    
    Args:
        request: Similarity search request with text and parameters
        
    Returns:
        Similar documents with similarity scores and query analysis
    """
    try:
        # Find similar documents
        similar_docs = engine.similarity_analyzer.find_similar_documents(
            text=request.text,
            top_k=request.top_k
        )
        
        # Analyze the query text itself
        query_analysis = engine.analyze_document(
            title="Query",
            content=request.text
        )
        
        # Format response
        similar_documents = []
        for doc_id, similarity_score in similar_docs:
            similar_documents.append({
                "document_id": doc_id,
                "similarity_score": similarity_score
            })
        
        return SimilarityResponse(
            similar_documents=similar_documents,
            query_analysis=DocumentAnalysisResponse(
                transport_score=query_analysis.transport_score,
                category=query_analysis.category,
                keywords=query_analysis.keywords,
                similarity_scores=query_analysis.similarity_scores,
                cluster_id=query_analysis.cluster_id,
                confidence=query_analysis.confidence
            )
        )
        
    except Exception as e:
        logger.error(f"Similarity search failed: {e}")
        raise HTTPException(status_code=500, detail="Similarity search failed")


@router.get("/text/stats", response_model=TextStatsResponse)
async def get_text_statistics(
    text: str,
    engine: TextAnalysisEngine = Depends(get_ml_engine)
):
    """
    Get detailed text statistics for a document
    
    Args:
        text: Text to analyze
        
    Returns:
        Text statistics including word count, complexity, and transport keywords
    """
    try:
        stats = engine.get_text_statistics(text)
        
        return TextStatsResponse(
            word_count=stats.word_count,
            sentence_count=stats.sentence_count,
            avg_word_length=stats.avg_word_length,
            complexity_score=stats.complexity_score,
            transport_keywords_found=stats.transport_keywords_found
        )
        
    except Exception as e:
        logger.error(f"Text statistics calculation failed: {e}")
        raise HTTPException(status_code=500, detail="Text statistics calculation failed")


@router.get("/keywords/extract")
async def extract_keywords(
    text: str,
    max_keywords: int = 10,
    engine: TextAnalysisEngine = Depends(get_ml_engine)
):
    """
    Extract important keywords from text
    
    Args:
        text: Text to extract keywords from
        max_keywords: Maximum number of keywords to return
        
    Returns:
        List of extracted keywords ranked by importance
    """
    try:
        keywords = engine.extract_keywords(text, max_keywords)
        
        return {
            "keywords": keywords,
            "count": len(keywords),
            "text_length": len(text)
        }
        
    except Exception as e:
        logger.error(f"Keyword extraction failed: {e}")
        raise HTTPException(status_code=500, detail="Keyword extraction failed")


@router.get("/transport/classify")
async def classify_transport_relevance(
    title: str,
    content: str = "",
    engine: TextAnalysisEngine = Depends(get_ml_engine)
):
    """
    Quick transport classification for a document
    
    Args:
        title: Document title
        content: Optional document content
        
    Returns:
        Transport classification result
    """
    try:
        analysis = engine.transport_classifier.classify_document(title, content)
        
        return {
            "transport_score": analysis.transport_score,
            "category": analysis.category,
            "confidence": analysis.confidence,
            "transport_keywords": analysis.keywords,
            "is_transport_related": analysis.transport_score >= 0.1
        }
        
    except Exception as e:
        logger.error(f"Transport classification failed: {e}")
        raise HTTPException(status_code=500, detail="Transport classification failed")


@router.get("/engine/statistics")
async def get_engine_statistics(
    engine: TextAnalysisEngine = Depends(get_ml_engine)
):
    """
    Get ML analysis engine statistics and health information
    
    Returns:
        Engine statistics including initialization status and capabilities
    """
    try:
        stats = engine.get_analysis_statistics()
        
        return {
            "status": "healthy" if stats["initialized"] else "initializing",
            "capabilities": {
                "sklearn_available": stats["sklearn_available"],
                "similarity_analysis": stats["similarity_analyzer_ready"],
                "transport_classification": True,
                "keyword_extraction": True,
                "text_statistics": True
            },
            "data": {
                "transport_keywords_count": stats["transport_keywords_count"],
                "document_count": stats["document_count"]
            },
            "version": "1.0.0"
        }
        
    except Exception as e:
        logger.error(f"Engine statistics failed: {e}")
        return {
            "status": "error",
            "error": str(e)
        }


@router.get("/health")
async def ml_health_check():
    """
    Health check endpoint for ML analysis service
    
    Returns:
        Service health status
    """
    try:
        engine = await get_ml_engine()
        stats = engine.get_analysis_statistics()
        
        return {
            "status": "healthy",
            "ml_engine_initialized": stats["initialized"],
            "sklearn_available": stats["sklearn_available"],
            "transport_classifier_ready": True,
            "features_available": [
                "document_classification",
                "keyword_extraction", 
                "text_statistics",
                "transport_analysis"
            ] + (["similarity_analysis", "document_clustering"] if stats["sklearn_available"] else [])
        }
        
    except Exception as e:
        logger.error(f"ML health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e)
        }