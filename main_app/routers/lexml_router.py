"""
FastAPI router for LexML Brasil API integration
Provides proxy endpoints for frontend to access LexML data
"""

import asyncio
import logging
from typing import Optional, List
from datetime import datetime
from fastapi import APIRouter, HTTPException, Query, Depends, BackgroundTasks
from fastapi.responses import JSONResponse

# Use enhanced search service with database integration
from ..services.simple_search_service import (
    get_simple_search_service, LexMLSearchResponse, LexMLDocument
)
from ..services.database_cache_service import get_database_cache_service

logger = logging.getLogger(__name__)

# Router configuration
router = APIRouter(
    prefix="/api/lexml",
    tags=["LexML Integration"],
    responses={
        500: {"description": "LexML API Error"},
        503: {"description": "Service Temporarily Unavailable"}
    }
)

# Enhanced service dependencies
async def get_search_service():
    """Dependency to get enhanced search service"""
    return await get_simple_search_service()

async def get_cache_service():
    """Dependency to get database cache service"""
    return await get_database_cache_service()


@router.get("/health")
async def get_api_health(
    service = Depends(get_search_service),
    cache_service = Depends(get_cache_service)
):
    """
    Check enhanced service health status with database integration
    """
    try:
        search_health = await service.get_health_status()
        cache_health = await cache_service.get_health_status()
        
        return {
            "search_service": search_health,
            "cache_service": cache_health,
            "overall_health": {
                "is_healthy": search_health.get("is_healthy", False),
                "database_enabled": cache_health.get("database_available", False),
                "features_operational": search_health.get("features_enabled", [])
            }
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "is_healthy": False,
            "error_message": str(e)
        }


@router.get("/search")
async def search_documents(
    # Query parameters
    q: Optional[str] = Query(None, description="Search query"),
    cql: Optional[str] = Query(None, description="Direct CQL query"),
    
    # Filters (simplified)
    tipo_documento: Optional[List[str]] = Query(None, description="Document types"),
    autoridade: Optional[List[str]] = Query(None, description="Authority levels"),
    localidade: Optional[List[str]] = Query(None, description="Geographic localities"),
    date_from: Optional[str] = Query(None, description="Start date (YYYY-MM-DD)"),
    date_to: Optional[str] = Query(None, description="End date (YYYY-MM-DD)"),
    subject: Optional[List[str]] = Query(None, description="Subject classifications"),
    
    # Pagination
    start_record: int = Query(1, ge=1, description="Starting record number"),
    max_records: int = Query(50, ge=1, le=100, description="Maximum records per page"),
    
    # Options
    include_content: bool = Query(False, description="Include full document content"),
    use_cache: bool = Query(True, description="Use cached results if available"),
    
    # Dependencies
    service = Depends(get_search_service)
):
    """
    Search legislative database using three-tier fallback system
    
    Supports both simple text search and advanced CQL queries.
    Uses CSV fallback when APIs are unavailable.
    """
    try:
        # Create simple search request object
        class SimpleSearchRequest:
            def __init__(self):
                self.query = q or cql or ""
                self.cql_query = cql
                self.start_record = start_record
                self.max_records = max_records
                self.filters = {
                    "tipoDocumento": tipo_documento or [],
                    "autoridade": autoridade or [],
                    "localidade": localidade or [],
                    "date_from": date_from,
                    "date_to": date_to,
                    "subject": subject or []
                }
        
        search_request = SimpleSearchRequest()
        
        # Perform search using simple service
        search_response = await service.search(search_request)
        
        logger.info(
            f"Search completed: {len(search_response.documents)} documents, "
            f"{search_response.search_time_ms:.2f}ms, source: {search_response.data_source}"
        )
        
        # Convert to dict for JSON response
        return {
            "documents": [
                {
                    "urn": doc.urn,
                    "title": doc.title,
                    "description": doc.description,
                    "url": doc.url,
                    "metadata": doc.metadata
                } for doc in search_response.documents
            ],
            "total_found": search_response.total_found,
            "start_record": search_response.start_record,
            "records_returned": search_response.records_returned,
            "search_time_ms": search_response.search_time_ms,
            "data_source": search_response.data_source,
            "cache_hit": search_response.cache_hit,
            "api_status": search_response.api_status,
            "next_start_record": search_response.next_start_record
        }
        
    except Exception as e:
        logger.error(f"Search error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Search error: {str(e)}"
        )


@router.get("/document/{urn:path}")
async def get_document_content(
    urn: str,
    service = Depends(get_search_service)
) -> dict:
    """
    Get document information by URN (simplified implementation)
    """
    try:
        # For now, return basic information about the URN
        # In a full implementation, this would retrieve the actual document content
        return {
            "urn": urn,
            "message": "Document retrieval available via URL",
            "url": f"https://www.lexml.gov.br/urn/{urn}",
            "data_source": "csv_fallback",
            "retrieved_at": datetime.now().isoformat(),
            "note": "Full document content available at the provided URL"
        }
        
    except Exception as e:
        logger.error(f"Document retrieval error for {urn}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Document error: {str(e)}"
        )


@router.get("/suggest")
async def get_search_suggestions(
    term: str = Query(..., min_length=2, description="Partial search term"),
    max_suggestions: int = Query(10, ge=1, le=20, description="Maximum suggestions to return")
) -> dict:
    """
    Get search suggestions for auto-complete
    """
    try:
        # Basic transport-related suggestions
        transport_suggestions = [
            "transporte", "transporte de carga", "transporte urbano", "transporte público",
            "carga", "logística", "mobilidade urbana", "sustentável", "combustível",
            "licenciamento", "rodovia", "caminhão", "veículo", "ANTT", "ANTAQ", "ANAC"
        ]
        
        # Filter suggestions based on the input term
        term_lower = term.lower()
        matching_suggestions = [
            suggestion for suggestion in transport_suggestions
            if term_lower in suggestion.lower()
        ]
        
        return {
            "term": term,
            "suggestions": matching_suggestions[:max_suggestions],
            "count": len(matching_suggestions[:max_suggestions]),
            "generated_at": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Suggestion error for term '{term}': {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Suggestion generation error: {str(e)}"
        )


# Background task to warm up the search service
@router.on_event("startup")
async def startup_warmup():
    """Initialize search service on startup"""
    try:
        service = await get_simple_search_service()
        logger.info("Simple Search Service warmed up successfully")
    except Exception as e:
        logger.warning(f"Service warmup failed: {e}")


# Enhanced analytics and statistics endpoints
@router.get("/stats")
async def get_api_stats(
    service = Depends(get_search_service),
    cache_service = Depends(get_cache_service)
) -> dict:
    """
    Get comprehensive service statistics with database analytics
    """
    try:
        search_health = await service.get_health_status()
        cache_health = await cache_service.get_health_status()
        
        # Get analytics summary if database is available
        analytics_summary = {}
        if cache_service.db_available:
            analytics_summary = await cache_service.get_analytics_summary(24)
        
        return {
            "service_stats": search_health,
            "cache_stats": cache_health,
            "analytics_summary": analytics_summary,
            "generated_at": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Stats retrieval error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Stats retrieval error: {str(e)}"
        )


@router.get("/analytics")
async def get_search_analytics(
    hours: int = Query(24, ge=1, le=168, description="Hours to analyze (1-168)"),
    cache_service = Depends(get_cache_service)
) -> dict:
    """
    Get detailed search analytics for academic research insights
    """
    try:
        if not cache_service.db_available:
            return {
                "error": "Analytics require database connection",
                "message": "Database integration is not available",
                "fallback_mode": True
            }
        
        analytics = await cache_service.get_analytics_summary(hours)
        return analytics
        
    except Exception as e:
        logger.error(f"Analytics retrieval error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Analytics error: {str(e)}"
        )


@router.post("/cache/cleanup")
async def cleanup_cache(
    background_tasks: BackgroundTasks,
    cache_service = Depends(get_cache_service)
) -> dict:
    """
    Clean up expired cache entries (runs in background)
    """
    try:
        if not cache_service.db_available:
            return {
                "message": "Cache cleanup not available - database not connected",
                "database_enabled": False
            }
        
        # Run cleanup in background
        background_tasks.add_task(cache_service.cleanup_expired_entries)
        
        return {
            "message": "Cache cleanup initiated",
            "status": "running_in_background",
            "database_enabled": True,
            "initiated_at": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Cache cleanup error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Cache cleanup error: {str(e)}"
        )