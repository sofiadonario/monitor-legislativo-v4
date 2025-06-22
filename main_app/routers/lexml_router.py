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

try:
    from ..models.lexml_models import (
        LexMLSearchRequest, LexMLSearchResponse, LexMLDocument, 
        DocumentType, Autoridade, APIHealthStatus, CQLQuery
    )
    from ..services.lexml_client import LexMLClient, LexMLAPIError
    from ..services.cql_builder import CQLQueryBuilder
    from ..services.cache_service import CacheService
except ImportError:
    # Fallback for development
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    
    from models.lexml_models import (
        LexMLSearchRequest, LexMLSearchResponse, LexMLDocument, 
        DocumentType, Autoridade, APIHealthStatus, CQLQuery
    )
    from services.lexml_client import LexMLClient, LexMLAPIError
    from services.cql_builder import CQLQueryBuilder
    from services.cache_service import CacheService

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

# Global instances (will be properly injected in production)
lexml_client: Optional[LexMLClient] = None
cql_builder = CQLQueryBuilder()
cache_service: Optional[CacheService] = None


async def get_lexml_client() -> LexMLClient:
    """Dependency to get LexML client"""
    global lexml_client
    if lexml_client is None:
        lexml_client = LexMLClient()
    return lexml_client


async def get_cache_service() -> CacheService:
    """Dependency to get cache service"""
    global cache_service
    if cache_service is None:
        # Will be properly configured with Redis in production
        cache_service = CacheService()
    return cache_service


@router.get("/health", response_model=APIHealthStatus)
async def get_api_health(
    client: LexMLClient = Depends(get_lexml_client)
) -> APIHealthStatus:
    """
    Check LexML API health status
    """
    try:
        async with client:
            health_status = await client.get_health_status()
        return health_status
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return APIHealthStatus(
            is_healthy=False,
            error_message=str(e)
        )


@router.get("/search", response_model=LexMLSearchResponse)
async def search_documents(
    # Query parameters
    q: Optional[str] = Query(None, description="Search query"),
    cql: Optional[str] = Query(None, description="Direct CQL query"),
    
    # Filters
    tipo_documento: Optional[List[DocumentType]] = Query(None, description="Document types"),
    autoridade: Optional[List[Autoridade]] = Query(None, description="Authority levels"),
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
    client: LexMLClient = Depends(get_lexml_client),
    cache: CacheService = Depends(get_cache_service)
) -> LexMLSearchResponse:
    """
    Search LexML Brasil legislative database
    
    Supports both simple text search and advanced CQL queries.
    Results are cached for performance.
    """
    try:
        # Parse date filters
        parsed_date_from = None
        parsed_date_to = None
        
        if date_from:
            try:
                parsed_date_from = datetime.fromisoformat(date_from)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid date_from format: {date_from}")
        
        if date_to:
            try:
                parsed_date_to = datetime.fromisoformat(date_to)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid date_to format: {date_to}")
        
        # Build search request
        search_request = LexMLSearchRequest(
            query=q,
            cql_query=cql,
            filters={
                "tipoDocumento": tipo_documento or [],
                "autoridade": autoridade or [],
                "localidade": localidade or [],
                "date_from": parsed_date_from,
                "date_to": parsed_date_to,
                "subject": subject or [],
                "search_term": q
            },
            start_record=start_record,
            max_records=max_records,
            include_content=include_content
        )
        
        # Generate cache key
        cache_key = f"lexml_search:{hash(str(search_request.dict()))}"
        
        # Check cache first (if enabled)
        if use_cache:
            cached_result = await cache.get(cache_key)
            if cached_result:
                logger.info(f"Cache hit for search: {cache_key}")
                cached_result.cache_hit = True
                return cached_result
        
        # Perform live search
        async with client:
            search_response = await client.search(search_request)
        
        # Cache the result
        if use_cache and search_response.documents:
            await cache.set(
                cache_key, 
                search_response, 
                ttl=3600  # 1 hour cache
            )
        
        logger.info(
            f"LexML search completed: {len(search_response.documents)} documents, "
            f"{search_response.search_time_ms:.2f}ms"
        )
        
        return search_response
        
    except LexMLAPIError as e:
        logger.error(f"LexML API error: {e}")
        raise HTTPException(
            status_code=502,
            detail=f"LexML API error: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Search error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )


@router.get("/document/{urn:path}")
async def get_document_content(
    urn: str,
    use_cache: bool = Query(True, description="Use cached content if available"),
    client: LexMLClient = Depends(get_lexml_client),
    cache: CacheService = Depends(get_cache_service)
) -> dict:
    """
    Get full content of a specific document by URN
    """
    try:
        cache_key = f"lexml_document:{urn}"
        
        # Check cache first
        if use_cache:
            cached_content = await cache.get(cache_key)
            if cached_content:
                logger.info(f"Document cache hit: {urn}")
                return {
                    "urn": urn,
                    "content": cached_content,
                    "cached": True,
                    "retrieved_at": datetime.now().isoformat()
                }
        
        # For now, return metadata (full content retrieval would need additional implementation)
        # In a complete implementation, this would fetch from the document's identifier URL
        
        # Search for the document to get its metadata
        search_request = LexMLSearchRequest(
            cql_query=f'urn exact "{urn}"',
            max_records=1
        )
        
        async with client:
            search_response = await client.search(search_request)
        
        if not search_response.documents:
            raise HTTPException(status_code=404, detail=f"Document not found: {urn}")
        
        document = search_response.documents[0]
        
        # Cache the document metadata
        if use_cache:
            await cache.set(
                cache_key,
                document.dict(),
                ttl=86400  # 24 hour cache for documents
            )
        
        return {
            "urn": urn,
            "document": document.dict(),
            "cached": False,
            "retrieved_at": datetime.now().isoformat()
        }
        
    except LexMLAPIError as e:
        logger.error(f"LexML API error for document {urn}: {e}")
        raise HTTPException(
            status_code=502,
            detail=f"LexML API error: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Document retrieval error for {urn}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )


@router.get("/suggest")
async def get_search_suggestions(
    term: str = Query(..., min_length=2, description="Partial search term"),
    field: Optional[str] = Query(None, description="Specific field to suggest for"),
    max_suggestions: int = Query(10, ge=1, le=20, description="Maximum suggestions to return")
) -> dict:
    """
    Get search suggestions for auto-complete
    """
    try:
        suggestions = cql_builder.build_suggestion_queries(term)
        
        # Limit results
        limited_suggestions = suggestions[:max_suggestions]
        
        # Get common patterns if no specific suggestions
        if not limited_suggestions and len(term) >= 3:
            patterns = cql_builder.get_common_patterns()
            matching_patterns = {
                name: query for name, query in patterns.items()
                if term.lower() in name.lower() or term.lower() in query.lower()
            }
            limited_suggestions = list(matching_patterns.values())[:max_suggestions]
        
        return {
            "term": term,
            "suggestions": limited_suggestions,
            "count": len(limited_suggestions),
            "generated_at": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Suggestion error for term '{term}': {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Suggestion generation error: {str(e)}"
        )


@router.post("/cql/parse", response_model=CQLQuery)
async def parse_cql_query(
    query: str,
    validate_only: bool = Query(False, description="Only validate, don't execute")
) -> CQLQuery:
    """
    Parse and validate CQL query
    """
    try:
        parsed_query = cql_builder.parse_user_query(query)
        
        if not parsed_query.is_valid:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid CQL query: {parsed_query.error_message}"
            )
        
        return parsed_query
        
    except Exception as e:
        logger.error(f"CQL parsing error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"CQL parsing error: {str(e)}"
        )


@router.get("/patterns")
async def get_common_patterns() -> dict:
    """
    Get common CQL query patterns for legal research
    """
    try:
        patterns = cql_builder.get_common_patterns()
        
        return {
            "patterns": patterns,
            "description": "Common CQL patterns for Brazilian legal research",
            "usage": "Use these patterns as templates for advanced searches",
            "generated_at": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Pattern retrieval error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Pattern retrieval error: {str(e)}"
        )


@router.get("/stats")
async def get_api_stats(
    client: LexMLClient = Depends(get_lexml_client)
) -> dict:
    """
    Get API usage statistics and performance metrics
    """
    try:
        async with client:
            health = await client.get_health_status()
        
        return {
            "circuit_breaker": health.circuit_breaker.dict(),
            "performance": {
                "response_time_ms": health.response_time_ms,
                "success_rate": health.success_rate,
                "is_healthy": health.is_healthy
            },
            "generated_at": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Stats retrieval error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Stats retrieval error: {str(e)}"
        )


# Background task to warm up the API connection
@router.on_event("startup")
async def startup_warmup():
    """Warm up LexML API connection on startup"""
    try:
        client = await get_lexml_client()
        async with client:
            await client.get_health_status()
        logger.info("LexML API connection warmed up successfully")
    except Exception as e:
        logger.warning(f"API warmup failed: {e}")


# Error handlers
@router.exception_handler(LexMLAPIError)
async def lexml_api_error_handler(request, exc: LexMLAPIError):
    """Handle LexML API specific errors"""
    return JSONResponse(
        status_code=502,
        content={
            "error": "LexML API Error",
            "detail": str(exc),
            "fallback_available": True,
            "timestamp": datetime.now().isoformat()
        }
    )