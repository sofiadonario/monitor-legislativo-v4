from fastapi import APIRouter, Query, HTTPException, Request, Depends
from typing import List
from ..services.simple_search_service import get_simple_search_service, SimpleSearchService, Document
from ..services.database_cache_service import get_database_cache_service
import logging

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/lexml/search", summary="Search LexML Brasil", response_model=List[Document])
async def search_lexml(
    request: Request,
    query: str = Query(..., description="Search query for LexML"),
    limit: int = Query(50, description="Number of results to return"),
    search_service: SimpleSearchService = Depends(get_simple_search_service),
    cache_service = Depends(get_database_cache_service),
):
    """
    Search for legislative documents on LexML Brasil.
    Results are cached for performance.
    """
    if not query:
        raise HTTPException(status_code=400, detail="Query parameter is required")

    # Use client IP for rate limiting or analytics if needed
    client_ip = request.client.host
    logger.info(f"LexML search request from {client_ip} for query: '{query}'")

    try:
        # Check cache first
        cached_results = await cache_service.get_search_results(query)
        if cached_results:
            logger.info(f"Cache hit for query: '{query}'")
            return cached_results

        logger.info(f"Cache miss for query: '{query}'. Searching LexML.")
        documents = await search_service.search(query, limit=limit)

        # Store results in cache
        await cache_service.save_search_results(query, documents)

        return documents

    except HTTPException as http_exc:
        # Re-raise HTTP exceptions
        raise http_exc
    except Exception as e:
        logger.error(f"Error during LexML search for query '{query}': {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="An unexpected error occurred during the search.")
