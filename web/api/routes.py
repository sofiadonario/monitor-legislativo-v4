"""
API routes for Monitor Legislativo Web
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Query, HTTPException, BackgroundTasks, Depends
from pydantic import BaseModel

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from core.api.api_service import APIService
from core.models.models import SearchResult, APIStatus
from core.utils.export_service import ExportService
from core.auth.fastapi_auth import (
    require_cache_management, 
    require_researcher,
    require_admin,
    get_optional_user,
    log_admin_action,
    rate_limit_check,
    User
)

router = APIRouter()

# Initialize services
api_service = APIService()
export_service = ExportService()


class SearchRequest(BaseModel):
    """Search request model"""
    query: str
    sources: Optional[List[str]] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    page: Optional[int] = 1
    page_size: Optional[int] = 25


class ExportRequest(BaseModel):
    """Export request model"""
    results: List[Dict[str, Any]]
    format: str = "CSV"
    metadata: Optional[Dict[str, Any]] = None


@router.get("/search") 
async def search(
    q: str = Query(..., description="Search query", min_length=1, max_length=500),
    sources: Optional[str] = Query(None, description="Comma-separated source keys"),
    start_date: Optional[str] = Query(None, description="Start date (YYYY-MM-DD)", regex=r"^\d{4}-\d{2}-\d{2}$"),
    end_date: Optional[str] = Query(None, description="End date (YYYY-MM-DD)", regex=r"^\d{4}-\d{2}-\d{2}$"),
    page: int = Query(1, ge=1, le=1000, description="Page number"),
    page_size: int = Query(25, ge=1, le=100, description="Results per page"),
    current_user: User = Depends(require_researcher()),
    _rate_limit: None = Depends(rate_limit_check)
):
    """
    Search for legislative propositions across multiple government sources.
    
    **REQUIRES AUTHENTICATION**: Researcher role required for scientific data access.
    **REAL DATA ONLY**: This endpoint returns only authentic legislative data 
    from verified government sources for research purposes.
    """
    # Enhanced input validation for security
    q = q.strip()
    if not q:
        raise HTTPException(status_code=400, detail="Search query cannot be empty")
    
    # Validate query doesn't contain obvious injection attempts
    suspicious_patterns = ["'", '"', "--", "/*", "*/", "<script", "javascript:", "data:"]
    if any(pattern in q.lower() for pattern in suspicious_patterns):
        raise HTTPException(status_code=400, detail="Invalid characters in search query")
    
    # Parse and validate sources
    source_list = None
    if sources:
        available_sources = api_service.get_available_sources()
        source_list = [s.strip() for s in sources.split(",")]
        
        # Validate all requested sources exist
        invalid_sources = [s for s in source_list if s not in available_sources]
        if invalid_sources:
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid sources: {invalid_sources}. Available: {list(available_sources.keys())}"
            )
    
    # Build filters with validation
    filters = {}
    if start_date:
        try:
            # Additional date validation
            datetime.strptime(start_date, "%Y-%m-%d")
            filters["start_date"] = start_date
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid start_date format. Use YYYY-MM-DD")
    
    if end_date:
        try:
            datetime.strptime(end_date, "%Y-%m-%d")
            filters["end_date"] = end_date
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid end_date format. Use YYYY-MM-DD")
    
    try:
        # Perform search
        results = await api_service.search_all(q, filters, source_list)
        
        # Aggregate results
        all_propositions = []
        total_count = 0
        
        for result in results:
            for prop in result.propositions:
                prop_dict = prop.to_dict()
                prop_dict["_source"] = result.source.value if result.source else "Unknown"
                all_propositions.append(prop_dict)
            total_count += result.total_count
        
        # Apply pagination
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        paginated_props = all_propositions[start_idx:end_idx]
        
        return {
            "query": q,
            "filters": filters,
            "sources": source_list or list(api_service.get_available_sources().keys()),
            "total_count": total_count,
            "page": page,
            "page_size": page_size,
            "total_pages": (total_count + page_size - 1) // page_size,
            "results": paginated_props,
            # Research compliance metadata
            "research_metadata": {
                "data_authenticity": "verified_government_sources",
                "researcher": current_user.email,
                "search_timestamp": datetime.now().isoformat(),
                "data_lineage": "direct_api_access_no_mocks",
                "compliance": "scientific_research_standards"
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")


@router.get("/sources")
async def get_sources():
    """
    Get available data sources
    """
    sources = api_service.get_available_sources()
    return {
        "sources": [
            {"key": key, "name": name, "enabled": True}
            for key, name in sources.items()
        ]
    }


@router.get("/status")
async def get_api_status():
    """
    Get current status of all APIs
    """
    try:
        statuses = await api_service.get_api_status()
        
        return {
            "timestamp": datetime.now().isoformat(),
            "services": [
                {
                    "name": status.name,
                    "source": status.source.value,
                    "is_healthy": status.is_healthy,
                    "last_check": status.last_check.isoformat(),
                    "response_time": status.response_time,
                    "error_message": status.error_message
                }
                for status in statuses
            ]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Status check failed: {str(e)}")


@router.post("/export")
async def export_results(request: ExportRequest, background_tasks: BackgroundTasks):
    """
    Export search results to specified format
    """
    # TODO: Implement async export with file upload to storage
    # For now, return a simple response
    
    return {
        "message": "Export functionality is under development",
        "format": request.format,
        "result_count": len(request.results)
    }


@router.delete("/cache")
@log_admin_action("clear_cache", "system_cache")
async def clear_cache(
    source: Optional[str] = Query(None, description="Specific source to clear"),
    current_user: User = Depends(require_cache_management()),
    _rate_limit: None = Depends(rate_limit_check)
):
    """
    Clear cache for specific source or all sources.
    
    **REQUIRES AUTHENTICATION**: Cache management permission required.
    This endpoint can impact system performance and is restricted to authorized users.
    """
    # Validate source parameter to prevent injection
    if source:
        available_sources = api_service.get_available_sources()
        if source not in available_sources:
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid source '{source}'. Available sources: {list(available_sources.keys())}"
            )
    
    try:
        api_service.clear_cache(source)
        
        return {
            "message": f"Cache cleared for {'source: ' + source if source else 'all sources'}",
            "cleared_by": current_user.email,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear cache: {str(e)}")


@router.get("/proposition/{source}/{id}")
async def get_proposition_details(source: str, id: str):
    """
    Get detailed information about a specific proposition
    """
    # TODO: Implement proposition details endpoint
    raise HTTPException(status_code=501, detail="Not implemented yet")