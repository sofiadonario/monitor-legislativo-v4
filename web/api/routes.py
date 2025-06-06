"""
API routes for Monitor Legislativo Web
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Query, HTTPException, BackgroundTasks
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
from core.auth.decorators import require_auth

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
    q: str = Query(..., description="Search query"),
    sources: Optional[str] = Query(None, description="Comma-separated source keys"),
    start_date: Optional[str] = Query(None, description="Start date (YYYY-MM-DD)"),
    end_date: Optional[str] = Query(None, description="End date (YYYY-MM-DD)"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(25, ge=1, le=100, description="Results per page")
):
    """
    Search for propositions across multiple sources
    """
    if not q.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty")
    
    # Parse sources
    source_list = None
    if sources:
        source_list = [s.strip() for s in sources.split(",")]
    
    # Build filters
    filters = {}
    if start_date:
        filters["start_date"] = start_date
    if end_date:
        filters["end_date"] = end_date
    
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
            "results": paginated_props
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
@require_auth(roles=["admin"])
async def clear_cache(source: Optional[str] = Query(None, description="Specific source to clear")):
    """
    Clear cache for specific source or all sources
    """
    api_service.clear_cache(source)
    
    return {
        "message": f"Cache cleared for {'source: ' + source if source else 'all sources'}",
        "timestamp": datetime.now().isoformat()
    }


@router.get("/proposition/{source}/{id}")
async def get_proposition_details(source: str, id: str):
    """
    Get detailed information about a specific proposition
    """
    # TODO: Implement proposition details endpoint
    raise HTTPException(status_code=501, detail="Not implemented yet")