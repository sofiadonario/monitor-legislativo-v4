"""
API Gateway
Unified REST API for all data sources
Implements API gateway recommendation from analysis
"""

from fastapi import APIRouter, Query, HTTPException, Depends
from fastapi.responses import JSONResponse
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field
import asyncio

from core.api.api_service import APIService
from core.utils.monitoring_dashboard import monitoring_dashboard
from core.utils.unified_search import unified_search
from core.models.models import SearchResult, DataSource


# API Models
class SearchRequest(BaseModel):
    """Search request model"""
    query: str = Field(..., min_length=1, max_length=500, description="Search query")
    sources: Optional[List[str]] = Field(None, description="Data sources to search")
    start_date: Optional[str] = Field(None, pattern="^\d{4}-\d{2}-\d{2}$", description="Start date (YYYY-MM-DD)")
    end_date: Optional[str] = Field(None, pattern="^\d{4}-\d{2}-\d{2}$", description="End date (YYYY-MM-DD)")
    page: int = Field(1, ge=1, description="Page number")
    page_size: int = Field(20, ge=1, le=100, description="Results per page")


class SearchResponse(BaseModel):
    """Standardized search response"""
    success: bool
    query: str
    sources_searched: List[str]
    total_results: int
    page: int
    page_size: int
    results: List[Dict[str, Any]]
    metadata: Dict[str, Any]


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    timestamp: str
    services: Dict[str, Dict[str, Any]]
    system_metrics: Dict[str, Any]


class SourceStatusResponse(BaseModel):
    """Individual source status"""
    source: str
    status: str
    response_time_ms: float
    last_success: Optional[str]
    error_count_24h: int
    success_rate: float


# Create router
router = APIRouter(prefix="/api/v1", tags=["API Gateway"])

# Initialize services
api_service = APIService()


@router.post("/search", response_model=SearchResponse)
async def unified_search_endpoint(request: SearchRequest):
    """
    Unified search across all data sources
    
    This endpoint provides standardized access to all 14 government data sources,
    including legislative APIs and regulatory agency scrapers.
    """
    try:
        # Validate sources
        valid_sources = list(monitoring_dashboard.sources_config.keys())
        if request.sources:
            invalid_sources = [s for s in request.sources if s not in valid_sources]
            if invalid_sources:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid sources: {invalid_sources}. Valid sources: {valid_sources}"
                )
            sources = request.sources
        else:
            # Default to all healthy sources
            sources = []
            for source in valid_sources:
                status = await monitoring_dashboard.check_source_health(source)
                if status.status.value == "healthy":
                    sources.append(source)
        
        # Prepare filters
        filters = {}
        if request.start_date:
            filters["start_date"] = request.start_date
        if request.end_date:
            filters["end_date"] = request.end_date
        
        # Use optimized unified search
        results = await unified_search.search_optimized(
            request.query,
            sources,
            filters
        )
        
        # Flatten and paginate results
        all_propositions = []
        for result in results:
            for prop in result.propositions:
                all_propositions.append({
                    "id": prop.id,
                    "source": result.source.value,
                    "type": prop.type.value,
                    "number": prop.number,
                    "year": prop.year,
                    "title": prop.title,
                    "summary": prop.summary,
                    "status": prop.status.value if prop.status else None,
                    "url": prop.url,
                    "publication_date": prop.publication_date.isoformat() if prop.publication_date else None,
                    "authors": [{"name": a.name, "type": a.type} for a in prop.authors],
                    "relevance_score": getattr(prop, 'relevance_score', 0)
                })
        
        # Sort by relevance if available
        all_propositions.sort(key=lambda x: x.get('relevance_score', 0), reverse=True)
        
        # Pagination
        start_idx = (request.page - 1) * request.page_size
        end_idx = start_idx + request.page_size
        paginated_results = all_propositions[start_idx:end_idx]
        
        # Performance metrics
        perf_report = unified_search.get_performance_report()
        
        return SearchResponse(
            success=True,
            query=request.query,
            sources_searched=sources,
            total_results=len(all_propositions),
            page=request.page,
            page_size=request.page_size,
            results=paginated_results,
            metadata={
                "search_time_ms": sum(r.search_time * 1000 for r in results),
                "cache_hit": any(hasattr(r, 'from_cache') and r.from_cache for r in results),
                "performance": perf_report
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """
    System health check
    
    Returns real-time health status for all data sources and system metrics.
    """
    try:
        dashboard_status = await monitoring_dashboard.get_realtime_status()
        
        # Format services health
        services = {}
        for source_name, source_data in dashboard_status['sources'].items():
            services[source_name] = {
                "status": source_data['status'],
                "response_time_ms": source_data['response_time_ms'],
                "circuit_breaker": source_data['circuit_breaker_state'],
                "success_rate": source_data['success_rate_24h']
            }
        
        return HealthResponse(
            status=dashboard_status['system_metrics']['health_percentage'] > 80 
                   and "healthy" or "degraded",
            timestamp=dashboard_status['timestamp'],
            services=services,
            system_metrics=dashboard_status['system_metrics']
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sources", response_model=List[SourceStatusResponse])
async def list_sources():
    """
    List all available data sources with their current status
    """
    try:
        sources = []
        
        for source_name in monitoring_dashboard.sources_config.keys():
            status = await monitoring_dashboard.check_source_health(source_name)
            
            sources.append(SourceStatusResponse(
                source=source_name,
                status=status.status.value,
                response_time_ms=status.response_time_ms,
                last_success=status.last_success.isoformat() if status.last_success else None,
                error_count_24h=status.error_count_24h,
                success_rate=status.success_rate_24h
            ))
        
        # Sort by health status
        sources.sort(key=lambda x: (x.status != "healthy", x.source))
        
        return sources
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sources/{source_name}")
async def get_source_details(source_name: str):
    """
    Get detailed information about a specific data source
    """
    if source_name not in monitoring_dashboard.sources_config:
        raise HTTPException(status_code=404, detail=f"Source '{source_name}' not found")
    
    try:
        status = await monitoring_dashboard.check_source_health(source_name)
        cb_stats = monitoring_dashboard.current_status.get(source_name)
        
        return {
            "source": source_name,
            "type": monitoring_dashboard.sources_config[source_name].value,
            "status": status.status.value,
            "health_details": {
                "response_time_ms": status.response_time_ms,
                "last_success": status.last_success.isoformat() if status.last_success else None,
                "last_failure": status.last_failure.isoformat() if status.last_failure else None,
                "error_count_24h": status.error_count_24h,
                "success_rate_24h": status.success_rate_24h,
                "data_freshness_hours": status.data_freshness_hours
            },
            "circuit_breaker": {
                "state": status.circuit_breaker_state,
                "stats": cb_stats
            },
            "cache": {
                "hit_rate": status.cache_hit_rate
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/metrics")
async def get_metrics():
    """
    Get system performance metrics
    """
    try:
        # Get current dashboard status
        status = await monitoring_dashboard.get_realtime_status()
        
        # Get historical data
        historical = await monitoring_dashboard.get_historical_data(24)
        
        # Get search performance
        search_perf = unified_search.get_performance_report()
        
        return {
            "current": status['system_metrics'],
            "performance": status['performance_summary'],
            "search_metrics": search_perf,
            "alerts": {
                "active": len([a for a in status['active_alerts'] if not a.get('resolved')]),
                "recent": status['active_alerts']
            },
            "historical": {
                "data_points": len(historical),
                "period_hours": 24
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cache/clear")
async def clear_cache(source: Optional[str] = None):
    """
    Clear cache for specific source or all sources
    """
    try:
        from core.utils.smart_cache import smart_cache
        
        if source:
            if source not in monitoring_dashboard.sources_config:
                raise HTTPException(status_code=404, detail=f"Source '{source}' not found")
            
            await smart_cache.clear_pattern(f"*{source}*", source)
            message = f"Cache cleared for source: {source}"
        else:
            # Clear all cache
            await smart_cache.clear_all()
            message = "All cache cleared"
        
        return {"success": True, "message": message}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/monitoring/start")
async def start_monitoring():
    """Start continuous monitoring"""
    try:
        await monitoring_dashboard.start_monitoring()
        return {"success": True, "message": "Monitoring started"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/monitoring/stop")
async def stop_monitoring():
    """Stop continuous monitoring"""
    try:
        await monitoring_dashboard.stop_monitoring()
        return {"success": True, "message": "Monitoring stopped"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Rate limiting decorator (placeholder for actual implementation)
async def rate_limit_check():
    """Check rate limits"""
    # TODO: Implement actual rate limiting
    return True


# Add to main FastAPI app
def register_gateway(app):
    """Register API gateway routes"""
    app.include_router(router)