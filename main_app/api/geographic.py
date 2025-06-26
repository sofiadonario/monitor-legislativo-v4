"""
Geographic API endpoints for Monitor Legislativo v4
Provides Brazilian geographic data and document analysis capabilities
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
import logging

# Import geographic components
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent / "core"))

from geographic import GeographicService, BrazilianGeographicDataLoader
from geographic.models import BrazilianRegion

logger = logging.getLogger(__name__)

# Initialize geographic service
_geographic_service: Optional[GeographicService] = None


async def get_geographic_service() -> GeographicService:
    """Dependency to get initialized geographic service"""
    global _geographic_service
    if _geographic_service is None:
        _geographic_service = GeographicService()
        await _geographic_service.initialize()
    return _geographic_service


# Response models
class MunicipalityResponse(BaseModel):
    """Municipality data response model"""
    name: str
    state: str
    state_name: str
    region: str
    ibge_code: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    population: Optional[int] = None
    area_km2: Optional[float] = None


class GeographicScopeResponse(BaseModel):
    """Geographic scope analysis response"""
    municipalities: List[MunicipalityResponse]
    states: List[str]
    regions: List[str]
    scope_type: str
    confidence: float


class DocumentAnalysisRequest(BaseModel):
    """Document geographic analysis request"""
    title: str = Field(..., description="Document title")
    content: str = Field(..., description="Document content")
    source: Optional[str] = Field(None, description="Document source")


class GeographicStatsResponse(BaseModel):
    """Geographic statistics response"""
    total_municipalities: int
    municipalities_with_coordinates: int
    municipalities_with_population: int
    municipalities_by_region: Dict[str, int]
    municipalities_by_state: Dict[str, int]


# Create router
router = APIRouter(prefix="/api/v1/geographic", tags=["Geographic"])


@router.get("/municipalities/search", response_model=List[MunicipalityResponse])
async def search_municipalities(
    query: str = Query(..., description="Search query for municipality name"),
    state: Optional[str] = Query(None, description="Filter by state code (e.g., SP, RJ)"),
    region: Optional[str] = Query(None, description="Filter by region"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of results"),
    service: GeographicService = Depends(get_geographic_service)
):
    """
    Search Brazilian municipalities by name with optional filters
    
    Args:
        query: Municipality name to search for
        state: Optional state code filter (SP, RJ, etc.)
        region: Optional region filter (Norte, Nordeste, etc.)
        limit: Maximum number of results (1-100)
    
    Returns:
        List of matching municipalities
    """
    try:
        # Convert region string to enum if provided
        region_filter = None
        if region:
            try:
                region_filter = BrazilianRegion(region)
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid region. Must be one of: {[r.value for r in BrazilianRegion]}"
                )
        
        municipalities = await service.search_municipalities(
            query=query,
            state_filter=state,
            region_filter=region_filter,
            limit=limit
        )
        
        return [
            MunicipalityResponse(
                name=m.name,
                state=m.state,
                state_name=m.state_name,
                region=m.region.value,
                ibge_code=m.ibge_code,
                latitude=m.latitude,
                longitude=m.longitude,
                population=m.population,
                area_km2=m.area_km2
            )
            for m in municipalities
        ]
        
    except Exception as e:
        logger.error(f"Municipality search failed: {e}")
        raise HTTPException(status_code=500, detail="Municipality search failed")


@router.get("/municipalities/{ibge_code}", response_model=MunicipalityResponse)
async def get_municipality_by_ibge(
    ibge_code: str,
    service: GeographicService = Depends(get_geographic_service)
):
    """
    Get municipality by IBGE code
    
    Args:
        ibge_code: 7-digit IBGE municipality code
    
    Returns:
        Municipality data
    """
    try:
        municipality = service.data_loader.get_municipality_by_ibge_code(ibge_code)
        
        if not municipality:
            raise HTTPException(status_code=404, detail="Municipality not found")
        
        return MunicipalityResponse(
            name=municipality.name,
            state=municipality.state,
            state_name=municipality.state_name,
            region=municipality.region.value,
            ibge_code=municipality.ibge_code,
            latitude=municipality.latitude,
            longitude=municipality.longitude,
            population=municipality.population,
            area_km2=municipality.area_km2
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Municipality lookup failed: {e}")
        raise HTTPException(status_code=500, detail="Municipality lookup failed")


@router.get("/states/{state_code}/municipalities", response_model=List[MunicipalityResponse])
async def get_municipalities_by_state(
    state_code: str,
    service: GeographicService = Depends(get_geographic_service)
):
    """
    Get all municipalities in a state
    
    Args:
        state_code: Two-letter state code (SP, RJ, etc.)
    
    Returns:
        List of municipalities in the state
    """
    try:
        municipalities = await service.get_municipalities_by_state(state_code.upper())
        
        return [
            MunicipalityResponse(
                name=m.name,
                state=m.state,
                state_name=m.state_name,
                region=m.region.value,
                ibge_code=m.ibge_code,
                latitude=m.latitude,
                longitude=m.longitude,
                population=m.population,
                area_km2=m.area_km2
            )
            for m in municipalities
        ]
        
    except Exception as e:
        logger.error(f"State municipalities lookup failed: {e}")
        raise HTTPException(status_code=500, detail="State municipalities lookup failed")


@router.post("/analyze", response_model=GeographicScopeResponse)
async def analyze_document_geography(
    request: DocumentAnalysisRequest,
    service: GeographicService = Depends(get_geographic_service)
):
    """
    Analyze the geographic scope of a legislative document
    
    Args:
        request: Document analysis request with title, content, and optional source
    
    Returns:
        Geographic scope analysis with detected municipalities, states, and regions
    """
    try:
        geographic_scope = await service.analyze_document_geography(
            document_title=request.title,
            document_content=request.content,
            document_source=request.source
        )
        
        return GeographicScopeResponse(
            municipalities=[
                MunicipalityResponse(
                    name=m.name,
                    state=m.state,
                    state_name=m.state_name,
                    region=m.region.value,
                    ibge_code=m.ibge_code,
                    latitude=m.latitude,
                    longitude=m.longitude,
                    population=m.population,
                    area_km2=m.area_km2
                )
                for m in geographic_scope.municipalities
            ],
            states=geographic_scope.states,
            regions=[r.value for r in geographic_scope.regions],
            scope_type=geographic_scope.scope_type,
            confidence=geographic_scope.confidence
        )
        
    except Exception as e:
        logger.error(f"Document geographic analysis failed: {e}")
        raise HTTPException(status_code=500, detail="Document geographic analysis failed")


@router.get("/statistics", response_model=GeographicStatsResponse)
async def get_geographic_statistics(
    service: GeographicService = Depends(get_geographic_service)
):
    """
    Get statistics about the geographic service and data
    
    Returns:
        Geographic statistics including counts by region and state
    """
    try:
        stats = await service.get_statistics()
        
        # Separate region and state statistics
        region_stats = {}
        state_stats = {}
        
        for key, value in stats.items():
            if key.startswith('municipalities_') and len(key.split('_')) > 2:
                # This is a region stat (e.g., municipalities_centro_oeste)
                region_name = key.replace('municipalities_', '').replace('_', ' ').title()
                region_stats[region_name] = value
            elif key.startswith('municipalities_') and len(key.split('_')[-1]) == 2:
                # This is a state stat (e.g., municipalities_sp)
                state_code = key.split('_')[-1].upper()
                state_stats[state_code] = value
        
        return GeographicStatsResponse(
            total_municipalities=stats.get('total_municipalities', 0),
            municipalities_with_coordinates=stats.get('municipalities_with_coordinates', 0),
            municipalities_with_population=stats.get('municipalities_with_population', 0),
            municipalities_by_region=region_stats,
            municipalities_by_state=state_stats
        )
        
    except Exception as e:
        logger.error(f"Geographic statistics failed: {e}")
        raise HTTPException(status_code=500, detail="Geographic statistics failed")


@router.get("/health")
async def geographic_health_check(
    service: GeographicService = Depends(get_geographic_service)
):
    """
    Health check endpoint for geographic service
    
    Returns:
        Service health status and basic metrics
    """
    try:
        stats = await service.get_statistics()
        
        return {
            "status": "healthy",
            "service_initialized": stats.get('service_initialized', False),
            "municipalities_loaded": stats.get('total_municipalities', 0),
            "cache_size": stats.get('cache_size', 0)
        }
        
    except Exception as e:
        logger.error(f"Geographic health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e)
        }