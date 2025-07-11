from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Optional
from pydantic import BaseModel
import logging

from ..geographic.service import get_geographic_service, GeographicService
from ..geographic.models import BrazilianRegion

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/geographic", tags=["Geographic"])

class RegionResponse(BaseModel):
    regions: List[BrazilianRegion]
    total: int

@router.get("/regions", response_model=RegionResponse)
async def get_all_regions(
    service: GeographicService = Depends(get_geographic_service),
    limit: int = Query(100, ge=1, le=5570),
    offset: int = Query(0, ge=0),
):
    """Get all Brazilian municipalities, states, and regions."""
    regions, total = await service.get_all_regions(limit=limit, offset=offset)
    return {"regions": regions, "total": total}

@router.get("/search", response_model=List[BrazilianRegion])
async def search_regions(
    query: str,
    service: GeographicService = Depends(get_geographic_service),
    limit: int = 10,
):
    """Search for a specific municipality or state."""
    return await service.search_regions(query, limit=limit)
