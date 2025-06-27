"""
Advanced Geocoding API Endpoints
===============================

FastAPI endpoints for advanced Brazilian geocoding with IBGE CNEFE integration.
Implements 6-level precision geocoding with SIRGAS 2000 coordinate system support.

Features:
- Forward and reverse geocoding endpoints
- Multiple precision levels (exact to state centroid)
- SIRGAS 2000 and WGS84 coordinate system support
- Brazilian address standardization
- CEP validation and lookup
- Spatial distance calculations
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, validator
import logging
import sys
from pathlib import Path

# Import advanced geocoding components
sys.path.append(str(Path(__file__).parent.parent.parent / "core"))
from geographic.advanced_geocoder import (
    AdvancedBrazilianGeocoder, 
    GeocodeResult, 
    AddressComponents,
    PrecisionLevel,
    CoordinateSystem
)

logger = logging.getLogger(__name__)

# Global advanced geocoder instance
_advanced_geocoder: Optional[AdvancedBrazilianGeocoder] = None


async def get_advanced_geocoder() -> AdvancedBrazilianGeocoder:
    """Dependency to get initialized advanced geocoder"""
    global _advanced_geocoder
    if _advanced_geocoder is None:
        _advanced_geocoder = AdvancedBrazilianGeocoder()
        logger.info("Advanced Brazilian geocoder initialized")
    return _advanced_geocoder


# Request/Response Models
class GeocodeRequest(BaseModel):
    """Request model for forward geocoding"""
    address: str = Field(..., description="Brazilian address to geocode")
    max_precision: Optional[str] = Field("STATE_CENTROID", description="Maximum precision level")
    coordinate_system: Optional[str] = Field("SIRGAS_2000", description="Target coordinate system")
    
    @validator('max_precision')
    def validate_precision(cls, v):
        if v:
            try:
                PrecisionLevel[v]
            except KeyError:
                raise ValueError(f"Invalid precision level. Must be one of: {[p.name for p in PrecisionLevel]}")
        return v
    
    @validator('coordinate_system')
    def validate_coordinate_system(cls, v):
        if v:
            try:
                CoordinateSystem[v]
            except KeyError:
                raise ValueError(f"Invalid coordinate system. Must be one of: {[c.name for c in CoordinateSystem]}")
        return v


class ReverseGeocodeRequest(BaseModel):
    """Request model for reverse geocoding"""
    latitude: float = Field(..., description="Latitude coordinate", ge=-90, le=90)
    longitude: float = Field(..., description="Longitude coordinate", ge=-180, le=180)
    radius_meters: Optional[float] = Field(100.0, description="Search radius in meters", ge=1, le=10000)
    coordinate_system: Optional[str] = Field("SIRGAS_2000", description="Source coordinate system")
    
    @validator('coordinate_system')
    def validate_coordinate_system(cls, v):
        if v:
            try:
                CoordinateSystem[v]
            except KeyError:
                raise ValueError(f"Invalid coordinate system. Must be one of: {[c.name for c in CoordinateSystem]}")
        return v


class GeocodeResponse(BaseModel):
    """Response model for geocoding results"""
    latitude: float
    longitude: float
    precision_level: str
    confidence: float
    address: str
    municipality: Optional[str] = None
    state: Optional[str] = None
    cep: Optional[str] = None
    coordinate_system: str
    distance_meters: Optional[float] = None
    processing_time_ms: Optional[float] = None


class AddressStandardizationResponse(BaseModel):
    """Response model for address standardization"""
    original_address: str
    standardized_address: str
    components: Dict[str, Optional[str]]
    cep_valid: bool


class DistanceCalculationRequest(BaseModel):
    """Request model for distance calculation"""
    point1_lat: float = Field(..., ge=-90, le=90)
    point1_lon: float = Field(..., ge=-180, le=180)
    point2_lat: float = Field(..., ge=-90, le=90)
    point2_lon: float = Field(..., ge=-180, le=180)


class BatchGeocodeRequest(BaseModel):
    """Request model for batch geocoding"""
    addresses: List[str] = Field(..., description="List of addresses to geocode", max_items=50)
    max_precision: Optional[str] = Field("MUNICIPALITY_CENTROID", description="Maximum precision level")
    coordinate_system: Optional[str] = Field("SIRGAS_2000", description="Target coordinate system")


# Create router
router = APIRouter(prefix="/api/v1/geocoding", tags=["Advanced Geocoding"])


@router.post("/forward", response_model=GeocodeResponse)
async def forward_geocode(
    request: GeocodeRequest,
    geocoder: AdvancedBrazilianGeocoder = Depends(get_advanced_geocoder)
):
    """
    Forward geocoding with multiple precision levels
    
    Args:
        request: Geocoding request with address and options
        
    Returns:
        Geocoding result with coordinates and metadata
    """
    try:
        # Convert string enums to actual enums
        max_precision = PrecisionLevel[request.max_precision] if request.max_precision else PrecisionLevel.STATE_CENTROID
        coordinate_system = CoordinateSystem[request.coordinate_system] if request.coordinate_system else CoordinateSystem.SIRGAS_2000
        
        result = await geocoder.forward_geocode(
            address=request.address,
            max_precision=max_precision,
            coordinate_system=coordinate_system
        )
        
        if not result:
            raise HTTPException(status_code=404, detail="Address not found")
        
        return GeocodeResponse(
            latitude=result.latitude,
            longitude=result.longitude,
            precision_level=result.precision_level.name,
            confidence=result.confidence,
            address=result.address,
            municipality=result.municipality,
            state=result.state,
            cep=result.cep,
            coordinate_system=result.coordinate_system.name,
            distance_meters=result.distance_meters,
            processing_time_ms=result.processing_time_ms
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Forward geocoding failed: {e}")
        raise HTTPException(status_code=500, detail="Geocoding failed")


@router.post("/reverse", response_model=List[GeocodeResponse])
async def reverse_geocode(
    request: ReverseGeocodeRequest,
    geocoder: AdvancedBrazilianGeocoder = Depends(get_advanced_geocoder)
):
    """
    Reverse geocoding with configurable search radius
    
    Args:
        request: Reverse geocoding request with coordinates and options
        
    Returns:
        List of nearby addresses with distances
    """
    try:
        coordinate_system = CoordinateSystem[request.coordinate_system] if request.coordinate_system else CoordinateSystem.SIRGAS_2000
        
        results = await geocoder.reverse_geocode(
            latitude=request.latitude,
            longitude=request.longitude,
            radius_meters=request.radius_meters,
            coordinate_system=coordinate_system
        )
        
        return [
            GeocodeResponse(
                latitude=result.latitude,
                longitude=result.longitude,
                precision_level=result.precision_level.name,
                confidence=result.confidence,
                address=result.address,
                municipality=result.municipality,
                state=result.state,
                cep=result.cep,
                coordinate_system=result.coordinate_system.name,
                distance_meters=result.distance_meters,
                processing_time_ms=result.processing_time_ms
            )
            for result in results
        ]
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Reverse geocoding failed: {e}")
        raise HTTPException(status_code=500, detail="Reverse geocoding failed")


@router.post("/standardize", response_model=AddressStandardizationResponse)
async def standardize_address(
    address: str,
    geocoder: AdvancedBrazilianGeocoder = Depends(get_advanced_geocoder)
):
    """
    Standardize a Brazilian address into components
    
    Args:
        address: Raw Brazilian address
        
    Returns:
        Standardized address with components
    """
    try:
        components = geocoder.address_standardizer.standardize_address(address)
        
        # Validate CEP if present
        cep_valid = False
        if components.cep:
            cep_valid = geocoder.address_standardizer.validate_cep(components.cep)
        
        return AddressStandardizationResponse(
            original_address=address,
            standardized_address=components.full_address or "",
            components={
                "street_type": components.street_type,
                "street_name": components.street_name,
                "number": components.number,
                "complement": components.complement,
                "neighborhood": components.neighborhood,
                "municipality": components.municipality,
                "state": components.state,
                "cep": components.cep
            },
            cep_valid=cep_valid
        )
        
    except Exception as e:
        logger.error(f"Address standardization failed: {e}")
        raise HTTPException(status_code=500, detail="Address standardization failed")


@router.post("/distance")
async def calculate_distance(
    request: DistanceCalculationRequest,
    geocoder: AdvancedBrazilianGeocoder = Depends(get_advanced_geocoder)
):
    """
    Calculate distance between two points using Haversine formula
    
    Args:
        request: Two points for distance calculation
        
    Returns:
        Distance in meters and other units
    """
    try:
        distance_meters = geocoder.spatial_calculator.haversine_distance(
            request.point1_lat, request.point1_lon,
            request.point2_lat, request.point2_lon
        )
        
        return {
            "distance_meters": distance_meters,
            "distance_kilometers": distance_meters / 1000,
            "point1": {
                "latitude": request.point1_lat,
                "longitude": request.point1_lon
            },
            "point2": {
                "latitude": request.point2_lat,
                "longitude": request.point2_lon
            }
        }
        
    except Exception as e:
        logger.error(f"Distance calculation failed: {e}")
        raise HTTPException(status_code=500, detail="Distance calculation failed")


@router.post("/batch", response_model=List[Optional[GeocodeResponse]])
async def batch_geocode(
    request: BatchGeocodeRequest,
    geocoder: AdvancedBrazilianGeocoder = Depends(get_advanced_geocoder)
):
    """
    Batch geocoding for multiple addresses
    
    Args:
        request: Batch geocoding request with multiple addresses
        
    Returns:
        List of geocoding results (null for failed addresses)
    """
    try:
        # Convert string enums to actual enums
        max_precision = PrecisionLevel[request.max_precision] if request.max_precision else PrecisionLevel.MUNICIPALITY_CENTROID
        coordinate_system = CoordinateSystem[request.coordinate_system] if request.coordinate_system else CoordinateSystem.SIRGAS_2000
        
        results = []
        
        for address in request.addresses:
            try:
                result = await geocoder.forward_geocode(
                    address=address,
                    max_precision=max_precision,
                    coordinate_system=coordinate_system
                )
                
                if result:
                    results.append(GeocodeResponse(
                        latitude=result.latitude,
                        longitude=result.longitude,
                        precision_level=result.precision_level.name,
                        confidence=result.confidence,
                        address=result.address,
                        municipality=result.municipality,
                        state=result.state,
                        cep=result.cep,
                        coordinate_system=result.coordinate_system.name,
                        distance_meters=result.distance_meters,
                        processing_time_ms=result.processing_time_ms
                    ))
                else:
                    results.append(None)
                    
            except Exception as e:
                logger.warning(f"Batch geocoding failed for address '{address}': {e}")
                results.append(None)
        
        return results
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Batch geocoding failed: {e}")
        raise HTTPException(status_code=500, detail="Batch geocoding failed")


@router.get("/cep/{cep}")
async def validate_cep(
    cep: str,
    geocoder: AdvancedBrazilianGeocoder = Depends(get_advanced_geocoder)
):
    """
    Validate and format Brazilian CEP
    
    Args:
        cep: CEP to validate
        
    Returns:
        CEP validation result and formatted version
    """
    try:
        is_valid = geocoder.address_standardizer.validate_cep(cep)
        formatted = geocoder.address_standardizer.format_cep(cep)
        
        return {
            "cep": cep,
            "valid": is_valid,
            "formatted": formatted,
            "message": "Valid CEP" if is_valid else "Invalid CEP format"
        }
        
    except Exception as e:
        logger.error(f"CEP validation failed: {e}")
        raise HTTPException(status_code=500, detail="CEP validation failed")


@router.get("/precision-levels")
async def get_precision_levels():
    """
    Get available geocoding precision levels
    
    Returns:
        List of precision levels with descriptions
    """
    return {
        "precision_levels": [
            {
                "level": 1,
                "name": "EXACT_MATCH",
                "description": "Exact address match in CNEFE database"
            },
            {
                "level": 2,
                "name": "PROBABILISTIC",
                "description": "Probabilistic address match with fuzzy matching"
            },
            {
                "level": 3,
                "name": "INTERPOLATED",
                "description": "Interpolated coordinates between known points"
            },
            {
                "level": 4,
                "name": "CEP_CENTROID",
                "description": "CEP (postal code) centroid"
            },
            {
                "level": 5,
                "name": "MUNICIPALITY_CENTROID",
                "description": "Municipality centroid"
            },
            {
                "level": 6,
                "name": "STATE_CENTROID",
                "description": "State centroid"
            }
        ],
        "coordinate_systems": [
            {
                "name": "SIRGAS_2000",
                "epsg": "EPSG:4674",
                "description": "Official Brazilian coordinate system"
            },
            {
                "name": "WGS84",
                "epsg": "EPSG:4326",
                "description": "International standard (GPS)"
            },
            {
                "name": "SAD69",
                "epsg": "EPSG:4291",
                "description": "Legacy Brazilian system"
            }
        ]
    }


@router.get("/statistics")
async def get_geocoder_statistics(
    geocoder: AdvancedBrazilianGeocoder = Depends(get_advanced_geocoder)
):
    """
    Get geocoder statistics and capabilities
    
    Returns:
        Geocoder statistics and available features
    """
    try:
        stats = geocoder.get_geocoder_statistics()
        
        return {
            "status": "operational",
            "statistics": stats,
            "version": "1.0.0",
            "data_sources": [
                "IBGE CNEFE (mock sample data)",
                "CEP centroids",
                "Municipality centroids (integrated)",
                "State centroids (built-in)"
            ],
            "features": {
                "forward_geocoding": True,
                "reverse_geocoding": True,
                "batch_processing": True,
                "address_standardization": True,
                "cep_validation": True,
                "precision_levels": 6,
                "coordinate_systems": 3
            }
        }
        
    except Exception as e:
        logger.error(f"Statistics retrieval failed: {e}")
        return {
            "status": "error",
            "error": str(e)
        }


@router.get("/health")
async def geocoding_health_check():
    """
    Health check endpoint for advanced geocoding service
    
    Returns:
        Service health status
    """
    try:
        geocoder = await get_advanced_geocoder()
        stats = geocoder.get_geocoder_statistics()
        
        return {
            "status": "healthy",
            "geocoder_initialized": True,
            "cnefe_records": stats["cnefe_records"],
            "cep_centroids": stats["cep_centroids"],
            "features_available": [
                "forward_geocoding",
                "reverse_geocoding",
                "batch_processing",
                "address_standardization",
                "cep_validation",
                "spatial_calculations"
            ]
        }
        
    except Exception as e:
        logger.error(f"Geocoding health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e)
        }