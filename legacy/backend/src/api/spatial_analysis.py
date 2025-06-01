"""
Spatial Analysis API - Advanced spatial document analysis with municipal boundaries and transport corridors
Provides comprehensive geographic analysis for Brazilian legislative documents
"""

import asyncio
import json
import logging
import math
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field

# Geospatial analysis libraries
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    logging.warning("NumPy not available - spatial calculations will be limited")

try:
    from shapely.geometry import Point, Polygon, LineString, MultiPolygon
    from shapely.ops import unary_union
    SHAPELY_AVAILABLE = True
except ImportError:
    SHAPELY_AVAILABLE = False
    logging.warning("Shapely not available - geometric operations will be limited")

# Import enhanced geocoding for integration
try:
    from .enhanced_geocoding import get_geocoding_processor, GeographicEntity, TransportCorridor
    ENHANCED_GEOCODING_AVAILABLE = True
except ImportError:
    ENHANCED_GEOCODING_AVAILABLE = False
    logging.warning("Enhanced geocoding not available - spatial analysis will be limited")

logger = logging.getLogger(__name__)

# Router for spatial analysis API
router = APIRouter(prefix="/api/v1/spatial-analysis", tags=["Spatial Analysis"])

class SpatialRelationType(str, Enum):
    """Types of spatial relationships"""
    INTERSECTS = "intersects"
    CONTAINS = "contains"
    WITHIN = "within"
    TOUCHES = "touches"
    OVERLAPS = "overlaps"
    NEAR = "near"
    CROSSES = "crosses"

class ImpactLevel(str, Enum):
    """Impact levels for spatial analysis"""
    DIRECT = "direct"
    INDIRECT = "indirect"
    REGIONAL = "regional"
    NATIONAL = "national"

@dataclass
class MunicipalBoundary:
    """Municipal boundary with spatial data"""
    municipality_name: str
    ibge_code: str
    state_code: str
    boundary_polygon: Optional[str]  # GeoJSON polygon
    centroid: Tuple[float, float]  # (lat, lon)
    area_km2: float
    population: int
    administrative_level: str
    neighboring_municipalities: List[str]

@dataclass
class TransportNetwork:
    """Transport network element"""
    network_id: str
    network_type: str  # highway, railway, waterway, etc.
    route_geometry: str  # GeoJSON LineString
    start_point: Tuple[float, float]
    end_point: Tuple[float, float]
    total_length_km: float
    affected_municipalities: List[str]
    regulatory_authority: str
    strategic_importance: str

@dataclass
class SpatialRelationship:
    """Spatial relationship between entities"""
    entity1_id: str
    entity2_id: str
    relationship_type: SpatialRelationType
    distance_km: Optional[float]
    confidence: float
    description: str

@dataclass
class ImpactAssessment:
    """Spatial impact assessment"""
    impact_type: str
    impact_level: ImpactLevel
    affected_area_km2: float
    affected_population: int
    affected_municipalities: List[str]
    economic_zones: List[str]
    transport_networks: List[str]
    environmental_considerations: List[str]

@dataclass
class SpatialAnalysisResult:
    """Comprehensive spatial analysis result"""
    document_id: str
    analysis_timestamp: str
    municipal_boundaries: List[MunicipalBoundary]
    transport_networks: List[TransportNetwork]
    spatial_relationships: List[SpatialRelationship]
    impact_assessments: List[ImpactAssessment]
    coverage_statistics: Dict[str, Any]
    spatial_patterns: Dict[str, Any]
    processing_time: float

# Pydantic models for API
class SpatialAnalysisRequest(BaseModel):
    document_content: str = Field(..., description="Legislative document content to analyze")
    document_id: str = Field(..., description="Unique document identifier")
    include_boundaries: bool = Field(default=True, description="Include municipal boundary analysis")
    include_transport: bool = Field(default=True, description="Include transport network analysis")
    include_impact: bool = Field(default=True, description="Include impact assessment")
    analysis_radius_km: float = Field(default=50.0, description="Analysis radius in kilometers")

class BoundaryAnalysisRequest(BaseModel):
    municipalities: List[str] = Field(..., description="List of municipalities to analyze")
    state_codes: Optional[List[str]] = Field(default=None, description="Filter by state codes")
    include_neighbors: bool = Field(default=True, description="Include neighboring municipalities")

class TransportCorridorAnalysisRequest(BaseModel):
    corridor_name: str = Field(..., description="Transport corridor name or ID")
    buffer_distance_km: float = Field(default=25.0, description="Buffer distance for impact analysis")
    include_economic_impact: bool = Field(default=True, description="Include economic impact analysis")

class SpatialAnalysisResponse(BaseModel):
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    processing_time: Optional[float] = None

class SpatialAnalysisProcessor:
    """Advanced spatial analysis processor for Brazilian legislative documents"""
    
    def __init__(self):
        self.municipal_boundaries_cache = {}
        self.transport_networks_cache = {}
        self.geocoding_processor = None
        
        # Brazilian geographic reference data
        self._init_brazilian_geographic_data()
    
    async def initialize(self) -> bool:
        """Initialize spatial analysis processor"""
        try:
            # Initialize enhanced geocoding integration
            if ENHANCED_GEOCODING_AVAILABLE:
                from .enhanced_geocoding import get_geocoding_processor
                self.geocoding_processor = await get_geocoding_processor()
            
            # Load municipal boundaries data
            await self._load_municipal_boundaries()
            
            # Load transport network data
            await self._load_transport_networks()
            
            logger.info("✅ Spatial analysis processor initialized")
            return True
            
        except Exception as e:
            logger.error(f"Spatial analysis processor initialization failed: {e}")
            return False
    
    async def analyze_document_spatial_impact(
        self,
        document_content: str,
        document_id: str,
        include_boundaries: bool = True,
        include_transport: bool = True,
        include_impact: bool = True,
        analysis_radius_km: float = 50.0
    ) -> SpatialAnalysisResult:
        """Comprehensive spatial analysis of legislative document"""
        
        start_time = time.time()
        
        # Extract geographic entities using enhanced geocoding
        geographic_entities = []
        transport_corridors = []
        
        if self.geocoding_processor:
            spatial_data = await self.geocoding_processor.analyze_document(
                text=document_content,
                document_id=document_id,
                include_transport=include_transport,
                include_ibge=include_boundaries
            )
            geographic_entities = spatial_data.geographic_entities
            transport_corridors = spatial_data.transport_corridors
        
        # Analyze municipal boundaries
        municipal_boundaries = []
        if include_boundaries and geographic_entities:
            municipal_boundaries = await self._analyze_municipal_boundaries(
                geographic_entities, analysis_radius_km
            )
        
        # Analyze transport networks
        transport_networks = []
        if include_transport and transport_corridors:
            transport_networks = await self._analyze_transport_networks(
                transport_corridors, geographic_entities
            )
        
        # Calculate spatial relationships
        spatial_relationships = await self._calculate_spatial_relationships(
            municipal_boundaries, transport_networks
        )
        
        # Perform impact assessments
        impact_assessments = []
        if include_impact:
            impact_assessments = await self._perform_impact_assessments(
                municipal_boundaries, transport_networks, spatial_relationships
            )
        
        # Generate coverage statistics
        coverage_stats = self._generate_coverage_statistics(
            municipal_boundaries, transport_networks, geographic_entities
        )
        
        # Detect spatial patterns
        spatial_patterns = self._detect_spatial_patterns(
            municipal_boundaries, transport_networks, spatial_relationships
        )
        
        processing_time = time.time() - start_time
        
        return SpatialAnalysisResult(
            document_id=document_id,
            analysis_timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
            municipal_boundaries=municipal_boundaries,
            transport_networks=transport_networks,
            spatial_relationships=spatial_relationships,
            impact_assessments=impact_assessments,
            coverage_statistics=coverage_stats,
            spatial_patterns=spatial_patterns,
            processing_time=processing_time
        )
    
    # Private helper methods
    def _init_brazilian_geographic_data(self):
        """Initialize Brazilian geographic reference data"""
        
        # Brazilian states with centroids (approximate)
        self.state_centroids = {
            'AC': (-9.0238, -70.8120), 'AL': (-9.5713, -36.7820), 'AP': (0.9020, -52.0030),
            'AM': (-3.4168, -65.8561), 'BA': (-12.5797, -41.7007), 'CE': (-5.4984, -39.3206),
            'DF': (-15.7998, -47.8645), 'ES': (-19.1834, -40.3089), 'GO': (-15.8270, -49.8362),
            'MA': (-4.9609, -45.2744), 'MT': (-12.6819, -56.9211), 'MS': (-20.7722, -54.7852),
            'MG': (-18.5122, -44.5550), 'PA': (-1.9981, -54.9306), 'PB': (-7.2399, -36.7819),
            'PR': (-24.8932, -51.4279), 'PE': (-8.8137, -36.9541), 'PI': (-8.6784, -42.7286),
            'RJ': (-22.9129, -43.2003), 'RN': (-5.4026, -36.9541), 'RS': (-30.2431, -53.7093),
            'RO': (-10.9472, -62.8097), 'RR': (1.9981, -61.3308), 'SC': (-27.2423, -50.2189),
            'SP': (-23.6821, -46.8755), 'SE': (-10.5741, -37.3857), 'TO': (-10.1753, -48.2982)
        }
        
        # Major Brazilian transport corridors
        self.major_corridors = {
            'BR-101': {
                'name': 'Rodovia Longitudinal',
                'type': 'highway',
                'states': ['RN', 'PB', 'PE', 'AL', 'SE', 'BA', 'ES', 'RJ', 'SP', 'PR', 'SC', 'RS'],
                'length_km': 4650
            },
            'BR-116': {
                'name': 'Rodovia Santos Dumont',
                'type': 'highway',
                'states': ['CE', 'PE', 'BA', 'MG', 'RJ', 'SP', 'PR', 'SC', 'RS'],
                'length_km': 4542
            },
            'BR-153': {
                'name': 'Rodovia Transbrasiliana',
                'type': 'highway',
                'states': ['TO', 'GO', 'MG', 'SP'],
                'length_km': 3585
            }
        }
    
    async def _load_municipal_boundaries(self):
        """Load municipal boundary data from various sources"""
        
        # In a production system, this would load from:
        # - IBGE municipal boundaries API
        # - Local shapefiles
        # - Cached boundary data
        
        # For now, we'll simulate with major municipalities
        major_municipalities = [
            {
                'name': 'São Paulo',
                'ibge_code': '3550308',
                'state_code': 'SP',
                'centroid': (-23.5505, -46.6333),
                'area_km2': 1521.11,
                'population': 12396372
            },
            {
                'name': 'Rio de Janeiro',
                'ibge_code': '3304557',
                'state_code': 'RJ',
                'centroid': (-22.9068, -43.1729),
                'area_km2': 1200.27,
                'population': 6775561
            },
            {
                'name': 'Brasília',
                'ibge_code': '5300108',
                'state_code': 'DF',
                'centroid': (-15.7801, -47.9292),
                'area_km2': 5760.78,
                'population': 3094325
            }
        ]
        
        for muni in major_municipalities:
            boundary = MunicipalBoundary(
                municipality_name=muni['name'],
                ibge_code=muni['ibge_code'],
                state_code=muni['state_code'],
                boundary_polygon=None,  # Would contain actual GeoJSON polygon
                centroid=muni['centroid'],
                area_km2=muni['area_km2'],
                population=muni['population'],
                administrative_level='municipality',
                neighboring_municipalities=[]
            )
            self.municipal_boundaries_cache[muni['name']] = boundary
        
        logger.info(f"✅ Loaded {len(major_municipalities)} municipal boundaries")
    
    async def _load_transport_networks(self):
        """Load transport network data"""
        
        # Load major transport networks
        for corridor_id, corridor_data in self.major_corridors.items():
            network = TransportNetwork(
                network_id=corridor_id,
                network_type='highway',
                route_geometry="",  # Would contain GeoJSON LineString
                start_point=self.state_centroids[corridor_data['states'][0]],
                end_point=self.state_centroids[corridor_data['states'][-1]],
                total_length_km=corridor_data['length_km'],
                affected_municipalities=[],  # Would be calculated from geometry
                regulatory_authority='DNIT',
                strategic_importance='National'
            )
            self.transport_networks_cache[corridor_id] = network
        
        logger.info(f"✅ Loaded {len(self.major_corridors)} transport networks")
    
    async def _analyze_municipal_boundaries(
        self,
        geographic_entities: List[GeographicEntity],
        radius_km: float
    ) -> List[MunicipalBoundary]:
        """Analyze municipal boundaries for geographic entities"""
        
        boundaries = []
        
        for entity in geographic_entities:
            if entity.level.value == 'municipality':
                # Try to get cached boundary data
                boundary = self.municipal_boundaries_cache.get(entity.name)
                if boundary:
                    boundaries.append(boundary)
                else:
                    # Create boundary from entity data
                    if entity.coordinates:
                        boundary = MunicipalBoundary(
                            municipality_name=entity.name,
                            ibge_code=entity.ibge_code or '',
                            state_code=entity.state_code or '',
                            boundary_polygon=None,
                            centroid=entity.coordinates,
                            area_km2=entity.area_km2 or 0.0,
                            population=entity.population or 0,
                            administrative_level='municipality',
                            neighboring_municipalities=[]
                        )
                        boundaries.append(boundary)
        
        return boundaries
    
    async def _analyze_transport_networks(
        self,
        transport_corridors: List[TransportCorridor],
        geographic_entities: List[GeographicEntity]
    ) -> List[TransportNetwork]:
        """Analyze transport networks from corridor data"""
        
        networks = []
        
        for corridor in transport_corridors:
            # Convert corridor to network format
            network = TransportNetwork(
                network_id=corridor.name,
                network_type=corridor.corridor_type.value,
                route_geometry="",  # Would contain actual geometry
                start_point=(0.0, 0.0),  # Would calculate from geometry
                end_point=(0.0, 0.0),   # Would calculate from geometry
                total_length_km=corridor.total_length_km or 0.0,
                affected_municipalities=[corridor.start_municipality, corridor.end_municipality],
                regulatory_authority=corridor.regulatory_authority or '',
                strategic_importance=corridor.strategic_importance
            )
            networks.append(network)
        
        return networks
    
    async def _calculate_spatial_relationships(
        self,
        boundaries: List[MunicipalBoundary],
        networks: List[TransportNetwork]
    ) -> List[SpatialRelationship]:
        """Calculate spatial relationships between entities"""
        
        relationships = []
        
        # Calculate relationships between municipalities
        for i, boundary1 in enumerate(boundaries):
            for boundary2 in boundaries[i+1:]:
                distance = self._calculate_distance(
                    boundary1.centroid, boundary2.centroid
                )
                
                # Determine relationship type based on distance
                if distance < 50:  # Within 50km
                    rel_type = SpatialRelationType.NEAR
                elif distance < 100:  # Within 100km
                    rel_type = SpatialRelationType.NEAR
                else:
                    continue  # Too far for meaningful relationship
                
                relationship = SpatialRelationship(
                    entity1_id=boundary1.municipality_name,
                    entity2_id=boundary2.municipality_name,
                    relationship_type=rel_type,
                    distance_km=distance,
                    confidence=0.9,
                    description=f"{boundary1.municipality_name} is {distance:.1f}km from {boundary2.municipality_name}"
                )
                relationships.append(relationship)
        
        return relationships
    
    async def _perform_impact_assessments(
        self,
        boundaries: List[MunicipalBoundary],
        networks: List[TransportNetwork],
        relationships: List[SpatialRelationship]
    ) -> List[ImpactAssessment]:
        """Perform spatial impact assessments"""
        
        assessments = []
        
        # Direct municipal impact
        if boundaries:
            total_area = sum(b.area_km2 for b in boundaries)
            total_population = sum(b.population for b in boundaries)
            
            direct_impact = ImpactAssessment(
                impact_type="direct_municipal",
                impact_level=ImpactLevel.DIRECT,
                affected_area_km2=total_area,
                affected_population=total_population,
                affected_municipalities=[b.municipality_name for b in boundaries],
                economic_zones=[],
                transport_networks=[n.network_id for n in networks],
                environmental_considerations=[]
            )
            assessments.append(direct_impact)
        
        return assessments
    
    def _generate_coverage_statistics(
        self,
        boundaries: List[MunicipalBoundary],
        networks: List[TransportNetwork],
        entities: List[GeographicEntity]
    ) -> Dict[str, Any]:
        """Generate coverage statistics"""
        
        stats = {
            "total_municipalities": len(boundaries),
            "total_transport_networks": len(networks),
            "total_area_km2": sum(b.area_km2 for b in boundaries),
            "total_population": sum(b.population for b in boundaries),
            "states_covered": list(set(b.state_code for b in boundaries if b.state_code)),
            "network_types": list(set(n.network_type for n in networks))
        }
        
        return stats
    
    def _detect_spatial_patterns(
        self,
        boundaries: List[MunicipalBoundary],
        networks: List[TransportNetwork],
        relationships: List[SpatialRelationship]
    ) -> Dict[str, Any]:
        """Detect spatial patterns in the data"""
        
        patterns = {
            "clustering": {
                "has_municipal_clusters": len(boundaries) > 3,
                "transport_hubs": len([n for n in networks if n.strategic_importance == "National"]) > 0
            },
            "connectivity": {
                "well_connected": len(relationships) > len(boundaries),
                "transport_integration": len(networks) > 0
            }
        }
        
        return patterns
    
    def _calculate_distance(self, point1: Tuple[float, float], point2: Tuple[float, float]) -> float:
        """Calculate distance between two points using Haversine formula"""
        
        lat1, lon1 = math.radians(point1[0]), math.radians(point1[1])
        lat2, lon2 = math.radians(point2[0]), math.radians(point2[1])
        
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        
        a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
        c = 2 * math.asin(math.sqrt(a))
        
        # Earth radius in kilometers
        r = 6371
        
        return c * r

# Global spatial analysis processor instance
_spatial_processor: Optional[SpatialAnalysisProcessor] = None

async def get_spatial_processor() -> SpatialAnalysisProcessor:
    """Get or create the global spatial analysis processor"""
    global _spatial_processor
    
    if _spatial_processor is None:
        _spatial_processor = SpatialAnalysisProcessor()
        if await _spatial_processor.initialize():
            logger.info("✅ Spatial analysis processor initialized")
        else:
            logger.warning("⚠️ Spatial analysis processor initialized with limited functionality")
    
    return _spatial_processor

# API endpoints
@router.post("/analyze-document", response_model=SpatialAnalysisResponse)
async def analyze_document_spatial_impact_endpoint(
    request: SpatialAnalysisRequest
) -> SpatialAnalysisResponse:
    """Analyze spatial impact of legislative document"""
    try:
        start_time = time.time()
        spatial_processor = await get_spatial_processor()
        
        result = await spatial_processor.analyze_document_spatial_impact(
            document_content=request.document_content,
            document_id=request.document_id,
            include_boundaries=request.include_boundaries,
            include_transport=request.include_transport,
            include_impact=request.include_impact,
            analysis_radius_km=request.analysis_radius_km
        )
        
        processing_time = time.time() - start_time
        
        return SpatialAnalysisResponse(
            success=True,
            data=asdict(result),
            processing_time=processing_time
        )
        
    except Exception as e:
        logger.error(f"Spatial analysis failed: {e}")
        return SpatialAnalysisResponse(
            success=False,
            error=str(e)
        )

@router.get("/health")
async def spatial_analysis_health_status() -> Dict[str, Any]:
    """Get spatial analysis system health status"""
    try:
        spatial_processor = await get_spatial_processor()
        
        return {
            "status": "healthy",
            "municipal_boundaries_loaded": len(spatial_processor.municipal_boundaries_cache),
            "transport_networks_loaded": len(spatial_processor.transport_networks_cache),
            "enhanced_geocoding_available": ENHANCED_GEOCODING_AVAILABLE,
            "numpy_available": NUMPY_AVAILABLE,
            "shapely_available": SHAPELY_AVAILABLE
        }
        
    except Exception as e:
        logger.error(f"Spatial analysis health check failed: {e}")
        return {
            "status": "error",
            "error": str(e)
        }

# Export router and processor getter
__all__ = ["router", "get_spatial_processor"]