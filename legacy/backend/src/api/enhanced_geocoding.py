"""
Enhanced Geocoding API - Advanced IBGE CNEFE Integration
Precise Brazilian geographic analysis for legislative documents
"""

import asyncio
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
import aiohttp
import unicodedata

# Additional libraries for geographic processing
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    logging.warning("Pandas not available - some geocoding features will be limited")

try:
    from geopy.distance import geodesic
    from geopy.geocoders import Nominatim
    GEOPY_AVAILABLE = True
except ImportError:
    GEOPY_AVAILABLE = False
    logging.warning("GeoPy not available - distance calculations will be limited")

logger = logging.getLogger(__name__)

# Router for enhanced geocoding API
router = APIRouter(prefix="/api/v1/enhanced-geocoding", tags=["Enhanced Geocoding"])

class GeographicLevel(str, Enum):
    """Brazilian geographic administrative levels"""
    COUNTRY = "country"
    REGION = "region"  # Norte, Nordeste, etc.
    STATE = "state"    # UF
    MESOREGION = "mesoregion"
    MICROREGION = "microregion"
    MUNICIPALITY = "municipality"
    DISTRICT = "district"
    NEIGHBORHOOD = "neighborhood"
    TRANSPORT_CORRIDOR = "transport_corridor"

class TransportMode(str, Enum):
    """Brazilian transport modes for corridor analysis"""
    ROAD = "road"
    RAIL = "rail"
    WATERWAY = "waterway"
    AIRPORT = "airport"
    PORT = "port"
    MULTIMODAL = "multimodal"

@dataclass
class GeographicEntity:
    """Enhanced geographic entity with IBGE data"""
    name: str
    normalized_name: str
    level: GeographicLevel
    ibge_code: Optional[str]
    coordinates: Optional[Tuple[float, float]]  # (lat, lon)
    state_code: Optional[str]
    region: Optional[str]
    area_km2: Optional[float]
    population: Optional[int]
    transport_hubs: List[str]
    administrative_info: Dict[str, Any]
    confidence: float

@dataclass
class TransportCorridor:
    """Transport corridor information"""
    name: str
    corridor_type: TransportMode
    start_municipality: str
    end_municipality: str
    intermediate_cities: List[str]
    total_length_km: Optional[float]
    regulatory_authority: Optional[str]
    highway_codes: List[str]  # BR-XXX codes
    rail_lines: List[str]
    waterways: List[str]
    strategic_importance: str

@dataclass
class SpatialAnalysis:
    """Spatial analysis results"""
    document_id: str
    geographic_entities: List[GeographicEntity]
    transport_corridors: List[TransportCorridor]
    affected_municipalities: List[str]
    affected_states: List[str]
    coverage_analysis: Dict[str, Any]
    spatial_patterns: Dict[str, Any]
    processing_time: float

# Pydantic models for API
class GeocodingRequest(BaseModel):
    text: str = Field(..., description="Text to analyze for geographic entities")
    document_id: str = Field(..., description="Document identifier")
    include_transport_analysis: bool = Field(default=True, description="Include transport corridor analysis")
    include_ibge_data: bool = Field(default=True, description="Include IBGE demographic data")
    confidence_threshold: float = Field(default=0.7, description="Minimum confidence for entity inclusion")

class TransportCorridorRequest(BaseModel):
    start_city: str = Field(..., description="Starting city")
    end_city: str = Field(..., description="Destination city")
    transport_modes: List[TransportMode] = Field(default=[TransportMode.ROAD], description="Transport modes to analyze")

class GeocodingResponse(BaseModel):
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    processing_time: Optional[float] = None

class BrazilianGeocodingProcessor:
    """Enhanced geocoding processor with IBGE CNEFE integration"""
    
    def __init__(self):
        self.session = None
        self.ibge_cache = {}
        self.municipality_data = {}
        self.transport_corridors = {}
        
        # Brazilian geographic patterns
        self._init_geographic_patterns()
        self._init_transport_patterns()
        
        # IBGE API endpoints
        self.ibge_endpoints = {
            'municipalities': 'https://servicodados.ibge.gov.br/api/v1/localidades/municipios',
            'states': 'https://servicodados.ibge.gov.br/api/v1/localidades/estados',
            'regions': 'https://servicodados.ibge.gov.br/api/v1/localidades/regioes',
            'districts': 'https://servicodados.ibge.gov.br/api/v1/localidades/distritos'
        }
    
    async def initialize(self) -> bool:
        """Initialize geocoding processor with IBGE data"""
        try:
            self.session = aiohttp.ClientSession()
            
            # Load IBGE municipality data
            await self._load_ibge_municipalities()
            
            # Load transport corridor data
            await self._load_transport_corridors()
            
            logger.info("✅ Enhanced geocoding processor initialized with IBGE integration")
            return True
            
        except Exception as e:
            logger.error(f"Geocoding processor initialization failed: {e}")
            return False
    
    async def analyze_document(
        self, 
        text: str, 
        document_id: str,
        include_transport: bool = True,
        include_ibge: bool = True
    ) -> SpatialAnalysis:
        """Comprehensive spatial analysis of document"""
        
        start_time = time.time()
        
        # Extract geographic entities
        entities = await self._extract_geographic_entities(text, include_ibge)
        
        # Analyze transport corridors
        corridors = []
        if include_transport:
            corridors = await self._analyze_transport_corridors(text, entities)
        
        # Generate coverage analysis
        coverage = self._analyze_geographic_coverage(entities)
        
        # Detect spatial patterns
        patterns = self._detect_spatial_patterns(entities, corridors)
        
        # Compile affected areas
        affected_municipalities = [e.name for e in entities if e.level == GeographicLevel.MUNICIPALITY]
        affected_states = list(set([e.state_code for e in entities if e.state_code]))
        
        processing_time = time.time() - start_time
        
        return SpatialAnalysis(
            document_id=document_id,
            geographic_entities=entities,
            transport_corridors=corridors,
            affected_municipalities=affected_municipalities,
            affected_states=affected_states,
            coverage_analysis=coverage,
            spatial_patterns=patterns,
            processing_time=processing_time
        )
    
    async def find_transport_corridor(
        self,
        start_city: str,
        end_city: str,
        transport_modes: List[TransportMode]
    ) -> List[TransportCorridor]:
        """Find transport corridors between cities"""
        
        corridors = []
        
        # Normalize city names
        start_normalized = self._normalize_city_name(start_city)
        end_normalized = self._normalize_city_name(end_city)
        
        # Search for existing corridors
        for corridor in self.transport_corridors.values():
            if (self._matches_city(corridor.start_municipality, start_normalized) and 
                self._matches_city(corridor.end_municipality, end_normalized)) or \
               (self._matches_city(corridor.start_municipality, end_normalized) and 
                self._matches_city(corridor.end_municipality, start_normalized)):
                
                if corridor.corridor_type in transport_modes:
                    corridors.append(corridor)
        
        # If no exact match, find connections through intermediate cities
        if not corridors:
            corridors = await self._find_indirect_corridors(start_normalized, end_normalized, transport_modes)
        
        return corridors
    
    async def get_municipality_info(self, municipality_name: str, state_code: Optional[str] = None) -> Optional[GeographicEntity]:
        """Get detailed municipality information from IBGE"""
        
        normalized_name = self._normalize_city_name(municipality_name)
        
        # Search in cached data
        for muni_id, muni_data in self.municipality_data.items():
            if (self._normalize_city_name(muni_data['nome']) == normalized_name and
                (not state_code or muni_data.get('microrregiao', {}).get('mesorregiao', {}).get('UF', {}).get('sigla') == state_code)):
                
                return self._create_geographic_entity_from_ibge(muni_data)
        
        return None
    
    # Private helper methods
    def _init_geographic_patterns(self):
        """Initialize Brazilian geographic name patterns"""
        self.geographic_patterns = {
            'municipalities': [
                r'\b([A-Z][a-záêçãõúíó\s]+?)(?:\s*-\s*([A-Z]{2}))?\b',
                r'\bmunicipio\s+de\s+([A-Z][a-záêçãõúíó\s]+)\b',
                r'\bcidade\s+de\s+([A-Z][a-záêçãõúíó\s]+)\b'
            ],
            'states': [
                r'\bEstado\s+de\s+([A-Z][a-záêçãõúíó\s]+)\b',
                r'\b([A-Z][a-záêçãõúíó\s]+)\s*-\s*([A-Z]{2})\b',
                r'\b(Acre|Alagoas|Amapá|Amazonas|Bahia|Ceará|Espírito Santo|Goiás|Maranhão|Mato Grosso|Mato Grosso do Sul|Minas Gerais|Pará|Paraíba|Paraná|Pernambuco|Piauí|Rio de Janeiro|Rio Grande do Norte|Rio Grande do Sul|Rondônia|Roraima|Santa Catarina|São Paulo|Sergipe|Tocantins|Distrito Federal)\b'
            ],
            'regions': [
                r'\bRegião\s+(Norte|Nordeste|Centro-Oeste|Sudeste|Sul)\b',
                r'\b(Norte|Nordeste|Centro-Oeste|Sudeste|Sul)\s+do\s+Brasil\b'
            ]
        }
    
    def _init_transport_patterns(self):
        """Initialize transport infrastructure patterns"""
        self.transport_patterns = {
            'highways': [
                r'\b(BR-\d{3})\b',
                r'\bRodovia\s+([A-Z][a-záêçãõúíó\s]+)\b',
                r'\bAutoestrada\s+([A-Z][a-záêçãõúíó\s]+)\b'
            ],
            'railways': [
                r'\bFerrovia\s+([A-Z][a-záêçãõúíó\s-]+)\b',
                r'\bLinha\s+férrea\s+([A-Z][a-záêçãõúíó\s-]+)\b',
                r'\bEstrada\s+de\s+Ferro\s+([A-Z][a-záêçãõúíó\s-]+)\b'
            ],
            'waterways': [
                r'\bHidrovia\s+([A-Z][a-záêçãõúíó\s-]+)\b',
                r'\bRio\s+([A-Z][a-záêçãõúíó\s]+)\b',
                r'\bCanal\s+([A-Z][a-záêçãõúíó\s]+)\b'
            ],
            'ports': [
                r'\bPorto\s+de\s+([A-Z][a-záêçãõúíó\s]+)\b',
                r'\bTerminal\s+Portuário\s+de\s+([A-Z][a-záêçãõúíó\s]+)\b'
            ],
            'airports': [
                r'\bAeroporto\s+([A-Z][a-záêçãõúíó\s-]+)\b',
                r'\bAeródromo\s+([A-Z][a-záêçãõúíó\s-]+)\b'
            ]
        }
    
    async def _load_ibge_municipalities(self):
        """Load IBGE municipality data"""
        try:
            if not self.session:
                return
            
            async with self.session.get(self.ibge_endpoints['municipalities']) as response:
                if response.status == 200:
                    municipalities = await response.json()
                    
                    for muni in municipalities:
                        self.municipality_data[muni['id']] = muni
                    
                    logger.info(f"✅ Loaded {len(municipalities)} IBGE municipalities")
                else:
                    logger.warning(f"Failed to load IBGE municipalities: {response.status}")
                    
        except Exception as e:
            logger.warning(f"IBGE municipality loading failed: {e}")
    
    async def _load_transport_corridors(self):
        """Load Brazilian transport corridor data"""
        # Define major Brazilian transport corridors
        corridors_data = [
            {
                'name': 'Corredor São Paulo - Rio de Janeiro',
                'type': TransportMode.ROAD,
                'start': 'São Paulo',
                'end': 'Rio de Janeiro',
                'highways': ['BR-116'],
                'length_km': 430,
                'authority': 'DNIT'
            },
            {
                'name': 'Corredor Brasília - Goiânia',
                'type': TransportMode.ROAD,
                'start': 'Brasília',
                'end': 'Goiânia',
                'highways': ['BR-060'],
                'length_km': 210,
                'authority': 'DNIT'
            },
            {
                'name': 'Ferrovia Norte-Sul',
                'type': TransportMode.RAIL,
                'start': 'Estrela d\'Oeste',
                'end': 'Palmas',
                'railways': ['FNS'],
                'length_km': 1550,
                'authority': 'ANTT'
            },
            {
                'name': 'Hidrovia Tietê-Paraná',
                'type': TransportMode.WATERWAY,
                'start': 'São Paulo',
                'end': 'Corumbá',
                'waterways': ['Rio Tietê', 'Rio Paraná'],
                'length_km': 2400,
                'authority': 'ANTAQ'
            }
        ]
        
        for corridor_data in corridors_data:
            corridor = TransportCorridor(
                name=corridor_data['name'],
                corridor_type=corridor_data['type'],
                start_municipality=corridor_data['start'],
                end_municipality=corridor_data['end'],
                intermediate_cities=[],
                total_length_km=corridor_data.get('length_km'),
                regulatory_authority=corridor_data.get('authority'),
                highway_codes=corridor_data.get('highways', []),
                rail_lines=corridor_data.get('railways', []),
                waterways=corridor_data.get('waterways', []),
                strategic_importance='National'
            )
            
            self.transport_corridors[corridor_data['name']] = corridor
        
        logger.info(f"✅ Loaded {len(corridors_data)} transport corridors")
    
    async def _extract_geographic_entities(self, text: str, include_ibge: bool) -> List[GeographicEntity]:
        """Extract geographic entities from text with IBGE enhancement"""
        entities = []
        
        # Extract municipalities
        for pattern in self.geographic_patterns['municipalities']:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                city_name = match.group(1).strip()
                state_code = match.group(2) if match.lastindex > 1 else None
                
                if len(city_name) > 2:  # Filter out very short matches
                    entity = await self._create_enhanced_entity(
                        city_name, 
                        GeographicLevel.MUNICIPALITY,
                        state_code,
                        include_ibge
                    )
                    if entity:
                        entities.append(entity)
        
        # Extract states
        for pattern in self.geographic_patterns['states']:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                state_name = match.group(1).strip() if match.lastindex >= 1 else match.group(0)
                
                entity = await self._create_enhanced_entity(
                    state_name,
                    GeographicLevel.STATE,
                    None,
                    include_ibge
                )
                if entity:
                    entities.append(entity)
        
        # Extract regions
        for pattern in self.geographic_patterns['regions']:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                region_name = match.group(1).strip() if match.lastindex >= 1 else match.group(0)
                
                entity = GeographicEntity(
                    name=region_name,
                    normalized_name=self._normalize_text(region_name),
                    level=GeographicLevel.REGION,
                    ibge_code=None,
                    coordinates=None,
                    state_code=None,
                    region=region_name,
                    area_km2=None,
                    population=None,
                    transport_hubs=[],
                    administrative_info={},
                    confidence=0.9
                )
                entities.append(entity)
        
        # Remove duplicates
        return self._remove_duplicate_entities(entities)
    
    async def _create_enhanced_entity(
        self, 
        name: str, 
        level: GeographicLevel,
        state_code: Optional[str],
        include_ibge: bool
    ) -> Optional[GeographicEntity]:
        """Create enhanced geographic entity with IBGE data"""
        
        normalized_name = self._normalize_text(name)
        
        if include_ibge and level == GeographicLevel.MUNICIPALITY:
            # Try to find in IBGE data
            ibge_data = await self._find_in_ibge_data(normalized_name, state_code)
            if ibge_data:
                return self._create_geographic_entity_from_ibge(ibge_data)
        
        # Fallback to basic entity
        return GeographicEntity(
            name=name,
            normalized_name=normalized_name,
            level=level,
            ibge_code=None,
            coordinates=None,
            state_code=state_code,
            region=None,
            area_km2=None,
            population=None,
            transport_hubs=[],
            administrative_info={},
            confidence=0.7
        )
    
    async def _find_in_ibge_data(self, normalized_name: str, state_code: Optional[str]) -> Optional[Dict]:
        """Find municipality in IBGE data"""
        
        for muni_data in self.municipality_data.values():
            muni_normalized = self._normalize_text(muni_data['nome'])
            muni_state = muni_data.get('microrregiao', {}).get('mesorregiao', {}).get('UF', {}).get('sigla')
            
            if (muni_normalized == normalized_name and
                (not state_code or muni_state == state_code)):
                return muni_data
        
        return None
    
    def _create_geographic_entity_from_ibge(self, ibge_data: Dict) -> GeographicEntity:
        """Create geographic entity from IBGE data"""
        
        uf_data = ibge_data.get('microrregiao', {}).get('mesorregiao', {}).get('UF', {})
        region_data = uf_data.get('regiao', {})
        
        return GeographicEntity(
            name=ibge_data['nome'],
            normalized_name=self._normalize_text(ibge_data['nome']),
            level=GeographicLevel.MUNICIPALITY,
            ibge_code=str(ibge_data['id']),
            coordinates=None,  # Would need additional API call
            state_code=uf_data.get('sigla'),
            region=region_data.get('nome'),
            area_km2=None,
            population=None,
            transport_hubs=[],
            administrative_info={
                'microregion': ibge_data.get('microrregiao', {}).get('nome'),
                'mesoregion': ibge_data.get('microrregiao', {}).get('mesorregiao', {}).get('nome'),
                'state': uf_data.get('nome'),
                'region_id': region_data.get('id')
            },
            confidence=0.95
        )
    
    async def _analyze_transport_corridors(self, text: str, entities: List[GeographicEntity]) -> List[TransportCorridor]:
        """Analyze transport corridors mentioned in text"""
        corridors = []
        
        # Extract highway references
        for pattern in self.transport_patterns['highways']:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                highway_code = match.group(1) if match.lastindex >= 1 else match.group(0)
                
                # Find corridors that use this highway
                for corridor in self.transport_corridors.values():
                    if highway_code in corridor.highway_codes:
                        corridors.append(corridor)
        
        # Extract railway references
        for pattern in self.transport_patterns['railways']:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                railway_name = match.group(1) if match.lastindex >= 1 else match.group(0)
                
                # Find corridors that use this railway
                for corridor in self.transport_corridors.values():
                    if any(railway_name.lower() in rail.lower() for rail in corridor.rail_lines):
                        corridors.append(corridor)
        
        return list(set(corridors))  # Remove duplicates
    
    def _analyze_geographic_coverage(self, entities: List[GeographicEntity]) -> Dict[str, Any]:
        """Analyze geographic coverage of entities"""
        
        coverage = {
            'total_entities': len(entities),
            'by_level': {},
            'by_region': {},
            'by_state': {},
            'national_scope': False,
            'multi_regional': False
        }
        
        # Count by level
        for entity in entities:
            level = entity.level.value
            coverage['by_level'][level] = coverage['by_level'].get(level, 0) + 1
        
        # Count by region and state
        regions = set()
        states = set()
        
        for entity in entities:
            if entity.region:
                regions.add(entity.region)
                coverage['by_region'][entity.region] = coverage['by_region'].get(entity.region, 0) + 1
            
            if entity.state_code:
                states.add(entity.state_code)
                coverage['by_state'][entity.state_code] = coverage['by_state'].get(entity.state_code, 0) + 1
        
        # Determine scope
        coverage['national_scope'] = len(regions) >= 3  # 3+ regions = national
        coverage['multi_regional'] = len(regions) > 1
        coverage['multi_state'] = len(states) > 1
        
        return coverage
    
    def _detect_spatial_patterns(
        self, 
        entities: List[GeographicEntity], 
        corridors: List[TransportCorridor]
    ) -> Dict[str, Any]:
        """Detect spatial patterns in geographic data"""
        
        patterns = {
            'urban_focus': False,
            'rural_focus': False,
            'coastal_areas': False,
            'border_regions': False,
            'metropolitan_areas': [],
            'transport_integration': len(corridors) > 0,
            'corridor_types': [c.corridor_type.value for c in corridors]
        }
        
        # Detect metropolitan areas
        metropolitan_cities = {
            'São Paulo', 'Rio de Janeiro', 'Belo Horizonte', 'Salvador',
            'Brasília', 'Fortaleza', 'Manaus', 'Curitiba', 'Recife', 'Porto Alegre'
        }
        
        for entity in entities:
            if entity.level == GeographicLevel.MUNICIPALITY:
                if any(metro in entity.name for metro in metropolitan_cities):
                    patterns['metropolitan_areas'].append(entity.name)
        
        patterns['urban_focus'] = len(patterns['metropolitan_areas']) > 0
        
        # Detect coastal states
        coastal_states = {'RJ', 'SP', 'ES', 'BA', 'SE', 'AL', 'PE', 'PB', 'RN', 'CE', 'PI', 'MA', 'PA', 'AP', 'AM', 'RR', 'SC', 'PR', 'RS'}
        coastal_count = sum(1 for entity in entities if entity.state_code in coastal_states)
        patterns['coastal_areas'] = coastal_count > 0
        
        return patterns
    
    def _normalize_text(self, text: str) -> str:
        """Normalize text for comparison"""
        # Remove accents and convert to lowercase
        text = unicodedata.normalize('NFD', text)
        text = ''.join(c for c in text if unicodedata.category(c) != 'Mn')
        return text.lower().strip()
    
    def _normalize_city_name(self, city_name: str) -> str:
        """Normalize city name for matching"""
        normalized = self._normalize_text(city_name)
        # Remove common prefixes/suffixes
        normalized = re.sub(r'\b(de|da|do|das|dos)\b', '', normalized)
        return normalized.strip()
    
    def _matches_city(self, city1: str, city2: str) -> bool:
        """Check if two city names match"""
        return self._normalize_city_name(city1) == self._normalize_city_name(city2)
    
    def _remove_duplicate_entities(self, entities: List[GeographicEntity]) -> List[GeographicEntity]:
        """Remove duplicate geographic entities"""
        seen = set()
        unique_entities = []
        
        for entity in entities:
            key = (entity.normalized_name, entity.level.value, entity.state_code)
            if key not in seen:
                seen.add(key)
                unique_entities.append(entity)
        
        return unique_entities
    
    async def _find_indirect_corridors(
        self,
        start_city: str,
        end_city: str,
        transport_modes: List[TransportMode]
    ) -> List[TransportCorridor]:
        """Find indirect transport corridors between cities"""
        # Simplified implementation - would need graph algorithms for complex routing
        return []

# Global geocoding processor instance
_geocoding_processor: Optional[BrazilianGeocodingProcessor] = None

async def get_geocoding_processor() -> BrazilianGeocodingProcessor:
    """Get or create the global geocoding processor"""
    global _geocoding_processor
    
    if _geocoding_processor is None:
        _geocoding_processor = BrazilianGeocodingProcessor()
        if await _geocoding_processor.initialize():
            logger.info("✅ Brazilian geocoding processor initialized")
        else:
            logger.warning("⚠️ Geocoding processor initialized with limited functionality")
    
    return _geocoding_processor

# API endpoints
@router.post("/analyze-document", response_model=GeocodingResponse)
async def analyze_document_geography(request: GeocodingRequest) -> GeocodingResponse:
    """Analyze geographic entities and transport corridors in document"""
    try:
        start_time = time.time()
        geocoding_processor = await get_geocoding_processor()
        
        analysis = await geocoding_processor.analyze_document(
            text=request.text,
            document_id=request.document_id,
            include_transport=request.include_transport_analysis,
            include_ibge=request.include_ibge_data
        )
        
        processing_time = time.time() - start_time
        
        return GeocodingResponse(
            success=True,
            data=asdict(analysis),
            processing_time=processing_time
        )
        
    except Exception as e:
        logger.error(f"Geographic analysis failed: {e}")
        return GeocodingResponse(
            success=False,
            error=str(e)
        )

@router.post("/find-corridor", response_model=GeocodingResponse)
async def find_transport_corridor_endpoint(request: TransportCorridorRequest) -> GeocodingResponse:
    """Find transport corridors between cities"""
    try:
        geocoding_processor = await get_geocoding_processor()
        
        corridors = await geocoding_processor.find_transport_corridor(
            start_city=request.start_city,
            end_city=request.end_city,
            transport_modes=request.transport_modes
        )
        
        return GeocodingResponse(
            success=True,
            data={
                "corridors": [asdict(corridor) for corridor in corridors],
                "total_found": len(corridors)
            }
        )
        
    except Exception as e:
        logger.error(f"Transport corridor search failed: {e}")
        return GeocodingResponse(
            success=False,
            error=str(e)
        )

@router.get("/municipality/{municipality_name}")
async def get_municipality_info_endpoint(
    municipality_name: str,
    state_code: Optional[str] = None
) -> GeocodingResponse:
    """Get detailed municipality information from IBGE"""
    try:
        geocoding_processor = await get_geocoding_processor()
        
        municipality = await geocoding_processor.get_municipality_info(
            municipality_name=municipality_name,
            state_code=state_code
        )
        
        if municipality:
            return GeocodingResponse(
                success=True,
                data=asdict(municipality)
            )
        else:
            return GeocodingResponse(
                success=False,
                error=f"Municipality '{municipality_name}' not found"
            )
        
    except Exception as e:
        logger.error(f"Municipality lookup failed: {e}")
        return GeocodingResponse(
            success=False,
            error=str(e)
        )

@router.get("/health")
async def geocoding_health_status() -> Dict[str, Any]:
    """Get geocoding system health status"""
    try:
        geocoding_processor = await get_geocoding_processor()
        
        return {
            "status": "healthy",
            "ibge_municipalities_loaded": len(geocoding_processor.municipality_data),
            "transport_corridors_loaded": len(geocoding_processor.transport_corridors),
            "pandas_available": PANDAS_AVAILABLE,
            "geopy_available": GEOPY_AVAILABLE,
            "session_active": geocoding_processor.session is not None
        }
        
    except Exception as e:
        logger.error(f"Geocoding health check failed: {e}")
        return {
            "status": "error",
            "error": str(e)
        }

# Export router and processor getter
__all__ = ["router", "get_geocoding_processor"]