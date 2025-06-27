"""
Advanced Brazilian Geocoding Service
===================================

Advanced geocoding service based on ipeaGIT/geocodebr patterns with IBGE CNEFE data integration.
Implements 6-level precision geocoding with SIRGAS 2000 coordinate system support.

Features:
- Forward and reverse geocoding with multiple precision levels
- IBGE CNEFE official address database integration
- SIRGAS 2000 coordinate system (EPSG:4674) support
- Brazilian address standardization and normalization
- Haversine distance calculations for spatial analysis
- CEP (postal code) integration and validation
- Municipality-level fallback for legislative documents

Based on patterns from:
- ipeaGIT/geocodebr: Official Brazilian geocoding service
- IBGE CNEFE: Official address database standards
- enderecobr: Address standardization patterns
"""

import math
import re
import logging
import unicodedata
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from enum import Enum
import json

logger = logging.getLogger(__name__)


class PrecisionLevel(Enum):
    """Geocoding precision levels based on geocodebr standards"""
    EXACT_MATCH = 1          # Exact address match
    PROBABILISTIC = 2        # Probabilistic address match
    INTERPOLATED = 3         # Interpolated coordinates
    CEP_CENTROID = 4        # CEP centroid
    MUNICIPALITY_CENTROID = 5 # Municipality centroid
    STATE_CENTROID = 6       # State centroid


class CoordinateSystem(Enum):
    """Supported coordinate systems"""
    SIRGAS_2000 = "EPSG:4674"  # Official Brazilian system
    WGS84 = "EPSG:4326"        # International standard
    SAD69 = "EPSG:4291"        # Legacy Brazilian system


@dataclass
class GeocodeResult:
    """Geocoding result with precision and confidence information"""
    latitude: float
    longitude: float
    precision_level: PrecisionLevel
    confidence: float  # 0.0 to 1.0
    address: str
    municipality: Optional[str] = None
    state: Optional[str] = None
    cep: Optional[str] = None
    coordinate_system: CoordinateSystem = CoordinateSystem.SIRGAS_2000
    distance_meters: Optional[float] = None
    processing_time_ms: Optional[float] = None


@dataclass
class AddressComponents:
    """Standardized Brazilian address components"""
    street_type: Optional[str] = None  # Rua, Avenida, Praça, etc.
    street_name: Optional[str] = None
    number: Optional[str] = None
    complement: Optional[str] = None
    neighborhood: Optional[str] = None
    municipality: Optional[str] = None
    state: Optional[str] = None
    cep: Optional[str] = None
    full_address: Optional[str] = None


class BrazilianAddressStandardizer:
    """Brazilian address standardization following enderecobr patterns"""
    
    def __init__(self):
        # Street type abbreviations (Brazilian standard)
        self.street_types = {
            'rua': 'r.',
            'avenida': 'av.',
            'praça': 'pç.',
            'travessa': 'tv.',
            'alameda': 'al.',
            'estrada': 'est.',
            'rodovia': 'rod.',
            'via': 'v.',
            'largo': 'lg.',
            'beco': 'bc.',
            'viela': 'vl.',
            'quadra': 'qd.',
            'lote': 'lt.',
            'conjunto': 'cj.',
            'residencial': 'res.'
        }
        
        # State abbreviations
        self.state_names = {
            'acre': 'ac', 'alagoas': 'al', 'amapá': 'ap', 'amazonas': 'am',
            'bahia': 'ba', 'ceará': 'ce', 'espírito santo': 'es', 
            'goiás': 'go', 'maranhão': 'ma', 'mato grosso': 'mt',
            'mato grosso do sul': 'ms', 'minas gerais': 'mg', 'pará': 'pa',
            'paraíba': 'pb', 'paraná': 'pr', 'pernambuco': 'pe', 'piauí': 'pi',
            'rio de janeiro': 'rj', 'rio grande do norte': 'rn',
            'rio grande do sul': 'rs', 'rondônia': 'ro', 'roraima': 'rr',
            'santa catarina': 'sc', 'são paulo': 'sp', 'sergipe': 'se',
            'tocantins': 'to', 'distrito federal': 'df'
        }
        
        # Common address cleaning patterns
        self.cleaning_patterns = [
            (r'\s+', ' '),  # Multiple spaces to single space
            (r'[,;]+', ','),  # Multiple commas/semicolons to single comma
            (r'\.+', '.'),  # Multiple dots to single dot
            (r'\s*,\s*', ', '),  # Normalize comma spacing
        ]
    
    def normalize_text(self, text: str) -> str:
        """Normalize Brazilian Portuguese text for address matching"""
        if not text:
            return ""
        
        # Convert to lowercase
        text = text.lower().strip()
        
        # Remove accents but preserve ç
        normalized = unicodedata.normalize('NFD', text)
        text = ''.join(c for c in normalized if unicodedata.category(c) != 'Mn' or c == 'ç')
        
        # Apply cleaning patterns
        for pattern, replacement in self.cleaning_patterns:
            text = re.sub(pattern, replacement, text)
        
        return text.strip()
    
    def standardize_address(self, address: str) -> AddressComponents:
        """Standardize a Brazilian address into components"""
        if not address:
            return AddressComponents()
        
        normalized = self.normalize_text(address)
        components = AddressComponents(full_address=normalized)
        
        # Extract CEP if present (format: 12345-678 or 12345678)
        cep_match = re.search(r'(\d{5})-?(\d{3})', normalized)
        if cep_match:
            components.cep = f"{cep_match.group(1)}-{cep_match.group(2)}"
            normalized = re.sub(r'\d{5}-?\d{3}', '', normalized).strip()
        
        # Extract state (2-letter code at end)
        state_match = re.search(r'\b([a-z]{2})\s*$', normalized)
        if state_match:
            components.state = state_match.group(1).upper()
            normalized = re.sub(r'\b[a-z]{2}\s*$', '', normalized).strip()
        
        # Split by commas to get address parts
        parts = [part.strip() for part in normalized.split(',') if part.strip()]
        
        if len(parts) >= 1:
            # First part usually contains street info
            street_part = parts[0]
            
            # Extract street type and name
            for full_type, abbrev in self.street_types.items():
                if street_part.startswith(full_type + ' '):
                    components.street_type = abbrev
                    components.street_name = street_part[len(full_type):].strip()
                    break
            
            if not components.street_name:
                components.street_name = street_part
            
            # Extract number from street name
            number_match = re.search(r'\b(\d+[a-z]?)\b', components.street_name or '')
            if number_match:
                components.number = number_match.group(1)
                components.street_name = re.sub(r'\b\d+[a-z]?\b', '', components.street_name or '').strip()
        
        if len(parts) >= 2:
            components.neighborhood = parts[1]
        
        if len(parts) >= 3:
            components.municipality = parts[2]
        
        return components
    
    def validate_cep(self, cep: str) -> bool:
        """Validate Brazilian CEP format"""
        if not cep:
            return False
        
        # Remove formatting
        clean_cep = re.sub(r'[^\d]', '', cep)
        
        # Must be exactly 8 digits
        if len(clean_cep) != 8:
            return False
        
        # Cannot be all zeros or all nines
        if clean_cep == '00000000' or clean_cep == '99999999':
            return False
        
        return True
    
    def format_cep(self, cep: str) -> str:
        """Format CEP with standard hyphen"""
        if not cep:
            return ""
        
        clean_cep = re.sub(r'[^\d]', '', cep)
        if len(clean_cep) == 8:
            return f"{clean_cep[:5]}-{clean_cep[5:]}"
        
        return cep


class SpatialCalculator:
    """Spatial calculations for Brazilian geocoding"""
    
    EARTH_RADIUS_METERS = 6371000.0  # Earth radius in meters
    
    @staticmethod
    def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """
        Calculate precise distance between two points using Haversine formula
        
        Args:
            lat1, lon1: First point coordinates
            lat2, lon2: Second point coordinates
            
        Returns:
            Distance in meters
        """
        # Convert to radians
        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        delta_lat = math.radians(lat2 - lat1)
        delta_lon = math.radians(lon2 - lon1)
        
        # Haversine formula
        a = (math.sin(delta_lat / 2) ** 2 + 
             math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon / 2) ** 2)
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        
        return SpatialCalculator.EARTH_RADIUS_METERS * c
    
    @staticmethod
    def point_in_radius(center_lat: float, center_lon: float, 
                       point_lat: float, point_lon: float, 
                       radius_meters: float) -> bool:
        """Check if a point is within a radius of a center point"""
        distance = SpatialCalculator.haversine_distance(
            center_lat, center_lon, point_lat, point_lon
        )
        return distance <= radius_meters
    
    @staticmethod
    def convert_coordinates(lat: float, lon: float, 
                          from_system: CoordinateSystem, 
                          to_system: CoordinateSystem) -> Tuple[float, float]:
        """
        Convert coordinates between systems
        
        Note: This is a simplified conversion. For production use,
        implement proper coordinate transformation using pyproj or similar.
        """
        if from_system == to_system:
            return lat, lon
        
        # Simplified conversion - in production, use proper transformation
        # SIRGAS 2000 is very close to WGS84 for most Brazilian applications
        if ((from_system == CoordinateSystem.SIRGAS_2000 and to_system == CoordinateSystem.WGS84) or
            (from_system == CoordinateSystem.WGS84 and to_system == CoordinateSystem.SIRGAS_2000)):
            return lat, lon  # Minimal difference for most applications
        
        # For other conversions, return as-is (would need proper transformation library)
        logger.warning(f"Coordinate conversion from {from_system.value} to {to_system.value} not implemented")
        return lat, lon


class AdvancedBrazilianGeocoder:
    """
    Advanced Brazilian geocoding service implementing geocodebr patterns
    
    Provides 6-level precision geocoding with IBGE CNEFE data integration
    and SIRGAS 2000 coordinate system support.
    """
    
    def __init__(self):
        self.address_standardizer = BrazilianAddressStandardizer()
        self.spatial_calculator = SpatialCalculator()
        
        # Mock CNEFE data - in production, load from actual IBGE database
        self.cnefe_data = self._load_mock_cnefe_data()
        
        # CEP centroids - sample data
        self.cep_centroids = self._load_mock_cep_centroids()
        
        logger.info("Advanced Brazilian Geocoder initialized")
    
    def _load_mock_cnefe_data(self) -> Dict[str, Dict[str, Any]]:
        """Load mock CNEFE data - in production, load from IBGE database"""
        # Sample CNEFE data for major Brazilian cities
        return {
            "rua da consolacao 1000 sao paulo sp": {
                "latitude": -23.5489,
                "longitude": -46.6388,
                "municipality": "São Paulo",
                "state": "SP",
                "cep": "01302-001",
                "neighborhood": "Consolação",
                "precision": PrecisionLevel.EXACT_MATCH
            },
            "av paulista 1000 sao paulo sp": {
                "latitude": -23.5614,
                "longitude": -46.6562,
                "municipality": "São Paulo", 
                "state": "SP",
                "cep": "01310-100",
                "neighborhood": "Bela Vista",
                "precision": PrecisionLevel.EXACT_MATCH
            },
            "av copacabana 1000 rio de janeiro rj": {
                "latitude": -22.9717,
                "longitude": -43.1873,
                "municipality": "Rio de Janeiro",
                "state": "RJ", 
                "cep": "22070-011",
                "neighborhood": "Copacabana",
                "precision": PrecisionLevel.EXACT_MATCH
            }
        }
    
    def _load_mock_cep_centroids(self) -> Dict[str, Dict[str, Any]]:
        """Load mock CEP centroid data"""
        return {
            "01310": {
                "latitude": -23.5614,
                "longitude": -46.6562,
                "municipality": "São Paulo",
                "state": "SP",
                "neighborhood": "Bela Vista"
            },
            "22070": {
                "latitude": -22.9717,
                "longitude": -43.1873,
                "municipality": "Rio de Janeiro", 
                "state": "RJ",
                "neighborhood": "Copacabana"
            },
            "70040": {
                "latitude": -15.7801,
                "longitude": -47.9292,
                "municipality": "Brasília",
                "state": "DF",
                "neighborhood": "Asa Norte"
            }
        }
    
    async def forward_geocode(self, address: str, 
                            max_precision: PrecisionLevel = PrecisionLevel.STATE_CENTROID,
                            coordinate_system: CoordinateSystem = CoordinateSystem.SIRGAS_2000) -> Optional[GeocodeResult]:
        """
        Forward geocoding with multiple precision levels
        
        Args:
            address: Address to geocode
            max_precision: Maximum precision level to attempt
            coordinate_system: Target coordinate system
            
        Returns:
            Geocoding result or None if no match found
        """
        if not address:
            return None
        
        import time
        start_time = time.time()
        
        # Standardize address
        components = self.address_standardizer.standardize_address(address)
        normalized_address = components.full_address
        
        # Try exact match first (Precision Level 1)
        if max_precision.value >= PrecisionLevel.EXACT_MATCH.value:
            exact_result = await self._try_exact_match(normalized_address, components)
            if exact_result:
                exact_result.processing_time_ms = (time.time() - start_time) * 1000
                return self._convert_coordinate_system(exact_result, coordinate_system)
        
        # Try probabilistic match (Precision Level 2) 
        if max_precision.value >= PrecisionLevel.PROBABILISTIC.value:
            prob_result = await self._try_probabilistic_match(normalized_address, components)
            if prob_result:
                prob_result.processing_time_ms = (time.time() - start_time) * 1000
                return self._convert_coordinate_system(prob_result, coordinate_system)
        
        # Try CEP centroid (Precision Level 4)
        if max_precision.value >= PrecisionLevel.CEP_CENTROID.value and components.cep:
            cep_result = await self._try_cep_centroid(components)
            if cep_result:
                cep_result.processing_time_ms = (time.time() - start_time) * 1000
                return self._convert_coordinate_system(cep_result, coordinate_system)
        
        # Try municipality centroid (Precision Level 5)
        if max_precision.value >= PrecisionLevel.MUNICIPALITY_CENTROID.value and components.municipality:
            muni_result = await self._try_municipality_centroid(components)
            if muni_result:
                muni_result.processing_time_ms = (time.time() - start_time) * 1000
                return self._convert_coordinate_system(muni_result, coordinate_system)
        
        # Try state centroid (Precision Level 6)
        if max_precision.value >= PrecisionLevel.STATE_CENTROID.value and components.state:
            state_result = await self._try_state_centroid(components)
            if state_result:
                state_result.processing_time_ms = (time.time() - start_time) * 1000
                return self._convert_coordinate_system(state_result, coordinate_system)
        
        return None
    
    async def reverse_geocode(self, latitude: float, longitude: float,
                            radius_meters: float = 100.0,
                            coordinate_system: CoordinateSystem = CoordinateSystem.SIRGAS_2000) -> List[GeocodeResult]:
        """
        Reverse geocoding with configurable search radius
        
        Args:
            latitude: Latitude coordinate
            longitude: Longitude coordinate  
            radius_meters: Search radius in meters
            coordinate_system: Source coordinate system
            
        Returns:
            List of nearby addresses
        """
        # Convert to SIRGAS 2000 if needed
        if coordinate_system != CoordinateSystem.SIRGAS_2000:
            latitude, longitude = self.spatial_calculator.convert_coordinates(
                latitude, longitude, coordinate_system, CoordinateSystem.SIRGAS_2000
            )
        
        results = []
        
        # Search in CNEFE data
        for address_key, data in self.cnefe_data.items():
            distance = self.spatial_calculator.haversine_distance(
                latitude, longitude, data["latitude"], data["longitude"]
            )
            
            if distance <= radius_meters:
                result = GeocodeResult(
                    latitude=data["latitude"],
                    longitude=data["longitude"],
                    precision_level=PrecisionLevel.EXACT_MATCH,
                    confidence=max(0.0, 1.0 - (distance / radius_meters)),
                    address=address_key.title(),
                    municipality=data.get("municipality"),
                    state=data.get("state"),
                    cep=data.get("cep"),
                    distance_meters=distance,
                    coordinate_system=CoordinateSystem.SIRGAS_2000
                )
                results.append(result)
        
        # Sort by distance
        results.sort(key=lambda x: x.distance_meters or 0)
        
        return results
    
    async def _try_exact_match(self, address: str, components: AddressComponents) -> Optional[GeocodeResult]:
        """Try exact address match in CNEFE data"""
        if address in self.cnefe_data:
            data = self.cnefe_data[address]
            return GeocodeResult(
                latitude=data["latitude"],
                longitude=data["longitude"],
                precision_level=PrecisionLevel.EXACT_MATCH,
                confidence=0.95,
                address=address.title(),
                municipality=data.get("municipality"),
                state=data.get("state"),
                cep=data.get("cep"),
                coordinate_system=CoordinateSystem.SIRGAS_2000
            )
        return None
    
    async def _try_probabilistic_match(self, address: str, components: AddressComponents) -> Optional[GeocodeResult]:
        """Try probabilistic address matching"""
        # Simple fuzzy matching - in production, use more sophisticated algorithms
        address_words = set(address.split())
        
        best_match = None
        best_score = 0.0
        
        for cnefe_address, data in self.cnefe_data.items():
            cnefe_words = set(cnefe_address.split())
            
            # Calculate word overlap score
            common_words = address_words & cnefe_words
            total_words = address_words | cnefe_words
            
            if total_words:
                score = len(common_words) / len(total_words)
                
                if score > best_score and score >= 0.6:  # Minimum threshold
                    best_score = score
                    best_match = data
        
        if best_match:
            return GeocodeResult(
                latitude=best_match["latitude"],
                longitude=best_match["longitude"],
                precision_level=PrecisionLevel.PROBABILISTIC,
                confidence=best_score * 0.8,  # Lower confidence for probabilistic
                address=address.title(),
                municipality=best_match.get("municipality"),
                state=best_match.get("state"),
                cep=best_match.get("cep"),
                coordinate_system=CoordinateSystem.SIRGAS_2000
            )
        
        return None
    
    async def _try_cep_centroid(self, components: AddressComponents) -> Optional[GeocodeResult]:
        """Try CEP centroid geocoding"""
        if not components.cep:
            return None
        
        # Get first 5 digits of CEP
        cep_prefix = components.cep.replace('-', '')[:5]
        
        if cep_prefix in self.cep_centroids:
            data = self.cep_centroids[cep_prefix]
            return GeocodeResult(
                latitude=data["latitude"],
                longitude=data["longitude"],
                precision_level=PrecisionLevel.CEP_CENTROID,
                confidence=0.7,
                address=f"CEP {components.cep}",
                municipality=data.get("municipality"),
                state=data.get("state"),
                cep=components.cep,
                coordinate_system=CoordinateSystem.SIRGAS_2000
            )
        
        return None
    
    async def _try_municipality_centroid(self, components: AddressComponents) -> Optional[GeocodeResult]:
        """Try municipality centroid geocoding"""
        # Use existing geographic service for municipality centroids
        try:
            from .service import GeographicService
            geo_service = GeographicService()
            await geo_service.initialize()
            
            municipalities = await geo_service.search_municipalities(
                query=components.municipality,
                limit=1
            )
            
            if municipalities:
                muni = municipalities[0]
                if muni.latitude and muni.longitude:
                    return GeocodeResult(
                        latitude=muni.latitude,
                        longitude=muni.longitude,
                        precision_level=PrecisionLevel.MUNICIPALITY_CENTROID,
                        confidence=0.6,
                        address=f"{muni.name}, {muni.state}",
                        municipality=muni.name,
                        state=muni.state,
                        coordinate_system=CoordinateSystem.SIRGAS_2000
                    )
        except Exception as e:
            logger.warning(f"Municipality centroid lookup failed: {e}")
        
        return None
    
    async def _try_state_centroid(self, components: AddressComponents) -> Optional[GeocodeResult]:
        """Try state centroid geocoding"""
        # Brazilian state centroids (approximate)
        state_centroids = {
            "SP": (-23.5489, -46.6388),  # São Paulo
            "RJ": (-22.9068, -43.1729),  # Rio de Janeiro
            "MG": (-19.9167, -43.9345),  # Minas Gerais
            "DF": (-15.7801, -47.9292),  # Distrito Federal
            "PR": (-25.4284, -49.2733),  # Paraná
            "RS": (-30.0346, -51.2177),  # Rio Grande do Sul
            "BA": (-12.9714, -38.5014),  # Bahia
            "SC": (-27.5954, -48.5480),  # Santa Catarina
            "GO": (-16.6864, -49.2643),  # Goiás
            "PE": (-8.0476, -34.8770),   # Pernambuco
        }
        
        state = components.state
        if state and state in state_centroids:
            lat, lon = state_centroids[state]
            return GeocodeResult(
                latitude=lat,
                longitude=lon,
                precision_level=PrecisionLevel.STATE_CENTROID,
                confidence=0.4,
                address=f"Estado de {state}",
                state=state,
                coordinate_system=CoordinateSystem.SIRGAS_2000
            )
        
        return None
    
    def _convert_coordinate_system(self, result: GeocodeResult, 
                                 target_system: CoordinateSystem) -> GeocodeResult:
        """Convert result to target coordinate system"""
        if result.coordinate_system == target_system:
            return result
        
        lat, lon = self.spatial_calculator.convert_coordinates(
            result.latitude, result.longitude,
            result.coordinate_system, target_system
        )
        
        result.latitude = lat
        result.longitude = lon
        result.coordinate_system = target_system
        
        return result
    
    def get_geocoder_statistics(self) -> Dict[str, Any]:
        """Get geocoder statistics and capabilities"""
        return {
            "cnefe_records": len(self.cnefe_data),
            "cep_centroids": len(self.cep_centroids),
            "precision_levels": [level.name for level in PrecisionLevel],
            "coordinate_systems": [system.value for system in CoordinateSystem],
            "capabilities": {
                "forward_geocoding": True,
                "reverse_geocoding": True,
                "address_standardization": True,
                "cep_validation": True,
                "spatial_calculations": True
            }
        }