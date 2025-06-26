"""
Geographic data models for Brazilian legislative documents.
Based on datasets-br/city-codes and geocodebr patterns.
"""

from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from enum import Enum


class BrazilianRegion(Enum):
    """Brazilian geographic regions"""
    NORTE = "Norte"
    NORDESTE = "Nordeste"
    CENTRO_OESTE = "Centro-Oeste"
    SUDESTE = "Sudeste"
    SUL = "Sul"


@dataclass
class BrazilianMunicipality:
    """
    Brazilian municipality data model
    Based on datasets-br/city-codes structure with IBGE standards
    """
    name: str
    state: str  # Two-letter state code (SP, RJ, etc.)
    state_name: str  # Full state name
    region: BrazilianRegion
    ibge_code: str  # 7-digit IBGE municipality code
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    
    # Additional identifier systems (from datasets-br/city-codes)
    tse_code: Optional[str] = None  # Tribunal Superior Eleitoral
    anatel_code: Optional[str] = None  # Agência Nacional de Telecomunicações
    siafi_code: Optional[str] = None  # Sistema Integrado de Administração Financeira
    
    # Population and area data (optional)
    population: Optional[int] = None
    area_km2: Optional[float] = None
    
    def __post_init__(self):
        """Validate IBGE code format"""
        if self.ibge_code and len(self.ibge_code) != 7:
            raise ValueError(f"IBGE code must be 7 digits, got: {self.ibge_code}")
    
    @property
    def coordinates(self) -> Optional[tuple[float, float]]:
        """Return (latitude, longitude) tuple if available"""
        if self.latitude is not None and self.longitude is not None:
            return (self.latitude, self.longitude)
        return None
    
    @property
    def state_ibge_code(self) -> str:
        """Extract state IBGE code from municipality code"""
        return self.ibge_code[:2] if self.ibge_code else ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'name': self.name,
            'state': self.state,
            'state_name': self.state_name,
            'region': self.region.value,
            'ibge_code': self.ibge_code,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'tse_code': self.tse_code,
            'anatel_code': self.anatel_code,
            'siafi_code': self.siafi_code,
            'population': self.population,
            'area_km2': self.area_km2
        }


@dataclass
class GeographicScope:
    """
    Geographic scope for legislative documents
    Represents the geographic coverage/impact of a document
    """
    municipalities: List[BrazilianMunicipality]
    states: List[str]  # State codes
    regions: List[BrazilianRegion]
    scope_type: str  # 'municipal', 'state', 'regional', 'federal'
    confidence: float = 1.0  # Confidence in geographic detection (0.0-1.0)
    
    @property
    def is_federal(self) -> bool:
        """Check if scope covers entire country"""
        return self.scope_type == 'federal'
    
    @property
    def is_regional(self) -> bool:
        """Check if scope covers specific regions"""
        return self.scope_type == 'regional' and len(self.regions) > 0
    
    @property
    def is_state_level(self) -> bool:
        """Check if scope is at state level"""
        return self.scope_type == 'state' and len(self.states) > 0
    
    @property
    def is_municipal(self) -> bool:
        """Check if scope is at municipality level"""
        return self.scope_type == 'municipal' and len(self.municipalities) > 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'municipalities': [m.to_dict() for m in self.municipalities],
            'states': self.states,
            'regions': [r.value for r in self.regions],
            'scope_type': self.scope_type,
            'confidence': self.confidence
        }


class GeocodingPrecision(Enum):
    """Geocoding precision levels (based on geocodebr patterns)"""
    EXACT_MATCH = 1  # Exact address match
    PROBABILISTIC = 2  # Probabilistic address match
    INTERPOLATED = 3  # Interpolated coordinates
    CEP_CENTROID = 4  # CEP (postal code) centroid
    MUNICIPALITY_CENTROID = 5  # Municipality centroid
    STATE_CENTROID = 6  # State centroid


@dataclass
class GeocodingResult:
    """
    Result of geocoding operation
    Based on geocodebr multi-level precision approach
    """
    latitude: float
    longitude: float
    precision: GeocodingPrecision
    confidence: float  # 0.0-1.0
    address: str
    municipality: Optional[BrazilianMunicipality] = None
    
    # Additional metadata
    formatted_address: Optional[str] = None
    cep: Optional[str] = None  # Brazilian postal code
    distance_meters: Optional[float] = None  # For reverse geocoding
    
    @property
    def coordinates(self) -> tuple[float, float]:
        """Return (latitude, longitude) tuple"""
        return (self.latitude, self.longitude)
    
    @property
    def is_high_precision(self) -> bool:
        """Check if result has high precision (levels 1-3)"""
        return self.precision.value <= 3
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'latitude': self.latitude,
            'longitude': self.longitude,
            'precision': self.precision.value,
            'precision_name': self.precision.name,
            'confidence': self.confidence,
            'address': self.address,
            'formatted_address': self.formatted_address,
            'cep': self.cep,
            'distance_meters': self.distance_meters,
            'municipality': self.municipality.to_dict() if self.municipality else None
        }


@dataclass
class AddressSearchResult:
    """Result for address search operations (reverse geocoding)"""
    address: str
    municipality: BrazilianMunicipality
    distance_meters: float
    cep: Optional[str] = None
    confidence: float = 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'address': self.address,
            'municipality': self.municipality.to_dict(),
            'distance_meters': self.distance_meters,
            'cep': self.cep,
            'confidence': self.confidence
        }


# Brazilian state mappings for consistency
BRAZILIAN_STATES = {
    'AC': {'name': 'Acre', 'region': BrazilianRegion.NORTE},
    'AL': {'name': 'Alagoas', 'region': BrazilianRegion.NORDESTE},
    'AP': {'name': 'Amapá', 'region': BrazilianRegion.NORTE},
    'AM': {'name': 'Amazonas', 'region': BrazilianRegion.NORTE},
    'BA': {'name': 'Bahia', 'region': BrazilianRegion.NORDESTE},
    'CE': {'name': 'Ceará', 'region': BrazilianRegion.NORDESTE},
    'DF': {'name': 'Distrito Federal', 'region': BrazilianRegion.CENTRO_OESTE},
    'ES': {'name': 'Espírito Santo', 'region': BrazilianRegion.SUDESTE},
    'GO': {'name': 'Goiás', 'region': BrazilianRegion.CENTRO_OESTE},
    'MA': {'name': 'Maranhão', 'region': BrazilianRegion.NORDESTE},
    'MT': {'name': 'Mato Grosso', 'region': BrazilianRegion.CENTRO_OESTE},
    'MS': {'name': 'Mato Grosso do Sul', 'region': BrazilianRegion.CENTRO_OESTE},
    'MG': {'name': 'Minas Gerais', 'region': BrazilianRegion.SUDESTE},
    'PA': {'name': 'Pará', 'region': BrazilianRegion.NORTE},
    'PB': {'name': 'Paraíba', 'region': BrazilianRegion.NORDESTE},
    'PR': {'name': 'Paraná', 'region': BrazilianRegion.SUL},
    'PE': {'name': 'Pernambuco', 'region': BrazilianRegion.NORDESTE},
    'PI': {'name': 'Piauí', 'region': BrazilianRegion.NORDESTE},
    'RJ': {'name': 'Rio de Janeiro', 'region': BrazilianRegion.SUDESTE},
    'RN': {'name': 'Rio Grande do Norte', 'region': BrazilianRegion.NORDESTE},
    'RS': {'name': 'Rio Grande do Sul', 'region': BrazilianRegion.SUL},
    'RO': {'name': 'Rondônia', 'region': BrazilianRegion.NORTE},
    'RR': {'name': 'Roraima', 'region': BrazilianRegion.NORTE},
    'SC': {'name': 'Santa Catarina', 'region': BrazilianRegion.SUL},
    'SP': {'name': 'São Paulo', 'region': BrazilianRegion.SUDESTE},
    'SE': {'name': 'Sergipe', 'region': BrazilianRegion.NORDESTE},
    'TO': {'name': 'Tocantins', 'region': BrazilianRegion.NORTE}
}