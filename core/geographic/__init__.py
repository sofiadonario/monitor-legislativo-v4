"""
Geographic module for Monitor Legislativo v4
Provides Brazilian geographic data integration and spatial analysis capabilities.
"""

from .models import BrazilianMunicipality, GeographicScope, GeocodingResult
from .service import GeographicService
from .data_loader import BrazilianGeographicDataLoader

__all__ = [
    'BrazilianMunicipality',
    'GeographicScope', 
    'GeocodingResult',
    'GeographicService',
    'BrazilianGeographicDataLoader'
]