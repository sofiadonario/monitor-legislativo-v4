"""
Geographic service for Monitor Legislativo v4
Provides geographic analysis and context for Brazilian legislative documents
"""

import re
import asyncio
from typing import List, Optional, Dict, Set, Tuple
from functools import lru_cache
import logging

from .models import (
    BrazilianMunicipality, 
    GeographicScope, 
    BrazilianRegion,
    BRAZILIAN_STATES
)
from .data_loader import BrazilianGeographicDataLoader

logger = logging.getLogger(__name__)


class GeographicService:
    """
    Service for geographic analysis of Brazilian legislative documents
    Integrates with existing LexML document processing
    """
    
    def __init__(self, data_loader: Optional[BrazilianGeographicDataLoader] = None):
        self.data_loader = data_loader or BrazilianGeographicDataLoader()
        self._municipalities_cache: Optional[List[BrazilianMunicipality]] = None
        
        # Common geographic terms in Brazilian legislation
        self._geographic_keywords = {
            'federal': ['federal', 'união', 'nacional', 'brasil', 'brasileiro'],
            'regional': ['região', 'regional', 'nordeste', 'sudeste', 'sul', 'norte', 'centro-oeste'],
            'state': ['estado', 'estadual', 'governador', 'assembleia legislativa'],
            'municipal': ['município', 'municipal', 'prefeitura', 'câmara municipal', 'prefeito'],
        }
    
    async def initialize(self):
        """Initialize the service by loading municipality data"""
        self._municipalities_cache = await self.data_loader.load_municipalities()
        logger.info(f"Geographic service initialized with {len(self._municipalities_cache)} municipalities")
    
    async def analyze_document_geography(self, 
                                       document_title: str, 
                                       document_content: str,
                                       document_source: Optional[str] = None) -> GeographicScope:
        """
        Analyze the geographic scope of a legislative document
        
        Args:
            document_title: Title of the document
            document_content: Full text content of the document
            document_source: Source of the document (e.g., 'camara', 'senado')
            
        Returns:
            GeographicScope object with detected geographic coverage
        """
        if not self._municipalities_cache:
            await self.initialize()
        
        # Combine title and content for analysis
        full_text = f"{document_title} {document_content}".lower()
        
        # Detect scope level
        scope_type = self._detect_scope_type(full_text, document_source)
        
        # Extract geographic entities
        municipalities = await self._extract_municipalities(full_text)
        states = self._extract_states(full_text)
        regions = self._extract_regions(full_text)
        
        # Calculate confidence based on detection quality
        confidence = self._calculate_confidence(scope_type, municipalities, states, regions, full_text)
        
        return GeographicScope(
            municipalities=municipalities,
            states=states,
            regions=regions,
            scope_type=scope_type,
            confidence=confidence
        )
    
    def _detect_scope_type(self, text: str, source: Optional[str]) -> str:
        """Detect the geographic scope type of the document"""
        
        # Federal indicators
        federal_indicators = self._geographic_keywords['federal']
        if any(keyword in text for keyword in federal_indicators):
            return 'federal'
        
        # Source-based detection
        if source in ['senado', 'planalto']:
            return 'federal'
        
        # Regional indicators
        regional_indicators = self._geographic_keywords['regional']
        if any(keyword in text for keyword in regional_indicators):
            return 'regional'
        
        # State indicators
        state_indicators = self._geographic_keywords['state']
        if any(keyword in text for keyword in state_indicators):
            return 'state'
        
        # Municipal indicators
        municipal_indicators = self._geographic_keywords['municipal']
        if any(keyword in text for keyword in municipal_indicators):
            return 'municipal'
        
        # Default to federal if unclear
        return 'federal'
    
    async def _extract_municipalities(self, text: str) -> List[BrazilianMunicipality]:
        """Extract municipality references from text"""
        found_municipalities = []
        
        # Search for explicit municipality names
        for municipality in self._municipalities_cache:
            # Simple name matching (can be enhanced with fuzzy matching)
            if municipality.name.lower() in text:
                found_municipalities.append(municipality)
        
        # Remove duplicates while preserving order
        seen_ibge_codes = set()
        unique_municipalities = []
        for municipality in found_municipalities:
            if municipality.ibge_code not in seen_ibge_codes:
                unique_municipalities.append(municipality)
                seen_ibge_codes.add(municipality.ibge_code)
        
        return unique_municipalities
    
    def _extract_states(self, text: str) -> List[str]:
        """Extract state references from text"""
        found_states = []
        
        for state_code, state_info in BRAZILIAN_STATES.items():
            # Check for state name or abbreviation
            if (state_info['name'].lower() in text or 
                state_code.lower() in text):
                found_states.append(state_code)
        
        return list(set(found_states))  # Remove duplicates
    
    def _extract_regions(self, text: str) -> List[BrazilianRegion]:
        """Extract region references from text"""
        found_regions = []
        
        region_keywords = {
            BrazilianRegion.NORTE: ['norte', 'região norte', 'amazônia'],
            BrazilianRegion.NORDESTE: ['nordeste', 'região nordeste'],
            BrazilianRegion.CENTRO_OESTE: ['centro-oeste', 'centro oeste', 'região centro-oeste'],
            BrazilianRegion.SUDESTE: ['sudeste', 'região sudeste'],
            BrazilianRegion.SUL: ['sul', 'região sul']
        }
        
        for region, keywords in region_keywords.items():
            if any(keyword in text for keyword in keywords):
                found_regions.append(region)
        
        return found_regions
    
    def _calculate_confidence(self, 
                            scope_type: str, 
                            municipalities: List[BrazilianMunicipality],
                            states: List[str],
                            regions: List[BrazilianRegion],
                            text: str) -> float:
        """Calculate confidence score for geographic detection"""
        confidence = 0.5  # Base confidence
        
        # Increase confidence based on explicit matches
        if municipalities:
            confidence += 0.3
        if states:
            confidence += 0.2
        if regions:
            confidence += 0.1
        
        # Adjust based on scope consistency
        if scope_type == 'municipal' and municipalities:
            confidence += 0.2
        elif scope_type == 'state' and states:
            confidence += 0.2
        elif scope_type == 'regional' and regions:
            confidence += 0.2
        elif scope_type == 'federal':
            confidence += 0.1
        
        # Cap at 1.0
        return min(confidence, 1.0)
    
    async def get_municipality_by_name(self, name: str, state_code: Optional[str] = None) -> Optional[BrazilianMunicipality]:
        """
        Get municipality by name, optionally filtered by state
        
        Args:
            name: Municipality name
            state_code: Optional state code for disambiguation
            
        Returns:
            BrazilianMunicipality object or None
        """
        if not self._municipalities_cache:
            await self.initialize()
        
        candidates = self.data_loader.search_municipalities_by_name(name)
        
        if not candidates:
            return None
        
        if len(candidates) == 1:
            return candidates[0]
        
        # If multiple candidates and state provided, filter by state
        if state_code:
            state_candidates = [m for m in candidates if m.state == state_code.upper()]
            if state_candidates:
                return state_candidates[0]
        
        # Return first candidate if no state filter
        return candidates[0]
    
    async def get_municipalities_by_state(self, state_code: str) -> List[BrazilianMunicipality]:
        """Get all municipalities in a state"""
        if not self._municipalities_cache:
            await self.initialize()
        
        return self.data_loader.get_municipalities_by_state(state_code)
    
    async def get_municipalities_by_region(self, region: BrazilianRegion) -> List[BrazilianMunicipality]:
        """Get all municipalities in a region"""
        if not self._municipalities_cache:
            await self.initialize()
        
        return self.data_loader.get_municipalities_by_region(region)
    
    @lru_cache(maxsize=128)
    def _normalize_text_for_search(self, text: str) -> str:
        """Normalize text for better geographic entity matching"""
        # Remove accents, convert to lowercase, normalize whitespace
        import unicodedata
        
        text = unicodedata.normalize('NFD', text)
        text = ''.join(c for c in text if unicodedata.category(c) != 'Mn')
        text = text.lower().strip()
        text = re.sub(r'\s+', ' ', text)
        
        return text
    
    async def search_municipalities(self, 
                                  query: str, 
                                  state_filter: Optional[str] = None,
                                  region_filter: Optional[BrazilianRegion] = None,
                                  limit: int = 10) -> List[BrazilianMunicipality]:
        """
        Search municipalities by name with optional filters
        
        Args:
            query: Search query
            state_filter: Optional state code filter
            region_filter: Optional region filter
            limit: Maximum number of results
            
        Returns:
            List of matching municipalities
        """
        if not self._municipalities_cache:
            await self.initialize()
        
        normalized_query = self._normalize_text_for_search(query)
        results = []
        
        for municipality in self._municipalities_cache:
            normalized_name = self._normalize_text_for_search(municipality.name)
            
            # Check if query matches municipality name
            if normalized_query in normalized_name:
                # Apply filters
                if state_filter and municipality.state != state_filter.upper():
                    continue
                if region_filter and municipality.region != region_filter:
                    continue
                
                results.append(municipality)
                
                if len(results) >= limit:
                    break
        
        return results
    
    async def get_statistics(self) -> Dict[str, any]:
        """Get statistics about the geographic service"""
        if not self._municipalities_cache:
            await self.initialize()
        
        base_stats = await self.data_loader.get_statistics()
        
        # Add service-specific statistics
        base_stats.update({
            'service_initialized': self._municipalities_cache is not None,
            'cache_size': len(self._municipalities_cache) if self._municipalities_cache else 0,
            'geographic_keywords_loaded': len(self._geographic_keywords)
        })
        
        return base_stats
    
    def add_geographic_metadata_to_document(self, document_data: Dict, geographic_scope: GeographicScope) -> Dict:
        """
        Add geographic metadata to a document dictionary
        
        Args:
            document_data: Document dictionary
            geographic_scope: GeographicScope object
            
        Returns:
            Enhanced document dictionary with geographic metadata
        """
        document_data['geographic_scope'] = geographic_scope.to_dict()
        
        # Add convenience fields for querying
        document_data['geographic_municipalities'] = [m.ibge_code for m in geographic_scope.municipalities]
        document_data['geographic_states'] = geographic_scope.states
        document_data['geographic_regions'] = [r.value for r in geographic_scope.regions]
        document_data['geographic_scope_type'] = geographic_scope.scope_type
        document_data['geographic_confidence'] = geographic_scope.confidence
        
        return document_data