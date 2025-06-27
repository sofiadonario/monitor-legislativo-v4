"""
Advanced Spatial Analysis Service
Enhanced spatial document analysis with reverse geocoding for Brazilian legislative data
"""
from typing import Dict, List, Tuple, Optional, Set, Any
from dataclasses import dataclass, field
from datetime import datetime
import json
import math
import re
from collections import defaultdict, Counter
import asyncio
from geopy.distance import geodesic
from geopy.geocoders import Nominatim

from core.config.config import Config
from core.utils.logger import Logger
from core.models.legislative_data import LegislativeDocument

logger = Logger()


@dataclass
class GeoLocation:
    """Geographic location with Brazilian municipality context."""
    latitude: float
    longitude: float
    municipality: str
    state: str
    state_code: str
    region: str
    ibge_code: str
    population: Optional[int] = None
    area_km2: Optional[float] = None
    confidence: float = 1.0


@dataclass
class SpatialCluster:
    """Cluster of documents with spatial proximity."""
    cluster_id: str
    centroid: GeoLocation
    documents: List[str]  # Document IDs
    radius_km: float
    document_count: int
    themes: List[str]
    temporal_span: Tuple[str, str]  # Start and end dates
    regulatory_density: float
    cluster_strength: float


@dataclass
class DocumentSpatialAnalysis:
    """Spatial analysis results for a document."""
    document_id: str
    extracted_locations: List[GeoLocation]
    primary_location: Optional[GeoLocation]
    jurisdiction_level: str  # 'federal', 'estadual', 'municipal', 'regional'
    coverage_area: List[str]  # States/municipalities affected
    spatial_keywords: List[str]
    geographic_scope: str  # 'nacional', 'regional', 'estadual', 'municipal', 'local'
    related_locations: List[GeoLocation]
    confidence_score: float


@dataclass
class SpatialRelationship:
    """Relationship between documents based on spatial proximity."""
    document1_id: str
    document2_id: str
    relationship_type: str  # 'same_municipality', 'adjacent', 'same_state', 'same_region'
    distance_km: float
    shared_locations: List[str]
    correlation_strength: float
    temporal_overlap: bool


@dataclass
class SpatialTrendAnalysis:
    """Analysis of spatial trends in legislative activity."""
    region: str
    time_period: Tuple[str, str]
    document_count: int
    activity_trend: str  # 'increasing', 'decreasing', 'stable', 'volatile'
    dominant_themes: List[str]
    regulatory_hotspots: List[GeoLocation]
    spatial_distribution: Dict[str, int]  # state/municipality -> count
    trend_strength: float
    comparative_ranking: int


class SpatialAnalysisService:
    """Advanced spatial analysis service for Brazilian legislative documents."""
    
    def __init__(self):
        self.config = Config()
        self.geocoder = Nominatim(user_agent="monitor_legislativo_v4")
        self._load_brazilian_geography()
        self._initialize_spatial_patterns()
        
    def _load_brazilian_geography(self):
        """Load Brazilian geographic data for spatial analysis."""
        # Brazilian states and regions
        self.brazilian_states = {
            'AC': {'name': 'Acre', 'region': 'Norte', 'capital': 'Rio Branco'},
            'AL': {'name': 'Alagoas', 'region': 'Nordeste', 'capital': 'Maceió'},
            'AP': {'name': 'Amapá', 'region': 'Norte', 'capital': 'Macapá'},
            'AM': {'name': 'Amazonas', 'region': 'Norte', 'capital': 'Manaus'},
            'BA': {'name': 'Bahia', 'region': 'Nordeste', 'capital': 'Salvador'},
            'CE': {'name': 'Ceará', 'region': 'Nordeste', 'capital': 'Fortaleza'},
            'DF': {'name': 'Distrito Federal', 'region': 'Centro-Oeste', 'capital': 'Brasília'},
            'ES': {'name': 'Espírito Santo', 'region': 'Sudeste', 'capital': 'Vitória'},
            'GO': {'name': 'Goiás', 'region': 'Centro-Oeste', 'capital': 'Goiânia'},
            'MA': {'name': 'Maranhão', 'region': 'Nordeste', 'capital': 'São Luís'},
            'MT': {'name': 'Mato Grosso', 'region': 'Centro-Oeste', 'capital': 'Cuiabá'},
            'MS': {'name': 'Mato Grosso do Sul', 'region': 'Centro-Oeste', 'capital': 'Campo Grande'},
            'MG': {'name': 'Minas Gerais', 'region': 'Sudeste', 'capital': 'Belo Horizonte'},
            'PA': {'name': 'Pará', 'region': 'Norte', 'capital': 'Belém'},
            'PB': {'name': 'Paraíba', 'region': 'Nordeste', 'capital': 'João Pessoa'},
            'PR': {'name': 'Paraná', 'region': 'Sul', 'capital': 'Curitiba'},
            'PE': {'name': 'Pernambuco', 'region': 'Nordeste', 'capital': 'Recife'},
            'PI': {'name': 'Piauí', 'region': 'Nordeste', 'capital': 'Teresina'},
            'RJ': {'name': 'Rio de Janeiro', 'region': 'Sudeste', 'capital': 'Rio de Janeiro'},
            'RN': {'name': 'Rio Grande do Norte', 'region': 'Nordeste', 'capital': 'Natal'},
            'RS': {'name': 'Rio Grande do Sul', 'region': 'Sul', 'capital': 'Porto Alegre'},
            'RO': {'name': 'Rondônia', 'region': 'Norte', 'capital': 'Porto Velho'},
            'RR': {'name': 'Roraima', 'region': 'Norte', 'capital': 'Boa Vista'},
            'SC': {'name': 'Santa Catarina', 'region': 'Sul', 'capital': 'Florianópolis'},
            'SP': {'name': 'São Paulo', 'region': 'Sudeste', 'capital': 'São Paulo'},
            'SE': {'name': 'Sergipe', 'region': 'Nordeste', 'capital': 'Aracaju'},
            'TO': {'name': 'Tocantins', 'region': 'Norte', 'capital': 'Palmas'}
        }
        
        # Major Brazilian municipalities with coordinates
        self.major_municipalities = {
            'São Paulo': {'lat': -23.5505, 'lon': -46.6333, 'state': 'SP', 'population': 12396372},
            'Rio de Janeiro': {'lat': -22.9068, 'lon': -43.1729, 'state': 'RJ', 'population': 6775561},
            'Brasília': {'lat': -15.8267, 'lon': -47.9218, 'state': 'DF', 'population': 3094325},
            'Salvador': {'lat': -12.9777, 'lon': -38.5016, 'state': 'BA', 'population': 2886698},
            'Fortaleza': {'lat': -3.7319, 'lon': -38.5267, 'state': 'CE', 'population': 2703391},
            'Belo Horizonte': {'lat': -19.9191, 'lon': -43.9386, 'state': 'MG', 'population': 2722235},
            'Manaus': {'lat': -3.1190, 'lon': -60.0217, 'state': 'AM', 'population': 2255903},
            'Curitiba': {'lat': -25.4284, 'lon': -49.2733, 'state': 'PR', 'population': 1963726},
            'Recife': {'lat': -8.0476, 'lon': -34.8770, 'state': 'PE', 'population': 1661017},
            'Porto Alegre': {'lat': -30.0346, 'lon': -51.2177, 'state': 'RS', 'population': 1492530},
            'Goiânia': {'lat': -16.6799, 'lon': -49.2550, 'state': 'GO', 'population': 1555626},
            'Belém': {'lat': -1.4558, 'lon': -48.5044, 'state': 'PA', 'population': 1506420},
            'Guarulhos': {'lat': -23.4628, 'lon': -46.5333, 'state': 'SP', 'population': 1403694},
            'Campinas': {'lat': -22.9099, 'lon': -47.0626, 'state': 'SP', 'population': 1223237},
            'São Luís': {'lat': -2.5297, 'lon': -44.3028, 'state': 'MA', 'population': 1115932},
            'São Gonçalo': {'lat': -22.8267, 'lon': -43.0537, 'state': 'RJ', 'population': 1091737},
            'Maceió': {'lat': -9.6658, 'lon': -35.7353, 'state': 'AL', 'population': 1025360},
            'Duque de Caxias': {'lat': -22.7856, 'lon': -43.3056, 'state': 'RJ', 'population': 924624},
            'Teresina': {'lat': -5.0892, 'lon': -42.8019, 'state': 'PI', 'population': 871126},
            'Natal': {'lat': -5.7945, 'lon': -35.2110, 'state': 'RN', 'population': 890480}
        }
        
        # Regional boundaries for clustering
        self.regional_boundaries = {
            'Norte': {'min_lat': -5.0, 'max_lat': 5.0, 'min_lon': -75.0, 'max_lon': -44.0},
            'Nordeste': {'min_lat': -18.0, 'max_lat': -2.0, 'min_lon': -48.0, 'max_lon': -34.0},
            'Centro-Oeste': {'min_lat': -24.0, 'max_lat': -7.0, 'min_lon': -62.0, 'max_lon': -46.0},
            'Sudeste': {'min_lat': -25.0, 'max_lat': -14.0, 'min_lon': -53.0, 'max_lon': -39.0},
            'Sul': {'min_lat': -33.0, 'max_lat': -22.0, 'min_lon': -58.0, 'max_lon': -48.0}
        }
        
    def _initialize_spatial_patterns(self):
        """Initialize spatial pattern recognition."""
        # Geographic keywords for extraction
        self.geographic_keywords = {
            'municipalities': [
                'município', 'municípios', 'prefeitura', 'cidade', 'cidades',
                'localidade', 'distrito', 'vila', 'povoado'
            ],
            'states': [
                'estado', 'estados', 'unidade federativa', 'UF', 'governo estadual',
                'administração estadual'
            ],
            'regions': [
                'região', 'regiões', 'macro-região', 'microrregião', 'bacia',
                'vale', 'serra', 'chapada', 'planalto'
            ],
            'infrastructure': [
                'rodovia', 'estrada', 'BR-', 'km', 'quilômetro', 'porto', 'aeroporto',
                'ferrovia', 'linha férrea', 'estação', 'terminal'
            ],
            'administrative': [
                'federal', 'estadual', 'municipal', 'distrital', 'regional',
                'nacional', 'local', 'territorial'
            ]
        }
        
        # Jurisdiction indicators
        self.jurisdiction_patterns = {
            'federal': ['união', 'federal', 'nacional', 'república federativa'],
            'estadual': ['estado', 'estadual', 'governo do estado', 'administração estadual'],
            'municipal': ['município', 'municipal', 'prefeitura', 'câmara municipal'],
            'regional': ['região', 'regional', 'consórcio', 'região metropolitana']
        }
        
    async def analyze_document_spatial_context(self, document: LegislativeDocument) -> DocumentSpatialAnalysis:
        """Analyze spatial context of a legislative document."""
        try:
            logger.info(f"Analyzing spatial context for document {document.id}")
            
            # Extract geographic references
            extracted_locations = await self._extract_geographic_references(document)
            
            # Determine primary location
            primary_location = self._determine_primary_location(extracted_locations, document)
            
            # Classify jurisdiction level
            jurisdiction_level = self._classify_jurisdiction_level(document)
            
            # Determine coverage area
            coverage_area = self._determine_coverage_area(document, extracted_locations)
            
            # Extract spatial keywords
            spatial_keywords = self._extract_spatial_keywords(document)
            
            # Determine geographic scope
            geographic_scope = self._determine_geographic_scope(extracted_locations, document)
            
            # Find related locations
            related_locations = await self._find_related_locations(primary_location, extracted_locations)
            
            # Calculate confidence score
            confidence_score = self._calculate_spatial_confidence(
                extracted_locations, primary_location, spatial_keywords
            )
            
            return DocumentSpatialAnalysis(
                document_id=document.id,
                extracted_locations=extracted_locations,
                primary_location=primary_location,
                jurisdiction_level=jurisdiction_level,
                coverage_area=coverage_area,
                spatial_keywords=spatial_keywords,
                geographic_scope=geographic_scope,
                related_locations=related_locations,
                confidence_score=confidence_score
            )
            
        except Exception as e:
            logger.error(f"Error analyzing spatial context: {str(e)}")
            raise
            
    async def _extract_geographic_references(self, document: LegislativeDocument) -> List[GeoLocation]:
        """Extract geographic references from document text."""
        locations = []
        text_content = f"{document.title} {document.summary}"
        
        # Extract Brazilian state names and codes
        for state_code, state_info in self.brazilian_states.items():
            state_name = state_info['name']
            if state_name.lower() in text_content.lower() or state_code in text_content:
                # Get state capital coordinates
                capital = state_info['capital']
                if capital in self.major_municipalities:
                    coord = self.major_municipalities[capital]
                    location = GeoLocation(
                        latitude=coord['lat'],
                        longitude=coord['lon'],
                        municipality=capital,
                        state=state_name,
                        state_code=state_code,
                        region=state_info['region'],
                        ibge_code=f"state_{state_code}",
                        confidence=0.8
                    )
                    locations.append(location)
        
        # Extract major municipality names
        for city_name, city_info in self.major_municipalities.items():
            if city_name.lower() in text_content.lower():
                state_code = city_info['state']
                state_info = self.brazilian_states[state_code]
                location = GeoLocation(
                    latitude=city_info['lat'],
                    longitude=city_info['lon'],
                    municipality=city_name,
                    state=state_info['name'],
                    state_code=state_code,
                    region=state_info['region'],
                    ibge_code=f"city_{city_name.replace(' ', '_')}",
                    population=city_info.get('population'),
                    confidence=0.9
                )
                locations.append(location)
        
        # Extract road references (BR-XXX patterns)
        road_pattern = r'BR-?\s*(\d{2,3})'
        roads = re.findall(road_pattern, text_content, re.IGNORECASE)
        for road_number in roads:
            # Estimate location based on major federal highways
            estimated_location = self._estimate_highway_location(f"BR-{road_number}")
            if estimated_location:
                locations.append(estimated_location)
        
        # Extract port and airport references
        infrastructure_locations = await self._extract_infrastructure_references(text_content)
        locations.extend(infrastructure_locations)
        
        return locations
    
    def _estimate_highway_location(self, highway_code: str) -> Optional[GeoLocation]:
        """Estimate location for major Brazilian highways."""
        # Major highways with approximate central coordinates
        highway_coords = {
            'BR-101': {'lat': -15.0, 'lon': -40.0, 'states': ['BA', 'ES', 'RJ', 'SP', 'PR', 'SC', 'RS']},
            'BR-116': {'lat': -20.0, 'lon': -43.0, 'states': ['CE', 'PE', 'BA', 'MG', 'RJ', 'SP', 'PR', 'RS']},
            'BR-153': {'lat': -15.0, 'lon': -50.0, 'states': ['PA', 'TO', 'GO', 'MG', 'SP', 'PR']},
            'BR-230': {'lat': -7.0, 'lon': -55.0, 'states': ['PB', 'CE', 'PI', 'MA', 'TO', 'PA', 'AM']},
            'BR-364': {'lat': -12.0, 'lon': -60.0, 'states': ['SP', 'MT', 'RO', 'AC']},
            'BR-040': {'lat': -18.0, 'lon': -47.0, 'states': ['DF', 'GO', 'MG', 'RJ']},
            'BR-262': {'lat': -20.0, 'lon': -50.0, 'states': ['ES', 'MG', 'SP', 'MS']},
            'BR-319': {'lat': -7.0, 'lon': -62.0, 'states': ['AM', 'RO']}
        }
        
        highway_info = highway_coords.get(highway_code)
        if highway_info:
            # Use the first state as primary reference
            primary_state = highway_info['states'][0]
            state_info = self.brazilian_states.get(primary_state)
            if state_info:
                return GeoLocation(
                    latitude=highway_info['lat'],
                    longitude=highway_info['lon'],
                    municipality=f"Rodovia {highway_code}",
                    state=state_info['name'],
                    state_code=primary_state,
                    region=state_info['region'],
                    ibge_code=f"highway_{highway_code.replace('-', '_')}",
                    confidence=0.6
                )
        return None
    
    async def _extract_infrastructure_references(self, text: str) -> List[GeoLocation]:
        """Extract references to ports, airports, and major infrastructure."""
        locations = []
        
        # Major Brazilian ports
        ports = {
            'Porto de Santos': {'lat': -23.9618, 'lon': -46.3322, 'state': 'SP'},
            'Porto de Paranaguá': {'lat': -25.5163, 'lon': -48.5234, 'state': 'PR'},
            'Porto de Rio Grande': {'lat': -32.0350, 'lon': -52.0986, 'state': 'RS'},
            'Porto de Itaguaí': {'lat': -22.8526, 'lon': -43.7751, 'state': 'RJ'},
            'Porto de Suape': {'lat': -8.3544, 'lon': -34.9608, 'state': 'PE'},
            'Porto de Salvador': {'lat': -12.9777, 'lon': -38.5016, 'state': 'BA'},
            'Porto de Vitória': {'lat': -20.3155, 'lon': -40.3128, 'state': 'ES'},
            'Porto de Manaus': {'lat': -3.1190, 'lon': -60.0217, 'state': 'AM'}
        }
        
        # Major Brazilian airports
        airports = {
            'Aeroporto de Guarulhos': {'lat': -23.4356, 'lon': -46.4731, 'state': 'SP'},
            'Aeroporto de Congonhas': {'lat': -23.6261, 'lon': -46.6565, 'state': 'SP'},
            'Aeroporto do Galeão': {'lat': -22.8099, 'lon': -43.2505, 'state': 'RJ'},
            'Aeroporto de Brasília': {'lat': -15.8711, 'lon': -47.9175, 'state': 'DF'},
            'Aeroporto de Confins': {'lat': -19.6244, 'lon': -43.9686, 'state': 'MG'},
            'Aeroporto de Salvador': {'lat': -12.9108, 'lon': -38.3189, 'state': 'BA'},
            'Aeroporto de Recife': {'lat': -8.1263, 'lon': -34.9236, 'state': 'PE'},
            'Aeroporto de Fortaleza': {'lat': -3.7763, 'lon': -38.5326, 'state': 'CE'}
        }
        
        # Check for port references
        for port_name, port_info in ports.items():
            if any(term in text.lower() for term in [port_name.lower(), port_name.split()[-1].lower()]):
                state_code = port_info['state']
                state_info = self.brazilian_states[state_code]
                location = GeoLocation(
                    latitude=port_info['lat'],
                    longitude=port_info['lon'],
                    municipality=port_name,
                    state=state_info['name'],
                    state_code=state_code,
                    region=state_info['region'],
                    ibge_code=f"port_{port_name.replace(' ', '_').lower()}",
                    confidence=0.8
                )
                locations.append(location)
        
        # Check for airport references
        for airport_name, airport_info in airports.items():
            if any(term in text.lower() for term in [airport_name.lower(), 'aeroporto']):
                state_code = airport_info['state']
                state_info = self.brazilian_states[state_code]
                location = GeoLocation(
                    latitude=airport_info['lat'],
                    longitude=airport_info['lon'],
                    municipality=airport_name,
                    state=state_info['name'],
                    state_code=state_code,
                    region=state_info['region'],
                    ibge_code=f"airport_{airport_name.replace(' ', '_').lower()}",
                    confidence=0.8
                )
                locations.append(location)
        
        return locations
    
    def _determine_primary_location(self, locations: List[GeoLocation], document: LegislativeDocument) -> Optional[GeoLocation]:
        """Determine the primary geographic location for a document."""
        if not locations:
            return None
        
        # Score locations based on various factors
        scored_locations = []
        for location in locations:
            score = location.confidence
            
            # Boost score for state capitals
            if location.municipality in [info['capital'] for info in self.brazilian_states.values()]:
                score += 0.2
            
            # Boost score for major cities
            if location.population and location.population > 1000000:
                score += 0.1
            
            # Boost score if mentioned in title
            if location.municipality.lower() in document.title.lower():
                score += 0.3
            
            # Boost score if state is mentioned
            if location.state.lower() in document.title.lower():
                score += 0.2
            
            scored_locations.append((location, score))
        
        # Return location with highest score
        scored_locations.sort(key=lambda x: x[1], reverse=True)
        return scored_locations[0][0]
    
    def _classify_jurisdiction_level(self, document: LegislativeDocument) -> str:
        """Classify the jurisdiction level of a document."""
        text_content = f"{document.title} {document.summary}".lower()
        
        # Check for jurisdiction indicators
        for level, patterns in self.jurisdiction_patterns.items():
            if any(pattern in text_content for pattern in patterns):
                return level
        
        # Check document source
        fonte = getattr(document, 'fonte', '').lower()
        if 'federal' in fonte or 'união' in fonte:
            return 'federal'
        elif 'estadual' in fonte or 'estado' in fonte:
            return 'estadual'
        elif 'municipal' in fonte or 'prefeitura' in fonte:
            return 'municipal'
        
        # Default based on document type
        tipo_doc = getattr(document, 'tipo_documento', '').lower()
        if tipo_doc in ['lei federal', 'decreto federal', 'medida provisória']:
            return 'federal'
        elif tipo_doc in ['lei estadual', 'decreto estadual']:
            return 'estadual'
        elif tipo_doc in ['lei municipal', 'decreto municipal']:
            return 'municipal'
        
        return 'federal'  # Default
    
    def _determine_coverage_area(self, document: LegislativeDocument, locations: List[GeoLocation]) -> List[str]:
        """Determine the geographic coverage area of a document."""
        coverage = []
        
        # Extract states from locations
        states = list(set(loc.state for loc in locations))
        coverage.extend(states)
        
        # Extract municipalities
        municipalities = list(set(loc.municipality for loc in locations if loc.municipality not in states))
        coverage.extend(municipalities)
        
        # Check for national scope indicators
        text_content = f"{document.title} {document.summary}".lower()
        national_indicators = ['nacional', 'território nacional', 'todo o país', 'união']
        if any(indicator in text_content for indicator in national_indicators):
            coverage.append('Nacional')
        
        return coverage
    
    def _extract_spatial_keywords(self, document: LegislativeDocument) -> List[str]:
        """Extract spatial keywords from document."""
        keywords = []
        text_content = f"{document.title} {document.summary}".lower()
        
        for category, terms in self.geographic_keywords.items():
            for term in terms:
                if term in text_content:
                    keywords.append(term)
        
        return list(set(keywords))
    
    def _determine_geographic_scope(self, locations: List[GeoLocation], document: LegislativeDocument) -> str:
        """Determine the geographic scope of the document."""
        if not locations:
            return 'nacional'
        
        regions = set(loc.region for loc in locations)
        states = set(loc.state for loc in locations)
        
        if len(regions) >= 3:
            return 'nacional'
        elif len(regions) == 2:
            return 'regional'
        elif len(states) > 1:
            return 'multi-estadual'
        elif len(states) == 1:
            if len(locations) > 1:
                return 'estadual'
            else:
                return 'municipal'
        else:
            return 'local'
    
    async def _find_related_locations(self, primary_location: Optional[GeoLocation], 
                                     extracted_locations: List[GeoLocation]) -> List[GeoLocation]:
        """Find locations related to the primary location."""
        if not primary_location:
            return []
        
        related = []
        
        # Find locations in the same state
        same_state = [loc for loc in extracted_locations 
                     if loc.state == primary_location.state and loc != primary_location]
        related.extend(same_state)
        
        # Find locations in the same region
        same_region = [loc for loc in extracted_locations 
                      if loc.region == primary_location.region and loc.state != primary_location.state]
        related.extend(same_region)
        
        return related
    
    def _calculate_spatial_confidence(self, locations: List[GeoLocation], 
                                    primary_location: Optional[GeoLocation], 
                                    keywords: List[str]) -> float:
        """Calculate confidence score for spatial analysis."""
        score = 0.0
        
        # Base score from number of locations
        if locations:
            score += min(len(locations) * 0.1, 0.5)
        
        # Boost for primary location
        if primary_location:
            score += primary_location.confidence * 0.3
        
        # Boost for spatial keywords
        score += min(len(keywords) * 0.05, 0.2)
        
        # Ensure score is between 0 and 1
        return min(max(score, 0.0), 1.0)
    
    async def find_spatial_clusters(self, documents: List[LegislativeDocument], 
                                  max_distance_km: float = 100.0) -> List[SpatialCluster]:
        """Find spatial clusters of documents based on geographic proximity."""
        try:
            logger.info(f"Finding spatial clusters for {len(documents)} documents")
            
            # Analyze spatial context for all documents
            document_analyses = []
            for doc in documents:
                analysis = await self.analyze_document_spatial_context(doc)
                if analysis.primary_location:
                    document_analyses.append(analysis)
            
            # Group documents by proximity
            clusters = []
            processed_docs = set()
            
            for i, analysis in enumerate(document_analyses):
                if analysis.document_id in processed_docs:
                    continue
                
                cluster_docs = [analysis.document_id]
                cluster_locations = [analysis.primary_location]
                processed_docs.add(analysis.document_id)
                
                # Find nearby documents
                for j, other_analysis in enumerate(document_analyses[i+1:], i+1):
                    if other_analysis.document_id in processed_docs:
                        continue
                    
                    distance = geodesic(
                        (analysis.primary_location.latitude, analysis.primary_location.longitude),
                        (other_analysis.primary_location.latitude, other_analysis.primary_location.longitude)
                    ).kilometers
                    
                    if distance <= max_distance_km:
                        cluster_docs.append(other_analysis.document_id)
                        cluster_locations.append(other_analysis.primary_location)
                        processed_docs.add(other_analysis.document_id)
                
                # Create cluster if multiple documents
                if len(cluster_docs) >= 2:
                    centroid = self._calculate_centroid(cluster_locations)
                    max_distance = max(
                        geodesic((centroid.latitude, centroid.longitude),
                               (loc.latitude, loc.longitude)).kilometers
                        for loc in cluster_locations
                    )
                    
                    cluster = SpatialCluster(
                        cluster_id=f"cluster_{len(clusters)+1}",
                        centroid=centroid,
                        documents=cluster_docs,
                        radius_km=max_distance,
                        document_count=len(cluster_docs),
                        themes=self._extract_cluster_themes(cluster_docs, documents),
                        temporal_span=self._calculate_temporal_span(cluster_docs, documents),
                        regulatory_density=len(cluster_docs) / (max_distance ** 2) if max_distance > 0 else 0,
                        cluster_strength=self._calculate_cluster_strength(cluster_locations)
                    )
                    clusters.append(cluster)
            
            return clusters
            
        except Exception as e:
            logger.error(f"Error finding spatial clusters: {str(e)}")
            raise
    
    def _calculate_centroid(self, locations: List[GeoLocation]) -> GeoLocation:
        """Calculate the centroid of a list of geographic locations."""
        if not locations:
            raise ValueError("Cannot calculate centroid of empty location list")
        
        avg_lat = sum(loc.latitude for loc in locations) / len(locations)
        avg_lon = sum(loc.longitude for loc in locations) / len(locations)
        
        # Use the most common state/region for the centroid
        states = [loc.state for loc in locations]
        regions = [loc.region for loc in locations]
        
        most_common_state = Counter(states).most_common(1)[0][0]
        most_common_region = Counter(regions).most_common(1)[0][0]
        
        # Find state code
        state_code = None
        for code, info in self.brazilian_states.items():
            if info['name'] == most_common_state:
                state_code = code
                break
        
        return GeoLocation(
            latitude=avg_lat,
            longitude=avg_lon,
            municipality=f"Centroide ({len(locations)} locais)",
            state=most_common_state,
            state_code=state_code or 'XX',
            region=most_common_region,
            ibge_code=f"centroid_{len(locations)}",
            confidence=0.8
        )
    
    def _extract_cluster_themes(self, doc_ids: List[str], documents: List[LegislativeDocument]) -> List[str]:
        """Extract common themes from clustered documents."""
        cluster_docs = [doc for doc in documents if doc.id in doc_ids]
        
        # Extract keywords from titles and summaries
        all_text = ' '.join(f"{doc.title} {doc.summary}" for doc in cluster_docs).lower()
        
        # Common legislative themes
        themes = []
        theme_keywords = {
            'transporte': ['transporte', 'trânsito', 'veículo', 'rodovia', 'estrada'],
            'meio ambiente': ['ambiental', 'meio ambiente', 'sustentabilidade', 'preservação'],
            'energia': ['energia', 'elétrica', 'combustível', 'petróleo'],
            'saúde': ['saúde', 'hospital', 'médico', 'tratamento'],
            'educação': ['educação', 'escola', 'ensino', 'universidade'],
            'segurança': ['segurança', 'polícia', 'crime', 'violência'],
            'economia': ['economia', 'financeiro', 'investimento', 'desenvolvimento'],
            'infraestrutura': ['infraestrutura', 'obra', 'construção', 'projeto']
        }
        
        for theme, keywords in theme_keywords.items():
            if any(keyword in all_text for keyword in keywords):
                themes.append(theme)
        
        return themes
    
    def _calculate_temporal_span(self, doc_ids: List[str], documents: List[LegislativeDocument]) -> Tuple[str, str]:
        """Calculate the temporal span of clustered documents."""
        cluster_docs = [doc for doc in documents if doc.id in doc_ids]
        
        dates = []
        for doc in cluster_docs:
            if hasattr(doc, 'data_evento') and doc.data_evento:
                dates.append(doc.data_evento)
            elif hasattr(doc, 'data_publicacao') and doc.data_publicacao:
                dates.append(doc.data_publicacao)
        
        if dates:
            dates.sort()
            return (dates[0], dates[-1])
        else:
            return ('', '')
    
    def _calculate_cluster_strength(self, locations: List[GeoLocation]) -> float:
        """Calculate the strength/cohesion of a spatial cluster."""
        if len(locations) < 2:
            return 0.0
        
        # Calculate average distance between all pairs
        total_distance = 0
        pair_count = 0
        
        for i in range(len(locations)):
            for j in range(i + 1, len(locations)):
                distance = geodesic(
                    (locations[i].latitude, locations[i].longitude),
                    (locations[j].latitude, locations[j].longitude)
                ).kilometers
                total_distance += distance
                pair_count += 1
        
        avg_distance = total_distance / pair_count if pair_count > 0 else 0
        
        # Strength is inversely related to average distance
        # Normalize to 0-1 scale where smaller average distance = higher strength
        max_expected_distance = 500  # km
        strength = max(0, 1 - (avg_distance / max_expected_distance))
        
        return strength
    
    async def analyze_spatial_relationships(self, documents: List[LegislativeDocument]) -> List[SpatialRelationship]:
        """Analyze spatial relationships between documents."""
        try:
            logger.info(f"Analyzing spatial relationships for {len(documents)} documents")
            
            relationships = []
            
            # Analyze all document pairs
            for i in range(len(documents)):
                for j in range(i + 1, len(documents)):
                    doc1, doc2 = documents[i], documents[j]
                    
                    # Get spatial analyses
                    analysis1 = await self.analyze_document_spatial_context(doc1)
                    analysis2 = await self.analyze_document_spatial_context(doc2)
                    
                    if analysis1.primary_location and analysis2.primary_location:
                        relationship = await self._analyze_document_pair_relationship(
                            doc1, doc2, analysis1, analysis2
                        )
                        if relationship:
                            relationships.append(relationship)
            
            return relationships
            
        except Exception as e:
            logger.error(f"Error analyzing spatial relationships: {str(e)}")
            raise
    
    async def _analyze_document_pair_relationship(self, doc1: LegislativeDocument, doc2: LegislativeDocument,
                                                analysis1: DocumentSpatialAnalysis, 
                                                analysis2: DocumentSpatialAnalysis) -> Optional[SpatialRelationship]:
        """Analyze relationship between a pair of documents."""
        loc1 = analysis1.primary_location
        loc2 = analysis2.primary_location
        
        if not loc1 or not loc2:
            return None
        
        # Calculate distance
        distance = geodesic(
            (loc1.latitude, loc1.longitude),
            (loc2.latitude, loc2.longitude)
        ).kilometers
        
        # Determine relationship type
        relationship_type = 'distant'
        if loc1.municipality == loc2.municipality:
            relationship_type = 'same_municipality'
        elif loc1.state == loc2.state:
            relationship_type = 'same_state'
        elif loc1.region == loc2.region:
            relationship_type = 'same_region'
        elif distance <= 50:
            relationship_type = 'adjacent'
        
        # Find shared locations
        shared_locations = []
        for loc_a in analysis1.extracted_locations:
            for loc_b in analysis2.extracted_locations:
                if loc_a.municipality == loc_b.municipality:
                    shared_locations.append(loc_a.municipality)
        
        # Calculate correlation strength
        correlation_strength = self._calculate_correlation_strength(
            analysis1, analysis2, distance, shared_locations
        )
        
        # Check temporal overlap
        temporal_overlap = self._check_temporal_overlap(doc1, doc2)
        
        return SpatialRelationship(
            document1_id=doc1.id,
            document2_id=doc2.id,
            relationship_type=relationship_type,
            distance_km=distance,
            shared_locations=shared_locations,
            correlation_strength=correlation_strength,
            temporal_overlap=temporal_overlap
        )
    
    def _calculate_correlation_strength(self, analysis1: DocumentSpatialAnalysis, 
                                      analysis2: DocumentSpatialAnalysis, 
                                      distance: float, shared_locations: List[str]) -> float:
        """Calculate correlation strength between two documents."""
        strength = 0.0
        
        # Distance factor (closer = stronger)
        if distance <= 10:
            strength += 0.4
        elif distance <= 50:
            strength += 0.3
        elif distance <= 100:
            strength += 0.2
        elif distance <= 500:
            strength += 0.1
        
        # Shared locations factor
        strength += min(len(shared_locations) * 0.2, 0.3)
        
        # Same jurisdiction level
        if analysis1.jurisdiction_level == analysis2.jurisdiction_level:
            strength += 0.1
        
        # Shared keywords
        shared_keywords = set(analysis1.spatial_keywords) & set(analysis2.spatial_keywords)
        strength += min(len(shared_keywords) * 0.05, 0.2)
        
        return min(strength, 1.0)
    
    def _check_temporal_overlap(self, doc1: LegislativeDocument, doc2: LegislativeDocument) -> bool:
        """Check if two documents have temporal overlap."""
        date1 = getattr(doc1, 'data_evento', None) or getattr(doc1, 'data_publicacao', None)
        date2 = getattr(doc2, 'data_evento', None) or getattr(doc2, 'data_publicacao', None)
        
        if not date1 or not date2:
            return False
        
        try:
            # Simple year-based comparison
            year1 = int(date1[:4]) if len(date1) >= 4 else 0
            year2 = int(date2[:4]) if len(date2) >= 4 else 0
            
            return abs(year1 - year2) <= 2  # Within 2 years
        except (ValueError, TypeError):
            return False
    
    async def reverse_geocode_location(self, latitude: float, longitude: float) -> Optional[GeoLocation]:
        """Reverse geocode coordinates to get location information."""
        try:
            # Use geocoding service
            location = await asyncio.get_event_loop().run_in_executor(
                None, self.geocoder.reverse, f"{latitude}, {longitude}"
            )
            
            if location and location.raw:
                address = location.raw.get('address', {})
                
                # Extract Brazilian location components
                municipality = (address.get('city') or 
                              address.get('town') or 
                              address.get('municipality') or 
                              address.get('village', ''))
                
                state = address.get('state', '')
                
                # Find state code
                state_code = None
                for code, info in self.brazilian_states.items():
                    if info['name'].lower() == state.lower():
                        state_code = code
                        break
                
                if state_code:
                    return GeoLocation(
                        latitude=latitude,
                        longitude=longitude,
                        municipality=municipality,
                        state=state,
                        state_code=state_code,
                        region=self.brazilian_states[state_code]['region'],
                        ibge_code=f"reverse_{latitude}_{longitude}",
                        confidence=0.8
                    )
            
            return None
            
        except Exception as e:
            logger.warning(f"Reverse geocoding failed: {str(e)}")
            return None