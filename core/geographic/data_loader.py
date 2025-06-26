"""
Brazilian geographic data loader for Monitor Legislativo v4
Loads and processes municipality data from datasets-br/city-codes
"""

import json
import csv
import asyncio
from pathlib import Path
from typing import List, Dict, Optional
import logging

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

from .models import BrazilianMunicipality, BrazilianRegion, BRAZILIAN_STATES

logger = logging.getLogger(__name__)


class BrazilianGeographicDataLoader:
    """
    Loads Brazilian municipality data from datasets-br/city-codes repository
    Provides fallback mechanisms and data validation
    """
    
    # GitHub raw URL for datasets-br/city-codes
    GITHUB_RAW_BASE = "https://raw.githubusercontent.com/datasets-br/city-codes/master/"
    
    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or Path(__file__).parent.parent.parent / "data" / "geographic"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Cache for loaded data
        self._municipalities_cache: Optional[List[BrazilianMunicipality]] = None
        self._municipalities_by_ibge: Optional[Dict[str, BrazilianMunicipality]] = None
        self._municipalities_by_name: Optional[Dict[str, List[BrazilianMunicipality]]] = None
    
    async def load_municipalities(self, force_refresh: bool = False) -> List[BrazilianMunicipality]:
        """
        Load Brazilian municipalities data
        
        Args:
            force_refresh: Force download from GitHub even if local cache exists
            
        Returns:
            List of BrazilianMunicipality objects
        """
        if self._municipalities_cache and not force_refresh:
            return self._municipalities_cache
        
        # Try to load from local sample file first
        sample_file = self.data_dir / "sample_municipalities.csv"
        if sample_file.exists():
            try:
                municipalities = await self._load_from_sample_csv(sample_file)
                if municipalities:
                    self._municipalities_cache = municipalities
                    self._build_lookup_indices()
                    logger.info(f"Loaded {len(municipalities)} municipalities from sample CSV")
                    return municipalities
            except Exception as e:
                logger.warning(f"Failed to load from sample CSV: {e}")
        
        # Try to load from local cache
        local_file = self.data_dir / "brazilian_municipalities.json"
        if local_file.exists() and not force_refresh:
            try:
                municipalities = await self._load_from_local_file(local_file)
                if municipalities:
                    self._municipalities_cache = municipalities
                    self._build_lookup_indices()
                    logger.info(f"Loaded {len(municipalities)} municipalities from local cache")
                    return municipalities
            except Exception as e:
                logger.warning(f"Failed to load from local cache: {e}")
        
        # Download from GitHub if aiohttp is available and force refresh
        if AIOHTTP_AVAILABLE and force_refresh:
            try:
                municipalities = await self._download_from_github()
                if municipalities:
                    # Save to local cache
                    await self._save_to_local_file(local_file, municipalities)
                    self._municipalities_cache = municipalities
                    self._build_lookup_indices()
                    logger.info(f"Downloaded and cached {len(municipalities)} municipalities")
                    return municipalities
            except Exception as e:
                logger.error(f"Failed to download from GitHub: {e}")
        
        # Final fallback: use embedded sample data
        municipalities = self._get_fallback_data()
        self._municipalities_cache = municipalities
        self._build_lookup_indices()
        logger.warning(f"Using fallback data with {len(municipalities)} municipalities")
        return municipalities
    
    async def _load_from_sample_csv(self, file_path: Path) -> List[BrazilianMunicipality]:
        """Load municipalities from local sample CSV file"""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return self._parse_csv_content(content)
    
    async def _download_from_github(self) -> List[BrazilianMunicipality]:
        """Download municipality data from datasets-br/city-codes GitHub repository"""
        if not AIOHTTP_AVAILABLE:
            raise Exception("aiohttp not available for downloading")
        
        from urllib.parse import urljoin
        url = urljoin(self.GITHUB_RAW_BASE, "data/municipalities.csv")
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status != 200:
                    raise Exception(f"HTTP {response.status} when downloading from {url}")
                
                content = await response.text()
                return self._parse_csv_content(content)
    
    def _parse_csv_content(self, csv_content: str) -> List[BrazilianMunicipality]:
        """Parse CSV content and convert to BrazilianMunicipality objects"""
        municipalities = []
        csv_reader = csv.DictReader(csv_content.splitlines())
        
        for row in csv_reader:
            try:
                # Extract state info
                state_code = row.get('state', '').upper()
                if state_code not in BRAZILIAN_STATES:
                    logger.warning(f"Unknown state code: {state_code}")
                    continue
                
                state_info = BRAZILIAN_STATES[state_code]
                
                # Parse coordinates
                latitude = None
                longitude = None
                try:
                    if row.get('latitude'):
                        latitude = float(row['latitude'])
                    if row.get('longitude'):
                        longitude = float(row['longitude'])
                except (ValueError, TypeError):
                    pass
                
                # Parse population and area
                population = None
                area_km2 = None
                try:
                    if row.get('population'):
                        population = int(row['population'])
                    if row.get('area_km2'):
                        area_km2 = float(row['area_km2'])
                except (ValueError, TypeError):
                    pass
                
                municipality = BrazilianMunicipality(
                    name=row.get('name', '').strip(),
                    state=state_code,
                    state_name=state_info['name'],
                    region=state_info['region'],
                    ibge_code=row.get('ibge_code', '').strip(),
                    latitude=latitude,
                    longitude=longitude,
                    tse_code=row.get('tse_code', '').strip() or None,
                    anatel_code=row.get('anatel_code', '').strip() or None,
                    siafi_code=row.get('siafi_code', '').strip() or None,
                    population=population,
                    area_km2=area_km2
                )
                
                municipalities.append(municipality)
                
            except Exception as e:
                logger.warning(f"Failed to parse municipality row: {row}, error: {e}")
                continue
        
        return municipalities
    
    async def _load_from_local_file(self, file_path: Path) -> List[BrazilianMunicipality]:
        """Load municipalities from local JSON file"""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        municipalities = []
        for item in data:
            try:
                # Convert region string back to enum
                region = BrazilianRegion(item['region'])
                
                municipality = BrazilianMunicipality(
                    name=item['name'],
                    state=item['state'],
                    state_name=item['state_name'],
                    region=region,
                    ibge_code=item['ibge_code'],
                    latitude=item.get('latitude'),
                    longitude=item.get('longitude'),
                    tse_code=item.get('tse_code'),
                    anatel_code=item.get('anatel_code'),
                    siafi_code=item.get('siafi_code'),
                    population=item.get('population'),
                    area_km2=item.get('area_km2')
                )
                municipalities.append(municipality)
            except Exception as e:
                logger.warning(f"Failed to parse cached municipality: {item}, error: {e}")
                continue
        
        return municipalities
    
    async def _save_to_local_file(self, file_path: Path, municipalities: List[BrazilianMunicipality]):
        """Save municipalities to local JSON file"""
        data = [m.to_dict() for m in municipalities]
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    
    def _get_fallback_data(self) -> List[BrazilianMunicipality]:
        """
        Provide fallback municipality data for critical municipalities
        This ensures the system works even without external data sources
        """
        fallback_municipalities = [
            # Federal District
            BrazilianMunicipality(
                name="Brasília",
                state="DF",
                state_name="Distrito Federal",
                region=BrazilianRegion.CENTRO_OESTE,
                ibge_code="5300108",
                latitude=-15.7942,
                longitude=-47.8822
            ),
            # State capitals
            BrazilianMunicipality(
                name="São Paulo",
                state="SP",
                state_name="São Paulo",
                region=BrazilianRegion.SUDESTE,
                ibge_code="3550308",
                latitude=-23.5505,
                longitude=-46.6333
            ),
            BrazilianMunicipality(
                name="Rio de Janeiro",
                state="RJ",
                state_name="Rio de Janeiro",
                region=BrazilianRegion.SUDESTE,
                ibge_code="3304557",
                latitude=-22.9068,
                longitude=-43.1729
            ),
            BrazilianMunicipality(
                name="Belo Horizonte",
                state="MG",
                state_name="Minas Gerais",
                region=BrazilianRegion.SUDESTE,
                ibge_code="3106200",
                latitude=-19.9167,
                longitude=-43.9345
            ),
            BrazilianMunicipality(
                name="Salvador",
                state="BA",
                state_name="Bahia",
                region=BrazilianRegion.NORDESTE,
                ibge_code="2927408",
                latitude=-12.9714,
                longitude=-38.5014
            ),
            BrazilianMunicipality(
                name="Fortaleza",
                state="CE",
                state_name="Ceará",
                region=BrazilianRegion.NORDESTE,
                ibge_code="2304400",
                latitude=-3.7319,
                longitude=-38.5267
            ),
            BrazilianMunicipality(
                name="Manaus",
                state="AM",
                state_name="Amazonas",
                region=BrazilianRegion.NORTE,
                ibge_code="1302603",
                latitude=-3.1190,
                longitude=-60.0217
            ),
            BrazilianMunicipality(
                name="Curitiba",
                state="PR",
                state_name="Paraná",
                region=BrazilianRegion.SUL,
                ibge_code="4106902",
                latitude=-25.4244,
                longitude=-49.2654
            ),
            BrazilianMunicipality(
                name="Porto Alegre",
                state="RS",
                state_name="Rio Grande do Sul",
                region=BrazilianRegion.SUL,
                ibge_code="4314902",
                latitude=-30.0346,
                longitude=-51.2177
            ),
            BrazilianMunicipality(
                name="Goiânia",
                state="GO",
                state_name="Goiás",
                region=BrazilianRegion.CENTRO_OESTE,
                ibge_code="5208707",
                latitude=-16.6869,
                longitude=-49.2648
            )
        ]
        
        return fallback_municipalities
    
    def _build_lookup_indices(self):
        """Build lookup indices for fast searching"""
        if not self._municipalities_cache:
            return
        
        # Index by IBGE code
        self._municipalities_by_ibge = {
            m.ibge_code: m for m in self._municipalities_cache if m.ibge_code
        }
        
        # Index by name (can have multiple municipalities with same name)
        self._municipalities_by_name = {}
        for municipality in self._municipalities_cache:
            name_key = municipality.name.lower().strip()
            if name_key not in self._municipalities_by_name:
                self._municipalities_by_name[name_key] = []
            self._municipalities_by_name[name_key].append(municipality)
    
    def get_municipality_by_ibge_code(self, ibge_code: str) -> Optional[BrazilianMunicipality]:
        """Get municipality by IBGE code"""
        if not self._municipalities_by_ibge:
            return None
        return self._municipalities_by_ibge.get(ibge_code)
    
    def search_municipalities_by_name(self, name: str) -> List[BrazilianMunicipality]:
        """Search municipalities by name (case-insensitive)"""
        if not self._municipalities_by_name:
            return []
        
        name_key = name.lower().strip()
        return self._municipalities_by_name.get(name_key, [])
    
    def get_municipalities_by_state(self, state_code: str) -> List[BrazilianMunicipality]:
        """Get all municipalities in a state"""
        if not self._municipalities_cache:
            return []
        
        return [m for m in self._municipalities_cache if m.state == state_code.upper()]
    
    def get_municipalities_by_region(self, region: BrazilianRegion) -> List[BrazilianMunicipality]:
        """Get all municipalities in a region"""
        if not self._municipalities_cache:
            return []
        
        return [m for m in self._municipalities_cache if m.region == region]
    
    async def get_statistics(self) -> Dict[str, int]:
        """Get statistics about loaded municipality data"""
        municipalities = await self.load_municipalities()
        
        stats = {
            'total_municipalities': len(municipalities),
            'municipalities_with_coordinates': len([m for m in municipalities if m.coordinates]),
            'municipalities_with_population': len([m for m in municipalities if m.population]),
        }
        
        # Count by region
        for region in BrazilianRegion:
            count = len([m for m in municipalities if m.region == region])
            stats[f'municipalities_{region.value.lower().replace("-", "_")}'] = count
        
        # Count by state
        for state_code in BRAZILIAN_STATES:
            count = len([m for m in municipalities if m.state == state_code])
            stats[f'municipalities_{state_code.lower()}'] = count
        
        return stats