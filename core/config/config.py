"""
Configuration settings for Monitor Legislativo
"""

import os
from typing import Dict, List, Any
from dataclasses import dataclass


@dataclass
class APIConfig:
    """Configuration for an individual API source"""
    name: str
    base_url: str
    enabled: bool = True
    timeout: int = 30
    retry_count: int = 3
    cache_ttl: int = 3600  # 1 hour
    headers: Dict[str, str] = None
    
    def __post_init__(self):
        if self.headers is None:
            self.headers = {}


class Config:
    """Central configuration for Monitor Legislativo"""
    
    # Application settings
    APP_NAME = "Monitor de Políticas Públicas MackIntegridade"
    VERSION = "4.0.0"
    
    # Branding
    ORGANIZATION = "MackIntegridade"
    PRIMARY_COLOR = "#003366"  # Dark blue
    SECONDARY_COLOR = "#0066CC"  # Light blue
    ACCENT_COLOR = "#FF6600"  # Orange
    
    # API configurations
    APIS = {
        "camara": APIConfig(
            name="Câmara dos Deputados",
            base_url="https://dadosabertos.camara.leg.br/api/v2",
            timeout=60,
            headers={"Accept": "application/json"}
        ),
        "senado": APIConfig(
            name="Senado Federal",
            base_url="https://legis.senado.leg.br/dadosabertos",
            timeout=60,
            headers={"Accept": "application/xml"}
        ),
        "planalto": APIConfig(
            name="Diário Oficial da União",
            base_url="https://www.in.gov.br",
            timeout=120,  # Longer timeout for JavaScript rendering
            retry_count=2
        ),
    }
    
    # Regulatory Agencies APIs
    REGULATORY_AGENCIES = {
        "aneel": APIConfig(
            name="ANEEL - Agência Nacional de Energia Elétrica",
            base_url="https://www.aneel.gov.br",
            enabled=True
        ),
        "anatel": APIConfig(
            name="ANATEL - Agência Nacional de Telecomunicações",
            base_url="https://sistemas.anatel.gov.br",
            enabled=True
        ),
        "anvisa": APIConfig(
            name="ANVISA - Agência Nacional de Vigilância Sanitária",
            base_url="https://consultas.anvisa.gov.br",
            enabled=True
        ),
        "ans": APIConfig(
            name="ANS - Agência Nacional de Saúde Suplementar",
            base_url="https://www.ans.gov.br",
            enabled=True
        ),
        "ana": APIConfig(
            name="ANA - Agência Nacional de Águas",
            base_url="https://www.ana.gov.br",
            enabled=True
        ),
        "ancine": APIConfig(
            name="ANCINE - Agência Nacional do Cinema",
            base_url="https://www.ancine.gov.br",
            enabled=True
        ),
        "antt": APIConfig(
            name="ANTT - Agência Nacional de Transportes Terrestres",
            base_url="https://www.antt.gov.br",
            enabled=True
        ),
        "antaq": APIConfig(
            name="ANTAQ - Agência Nacional de Transportes Aquaviários",
            base_url="https://www.antaq.gov.br",
            enabled=True
        ),
        "anac": APIConfig(
            name="ANAC - Agência Nacional de Aviação Civil",
            base_url="https://www.anac.gov.br",
            enabled=True
        ),
        "anp": APIConfig(
            name="ANP - Agência Nacional do Petróleo",
            base_url="https://www.anp.gov.br",
            enabled=True
        ),
        "anm": APIConfig(
            name="ANM - Agência Nacional de Mineração",
            base_url="https://www.anm.gov.br",
            enabled=True
        ),
    }
    
    # Search settings
    DEFAULT_PAGE_SIZE = 25
    MAX_PAGE_SIZE = 100
    SEARCH_DEBOUNCE_MS = 500
    
    # Cache settings
    CACHE_DIR = os.path.expanduser("~/.monitor_legislativo/cache")
    MAX_CACHE_SIZE_MB = 100
    
    # Export settings
    EXPORT_FORMATS = ["CSV", "HTML", "PDF", "JSON", "XLSX"]
    DEFAULT_EXPORT_FORMAT = "CSV"
    
    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE = os.path.expanduser("~/.monitor_legislativo/monitor.log")
    
    # Playwright settings (for web scraping)
    PLAYWRIGHT_HEADLESS = True
    PLAYWRIGHT_TIMEOUT = 30000  # 30 seconds
    
    # Rate limiting
    RATE_LIMIT_REQUESTS = 10
    RATE_LIMIT_PERIOD = 60  # seconds
    
    @classmethod
    def get_all_apis(cls) -> Dict[str, APIConfig]:
        """Get all API configurations including regulatory agencies"""
        all_apis = {}
        all_apis.update(cls.APIS)
        all_apis.update(cls.REGULATORY_AGENCIES)
        return all_apis
    
    @classmethod
    def get_enabled_apis(cls) -> Dict[str, APIConfig]:
        """Get only enabled API configurations"""
        return {k: v for k, v in cls.get_all_apis().items() if v.enabled}