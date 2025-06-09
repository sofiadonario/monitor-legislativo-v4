"""
Configuration settings for Monitor Legislativo
SECURITY UPDATE: Now uses environment variables to prevent hardcoded secrets
TRANSPORT GUIDE COMPLIANCE: Updated URLs and validation system
"""

import os
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


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
    """
    Central configuration for Monitor Legislativo
    SECURITY: Now loads from environment variables to prevent credential exposure
    """
    
    # Application settings (from environment with fallbacks)
    APP_NAME = os.getenv("APP_NAME", "Monitor de Políticas Públicas MackIntegridade")
    VERSION = os.getenv("APP_VERSION", "4.0.0")
    
    # Branding
    ORGANIZATION = "MackIntegridade"
    PRIMARY_COLOR = "#003366"  # Dark blue
    SECONDARY_COLOR = "#0066CC"  # Light blue
    ACCENT_COLOR = "#FF6600"  # Orange
    
    # TRANSPORT GUIDE COMPLIANCE: Load API configurations from verified URLs (December 2024)
    @classmethod
    def get_api_configs(cls) -> Dict[str, APIConfig]:
        """Load API configurations from environment variables with transport guide verified URLs"""
        return {
            "lexml": APIConfig(
                name="LexML Brasil - Rede de Informação Legislativa e Jurídica",
                base_url=os.getenv("LEXML_BASE_URL", "https://www.lexml.gov.br/busca/SRU"),
                timeout=int(os.getenv("LEXML_TIMEOUT", "30")),
                headers={
                    "Accept": "application/xml",
                    "User-Agent": "Monitor-Legislacao-Transporte/1.0 (contato@mackenzie.br)"
                }
            ),
            "camara": APIConfig(
                name="Câmara dos Deputados - Dados Abertos",
                base_url=os.getenv("CAMARA_BASE_URL", "https://dadosabertos.camara.leg.br/api/v2"),
                timeout=int(os.getenv("CAMARA_TIMEOUT", "60")),
                headers={
                    "Accept": "application/json",
                    "User-Agent": "Monitor-Legislacao-Transporte/1.0 (contato@mackenzie.br)",
                    "Authorization": f"Bearer {os.getenv('CAMARA_API_KEY', '')}" if os.getenv('CAMARA_API_KEY') else None
                }
            ),
            "senado": APIConfig(
                name="Senado Federal - Dados Abertos", 
                base_url=os.getenv("SENADO_BASE_URL", "http://legis.senado.leg.br/dadosabertos"),
                timeout=int(os.getenv("SENADO_TIMEOUT", "60")),
                headers={
                    "Accept": "application/xml",
                    "User-Agent": "Monitor-Legislacao-Transporte/1.0 (contato@mackenzie.br)",
                    "Authorization": f"Bearer {os.getenv('SENADO_API_KEY', '')}" if os.getenv('SENADO_API_KEY') else None
                }
            ),
            "planalto": APIConfig(
                name="Presidência da República - Legislação",
                base_url=os.getenv("PLANALTO_BASE_URL", "http://www4.planalto.gov.br/legislacao"),
                timeout=int(os.getenv("PLANALTO_TIMEOUT", "120")),  # Longer timeout for JavaScript rendering
                retry_count=int(os.getenv("PLANALTO_RETRIES", "2")),
                headers={
                    "User-Agent": "Monitor-Legislacao-Transporte/1.0 (contato@mackenzie.br)",
                    "Authorization": f"Bearer {os.getenv('PLANALTO_API_KEY', '')}" if os.getenv('PLANALTO_API_KEY') else None
                }
            ),
            "dou": APIConfig(
                name="Diário Oficial da União - Imprensa Nacional",
                base_url=os.getenv("DOU_BASE_URL", "https://www.in.gov.br"),
                timeout=int(os.getenv("DOU_TIMEOUT", "60")),
                headers={
                    "Accept": "application/json, text/html",
                    "User-Agent": "Monitor-Legislacao-Transporte/1.0 (contato@mackenzie.br)"
                }
            ),
        }
    
    # Dynamic property to get APIs with current environment values
    @property
    def APIS(self) -> Dict[str, APIConfig]:
        """Get current API configurations from environment"""
        return self.get_api_configs()
    
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
            base_url="https://dados.antt.gov.br/api/3",  # Transport guide verified CKAN API
            enabled=True,
            timeout=30,
            headers={
                "Accept": "application/json",
                "User-Agent": "Monitor-Legislacao-Transporte/1.0 (contato@mackenzie.br)"
            }
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
            name="ANP - Agência Nacional do Petróleo, Gás Natural e Biocombustíveis",
            base_url="https://www.gov.br/anp/pt-br/centrais-de-conteudo/dados-abertos",  # Transport guide verified
            enabled=True,
            timeout=30,
            headers={
                "Accept": "application/json",
                "User-Agent": "Monitor-Legislacao-Transporte/1.0 (contato@mackenzie.br)"
            }
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
    
    @classmethod
    def validate_configuration(cls) -> Dict[str, Any]:
        """Validate configuration against transport guide requirements"""
        validation_results = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "api_checks": {}
        }
        
        try:
            # Import here to avoid circular dependency
            from core.config.url_validator import URLValidator
            
            # Validate all API URLs
            validator = URLValidator(timeout=10)
            api_configs = cls.get_all_apis()
            
            for api_name, config in api_configs.items():
                try:
                    status = validator.check_url(config.base_url)
                    validation_results["api_checks"][api_name] = {
                        "url": config.base_url,
                        "status": status.status,
                        "response_time_ms": status.response_time_ms,
                        "error": status.error_message
                    }
                    
                    if status.status == "ERROR":
                        validation_results["errors"].append(
                            f"API {api_name} failed health check: {status.error_message}"
                        )
                        validation_results["valid"] = False
                    elif status.status == "WARNING":
                        validation_results["warnings"].append(
                            f"API {api_name} has warnings: {status.error_message}"
                        )
                        
                except Exception as e:
                    validation_results["errors"].append(
                        f"Failed to validate API {api_name}: {str(e)}"
                    )
                    validation_results["valid"] = False
            
            # Check transport guide compliance
            required_apis = ["lexml", "camara", "senado", "planalto", "dou", "antt"]
            configured_apis = set(api_configs.keys())
            missing_apis = set(required_apis) - configured_apis
            
            if missing_apis:
                validation_results["errors"].append(
                    f"Missing required APIs for transport guide compliance: {missing_apis}"
                )
                validation_results["valid"] = False
            
            # Check environment variables
            critical_env_vars = ["LOG_LEVEL"]
            for var in critical_env_vars:
                if not os.getenv(var):
                    validation_results["warnings"].append(
                        f"Environment variable {var} not set, using default"
                    )
                    
        except ImportError:
            validation_results["warnings"].append(
                "URL validator not available, skipping URL validation"
            )
        except Exception as e:
            validation_results["errors"].append(f"Configuration validation failed: {str(e)}")
            validation_results["valid"] = False
            
        return validation_results
    
    @classmethod
    def get_transport_specific_config(cls) -> Dict[str, Any]:
        """Get transport-specific configuration settings"""
        return {
            "transport_keywords": [
                "transporte", "rodoviário", "ferroviário", "aquaviário", "aéreo",
                "logística", "mobilidade", "trânsito", "veículos", "combustível",
                "antt", "antaq", "anac", "anp", "transportadora", "frete"
            ],
            "priority_agencies": ["antt", "antaq", "anac", "anp"],
            "transport_document_types": [
                "resolução", "portaria", "instrução normativa", "regulamento",
                "lei", "decreto", "medida provisória"
            ],
            "monitoring_intervals": {
                "high_priority": 300,    # 5 minutes
                "normal_priority": 1800, # 30 minutes  
                "low_priority": 3600     # 1 hour
            }
        }