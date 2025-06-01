"""
Unified Configuration System for Monitor Legislativo v4
Consolidates all configuration settings with environment variable support
"""

import os
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class APIConfig:
    """Configuration for an individual API source"""
    name: str
    base_url: str
    enabled: bool = True
    timeout: int = 30
    retry_count: int = 3
    cache_ttl: int = 3600  # 1 hour
    headers: Dict[str, str] = field(default_factory=dict)
    rate_limit: int = 10  # requests per minute
    
    def __post_init__(self):
        # Ensure headers is always a dict
        if self.headers is None:
            self.headers = {}
        
        # Add default headers
        if "User-Agent" not in self.headers:
            self.headers["User-Agent"] = "Monitor-Legislativo/4.0 (Legal Data Aggregator)"


@dataclass 
class DatabaseConfig:
    """Database configuration settings"""
    type: str = "sqlite"  # sqlite, postgresql, mysql
    host: str = "localhost"
    port: int = 5432
    database: str = "monitor_legislativo"
    username: str = ""
    password: str = ""
    pool_size: int = 5
    
    @property
    def connection_string(self) -> str:
        """Generate database connection string"""
        if self.type == "sqlite":
            return f"sqlite:///{self.database}"
        elif self.type == "postgresql":
            return f"postgresql://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"
        elif self.type == "mysql":
            return f"mysql://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"
        else:
            raise ValueError(f"Unsupported database type: {self.type}")


@dataclass
class CacheConfig:
    """Cache configuration settings"""
    enabled: bool = True
    backend: str = "memory"  # memory, redis, file
    ttl_default: int = 3600  # 1 hour
    ttl_search: int = 1800   # 30 minutes
    ttl_health: int = 300    # 5 minutes
    max_size_mb: int = 100
    redis_url: str = "redis://localhost:6379/0"
    file_directory: str = field(default_factory=lambda: str(Path.home() / ".monitor_legislativo" / "cache"))


@dataclass
class SecurityConfig:
    """Security configuration settings"""
    api_key_required: bool = False
    api_key: str = ""
    jwt_secret: str = ""
    jwt_expiry_hours: int = 24
    cors_origins: List[str] = field(default_factory=lambda: ["*"])
    rate_limit_enabled: bool = True
    rate_limit_requests: int = 100
    rate_limit_window: int = 3600  # 1 hour


class UnifiedConfig:
    """Unified configuration system with environment variable support"""
    
    def __init__(self):
        # Application metadata
        self.APP_NAME = "Monitor de Políticas Públicas MackIntegridade"
        self.VERSION = "4.0.0"
        self.ORGANIZATION = "MackIntegridade"
        
        # Visual identity
        self.THEME = {
            "primary_color": "#003366",    # Dark blue
            "secondary_color": "#0066CC",  # Light blue  
            "accent_color": "#FF6600",     # Orange
            "success_color": "#28a745",
            "warning_color": "#ffc107",
            "error_color": "#dc3545",
            "font_family": "Arial, sans-serif"
        }
        
        # Environment detection
        self.ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
        self.DEBUG = os.getenv("DEBUG", "false").lower() == "true"
        
        # Paths
        self.BASE_DIR = Path(__file__).parent.parent.parent
        self.DATA_DIR = Path(os.getenv("DATA_DIR", Path.home() / ".monitor_legislativo"))
        self.LOG_DIR = self.DATA_DIR / "logs"
        self.EXPORT_DIR = self.DATA_DIR / "exports"
        
        # Ensure directories exist
        for directory in [self.DATA_DIR, self.LOG_DIR, self.EXPORT_DIR]:
            directory.mkdir(parents=True, exist_ok=True)
        
        # Logging configuration
        self.LOG_LEVEL = getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper())
        self.LOG_FILE = self.LOG_DIR / "monitor.log"
        self.LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        self.LOG_MAX_BYTES = int(os.getenv("LOG_MAX_BYTES", "10485760"))  # 10MB
        self.LOG_BACKUP_COUNT = int(os.getenv("LOG_BACKUP_COUNT", "5"))
        
        # Component configurations
        self.database = self._load_database_config()
        self.cache = self._load_cache_config()
        self.security = self._load_security_config()
        
        # API configurations
        self.apis = self._load_api_configs()
        
        # Search and pagination
        self.DEFAULT_PAGE_SIZE = int(os.getenv("DEFAULT_PAGE_SIZE", "25"))
        self.MAX_PAGE_SIZE = int(os.getenv("MAX_PAGE_SIZE", "100"))
        self.SEARCH_DEBOUNCE_MS = int(os.getenv("SEARCH_DEBOUNCE_MS", "500"))
        
        # Export settings
        self.EXPORT_FORMATS = ["CSV", "HTML", "PDF", "JSON", "XLSX"]
        self.DEFAULT_EXPORT_FORMAT = os.getenv("DEFAULT_EXPORT_FORMAT", "CSV")
        
        # Playwright settings
        self.PLAYWRIGHT_HEADLESS = os.getenv("PLAYWRIGHT_HEADLESS", "true").lower() == "true"
        self.PLAYWRIGHT_TIMEOUT = int(os.getenv("PLAYWRIGHT_TIMEOUT", "30000"))
        
    def _load_database_config(self) -> DatabaseConfig:
        """Load database configuration from environment"""
        return DatabaseConfig(
            type=os.getenv("DB_TYPE", "sqlite"),
            host=os.getenv("DB_HOST", "localhost"),
            port=int(os.getenv("DB_PORT", "5432")),
            database=os.getenv("DB_NAME", str(self.DATA_DIR / "monitor_legislativo.db")),
            username=os.getenv("DB_USERNAME", ""),
            password=os.getenv("DB_PASSWORD", ""),
            pool_size=int(os.getenv("DB_POOL_SIZE", "5"))
        )
    
    def _load_cache_config(self) -> CacheConfig:
        """Load cache configuration from environment"""
        return CacheConfig(
            enabled=os.getenv("CACHE_ENABLED", "true").lower() == "true",
            backend=os.getenv("CACHE_BACKEND", "memory"),
            ttl_default=int(os.getenv("CACHE_TTL_DEFAULT", "3600")),
            ttl_search=int(os.getenv("CACHE_TTL_SEARCH", "1800")),
            ttl_health=int(os.getenv("CACHE_TTL_HEALTH", "300")),
            max_size_mb=int(os.getenv("CACHE_MAX_SIZE_MB", "100")),
            redis_url=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
            file_directory=os.getenv("CACHE_DIR", str(self.DATA_DIR / "cache"))
        )
    
    def _load_security_config(self) -> SecurityConfig:
        """Load security configuration from environment"""
        cors_origins = os.getenv("CORS_ORIGINS", "*").split(",")
        return SecurityConfig(
            api_key_required=os.getenv("API_KEY_REQUIRED", "false").lower() == "true",
            api_key=os.getenv("API_KEY", ""),
            jwt_secret=os.getenv("JWT_SECRET", ""),
            jwt_expiry_hours=int(os.getenv("JWT_EXPIRY_HOURS", "24")),
            cors_origins=cors_origins,
            rate_limit_enabled=os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true",
            rate_limit_requests=int(os.getenv("RATE_LIMIT_REQUESTS", "100")),
            rate_limit_window=int(os.getenv("RATE_LIMIT_WINDOW", "3600"))
        )
    
    def _load_api_configs(self) -> Dict[str, APIConfig]:
        """Load API configurations with environment overrides"""
        
        # Base API configurations
        apis = {
            "camara": APIConfig(
                name="Câmara dos Deputados",
                base_url=os.getenv("CAMARA_API_URL", "https://dadosabertos.camara.leg.br/api/v2"),
                timeout=int(os.getenv("CAMARA_TIMEOUT", "60")),
                enabled=os.getenv("CAMARA_ENABLED", "true").lower() == "true",
                headers={"Accept": "application/json"}
            ),
            "senado": APIConfig(
                name="Senado Federal",
                base_url=os.getenv("SENADO_API_URL", "https://legis.senado.leg.br/dadosabertos"),
                timeout=int(os.getenv("SENADO_TIMEOUT", "60")),
                enabled=os.getenv("SENADO_ENABLED", "true").lower() == "true",
                headers={"Accept": "application/xml"}
            ),
            "planalto": APIConfig(
                name="Diário Oficial da União",
                base_url=os.getenv("PLANALTO_API_URL", "https://www.in.gov.br"),
                timeout=int(os.getenv("PLANALTO_TIMEOUT", "120")),
                enabled=os.getenv("PLANALTO_ENABLED", "true").lower() == "true",
                retry_count=2
            ),
        }
        
        # Regulatory agencies
        agencies = {
            "aneel": ("ANEEL - Agência Nacional de Energia Elétrica", "https://www.aneel.gov.br"),
            "anatel": ("ANATEL - Agência Nacional de Telecomunicações", "https://sistemas.anatel.gov.br"),
            "anvisa": ("ANVISA - Agência Nacional de Vigilância Sanitária", "https://consultas.anvisa.gov.br"),
            "ans": ("ANS - Agência Nacional de Saúde Suplementar", "https://www.ans.gov.br"),
            "ana": ("ANA - Agência Nacional de Águas", "https://www.ana.gov.br"),
            "ancine": ("ANCINE - Agência Nacional do Cinema", "https://www.ancine.gov.br"),
            "antt": ("ANTT - Agência Nacional de Transportes Terrestres", "https://www.antt.gov.br"),
            "antaq": ("ANTAQ - Agência Nacional de Transportes Aquaviários", "https://www.antaq.gov.br"),
            "anac": ("ANAC - Agência Nacional de Aviação Civil", "https://www.anac.gov.br"),
            "anp": ("ANP - Agência Nacional do Petróleo", "https://www.anp.gov.br"),
            "anm": ("ANM - Agência Nacional de Mineração", "https://www.anm.gov.br"),
        }
        
        for key, (name, base_url) in agencies.items():
            env_key = key.upper()
            apis[key] = APIConfig(
                name=name,
                base_url=os.getenv(f"{env_key}_API_URL", base_url),
                enabled=os.getenv(f"{env_key}_ENABLED", "true").lower() == "true",
                timeout=int(os.getenv(f"{env_key}_TIMEOUT", "60"))
            )
        
        return apis
    
    def get_enabled_apis(self) -> Dict[str, APIConfig]:
        """Get only enabled API configurations"""
        return {k: v for k, v in self.apis.items() if v.enabled}
    
    def get_api_config(self, api_name: str) -> Optional[APIConfig]:
        """Get configuration for a specific API"""
        return self.apis.get(api_name)
    
    def is_production(self) -> bool:
        """Check if running in production environment"""
        return self.ENVIRONMENT == "production"
    
    def is_development(self) -> bool:
        """Check if running in development environment"""
        return self.ENVIRONMENT == "development"
    
    def setup_logging(self):
        """Configure logging based on settings"""
        from logging.handlers import RotatingFileHandler
        
        # Create formatter
        formatter = logging.Formatter(self.LOG_FORMAT)
        
        # Setup file handler
        file_handler = RotatingFileHandler(
            self.LOG_FILE,
            maxBytes=self.LOG_MAX_BYTES,
            backupCount=self.LOG_BACKUP_COUNT
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(self.LOG_LEVEL)
        
        # Setup console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(logging.INFO if self.is_production() else logging.DEBUG)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(self.LOG_LEVEL)
        root_logger.addHandler(file_handler)
        root_logger.addHandler(console_handler)
        
        # Suppress noisy third-party loggers
        logging.getLogger("aiohttp").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("asyncio").setLevel(logging.WARNING)


# Global configuration instance
config = UnifiedConfig()


# Legacy compatibility - can be removed after refactoring
class Config:
    """Legacy configuration class for backward compatibility"""
    
    # Application settings
    APP_NAME = config.APP_NAME
    VERSION = config.VERSION
    ORGANIZATION = config.ORGANIZATION
    
    # Colors (for backward compatibility)
    PRIMARY_COLOR = config.THEME["primary_color"]
    SECONDARY_COLOR = config.THEME["secondary_color"]
    ACCENT_COLOR = config.THEME["accent_color"]
    
    # API configurations
    APIS = {k: v for k, v in config.apis.items() if k in ["camara", "senado", "planalto"]}
    REGULATORY_AGENCIES = {k: v for k, v in config.apis.items() if k not in ["camara", "senado", "planalto"]}
    
    # Search settings
    DEFAULT_PAGE_SIZE = config.DEFAULT_PAGE_SIZE
    MAX_PAGE_SIZE = config.MAX_PAGE_SIZE
    SEARCH_DEBOUNCE_MS = config.SEARCH_DEBOUNCE_MS
    
    # Cache settings
    CACHE_DIR = config.cache.file_directory
    MAX_CACHE_SIZE_MB = config.cache.max_size_mb
    
    # Export settings
    EXPORT_FORMATS = config.EXPORT_FORMATS
    DEFAULT_EXPORT_FORMAT = config.DEFAULT_EXPORT_FORMAT
    
    # Logging
    LOG_LEVEL = logging.getLevelName(config.LOG_LEVEL)
    LOG_FILE = str(config.LOG_FILE)
    
    # Playwright settings
    PLAYWRIGHT_HEADLESS = config.PLAYWRIGHT_HEADLESS
    PLAYWRIGHT_TIMEOUT = config.PLAYWRIGHT_TIMEOUT
    
    # Rate limiting
    RATE_LIMIT_REQUESTS = config.security.rate_limit_requests
    RATE_LIMIT_PERIOD = config.security.rate_limit_window
    
    @classmethod
    def get_all_apis(cls) -> Dict[str, APIConfig]:
        """Get all API configurations including regulatory agencies"""
        return config.apis
    
    @classmethod
    def get_enabled_apis(cls) -> Dict[str, APIConfig]:
        """Get only enabled API configurations"""
        return config.get_enabled_apis()