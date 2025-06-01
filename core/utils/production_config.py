"""
Production configuration and environment setup
Provides comprehensive production configuration management
"""

import os
import json
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

@dataclass
class ProductionConfig:
    """Production configuration settings"""
    
    # Application Settings
    app_name: str = "Monitor Legislativo"
    app_version: str = "1.0.0"
    environment: str = "production"
    debug: bool = False
    testing: bool = False
    
    # Server Settings
    host: str = "0.0.0.0"
    port: int = 5000
    workers: int = 4
    timeout: int = 60
    keepalive: int = 2
    max_requests: int = 1000
    
    # Database Settings
    database_url: str = ""
    database_pool_size: int = 20
    database_max_overflow: int = 30
    database_pool_timeout: int = 30
    database_pool_recycle: int = 3600
    
    # Redis Settings
    redis_url: str = ""
    redis_max_connections: int = 50
    redis_socket_keepalive: bool = True
    redis_socket_keepalive_options: Dict[str, int] = None
    
    # Elasticsearch Settings
    elasticsearch_url: str = ""
    elasticsearch_timeout: int = 30
    elasticsearch_max_retries: int = 3
    elasticsearch_retry_on_timeout: bool = True
    
    # Security Settings
    secret_key: str = ""
    jwt_secret_key: str = ""
    jwt_expiration_hours: int = 24
    password_hash_method: str = "pbkdf2:sha256"
    session_cookie_secure: bool = True
    session_cookie_httponly: bool = True
    session_cookie_samesite: str = "Lax"
    
    # Rate Limiting
    rate_limit_default: str = "100/minute"
    rate_limit_burst: int = 200
    rate_limit_storage_url: str = ""
    
    # Caching
    cache_type: str = "redis"
    cache_default_timeout: int = 3600
    cache_key_prefix: str = "monitor_legislativo:"
    
    # Logging
    log_level: str = "INFO"
    log_format: str = "json"
    log_file_enabled: bool = True
    log_console_enabled: bool = True
    log_max_file_size: int = 100 * 1024 * 1024  # 100MB
    log_backup_count: int = 10
    
    # Monitoring
    metrics_enabled: bool = True
    health_check_enabled: bool = True
    prometheus_metrics_path: str = "/metrics"
    
    # External APIs
    camara_api_base_url: str = "https://dadosabertos.camara.leg.br/api/v2"
    senado_api_base_url: str = "https://legis.senado.leg.br/dadosabertos"
    planalto_api_base_url: str = "https://www.planalto.gov.br/ccivil_03"
    api_timeout: int = 30
    api_retry_count: int = 3
    api_backoff_factor: float = 2.0
    
    # Circuit Breaker
    circuit_breaker_failure_threshold: int = 5
    circuit_breaker_recovery_timeout: int = 60
    circuit_breaker_expected_exception: str = "RequestException"
    
    # WebSocket
    websocket_enabled: bool = True
    websocket_cors_allowed_origins: str = "*"
    websocket_async_mode: str = "threading"
    
    # File Upload
    max_content_length: int = 16 * 1024 * 1024  # 16MB
    upload_folder: str = "data/uploads"
    
    # Export Settings
    export_max_records: int = 100000
    export_timeout: int = 300
    export_formats: list = None
    
    # Backup Settings
    backup_enabled: bool = True
    backup_schedule: str = "0 2 * * *"  # Daily at 2 AM
    backup_retention_days: int = 30
    backup_storage_path: str = "data/backups"
    
    # SSL/TLS
    ssl_cert_path: str = ""
    ssl_key_path: str = ""
    ssl_ca_cert_path: str = ""
    force_https: bool = True
    
    # CORS
    cors_origins: str = "*"
    cors_methods: str = "GET,POST,PUT,DELETE,OPTIONS"
    cors_headers: str = "Content-Type,Authorization,X-Requested-With"
    
    def __post_init__(self):
        if self.redis_socket_keepalive_options is None:
            self.redis_socket_keepalive_options = {
                "TCP_KEEPIDLE": 1,
                "TCP_KEEPINTVL": 3,
                "TCP_KEEPCNT": 5
            }
        
        if self.export_formats is None:
            self.export_formats = ["csv", "json", "excel", "pdf"]

class ProductionConfigManager:
    """Manages production configuration from multiple sources"""
    
    def __init__(self):
        self.config = ProductionConfig()
        self.config_sources = []
        
    def load_from_environment(self) -> 'ProductionConfigManager':
        """Load configuration from environment variables"""
        env_mapping = {
            # Application
            "APP_NAME": "app_name",
            "APP_VERSION": "app_version",
            "FLASK_ENV": "environment",
            "DEBUG": "debug",
            "TESTING": "testing",
            
            # Server
            "HOST": "host",
            "PORT": "port",
            "WORKERS": "workers",
            "TIMEOUT": "timeout",
            "KEEPALIVE": "keepalive",
            "MAX_REQUESTS": "max_requests",
            
            # Database
            "DATABASE_URL": "database_url",
            "DB_POOL_SIZE": "database_pool_size",
            "DB_MAX_OVERFLOW": "database_max_overflow",
            "DB_POOL_TIMEOUT": "database_pool_timeout",
            "DB_POOL_RECYCLE": "database_pool_recycle",
            
            # Redis
            "REDIS_URL": "redis_url",
            "REDIS_MAX_CONNECTIONS": "redis_max_connections",
            
            # Elasticsearch
            "ELASTICSEARCH_URL": "elasticsearch_url",
            "ELASTICSEARCH_TIMEOUT": "elasticsearch_timeout",
            
            # Security
            "SECRET_KEY": "secret_key",
            "JWT_SECRET_KEY": "jwt_secret_key",
            "JWT_EXPIRATION_HOURS": "jwt_expiration_hours",
            
            # Rate Limiting
            "RATE_LIMIT_DEFAULT": "rate_limit_default",
            "RATE_LIMIT_STORAGE_URL": "rate_limit_storage_url",
            
            # Logging
            "LOG_LEVEL": "log_level",
            "LOG_FORMAT": "log_format",
            
            # External APIs
            "CAMARA_API_KEY": "camara_api_key",
            "SENADO_API_KEY": "senado_api_key",
            "PLANALTO_API_KEY": "planalto_api_key",
            
            # SSL
            "SSL_CERT_PATH": "ssl_cert_path",
            "SSL_KEY_PATH": "ssl_key_path",
            "FORCE_HTTPS": "force_https"
        }
        
        for env_var, config_attr in env_mapping.items():
            value = os.getenv(env_var)
            if value is not None:
                # Type conversion
                if hasattr(self.config, config_attr):
                    current_value = getattr(self.config, config_attr)
                    if isinstance(current_value, bool):
                        value = value.lower() in ('true', '1', 'yes', 'on')
                    elif isinstance(current_value, int):
                        value = int(value)
                    elif isinstance(current_value, float):
                        value = float(value)
                    
                    setattr(self.config, config_attr, value)
        
        self.config_sources.append("environment")
        return self
    
    def load_from_file(self, config_file: str) -> 'ProductionConfigManager':
        """Load configuration from JSON file"""
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    file_config = json.load(f)
                
                for key, value in file_config.items():
                    if hasattr(self.config, key):
                        setattr(self.config, key, value)
                
                self.config_sources.append(f"file:{config_file}")
                
            except Exception as e:
                logging.warning(f"Failed to load config from {config_file}: {e}")
        
        return self
    
    def load_from_secrets(self, secrets_manager) -> 'ProductionConfigManager':
        """Load sensitive configuration from secrets manager"""
        try:
            secrets = {
                "database_url": "monitor-legislativo/database/url",
                "redis_url": "monitor-legislativo/redis/url",
                "elasticsearch_url": "monitor-legislativo/elasticsearch/url",
                "secret_key": "monitor-legislativo/app/secret-key",
                "jwt_secret_key": "monitor-legislativo/app/jwt-secret",
                "camara_api_key": "monitor-legislativo/apis/camara-key",
                "senado_api_key": "monitor-legislativo/apis/senado-key",
                "planalto_api_key": "monitor-legislativo/apis/planalto-key"
            }
            
            for config_attr, secret_path in secrets.items():
                try:
                    secret_value = secrets_manager.get_secret(secret_path)
                    if secret_value and hasattr(self.config, config_attr):
                        setattr(self.config, config_attr, secret_value)
                except:
                    pass  # Continue if secret is not available
            
            self.config_sources.append("secrets_manager")
            
        except Exception as e:
            logging.warning(f"Failed to load secrets: {e}")
        
        return self
    
    def validate_config(self) -> Dict[str, Any]:
        """Validate configuration and return validation results"""
        validation_results = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "checks": {}
        }
        
        # Required settings
        required_settings = [
            ("database_url", "Database URL is required"),
            ("secret_key", "Secret key is required"),
            ("jwt_secret_key", "JWT secret key is required")
        ]
        
        for setting, error_msg in required_settings:
            value = getattr(self.config, setting)
            is_valid = bool(value and value.strip())
            validation_results["checks"][setting] = is_valid
            
            if not is_valid:
                validation_results["valid"] = False
                validation_results["errors"].append(error_msg)
        
        # Optional but recommended settings
        recommended_settings = [
            ("redis_url", "Redis URL not configured - caching will be limited"),
            ("elasticsearch_url", "Elasticsearch URL not configured - search will use database fallback")
        ]
        
        for setting, warning_msg in recommended_settings:
            value = getattr(self.config, setting)
            if not (value and value.strip()):
                validation_results["warnings"].append(warning_msg)
        
        # Security checks
        if self.config.environment == "production":
            if self.config.debug:
                validation_results["warnings"].append("Debug mode is enabled in production")
            
            if not self.config.force_https:
                validation_results["warnings"].append("HTTPS is not enforced in production")
            
            if len(self.config.secret_key) < 32:
                validation_results["warnings"].append("Secret key should be at least 32 characters")
        
        return validation_results
    
    def get_config(self) -> ProductionConfig:
        """Get the loaded configuration"""
        return self.config
    
    def export_config(self, file_path: str, include_secrets: bool = False):
        """Export configuration to file"""
        config_dict = asdict(self.config)
        
        if not include_secrets:
            # Remove sensitive information
            sensitive_keys = [
                "secret_key", "jwt_secret_key", "database_url", 
                "redis_url", "elasticsearch_url"
            ]
            for key in sensitive_keys:
                if key in config_dict:
                    config_dict[key] = "***HIDDEN***"
        
        export_data = {
            "export_timestamp": datetime.utcnow().isoformat(),
            "config_sources": self.config_sources,
            "environment": self.config.environment,
            "configuration": config_dict
        }
        
        with open(file_path, 'w') as f:
            json.dump(export_data, f, indent=2)
    
    def get_flask_config(self) -> Dict[str, Any]:
        """Get Flask-compatible configuration dictionary"""
        return {
            "DEBUG": self.config.debug,
            "TESTING": self.config.testing,
            "SECRET_KEY": self.config.secret_key,
            "SQLALCHEMY_DATABASE_URI": self.config.database_url,
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "SQLALCHEMY_ENGINE_OPTIONS": {
                "pool_size": self.config.database_pool_size,
                "max_overflow": self.config.database_max_overflow,
                "pool_timeout": self.config.database_pool_timeout,
                "pool_recycle": self.config.database_pool_recycle,
                "pool_pre_ping": True
            },
            "REDIS_URL": self.config.redis_url,
            "ELASTICSEARCH_URL": self.config.elasticsearch_url,
            "JWT_SECRET_KEY": self.config.jwt_secret_key,
            "JWT_ACCESS_TOKEN_EXPIRES": self.config.jwt_expiration_hours * 3600,
            "RATELIMIT_STORAGE_URL": self.config.rate_limit_storage_url or self.config.redis_url,
            "RATELIMIT_DEFAULT": self.config.rate_limit_default,
            "MAX_CONTENT_LENGTH": self.config.max_content_length,
            "UPLOAD_FOLDER": self.config.upload_folder,
            "SESSION_COOKIE_SECURE": self.config.session_cookie_secure,
            "SESSION_COOKIE_HTTPONLY": self.config.session_cookie_httponly,
            "SESSION_COOKIE_SAMESITE": self.config.session_cookie_samesite,
            "CORS_ORIGINS": self.config.cors_origins.split(","),
            "CORS_METHODS": self.config.cors_methods.split(","),
            "CORS_HEADERS": self.config.cors_headers.split(",")
        }

def load_production_config() -> ProductionConfig:
    """Load production configuration from all sources"""
    config_manager = ProductionConfigManager()
    
    # Load from multiple sources in order of precedence
    config_manager.load_from_file("configs/production.json")
    config_manager.load_from_environment()
    
    # Validate configuration
    validation = config_manager.validate_config()
    if not validation["valid"]:
        for error in validation["errors"]:
            logging.error(f"Configuration error: {error}")
        raise ValueError("Invalid production configuration")
    
    for warning in validation["warnings"]:
        logging.warning(f"Configuration warning: {warning}")
    
    return config_manager.get_config()

# Global configuration instance
_production_config = None

def get_production_config() -> ProductionConfig:
    """Get the global production configuration"""
    global _production_config
    if _production_config is None:
        _production_config = load_production_config()
    return _production_config