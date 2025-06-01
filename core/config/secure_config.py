"""Secure configuration management for Legislative Monitoring System."""

import os
from typing import Any, Dict, Optional
from pathlib import Path
from dotenv import load_dotenv
import logging

logger = logging.getLogger(__name__)

# Load environment variables
env_path = Path(__file__).parent.parent.parent / '.env'
load_dotenv(env_path)


class ConfigurationError(Exception):
    """Raised when a required configuration is missing or invalid."""
    pass


class SecureConfig:
    """Secure configuration management with environment variable support."""
    
    def __init__(self):
        self._config_cache: Dict[str, Any] = {}
        self._validate_required_configs()
    
    def _validate_required_configs(self):
        """Validate that all required configurations are present."""
        required_configs = [
            'APP_SECRET_KEY',
            'DATABASE_URL',
            'JWT_SECRET_KEY',
        ]
        
        missing_configs = []
        for config in required_configs:
            if not os.getenv(config):
                missing_configs.append(config)
        
        if missing_configs:
            raise ConfigurationError(
                f"Missing required environment variables: {', '.join(missing_configs)}"
            )
    
    @staticmethod
    def get(key: str, default: Optional[Any] = None, required: bool = False) -> Any:
        """Get configuration value from environment variables.
        
        Args:
            key: Environment variable name
            default: Default value if not found
            required: Whether this config is required
            
        Returns:
            Configuration value
            
        Raises:
            ConfigurationError: If required config is missing
        """
        value = os.getenv(key, default)
        
        if required and value is None:
            raise ConfigurationError(f"Required configuration '{key}' is missing")
        
        # Convert string booleans
        if isinstance(value, str):
            if value.lower() in ('true', '1', 'yes', 'on'):
                return True
            elif value.lower() in ('false', '0', 'no', 'off'):
                return False
        
        return value
    
    @staticmethod
    def get_int(key: str, default: int = 0) -> int:
        """Get integer configuration value."""
        value = SecureConfig.get(key, default)
        try:
            return int(value)
        except (TypeError, ValueError):
            logger.warning(f"Invalid integer value for {key}: {value}, using default: {default}")
            return default
    
    @staticmethod
    def get_float(key: str, default: float = 0.0) -> float:
        """Get float configuration value."""
        value = SecureConfig.get(key, default)
        try:
            return float(value)
        except (TypeError, ValueError):
            logger.warning(f"Invalid float value for {key}: {value}, using default: {default}")
            return default
    
    @staticmethod
    def get_list(key: str, separator: str = ',', default: Optional[list] = None) -> list:
        """Get list configuration value."""
        value = SecureConfig.get(key, '')
        if not value:
            return default or []
        return [item.strip() for item in value.split(separator)]
    
    @classmethod
    def get_database_config(cls) -> Dict[str, Any]:
        """Get database configuration."""
        return {
            'url': cls.get('DATABASE_URL', required=True),
            'pool_size': cls.get_int('DATABASE_POOL_SIZE', 10),
            'max_overflow': cls.get_int('DATABASE_MAX_OVERFLOW', 20),
            'echo': cls.get('DATABASE_ECHO', False),
        }
    
    @classmethod
    def get_redis_config(cls) -> Dict[str, Any]:
        """Get Redis configuration."""
        return {
            'url': cls.get('REDIS_URL', 'redis://localhost:6379/0'),
            'password': cls.get('REDIS_PASSWORD'),
            'max_connections': cls.get_int('REDIS_MAX_CONNECTIONS', 50),
            'decode_responses': True,
        }
    
    @classmethod
    def get_api_config(cls) -> Dict[str, Any]:
        """Get API configuration."""
        return {
            'camara': {
                'base_url': 'https://dadosabertos.camara.leg.br/api/v2',
                'api_key': cls.get('CAMARA_API_KEY'),
                'timeout': cls.get_int('API_TIMEOUT', 30),
                'verify_ssl': True,  # Always verify SSL
            },
            'senado': {
                'base_url': 'https://legis.senado.leg.br/dadosabertos',
                'api_key': cls.get('SENADO_API_KEY'),
                'timeout': cls.get_int('API_TIMEOUT', 30),
                'verify_ssl': True,
            },
            'planalto': {
                'base_url': 'https://www.planalto.gov.br',
                'api_key': cls.get('PLANALTO_API_KEY'),
                'timeout': cls.get_int('API_TIMEOUT', 30),
                'verify_ssl': True,
            },
            'retry_count': cls.get_int('API_RETRY_COUNT', 3),
            'retry_delay': cls.get_int('API_RETRY_DELAY', 1),
        }
    
    @classmethod
    def get_security_config(cls) -> Dict[str, Any]:
        """Get security configuration."""
        return {
            'secret_key': cls.get('APP_SECRET_KEY', required=True),
            'jwt_secret': cls.get('JWT_SECRET_KEY', required=True),
            'jwt_access_expires': cls.get_int('JWT_ACCESS_TOKEN_EXPIRES', 3600),
            'jwt_refresh_expires': cls.get_int('JWT_REFRESH_TOKEN_EXPIRES', 86400),
            'session_lifetime': cls.get_int('SESSION_LIFETIME', 3600),
            'session_secure_cookie': cls.get('SESSION_SECURE_COOKIE', True),
            'cors_origins': cls.get_list('CORS_ALLOWED_ORIGINS', default=['http://localhost:5000']),
        }
    
    @classmethod
    def get_rate_limit_config(cls) -> Dict[str, Any]:
        """Get rate limiting configuration."""
        return {
            'per_hour': cls.get_int('RATE_LIMIT_PER_HOUR', 1000),
            'per_minute': cls.get_int('RATE_LIMIT_PER_MINUTE', 100),
            'storage_uri': cls.get('REDIS_URL', 'redis://localhost:6379/1'),
        }
    
    @classmethod
    def get_notification_config(cls) -> Dict[str, Any]:
        """Get notification configuration."""
        return {
            'smtp_host': cls.get('SMTP_HOST', 'smtp.gmail.com'),
            'smtp_port': cls.get_int('SMTP_PORT', 587),
            'smtp_username': cls.get('SMTP_USERNAME'),
            'smtp_password': cls.get('SMTP_PASSWORD'),
            'smtp_use_tls': cls.get('SMTP_USE_TLS', True),
            'from_email': cls.get('NOTIFICATION_FROM_EMAIL', 'noreply@legislativo.gov.br'),
            'admin_email': cls.get('NOTIFICATION_ADMIN_EMAIL', 'admin@legislativo.gov.br'),
        }
    
    @classmethod
    def is_debug(cls) -> bool:
        """Check if debug mode is enabled."""
        return cls.get('APP_DEBUG', False) and cls.get('APP_ENV', 'production') != 'production'
    
    @classmethod
    def is_testing(cls) -> bool:
        """Check if in testing mode."""
        return cls.get('APP_ENV', 'production') == 'testing'
    
    @classmethod
    def is_production(cls) -> bool:
        """Check if in production mode."""
        return cls.get('APP_ENV', 'production') == 'production'


# Create singleton instance
config = SecureConfig()