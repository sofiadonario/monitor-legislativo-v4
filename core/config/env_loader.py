"""
Environment Variable Loader for Monitor Legislativo
Centralized environment variable management with validation
"""

import os
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class EnvironmentConfig:
    """Centralized environment configuration management"""
    
    # Database Configuration
    DATABASE_URL: str = os.getenv('DATABASE_URL', '')
    
    # Application Configuration
    ENVIRONMENT: str = os.getenv('ENVIRONMENT', 'development')
    DEBUG: bool = os.getenv('DEBUG', 'false').lower() == 'true'
    API_HOST: str = os.getenv('API_HOST', '0.0.0.0')
    API_PORT: int = int(os.getenv('API_PORT', '8000'))
    
    # LexML Configuration
    LEXML_BASE_URL: str = os.getenv('LEXML_BASE_URL', 'https://www.lexml.gov.br/oai/sru')
    LEXML_TIMEOUT: int = int(os.getenv('LEXML_TIMEOUT', '60'))
    LEXML_MAX_RETRIES: int = int(os.getenv('LEXML_MAX_RETRIES', '3'))
    LEXML_RATE_LIMIT_DELAY: int = int(os.getenv('LEXML_RATE_LIMIT_DELAY', '1'))
    
    # Collection Configuration
    COLLECTION_FREQUENCY: str = os.getenv('COLLECTION_FREQUENCY', 'monthly')
    COLLECTION_TIME: str = os.getenv('COLLECTION_TIME', '02:00')
    MAX_DOCUMENTS_PER_TERM: int = int(os.getenv('MAX_DOCUMENTS_PER_TERM', '10000'))
    COLLECTION_BATCH_SIZE: int = int(os.getenv('COLLECTION_BATCH_SIZE', '100'))
    
    # Cache Configuration
    REDIS_URL: Optional[str] = os.getenv('REDIS_URL')
    REDIS_TTL: int = int(os.getenv('REDIS_TTL', '3600'))
    
    # Logging Configuration
    LOG_LEVEL: str = os.getenv('LOG_LEVEL', 'INFO')
    
    # Analytics Configuration
    ENABLE_ANALYTICS_TRACKING: bool = os.getenv('ENABLE_ANALYTICS_TRACKING', 'true').lower() == 'true'
    ENABLE_SEARCH_LOGGING: bool = os.getenv('ENABLE_SEARCH_LOGGING', 'true').lower() == 'true'
    
    # Search Configuration
    MAX_SEARCH_RESULTS: int = int(os.getenv('MAX_SEARCH_RESULTS', '500'))
    DEFAULT_PAGE_SIZE: int = int(os.getenv('DEFAULT_PAGE_SIZE', '50'))
    
    # Geographic Analysis
    ENABLE_STATE_DENSITY_MAPPING: bool = os.getenv('ENABLE_STATE_DENSITY_MAPPING', 'true').lower() == 'true'
    ENABLE_MUNICIPALITY_ANALYSIS: bool = os.getenv('ENABLE_MUNICIPALITY_ANALYSIS', 'true').lower() == 'true'
    
    # Railway/Production Configuration
    RAILWAY_ENVIRONMENT: Optional[str] = os.getenv('RAILWAY_ENVIRONMENT')
    RAILWAY_DEPLOYMENT_ID: Optional[str] = os.getenv('RAILWAY_DEPLOYMENT_ID')
    
    @classmethod
    def validate_configuration(cls) -> Dict[str, Any]:
        """Validate environment configuration and return status"""
        validation_results = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "configuration": {}
        }
        
        # Critical validations - DATABASE_URL is optional for fallback mode
        if not cls.DATABASE_URL:
            validation_results["warnings"].append("DATABASE_URL not set - application will run in fallback mode without database features")
        elif cls.DATABASE_URL.startswith('postgresql://postgres:postgres@localhost'):
            validation_results["warnings"].append("DATABASE_URL appears to be using localhost - check if this is intended for production")
        
        # Log level validation
        valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if cls.LOG_LEVEL.upper() not in valid_log_levels:
            validation_results["warnings"].append(f"LOG_LEVEL '{cls.LOG_LEVEL}' is not standard. Valid levels: {valid_log_levels}")
        
        # Port validation
        if not (1 <= cls.API_PORT <= 65535):
            validation_results["errors"].append(f"API_PORT '{cls.API_PORT}' is not a valid port number")
            validation_results["valid"] = False
        
        # Collection configuration validation
        if cls.MAX_DOCUMENTS_PER_TERM <= 0:
            validation_results["warnings"].append("MAX_DOCUMENTS_PER_TERM should be positive")
        
        if cls.COLLECTION_BATCH_SIZE <= 0:
            validation_results["warnings"].append("COLLECTION_BATCH_SIZE should be positive")
        
        # Store current configuration for debugging
        validation_results["configuration"] = {
            "environment": cls.ENVIRONMENT,
            "debug": cls.DEBUG,
            "database_configured": bool(cls.DATABASE_URL),
            "redis_configured": bool(cls.REDIS_URL),
            "railway_environment": cls.RAILWAY_ENVIRONMENT,
            "api_port": cls.API_PORT,
            "log_level": cls.LOG_LEVEL
        }
        
        return validation_results
    
    @classmethod
    def get_database_config(cls) -> Dict[str, Any]:
        """Get database-specific configuration"""
        return {
            "url": cls.DATABASE_URL,
            "is_production": cls.ENVIRONMENT.lower() == 'production',
            "debug": cls.DEBUG,
            "railway_deployment": bool(cls.RAILWAY_ENVIRONMENT)
        }
    
    @classmethod
    def get_api_config(cls) -> Dict[str, Any]:
        """Get API-specific configuration"""
        return {
            "host": cls.API_HOST,
            "port": cls.API_PORT,
            "debug": cls.DEBUG,
            "environment": cls.ENVIRONMENT
        }
    
    @classmethod
    def get_lexml_config(cls) -> Dict[str, Any]:
        """Get LexML-specific configuration"""
        return {
            "base_url": cls.LEXML_BASE_URL,
            "timeout": cls.LEXML_TIMEOUT,
            "max_retries": cls.LEXML_MAX_RETRIES,
            "rate_limit_delay": cls.LEXML_RATE_LIMIT_DELAY
        }
    
    @classmethod
    def is_production(cls) -> bool:
        """Check if running in production environment"""
        return cls.ENVIRONMENT.lower() == 'production' or bool(cls.RAILWAY_ENVIRONMENT)
    
    @classmethod
    def is_development(cls) -> bool:
        """Check if running in development environment"""
        return cls.ENVIRONMENT.lower() == 'development' and not cls.RAILWAY_ENVIRONMENT


def validate_environment() -> Dict[str, Any]:
    """Validate current environment configuration"""
    try:
        validation_result = EnvironmentConfig.validate_configuration()
        
        if validation_result["errors"]:
            logger.error("Environment configuration errors:")
            for error in validation_result["errors"]:
                logger.error(f"  - {error}")
        
        if validation_result["warnings"]:
            logger.warning("Environment configuration warnings:")
            for warning in validation_result["warnings"]:
                logger.warning(f"  - {warning}")
        
        return validation_result
        
    except Exception as e:
        logger.error(f"Failed to validate environment configuration: {e}")
        return {
            "valid": False,
            "errors": [f"Validation failed: {str(e)}"],
            "warnings": [],
            "configuration": {}
        }


def log_environment_info():
    """Log current environment information for debugging"""
    try:
        config = EnvironmentConfig
        logger.info("Environment Configuration:")
        logger.info(f"  Environment: {config.ENVIRONMENT}")
        logger.info(f"  Debug Mode: {config.DEBUG}")
        logger.info(f"  API Host: {config.API_HOST}:{config.API_PORT}")
        logger.info(f"  Database Configured: {bool(config.DATABASE_URL)}")
        logger.info(f"  Redis Configured: {bool(config.REDIS_URL)}")
        logger.info(f"  Railway Environment: {config.RAILWAY_ENVIRONMENT or 'None'}")
        logger.info(f"  Log Level: {config.LOG_LEVEL}")
        
    except Exception as e:
        logger.error(f"Failed to log environment info: {e}")