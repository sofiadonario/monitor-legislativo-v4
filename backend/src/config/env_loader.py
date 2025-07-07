import os
import logging
from typing import Optional
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

class EnvironmentConfig:
    """
    Environment configuration for Monitor Legislativo v4.
    Manages all environment variables and provides validation.
    """
    load_dotenv()
    
    # Database Configuration
    DATABASE_URL: str = os.getenv("DATABASE_URL", "")
    
    # Supabase Configuration
    SUPABASE_URL: str = os.getenv("SUPABASE_URL", "")
    SUPABASE_ANON_KEY: str = os.getenv("SUPABASE_ANON_KEY", "")
    SUPABASE_DB_URL: str = os.getenv("SUPABASE_DB_URL", "")
    
    # Redis Configuration (Upstash)
    REDIS_URL: str = os.getenv("REDIS_URL", "")
    REDIS_MAX_CONNECTIONS: int = int(os.getenv("REDIS_MAX_CONNECTIONS", "10"))
    REDIS_TIMEOUT: int = int(os.getenv("REDIS_TIMEOUT", "5"))
    
    # API Configuration
    LEXML_API_URL: str = os.getenv("LEXML_API_URL", "https://www.lexml.gov.br/busca/SRU")
    LEXML_TIMEOUT: int = int(os.getenv("LEXML_TIMEOUT", "30"))
    LEXML_MAX_RECORDS: int = int(os.getenv("LEXML_MAX_RECORDS", "100"))
    
    # Cache Configuration
    CACHE_TTL: int = int(os.getenv("CACHE_TTL", "3600"))  # 1 hour default
    CACHE_PREFIX: str = os.getenv("CACHE_PREFIX", "monitor_legislativo:")
    
    # Application Configuration
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "production")
    DEBUG: bool = os.getenv("DEBUG", "False").lower() in ("true", "1", "t")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    
    # Railway Specific
    RAILWAY_ENVIRONMENT: str = os.getenv("RAILWAY_ENVIRONMENT", "")
    PORT: int = int(os.getenv("PORT", "8000"))
    
    # Performance Configuration
    MAX_CONCURRENT_REQUESTS: int = int(os.getenv("MAX_CONCURRENT_REQUESTS", "10"))
    REQUEST_TIMEOUT: int = int(os.getenv("REQUEST_TIMEOUT", "60"))
    
    # Feature Flags
    ENABLE_CACHE: bool = os.getenv("ENABLE_CACHE", "True").lower() in ("true", "1", "t")
    ENABLE_VOCABULARY_EXPANSION: bool = os.getenv("ENABLE_VOCABULARY_EXPANSION", "True").lower() in ("true", "1", "t")
    USE_CSV_FALLBACK: bool = os.getenv("USE_CSV_FALLBACK", "True").lower() in ("true", "1", "t")

    @classmethod
    def is_production(cls):
        return cls.ENVIRONMENT == "production"

    @classmethod
    def is_development(cls):
        return cls.ENVIRONMENT == "development"
    
    @classmethod
    def is_railway(cls):
        return bool(cls.RAILWAY_ENVIRONMENT)
    
    @classmethod
    def get_redis_url(cls) -> Optional[str]:
        """Get Redis URL with fallback logic"""
        if cls.REDIS_URL:
            return cls.REDIS_URL
        # Try alternate environment variable names
        return os.getenv("UPSTASH_REDIS_URL") or os.getenv("REDIS_HOST")

def validate_environment():
    """Validate environment configuration and report issues."""
    logger.info("Validating environment configuration...")
    errors = []
    warnings = []
    
    # Critical checks
    if not EnvironmentConfig.DATABASE_URL:
        errors.append("DATABASE_URL is not set - database features will not work")
    
    # Warning checks
    if not EnvironmentConfig.get_redis_url():
        warnings.append("Redis URL not configured - caching will be disabled")
    
    if not EnvironmentConfig.SUPABASE_URL or not EnvironmentConfig.SUPABASE_ANON_KEY:
        warnings.append("Supabase not configured - processed documents features will not work")
    
    if not EnvironmentConfig.LEXML_API_URL:
        errors.append("LexML API URL not configured - search will not work")
    
    # Log validation results
    if errors:
        for error in errors:
            logger.error(f"Environment validation error: {error}")
    
    if warnings:
        for warning in warnings:
            logger.warning(f"Environment validation warning: {warning}")
    
    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings
    }

def log_environment_info():
    """Log current environment configuration for debugging."""
    logger.info("=== Environment Configuration ===")
    logger.info(f"Environment: {EnvironmentConfig.ENVIRONMENT}")
    logger.info(f"Debug Mode: {EnvironmentConfig.DEBUG}")
    logger.info(f"Railway Environment: {EnvironmentConfig.RAILWAY_ENVIRONMENT or 'Not on Railway'}")
    logger.info(f"Port: {EnvironmentConfig.PORT}")
    
    # Database status
    logger.info(f"Database URL: {'Configured' if EnvironmentConfig.DATABASE_URL else 'Not configured'}")
    
    # Redis status
    redis_url = EnvironmentConfig.get_redis_url()
    logger.info(f"Redis URL: {'Configured' if redis_url else 'Not configured'}")
    
    # Feature flags
    logger.info(f"Cache Enabled: {EnvironmentConfig.ENABLE_CACHE}")
    logger.info(f"Vocabulary Expansion: {EnvironmentConfig.ENABLE_VOCABULARY_EXPANSION}")
    logger.info(f"CSV Fallback: {EnvironmentConfig.USE_CSV_FALLBACK}")
    
    logger.info("================================") 