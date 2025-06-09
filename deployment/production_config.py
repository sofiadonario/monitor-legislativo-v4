"""
Production Configuration and Deployment Settings
Final configuration for production-ready deployment
"""

import os
from pathlib import Path
from typing import Dict, Any, List

class ProductionConfig:
    """Production environment configuration."""
    
    # Database configuration
    DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:pass@localhost:5432/monitor_legislativo")
    DATABASE_POOL_SIZE = int(os.getenv("DATABASE_POOL_SIZE", "100"))
    DATABASE_MAX_OVERFLOW = int(os.getenv("DATABASE_MAX_OVERFLOW", "200"))
    
    # Redis configuration
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    REDIS_POOL_SIZE = int(os.getenv("REDIS_POOL_SIZE", "50"))
    
    # Security configuration
    SECRET_KEY = os.getenv("SECRET_KEY")  # Must be set in production
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")  # Must be set in production
    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")  # Must be set in production
    
    # API configuration
    CAMARA_API_KEY = os.getenv("CAMARA_API_KEY", "")
    SENADO_API_KEY = os.getenv("SENADO_API_KEY", "")
    PLANALTO_API_KEY = os.getenv("PLANALTO_API_KEY", "")
    
    # Monitoring and logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    SENTRY_DSN = os.getenv("SENTRY_DSN", "")
    PROMETHEUS_ENABLED = os.getenv("PROMETHEUS_ENABLED", "true").lower() == "true"
    
    # Performance settings
    MAX_WORKERS = int(os.getenv("MAX_WORKERS", "4"))
    WORKER_TIMEOUT = int(os.getenv("WORKER_TIMEOUT", "30"))
    CACHE_TTL = int(os.getenv("CACHE_TTL", "3600"))
    
    # Security headers
    SECURITY_HEADERS = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Content-Security-Policy": "default-src 'self'",
        "Referrer-Policy": "strict-origin-when-cross-origin"
    }
    
    @classmethod
    def validate_production_config(cls) -> Dict[str, Any]:
        """Validate production configuration."""
        errors = []
        warnings = []
        
        # Check required environment variables
        required_vars = ["SECRET_KEY", "JWT_SECRET_KEY", "ENCRYPTION_KEY"]
        for var in required_vars:
            if not getattr(cls, var):
                errors.append(f"Missing required environment variable: {var}")
        
        # Check database configuration
        if "localhost" in cls.DATABASE_URL:
            warnings.append("Database URL points to localhost - ensure this is correct for production")
        
        # Check security settings
        if cls.LOG_LEVEL == "DEBUG":
            warnings.append("Debug logging enabled in production")
        
        return {"errors": errors, "warnings": warnings}


# Production deployment checklist
PRODUCTION_CHECKLIST = {
    "security": [
        "All secrets configured in environment variables",
        "HTTPS enabled with valid SSL certificates",
        "Security headers configured",
        "Rate limiting enabled",
        "Input validation active",
        "SQL injection protection verified",
        "XSS protection verified",
        "Authentication and authorization tested"
    ],
    "performance": [
        "Database connection pool optimized",
        "Caching strategy implemented",
        "CDN configured for static assets",
        "Load balancer configured",
        "Auto-scaling rules defined",
        "Performance monitoring active",
        "SLA targets defined and monitored"
    ],
    "reliability": [
        "Circuit breakers configured",
        "Health checks implemented",
        "Monitoring and alerting active",
        "Log aggregation configured",
        "Error tracking enabled",
        "Backup strategy verified",
        "Disaster recovery plan tested"
    ],
    "compliance": [
        "Security audit completed",
        "Performance testing passed",
        "Integration tests passed",
        "End-to-end tests passed",
        "Documentation updated",
        "Deployment procedures documented",
        "Rollback procedures tested"
    ]
}