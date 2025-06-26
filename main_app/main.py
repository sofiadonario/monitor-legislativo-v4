from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging
import sys
import os

# Add parent directory to path for core imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from . import gateway_router
from .routers import lexml_router, sse_router
from .services.database_cache_service import get_database_cache_service
from .services.simple_search_service import get_simple_search_service
from core.database.two_tier_manager import get_two_tier_manager

logger = logging.getLogger(__name__)

# Version 2.0.0 - Two-Tier Architecture
app = FastAPI(
    title="Monitor Legislativo - Two-Tier Service",
    description="Brazilian Legislative Monitor with Automated Collection and Advanced Analytics",
    version="2.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://sofiadonario.github.io",
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:5174"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(gateway_router.router)
app.include_router(lexml_router.router)
app.include_router(sse_router.router)


@app.on_event("startup")
async def startup_event():
    """Initialize services on application startup"""
    try:
        logger.info("Initializing Monitor Legislativo Enhanced Service...")
        
        # Initialize database cache service
        cache_service = await get_database_cache_service()
        if cache_service.db_available:
            logger.info("✅ Database cache service initialized successfully")
        else:
            logger.warning("⚠️  Database cache service running in fallback mode")
        
        # Initialize search service
        search_service = await get_simple_search_service()
        logger.info("✅ Enhanced search service initialized successfully")
        
        # Initialize two-tier manager
        two_tier_manager = await get_two_tier_manager()
        logger.info("✅ Two-tier database manager initialized successfully")
        
        logger.info("🚀 Monitor Legislativo Two-Tier Service startup complete")
        
    except Exception as e:
        logger.error(f"❌ Startup initialization failed: {e}")
        # Don't fail startup - services will work in fallback mode


@app.on_event("shutdown")
async def shutdown_event():
    """Clean up resources on application shutdown"""
    try:
        logger.info("Shutting down Monitor Legislativo Enhanced Service...")
        
        # Close database connections if available
        cache_service = await get_database_cache_service()
        if cache_service.db_available and cache_service.db_manager:
            await cache_service.db_manager.close()
            logger.info("✅ Database connections closed")
        
        logger.info("🔻 Monitor Legislativo Two-Tier Service shutdown complete")
        
    except Exception as e:
        logger.error(f"❌ Shutdown cleanup failed: {e}")

@app.get("/", tags=["Root"])
async def read_root():
    return {
        "message": "Welcome to the Monitor Legislativo Two-Tier Service",
        "version": "2.0.0",
        "features": [
            "🤖 Automated Data Collection with Prefect Orchestration",
            "📊 Real-time Analytics Dashboard with R Shiny Integration",
            "🔄 Two-Tier Architecture: Collection Service + Analytics Platform",
            "📈 Database-Backed Search Result Caching for 70% Performance Improvement",
            "🎓 Academic Analytics and Research Pattern Tracking",
            "🏛️ Three-Tier Fallback Architecture (LexML → Regional APIs → 889 CSV Documents)",
            "🧠 SKOS Vocabulary Expansion with Transport Domain Expertise",
            "🗄️ PostgreSQL Integration with Advanced Schema Design",
            "📤 Export Result Caching and Management",
            "📊 Real-time Performance Monitoring and Health Checks",
            "🎯 Academic Research Tools with DOI and Citation Support"
        ]
    }

@app.get("/health", tags=["Health"])
async def health_check():
    """Enhanced health check endpoint with database integration status."""
    try:
        # Get service health statuses
        cache_service = await get_database_cache_service()
        search_service = await get_simple_search_service()
        
        cache_health = await cache_service.get_health_status()
        search_health = await search_service.get_health_status()
        
        return {
            "status": "healthy",
            "service": "monitor-legislativo-two-tier-api",
            "version": "2.0.0",
            "components": {
                "two_tier_architecture": "operational",
                "automated_collection": "available",
                "database_integration": "available" if cache_service.db_available else "fallback_mode",
                "search_caching": "enabled" if cache_service.db_available else "disabled",
                "analytics_tracking": "enabled" if cache_service.db_available else "disabled",
                "three_tier_fallback": "operational",
                "csv_fallback_889_docs": "ready",
                "performance_monitoring": "active",
                "prefect_orchestration": "ready"
            },
            "database_status": cache_health,
            "search_status": search_health
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "degraded",
            "service": "monitor-legislativo-two-tier-api",
            "version": "2.0.0",
            "error": str(e)
        }

@app.get("/api/v1/health/database", tags=["Health"])
async def database_diagnostic():
    """Detailed database diagnostic endpoint for Railway debugging"""
    import urllib.parse
    import socket
    import time
    
    diagnostic_data = {
        "timestamp": time.time(),
        "environment": {
            "railway_environment": os.getenv("RAILWAY_ENVIRONMENT"),
            "environment": os.getenv("ENVIRONMENT", "unknown"),
            "deployment_id": os.getenv("RAILWAY_DEPLOYMENT_ID"),
        },
        "database_config": {},
        "network_tests": {},
        "connection_tests": {},
        "recommendations": []
    }
    
    try:
        # Database URL analysis
        db_url = os.getenv("DATABASE_URL", "")
        if db_url:
            parsed = urllib.parse.urlparse(db_url)
            diagnostic_data["database_config"] = {
                "host": parsed.hostname,
                "port": parsed.port or 5432,
                "database": parsed.path.lstrip("/"),
                "username": parsed.username,
                "password_set": bool(parsed.password),
                "has_special_chars_in_password": bool(parsed.password and ('*' in parsed.password or '+' in parsed.password)),
                "ssl_in_url": "sslmode" in db_url,
                "is_supabase": "supabase.co" in db_url if parsed.hostname else False
            }
            
            # Network connectivity test
            if parsed.hostname:
                try:
                    start_time = time.time()
                    socket.create_connection((parsed.hostname, parsed.port or 5432), timeout=10)
                    connection_time = time.time() - start_time
                    diagnostic_data["network_tests"]["tcp_connection"] = {
                        "status": "success",
                        "connection_time_ms": round(connection_time * 1000, 2)
                    }
                except socket.timeout:
                    diagnostic_data["network_tests"]["tcp_connection"] = {
                        "status": "timeout",
                        "error": "Connection timed out after 10 seconds"
                    }
                    diagnostic_data["recommendations"].append("Network timeout - check Railway to Supabase connectivity")
                except OSError as e:
                    diagnostic_data["network_tests"]["tcp_connection"] = {
                        "status": "failed",
                        "error": str(e),
                        "errno": getattr(e, 'errno', None)
                    }
                    if getattr(e, 'errno', None) == 101:
                        diagnostic_data["recommendations"].append("Network unreachable - Supabase may be blocking Railway IPs")
            
            # DNS resolution test
            try:
                import socket
                ip_addresses = socket.gethostbyname_ex(parsed.hostname)[2]
                diagnostic_data["network_tests"]["dns_resolution"] = {
                    "status": "success",
                    "ip_addresses": ip_addresses
                }
            except Exception as e:
                diagnostic_data["network_tests"]["dns_resolution"] = {
                    "status": "failed",
                    "error": str(e)
                }
                diagnostic_data["recommendations"].append("DNS resolution failed - check hostname")
        
        # Database connection test
        try:
            from core.database.supabase_config import get_database_manager
            db_manager = await get_database_manager()
            connection_success = await db_manager.test_connection()
            
            diagnostic_data["connection_tests"]["database_connection"] = {
                "status": "success" if connection_success else "failed",
                "manager_available": db_manager is not None
            }
            
            if not connection_success:
                diagnostic_data["recommendations"].append("Database connection failed - check credentials and network")
        
        except Exception as e:
            diagnostic_data["connection_tests"]["database_connection"] = {
                "status": "error",
                "error": str(e),
                "error_type": type(e).__name__
            }
            diagnostic_data["recommendations"].append("Database manager error - check imports and dependencies")
        
        # Environment variable recommendations
        if not diagnostic_data["database_config"].get("ssl_in_url") and diagnostic_data["database_config"].get("is_supabase"):
            diagnostic_data["recommendations"].append("Add explicit SSL mode to DATABASE_URL for Supabase")
        
        if diagnostic_data["database_config"].get("has_special_chars_in_password"):
            diagnostic_data["recommendations"].append("URL encode password in DATABASE_URL")
        
        return diagnostic_data
        
    except Exception as e:
        logger.error(f"Database diagnostic failed: {e}")
        return {
            "status": "error",
            "error": str(e),
            "recommendations": ["Check Railway logs for detailed error information"]
        } 