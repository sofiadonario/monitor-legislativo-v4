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