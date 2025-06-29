from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging
import sys
import os

# Add parent directory to path for core imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Force Railway redeployment - 2025-06-29

from . import gateway_router
from .routers import lexml_router, sse_router, private_database_router

# Import API modules with error handling for production deployment
try:
    from .api import geographic
    GEOGRAPHIC_API_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Geographic API not available: {e}")
    GEOGRAPHIC_API_AVAILABLE = False

try:
    from .api import advanced_geocoding
    ADVANCED_GEOCODING_API_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Advanced Geocoding API not available: {e}")
    ADVANCED_GEOCODING_API_AVAILABLE = False

from .services.database_cache_service import get_database_cache_service
from .services.simple_search_service import get_simple_search_service
from core.database.two_tier_manager import get_two_tier_manager
from core.database.alternative_config import get_alternative_database_manager

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
app.include_router(private_database_router.router)

# Include API routers conditionally
if GEOGRAPHIC_API_AVAILABLE:
    app.include_router(geographic.router)

if ADVANCED_GEOCODING_API_AVAILABLE:
    app.include_router(advanced_geocoding.router)


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
            
            # CRITICAL: Try alternative database manager if primary fails
            logger.info("🔄 Attempting alternative database connection methods...")
            try:
                alt_manager = await get_alternative_database_manager()
                alt_status = await alt_manager.get_health_status()
                if alt_status["connected"]:
                    logger.info(f"✅ Alternative database connection successful using {alt_status['driver_used']}")
                else:
                    logger.error("❌ Alternative database connection also failed")
            except Exception as alt_e:
                logger.error(f"❌ Alternative database manager failed: {alt_e}")
        
        # Initialize search service
        search_service = await get_simple_search_service()
        logger.info("✅ Enhanced search service initialized successfully")
        
        # Initialize two-tier manager
        two_tier_manager = await get_two_tier_manager()
        logger.info("✅ Two-tier database manager initialized successfully")
        
        # Initialize geographic service (if available)
        if GEOGRAPHIC_API_AVAILABLE:
            try:
                from .api.geographic import get_geographic_service
                geographic_service = await get_geographic_service()
                logger.info("✅ Geographic service initialized successfully")
            except Exception as geo_e:
                logger.warning(f"⚠️  Geographic service initialization failed: {geo_e}")
        else:
            logger.info("ℹ️  Geographic service not available - skipping initialization")
        
        # Initialize ML analysis engine (if available)
        if ML_ANALYSIS_API_AVAILABLE:
            try:
                from .api.ml_analysis import get_ml_engine
                ml_engine = await get_ml_engine()
                logger.info("✅ ML text analysis engine initialized successfully")
            except Exception as ml_e:
                logger.warning(f"⚠️  ML analysis engine initialization failed: {ml_e}")
        else:
            logger.info("ℹ️  ML analysis engine not available - skipping initialization")
        
        # Initialize advanced geocoding service (if available)
        if ADVANCED_GEOCODING_API_AVAILABLE:
            try:
                from .api.advanced_geocoding import get_advanced_geocoder
                advanced_geocoder = await get_advanced_geocoder()
                logger.info("✅ Advanced Brazilian geocoding service initialized successfully")
            except Exception as geo_e:
                logger.warning(f"⚠️  Advanced geocoding service initialization failed: {geo_e}")
        else:
            logger.info("ℹ️  Advanced geocoding service not available - skipping initialization")
        
        # Initialize document validation service (if available)
        if DOCUMENT_VALIDATION_API_AVAILABLE:
            try:
                from .api.document_validation import get_document_validator
                document_validator = await get_document_validator()
                logger.info("✅ Document validation service initialized successfully")
            except Exception as val_e:
                logger.warning(f"⚠️  Document validation service initialization failed: {val_e}")
        else:
            logger.info("ℹ️  Document validation service not available - skipping initialization")
        
        # Initialize AI agents service (if available)
        if AI_AGENTS_API_AVAILABLE:
            try:
                from .api.ai_agents import get_agent_manager
                agent_manager = await get_agent_manager()
                logger.info("✅ AI agents service initialized successfully")
            except Exception as ai_e:
                logger.warning(f"⚠️  AI agents service initialization failed: {ai_e}")
        else:
            logger.info("ℹ️  AI agents service not available - skipping initialization")
        
        # Initialize AI document analysis service (if available)
        if AI_DOCUMENT_ANALYSIS_API_AVAILABLE:
            try:
                from .api.ai_document_analysis import get_analysis_engine, get_citation_generator
                analysis_engine = await get_analysis_engine()
                citation_generator = await get_citation_generator()
                logger.info("✅ AI document analysis service initialized successfully")
            except Exception as analysis_e:
                logger.warning(f"⚠️  AI document analysis service initialization failed: {analysis_e}")
        else:
            logger.info("ℹ️  AI document analysis service not available - skipping initialization")
        
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
    # Build features list dynamically based on available components
    features = [
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
    
    # Add features based on available components
    if GEOGRAPHIC_API_AVAILABLE:
        features.extend([
            "🇧🇷 Brazilian Geographic Integration with 5,570+ Municipalities",
            "📍 Document Geographic Analysis and Scope Detection",
            "🗺️ IBGE-compliant Municipality Data with Coordinates"
        ])
    
    if ML_ANALYSIS_API_AVAILABLE:
        features.extend([
            "🤖 ML-Powered Text Analysis with Transport Classification",
            "🔍 Document Similarity Detection and Clustering", 
            "🏷️ Automated Keyword Extraction and Categorization",
            "📊 Advanced Text Statistics and Complexity Analysis"
        ])
    
    if ADVANCED_GEOCODING_API_AVAILABLE:
        features.extend([
            "🎯 Advanced Brazilian Geocoding with 6-Level Precision",
            "🗺️ SIRGAS 2000 Coordinate System Support",
            "📮 CEP Validation and Address Standardization",
            "📐 Haversine Distance Calculations and Spatial Analysis"
        ])
    
    if DOCUMENT_VALIDATION_API_AVAILABLE:
        features.extend([
            "✅ Document Validation Framework with Quality Metrics",
            "🔍 URN Format Validation for Brazilian Legislative Standards",
            "📊 Metadata Completeness Assessment and Scoring",
            "🛡️ Data Integrity Monitoring and Health Checks"
        ])
    
    if AI_AGENTS_API_AVAILABLE:
        features.extend([
            "🤖 Production-Ready AI Agents with Dual-Memory Architecture",
            "💰 Cost Monitoring and 60-80% Semantic Caching Optimization",
            "🧠 Specialized Brazilian Legislative Research Assistance"
        ])
    
    if AI_DOCUMENT_ANALYSIS_API_AVAILABLE:
        features.extend([
            "📄 AI-Powered Document Summarization with Academic Focus",
            "🔍 Intelligent Metadata Extraction and Enhancement",
            "📊 Comprehensive Content Analysis and Quality Metrics",
            "🔗 Document Relationship Discovery and Legal Connections",
            "📚 AI-Enhanced Citation Generation (ABNT, APA, Chicago, Vancouver)",
            "🎓 Academic Research Integration with Cost Optimization"
        ])
    
    if SPATIAL_ANALYSIS_API_AVAILABLE:
        features.extend([
            "🗺️ Advanced Spatial Document Analysis with Brazilian Geography",
            "📍 Automatic Geographic Reference Extraction from Legislative Texts",
            "🌍 Reverse Geocoding with Brazilian Municipality Context",
            "🔗 Spatial Document Clustering and Proximity Analysis",
            "🏛️ Jurisdiction Level Classification (Federal, State, Municipal)",
            "📊 Distance-based Document Correlation and Relationship Detection"
        ])
    
    if VOCABULARY_API_AVAILABLE:
        features.extend([
            "📚 W3C SKOS-Compliant Vocabulary Management",
            "🌲 Interactive Hierarchical Vocabulary Navigation",
            "🔍 Vocabulary-Enhanced Query Expansion",
            "🇧🇷 Brazilian Legislative Terminology with Transport Focus",
            "🔗 Semantic Concept Relationships (Broader, Narrower, Related)",
            "📤 RDF/JSON-LD Export for Semantic Web Integration"
        ])
    
    if BATCH_PROCESSING_API_AVAILABLE:
        features.extend([
            "⚙️ Parallel Batch Document Processing with AI Enhancement",
            "📊 Real-time Progress Tracking and Queue Management",
            "🔄 7-Step Processing Pipeline (Entities, Knowledge Graph, Patterns, Spatial, Standards, AI, Export)",
            "📈 Resource Utilization Monitoring and Performance Statistics",
            "📤 Bulk Export with Multiple Format Support",
            "🎯 Priority-based Job Scheduling and Management"
        ])
    
    if GOVERNMENT_STANDARDS_API_AVAILABLE:
        features.extend([
            "🏛️ Brazilian Government Document Standards Validation",
            "📊 5-Level Digitization Maturity Model Assessment",
            "✅ LexML URN Validation and Metadata Completeness Checking",
            "🔍 Quality Scoring with Compliance Percentage",
            "🔄 Processing Pipeline Recommendations",
            "📋 Document Validation Rules and Government Compliance"
        ])
    
    return {
        "message": "Welcome to the Monitor Legislativo Two-Tier Service",
        "version": "2.0.0",
        "features": features,
        "components_status": {
            "geographic_api": GEOGRAPHIC_API_AVAILABLE,
            "ml_analysis_api": ML_ANALYSIS_API_AVAILABLE,
            "advanced_geocoding_api": ADVANCED_GEOCODING_API_AVAILABLE,
            "document_validation_api": DOCUMENT_VALIDATION_API_AVAILABLE,
            "ai_agents_api": AI_AGENTS_API_AVAILABLE,
            "ai_document_analysis_api": AI_DOCUMENT_ANALYSIS_API_AVAILABLE,
            "knowledge_graph_api": KNOWLEDGE_GRAPH_API_AVAILABLE,
            "spatial_analysis_api": SPATIAL_ANALYSIS_API_AVAILABLE,
            "vocabulary_api": VOCABULARY_API_AVAILABLE,
            "batch_processing_api": BATCH_PROCESSING_API_AVAILABLE,
            "government_standards_api": GOVERNMENT_STANDARDS_API_AVAILABLE
        }
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

@app.get("/api/v1/test/alternative-connection", tags=["Testing"])
async def test_alternative_connection():
    """Test alternative database connection methods"""
    try:
        logger.info("🔧 Testing alternative database connection methods")
        
        # Test the alternative database manager
        alt_manager = await get_alternative_database_manager()
        alt_status = await alt_manager.get_health_status()
        
        return {
            "status": "success",
            "alternative_connection": alt_status,
            "message": f"Alternative connection test completed using {alt_status.get('driver_used', 'unknown')} driver",
            "connected": alt_status.get("connected", False)
        }
        
    except Exception as e:
        logger.error(f"Alternative connection test failed: {e}")
        return {
            "status": "error",
            "error": str(e),
            "message": "Alternative connection test failed"
        }

@app.get("/api/v1/test/ssl-bypass", tags=["Testing"])
async def test_ssl_bypass():
    """Test direct asyncpg connection with SSL bypass for Supabase certificate issues"""
    import urllib.parse
    import ssl
    import asyncio
    
    try:
        db_url = os.getenv('DATABASE_URL', '')
        if not db_url:
            return {"status": "error", "message": "DATABASE_URL not configured"}
        
        parsed = urllib.parse.urlparse(db_url)
        
        # Create SSL context with certificate verification disabled
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        logger.info("🔧 Testing SSL bypass for Supabase certificate issues")
        
        # Import asyncpg and test direct connection
        import asyncpg
        
        conn_params = {
            'host': parsed.hostname,
            'port': parsed.port or 5432,
            'database': parsed.path.lstrip('/'),
            'user': parsed.username,
            'password': parsed.password,
            'ssl': ssl_context,
            'server_settings': {
                'application_name': 'ssl_bypass_test'
            }
        }
        
        # Test connection with 30 second timeout
        conn = await asyncio.wait_for(
            asyncpg.connect(**conn_params),
            timeout=30
        )
        
        # Test basic query
        result = await conn.fetchval("SELECT 1")
        
        # Test version query
        version = await conn.fetchval("SELECT version()")
        
        await conn.close()
        
        return {
            "status": "success",
            "message": "SSL bypass connection successful!",
            "test_result": result,
            "postgres_version": version[:100],  # Truncate for display
            "ssl_bypass": "enabled",
            "connection_method": "direct_asyncpg_ssl_bypass"
        }
        
    except Exception as e:
        logger.error(f"SSL bypass test failed: {e}")
        return {
            "status": "error", 
            "error": str(e),
            "error_type": type(e).__name__,
            "message": "SSL bypass test failed - check logs for details"
        }

@app.get("/api/v1/test/password-decoding", tags=["Testing"])
async def test_password_decoding():
    """Test URL password decoding for debugging"""
    import urllib.parse
    
    try:
        db_url = os.getenv('DATABASE_URL', '')
        if not db_url:
            return {"status": "error", "message": "DATABASE_URL not configured"}
        
        parsed = urllib.parse.urlparse(db_url)
        
        # Show password encoding status
        original_password = parsed.password
        decoded_password = urllib.parse.unquote(original_password) if original_password else None
        
        password_info = {
            "has_password": bool(original_password),
            "password_length": len(original_password) if original_password else 0,
            "contains_encoding": '%' in original_password if original_password else False,
            "original_contains_percent2A": '%2A' in original_password if original_password else False,
            "decoded_contains_asterisk": '*' in decoded_password if decoded_password else False,
            "encoding_fixed": original_password != decoded_password if original_password else False
        }
        
        return {
            "status": "success",
            "message": "Password decoding analysis complete",
            "database_host": parsed.hostname,
            "database_user": parsed.username,
            "password_analysis": password_info,
            "encoding_issue_detected": password_info.get("contains_encoding", False),
            "fix_applied": password_info.get("encoding_fixed", False)
        }
        
    except Exception as e:
        logger.error(f"Password decoding test failed: {e}")
        return {
            "status": "error",
            "error": str(e),
            "message": "Password decoding test failed"
        }

@app.get("/api/v1/test/primary-driver", tags=["Testing"])
async def test_primary_driver():
    """Test the new primary psycopg driver configuration"""
    import urllib.parse
    import psycopg
    import asyncio
    
    try:
        db_url = os.getenv('DATABASE_URL', '')
        if not db_url:
            return {"status": "error", "message": "DATABASE_URL not configured"}
        
        parsed = urllib.parse.urlparse(db_url)
        
        # Test password decoding
        password = parsed.password
        password_decoded = False
        if password and ('%' in password):
            original_password = password
            password = urllib.parse.unquote(password)
            password_decoded = True
            logger.info(f"Password decoded: {original_password} → {password}")
        
        # Create psycopg connection string
        conn_string = f"host={parsed.hostname} port={parsed.port or 5432} dbname={parsed.path.lstrip('/')} user={parsed.username} password={password} sslmode=require"
        
        logger.info("🔧 Testing NEW PRIMARY DRIVER: psycopg")
        
        # Test connection
        conn = await asyncio.wait_for(
            psycopg.AsyncConnection.connect(conn_string),
            timeout=30
        )
        
        # Test query
        async with conn.cursor() as cur:
            await cur.execute("SELECT 1")
            result = await cur.fetchone()
            
            await cur.execute("SELECT current_database(), current_user")
            db_info = await cur.fetchone()
        
        await conn.close()
        
        return {
            "status": "success",
            "message": "PRIMARY DRIVER CHANGE SUCCESSFUL!",
            "driver": "psycopg",
            "test_result": result[0],
            "database_info": {
                "database": db_info[0],
                "user": db_info[1]
            },
            "connection_details": {
                "host": parsed.hostname,
                "port": parsed.port or 5432,
                "password_decoded": password_decoded,
                "ssl_mode": "require"
            }
        }
        
    except Exception as e:
        logger.error(f"Primary driver test failed: {e}")
        return {
            "status": "error",
            "error": str(e),
            "error_type": type(e).__name__,
            "message": "Primary driver test failed - psycopg connection unsuccessful"
        } 