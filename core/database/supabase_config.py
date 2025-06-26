"""
Supabase Database Configuration for Monitor Legislativo
Ultra-Budget Academic Deployment
"""

import os
import asyncio
import urllib.parse
import time
from typing import Optional, Dict, Any
import logging
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, TimeoutError as SQLTimeoutError

logger = logging.getLogger(__name__)


class SupabaseConfig:
    """Configuration for Supabase PostgreSQL database"""
    
    # Database connection
    DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/legislativo')
    
    # Connection pool settings for Railway/Supabase optimization
    POOL_SIZE = 3  # Smaller pool for Railway container limits
    MAX_OVERFLOW = 0  # No overflow to stay within limits
    POOL_TIMEOUT = 60  # Increased timeout for Railway network
    POOL_RECYCLE = 1800  # 30 minutes for Railway connections
    
    # Railway-specific timeouts
    CONNECT_TIMEOUT = 30  # Connection establishment timeout
    COMMAND_TIMEOUT = 60  # SQL command timeout
    
    # Query optimization
    ECHO_SQL = os.getenv('DEBUG', 'false').lower() == 'true'
    
    @classmethod
    def fix_database_url(cls) -> str:
        """Fix DATABASE_URL for Railway/Supabase compatibility"""
        db_url = cls.DATABASE_URL
        
        # Parse URL to fix encoding issues
        try:
            parsed = urllib.parse.urlparse(db_url)
            
            # CRITICAL FIX: URL decode password if it contains encoded characters
            if parsed.password and ('%' in parsed.password):
                # URL decode the password for asyncpg compatibility
                decoded_password = urllib.parse.unquote(parsed.password)
                # Reconstruct URL with decoded password
                netloc = f"{parsed.username}:{decoded_password}@{parsed.hostname}"
                if parsed.port:
                    netloc += f":{parsed.port}"
                
                db_url = urllib.parse.urlunparse((
                    parsed.scheme,
                    netloc,
                    parsed.path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment
                ))
                logger.info(f"Fixed DATABASE_URL password decoding: %2A → * for asyncpg compatibility")
            
            # Additional validation for Supabase pooler format
            if 'pooler.supabase.com' in db_url:
                # Ensure proper username format for pooler connections
                if parsed.username and '.' in parsed.username:
                    logger.info(f"Using Supabase pooler format with username: {parsed.username}")
                else:
                    logger.warning("Supabase pooler connections require project-specific username format")
            
            # Clean URL - SSL will be handled by connect_args
            if 'supabase.co' in db_url:
                logger.info("SSL will be handled by asyncpg connect_args")
            
            return db_url
            
        except Exception as e:
            logger.warning(f"Could not parse DATABASE_URL: {e}, using original")
            return db_url
    
    @classmethod
    def get_async_engine(cls):
        """Create async engine optimized for Railway/Supabase deployment - SWITCHED TO PSYCOPG"""
        # Fix DATABASE_URL encoding and SSL
        db_url = cls.fix_database_url()
        
        # CRITICAL CHANGE: Switch to psycopg driver instead of asyncpg
        if db_url.startswith('postgresql://'):
            db_url = db_url.replace('postgresql://', 'postgresql+psycopg://', 1)
        
        # Add SSL to URL for psycopg (not in connect_args)
        if 'supabase.com' in db_url:
            if '?' in db_url:
                db_url += '&sslmode=require'
            else:
                db_url += '?sslmode=require'
            logger.info("Using psycopg driver as PRIMARY due to asyncpg compatibility issues")
        
        # Psycopg connection arguments (different from asyncpg)
        connect_args = {
            "application_name": "monitor_legislativo_v4_railway_psycopg",
            "connect_timeout": cls.CONNECT_TIMEOUT,
        }
        
        logger.info("SWITCHED PRIMARY DRIVER: Using psycopg instead of asyncpg for Supabase compatibility")
        
        return create_async_engine(
            db_url,
            pool_size=cls.POOL_SIZE,
            max_overflow=cls.MAX_OVERFLOW,
            pool_timeout=cls.POOL_TIMEOUT,
            pool_recycle=cls.POOL_RECYCLE,
            echo=cls.ECHO_SQL,
            connect_args=connect_args,
            # Additional Railway optimizations
            pool_pre_ping=True,  # Validate connections before use
            pool_reset_on_return='commit',  # Clean up connections
        )
    
    @classmethod
    def get_session_factory(cls):
        """Create session factory"""
        engine = cls.get_async_engine() 
        return sessionmaker(
            bind=engine,
            class_=AsyncSession,
            expire_on_commit=False
        )


class DatabaseManager:
    """Lightweight database manager for academic deployment"""
    
    def __init__(self):
        self.engine = SupabaseConfig.get_async_engine()
        self.session_factory = SupabaseConfig.get_session_factory()
    
    async def test_direct_asyncpg_connection(self) -> bool:
        """CRITICAL: Test direct psycopg connection bypassing SQLAlchemy (SWITCHED FROM ASYNCPG)"""
        try:
            # Try direct psycopg connection instead of asyncpg
            import psycopg
            
            db_url = SupabaseConfig.DATABASE_URL
            if not db_url:
                logger.error("No DATABASE_URL available for direct connection test")
                return False
            
            logger.info("🔧 Testing DIRECT psycopg connection (bypassing SQLAlchemy)")
            
            # Parse the URL for direct psycopg connection
            parsed = urllib.parse.urlparse(db_url)
            
            # CRITICAL FIX: Decode password if it contains URL encoding
            password = parsed.password
            if password and ('%' in password):
                original_password = password
                password = urllib.parse.unquote(password)
                logger.info(f"Decoded URL-encoded password: {original_password} → {password}")
            else:
                logger.info("Password does not contain URL encoding")
            
            # Connection string for psycopg
            conn_string = f"host={parsed.hostname} port={parsed.port or 5432} dbname={parsed.path.lstrip('/')} user={parsed.username} password={password} sslmode=require"
            
            logger.info(f"Direct connection to: {parsed.hostname}:{parsed.port or 5432}")
            logger.info(f"Database: {parsed.path.lstrip('/')}")
            logger.info(f"Username: {parsed.username}")
            
            # Try direct connection with timeout
            conn = await asyncio.wait_for(
                psycopg.AsyncConnection.connect(conn_string),
                timeout=30
            )
            
            # Test basic query
            async with conn.cursor() as cur:
                await cur.execute("SELECT 1")
                result = await cur.fetchone()
                logger.info(f"✅ DIRECT psycopg connection successful! Result: {result[0]}")
                
                # Test PostgreSQL version
                await cur.execute("SELECT version()")
                version = await cur.fetchone()
                logger.info(f"✅ PostgreSQL version: {version[0][:100]}")
            
            await conn.close()
            return True
            
        except Exception as e:
            logger.error(f"❌ DIRECT psycopg connection failed: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            
            error_str = str(e).lower()
            if 'password' in error_str or 'authentication' in error_str:
                logger.error("🔍 AUTHENTICATION ISSUE - check password decoding")
            elif 'ssl' in error_str:
                logger.error("🔍 SSL/TLS handshake issue - certificate problem")
            elif 'connection' in error_str:
                logger.error("🔍 Network connectivity issue")
            
            # Fallback: try asyncpg as secondary test
            logger.info("🔄 Falling back to asyncpg test...")
            try:
                import asyncpg
                
                parsed = urllib.parse.urlparse(SupabaseConfig.DATABASE_URL)
                password = parsed.password
                if password and ('%' in password):
                    password = urllib.parse.unquote(password)
                
                import ssl
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                
                conn = await asyncpg.connect(
                    host=parsed.hostname,
                    port=parsed.port or 5432,
                    database=parsed.path.lstrip('/'),
                    user=parsed.username,
                    password=password,
                    ssl=ssl_context
                )
                
                result = await conn.fetchval("SELECT 1")
                await conn.close()
                logger.info("✅ Fallback asyncpg connection successful!")
                return True
                
            except Exception as fallback_e:
                logger.error(f"❌ Fallback asyncpg also failed: {fallback_e}")
                return False
            
            return False
    
    async def test_connection(self) -> bool:
        """Test database connection with retry logic and detailed error reporting"""
        max_retries = 3
        retry_delay = 2
        
        # FIRST: Try direct asyncpg connection to isolate the issue
        logger.info("🔬 DIAGNOSTIC: Testing direct asyncpg connection first...")
        direct_success = await self.test_direct_asyncpg_connection()
        
        if direct_success:
            logger.info("✅ Direct asyncpg works - issue is in SQLAlchemy layer")
        else:
            logger.error("❌ Direct asyncpg fails - issue is in asyncpg/Supabase compatibility")
        
        # SECOND: Try SQLAlchemy connection
        for attempt in range(max_retries):
            try:
                logger.info(f"Database connection attempt {attempt + 1}/{max_retries} (via SQLAlchemy)")
                
                async with self.session_factory() as session:
                    result = await session.execute(text("SELECT 1"))
                    logger.info("✅ Database connection successful")
                    return result.scalar() == 1
                    
            except ImportError as e:
                logger.error(f"Missing dependency: {e}")
                logger.error("Please install: pip install sqlalchemy[asyncio] asyncpg")
                return False
                
            except (OperationalError, SQLTimeoutError, OSError) as e:
                error_msg = str(e)
                error_type = type(e).__name__
                
                # Enhanced error logging with network details
                logger.error(f"Database connection attempt {attempt + 1} failed: {error_msg}")
                logger.error(f"Error type: {error_type}")
                
                # Specific error analysis
                if "errno 101" in error_msg.lower() or "network is unreachable" in error_msg.lower():
                    logger.error("🌐 NETWORK ISSUE: Railway cannot reach Supabase")
                    logger.error("Possible causes:")
                    logger.error("  - Supabase project is paused/inactive")
                    logger.error("  - Railway IP blocked by Supabase firewall")
                    logger.error("  - DNS resolution issues")
                    logger.error("  - Supabase service outage")
                elif "ssl" in error_msg.lower():
                    logger.error("🔒 SSL ISSUE: SSL configuration problem")
                    logger.error("Check SSL mode and certificates")
                elif "authentication" in error_msg.lower() or "password" in error_msg.lower() or "object has no attribute 'group'" in error_msg.lower():
                    logger.error("🔐 AUTH ISSUE: Database authentication failed")
                    logger.error("Check DATABASE_URL credentials and format")
                    logger.error("For Supabase pooler, ensure username format: postgres.PROJECT_REF")
                    logger.error("For direct connection, use: postgres")
                    
                    # CRITICAL: Check if direct asyncpg worked but SQLAlchemy failed
                    if direct_success:
                        logger.error("🎯 SOLUTION FOUND: Direct asyncpg works, SQLAlchemy fails")
                        logger.error("🎯 Try switching to psycopg2 driver or different asyncpg version")
                    
                elif "timeout" in error_msg.lower():
                    logger.error("⏱️ TIMEOUT ISSUE: Connection timed out")
                    logger.error("Network latency or Supabase overloaded")
                else:
                    logger.error(f"🔧 OTHER ISSUE: {error_msg}")
                
                # Log connection details for debugging
                db_url = SupabaseConfig.DATABASE_URL
                if db_url:
                    parsed = urllib.parse.urlparse(db_url)
                    logger.error(f"Target host: {parsed.hostname}")
                    logger.error(f"Target port: {parsed.port or 5432}")
                    logger.error(f"Database: {parsed.path.lstrip('/')}")
                
                # Retry logic
                if attempt < max_retries - 1:
                    logger.info(f"Retrying in {retry_delay} seconds...")
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                else:
                    logger.error("❌ All connection attempts failed")
                    return False
                    
            except Exception as e:
                logger.error(f"Unexpected database error: {e}")
                logger.error(f"Error type: {type(e).__name__}")
                return False
        
        return False
    
    async def initialize_schema(self) -> bool:
        """Initialize basic schema for academic use"""
        try:
            async with self.session_factory() as session:
                # Create basic tables for caching and session data
                await session.execute(text("""
                    CREATE TABLE IF NOT EXISTS cache_entries (
                        key VARCHAR(255) PRIMARY KEY,
                        value TEXT,
                        expires_at TIMESTAMP WITH TIME ZONE,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                    )
                """))
                
                await session.execute(text("""
                    CREATE TABLE IF NOT EXISTS export_cache (
                        id SERIAL PRIMARY KEY,
                        cache_key VARCHAR(255) UNIQUE,
                        format VARCHAR(50),
                        content TEXT,
                        metadata JSONB,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                        expires_at TIMESTAMP WITH TIME ZONE
                    )
                """))
                
                await session.execute(text("""
                    CREATE TABLE IF NOT EXISTS search_history (
                        id SERIAL PRIMARY KEY,
                        query_hash VARCHAR(64),
                        query_params JSONB,
                        result_count INTEGER,
                        execution_time_ms INTEGER,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                    )
                """))
                
                # Create indexes for performance
                await session.execute(text("""
                    CREATE INDEX IF NOT EXISTS idx_cache_expires 
                    ON cache_entries(expires_at)
                """))
                
                await session.execute(text("""
                    CREATE INDEX IF NOT EXISTS idx_export_cache_key 
                    ON export_cache(cache_key)
                """))
                
                await session.execute(text("""
                    CREATE INDEX IF NOT EXISTS idx_search_query_hash 
                    ON search_history(query_hash)
                """))
                
                await session.commit()
                logger.info("Database schema initialized successfully")
                return True
                
        except Exception as e:
            logger.error(f"Schema initialization failed: {e}")
            return False
    
    async def cleanup_expired_cache(self) -> int:
        """Clean up expired cache entries"""
        try:
            async with self.session_factory() as session:
                result = await session.execute(text("""
                    DELETE FROM cache_entries 
                    WHERE expires_at < NOW()
                """))
                
                result2 = await session.execute(text("""
                    DELETE FROM export_cache 
                    WHERE expires_at < NOW()
                """))
                
                await session.commit()
                
                total_deleted = result.rowcount + result2.rowcount
                logger.info(f"Cleaned up {total_deleted} expired cache entries")
                return total_deleted
                
        except Exception as e:
            logger.error(f"Cache cleanup failed: {e}")
            return 0
    
    async def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        try:
            async with self.session_factory() as session:
                # Cache entries stats
                cache_result = await session.execute(text("""
                    SELECT 
                        COUNT(*) as total_entries,
                        COUNT(*) FILTER (WHERE expires_at > NOW()) as active_entries,
                        COUNT(*) FILTER (WHERE expires_at <= NOW()) as expired_entries
                    FROM cache_entries
                """))
                
                # Export cache stats  
                export_result = await session.execute(text("""
                    SELECT 
                        COUNT(*) as total_exports,
                        COUNT(DISTINCT format) as unique_formats
                    FROM export_cache 
                    WHERE expires_at > NOW()
                """))
                
                # Search history stats
                search_result = await session.execute(text("""
                    SELECT 
                        COUNT(*) as total_searches,
                        AVG(execution_time_ms) as avg_execution_time,
                        AVG(result_count) as avg_result_count
                    FROM search_history 
                    WHERE created_at > NOW() - INTERVAL '24 hours'
                """))
                
                cache_row = cache_result.fetchone()
                export_row = export_result.fetchone()
                search_row = search_result.fetchone()
                
                return {
                    "cache": {
                        "total_entries": cache_row[0] if cache_row else 0,
                        "active_entries": cache_row[1] if cache_row else 0,
                        "expired_entries": cache_row[2] if cache_row else 0
                    },
                    "exports": {
                        "total_cached": export_row[0] if export_row else 0,
                        "unique_formats": export_row[1] if export_row else 0
                    },
                    "searches": {
                        "total_24h": search_row[0] if search_row else 0,
                        "avg_execution_ms": float(search_row[1]) if search_row and search_row[1] else 0,
                        "avg_results": float(search_row[2]) if search_row and search_row[2] else 0
                    }
                }
                
        except Exception as e:
            logger.error(f"Failed to get cache stats: {e}")
            return {}
    
    async def close(self):
        """Close database connections"""
        await self.engine.dispose()


# Singleton instance for academic deployment
_db_manager: Optional[DatabaseManager] = None


async def get_database_manager() -> DatabaseManager:
    """Get or create database manager singleton"""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
        # Test connection and initialize schema
        if await _db_manager.test_connection():
            await _db_manager.initialize_schema()
        else:
            logger.warning("Database connection failed - some features may not work")
    return _db_manager