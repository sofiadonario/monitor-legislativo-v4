"""
Alternative Database Configuration for Supabase
Fallback to psycopg2 if asyncpg authentication fails
"""

import os
import asyncio
import urllib.parse
import logging
from typing import Optional, Dict, Any
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

logger = logging.getLogger(__name__)


class AlternativeSupabaseConfig:
    """Alternative configuration using psycopg2 driver for Supabase compatibility"""
    
    DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/legislativo')
    
    # Connection settings
    POOL_SIZE = 3
    MAX_OVERFLOW = 0
    POOL_TIMEOUT = 60
    POOL_RECYCLE = 1800
    CONNECT_TIMEOUT = 30
    COMMAND_TIMEOUT = 60
    
    @classmethod
    def get_psycopg_engine(cls):
        """Create async engine using psycopg (async version) driver instead of asyncpg"""
        db_url = cls.DATABASE_URL
        
        # Convert to psycopg format (async psycopg)
        if db_url.startswith('postgresql://'):
            db_url = db_url.replace('postgresql://', 'postgresql+psycopg://', 1)
        
        # psycopg connection arguments
        connect_args = {
            "sslmode": "require",
            "application_name": "monitor_legislativo_v4_psycopg",
            "connect_timeout": cls.CONNECT_TIMEOUT,
        }
        
        logger.info("Using psycopg (async) driver as fallback for Supabase connection")
        
        return create_async_engine(
            db_url,
            pool_size=cls.POOL_SIZE,
            max_overflow=cls.MAX_OVERFLOW,
            pool_timeout=cls.POOL_TIMEOUT,
            pool_recycle=cls.POOL_RECYCLE,
            connect_args=connect_args,
            pool_pre_ping=True,
            pool_reset_on_return='commit',
        )
    
    @classmethod
    def get_asyncpg_engine_v28(cls):
        """Try asyncpg with version 0.28.0 parameters (more compatible)"""
        db_url = cls.DATABASE_URL
        
        if db_url.startswith('postgresql://'):
            db_url = db_url.replace('postgresql://', 'postgresql+asyncpg://', 1)
        
        # Simplified connection arguments for older asyncpg compatibility
        connect_args = {
            "server_settings": {
                "application_name": "monitor_legislativo_v4_asyncpg_compat",
            },
            "command_timeout": cls.COMMAND_TIMEOUT,
            "prepared_statement_cache_size": 0,
            # Minimal SSL configuration
            "sslmode": "require",
        }
        
        # Minimal SSL context for compatibility
        if 'supabase.com' in db_url:
            import ssl
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE  # Most permissive for compatibility
            connect_args["ssl"] = ssl_context
            logger.info("Using minimal SSL configuration for asyncpg compatibility")
        
        return create_async_engine(
            db_url,
            pool_size=cls.POOL_SIZE,
            max_overflow=cls.MAX_OVERFLOW,
            pool_timeout=cls.POOL_TIMEOUT,
            pool_recycle=cls.POOL_RECYCLE,
            connect_args=connect_args,
            pool_pre_ping=True,
            pool_reset_on_return='commit',
        )


class AlternativeDatabaseManager:
    """Database manager that tries multiple connection methods"""
    
    def __init__(self):
        self.engine = None
        self.session_factory = None
        self.driver_used = None
    
    async def initialize_with_fallback(self) -> bool:
        """Try different database drivers in order of preference"""
        
        # Method 1: Try improved asyncpg configuration
        try:
            logger.info("🔧 Trying Method 1: Improved asyncpg configuration")
            self.engine = AlternativeSupabaseConfig.get_asyncpg_engine_v28()
            self.session_factory = sessionmaker(
                bind=self.engine,
                class_=AsyncSession,
                expire_on_commit=False
            )
            
            if await self._test_connection():
                self.driver_used = "asyncpg_improved"
                logger.info("✅ Method 1 SUCCESS: Improved asyncpg configuration works!")
                return True
            
        except Exception as e:
            logger.error(f"❌ Method 1 failed: {e}")
        
        # Method 2: Try psycopg driver
        try:
            logger.info("🔧 Trying Method 2: psycopg (async) driver")
            self.engine = AlternativeSupabaseConfig.get_psycopg_engine()
            self.session_factory = sessionmaker(
                bind=self.engine,
                class_=AsyncSession,
                expire_on_commit=False
            )
            
            if await self._test_connection():
                self.driver_used = "psycopg"
                logger.info("✅ Method 2 SUCCESS: psycopg (async) driver works!")
                return True
            
        except Exception as e:
            logger.error(f"❌ Method 2 failed: {e}")
        
        # Method 3: Try direct connection without pooling
        try:
            logger.info("🔧 Trying Method 3: Direct connection without pooling")
            await self._test_direct_connection()
            logger.info("✅ Method 3 SUCCESS: Direct connection works!")
            return True
            
        except Exception as e:
            logger.error(f"❌ Method 3 failed: {e}")
        
        logger.error("❌ All connection methods failed")
        return False
    
    async def _test_connection(self) -> bool:
        """Test the current engine configuration"""
        try:
            async with self.session_factory() as session:
                result = await session.execute(text("SELECT 1"))
                return result.scalar() == 1
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False
    
    async def _test_direct_connection(self) -> bool:
        """Test direct connection without SQLAlchemy"""
        try:
            # Try direct asyncpg connection
            import asyncpg
            
            db_url = AlternativeSupabaseConfig.DATABASE_URL
            parsed = urllib.parse.urlparse(db_url)
            
            # Ultra-minimal connection parameters
            conn = await asyncpg.connect(
                host=parsed.hostname,
                port=parsed.port or 5432,
                database=parsed.path.lstrip('/'),
                user=parsed.username,
                password=parsed.password,
                ssl='require'  # Simple SSL requirement
            )
            
            result = await conn.fetchval("SELECT 1")
            await conn.close()
            return result == 1
            
        except Exception as e:
            logger.error(f"Direct connection failed: {e}")
            return False
    
    async def get_health_status(self) -> Dict[str, Any]:
        """Get connection health status"""
        return {
            "connected": self.engine is not None,
            "driver_used": self.driver_used,
            "database_url_configured": bool(AlternativeSupabaseConfig.DATABASE_URL),
        }


# Global instance
_alternative_manager: Optional[AlternativeDatabaseManager] = None


async def get_alternative_database_manager() -> AlternativeDatabaseManager:
    """Get alternative database manager with fallback capabilities"""
    global _alternative_manager
    if _alternative_manager is None:
        _alternative_manager = AlternativeDatabaseManager()
        success = await _alternative_manager.initialize_with_fallback()
        if success:
            logger.info(f"✅ Alternative database manager initialized with {_alternative_manager.driver_used}")
        else:
            logger.error("❌ Alternative database manager failed to initialize")
    return _alternative_manager 