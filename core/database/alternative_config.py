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
    
    DATABASE_URL = os.getenv('DATABASE_URL')
    
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
        
        # Return None if no DATABASE_URL is configured
        if not db_url:
            logger.warning("No DATABASE_URL configured for psycopg engine")
            return None
        
        # Validate DATABASE_URL to prevent invalid connection attempts
        if 'db.supabase.co' in db_url:
            logger.error("Invalid DATABASE_URL detected: db.supabase.co is not a valid Supabase host")
            logger.error("Please use your actual Supabase project URL or leave DATABASE_URL unset for fallback mode")
            return None
        
        # FIXED: Properly handle password encoding for psycopg
        parsed = urllib.parse.urlparse(db_url)
        if parsed.password and ('%' in parsed.password):
            # URL decode the password for psycopg
            decoded_password = urllib.parse.unquote(parsed.password)
            
            # Reconstruct URL with decoded password for psycopg
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
            logger.info("Fixed password encoding for psycopg driver")
        
        # Convert to psycopg format (async psycopg)
        if db_url.startswith('postgresql://'):
            db_url = db_url.replace('postgresql://', 'postgresql+psycopg://', 1)
        
        # FIXED: Use proper psycopg connection arguments (no sslmode in connect_args)
        connect_args = {
            "application_name": "monitor_legislativo_v4_psycopg",
            "connect_timeout": cls.CONNECT_TIMEOUT,
        }
        
        # Add SSL to the URL itself for psycopg
        if 'supabase.com' in db_url:
            if '?' in db_url:
                db_url += '&sslmode=require'
            else:
                db_url += '?sslmode=require'
            logger.info("Added SSL mode to URL for psycopg driver")
        
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
        
        # Return None if no DATABASE_URL is configured
        if not db_url:
            logger.warning("No DATABASE_URL configured for asyncpg engine")
            return None
        
        # Validate DATABASE_URL to prevent invalid connection attempts
        if 'db.supabase.co' in db_url:
            logger.error("Invalid DATABASE_URL detected: db.supabase.co is not a valid Supabase host")
            return None
        
        if db_url.startswith('postgresql://'):
            db_url = db_url.replace('postgresql://', 'postgresql+asyncpg://', 1)
        
        # FIXED: Simplified connection arguments for asyncpg compatibility (no sslmode)
        connect_args = {
            "server_settings": {
                "application_name": "monitor_legislativo_v4_asyncpg_compat",
            },
            "command_timeout": cls.COMMAND_TIMEOUT,
            "prepared_statement_cache_size": 0,
            # REMOVED: sslmode parameter - invalid for asyncpg
        }
        
        # FIXED: Minimal SSL context for compatibility
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
        
        # Check if DATABASE_URL is configured first
        if not AlternativeSupabaseConfig.DATABASE_URL:
            logger.info("No DATABASE_URL configured - skipping alternative database initialization")
            return False
        
        # Method 1: Try improved asyncpg configuration
        try:
            logger.info("🔧 Trying Method 1: Improved asyncpg configuration")
            self.engine = AlternativeSupabaseConfig.get_asyncpg_engine_v28()
            if not self.engine:
                logger.error("❌ Method 1 failed: Could not create asyncpg engine")
                raise Exception("Engine creation failed")
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
            if not self.engine:
                logger.error("❌ Method 2 failed: Could not create psycopg engine")
                raise Exception("Engine creation failed")
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
            
            # CRITICAL FIX: Decode password if it contains URL encoding
            password = parsed.password
            if password and ('%' in password):
                password = urllib.parse.unquote(password)
                logger.info("Decoded URL-encoded password for direct connection test")
            
            # FIXED: Proper SSL context for direct asyncpg connection
            import ssl
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE  # Disable cert verification
            
            # FIXED: Ultra-minimal connection parameters (no sslmode)
            conn = await asyncpg.connect(
                host=parsed.hostname,
                port=parsed.port or 5432,
                database=parsed.path.lstrip('/'),
                user=parsed.username,
                password=password,  # Use decoded password
                ssl=ssl_context  # Use SSL context instead of 'require'
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