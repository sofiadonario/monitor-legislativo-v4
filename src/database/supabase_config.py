import os
from typing import Optional, Dict, Any
import logging
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, TimeoutError as SQLTimeoutError
import ssl
import re

from ..config.env_loader import EnvironmentConfig

Base = declarative_base()
logger = logging.getLogger(__name__)


class DatabaseManager:
    _instance = None
    _engine = None
    _session_factory = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseManager, cls).__new__(cls)
            try:
                db_url = EnvironmentConfig.DATABASE_URL
                if not db_url:
                    raise ValueError("DATABASE_URL environment variable is not set.")
                
                # AGGRESSIVE FIX: Manually remove any sslmode from the URL string
                db_url = re.sub(r'[?&]sslmode=[^&]*', '', db_url)

                #
                # THIS IS THE FIX:
                # Force the URL to use the asyncpg driver, which is what
                # SQLAlchemy's asyncio extension requires.
                #
                if db_url.startswith("postgresql://"):
                    db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)

                # Create a permissive SSL context for Supabase
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

                cls._engine = create_async_engine(
                    db_url,
                    pool_pre_ping=True,
                    pool_recycle=3600,
                    connect_args={
                        "server_settings": {
                            "application_name": "MonitorLegislativoV4"
                        },
                        "ssl": ssl_context
                    }
                )
                cls._session_factory = async_sessionmaker(
                    bind=cls._engine,
                    expire_on_commit=False,
                    class_=AsyncSession
                )
                logger.info("Database engine and session factory initialized successfully.")
            except Exception as e:
                logger.error(f"Failed to initialize database engine: {e}", exc_info=True)
                cls._instance = None # Ensure instance is not created on failure
                raise
        return cls._instance

    @property
    def engine(self):
        return self._engine

    @property
    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        return self._session_factory

    async def test_connection(self) -> bool:
        if not self._session_factory:
            logger.error("Database connection test failed: session factory not initialized.")
            return False
        try:
            async with self._session_factory() as session:
                result = await session.execute(text("SELECT 1"))
                return result.scalar() == 1
        except (OperationalError, SQLTimeoutError, ConnectionRefusedError) as e:
            logger.error(f"Database connection test failed: {e}", exc_info=True)
            return False
        except Exception as e:
            logger.error(f"An unexpected error occurred during database connection test: {e}", exc_info=True)
            return False

    async def close(self):
        if self._engine:
            await self._engine.dispose()
            logger.info("Database connection pool disposed.")


async def get_database_manager() -> DatabaseManager:
    """Dependency to get the database manager instance"""
    try:
        return DatabaseManager()
    except Exception as e:
        logger.error(f"Could not provide DatabaseManager dependency: {e}")
        # In a real app, you might want to raise a specific HTTPException
        # to indicate that the database is unavailable.
        return None
