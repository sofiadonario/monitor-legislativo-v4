"""
Tenant Database Management for Monitor Legislativo v4
Handles database isolation and connection pooling

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import logging
from typing import Dict, Optional, Any, List
from contextlib import asynccontextmanager
import asyncpg
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, AsyncEngine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text
import os

from .tenant_model import Tenant, TenantIsolationLevel
from .tenant_manager import get_current_tenant
from ..config.config import config

logger = logging.getLogger(__name__)

class TenantConnectionPool:
    """Manages database connections for tenants"""
    
    def __init__(self):
        self.engines: Dict[str, AsyncEngine] = {}
        self.session_makers: Dict[str, sessionmaker] = {}
        self.pools: Dict[str, asyncpg.Pool] = {}
        
    async def get_engine(self, tenant: Tenant) -> AsyncEngine:
        """Get SQLAlchemy engine for tenant"""
        engine_key = self._get_engine_key(tenant)
        
        if engine_key not in self.engines:
            # Create new engine
            db_url = self._get_database_url(tenant)
            
            engine = create_async_engine(
                db_url,
                pool_size=tenant.limits.max_db_connections // 2,
                max_overflow=tenant.limits.max_db_connections // 2,
                pool_pre_ping=True,
                echo=False
            )
            
            self.engines[engine_key] = engine
            
            # Create session maker
            self.session_makers[engine_key] = sessionmaker(
                bind=engine,
                class_=AsyncSession,
                expire_on_commit=False
            )
            
            logger.info(f"Created database engine for tenant {tenant.id}")
            
        return self.engines[engine_key]
    
    async def get_pool(self, tenant: Tenant) -> asyncpg.Pool:
        """Get asyncpg connection pool for tenant"""
        pool_key = self._get_engine_key(tenant)
        
        if pool_key not in self.pools:
            # Parse database URL
            db_config = self._parse_database_url(tenant)
            
            # Create pool
            pool = await asyncpg.create_pool(
                host=db_config["host"],
                port=db_config["port"],
                user=db_config["user"],
                password=db_config["password"],
                database=db_config["database"],
                min_size=2,
                max_size=tenant.limits.max_db_connections,
                command_timeout=60
            )
            
            self.pools[pool_key] = pool
            
            logger.info(f"Created connection pool for tenant {tenant.id}")
            
        return self.pools[pool_key]
    
    @asynccontextmanager
    async def get_session(self, tenant: Tenant) -> AsyncSession:
        """Get database session for tenant"""
        engine = await self.get_engine(tenant)
        session_maker = self.session_makers[self._get_engine_key(tenant)]
        
        async with session_maker() as session:
            # Set schema if needed
            if tenant.isolation_level == TenantIsolationLevel.SCHEMA:
                await session.execute(
                    text(f"SET search_path TO {tenant.get_schema_name()}, public")
                )
                
            yield session
    
    @asynccontextmanager
    async def get_connection(self, tenant: Tenant) -> asyncpg.Connection:
        """Get raw database connection for tenant"""
        pool = await self.get_pool(tenant)
        
        async with pool.acquire() as connection:
            # Set schema if needed
            if tenant.isolation_level == TenantIsolationLevel.SCHEMA:
                await connection.execute(
                    f"SET search_path TO {tenant.get_schema_name()}, public"
                )
                
            yield connection
    
    def _get_engine_key(self, tenant: Tenant) -> str:
        """Get unique key for tenant engine"""
        if tenant.isolation_level == TenantIsolationLevel.DATABASE:
            return f"{tenant.id}_db"
        elif tenant.isolation_level == TenantIsolationLevel.SCHEMA:
            return f"main_{tenant.id}_schema"
        else:
            return "main_shared"
    
    def _get_database_url(self, tenant: Tenant) -> str:
        """Get database URL for tenant"""
        base_url = config.database_url
        
        if tenant.isolation_level == TenantIsolationLevel.DATABASE:
            # Replace database name
            db_name = tenant.get_database_name()
            return base_url.replace("/legislativo", f"/{db_name}")
        else:
            # Use main database
            return base_url
    
    def _parse_database_url(self, tenant: Tenant) -> Dict[str, Any]:
        """Parse database URL into components"""
        url = self._get_database_url(tenant)
        
        # Simple parsing (in production, use proper URL parser)
        # postgresql+asyncpg://user:password@host:port/database
        parts = url.split("://")[1].split("@")
        auth = parts[0].split(":")
        host_db = parts[1].split("/")
        host_port = host_db[0].split(":")
        
        return {
            "user": auth[0],
            "password": auth[1] if len(auth) > 1 else "",
            "host": host_port[0],
            "port": int(host_port[1]) if len(host_port) > 1 else 5432,
            "database": host_db[1]
        }
    
    async def close_all(self) -> None:
        """Close all connections"""
        # Close SQLAlchemy engines
        for engine in self.engines.values():
            await engine.dispose()
            
        # Close asyncpg pools
        for pool in self.pools.values():
            await pool.close()
            
        self.engines.clear()
        self.session_makers.clear()
        self.pools.clear()

class TenantDatabase:
    """Database operations with tenant context"""
    
    def __init__(self):
        self.connection_pool = TenantConnectionPool()
        
    async def create_schema(self, tenant: Tenant) -> bool:
        """Create schema for tenant"""
        if tenant.isolation_level != TenantIsolationLevel.SCHEMA:
            return True
            
        schema_name = tenant.get_schema_name()
        
        try:
            # Use admin connection to create schema
            async with self.connection_pool.get_connection(tenant) as conn:
                # Create schema
                await conn.execute(f"CREATE SCHEMA IF NOT EXISTS {schema_name}")
                
                # Grant permissions
                await conn.execute(
                    f"GRANT ALL ON SCHEMA {schema_name} TO {tenant.slug}_user"
                )
                
                # Create tables in schema
                await self._create_tenant_tables(conn, schema_name)
                
            logger.info(f"Created schema {schema_name} for tenant {tenant.id}")
            return True
            
        except Exception as e:
            logger.error(f"Error creating schema for tenant {tenant.id}: {e}")
            return False
    
    async def create_database(self, tenant: Tenant) -> bool:
        """Create database for tenant"""
        if tenant.isolation_level != TenantIsolationLevel.DATABASE:
            return True
            
        db_name = tenant.get_database_name()
        
        try:
            # Use admin connection to create database
            # This requires connecting to postgres/template1 database
            admin_url = config.database_url.replace("/legislativo", "/postgres")
            
            # Create database (simplified - in production use proper admin connection)
            logger.info(f"Would create database {db_name} for tenant {tenant.id}")
            
            # Create user for tenant
            logger.info(f"Would create user {tenant.slug}_user for tenant {tenant.id}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error creating database for tenant {tenant.id}: {e}")
            return False
    
    async def migrate_tenant(self, tenant: Tenant) -> bool:
        """Run migrations for tenant"""
        try:
            async with self.connection_pool.get_session(tenant) as session:
                # Run migrations specific to tenant
                # In production, use Alembic or similar
                logger.info(f"Running migrations for tenant {tenant.id}")
                
                # Example: ensure tables exist
                await self._ensure_tenant_tables(session, tenant)
                
            return True
            
        except Exception as e:
            logger.error(f"Error migrating tenant {tenant.id}: {e}")
            return False
    
    async def _create_tenant_tables(self, conn: asyncpg.Connection, schema: str) -> None:
        """Create tables in tenant schema"""
        # Create tenant-specific tables
        tables = [
            f"""
            CREATE TABLE IF NOT EXISTS {schema}.propositions (
                id SERIAL PRIMARY KEY,
                source VARCHAR(50),
                type VARCHAR(100),
                number VARCHAR(50),
                year INTEGER,
                title TEXT,
                summary TEXT,
                status VARCHAR(100),
                author VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            f"""
            CREATE TABLE IF NOT EXISTS {schema}.users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE,
                name VARCHAR(255),
                role VARCHAR(50),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            f"""
            CREATE TABLE IF NOT EXISTS {schema}.alerts (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES {schema}.users(id),
                name VARCHAR(255),
                query TEXT,
                frequency VARCHAR(50),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        ]
        
        for table_sql in tables:
            await conn.execute(table_sql)
    
    async def _ensure_tenant_tables(self, session: AsyncSession, tenant: Tenant) -> None:
        """Ensure tenant tables exist"""
        # Check if tables exist and create if needed
        # This is a simplified version
        pass
    
    @asynccontextmanager
    async def tenant_session(self, tenant: Optional[Tenant] = None):
        """Get session with tenant context"""
        if not tenant:
            tenant = get_current_tenant()
            
        if not tenant:
            raise ValueError("No tenant context available")
            
        async with self.connection_pool.get_session(tenant) as session:
            yield session
    
    async def execute_query(self, 
                          query: str, 
                          params: Optional[Dict[str, Any]] = None,
                          tenant: Optional[Tenant] = None) -> List[Dict[str, Any]]:
        """Execute query in tenant context"""
        if not tenant:
            tenant = get_current_tenant()
            
        if not tenant:
            raise ValueError("No tenant context available")
            
        async with self.connection_pool.get_connection(tenant) as conn:
            # Execute query
            rows = await conn.fetch(query, *(params or {}).values())
            
            # Convert to dictionaries
            return [dict(row) for row in rows]

# Global instances
tenant_database = TenantDatabase()

# Helper functions
async def get_tenant_db() -> AsyncSession:
    """Get database session for current tenant"""
    tenant = get_current_tenant()
    if not tenant:
        raise ValueError("No tenant context available")
        
    async with tenant_database.tenant_session(tenant) as session:
        yield session

async def execute_in_tenant_context(
    func: Callable,
    tenant: Tenant,
    *args,
    **kwargs
) -> Any:
    """Execute function in tenant database context"""
    from .tenant_manager import TenantContext
    
    with TenantContext(tenant):
        async with tenant_database.tenant_session(tenant) as session:
            # Add session to kwargs if function expects it
            import inspect
            sig = inspect.signature(func)
            if 'session' in sig.parameters:
                kwargs['session'] = session
                
            if asyncio.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            else:
                return func(*args, **kwargs)