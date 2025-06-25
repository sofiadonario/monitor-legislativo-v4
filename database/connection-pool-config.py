# Advanced Connection Pool Configuration for Monitor Legislativo v4
# Phase 4 Week 14: Database optimization with intelligent connection pooling
# Supports PostgreSQL with async operations and connection health monitoring

import asyncio
import asyncpg
import logging
import time
import json
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
import os
from enum import Enum

# Configuration and monitoring
logger = logging.getLogger(__name__)

class PoolHealth(Enum):
    HEALTHY = "healthy"
    WARNING = "warning" 
    CRITICAL = "critical"
    UNKNOWN = "unknown"

@dataclass
class PoolMetrics:
    """Connection pool performance metrics"""
    total_connections: int
    active_connections: int
    idle_connections: int
    waiting_connections: int
    total_queries: int
    slow_queries: int
    failed_queries: int
    avg_query_time: float
    pool_health: PoolHealth
    last_health_check: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary for JSON serialization"""
        result = asdict(self)
        result['pool_health'] = self.pool_health.value
        result['last_health_check'] = self.last_health_check.isoformat()
        return result

@dataclass
class ConnectionConfig:
    """Database connection configuration"""
    host: str = "localhost"
    port: int = 5432
    database: str = "monitor_legislativo"
    user: str = "postgres" 
    password: str = ""
    
    # Connection pool settings
    min_size: int = 5
    max_size: int = 20
    max_queries: int = 50000
    max_inactive_connection_lifetime: float = 300.0  # 5 minutes
    
    # Query performance settings
    command_timeout: float = 60.0
    server_settings: Dict[str, str] = None
    
    # Health monitoring
    health_check_interval: int = 30  # seconds
    slow_query_threshold: float = 1.0  # seconds
    
    def __post_init__(self):
        if self.server_settings is None:
            self.server_settings = {
                'application_name': 'monitor_legislativo_v4',
                'tcp_keepalives_idle': '300',
                'tcp_keepalives_interval': '30', 
                'tcp_keepalives_count': '3',
                'statement_timeout': '60000',  # 60 seconds
                'lock_timeout': '30000',       # 30 seconds
                'idle_in_transaction_session_timeout': '120000'  # 2 minutes
            }

class AdvancedConnectionPool:
    """
    Advanced PostgreSQL connection pool with health monitoring,
    automatic failover, and performance optimization for Monitor Legislativo v4
    """
    
    def __init__(self, config: ConnectionConfig):
        self.config = config
        self.pool: Optional[asyncpg.Pool] = None
        self.metrics = PoolMetrics(
            total_connections=0,
            active_connections=0,
            idle_connections=0,
            waiting_connections=0,
            total_queries=0,
            slow_queries=0,
            failed_queries=0,
            avg_query_time=0.0,
            pool_health=PoolHealth.UNKNOWN,
            last_health_check=datetime.now()
        )
        self.query_times: List[float] = []
        self.is_monitoring = False
        self._health_check_task: Optional[asyncio.Task] = None
        
    async def initialize(self) -> None:
        """Initialize the connection pool with optimized settings"""
        try:
            logger.info("Initializing advanced connection pool...")
            
            # Connection factory for custom connection setup
            async def connection_factory(dsn: str):
                conn = await asyncpg.connect(dsn)
                
                # Set connection-specific optimizations
                await conn.execute("SET TIME ZONE 'America/Sao_Paulo'")
                await conn.execute("SET default_text_search_config = 'portuguese'")
                await conn.execute("SET shared_preload_libraries = 'pg_stat_statements'")
                
                # Enable query logging for slow queries
                await conn.execute(f"SET log_min_duration_statement = {int(self.config.slow_query_threshold * 1000)}")
                
                return conn
            
            # Create connection pool
            self.pool = await asyncpg.create_pool(
                host=self.config.host,
                port=self.config.port,
                database=self.config.database,
                user=self.config.user,
                password=self.config.password,
                min_size=self.config.min_size,
                max_size=self.config.max_size,
                max_queries=self.config.max_queries,
                max_inactive_connection_lifetime=self.config.max_inactive_connection_lifetime,
                command_timeout=self.config.command_timeout,
                server_settings=self.config.server_settings,
                init=self._init_connection
            )
            
            # Start health monitoring
            await self.start_monitoring()
            
            logger.info(f"Connection pool initialized with {self.config.min_size}-{self.config.max_size} connections")
            
        except Exception as e:
            logger.error(f"Failed to initialize connection pool: {e}")
            raise
    
    async def _init_connection(self, conn: asyncpg.Connection) -> None:
        """Initialize individual connections with Monitor Legislativo specific settings"""
        # Set Portuguese locale for text search
        await conn.execute("SET lc_messages = 'pt_BR.UTF-8'")
        await conn.execute("SET DateStyle = 'ISO, DMY'")
        
        # Optimize for our specific workload
        await conn.execute("SET random_page_cost = 1.1")  # SSD optimization
        await conn.execute("SET effective_cache_size = '1GB'")
        await conn.execute("SET work_mem = '4MB'")
        
        # Enable query plan caching
        await conn.execute("SET plan_cache_mode = 'auto'")
        
    async def start_monitoring(self) -> None:
        """Start background health monitoring"""
        if not self.is_monitoring:
            self.is_monitoring = True
            self._health_check_task = asyncio.create_task(self._health_monitor())
            logger.info("Connection pool health monitoring started")
    
    async def stop_monitoring(self) -> None:
        """Stop background health monitoring"""
        self.is_monitoring = False
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
        logger.info("Connection pool health monitoring stopped")
    
    async def _health_monitor(self) -> None:
        """Background task for monitoring pool health"""
        while self.is_monitoring:
            try:
                await self._update_metrics()
                await asyncio.sleep(self.config.health_check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health monitoring error: {e}")
                await asyncio.sleep(5)  # Brief pause before retry
    
    async def _update_metrics(self) -> None:
        """Update connection pool metrics"""
        if not self.pool:
            return
            
        # Update basic pool stats
        self.metrics.total_connections = self.pool.get_size()
        self.metrics.idle_connections = self.pool.get_idle_size()
        self.metrics.active_connections = self.metrics.total_connections - self.metrics.idle_connections
        
        # Calculate average query time
        if self.query_times:
            self.metrics.avg_query_time = sum(self.query_times) / len(self.query_times)
            
            # Keep only recent query times (last 100 queries)
            if len(self.query_times) > 100:
                self.query_times = self.query_times[-100:]
        
        # Determine pool health
        self.metrics.pool_health = self._calculate_health()
        self.metrics.last_health_check = datetime.now()
        
        # Log health status if not healthy
        if self.metrics.pool_health != PoolHealth.HEALTHY:
            logger.warning(f"Pool health: {self.metrics.pool_health.value}")
    
    def _calculate_health(self) -> PoolHealth:
        """Calculate overall pool health status"""
        # Check connection utilization
        utilization = self.metrics.active_connections / max(self.metrics.total_connections, 1)
        
        # Check query performance
        slow_query_rate = self.metrics.slow_queries / max(self.metrics.total_queries, 1)
        failed_query_rate = self.metrics.failed_queries / max(self.metrics.total_queries, 1)
        
        # Determine health based on metrics
        if utilization > 0.9 or slow_query_rate > 0.1 or failed_query_rate > 0.05:
            return PoolHealth.CRITICAL
        elif utilization > 0.7 or slow_query_rate > 0.05 or failed_query_rate > 0.02:
            return PoolHealth.WARNING
        elif self.pool and self.pool.get_size() > 0:
            return PoolHealth.HEALTHY
        else:
            return PoolHealth.UNKNOWN
    
    @asynccontextmanager
    async def acquire_connection(self):
        """Context manager for acquiring a connection with metrics tracking"""
        if not self.pool:
            raise RuntimeError("Connection pool not initialized")
        
        start_time = time.time()
        connection = None
        
        try:
            connection = await self.pool.acquire()
            yield connection
            
        except Exception as e:
            self.metrics.failed_queries += 1
            logger.error(f"Database operation failed: {e}")
            raise
            
        finally:
            if connection:
                await self.pool.release(connection)
            
            # Track query timing
            query_time = time.time() - start_time
            self.query_times.append(query_time)
            self.metrics.total_queries += 1
            
            if query_time > self.config.slow_query_threshold:
                self.metrics.slow_queries += 1
                logger.warning(f"Slow query detected: {query_time:.2f}s")
    
    async def execute_query(self, query: str, *args, **kwargs) -> Any:
        """Execute a query with connection pooling and error handling"""
        async with self.acquire_connection() as conn:
            return await conn.fetch(query, *args, **kwargs)
    
    async def execute_one(self, query: str, *args, **kwargs) -> Any:
        """Execute a query and return a single result"""
        async with self.acquire_connection() as conn:
            return await conn.fetchrow(query, *args, **kwargs)
    
    async def execute_command(self, query: str, *args, **kwargs) -> str:
        """Execute a command (INSERT/UPDATE/DELETE) and return status"""
        async with self.acquire_connection() as conn:
            return await conn.execute(query, *args, **kwargs)
    
    async def execute_transaction(self, queries: List[tuple]) -> List[Any]:
        """Execute multiple queries in a transaction"""
        async with self.acquire_connection() as conn:
            async with conn.transaction():
                results = []
                for query, args in queries:
                    if args:
                        result = await conn.fetch(query, *args)
                    else:
                        result = await conn.fetch(query)
                    results.append(result)
                return results
    
    async def test_connection(self) -> bool:
        """Test pool connectivity and performance"""
        try:
            async with self.acquire_connection() as conn:
                start_time = time.time()
                await conn.fetchval("SELECT 1")
                response_time = time.time() - start_time
                
                logger.info(f"Connection test successful: {response_time:.3f}s")
                return response_time < 1.0  # Consider healthy if < 1 second
                
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False
    
    async def get_pool_stats(self) -> Dict[str, Any]:
        """Get detailed pool statistics"""
        if not self.pool:
            return {"error": "Pool not initialized"}
        
        # Get database-level statistics
        db_stats = {}
        try:
            async with self.acquire_connection() as conn:
                # Active connections
                active_conns = await conn.fetchval("""
                    SELECT count(*) FROM pg_stat_activity 
                    WHERE state = 'active' AND application_name = 'monitor_legislativo_v4'
                """)
                
                # Database size
                db_size = await conn.fetchval("""
                    SELECT pg_size_pretty(pg_database_size(current_database()))
                """)
                
                # Recent activity
                recent_activity = await conn.fetch("""
                    SELECT query, state, query_start, state_change
                    FROM pg_stat_activity 
                    WHERE application_name = 'monitor_legislativo_v4'
                    AND state != 'idle'
                    ORDER BY query_start DESC
                    LIMIT 5
                """)
                
                db_stats = {
                    "active_db_connections": active_conns,
                    "database_size": db_size,
                    "recent_activity_count": len(recent_activity)
                }
                
        except Exception as e:
            logger.error(f"Failed to get database stats: {e}")
            db_stats = {"error": str(e)}
        
        return {
            "pool_metrics": self.metrics.to_dict(),
            "pool_config": {
                "min_size": self.config.min_size,
                "max_size": self.config.max_size,
                "max_queries": self.config.max_queries,
                "command_timeout": self.config.command_timeout
            },
            "database_stats": db_stats,
            "performance": {
                "recent_query_count": len(self.query_times),
                "avg_query_time_ms": round(self.metrics.avg_query_time * 1000, 2),
                "slow_query_threshold_ms": round(self.config.slow_query_threshold * 1000),
                "utilization_percent": round(
                    (self.metrics.active_connections / max(self.metrics.total_connections, 1)) * 100, 1
                )
            }
        }
    
    async def optimize_pool(self) -> Dict[str, Any]:
        """Automatically optimize pool settings based on current performance"""
        stats = await self.get_pool_stats()
        recommendations = []
        
        utilization = stats["performance"]["utilization_percent"]
        avg_query_time = self.metrics.avg_query_time
        
        # Analyze performance and make recommendations
        if utilization > 80:
            recommendations.append({
                "type": "scale_up",
                "message": f"High utilization ({utilization}%) - consider increasing max_size",
                "suggested_max_size": min(self.config.max_size + 5, 50)
            })
        
        if avg_query_time > 2.0:
            recommendations.append({
                "type": "performance",
                "message": f"Slow queries detected (avg: {avg_query_time:.2f}s) - check database indexes",
                "suggested_actions": ["review_indexes", "analyze_slow_queries"]
            })
        
        if self.metrics.failed_queries > 0:
            failure_rate = self.metrics.failed_queries / max(self.metrics.total_queries, 1)
            if failure_rate > 0.02:  # > 2% failure rate
                recommendations.append({
                    "type": "reliability", 
                    "message": f"High failure rate ({failure_rate:.1%}) - investigate connection issues",
                    "suggested_actions": ["check_network", "review_timeouts"]
                })
        
        return {
            "current_performance": stats,
            "recommendations": recommendations,
            "auto_optimization_available": len(recommendations) > 0
        }
    
    async def close(self) -> None:
        """Close the connection pool and cleanup resources"""
        await self.stop_monitoring()
        
        if self.pool:
            await self.pool.close()
            logger.info("Connection pool closed")

# Factory function for easy pool creation
async def create_optimized_pool(
    database_url: Optional[str] = None,
    config: Optional[ConnectionConfig] = None
) -> AdvancedConnectionPool:
    """Create an optimized connection pool for Monitor Legislativo v4"""
    
    if config is None:
        # Parse database URL or use environment variables
        if database_url:
            # Parse PostgreSQL URL format: postgresql://user:pass@host:port/db
            import urllib.parse
            parsed = urllib.parse.urlparse(database_url)
            
            config = ConnectionConfig(
                host=parsed.hostname or "localhost",
                port=parsed.port or 5432,
                database=parsed.path.lstrip('/') if parsed.path else "monitor_legislativo",
                user=parsed.username or "postgres",
                password=parsed.password or ""
            )
        else:
            # Use environment variables
            config = ConnectionConfig(
                host=os.getenv("DB_HOST", "localhost"),
                port=int(os.getenv("DB_PORT", "5432")),
                database=os.getenv("DB_NAME", "monitor_legislativo"),
                user=os.getenv("DB_USER", "postgres"),
                password=os.getenv("DB_PASSWORD", "")
            )
    
    # Create and initialize pool
    pool = AdvancedConnectionPool(config)
    await pool.initialize()
    
    return pool

# Connection pool singleton for application use
_global_pool: Optional[AdvancedConnectionPool] = None

async def get_connection_pool() -> AdvancedConnectionPool:
    """Get the global connection pool instance"""
    global _global_pool
    
    if _global_pool is None:
        database_url = os.getenv("DATABASE_URL")
        _global_pool = await create_optimized_pool(database_url)
    
    return _global_pool

async def close_connection_pool() -> None:
    """Close the global connection pool"""
    global _global_pool
    
    if _global_pool:
        await _global_pool.close()
        _global_pool = None

# Context manager for temporary connection pools
@asynccontextmanager
async def temporary_pool(config: ConnectionConfig):
    """Context manager for temporary connection pools"""
    pool = AdvancedConnectionPool(config)
    try:
        await pool.initialize()
        yield pool
    finally:
        await pool.close()

# Export main classes and functions
__all__ = [
    'AdvancedConnectionPool',
    'ConnectionConfig', 
    'PoolMetrics',
    'PoolHealth',
    'create_optimized_pool',
    'get_connection_pool',
    'close_connection_pool',
    'temporary_pool'
]