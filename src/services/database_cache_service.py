import logging
import json
import hashlib
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import redis.asyncio as redis
from redis.exceptions import ConnectionError, TimeoutError

from ..config.env_loader import EnvironmentConfig
from ..database.supabase_config import get_database_manager
from sqlalchemy import text

logger = logging.getLogger(__name__)

class DatabaseCacheService:
    """
    Database cache service with Redis and PostgreSQL fallback.
    Implements multi-tier caching for search results.
    """
    def __init__(self):
        self.redis_client: Optional[redis.Redis] = None
        self.db_manager = None
        self.db_available = False
        self.redis_available = False
        self.cache_prefix = EnvironmentConfig.CACHE_PREFIX
        self.ttl = EnvironmentConfig.CACHE_TTL
        
    async def initialize(self):
        """Initialize cache connections"""
        # Initialize Redis connection
        redis_url = EnvironmentConfig.get_redis_url()
        if redis_url and EnvironmentConfig.ENABLE_CACHE:
            try:
                self.redis_client = redis.from_url(
                    redis_url,
                    decode_responses=True,
                    max_connections=EnvironmentConfig.REDIS_MAX_CONNECTIONS,
                    socket_connect_timeout=EnvironmentConfig.REDIS_TIMEOUT,
                    socket_timeout=EnvironmentConfig.REDIS_TIMEOUT
                )
                # Test connection
                await self.redis_client.ping()
                self.redis_available = True
                logger.info("Redis cache initialized successfully")
            except (ConnectionError, TimeoutError) as e:
                logger.warning(f"Redis connection failed: {e}. Using database cache only.")
                self.redis_available = False
        else:
            logger.info("Redis not configured or cache disabled")
            
        # Initialize database connection
        try:
            self.db_manager = await get_database_manager()
            if self.db_manager:
                self.db_available = await self.db_manager.test_connection()
                if self.db_available:
                    logger.info("Database cache initialized successfully")
                else:
                    logger.warning("Database connection test failed")
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            self.db_available = False

    def _generate_cache_key(self, query: str) -> str:
        """Generate a cache key from query string"""
        query_hash = hashlib.sha256(query.encode()).hexdigest()[:16]
        return f"{self.cache_prefix}search:{query_hash}"

    async def get_search_results(self, query: str) -> Optional[List[Dict[str, Any]]]:
        """
        Get cached search results from Redis or database.
        
        Args:
            query: Search query string
            
        Returns:
            Cached results or None if not found
        """
        if not query:
            return None
            
        cache_key = self._generate_cache_key(query)
        
        # Try Redis first
        if self.redis_available and self.redis_client:
            try:
                cached_data = await self.redis_client.get(cache_key)
                if cached_data:
                    logger.debug(f"Redis cache hit for query: {query}")
                    return json.loads(cached_data)
            except Exception as e:
                logger.warning(f"Redis get failed: {e}")
        
        # Try database cache
        if self.db_available and self.db_manager:
            try:
                async with self.db_manager.session_factory() as session:
                    result = await session.execute(
                        text("""
                            SELECT result_data, created_at 
                            FROM search_cache 
                            WHERE query_hash = :query_hash 
                            AND created_at > :expiry_time
                            ORDER BY created_at DESC
                            LIMIT 1
                        """),
                        {
                            "query_hash": cache_key,
                            "expiry_time": datetime.utcnow() - timedelta(seconds=self.ttl)
                        }
                    )
                    row = result.first()
                    if row:
                        logger.debug(f"Database cache hit for query: {query}")
                        # Update Redis if available
                        if self.redis_available and self.redis_client:
                            try:
                                await self.redis_client.setex(
                                    cache_key, 
                                    self.ttl, 
                                    json.dumps(row.result_data)
                                )
                            except Exception:
                                pass
                        return row.result_data
            except Exception as e:
                logger.warning(f"Database cache get failed: {e}")
        
        logger.debug(f"Cache miss for query: {query}")
        return None

    async def save_search_results(self, query: str, results: List[Dict[str, Any]]):
        """
        Save search results to cache.
        
        Args:
            query: Search query string
            results: List of search results
        """
        if not query or not results:
            return
            
        cache_key = self._generate_cache_key(query)
        serialized_results = json.dumps(results, ensure_ascii=False)
        
        # Save to Redis
        if self.redis_available and self.redis_client:
            try:
                await self.redis_client.setex(cache_key, self.ttl, serialized_results)
                logger.debug(f"Saved {len(results)} results to Redis cache for query: {query}")
            except Exception as e:
                logger.warning(f"Redis save failed: {e}")
        
        # Save to database
        if self.db_available and self.db_manager:
            try:
                async with self.db_manager.session_factory() as session:
                    # First check if table exists
                    table_check = await session.execute(
                        text("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'search_cache')")
                    )
                    if not table_check.scalar():
                        # Create table if it doesn't exist
                        await session.execute(text("""
                            CREATE TABLE IF NOT EXISTS search_cache (
                                id BIGSERIAL PRIMARY KEY,
                                query_hash VARCHAR(64) NOT NULL,
                                query_text TEXT,
                                result_data JSONB,
                                result_count INTEGER,
                                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                                CONSTRAINT idx_query_hash_unique UNIQUE (query_hash)
                            )
                        """))
                        await session.execute(text("""
                            CREATE INDEX IF NOT EXISTS idx_search_cache_query_hash 
                            ON search_cache(query_hash)
                        """))
                        await session.execute(text("""
                            CREATE INDEX IF NOT EXISTS idx_search_cache_created_at 
                            ON search_cache(created_at)
                        """))
                        await session.commit()
                    
                    # Insert or update cache entry
                    await session.execute(
                        text("""
                            INSERT INTO search_cache (query_hash, query_text, result_data, result_count)
                            VALUES (:query_hash, :query_text, :result_data::jsonb, :result_count)
                            ON CONFLICT (query_hash) DO UPDATE SET
                                result_data = EXCLUDED.result_data,
                                result_count = EXCLUDED.result_count,
                                created_at = NOW()
                        """),
                        {
                            "query_hash": cache_key,
                            "query_text": query,
                            "result_data": serialized_results,
                            "result_count": len(results)
                        }
                    )
                    await session.commit()
                    logger.debug(f"Saved {len(results)} results to database cache for query: {query}")
            except Exception as e:
                logger.warning(f"Database cache save failed: {e}")

    async def invalidate_cache(self, pattern: Optional[str] = None):
        """
        Invalidate cache entries.
        
        Args:
            pattern: Optional pattern to match keys for deletion
        """
        if pattern:
            search_pattern = f"{self.cache_prefix}search:*{pattern}*"
        else:
            search_pattern = f"{self.cache_prefix}search:*"
        
        # Clear Redis cache
        if self.redis_available and self.redis_client:
            try:
                keys = await self.redis_client.keys(search_pattern)
                if keys:
                    await self.redis_client.delete(*keys)
                    logger.info(f"Invalidated {len(keys)} Redis cache entries")
            except Exception as e:
                logger.warning(f"Redis cache invalidation failed: {e}")
        
        # Clear database cache
        if self.db_available and self.db_manager:
            try:
                async with self.db_manager.session_factory() as session:
                    if pattern:
                        await session.execute(
                            text("DELETE FROM search_cache WHERE query_text ILIKE :pattern"),
                            {"pattern": f"%{pattern}%"}
                        )
                    else:
                        await session.execute(text("DELETE FROM search_cache"))
                    await session.commit()
                    logger.info("Database cache invalidated")
            except Exception as e:
                logger.warning(f"Database cache invalidation failed: {e}")

    async def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        stats = {
            "redis_available": self.redis_available,
            "database_available": self.db_available,
            "cache_enabled": EnvironmentConfig.ENABLE_CACHE
        }
        
        # Get Redis stats
        if self.redis_available and self.redis_client:
            try:
                info = await self.redis_client.info()
                keys = await self.redis_client.keys(f"{self.cache_prefix}search:*")
                stats["redis_stats"] = {
                    "connected_clients": info.get("connected_clients", 0),
                    "used_memory_human": info.get("used_memory_human", "0"),
                    "cache_keys": len(keys)
                }
            except Exception:
                stats["redis_stats"] = {"error": "Failed to get Redis stats"}
        
        # Get database stats
        if self.db_available and self.db_manager:
            try:
                async with self.db_manager.session_factory() as session:
                    result = await session.execute(
                        text("""
                            SELECT 
                                COUNT(*) as total_entries,
                                COUNT(DISTINCT query_hash) as unique_queries,
                                SUM(result_count) as total_results,
                                MAX(created_at) as last_cache_update
                            FROM search_cache
                            WHERE created_at > :expiry_time
                        """),
                        {"expiry_time": datetime.utcnow() - timedelta(seconds=self.ttl)}
                    )
                    row = result.first()
                    stats["database_stats"] = {
                        "total_entries": row.total_entries,
                        "unique_queries": row.unique_queries,
                        "total_results": row.total_results,
                        "last_cache_update": row.last_cache_update.isoformat() if row.last_cache_update else None
                    }
            except Exception:
                stats["database_stats"] = {"error": "Failed to get database stats"}
        
        return stats

# Singleton instance
_cache_service_instance = None

async def get_database_cache_service() -> DatabaseCacheService:
    """
    Dependency injector for the DatabaseCacheService.
    """
    global _cache_service_instance
    if _cache_service_instance is None:
        _cache_service_instance = DatabaseCacheService()
        await _cache_service_instance.initialize()
    return _cache_service_instance 