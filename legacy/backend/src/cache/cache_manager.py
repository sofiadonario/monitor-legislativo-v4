"""
Smart Cache Manager for Monitor Legislativo
Implements intelligent caching strategies with monitoring and metrics
"""

import json
import hashlib
import time
import asyncio
from typing import Any, Dict, List, Optional, Callable, Union
from datetime import datetime, timedelta
from collections import defaultdict
import logging

import redis
from redis import asyncio as aioredis
from redis.exceptions import RedisError

from .redis_config import RedisConfig, redis_config

logger = logging.getLogger(__name__)


class CacheMetrics:
    """Track cache performance metrics"""
    
    def __init__(self):
        self.hits = 0
        self.misses = 0
        self.api_calls_saved = 0
        self.bandwidth_saved_bytes = 0
        self.response_times = []
        self.start_time = time.time()
    
    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate"""
        total = self.hits + self.misses
        return (self.hits / total * 100) if total > 0 else 0
    
    @property
    def avg_response_time(self) -> float:
        """Calculate average response time"""
        return sum(self.response_times) / len(self.response_times) if self.response_times else 0
    
    def record_hit(self, size_bytes: int = 0, response_time: float = 0):
        """Record a cache hit"""
        self.hits += 1
        self.api_calls_saved += 1
        self.bandwidth_saved_bytes += size_bytes
        if response_time:
            self.response_times.append(response_time)
    
    def record_miss(self, response_time: float = 0):
        """Record a cache miss"""
        self.misses += 1
        if response_time:
            self.response_times.append(response_time)
    
    def to_dict(self) -> Dict[str, Any]:
        """Export metrics as dictionary"""
        return {
            'hits': self.hits,
            'misses': self.misses,
            'hit_rate': self.hit_rate,
            'api_calls_saved': self.api_calls_saved,
            'bandwidth_saved_mb': self.bandwidth_saved_bytes / 1048576,
            'avg_response_time': self.avg_response_time,
            'uptime_hours': (time.time() - self.start_time) / 3600
        }


class SmartCacheManager:
    """
    Intelligent cache manager with advanced features:
    - Normalized cache key generation
    - TTL management based on data patterns
    - Batch operations support
    - Stale-while-revalidate pattern
    - Cache warming
    - Performance metrics
    """
    
    def __init__(self, redis_url: Optional[str] = None):
        self.redis_url = redis_url or redis_config.get_redis_url()
        self.redis_client: Optional[redis.Redis] = None
        self.async_redis_client: Optional[aioredis.Redis] = None
        self.metrics = CacheMetrics()
        self.warming_tasks = []
        self._lock = asyncio.Lock()
        
    def connect(self):
        """Initialize Redis connection"""
        try:
            # Create connection pool
            pool = redis.ConnectionPool.from_url(
                self.redis_url,
                max_connections=redis_config.POOL.max_connections,
                socket_keepalive=redis_config.POOL.socket_keepalive,
                socket_keepalive_options=redis_config.POOL.socket_keepalive_options,
                decode_responses=True
            )
            
            self.redis_client = redis.Redis(connection_pool=pool)
            
            # Test connection
            self.redis_client.ping()
            
            # Configure Redis settings
            self._configure_redis()
            
            logger.info("Redis connection established successfully")
            
        except RedisError as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise
    
    async def connect_async(self):
        """Initialize async Redis connection"""
        try:
            self.async_redis_client = await aioredis.from_url(
                self.redis_url,
                max_connections=redis_config.POOL.max_connections,
                decode_responses=True
            )
            
            # Test connection
            await self.async_redis_client.ping()
            
            logger.info("Async Redis connection established successfully")
            
        except RedisError as e:
            logger.error(f"Failed to connect to async Redis: {e}")
            raise
    
    def _configure_redis(self):
        """Configure Redis memory and performance settings"""
        try:
            config = redis_config.get_memory_config()
            for key, value in config.items():
                self.redis_client.config_set(key.replace('-', '_'), value)
        except Exception as e:
            logger.warning(f"Could not configure Redis settings: {e}")
    
    def generate_cache_key(self, source: str, query: Dict[str, Any], prefix: str = "api") -> str:
        """
        Generate normalized, deterministic cache keys
        
        Args:
            source: Data source (e.g., 'camara', 'senado')
            query: Query parameters
            prefix: Key prefix for namespacing
            
        Returns:
            Normalized cache key
        """
        # Sort parameters for consistency
        sorted_params = sorted(query.items())
        
        # Create deterministic hash
        param_str = json.dumps(sorted_params, sort_keys=True, ensure_ascii=True)
        param_hash = hashlib.md5(param_str.encode()).hexdigest()[:12]
        
        # Generate key: prefix:source:hash
        return f"{prefix}:{source}:{param_hash}"
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache with metrics tracking"""
        start_time = time.time()
        
        try:
            value = self.redis_client.get(key)
            
            if value:
                # Parse JSON if stored as string
                try:
                    parsed_value = json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    parsed_value = value
                
                # Record metrics
                response_time = time.time() - start_time
                size_bytes = len(value.encode()) if isinstance(value, str) else 0
                self.metrics.record_hit(size_bytes, response_time)
                
                return parsed_value
            else:
                self.metrics.record_miss(time.time() - start_time)
                return None
                
        except Exception as e:
            logger.error(f"Cache get error for key {key}: {e}")
            self.metrics.record_miss(time.time() - start_time)
            return None
    
    async def get_async(self, key: str) -> Optional[Any]:
        """Async get value from cache"""
        start_time = time.time()
        
        try:
            value = await self.async_redis_client.get(key)
            
            if value:
                try:
                    parsed_value = json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    parsed_value = value
                
                response_time = time.time() - start_time
                size_bytes = len(value.encode()) if isinstance(value, str) else 0
                self.metrics.record_hit(size_bytes, response_time)
                
                return parsed_value
            else:
                self.metrics.record_miss(time.time() - start_time)
                return None
                
        except Exception as e:
            logger.error(f"Async cache get error for key {key}: {e}")
            self.metrics.record_miss(time.time() - start_time)
            return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache with automatic TTL"""
        try:
            # Determine TTL
            if ttl is None:
                ttl = redis_config.get_ttl_for_key(key)
            
            # Serialize value
            if not isinstance(value, str):
                value = json.dumps(value, ensure_ascii=True)
            
            # Set with expiration
            return self.redis_client.setex(key, ttl, value)
            
        except Exception as e:
            logger.error(f"Cache set error for key {key}: {e}")
            return False
    
    async def set_async(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Async set value in cache"""
        try:
            if ttl is None:
                ttl = redis_config.get_ttl_for_key(key)
            
            if not isinstance(value, str):
                value = json.dumps(value, ensure_ascii=True)
            
            return await self.async_redis_client.setex(key, ttl, value)
            
        except Exception as e:
            logger.error(f"Async cache set error for key {key}: {e}")
            return False
    
    def get_or_fetch(self, key: str, fetch_func: Callable, ttl: Optional[int] = None) -> Any:
        """
        Cache-aside pattern implementation
        Try cache first, fetch and cache if miss
        """
        # Try cache first
        cached = self.get(key)
        if cached is not None:
            return cached
        
        # Fetch fresh data
        try:
            data = fetch_func()
            
            # Cache the result
            if data is not None:
                self.set(key, data, ttl)
            
            return data
            
        except Exception as e:
            logger.error(f"Fetch function error for key {key}: {e}")
            
            # Try stale cache as fallback
            stale_key = f"stale:{key}"
            stale_data = self.get(stale_key)
            if stale_data:
                logger.warning(f"Using stale cache for key {key}")
                return stale_data
            
            raise
    
    async def get_or_fetch_async(self, key: str, fetch_func: Callable, ttl: Optional[int] = None) -> Any:
        """Async cache-aside pattern"""
        # Try cache first
        cached = await self.get_async(key)
        if cached is not None:
            return cached
        
        # Use lock to prevent cache stampede
        async with self._lock:
            # Double-check after acquiring lock
            cached = await self.get_async(key)
            if cached is not None:
                return cached
            
            # Fetch fresh data
            try:
                if asyncio.iscoroutinefunction(fetch_func):
                    data = await fetch_func()
                else:
                    data = fetch_func()
                
                # Cache the result
                if data is not None:
                    await self.set_async(key, data, ttl)
                    # Also set stale version for fallback
                    await self.set_async(f"stale:{key}", data, ttl * 2)
                
                return data
                
            except Exception as e:
                logger.error(f"Async fetch function error for key {key}: {e}")
                
                # Try stale cache as fallback
                stale_data = await self.get_async(f"stale:{key}")
                if stale_data:
                    logger.warning(f"Using stale cache for key {key}")
                    return stale_data
                
                raise
    
    def batch_get(self, keys: List[str]) -> Dict[str, Any]:
        """Get multiple values in a single operation"""
        try:
            # Use pipeline for efficiency
            pipe = self.redis_client.pipeline()
            for key in keys:
                pipe.get(key)
            
            values = pipe.execute()
            
            # Build result dictionary
            result = {}
            for key, value in zip(keys, values):
                if value:
                    try:
                        result[key] = json.loads(value)
                    except (json.JSONDecodeError, TypeError):
                        result[key] = value
                    self.metrics.hits += 1
                else:
                    self.metrics.misses += 1
            
            return result
            
        except Exception as e:
            logger.error(f"Batch get error: {e}")
            return {}
    
    def batch_set(self, items: Dict[str, Any], ttl: Optional[int] = None) -> bool:
        """Set multiple values in a single operation"""
        try:
            pipe = self.redis_client.pipeline()
            
            for key, value in items.items():
                if ttl is None:
                    key_ttl = redis_config.get_ttl_for_key(key)
                else:
                    key_ttl = ttl
                
                if not isinstance(value, str):
                    value = json.dumps(value, ensure_ascii=True)
                
                pipe.setex(key, key_ttl, value)
            
            results = pipe.execute()
            return all(results)
            
        except Exception as e:
            logger.error(f"Batch set error: {e}")
            return False
    
    def invalidate_pattern(self, pattern: str) -> int:
        """Invalidate all keys matching pattern"""
        try:
            cursor = 0
            deleted = 0
            
            while True:
                cursor, keys = self.redis_client.scan(
                    cursor,
                    match=pattern,
                    count=redis_config.BATCH_SIZE
                )
                
                if keys:
                    deleted += self.redis_client.delete(*keys)
                
                if cursor == 0:
                    break
            
            logger.info(f"Invalidated {deleted} keys matching pattern: {pattern}")
            return deleted
            
        except Exception as e:
            logger.error(f"Pattern invalidation error: {e}")
            return 0
    
    def warm_cache(self, patterns: Optional[List[str]] = None):
        """Pre-load commonly accessed data into cache"""
        patterns = patterns or redis_config.CACHE_WARMING_PATTERNS
        
        for pattern in patterns:
            try:
                # This would be implemented based on specific warming strategies
                logger.info(f"Warming cache for pattern: {pattern}")
                # Example: self.get_or_fetch(pattern, fetch_func)
                
            except Exception as e:
                logger.error(f"Cache warming error for {pattern}: {e}")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current cache metrics"""
        try:
            # Get Redis info
            info = self.redis_client.info('stats')
            memory_info = self.redis_client.info('memory')
            
            metrics = self.metrics.to_dict()
            metrics.update({
                'redis_connected_clients': info.get('connected_clients', 0),
                'redis_used_memory_mb': memory_info.get('used_memory', 0) / 1048576,
                'redis_hit_rate': info.get('keyspace_hits', 0) / 
                                 (info.get('keyspace_hits', 0) + info.get('keyspace_misses', 1)) * 100
            })
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error getting metrics: {e}")
            return self.metrics.to_dict()
    
    def close(self):
        """Close Redis connections"""
        if self.redis_client:
            self.redis_client.close()
        
    async def close_async(self):
        """Close async Redis connections"""
        if self.async_redis_client:
            await self.async_redis_client.close()


# Singleton instance
_cache_manager: Optional[SmartCacheManager] = None


def get_cache_manager() -> SmartCacheManager:
    """Get or create cache manager singleton"""
    global _cache_manager
    if _cache_manager is None:
        _cache_manager = SmartCacheManager()
        _cache_manager.connect()
    return _cache_manager


async def get_async_cache_manager() -> SmartCacheManager:
    """Get or create async cache manager singleton"""
    global _cache_manager
    if _cache_manager is None:
        _cache_manager = SmartCacheManager()
        await _cache_manager.connect_async()
    return _cache_manager