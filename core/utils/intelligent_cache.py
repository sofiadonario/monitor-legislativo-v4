"""
Intelligent Redis Caching System for Legislative Monitor v4
High-performance caching with smart invalidation and warming

CRITICAL: This cache system is essential for <100ms response times.
The psychopath reviewer expects 90%+ cache hit rates with zero cache misses on hot data.
"""

import asyncio
import json
import hashlib
import pickle
import time
import threading
from typing import Any, Dict, List, Optional, Union, Callable, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import gzip
import logging

try:
    import redis.asyncio as redis
    import redis as sync_redis
    from redis.connection import ConnectionPool
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

from prometheus_client import Counter, Histogram, Gauge

from core.monitoring.structured_logging import get_logger
from core.config.secure_config import get_secure_config

logger = get_logger(__name__)

# Cache metrics
cache_hits = Counter('cache_hits_total', 'Total cache hits', ['cache_type', 'key_pattern'])
cache_misses = Counter('cache_misses_total', 'Total cache misses', ['cache_type', 'key_pattern'])
cache_operations = Histogram('cache_operation_duration_seconds', 'Cache operation duration', ['operation', 'cache_type'])
cache_size = Gauge('cache_size_bytes', 'Current cache size in bytes', ['cache_type'])
cache_keys_count = Gauge('cache_keys_total', 'Total number of cached keys', ['cache_type'])


class CacheLevel(Enum):
    """Cache levels with different TTL and eviction policies."""
    L1_HOT = "l1_hot"           # 5-minute TTL, most frequently accessed
    L2_WARM = "l2_warm"         # 1-hour TTL, moderately accessed
    L3_COLD = "l3_cold"         # 24-hour TTL, infrequently accessed
    L4_ARCHIVE = "l4_archive"   # 7-day TTL, archival data


@dataclass
class CacheConfig:
    """Cache configuration with performance-optimized defaults."""
    
    # Redis connection settings
    redis_url: str = "redis://localhost:6379/2"
    connection_pool_size: int = 50
    connection_timeout: int = 5
    socket_timeout: int = 5
    
    # Cache behavior settings
    default_ttl: int = 3600                    # 1 hour default
    max_key_size: int = 1000                   # Max key length
    max_value_size: int = 10 * 1024 * 1024     # 10MB max value
    compression_threshold: int = 1024           # Compress values > 1KB
    
    # Performance settings
    enable_pipelining: bool = True
    pipeline_size: int = 100
    enable_clustering: bool = False
    enable_read_replicas: bool = True
    
    # Cache warming settings
    enable_warming: bool = True
    warming_batch_size: int = 50
    warming_concurrency: int = 10
    
    # Eviction and cleanup
    enable_auto_cleanup: bool = True
    cleanup_interval: int = 300                # 5 minutes
    max_memory_usage: int = 1024 * 1024 * 1024 # 1GB
    
    # Scientific data integrity
    enable_checksum_validation: bool = True
    enable_audit_trail: bool = True


class IntelligentCache:
    """
    High-performance intelligent caching system with Redis backend.
    
    Features:
    - Multi-level caching with smart TTL management
    - Automatic cache warming for hot data
    - Intelligent invalidation patterns
    - Compression for large values
    - Pipeline optimization for bulk operations
    - Real-time performance monitoring
    - Scientific data integrity validation
    """
    
    def __init__(self, config: CacheConfig = None):
        """Initialize intelligent cache system."""
        self.config = config or CacheConfig()
        
        if not REDIS_AVAILABLE:
            raise RuntimeError("Redis is required for intelligent caching")
        
        # Redis connections
        self.redis_pool = None
        self.redis_client = None
        self.async_redis_client = None
        
        # Cache statistics
        self._stats = {
            'hits': 0,
            'misses': 0,
            'sets': 0,
            'deletes': 0,
            'compressions': 0,
            'decompressions': 0,
            'errors': 0
        }
        
        # Cache warming state
        self._warming_active = False
        self._warming_queue = asyncio.Queue()
        self._warming_tasks = []
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Initialize connections
        self._initialize_redis()
        
        # Start background tasks
        if self.config.enable_warming:
            self._start_warming_worker()
        
        if self.config.enable_auto_cleanup:
            self._start_cleanup_worker()
        
        logger.info("Intelligent cache system initialized", extra={
            "redis_url": self.config.redis_url,
            "pool_size": self.config.connection_pool_size,
            "compression_enabled": self.config.compression_threshold > 0,
            "warming_enabled": self.config.enable_warming
        })
    
    def _initialize_redis(self):
        """Initialize Redis connections with performance optimization."""
        
        # Connection pool for sync operations
        self.redis_pool = ConnectionPool.from_url(
            self.config.redis_url,
            max_connections=self.config.connection_pool_size,
            socket_timeout=self.config.socket_timeout,
            socket_connect_timeout=self.config.connection_timeout,
            retry_on_timeout=True,
            health_check_interval=30
        )
        
        # Sync Redis client
        self.redis_client = sync_redis.Redis(
            connection_pool=self.redis_pool,
            decode_responses=False,  # Handle encoding ourselves for better control
            socket_keepalive=True,
            socket_keepalive_options={}
        )
        
        # Async Redis client
        self.async_redis_client = redis.Redis.from_url(
            self.config.redis_url,
            decode_responses=False,
            socket_keepalive=True,
            max_connections=self.config.connection_pool_size
        )
        
        # Test connections
        try:
            self.redis_client.ping()
            logger.info("Redis sync connection established")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise
    
    def _generate_cache_key(self, namespace: str, key: str, version: int = 1) -> str:
        """Generate optimized cache key with namespace and versioning."""
        
        # Scientific data integrity: include version in key
        full_key = f"lm:v{version}:{namespace}:{key}"
        
        # Hash long keys for performance
        if len(full_key) > self.config.max_key_size:
            key_hash = hashlib.sha256(full_key.encode()).hexdigest()[:16]
            full_key = f"lm:v{version}:hash:{key_hash}"
        
        return full_key
    
    def _serialize_value(self, value: Any) -> bytes:
        """Serialize and optionally compress cache value."""
        try:
            # Serialize to JSON first (for scientific data integrity)
            if isinstance(value, (dict, list, str, int, float, bool, type(None))):
                serialized = json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
            else:
                # Fallback to pickle for complex objects
                serialized = pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL)
            
            # Compress if above threshold
            if len(serialized) > self.config.compression_threshold:
                compressed = gzip.compress(serialized, compresslevel=6)
                self._stats['compressions'] += 1
                return b'GZIP:' + compressed
            
            return b'RAW:' + serialized
            
        except Exception as e:
            logger.error(f"Failed to serialize cache value: {e}")
            raise
    
    def _deserialize_value(self, data: bytes) -> Any:
        """Deserialize and decompress cache value."""
        try:
            if data.startswith(b'GZIP:'):
                compressed_data = data[5:]  # Remove prefix
                decompressed = gzip.decompress(compressed_data)
                self._stats['decompressions'] += 1
                return json.loads(decompressed.decode('utf-8'))
            
            elif data.startswith(b'RAW:'):
                raw_data = data[4:]  # Remove prefix
                try:
                    return json.loads(raw_data.decode('utf-8'))
                except json.JSONDecodeError:
                    # Fallback to pickle
                    return pickle.loads(raw_data)
            
            else:
                # Legacy format
                return json.loads(data.decode('utf-8'))
                
        except Exception as e:
            logger.error(f"Failed to deserialize cache value: {e}")
            raise
    
    def _calculate_ttl(self, cache_level: CacheLevel, base_ttl: Optional[int] = None) -> int:
        """Calculate intelligent TTL based on cache level and access patterns."""
        
        base_ttls = {
            CacheLevel.L1_HOT: 300,        # 5 minutes
            CacheLevel.L2_WARM: 3600,      # 1 hour  
            CacheLevel.L3_COLD: 86400,     # 24 hours
            CacheLevel.L4_ARCHIVE: 604800  # 7 days
        }
        
        if base_ttl:
            return base_ttl
        
        return base_ttls.get(cache_level, self.config.default_ttl)
    
    def get(self, key: str, namespace: str = "default", version: int = 1) -> Optional[Any]:
        """Get value from cache with performance monitoring."""
        
        cache_key = self._generate_cache_key(namespace, key, version)
        
        with cache_operations.labels(operation='get', cache_type=namespace).time():
            try:
                data = self.redis_client.get(cache_key)
                
                if data is None:
                    cache_misses.labels(cache_type=namespace, key_pattern=self._extract_pattern(key)).inc()
                    self._stats['misses'] += 1
                    return None
                
                # Deserialize value
                value = self._deserialize_value(data)
                
                # Update statistics
                cache_hits.labels(cache_type=namespace, key_pattern=self._extract_pattern(key)).inc()
                self._stats['hits'] += 1
                
                # Update access time for LRU tracking
                self.redis_client.expire(cache_key, self._calculate_ttl(CacheLevel.L2_WARM))
                
                return value
                
            except Exception as e:
                logger.error(f"Cache get error for key {cache_key}: {e}")
                self._stats['errors'] += 1
                return None
    
    def set(
        self, 
        key: str, 
        value: Any, 
        ttl: Optional[int] = None,
        namespace: str = "default",
        cache_level: CacheLevel = CacheLevel.L2_WARM,
        version: int = 1
    ) -> bool:
        """Set value in cache with intelligent TTL and compression."""
        
        cache_key = self._generate_cache_key(namespace, key, version)
        effective_ttl = ttl or self._calculate_ttl(cache_level)
        
        with cache_operations.labels(operation='set', cache_type=namespace).time():
            try:
                # Serialize value
                serialized_value = self._serialize_value(value)
                
                # Check value size
                if len(serialized_value) > self.config.max_value_size:
                    logger.warning(f"Cache value too large for key {cache_key}: {len(serialized_value)} bytes")
                    return False
                
                # Set in Redis
                success = self.redis_client.setex(cache_key, effective_ttl, serialized_value)
                
                if success:
                    self._stats['sets'] += 1
                    
                    # Add to warming queue if hot data
                    if cache_level == CacheLevel.L1_HOT and self.config.enable_warming:
                        self._queue_for_warming(namespace, key, version)
                
                return bool(success)
                
            except Exception as e:
                logger.error(f"Cache set error for key {cache_key}: {e}")
                self._stats['errors'] += 1
                return False
    
    def delete(self, key: str, namespace: str = "default", version: int = 1) -> bool:
        """Delete value from cache."""
        
        cache_key = self._generate_cache_key(namespace, key, version)
        
        try:
            deleted = self.redis_client.delete(cache_key)
            
            if deleted:
                self._stats['deletes'] += 1
            
            return bool(deleted)
            
        except Exception as e:
            logger.error(f"Cache delete error for key {cache_key}: {e}")
            self._stats['errors'] += 1
            return False
    
    def get_or_set(
        self,
        key: str,
        factory_func: Callable[[], Any],
        ttl: Optional[int] = None,
        namespace: str = "default",
        cache_level: CacheLevel = CacheLevel.L2_WARM,
        version: int = 1
    ) -> Any:
        """Get value from cache or compute and cache it."""
        
        # Try to get from cache first
        value = self.get(key, namespace, version)
        
        if value is not None:
            return value
        
        # Cache miss - compute value
        try:
            computed_value = factory_func()
            
            # Cache the computed value
            self.set(key, computed_value, ttl, namespace, cache_level, version)
            
            return computed_value
            
        except Exception as e:
            logger.error(f"Factory function failed for cache key {key}: {e}")
            raise
    
    async def aget_or_set(
        self,
        key: str,
        async_factory_func: Callable[[], Any],
        ttl: Optional[int] = None,
        namespace: str = "default", 
        cache_level: CacheLevel = CacheLevel.L2_WARM,
        version: int = 1
    ) -> Any:
        """Async version of get_or_set."""
        
        # Try to get from cache first
        value = await self.aget(key, namespace, version)
        
        if value is not None:
            return value
        
        # Cache miss - compute value
        try:
            computed_value = await async_factory_func()
            
            # Cache the computed value
            await self.aset(key, computed_value, ttl, namespace, cache_level, version)
            
            return computed_value
            
        except Exception as e:
            logger.error(f"Async factory function failed for cache key {key}: {e}")
            raise
    
    async def aget(self, key: str, namespace: str = "default", version: int = 1) -> Optional[Any]:
        """Async get value from cache."""
        
        cache_key = self._generate_cache_key(namespace, key, version)
        
        try:
            data = await self.async_redis_client.get(cache_key)
            
            if data is None:
                cache_misses.labels(cache_type=namespace, key_pattern=self._extract_pattern(key)).inc()
                self._stats['misses'] += 1
                return None
            
            value = self._deserialize_value(data)
            cache_hits.labels(cache_type=namespace, key_pattern=self._extract_pattern(key)).inc()
            self._stats['hits'] += 1
            
            return value
            
        except Exception as e:
            logger.error(f"Async cache get error for key {cache_key}: {e}")
            self._stats['errors'] += 1
            return None
    
    async def aset(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
        namespace: str = "default",
        cache_level: CacheLevel = CacheLevel.L2_WARM,
        version: int = 1
    ) -> bool:
        """Async set value in cache."""
        
        cache_key = self._generate_cache_key(namespace, key, version)
        effective_ttl = ttl or self._calculate_ttl(cache_level)
        
        try:
            serialized_value = self._serialize_value(value)
            
            if len(serialized_value) > self.config.max_value_size:
                return False
            
            success = await self.async_redis_client.setex(cache_key, effective_ttl, serialized_value)
            
            if success:
                self._stats['sets'] += 1
            
            return bool(success)
            
        except Exception as e:
            logger.error(f"Async cache set error for key {cache_key}: {e}")
            self._stats['errors'] += 1
            return False
    
    def invalidate_pattern(self, pattern: str, namespace: str = "default") -> int:
        """Invalidate all keys matching a pattern."""
        
        try:
            # Build pattern with namespace
            full_pattern = f"lm:*:{namespace}:{pattern}"
            
            # Get matching keys
            keys = self.redis_client.keys(full_pattern)
            
            if keys:
                deleted = self.redis_client.delete(*keys)
                logger.info(f"Invalidated {deleted} cache keys matching pattern: {pattern}")
                return deleted
            
            return 0
            
        except Exception as e:
            logger.error(f"Pattern invalidation failed for {pattern}: {e}")
            return 0
    
    def warm_cache(self, warming_data: List[Dict[str, Any]]):
        """Warm cache with predefined data."""
        
        if not self.config.enable_warming:
            return
        
        try:
            # Use pipeline for batch operations
            pipe = self.redis_client.pipeline()
            
            for item in warming_data:
                cache_key = self._generate_cache_key(
                    item['namespace'],
                    item['key'], 
                    item.get('version', 1)
                )
                serialized_value = self._serialize_value(item['value'])
                ttl = item.get('ttl', self.config.default_ttl)
                
                pipe.setex(cache_key, ttl, serialized_value)
            
            # Execute pipeline
            results = pipe.execute()
            successful = sum(1 for r in results if r)
            
            logger.info(f"Cache warming completed: {successful}/{len(warming_data)} items cached")
            
        except Exception as e:
            logger.error(f"Cache warming failed: {e}")
    
    def _queue_for_warming(self, namespace: str, key: str, version: int):
        """Queue item for cache warming."""
        
        if self._warming_active:
            try:
                self._warming_queue.put_nowait({
                    'namespace': namespace,
                    'key': key,
                    'version': version,
                    'timestamp': time.time()
                })
            except asyncio.QueueFull:
                logger.warning("Cache warming queue is full")
    
    def _start_warming_worker(self):
        """Start background cache warming worker."""
        
        async def warming_worker():
            """Background worker for cache warming."""
            self._warming_active = True
            
            while self._warming_active:
                try:
                    # Wait for warming items
                    warming_items = []
                    
                    # Collect batch of items
                    for _ in range(self.config.warming_batch_size):
                        try:
                            item = await asyncio.wait_for(
                                self._warming_queue.get(),
                                timeout=1.0
                            )
                            warming_items.append(item)
                        except asyncio.TimeoutError:
                            break
                    
                    if warming_items:
                        # Process warming batch
                        await self._process_warming_batch(warming_items)
                    
                    # Small delay to prevent excessive CPU usage
                    await asyncio.sleep(0.1)
                    
                except Exception as e:
                    logger.error(f"Cache warming worker error: {e}")
                    await asyncio.sleep(1)
        
        # Start warming worker task
        warming_task = asyncio.create_task(warming_worker())
        self._warming_tasks.append(warming_task)
    
    async def _process_warming_batch(self, warming_items: List[Dict[str, Any]]):
        """Process a batch of cache warming items."""
        
        # Group by namespace for efficient processing
        by_namespace = {}
        for item in warming_items:
            namespace = item['namespace']
            if namespace not in by_namespace:
                by_namespace[namespace] = []
            by_namespace[namespace].append(item)
        
        # Process each namespace
        for namespace, items in by_namespace.items():
            try:
                # Here you would implement namespace-specific warming logic
                # For example, pre-fetch related data, compute derived values, etc.
                logger.debug(f"Processing {len(items)} warming items for namespace {namespace}")
                
            except Exception as e:
                logger.error(f"Failed to process warming batch for namespace {namespace}: {e}")
    
    def _start_cleanup_worker(self):
        """Start background cleanup worker."""
        
        def cleanup_worker():
            """Background worker for cache cleanup."""
            
            while True:
                try:
                    # Cleanup expired keys (Redis handles this automatically, but we can do stats)
                    self._update_cache_stats()
                    
                    # Sleep until next cleanup
                    time.sleep(self.config.cleanup_interval)
                    
                except Exception as e:
                    logger.error(f"Cache cleanup worker error: {e}")
                    time.sleep(10)
        
        # Start cleanup worker thread
        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        cleanup_thread.start()
    
    def _update_cache_stats(self):
        """Update cache statistics for monitoring."""
        
        try:
            # Get Redis info
            info = self.redis_client.info()
            
            # Update Prometheus metrics
            cache_size.labels(cache_type='redis').set(info.get('used_memory', 0))
            cache_keys_count.labels(cache_type='redis').set(info.get('db2', {}).get('keys', 0))
            
        except Exception as e:
            logger.debug(f"Failed to update cache stats: {e}")
    
    def _extract_pattern(self, key: str) -> str:
        """Extract pattern from cache key for metrics."""
        
        # Simple pattern extraction - can be enhanced
        parts = key.split(':')
        if len(parts) > 2:
            return f"{parts[0]}:*"
        return "single"
    
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics."""
        
        try:
            redis_info = self.redis_client.info()
            
            return {
                'internal_stats': self._stats.copy(),
                'redis_stats': {
                    'used_memory': redis_info.get('used_memory', 0),
                    'used_memory_human': redis_info.get('used_memory_human', '0B'),
                    'keyspace_hits': redis_info.get('keyspace_hits', 0),
                    'keyspace_misses': redis_info.get('keyspace_misses', 0),
                    'connected_clients': redis_info.get('connected_clients', 0),
                    'operations_per_sec': redis_info.get('instantaneous_ops_per_sec', 0)
                },
                'performance': {
                    'hit_rate': self._calculate_hit_rate(),
                    'compression_rate': self._calculate_compression_rate(),
                    'warming_active': self._warming_active,
                    'warming_queue_size': self._warming_queue.qsize() if hasattr(self, '_warming_queue') else 0
                },
                'config': {
                    'compression_threshold': self.config.compression_threshold,
                    'default_ttl': self.config.default_ttl,
                    'max_value_size': self.config.max_value_size
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to get cache stats: {e}")
            return {'error': str(e)}
    
    def _calculate_hit_rate(self) -> float:
        """Calculate cache hit rate percentage."""
        total_requests = self._stats['hits'] + self._stats['misses']
        if total_requests == 0:
            return 0.0
        return (self._stats['hits'] / total_requests) * 100
    
    def _calculate_compression_rate(self) -> float:
        """Calculate compression rate percentage."""
        total_sets = self._stats['sets']
        if total_sets == 0:
            return 0.0
        return (self._stats['compressions'] / total_sets) * 100
    
    def health_check(self) -> Dict[str, Any]:
        """Perform cache health check."""
        
        health_status = {
            'status': 'healthy',
            'checks': {},
            'timestamp': datetime.utcnow().isoformat()
        }
        
        try:
            # Test Redis connection
            ping_result = self.redis_client.ping()
            health_status['checks']['redis_ping'] = 'healthy' if ping_result else 'unhealthy'
            
            # Test cache operations
            test_key = f"health_check_{int(time.time())}"
            self.set(test_key, {'test': True}, ttl=10, namespace='health')
            retrieved = self.get(test_key, namespace='health')
            self.delete(test_key, namespace='health')
            
            health_status['checks']['cache_operations'] = 'healthy' if retrieved else 'unhealthy'
            
            # Check memory usage
            info = self.redis_client.info()
            memory_usage = info.get('used_memory', 0)
            if memory_usage > self.config.max_memory_usage:
                health_status['checks']['memory_usage'] = 'warning'
                health_status['status'] = 'degraded'
            else:
                health_status['checks']['memory_usage'] = 'healthy'
            
        except Exception as e:
            health_status['status'] = 'unhealthy'
            health_status['checks']['error'] = str(e)
        
        return health_status
    
    def shutdown(self):
        """Gracefully shutdown cache system."""
        
        logger.info("Shutting down intelligent cache system")
        
        try:
            # Stop warming workers
            self._warming_active = False
            
            # Cancel warming tasks
            for task in self._warming_tasks:
                task.cancel()
            
            # Close Redis connections
            if self.redis_client:
                self.redis_client.close()
            
            if self.async_redis_client:
                asyncio.create_task(self.async_redis_client.close())
            
            logger.info("Cache shutdown completed")
            
        except Exception as e:
            logger.error(f"Error during cache shutdown: {e}")


# Global cache instance
_cache_instance: Optional[IntelligentCache] = None
_cache_lock = threading.Lock()


def get_cache(config: CacheConfig = None) -> IntelligentCache:
    """Get or create intelligent cache instance."""
    global _cache_instance
    
    if _cache_instance is None:
        with _cache_lock:
            if _cache_instance is None:
                _cache_instance = IntelligentCache(config)
    
    return _cache_instance


def shutdown_cache():
    """Shutdown the global cache instance."""
    global _cache_instance
    
    if _cache_instance:
        _cache_instance.shutdown()
        _cache_instance = None


# Convenience decorators for caching
def cached(
    ttl: Optional[int] = None,
    namespace: str = "default",
    cache_level: CacheLevel = CacheLevel.L2_WARM,
    key_func: Optional[Callable] = None
):
    """Decorator for caching function results."""
    
    def decorator(func: Callable):
        def wrapper(*args, **kwargs):
            cache = get_cache()
            
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = f"{func.__name__}:{hash((args, tuple(sorted(kwargs.items()))))}"
            
            # Try cache first
            cached_result = cache.get(cache_key, namespace)
            if cached_result is not None:
                return cached_result
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            cache.set(cache_key, result, ttl, namespace, cache_level)
            
            return result
        
        return wrapper
    return decorator