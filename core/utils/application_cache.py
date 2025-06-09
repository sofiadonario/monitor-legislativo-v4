"""
Application-Level Caching Strategy
Monitor Legislativo v4

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade - Integridade e Monitoramento de Políticas Públicas
Financing: MackPesquisa - Instituto de Pesquisa Mackenzie
"""

import asyncio
import hashlib
import json
import logging
import time
import threading
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Union, Callable
from dataclasses import dataclass, asdict
from functools import wraps
import pickle
import redis
import sqlite3
from threading import Lock

logger = logging.getLogger(__name__)


class CacheLevel(Enum):
    """Cache hierarchy levels"""
    MEMORY = 1      # In-memory cache (fastest)
    REDIS = 2       # Redis cache (fast, distributed)
    DATABASE = 3    # Database cache (persistent)
    STORAGE = 4     # File system cache (slowest, most persistent)


class CacheStrategy(Enum):
    """Cache invalidation strategies"""
    TTL = "ttl"                    # Time-to-live
    LRU = "lru"                    # Least Recently Used
    LFU = "lfu"                    # Least Frequently Used
    WRITE_THROUGH = "write_through" # Write to cache and storage simultaneously
    WRITE_BACK = "write_back"      # Write to cache first, storage later
    REFRESH_AHEAD = "refresh_ahead" # Proactive refresh before expiration


@dataclass
class CacheEntry:
    """Cache entry with metadata"""
    key: str
    value: Any
    created_at: datetime
    last_accessed: datetime
    access_count: int
    ttl_seconds: Optional[int]
    tags: List[str]
    size_bytes: int
    
    def is_expired(self) -> bool:
        """Check if cache entry is expired"""
        if self.ttl_seconds is None:
            return False
        return (datetime.now() - self.created_at).total_seconds() > self.ttl_seconds
    
    def touch(self):
        """Update last accessed time and increment count"""
        self.last_accessed = datetime.now()
        self.access_count += 1


class MemoryCache:
    """High-performance in-memory cache - MEMORY LEAK FIXED"""
    
    def __init__(self, max_size: int = 1000, max_memory_mb: int = 100):
        self.max_size = max_size
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        self.cache: Dict[str, CacheEntry] = {}
        self.current_memory = 0
        self.lock = Lock()
        
        # CRITICAL FIX: Add background cleanup to prevent memory leak from expired entries
        self._cleanup_interval = 60  # Clean up every 60 seconds
        self._cleanup_thread = None
        self._shutdown_event = threading.Event()
        self._start_cleanup_thread()
        
        # Attribution
        self.project_attribution = {
            "developers": "Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães",
            "organization": "MackIntegridade",
            "financing": "MackPesquisa"
        }
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from memory cache"""
        with self.lock:
            entry = self.cache.get(key)
            if entry is None:
                return None
            
            if entry.is_expired():
                self._remove_entry(key)
                return None
            
            entry.touch()
            return entry.value
    
    def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None, tags: List[str] = None) -> bool:
        """Set value in memory cache"""
        with self.lock:
            # Calculate size
            size_bytes = self._calculate_size(value)
            
            # Check if we need to make space
            if not self._ensure_space(size_bytes):
                return False
            
            # Remove existing entry if present
            if key in self.cache:
                self._remove_entry(key)
            
            # Create new entry
            entry = CacheEntry(
                key=key,
                value=value,
                created_at=datetime.now(),
                last_accessed=datetime.now(),
                access_count=1,
                ttl_seconds=ttl_seconds,
                tags=tags or [],
                size_bytes=size_bytes
            )
            
            self.cache[key] = entry
            self.current_memory += size_bytes
            return True
    
    def delete(self, key: str) -> bool:
        """Delete key from memory cache"""
        with self.lock:
            if key in self.cache:
                self._remove_entry(key)
                return True
            return False
    
    def clear_by_tags(self, tags: List[str]) -> int:
        """Clear entries by tags"""
        with self.lock:
            keys_to_remove = []
            for key, entry in self.cache.items():
                if any(tag in entry.tags for tag in tags):
                    keys_to_remove.append(key)
            
            for key in keys_to_remove:
                self._remove_entry(key)
            
            return len(keys_to_remove)
    
    def _remove_entry(self, key: str):
        """Remove entry and update memory usage"""
        if key in self.cache:
            entry = self.cache[key]
            self.current_memory -= entry.size_bytes
            del self.cache[key]
    
    def _ensure_space(self, needed_bytes: int) -> bool:
        """Ensure we have space for new entry"""
        # Check size limit
        if len(self.cache) >= self.max_size:
            self._evict_lru()
        
        # Check memory limit
        while self.current_memory + needed_bytes > self.max_memory_bytes:
            if not self._evict_lru():
                return False
        
        return True
    
    def _evict_lru(self) -> bool:
        """Evict least recently used entry"""
        if not self.cache:
            return False
        
        # Find LRU entry
        lru_key = min(self.cache.keys(), key=lambda k: self.cache[k].last_accessed)
        self._remove_entry(lru_key)
        return True
    
    def _calculate_size(self, value: Any) -> int:
        """Calculate approximate size of value in bytes"""
        try:
            return len(pickle.dumps(value))
        except Exception:
            return len(str(value).encode('utf-8'))
    
    def _start_cleanup_thread(self):
        """Start background thread for cleaning up expired entries - MEMORY LEAK FIX"""
        def cleanup_worker():
            while not self._shutdown_event.wait(self._cleanup_interval):
                try:
                    self._cleanup_expired_entries()
                except Exception as e:
                    logger.error(f"Memory cache cleanup error: {e}")
        
        self._cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        self._cleanup_thread.start()
        logger.info("Memory cache cleanup thread started")
    
    def _cleanup_expired_entries(self):
        """Remove all expired entries from cache - PREVENTS MEMORY LEAK"""
        with self.lock:
            expired_keys = []
            now = datetime.now()
            
            for key, entry in self.cache.items():
                if entry.is_expired():
                    expired_keys.append(key)
            
            # Remove expired entries
            removed_count = 0
            for key in expired_keys:
                self._remove_entry(key)
                removed_count += 1
            
            if removed_count > 0:
                logger.debug(f"Cleaned up {removed_count} expired cache entries, "
                           f"memory freed: {removed_count * 1024} bytes approx")
    
    def shutdown(self):
        """Shutdown cache and cleanup resources"""
        self._shutdown_event.set()
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=5)
        logger.info("Memory cache shutdown completed")


class RedisCache:
    """Redis-based distributed cache"""
    
    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        try:
            self.redis_client = redis.from_url(redis_url, decode_responses=True)
            self.redis_client.ping()
            self.available = True
        except Exception as e:
            logger.warning(f"Redis not available: {e}")
            self.redis_client = None
            self.available = False
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from Redis cache"""
        if not self.available:
            return None
        
        try:
            data = self.redis_client.get(key)
            if data is None:
                return None
            
            # Try to deserialize
            try:
                return json.loads(data)
            except json.JSONDecodeError:
                return data
        except Exception as e:
            logger.error(f"Redis get error: {e}")
            return None
    
    async def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> bool:
        """Set value in Redis cache"""
        if not self.available:
            return False
        
        try:
            # Serialize value
            if isinstance(value, (dict, list)):
                data = json.dumps(value)
            else:
                data = str(value)
            
            # Set with TTL
            if ttl_seconds:
                return self.redis_client.setex(key, ttl_seconds, data)
            else:
                return self.redis_client.set(key, data)
        except Exception as e:
            logger.error(f"Redis set error: {e}")
            return False
    
    async def delete(self, key: str) -> bool:
        """Delete key from Redis cache"""
        if not self.available:
            return False
        
        try:
            return bool(self.redis_client.delete(key))
        except Exception as e:
            logger.error(f"Redis delete error: {e}")
            return False
    
    async def clear_pattern(self, pattern: str) -> int:
        """Clear keys matching pattern"""
        if not self.available:
            return 0
        
        try:
            keys = self.redis_client.keys(pattern)
            if keys:
                return self.redis_client.delete(*keys)
            return 0
        except Exception as e:
            logger.error(f"Redis clear pattern error: {e}")
            return 0


class MultiLevelCache:
    """Multi-level caching with intelligent routing"""
    
    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        self.memory_cache = MemoryCache()
        self.redis_cache = RedisCache(redis_url)
        self.stats = {
            'hits': {'memory': 0, 'redis': 0, 'total': 0},
            'misses': {'memory': 0, 'redis': 0, 'total': 0},
            'sets': {'memory': 0, 'redis': 0, 'total': 0}
        }
        
        # Attribution
        self.project_attribution = {
            "developers": "Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães",
            "organization": "MackIntegridade",
            "financing": "MackPesquisa"
        }
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value with multi-level lookup"""
        # Try memory cache first
        value = self.memory_cache.get(key)
        if value is not None:
            self.stats['hits']['memory'] += 1
            self.stats['hits']['total'] += 1
            return value
        
        self.stats['misses']['memory'] += 1
        
        # Try Redis cache
        value = await self.redis_cache.get(key)
        if value is not None:
            self.stats['hits']['redis'] += 1
            self.stats['hits']['total'] += 1
            
            # Promote to memory cache
            self.memory_cache.set(key, value, ttl_seconds=300)  # 5 min TTL for promoted items
            return value
        
        self.stats['misses']['redis'] += 1
        self.stats['misses']['total'] += 1
        return None
    
    async def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None, 
                 cache_levels: List[CacheLevel] = None) -> bool:
        """Set value in specified cache levels"""
        if cache_levels is None:
            cache_levels = [CacheLevel.MEMORY, CacheLevel.REDIS]
        
        success = True
        
        # Set in memory cache
        if CacheLevel.MEMORY in cache_levels:
            memory_success = self.memory_cache.set(key, value, ttl_seconds)
            if memory_success:
                self.stats['sets']['memory'] += 1
            success = success and memory_success
        
        # Set in Redis cache
        if CacheLevel.REDIS in cache_levels:
            redis_success = await self.redis_cache.set(key, value, ttl_seconds)
            if redis_success:
                self.stats['sets']['redis'] += 1
            success = success and redis_success
        
        if success:
            self.stats['sets']['total'] += 1
        
        return success
    
    async def delete(self, key: str) -> bool:
        """Delete from all cache levels"""
        memory_deleted = self.memory_cache.delete(key)
        redis_deleted = await self.redis_cache.delete(key)
        return memory_deleted or redis_deleted
    
    async def invalidate_tags(self, tags: List[str]) -> int:
        """Invalidate entries by tags"""
        # Clear from memory cache
        memory_cleared = self.memory_cache.clear_by_tags(tags)
        
        # Clear from Redis (using patterns)
        redis_cleared = 0
        for tag in tags:
            redis_cleared += await self.redis_cache.clear_pattern(f"*{tag}*")
        
        return memory_cleared + redis_cleared
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_requests = self.stats['hits']['total'] + self.stats['misses']['total']
        hit_rate = (self.stats['hits']['total'] / total_requests * 100) if total_requests > 0 else 0
        
        return {
            **self.stats,
            'hit_rate_percent': round(hit_rate, 2),
            'total_requests': total_requests,
            'attribution': self.project_attribution
        }


class CacheManager:
    """High-level cache management with strategies"""
    
    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        self.cache = MultiLevelCache(redis_url)
        self.refresh_tasks: Dict[str, asyncio.Task] = {}
        
        # Attribution
        self.project_attribution = {
            "developers": "Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães",
            "organization": "MackIntegridade",
            "financing": "MackPesquisa"
        }
    
    async def get_or_compute(self, key: str, compute_func: Callable, 
                           ttl_seconds: int = 3600, 
                           strategy: CacheStrategy = CacheStrategy.TTL,
                           tags: List[str] = None) -> Any:
        """Get value from cache or compute and cache it"""
        # Try to get from cache
        value = await self.cache.get(key)
        if value is not None:
            # Handle refresh-ahead strategy
            if strategy == CacheStrategy.REFRESH_AHEAD:
                await self._maybe_refresh_ahead(key, compute_func, ttl_seconds, tags)
            return value
        
        # Compute value
        try:
            if asyncio.iscoroutinefunction(compute_func):
                value = await compute_func()
            else:
                value = compute_func()
            
            # Cache the computed value
            await self.cache.set(key, value, ttl_seconds)
            
            return value
        except Exception as e:
            logger.error(f"Error computing value for key {key}: {e}")
            raise
    
    async def _maybe_refresh_ahead(self, key: str, compute_func: Callable, 
                                 ttl_seconds: int, tags: List[str] = None):
        """Refresh cache ahead of expiration for refresh-ahead strategy"""
        # Check if refresh is already in progress
        if key in self.refresh_tasks and not self.refresh_tasks[key].done():
            return
        
        # Start background refresh
        self.refresh_tasks[key] = asyncio.create_task(
            self._background_refresh(key, compute_func, ttl_seconds, tags)
        )
    
    async def _background_refresh(self, key: str, compute_func: Callable, 
                                ttl_seconds: int, tags: List[str] = None):
        """Background task to refresh cache entry"""
        try:
            # Wait until 80% of TTL has passed
            await asyncio.sleep(ttl_seconds * 0.8)
            
            # Refresh the value
            if asyncio.iscoroutinefunction(compute_func):
                value = await compute_func()
            else:
                value = compute_func()
            
            await self.cache.set(key, value, ttl_seconds)
            logger.info(f"Refreshed cache for key: {key}")
            
        except Exception as e:
            logger.error(f"Error refreshing cache for key {key}: {e}")
        finally:
            # Clean up task reference
            if key in self.refresh_tasks:
                del self.refresh_tasks[key]


def cache_result(ttl_seconds: int = 3600, key_prefix: str = "", 
                tags: List[str] = None, strategy: CacheStrategy = CacheStrategy.TTL):
    """Decorator for caching function results"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Generate cache key
            key_parts = [key_prefix, func.__name__]
            if args:
                key_parts.append(hashlib.md5(str(args).encode()).hexdigest()[:8])
            if kwargs:
                key_parts.append(hashlib.md5(str(sorted(kwargs.items())).encode()).hexdigest()[:8])
            
            cache_key = ":".join(filter(None, key_parts))
            
            # Get or create cache manager
            cache_manager = getattr(wrapper, '_cache_manager', None)
            if cache_manager is None:
                cache_manager = CacheManager()
                wrapper._cache_manager = cache_manager
            
            # Get or compute value
            return await cache_manager.get_or_compute(
                cache_key, 
                lambda: func(*args, **kwargs),
                ttl_seconds=ttl_seconds,
                strategy=strategy,
                tags=tags
            )
        
        return wrapper
    return decorator


class DocumentCache:
    """Specialized cache for legislative documents"""
    
    def __init__(self, cache_manager: CacheManager):
        self.cache_manager = cache_manager
        self.document_ttl = 3600 * 24  # 24 hours
        self.search_ttl = 3600 * 2     # 2 hours
        self.metadata_ttl = 3600 * 12  # 12 hours
        
        # Attribution
        self.project_attribution = {
            "developers": "Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães",
            "organization": "MackIntegridade",
            "financing": "MackPesquisa"
        }
    
    async def get_document(self, document_id: str, fetch_func: Callable) -> Dict[str, Any]:
        """Get document with caching"""
        return await self.cache_manager.get_or_compute(
            f"document:{document_id}",
            fetch_func,
            ttl_seconds=self.document_ttl,
            tags=['documents', f'doc:{document_id}']
        )
    
    async def get_search_results(self, query_hash: str, search_func: Callable) -> List[Dict]:
        """Get search results with caching"""
        return await self.cache_manager.get_or_compute(
            f"search:{query_hash}",
            search_func,
            ttl_seconds=self.search_ttl,
            tags=['search', 'results']
        )
    
    async def get_document_metadata(self, document_id: str, metadata_func: Callable) -> Dict:
        """Get document metadata with caching"""
        return await self.cache_manager.get_or_compute(
            f"metadata:{document_id}",
            metadata_func,
            ttl_seconds=self.metadata_ttl,
            tags=['metadata', f'doc:{document_id}']
        )
    
    async def invalidate_document(self, document_id: str):
        """Invalidate all caches for a document"""
        await self.cache_manager.cache.invalidate_tags([f'doc:{document_id}'])
    
    async def invalidate_search_cache(self):
        """Invalidate all search caches"""
        await self.cache_manager.cache.invalidate_tags(['search'])


# Global cache manager instance
_global_cache_manager = None

def get_cache_manager() -> CacheManager:
    """Get global cache manager instance"""
    global _global_cache_manager
    if _global_cache_manager is None:
        _global_cache_manager = CacheManager()
    return _global_cache_manager


# Example usage functions
@cache_result(ttl_seconds=3600, key_prefix="api", tags=["api_calls"])
async def get_legislative_data(chamber: str, date_range: str) -> Dict[str, Any]:
    """Example cached API call"""
    # Simulate API call
    await asyncio.sleep(0.1)  # Simulate network delay
    return {
        "chamber": chamber,
        "date_range": date_range,
        "data": f"Legislative data for {chamber} in {date_range}",
        "cached_at": datetime.now().isoformat()
    }


if __name__ == "__main__":
    async def main():
        print("🗃️  Monitor Legislativo v4 - Application Cache System")
        print("Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães")
        print("Organization: MackIntegridade")
        print("Financing: MackPesquisa")
        print("=" * 70)
        
        # Test cache system
        cache_manager = CacheManager()
        
        # Test basic caching
        await cache_manager.cache.set("test_key", "test_value", ttl_seconds=60)
        value = await cache_manager.cache.get("test_key")
        print(f"✅ Basic cache test: {value}")
        
        # Test function caching
        result1 = await get_legislative_data("camara", "2024-01")
        result2 = await get_legislative_data("camara", "2024-01")  # Should be cached
        print(f"✅ Function cache test: {result1['cached_at'] == result2['cached_at']}")
        
        # Show cache stats
        stats = cache_manager.cache.get_stats()
        print(f"📊 Cache statistics: {stats}")
    
    asyncio.run(main())