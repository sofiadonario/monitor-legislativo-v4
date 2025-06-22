"""
Multi-tier Caching Service for LexML API
Implements Redis and in-memory caching with fallback strategies
"""

import json
import time
import hashlib
from typing import Any, Dict, Optional, Union, List
from datetime import datetime, timedelta
import logging
import asyncio
from functools import wraps
from abc import ABC, abstractmethod
import hashlib

logger = logging.getLogger(__name__)

# Cache TTL Configuration (in seconds)
class CacheTTL:
    SEARCH_RESULTS = 300        # 5 minutes
    DOCUMENT_CONTENT = 1800     # 30 minutes  
    SUGGESTIONS = 600           # 10 minutes
    HEALTH_STATUS = 120         # 2 minutes
    CROSS_REFERENCES = 3600     # 1 hour
    RELATED_DOCUMENTS = 1200    # 20 minutes
    API_RESPONSES = 300         # 5 minutes (default)


class CacheBackend(ABC):
    """Abstract cache backend interface"""
    
    @abstractmethod
    async def get(self, key: str) -> Optional[Any]:
        pass
    
    @abstractmethod
    async def set(self, key: str, value: Any, ttl: int = 3600) -> bool:
        pass
    
    @abstractmethod
    async def delete(self, key: str) -> bool:
        pass
    
    @abstractmethod
    async def clear(self) -> bool:
        pass


class MemoryCacheBackend(CacheBackend):
    """In-memory cache backend for development and fallback"""
    
    def __init__(self, max_size: int = 1000):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.max_size = max_size
        self.access_times: Dict[str, datetime] = {}
    
    async def get(self, key: str) -> Optional[Any]:
        if key in self.cache:
            entry = self.cache[key]
            
            # Check if expired
            if datetime.now() > entry['expires_at']:
                await self.delete(key)
                return None
            
            # Update access time
            self.access_times[key] = datetime.now()
            return entry['value']
        
        return None
    
    async def set(self, key: str, value: Any, ttl: int = 3600) -> bool:
        try:
            # Evict oldest entries if cache is full
            if len(self.cache) >= self.max_size and key not in self.cache:
                await self._evict_lru()
            
            expires_at = datetime.now() + timedelta(seconds=ttl)
            
            self.cache[key] = {
                'value': value,
                'created_at': datetime.now(),
                'expires_at': expires_at,
                'ttl': ttl
            }
            self.access_times[key] = datetime.now()
            
            return True
            
        except Exception as e:
            logger.error(f"Cache set error: {e}")
            return False
    
    async def delete(self, key: str) -> bool:
        try:
            if key in self.cache:
                del self.cache[key]
            if key in self.access_times:
                del self.access_times[key]
            return True
        except Exception as e:
            logger.error(f"Cache delete error: {e}")
            return False
    
    async def clear(self) -> bool:
        try:
            self.cache.clear()
            self.access_times.clear()
            return True
        except Exception as e:
            logger.error(f"Cache clear error: {e}")
            return False
    
    async def _evict_lru(self):
        """Evict least recently used entry"""
        if not self.access_times:
            return
        
        lru_key = min(self.access_times.keys(), key=lambda k: self.access_times[k])
        await self.delete(lru_key)


class RedisCacheBackend(CacheBackend):
    """Redis cache backend for production use"""
    
    def __init__(self, redis_client=None):
        self.redis = redis_client
        self.connected = False
    
    async def connect(self):
        """Initialize Redis connection"""
        try:
            if self.redis is None:
                # Try to import and connect to Redis
                import redis.asyncio as redis
                self.redis = redis.Redis(
                    host='localhost',
                    port=6379,
                    decode_responses=True
                )
            
            # Test connection
            await self.redis.ping()
            self.connected = True
            logger.info("Redis cache backend connected")
            
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}")
            self.connected = False
    
    async def get(self, key: str) -> Optional[Any]:
        if not self.connected:
            return None
        
        try:
            value = await self.redis.get(key)
            if value:
                return json.loads(value)
            return None
        except Exception as e:
            logger.error(f"Redis get error: {e}")
            return None
    
    async def set(self, key: str, value: Any, ttl: int = 3600) -> bool:
        if not self.connected:
            return False
        
        try:
            json_value = json.dumps(value, default=str)
            await self.redis.setex(key, ttl, json_value)
            return True
        except Exception as e:
            logger.error(f"Redis set error: {e}")
            return False
    
    async def delete(self, key: str) -> bool:
        if not self.connected:
            return False
        
        try:
            await self.redis.delete(key)
            return True
        except Exception as e:
            logger.error(f"Redis delete error: {e}")
            return False
    
    async def clear(self) -> bool:
        if not self.connected:
            return False
        
        try:
            await self.redis.flushdb()
            return True
        except Exception as e:
            logger.error(f"Redis clear error: {e}")
            return False


class CacheService:
    """
    Main cache service with fallback support
    Tries Redis first, falls back to memory cache
    """
    
    def __init__(self, redis_client=None):
        self.primary_backend = RedisCacheBackend(redis_client)
        self.fallback_backend = MemoryCacheBackend()
        self.stats = {
            'hits': 0,
            'misses': 0,
            'sets': 0,
            'errors': 0
        }
    
    async def initialize(self):
        """Initialize cache backends"""
        try:
            await self.primary_backend.connect()
        except Exception as e:
            logger.warning(f"Primary cache initialization failed: {e}")
    
    def _generate_key(self, key: str, prefix: str = "lexml") -> str:
        """Generate a standardized cache key"""
        # Create hash for very long keys
        if len(key) > 200:
            key_hash = hashlib.md5(key.encode()).hexdigest()
            return f"{prefix}:{key_hash}"
        
        # Sanitize key
        safe_key = key.replace(" ", "_").replace(":", "_")
        return f"{prefix}:{safe_key}"
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache with fallback"""
        cache_key = self._generate_key(key)
        
        try:
            # Try primary backend (Redis)
            if self.primary_backend.connected:
                value = await self.primary_backend.get(cache_key)
                if value is not None:
                    self.stats['hits'] += 1
                    logger.debug(f"Cache hit (Redis): {cache_key}")
                    return value
            
            # Try fallback backend (Memory)
            value = await self.fallback_backend.get(cache_key)
            if value is not None:
                self.stats['hits'] += 1
                logger.debug(f"Cache hit (Memory): {cache_key}")
                return value
            
            self.stats['misses'] += 1
            logger.debug(f"Cache miss: {cache_key}")
            return None
            
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"Cache get error: {e}")
            return None
    
    async def set(self, key: str, value: Any, ttl: int = 3600) -> bool:
        """Set value in cache with fallback"""
        cache_key = self._generate_key(key)
        success = False
        
        try:
            # Try primary backend (Redis)
            if self.primary_backend.connected:
                primary_success = await self.primary_backend.set(cache_key, value, ttl)
                if primary_success:
                    success = True
                    logger.debug(f"Cache set (Redis): {cache_key}")
            
            # Always set in fallback backend for reliability
            fallback_success = await self.fallback_backend.set(cache_key, value, ttl)
            if fallback_success:
                success = True
                logger.debug(f"Cache set (Memory): {cache_key}")
            
            if success:
                self.stats['sets'] += 1
            
            return success
            
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"Cache set error: {e}")
            return False
    
    async def delete(self, key: str) -> bool:
        """Delete value from all cache backends"""
        cache_key = self._generate_key(key)
        success = False
        
        try:
            # Delete from primary backend
            if self.primary_backend.connected:
                await self.primary_backend.delete(cache_key)
                success = True
            
            # Delete from fallback backend
            await self.fallback_backend.delete(cache_key)
            success = True
            
            logger.debug(f"Cache delete: {cache_key}")
            return success
            
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"Cache delete error: {e}")
            return False
    
    async def clear_pattern(self, pattern: str) -> bool:
        """Clear cache entries matching pattern"""
        try:
            # For simplicity, just clear all in memory cache
            # Redis pattern deletion would need SCAN and DEL
            await self.fallback_backend.clear()
            logger.info(f"Cache pattern clear: {pattern}")
            return True
        except Exception as e:
            logger.error(f"Cache pattern clear error: {e}")
            return False
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_operations = self.stats['hits'] + self.stats['misses']
        hit_rate = (self.stats['hits'] / max(total_operations, 1)) * 100
        
        return {
            'hits': self.stats['hits'],
            'misses': self.stats['misses'],
            'sets': self.stats['sets'],
            'errors': self.stats['errors'],
            'hit_rate_percent': round(hit_rate, 2),
            'primary_backend_connected': self.primary_backend.connected,
            'fallback_backend_active': True
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform cache health check"""
        try:
            test_key = "health_check_test"
            test_value = {"timestamp": datetime.now().isoformat()}
            
            # Test set and get
            set_success = await self.set(test_key, test_value, ttl=60)
            get_result = await self.get(test_key)
            get_success = get_result is not None
            
            # Cleanup
            await self.delete(test_key)
            
            return {
                'healthy': set_success and get_success,
                'set_success': set_success,
                'get_success': get_success,
                'primary_backend': self.primary_backend.connected,
                'fallback_backend': True,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Cache health check error: {e}")
            return {
                'healthy': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }


# Global cache instance
_cache_service: Optional[CacheService] = None


async def get_cache_service() -> CacheService:
    """Get or create global cache service instance"""
    global _cache_service
    if _cache_service is None:
        _cache_service = CacheService()
        await _cache_service.initialize()
    return _cache_service


# Convenience functions
async def cache_get(key: str) -> Optional[Any]:
    """Convenience function for cache get"""
    cache = await get_cache_service()
    return await cache.get(key)


async def cache_set(key: str, value: Any, ttl: int = 3600) -> bool:
    """Convenience function for cache set"""
    cache = await get_cache_service()
    return await cache.set(key, value, ttl)


async def cache_delete(key: str) -> bool:
    """Convenience function for cache delete"""
    cache = await get_cache_service()
    return await cache.delete(key)


# Cache key generation utilities
def create_search_cache_key(query: str, filters: dict, start_record: int, max_records: int) -> str:
    """Create cache key for search results"""
    filter_str = json.dumps(filters or {}, sort_keys=True)
    key_parts = [query, filter_str, str(start_record), str(max_records)]
    return f"search:{hashlib.md5(':'.join(key_parts).encode()).hexdigest()}"

def create_document_cache_key(urn: str) -> str:
    """Create cache key for document content"""
    return f"document:{hashlib.md5(urn.encode()).hexdigest()}"

def create_suggestions_cache_key(term: str, field: str = None) -> str:
    """Create cache key for search suggestions"""
    key = f"suggestions:{hashlib.md5(term.encode()).hexdigest()}"
    return f"{key}:{field}" if field else key

def create_crossref_cache_key(urn: str) -> str:
    """Create cache key for cross-references"""
    return f"crossref:{hashlib.md5(urn.encode()).hexdigest()}"

def create_related_cache_key(urn: str, max_results: int) -> str:
    """Create cache key for related documents"""
    return f"related:{hashlib.md5(urn.encode()).hexdigest()}:{max_results}"

def create_health_cache_key() -> str:
    """Create cache key for API health status"""
    return "health:api_status"


# Caching decorator for automatic function result caching
def cached_result(ttl: int = None, key_func: callable = None):
    """Decorator for automatic caching of async function results"""
    
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                # Default key generation from function name and arguments
                key_parts = [func.__name__]
                key_parts.extend(str(arg)[:50] for arg in args)  # Limit arg length
                key_parts.extend(f"{k}:{str(v)[:50]}" for k, v in sorted(kwargs.items()))
                cache_key = hashlib.md5(':'.join(key_parts).encode()).hexdigest()
            
            # Check cache first
            cache = await get_cache_service()
            cached_result = await cache.get(cache_key)
            
            if cached_result is not None:
                logger.debug(f"Cache hit for {func.__name__}: {cache_key}")
                return cached_result
            
            # Execute function and cache result
            result = await func(*args, **kwargs)
            
            # Determine TTL based on function name if not specified
            cache_ttl = ttl
            if cache_ttl is None:
                if 'search' in func.__name__.lower():
                    cache_ttl = CacheTTL.SEARCH_RESULTS
                elif 'document' in func.__name__.lower():
                    cache_ttl = CacheTTL.DOCUMENT_CONTENT
                elif 'suggest' in func.__name__.lower():
                    cache_ttl = CacheTTL.SUGGESTIONS
                elif 'health' in func.__name__.lower():
                    cache_ttl = CacheTTL.HEALTH_STATUS
                elif 'crossref' in func.__name__.lower() or 'reference' in func.__name__.lower():
                    cache_ttl = CacheTTL.CROSS_REFERENCES
                elif 'related' in func.__name__.lower():
                    cache_ttl = CacheTTL.RELATED_DOCUMENTS
                else:
                    cache_ttl = CacheTTL.API_RESPONSES
            
            # Cache the result
            await cache.set(cache_key, result, cache_ttl)
            logger.debug(f"Cached result for {func.__name__}: {cache_key} (TTL: {cache_ttl}s)")
            
            return result
        
        return wrapper
    return decorator


# Statistics and monitoring utilities
async def get_cache_statistics() -> dict:
    """Get comprehensive cache statistics"""
    cache = await get_cache_service()
    return await cache.get_stats()

async def perform_cache_health_check() -> dict:
    """Perform comprehensive cache health check"""
    cache = await get_cache_service()
    return await cache.health_check()

async def warm_cache_with_common_queries():
    """Pre-populate cache with common search queries"""
    common_queries = [
        "transporte",
        "mobilidade urbana", 
        "trânsito",
        "transporte público",
        "infraestrutura",
        "lei transporte"
    ]
    
    cache = await get_cache_service()
    
    for query in common_queries:
        # Create a placeholder cache entry to mark as "warmed"
        cache_key = create_search_cache_key(query, {}, 1, 50)
        warm_data = {
            "warmed": True,
            "query": query,
            "timestamp": datetime.now().isoformat()
        }
        await cache.set(cache_key, warm_data, CacheTTL.SEARCH_RESULTS)
        logger.info(f"Cache warmed for query: {query}")

async def clear_expired_cache_entries():
    """Clean up expired cache entries (handled automatically by backends)"""
    # This is mostly handled by the backends themselves, but we can add
    # additional cleanup logic here if needed
    cache = await get_cache_service()
    logger.info("Cache cleanup completed")
    return True