"""
Smart Caching System for Legislative Monitor
Multi-layer caching with Redis and in-memory support
"""

import json
import time
import hashlib
from typing import Any, Optional, Dict, Set, Callable, Union
from functools import wraps
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import threading
import logging

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class CacheConfig:
    """Configuration for cache TTL settings"""
    default_ttl: int = 3600  # 1 hour
    api_response_ttl: int = 900  # 15 minutes
    search_results_ttl: int = 1800  # 30 minutes
    metadata_ttl: int = 7200  # 2 hours
    user_data_ttl: int = 300  # 5 minutes
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    max_memory_items: int = 1000

class CacheKeyBuilder:
    """Generates consistent cache keys"""
    
    @staticmethod
    def build_key(prefix: str, *args, **kwargs) -> str:
        """Build a cache key from prefix and parameters"""
        key_parts = [prefix]
        
        # Add positional arguments
        for arg in args:
            if isinstance(arg, (dict, list)):
                key_parts.append(hashlib.md5(json.dumps(arg, sort_keys=True).encode()).hexdigest()[:8])
            else:
                key_parts.append(str(arg))
        
        # Add keyword arguments
        if kwargs:
            sorted_kwargs = sorted(kwargs.items())
            kwargs_str = json.dumps(sorted_kwargs, sort_keys=True)
            key_parts.append(hashlib.md5(kwargs_str.encode()).hexdigest()[:8])
        
        return ":".join(key_parts)
    
    @staticmethod
    def api_key(service: str, endpoint: str, params: Dict = None) -> str:
        """Generate key for API responses"""
        return CacheKeyBuilder.build_key("api", service, endpoint, **(params or {}))
    
    @staticmethod
    def search_key(query: str, filters: Dict = None) -> str:
        """Generate key for search results"""
        return CacheKeyBuilder.build_key("search", query, **(filters or {}))

class BaseCache:
    """Base cache interface"""
    
    def get(self, key: str) -> Optional[Any]:
        raise NotImplementedError
    
    def set(self, key: str, value: Any, ttl: int = None) -> bool:
        raise NotImplementedError
    
    def delete(self, key: str) -> bool:
        raise NotImplementedError
    
    def exists(self, key: str) -> bool:
        raise NotImplementedError
    
    def clear(self) -> bool:
        raise NotImplementedError

class MemoryCache(BaseCache):
    """In-memory cache with TTL support"""
    
    def __init__(self, max_items: int = 1000):
        self._cache: Dict[str, Dict] = {}
        self._max_items = max_items
        self._lock = threading.RLock()
    
    def _cleanup_expired(self):
        """Remove expired items"""
        now = time.time()
        expired_keys = []
        
        for key, data in self._cache.items():
            if data.get('expires_at', 0) <= now:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self._cache[key]
    
    def _ensure_capacity(self):
        """Ensure cache doesn't exceed max items (LRU eviction)"""
        if len(self._cache) >= self._max_items:
            # Sort by last access time and remove oldest
            sorted_items = sorted(
                self._cache.items(),
                key=lambda x: x[1].get('accessed_at', 0)
            )
            
            # Remove oldest 20% of items
            items_to_remove = max(1, len(sorted_items) // 5)
            for key, _ in sorted_items[:items_to_remove]:
                del self._cache[key]
    
    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            self._cleanup_expired()
            
            if key not in self._cache:
                return None
            
            data = self._cache[key]
            now = time.time()
            
            if data.get('expires_at', 0) <= now:
                del self._cache[key]
                return None
            
            # Update access time for LRU
            data['accessed_at'] = now
            return data['value']
    
    def set(self, key: str, value: Any, ttl: int = None) -> bool:
        with self._lock:
            self._cleanup_expired()
            self._ensure_capacity()
            
            now = time.time()
            expires_at = now + ttl if ttl else now + 3600  # Default 1 hour
            
            self._cache[key] = {
                'value': value,
                'created_at': now,
                'accessed_at': now,
                'expires_at': expires_at
            }
            return True
    
    def delete(self, key: str) -> bool:
        with self._lock:
            return self._cache.pop(key, None) is not None
    
    def exists(self, key: str) -> bool:
        return self.get(key) is not None
    
    def clear(self) -> bool:
        with self._lock:
            self._cache.clear()
            return True

class RedisCache(BaseCache):
    """Redis-based cache"""
    
    def __init__(self, config: CacheConfig):
        self._config = config
        self._redis = None
        self._connect()
    
    def _connect(self):
        """Connect to Redis"""
        if not REDIS_AVAILABLE:
            logger.warning("Redis not available, falling back to memory cache")
            return
        
        try:
            self._redis = redis.Redis(
                host=self._config.redis_host,
                port=self._config.redis_port,
                db=self._config.redis_db,
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5
            )
            # Test connection
            self._redis.ping()
            logger.info("Connected to Redis cache")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self._redis = None
    
    def _is_available(self) -> bool:
        """Check if Redis is available"""
        if not self._redis:
            return False
        
        try:
            self._redis.ping()
            return True
        except:
            return False
    
    def get(self, key: str) -> Optional[Any]:
        if not self._is_available():
            return None
        
        try:
            value = self._redis.get(key)
            if value is None:
                return None
            return json.loads(value)
        except Exception as e:
            logger.error(f"Redis get error: {e}")
            return None
    
    def set(self, key: str, value: Any, ttl: int = None) -> bool:
        if not self._is_available():
            return False
        
        try:
            serialized = json.dumps(value, default=str)
            return self._redis.setex(
                key, 
                ttl or self._config.default_ttl, 
                serialized
            )
        except Exception as e:
            logger.error(f"Redis set error: {e}")
            return False
    
    def delete(self, key: str) -> bool:
        if not self._is_available():
            return False
        
        try:
            return bool(self._redis.delete(key))
        except Exception as e:
            logger.error(f"Redis delete error: {e}")
            return False
    
    def exists(self, key: str) -> bool:
        if not self._is_available():
            return False
        
        try:
            return bool(self._redis.exists(key))
        except Exception as e:
            logger.error(f"Redis exists error: {e}")
            return False
    
    def clear(self) -> bool:
        if not self._is_available():
            return False
        
        try:
            return self._redis.flushdb()
        except Exception as e:
            logger.error(f"Redis clear error: {e}")
            return False

class MultiLayerCache:
    """Multi-layer cache with automatic promotion"""
    
    def __init__(self, config: CacheConfig):
        self.config = config
        self.memory_cache = MemoryCache(config.max_memory_items)
        self.redis_cache = RedisCache(config) if REDIS_AVAILABLE else None
        self._promotion_threshold = 3  # Promote to memory after 3 hits
        self._hit_counts: Dict[str, int] = {}
        self._lock = threading.RLock()
    
    def get(self, key: str) -> Optional[Any]:
        # Try memory cache first
        value = self.memory_cache.get(key)
        if value is not None:
            return value
        
        # Try Redis cache
        if self.redis_cache:
            value = self.redis_cache.get(key)
            if value is not None:
                # Track hits for promotion
                with self._lock:
                    self._hit_counts[key] = self._hit_counts.get(key, 0) + 1
                    
                    # Promote to memory cache if frequently accessed
                    if self._hit_counts[key] >= self._promotion_threshold:
                        self.memory_cache.set(key, value, self.config.default_ttl)
                        del self._hit_counts[key]
                
                return value
        
        return None
    
    def set(self, key: str, value: Any, ttl: int = None) -> bool:
        ttl = ttl or self.config.default_ttl
        
        # Store in both layers
        memory_success = self.memory_cache.set(key, value, ttl)
        redis_success = True
        
        if self.redis_cache:
            redis_success = self.redis_cache.set(key, value, ttl)
        
        return memory_success or redis_success
    
    def delete(self, key: str) -> bool:
        memory_success = self.memory_cache.delete(key)
        redis_success = True
        
        if self.redis_cache:
            redis_success = self.redis_cache.delete(key)
        
        # Clean up hit tracking
        with self._lock:
            self._hit_counts.pop(key, None)
        
        return memory_success or redis_success
    
    def exists(self, key: str) -> bool:
        return (self.memory_cache.exists(key) or 
                (self.redis_cache and self.redis_cache.exists(key)))
    
    def clear(self) -> bool:
        memory_success = self.memory_cache.clear()
        redis_success = True
        
        if self.redis_cache:
            redis_success = self.redis_cache.clear()
        
        with self._lock:
            self._hit_counts.clear()
        
        return memory_success and redis_success

class SmartCache:
    """Main cache class with invalidation rules"""
    
    def __init__(self, config: CacheConfig = None):
        self.config = config or CacheConfig()
        self.cache = MultiLayerCache(self.config)
        self.invalidation_patterns: Dict[str, Set[str]] = {}
        self._lock = threading.RLock()
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        return self.cache.get(key)
    
    def set(self, key: str, value: Any, ttl: int = None, tags: Set[str] = None) -> bool:
        """Set value in cache with optional tags for invalidation"""
        success = self.cache.set(key, value, ttl)
        
        if success and tags:
            with self._lock:
                for tag in tags:
                    if tag not in self.invalidation_patterns:
                        self.invalidation_patterns[tag] = set()
                    self.invalidation_patterns[tag].add(key)
        
        return success
    
    def delete(self, key: str) -> bool:
        """Delete specific key"""
        return self.cache.delete(key)
    
    def invalidate_by_pattern(self, pattern: str) -> int:
        """Invalidate all keys matching pattern"""
        invalidated = 0
        
        with self._lock:
            if pattern in self.invalidation_patterns:
                keys_to_delete = self.invalidation_patterns[pattern].copy()
                
                for key in keys_to_delete:
                    if self.cache.delete(key):
                        invalidated += 1
                
                # Clean up pattern
                del self.invalidation_patterns[pattern]
        
        return invalidated
    
    def invalidate_by_prefix(self, prefix: str) -> int:
        """Invalidate all cached API responses for a service"""
        # This is a simplified implementation
        # In production, you'd want to track keys by prefix more efficiently
        logger.info(f"Invalidating cache entries with prefix: {prefix}")
        return 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return {
            'memory_cache_size': len(self.cache.memory_cache._cache),
            'redis_available': self.cache.redis_cache is not None,
            'invalidation_patterns': len(self.invalidation_patterns),
            'config': asdict(self.config)
        }

# Global cache instance
_cache_instance: Optional[SmartCache] = None

def get_cache() -> SmartCache:
    """Get global cache instance"""
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = SmartCache()
    return _cache_instance

def init_cache(config: CacheConfig = None) -> SmartCache:
    """Initialize global cache with config"""
    global _cache_instance
    _cache_instance = SmartCache(config)
    return _cache_instance

# Decorators for easy caching

def cached(ttl: int = None, key_prefix: str = None, tags: Set[str] = None):
    """Decorator to cache function results"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            cache = get_cache()
            
            # Build cache key
            prefix = key_prefix or f"func:{func.__name__}"
            key = CacheKeyBuilder.build_key(prefix, *args, **kwargs)
            
            # Try to get from cache
            result = cache.get(key)
            if result is not None:
                return result
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            cache.set(key, result, ttl, tags)
            
            return result
        
        # Add cache control methods to function
        wrapper.cache_key = lambda *args, **kwargs: CacheKeyBuilder.build_key(
            key_prefix or f"func:{func.__name__}", *args, **kwargs
        )
        wrapper.invalidate = lambda *args, **kwargs: get_cache().delete(
            wrapper.cache_key(*args, **kwargs)
        )
        
        return wrapper
    return decorator

def cached_api_response(service: str, ttl: int = None):
    """Decorator specifically for API responses"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            cache = get_cache()
            
            # Extract endpoint from function name or kwargs
            endpoint = kwargs.get('endpoint', func.__name__)
            params = {k: v for k, v in kwargs.items() if k != 'endpoint'}
            
            key = CacheKeyBuilder.api_key(service, endpoint, params)
            
            # Try cache first
            result = cache.get(key)
            if result is not None:
                logger.debug(f"Cache hit for {service}:{endpoint}")
                return result
            
            # Execute API call and cache result
            result = func(*args, **kwargs)
            cache_ttl = ttl or cache.config.api_response_ttl
            tags = {f"api:{service}", f"service:{service}"}
            
            cache.set(key, result, cache_ttl, tags)
            logger.debug(f"Cached {service}:{endpoint} for {cache_ttl}s")
            
            return result
        
        return wrapper
    return decorator