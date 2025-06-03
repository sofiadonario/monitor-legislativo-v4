"""
Unified Cache Strategy for Monitor Legislativo v4
Implements multi-layer caching with intelligent routing

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import asyncio
import logging
from typing import Any, Optional, Dict, List, Callable
from datetime import datetime, timedelta
from enum import Enum
import json

from .redis_cache import get_redis_cache
from .cdn_cache import cdn_manager, CacheKeyGenerator
from ..utils.smart_cache import get_cache as get_memory_cache

logger = logging.getLogger(__name__)

class CacheLayer(Enum):
    """Cache layer priorities"""
    MEMORY = 1  # In-memory cache (fastest)
    REDIS = 2   # Redis cache (distributed)
    CDN = 3     # CDN cache (static content)

class CacheStrategy:
    """Unified caching strategy with multiple layers"""
    
    def __init__(self):
        self.memory_cache = get_memory_cache()
        self.redis_cache = None
        self.cdn_enabled = False
        self.cache_stats = {
            "hits": {"memory": 0, "redis": 0, "cdn": 0},
            "misses": {"memory": 0, "redis": 0, "cdn": 0},
            "errors": {"memory": 0, "redis": 0, "cdn": 0}
        }
        
    async def initialize(self, redis_config: Optional[Dict[str, Any]] = None,
                        cdn_config: Optional[Dict[str, Any]] = None):
        """Initialize cache layers"""
        # Initialize Redis
        if redis_config:
            self.redis_cache = await get_redis_cache()
            if not self.redis_cache:
                from .redis_cache import init_redis_cache
                await init_redis_cache(**redis_config)
                self.redis_cache = await get_redis_cache()
                
        # Initialize CDN
        if cdn_config:
            for provider_name, provider_config in cdn_config.items():
                if provider_name == "cloudflare":
                    from .cdn_cache import CloudflareCDN
                    provider = CloudflareCDN(**provider_config)
                    await cdn_manager.add_provider("cloudflare", provider)
                    self.cdn_enabled = True
                elif provider_name == "fastly":
                    from .cdn_cache import FastlyCDN
                    provider = FastlyCDN(**provider_config)
                    await cdn_manager.add_provider("fastly", provider)
                    self.cdn_enabled = True
                    
        logger.info("Cache strategy initialized")
        
    async def get(self, key: str, cache_layers: List[CacheLayer] = None) -> Optional[Any]:
        """Get value from cache using layer priority"""
        if cache_layers is None:
            cache_layers = [CacheLayer.MEMORY, CacheLayer.REDIS]
            
        for layer in sorted(cache_layers, key=lambda x: x.value):
            try:
                value = None
                
                if layer == CacheLayer.MEMORY:
                    value = self.memory_cache.get(key)
                    if value is not None:
                        self.cache_stats["hits"]["memory"] += 1
                        logger.debug(f"Memory cache hit for key: {key}")
                        return value
                    else:
                        self.cache_stats["misses"]["memory"] += 1
                        
                elif layer == CacheLayer.REDIS and self.redis_cache:
                    value = await self.redis_cache.get(key)
                    if value is not None:
                        self.cache_stats["hits"]["redis"] += 1
                        logger.debug(f"Redis cache hit for key: {key}")
                        
                        # Backfill to memory cache
                        self.memory_cache.set(key, value, ttl=300)  # 5 min TTL
                        return value
                    else:
                        self.cache_stats["misses"]["redis"] += 1
                        
            except Exception as e:
                self.cache_stats["errors"][layer.name.lower()] += 1
                logger.error(f"Cache get error in {layer.name}: {e}")
                
        return None
        
    async def set(self, key: str, value: Any, ttl: Optional[int] = None,
                  cache_layers: List[CacheLayer] = None) -> bool:
        """Set value in specified cache layers"""
        if cache_layers is None:
            cache_layers = [CacheLayer.MEMORY, CacheLayer.REDIS]
            
        success = False
        
        for layer in cache_layers:
            try:
                if layer == CacheLayer.MEMORY:
                    self.memory_cache.set(key, value, ttl=ttl)
                    success = True
                    
                elif layer == CacheLayer.REDIS and self.redis_cache:
                    await self.redis_cache.set(key, value, ttl=ttl)
                    success = True
                    
            except Exception as e:
                self.cache_stats["errors"][layer.name.lower()] += 1
                logger.error(f"Cache set error in {layer.name}: {e}")
                
        return success
        
    async def delete(self, key: str, cache_layers: List[CacheLayer] = None) -> bool:
        """Delete value from specified cache layers"""
        if cache_layers is None:
            cache_layers = [CacheLayer.MEMORY, CacheLayer.REDIS]
            
        success = False
        
        for layer in cache_layers:
            try:
                if layer == CacheLayer.MEMORY:
                    self.memory_cache.delete(key)
                    success = True
                    
                elif layer == CacheLayer.REDIS and self.redis_cache:
                    await self.redis_cache.delete(key)
                    success = True
                    
            except Exception as e:
                self.cache_stats["errors"][layer.name.lower()] += 1
                logger.error(f"Cache delete error in {layer.name}: {e}")
                
        return success
        
    async def cache_static_content(self, content: bytes, content_type: str,
                                  url_path: str) -> Optional[str]:
        """Cache static content to CDN"""
        if not self.cdn_enabled:
            return None
            
        try:
            from .cdn_cache import cache_static_content
            cdn_url = await cache_static_content(url_path, content, content_type)
            self.cache_stats["hits"]["cdn"] += 1
            return cdn_url
        except Exception as e:
            self.cache_stats["errors"]["cdn"] += 1
            logger.error(f"CDN cache error: {e}")
            return None
            
    async def invalidate_pattern(self, pattern: str) -> int:
        """Invalidate cache entries matching pattern"""
        count = 0
        
        # Invalidate memory cache
        count += self.memory_cache.invalidate_by_prefix(pattern)
        
        # Invalidate Redis cache
        if self.redis_cache:
            count += await self.redis_cache.delete_pattern(f"{pattern}*")
            
        # Invalidate CDN cache
        if self.cdn_enabled:
            await cdn_manager.purge_pattern(pattern)
            
        logger.info(f"Invalidated {count} cache entries for pattern: {pattern}")
        return count
        
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        stats = {
            "layers": {
                "memory": {
                    "enabled": True,
                    "stats": self.memory_cache.get_stats()
                },
                "redis": {
                    "enabled": self.redis_cache is not None,
                    "connected": self.redis_cache._connected if self.redis_cache else False
                },
                "cdn": {
                    "enabled": self.cdn_enabled,
                    "providers": list(cdn_manager.providers.keys())
                }
            },
            "performance": self.cache_stats,
            "timestamp": datetime.now().isoformat()
        }
        
        # Calculate hit rates
        for layer in ["memory", "redis", "cdn"]:
            hits = self.cache_stats["hits"][layer]
            misses = self.cache_stats["misses"][layer]
            total = hits + misses
            
            if total > 0:
                stats["performance"][f"{layer}_hit_rate"] = (hits / total) * 100
            else:
                stats["performance"][f"{layer}_hit_rate"] = 0.0
                
        return stats

class CachedEndpoint:
    """Decorator for caching API endpoints"""
    
    def __init__(self, ttl: int = 300, 
                 key_builder: Optional[Callable] = None,
                 cache_layers: List[CacheLayer] = None):
        self.ttl = ttl
        self.key_builder = key_builder
        self.cache_layers = cache_layers or [CacheLayer.MEMORY, CacheLayer.REDIS]
        
    def __call__(self, func: Callable) -> Callable:
        async def wrapper(*args, **kwargs):
            # Build cache key
            if self.key_builder:
                cache_key = self.key_builder(*args, **kwargs)
            else:
                # Default key builder
                cache_key = f"{func.__name__}:{str(args)}:{str(kwargs)}"
                
            # Try to get from cache
            cached_value = await cache_strategy.get(cache_key, self.cache_layers)
            if cached_value is not None:
                return cached_value
                
            # Execute function
            result = await func(*args, **kwargs)
            
            # Cache result
            await cache_strategy.set(cache_key, result, self.ttl, self.cache_layers)
            
            return result
            
        return wrapper

# Smart cache warming
class CacheWarmer:
    """Preloads frequently accessed data into cache"""
    
    def __init__(self, strategy: CacheStrategy):
        self.strategy = strategy
        self.warming_tasks = []
        
    async def warm_search_results(self, popular_queries: List[str]):
        """Warm cache with popular search queries"""
        for query in popular_queries:
            key = CacheKeyGenerator.search_results_key(query, ["all"], 1)
            
            # Check if already cached
            if await self.strategy.get(key):
                continue
                
            # Fetch and cache data
            try:
                # In real implementation, would call search API
                # For now, create mock data
                mock_results = {
                    "query": query,
                    "results": [],
                    "timestamp": datetime.now().isoformat()
                }
                
                await self.strategy.set(key, mock_results, ttl=3600)
                logger.info(f"Warmed cache for query: {query}")
                
            except Exception as e:
                logger.error(f"Cache warming error for query {query}: {e}")
                
    async def warm_static_content(self):
        """Warm CDN with static assets"""
        static_assets = [
            ("css/main.css", "text/css"),
            ("js/app.js", "application/javascript"),
            ("images/logo.png", "image/png")
        ]
        
        for asset_path, content_type in static_assets:
            # In real implementation, would read actual files
            mock_content = f"/* {asset_path} content */".encode()
            
            cdn_url = await self.strategy.cache_static_content(
                mock_content, content_type, asset_path
            )
            
            if cdn_url:
                logger.info(f"Warmed CDN for asset: {asset_path} -> {cdn_url}")
                
    async def start_periodic_warming(self, interval: int = 3600):
        """Start periodic cache warming"""
        async def warm_loop():
            while True:
                try:
                    await self.warm_search_results([
                        "política pública",
                        "saúde",
                        "educação",
                        "meio ambiente"
                    ])
                    await self.warm_static_content()
                except Exception as e:
                    logger.error(f"Cache warming error: {e}")
                    
                await asyncio.sleep(interval)
                
        task = asyncio.create_task(warm_loop())
        self.warming_tasks.append(task)
        
    def stop_warming(self):
        """Stop all warming tasks"""
        for task in self.warming_tasks:
            task.cancel()
        self.warming_tasks.clear()

# Global cache strategy instance
cache_strategy = CacheStrategy()

# Convenience functions
async def get_cached(key: str) -> Optional[Any]:
    """Get value from cache"""
    return await cache_strategy.get(key)

async def set_cached(key: str, value: Any, ttl: Optional[int] = None) -> bool:
    """Set value in cache"""
    return await cache_strategy.set(key, value, ttl)

async def invalidate_cache(pattern: str) -> int:
    """Invalidate cache by pattern"""
    return await cache_strategy.invalidate_pattern(pattern)

async def get_cache_stats() -> Dict[str, Any]:
    """Get cache statistics"""
    return cache_strategy.get_stats()