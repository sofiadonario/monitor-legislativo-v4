"""
Tenant Cache Management for Monitor Legislativo v4
Handles cache isolation per tenant

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import logging
from typing import Dict, Any, Optional, List, Set
from datetime import datetime, timedelta
import asyncio
import json

from .tenant_model import Tenant
from .tenant_manager import get_current_tenant
from ..cache.redis_cache import RedisCache
from ..cache.cache_strategy import CacheStrategy

logger = logging.getLogger(__name__)

class TenantCache:
    """Cache operations with tenant isolation"""
    
    def __init__(self, tenant: Tenant, backend: str = "redis"):
        self.tenant = tenant
        self.prefix = tenant.get_cache_prefix()
        self.backend = backend
        
        # Initialize cache backend
        if backend == "redis":
            self.cache = RedisCache()
        else:
            # Fallback to in-memory cache
            self.cache = CacheStrategy()
    
    def _make_key(self, key: str) -> str:
        """Make tenant-specific cache key"""
        return f"{self.prefix}{key}"
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        tenant_key = self._make_key(key)
        
        # Track cache access
        await self._track_access("get", key)
        
        return await self.cache.get(tenant_key)
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache"""
        tenant_key = self._make_key(key)
        
        # Check storage limits
        if not await self._check_storage_limit():
            logger.warning(f"Tenant {self.tenant.id} exceeding cache storage limit")
            return False
        
        # Track cache operation
        await self._track_access("set", key)
        
        return await self.cache.set(tenant_key, value, ttl)
    
    async def delete(self, key: str) -> bool:
        """Delete value from cache"""
        tenant_key = self._make_key(key)
        
        # Track cache operation
        await self._track_access("delete", key)
        
        return await self.cache.delete(tenant_key)
    
    async def exists(self, key: str) -> bool:
        """Check if key exists"""
        tenant_key = self._make_key(key)
        return await self.cache.exists(tenant_key)
    
    async def get_many(self, keys: List[str]) -> Dict[str, Any]:
        """Get multiple values"""
        tenant_keys = [self._make_key(key) for key in keys]
        
        # Track cache access
        await self._track_access("get_many", f"{len(keys)} keys")
        
        # Get values
        if hasattr(self.cache, 'mget'):
            values = await self.cache.mget(tenant_keys)
            return dict(zip(keys, values))
        else:
            # Fallback for backends without mget
            result = {}
            for key, tenant_key in zip(keys, tenant_keys):
                value = await self.cache.get(tenant_key)
                if value is not None:
                    result[key] = value
            return result
    
    async def set_many(self, mapping: Dict[str, Any], ttl: Optional[int] = None) -> bool:
        """Set multiple values"""
        # Check storage limits
        if not await self._check_storage_limit():
            return False
        
        # Track cache operation
        await self._track_access("set_many", f"{len(mapping)} keys")
        
        # Transform keys
        tenant_mapping = {
            self._make_key(key): value 
            for key, value in mapping.items()
        }
        
        # Set values
        if hasattr(self.cache, 'mset'):
            return await self.cache.mset(tenant_mapping, ttl)
        else:
            # Fallback for backends without mset
            success = True
            for key, value in tenant_mapping.items():
                if not await self.cache.set(key, value, ttl):
                    success = False
            return success
    
    async def invalidate_pattern(self, pattern: str) -> int:
        """Invalidate keys matching pattern"""
        tenant_pattern = self._make_key(pattern)
        
        # Track cache operation
        await self._track_access("invalidate", pattern)
        
        if hasattr(self.cache, 'invalidate'):
            return await self.cache.invalidate(tenant_pattern)
        else:
            # Fallback: get keys and delete
            count = 0
            # This is a simplified version - in production, 
            # implement proper pattern matching
            return count
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics for tenant"""
        stats = {
            "tenant_id": self.tenant.id,
            "cache_prefix": self.prefix,
            "operations": await self._get_operation_stats(),
            "storage": await self._get_storage_stats()
        }
        
        return stats
    
    async def _check_storage_limit(self) -> bool:
        """Check if tenant is within storage limits"""
        # Get current cache size
        size_mb = await self._get_cache_size_mb()
        
        # Check against limit (cache gets portion of storage)
        cache_limit_mb = self.tenant.limits.storage_gb * 1024 * 0.1  # 10% of storage
        
        return size_mb < cache_limit_mb
    
    async def _get_cache_size_mb(self) -> float:
        """Get approximate cache size in MB"""
        # This is approximate - in production, track more accurately
        if hasattr(self.cache, 'dbsize'):
            key_count = await self.cache.dbsize(self.prefix)
            # Estimate 1KB per key average
            return (key_count * 1) / 1024
        return 0.0
    
    async def _track_access(self, operation: str, key: str) -> None:
        """Track cache access for analytics"""
        # Update tenant usage
        from .tenant_manager import tenant_manager
        
        await tenant_manager.update_usage(
            self.tenant.id,
            f"cache_{operation}_count",
            1
        )
    
    async def _get_operation_stats(self) -> Dict[str, int]:
        """Get operation statistics"""
        # In production, track these properly
        return {
            "gets": 0,
            "sets": 0,
            "deletes": 0,
            "hits": 0,
            "misses": 0
        }
    
    async def _get_storage_stats(self) -> Dict[str, Any]:
        """Get storage statistics"""
        size_mb = await self._get_cache_size_mb()
        
        return {
            "size_mb": size_mb,
            "key_count": 0,  # Track this properly in production
            "limit_mb": self.tenant.limits.storage_gb * 1024 * 0.1
        }

class TenantCacheManager:
    """Manages cache instances for multiple tenants"""
    
    def __init__(self):
        self.caches: Dict[str, TenantCache] = {}
        self._lock = asyncio.Lock()
        
    async def get_cache(self, tenant: Tenant) -> TenantCache:
        """Get cache instance for tenant"""
        cache_key = tenant.id
        
        if cache_key not in self.caches:
            async with self._lock:
                # Double-check after acquiring lock
                if cache_key not in self.caches:
                    # Determine backend based on tenant isolation
                    backend = "redis" if tenant.isolation_level.value != "shared" else "memory"
                    
                    self.caches[cache_key] = TenantCache(tenant, backend)
                    logger.info(f"Created cache instance for tenant {tenant.id}")
        
        return self.caches[cache_key]
    
    async def invalidate_tenant_cache(self, tenant: Tenant) -> int:
        """Invalidate all cache for a tenant"""
        cache = await self.get_cache(tenant)
        count = await cache.invalidate_pattern("*")
        
        # Remove from cache manager
        self.caches.pop(tenant.id, None)
        
        logger.info(f"Invalidated {count} cache entries for tenant {tenant.id}")
        return count
    
    async def get_all_stats(self) -> List[Dict[str, Any]]:
        """Get statistics for all tenant caches"""
        stats = []
        
        for tenant_id, cache in self.caches.items():
            cache_stats = await cache.get_stats()
            stats.append(cache_stats)
            
        return stats

# Global cache manager
tenant_cache_manager = TenantCacheManager()

# Helper functions
async def get_tenant_cache(tenant: Optional[Tenant] = None) -> TenantCache:
    """Get cache for tenant"""
    if not tenant:
        tenant = get_current_tenant()
        
    if not tenant:
        raise ValueError("No tenant context available")
        
    return await tenant_cache_manager.get_cache(tenant)

async def invalidate_tenant_cache(pattern: str = "*", tenant: Optional[Tenant] = None) -> int:
    """Invalidate cache entries for tenant"""
    cache = await get_tenant_cache(tenant)
    return await cache.invalidate_pattern(pattern)

# Cache decorators
def tenant_cached(key_pattern: str, ttl: int = 3600):
    """Decorator for caching with tenant isolation"""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Get tenant cache
            cache = await get_tenant_cache()
            
            # Generate cache key
            import hashlib
            key_data = f"{func.__name__}:{args}:{kwargs}"
            key_hash = hashlib.md5(key_data.encode()).hexdigest()
            cache_key = key_pattern.format(hash=key_hash)
            
            # Try to get from cache
            cached_value = await cache.get(cache_key)
            if cached_value is not None:
                return cached_value
                
            # Execute function
            result = await func(*args, **kwargs)
            
            # Cache result
            await cache.set(cache_key, result, ttl)
            
            return result
            
        return wrapper
    return decorator