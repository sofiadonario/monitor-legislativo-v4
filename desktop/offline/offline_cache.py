"""
Offline Cache for Monitor Legislativo v4 Desktop App
Local caching for offline functionality

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import logging
from typing import Dict, Any, Optional, List, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import json
import hashlib
import os
import asyncio

logger = logging.getLogger(__name__)

class CacheStrategy(Enum):
    """Cache eviction strategies"""
    LRU = "lru"  # Least Recently Used
    LFU = "lfu"  # Least Frequently Used
    TTL = "ttl"  # Time To Live
    FIFO = "fifo"  # First In First Out

@dataclass
class CacheEntry:
    """Represents a cache entry"""
    key: str
    value: Any
    created_at: datetime
    accessed_at: datetime
    access_count: int = 0
    ttl_seconds: Optional[int] = None
    size_bytes: int = 0
    
    def is_expired(self) -> bool:
        """Check if entry is expired"""
        if not self.ttl_seconds:
            return False
        
        age = (datetime.now() - self.created_at).total_seconds()
        return age > self.ttl_seconds
    
    def touch(self) -> None:
        """Update access information"""
        self.accessed_at = datetime.now()
        self.access_count += 1

class OfflineCache:
    """Local cache for offline functionality"""
    
    def __init__(self, 
                 max_size_mb: int = 100,
                 strategy: CacheStrategy = CacheStrategy.LRU,
                 default_ttl: int = 3600):
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.strategy = strategy
        self.default_ttl = default_ttl
        
        self.entries: Dict[str, CacheEntry] = {}
        self.current_size_bytes = 0
        
        # Strategy-specific data structures
        self.lru_order: List[str] = []
        self.access_frequencies: Dict[str, int] = {}
        
        # Persistence
        self.cache_file = "data/offline_cache.json"
        self.auto_persist = True
        
        # Load existing cache
        self._load_from_disk()
        
        # Start cleanup task
        self._cleanup_task = asyncio.create_task(self._periodic_cleanup())
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        if key not in self.entries:
            return None
        
        entry = self.entries[key]
        
        # Check if expired
        if entry.is_expired():
            await self.delete(key)
            return None
        
        # Update access information
        entry.touch()
        self._update_strategy_data(key, "access")
        
        logger.debug(f"Cache hit for key: {key}")
        return entry.value
    
    async def set(self, 
                  key: str, 
                  value: Any, 
                  ttl: Optional[int] = None) -> bool:
        """Set value in cache"""
        try:
            # Calculate size
            serialized = json.dumps(value, default=str)
            size_bytes = len(serialized.encode('utf-8'))
            
            # Check if we need to make space
            if key not in self.entries:
                await self._ensure_space(size_bytes)
            else:
                # Update existing entry size
                old_entry = self.entries[key]
                self.current_size_bytes -= old_entry.size_bytes
            
            # Create entry
            entry = CacheEntry(
                key=key,
                value=value,
                created_at=datetime.now(),
                accessed_at=datetime.now(),
                ttl_seconds=ttl or self.default_ttl,
                size_bytes=size_bytes
            )
            
            # Store entry
            self.entries[key] = entry
            self.current_size_bytes += size_bytes
            
            # Update strategy data
            self._update_strategy_data(key, "set")
            
            # Persist if enabled
            if self.auto_persist:
                await self._persist_to_disk()
            
            logger.debug(f"Cached key: {key} ({size_bytes} bytes)")
            return True
            
        except Exception as e:
            logger.error(f"Error setting cache key {key}: {e}")
            return False
    
    async def delete(self, key: str) -> bool:
        """Delete value from cache"""
        if key not in self.entries:
            return False
        
        entry = self.entries[key]
        self.current_size_bytes -= entry.size_bytes
        
        del self.entries[key]
        
        # Update strategy data
        self._update_strategy_data(key, "delete")
        
        # Persist if enabled
        if self.auto_persist:
            await self._persist_to_disk()
        
        logger.debug(f"Deleted cache key: {key}")
        return True
    
    async def clear(self) -> None:
        """Clear all cache entries"""
        self.entries.clear()
        self.current_size_bytes = 0
        self.lru_order.clear()
        self.access_frequencies.clear()
        
        if self.auto_persist:
            await self._persist_to_disk()
        
        logger.info("Cache cleared")
    
    async def get_many(self, keys: List[str]) -> Dict[str, Any]:
        """Get multiple values from cache"""
        result = {}
        
        for key in keys:
            value = await self.get(key)
            if value is not None:
                result[key] = value
        
        return result
    
    async def set_many(self, 
                       mapping: Dict[str, Any], 
                       ttl: Optional[int] = None) -> List[str]:
        """Set multiple values in cache"""
        successful_keys = []
        
        for key, value in mapping.items():
            if await self.set(key, value, ttl):
                successful_keys.append(key)
        
        return successful_keys
    
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        if key not in self.entries:
            return False
        
        entry = self.entries[key]
        if entry.is_expired():
            await self.delete(key)
            return False
        
        return True
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_entries = len(self.entries)
        expired_count = sum(1 for entry in self.entries.values() if entry.is_expired())
        
        return {
            "total_entries": total_entries,
            "expired_entries": expired_count,
            "current_size_bytes": self.current_size_bytes,
            "current_size_mb": self.current_size_bytes / (1024 * 1024),
            "max_size_mb": self.max_size_bytes / (1024 * 1024),
            "utilization_percent": (self.current_size_bytes / self.max_size_bytes) * 100,
            "strategy": self.strategy.value,
            "default_ttl": self.default_ttl
        }
    
    async def cleanup_expired(self) -> int:
        """Remove expired entries"""
        expired_keys = []
        
        for key, entry in self.entries.items():
            if entry.is_expired():
                expired_keys.append(key)
        
        for key in expired_keys:
            await self.delete(key)
        
        if expired_keys:
            logger.info(f"Cleaned up {len(expired_keys)} expired cache entries")
        
        return len(expired_keys)
    
    async def _ensure_space(self, needed_bytes: int) -> None:
        """Ensure enough space for new entry"""
        while (self.current_size_bytes + needed_bytes) > self.max_size_bytes:
            if not self.entries:
                break
                
            # Find entry to evict based on strategy
            key_to_evict = self._find_eviction_candidate()
            if not key_to_evict:
                break
                
            await self.delete(key_to_evict)
    
    def _find_eviction_candidate(self) -> Optional[str]:
        """Find entry to evict based on strategy"""
        if not self.entries:
            return None
        
        if self.strategy == CacheStrategy.LRU:
            # Find least recently used
            if self.lru_order:
                return self.lru_order[0]
            else:
                # Fallback to oldest accessed
                return min(self.entries.keys(), 
                          key=lambda k: self.entries[k].accessed_at)
        
        elif self.strategy == CacheStrategy.LFU:
            # Find least frequently used
            return min(self.entries.keys(), 
                      key=lambda k: self.entries[k].access_count)
        
        elif self.strategy == CacheStrategy.TTL:
            # Find entry with shortest remaining TTL
            now = datetime.now()
            return min(self.entries.keys(), 
                      key=lambda k: self._get_remaining_ttl(self.entries[k], now))
        
        elif self.strategy == CacheStrategy.FIFO:
            # Find oldest entry
            return min(self.entries.keys(), 
                      key=lambda k: self.entries[k].created_at)
        
        return None
    
    def _get_remaining_ttl(self, entry: CacheEntry, now: datetime) -> float:
        """Get remaining TTL for entry"""
        if not entry.ttl_seconds:
            return float('inf')
        
        age = (now - entry.created_at).total_seconds()
        return max(0, entry.ttl_seconds - age)
    
    def _update_strategy_data(self, key: str, operation: str) -> None:
        """Update strategy-specific data structures"""
        if self.strategy == CacheStrategy.LRU:
            if key in self.lru_order:
                self.lru_order.remove(key)
            if operation != "delete":
                self.lru_order.append(key)
        
        elif self.strategy == CacheStrategy.LFU:
            if operation == "access":
                self.access_frequencies[key] = self.access_frequencies.get(key, 0) + 1
            elif operation == "set":
                self.access_frequencies[key] = 1
            elif operation == "delete":
                self.access_frequencies.pop(key, None)
    
    async def _periodic_cleanup(self) -> None:
        """Periodic cleanup task"""
        while True:
            try:
                await asyncio.sleep(300)  # 5 minutes
                await self.cleanup_expired()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in periodic cleanup: {e}")
    
    def _load_from_disk(self) -> None:
        """Load cache from disk"""
        if not os.path.exists(self.cache_file):
            return
        
        try:
            with open(self.cache_file, 'r') as f:
                data = json.load(f)
            
            for key, entry_data in data.get("entries", {}).items():
                entry = CacheEntry(
                    key=key,
                    value=entry_data["value"],
                    created_at=datetime.fromisoformat(entry_data["created_at"]),
                    accessed_at=datetime.fromisoformat(entry_data["accessed_at"]),
                    access_count=entry_data.get("access_count", 0),
                    ttl_seconds=entry_data.get("ttl_seconds"),
                    size_bytes=entry_data.get("size_bytes", 0)
                )
                
                # Skip expired entries
                if not entry.is_expired():
                    self.entries[key] = entry
                    self.current_size_bytes += entry.size_bytes
            
            logger.info(f"Loaded {len(self.entries)} cache entries from disk")
            
        except Exception as e:
            logger.error(f"Error loading cache from disk: {e}")
    
    async def _persist_to_disk(self) -> None:
        """Persist cache to disk"""
        try:
            os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
            
            data = {
                "metadata": {
                    "created_at": datetime.now().isoformat(),
                    "strategy": self.strategy.value,
                    "max_size_mb": self.max_size_bytes / (1024 * 1024)
                },
                "entries": {}
            }
            
            for key, entry in self.entries.items():
                data["entries"][key] = {
                    "value": entry.value,
                    "created_at": entry.created_at.isoformat(),
                    "accessed_at": entry.accessed_at.isoformat(),
                    "access_count": entry.access_count,
                    "ttl_seconds": entry.ttl_seconds,
                    "size_bytes": entry.size_bytes
                }
            
            with open(self.cache_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
        except Exception as e:
            logger.error(f"Error persisting cache to disk: {e}")
    
    async def close(self) -> None:
        """Close cache and cleanup"""
        if hasattr(self, '_cleanup_task'):
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        if self.auto_persist:
            await self._persist_to_disk()
        
        logger.info("Offline cache closed")

# Cache decorators for easy use
def cached(ttl: int = 3600, key_prefix: str = ""):
    """Decorator for caching function results"""
    def decorator(func: Callable):
        async def wrapper(*args, **kwargs):
            # Generate cache key
            import inspect
            key_parts = [key_prefix, func.__name__]
            
            # Add arguments to key
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()
            
            for arg_name, arg_value in bound_args.arguments.items():
                if isinstance(arg_value, (str, int, float, bool)):
                    key_parts.append(f"{arg_name}={arg_value}")
            
            cache_key = ":".join(str(part) for part in key_parts)
            
            # Try to get from cache
            cached_result = await offline_cache.get(cache_key)
            if cached_result is not None:
                return cached_result
            
            # Execute function and cache result
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
            
            await offline_cache.set(cache_key, result, ttl)
            return result
        
        return wrapper
    return decorator

# Global offline cache instance
offline_cache = OfflineCache()