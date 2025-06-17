"""
Smart Cache Implementation with adaptive TTL
Implements recommendations from technical analysis
"""

import os
import json
import time
import hashlib
import asyncio
from datetime import datetime, timedelta
from typing import Any, Optional, Dict, Set
import logging
from dataclasses import dataclass, asdict
from collections import defaultdict


@dataclass
class CacheStats:
    """Cache statistics for monitoring"""
    hits: int = 0
    misses: int = 0
    sets: int = 0
    evictions: int = 0
    size_bytes: int = 0
    last_access: Optional[float] = None
    
    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return (self.hits / total * 100) if total > 0 else 0


@dataclass
class CacheEntry:
    """Cache entry with metadata"""
    key: str
    value: Any
    created_at: float
    accessed_at: float
    access_count: int
    ttl: int
    source: str  # Which API/service created this entry
    
    @property
    def is_expired(self) -> bool:
        return time.time() - self.created_at > self.ttl
    
    @property
    def age_seconds(self) -> float:
        return time.time() - self.created_at
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'key': self.key,
            'value': self.value,
            'created_at': self.created_at,
            'accessed_at': self.accessed_at,
            'access_count': self.access_count,
            'ttl': self.ttl,
            'source': self.source
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'CacheEntry':
        """Create from dictionary"""
        return cls(**data)


class SmartCache:
    """
    Smart cache with adaptive TTL based on access patterns
    Features:
    - Access pattern analysis for adaptive TTL
    - LRU eviction with frequency consideration
    - Per-source statistics
    - Async-safe operations
    - Memory and disk persistence
    """
    
    def __init__(self, 
                 cache_dir: Optional[str] = None,
                 max_memory_items: int = 500,
                 max_disk_size_mb: int = 200,
                 default_ttl: int = 3600):
        
        self.cache_dir = cache_dir or os.path.expanduser("~/.monitor_legislativo/smart_cache")
        self.max_memory_items = max_memory_items
        self.max_disk_size_mb = max_disk_size_mb
        self.default_ttl = default_ttl
        
        self.logger = logging.getLogger(__name__)
        
        # Create cache directory
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # In-memory cache
        self._memory_cache: Dict[str, CacheEntry] = {}
        self._access_lock = asyncio.Lock()
        
        # Statistics
        self._stats = CacheStats()
        self._source_stats: Dict[str, CacheStats] = defaultdict(CacheStats)
        
        # Access pattern tracking for adaptive TTL
        self._access_patterns: Dict[str, list] = defaultdict(list)
        self._ttl_adjustments: Dict[str, float] = {}  # Key -> TTL multiplier
    
    async def get(self, key: str, source: str = "unknown") -> Optional[Any]:
        """Get item from cache with access pattern tracking"""
        async with self._access_lock:
            # Check memory cache first
            if key in self._memory_cache:
                entry = self._memory_cache[key]
                
                if entry.is_expired:
                    # Expired, remove from memory
                    del self._memory_cache[key]
                    self._stats.misses += 1
                    self._source_stats[source].misses += 1
                else:
                    # Hit - update access info
                    entry.accessed_at = time.time()
                    entry.access_count += 1
                    
                    self._update_access_pattern(key, source)
                    self._stats.hits += 1
                    self._stats.last_access = time.time()
                    self._source_stats[source].hits += 1
                    self._source_stats[source].last_access = time.time()
                    
                    self.logger.debug(f"Cache hit (memory): {key}")
                    return entry.value
            
            # Check disk cache
            entry = await self._load_from_disk(key)
            if entry and not entry.is_expired:
                # Move to memory cache
                await self._add_to_memory(entry)
                
                # Update access info
                entry.accessed_at = time.time()
                entry.access_count += 1
                
                self._update_access_pattern(key, source)
                self._stats.hits += 1
                self._stats.last_access = time.time()
                self._source_stats[source].hits += 1
                self._source_stats[source].last_access = time.time()
                
                self.logger.debug(f"Cache hit (disk): {key}")
                return entry.value
            
            # Miss
            self._stats.misses += 1
            self._source_stats[source].misses += 1
            self.logger.debug(f"Cache miss: {key}")
            return None
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None, source: str = "unknown"):
        """Set item in cache with smart TTL adjustment"""
        async with self._access_lock:
            # Calculate adaptive TTL
            if ttl is None:
                ttl = self._calculate_adaptive_ttl(key, source)
            
            entry = CacheEntry(
                key=key,
                value=value,
                created_at=time.time(),
                accessed_at=time.time(),
                access_count=1,
                ttl=ttl,
                source=source
            )
            
            # Add to memory cache
            await self._add_to_memory(entry)
            
            # Save to disk asynchronously
            asyncio.create_task(self._save_to_disk(entry))
            
            self._stats.sets += 1
            self._source_stats[source].sets += 1
            
            self.logger.debug(f"Cached: {key} (TTL: {ttl}s)")
    
    async def clear_pattern(self, pattern: str, source: str = None):
        """Clear cache entries matching pattern"""
        async with self._access_lock:
            # Clear from memory
            keys_to_remove = []
            for key in self._memory_cache:
                if pattern.replace('*', '') in key:
                    if source is None or self._memory_cache[key].source == source:
                        keys_to_remove.append(key)
            
            for key in keys_to_remove:
                del self._memory_cache[key]
            
            # Clear from disk
            await self._clear_disk_pattern(pattern, source)
            
            self.logger.info(f"Cleared cache pattern: {pattern} (source: {source})")
    
    async def clear_expired(self):
        """Remove expired entries from cache"""
        async with self._access_lock:
            current_time = time.time()
            
            # Clear from memory
            expired_keys = []
            for key, entry in self._memory_cache.items():
                if entry.is_expired:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self._memory_cache[key]
                self._stats.evictions += 1
            
            # Clear from disk
            await self._clear_expired_disk()
            
            if expired_keys:
                self.logger.info(f"Cleared {len(expired_keys)} expired entries")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics"""
        return {
            'global': asdict(self._stats),
            'by_source': {source: asdict(stats) for source, stats in self._source_stats.items()},
            'memory_usage': {
                'items': len(self._memory_cache),
                'max_items': self.max_memory_items,
                'utilization': len(self._memory_cache) / self.max_memory_items * 100
            },
            'ttl_adjustments': dict(self._ttl_adjustments),
            'top_accessed': self._get_top_accessed_keys(10)
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform cache health check"""
        try:
            # Test memory operations
            test_key = "__health_check__"
            await self.set(test_key, "test", ttl=1)
            result = await self.get(test_key)
            
            # Clean up
            if test_key in self._memory_cache:
                del self._memory_cache[test_key]
            
            # Check disk space
            disk_usage = await self._get_disk_usage()
            
            return {
                'status': 'healthy' if result == "test" else 'degraded',
                'memory_cache': len(self._memory_cache),
                'disk_usage_mb': disk_usage,
                'hit_rate': self._stats.hit_rate,
                'last_access': self._stats.last_access
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e)
            }
    
    def _calculate_adaptive_ttl(self, key: str, source: str) -> int:
        """Calculate adaptive TTL based on access patterns"""
        base_ttl = self.default_ttl
        
        # Source-specific TTL adjustments
        source_multipliers = {
            'camara': 0.5,    # Frequently updated
            'senado': 0.5,    # Frequently updated  
            'planalto': 1.0,  # Medium update frequency
            'anvisa': 2.0,    # Less frequent updates
            'aneel': 2.0,     # Regulatory consultations change slowly
            'anatel': 2.0,
        }
        
        multiplier = source_multipliers.get(source.lower(), 1.0)
        
        # Apply learned TTL adjustments
        if key in self._ttl_adjustments:
            multiplier *= self._ttl_adjustments[key]
        
        # Access pattern influence
        access_pattern = self._access_patterns.get(key, [])
        if len(access_pattern) > 1:
            # If frequently accessed, cache longer
            recent_accesses = [a for a in access_pattern if time.time() - a < 3600]
            if len(recent_accesses) > 3:
                multiplier *= 1.5
        
        return int(base_ttl * multiplier)
    
    def _update_access_pattern(self, key: str, source: str):
        """Update access pattern for adaptive TTL learning"""
        current_time = time.time()
        
        # Keep only recent access times (last 24 hours)
        self._access_patterns[key] = [
            t for t in self._access_patterns[key] 
            if current_time - t < 86400
        ]
        self._access_patterns[key].append(current_time)
        
        # Learn TTL adjustments based on access patterns
        accesses = self._access_patterns[key]
        if len(accesses) >= 5:
            # Calculate average time between accesses
            intervals = [accesses[i] - accesses[i-1] for i in range(1, len(accesses))]
            avg_interval = sum(intervals) / len(intervals)
            
            # Adjust TTL multiplier based on access frequency
            if avg_interval < 300:  # Very frequent (< 5 min)
                self._ttl_adjustments[key] = 0.5
            elif avg_interval < 1800:  # Frequent (< 30 min)
                self._ttl_adjustments[key] = 0.8
            elif avg_interval > 7200:  # Infrequent (> 2 hours)
                self._ttl_adjustments[key] = 2.0
    
    async def _add_to_memory(self, entry: CacheEntry):
        """Add entry to memory cache with LRU eviction"""
        # Check if we need to evict
        if len(self._memory_cache) >= self.max_memory_items:
            await self._evict_lru()
        
        self._memory_cache[entry.key] = entry
    
    async def _evict_lru(self):
        """Evict least recently used item considering access frequency"""
        if not self._memory_cache:
            return
        
        # Score = recency * frequency (higher is better)
        current_time = time.time()
        scores = {}
        
        for key, entry in self._memory_cache.items():
            recency = 1 / (current_time - entry.accessed_at + 1)
            frequency = entry.access_count
            scores[key] = recency * frequency
        
        # Remove item with lowest score
        lru_key = min(scores, key=scores.get)
        del self._memory_cache[lru_key]
        self._stats.evictions += 1
    
    async def _save_to_disk(self, entry: CacheEntry):
        """Save entry to disk"""
        try:
            cache_file = self._get_cache_file_path(entry.key)
            with open(cache_file, 'w') as f:
                json.dump(entry.to_dict(), f)
        except Exception as e:
            self.logger.error(f"Error saving to disk: {e}")
    
    async def _load_from_disk(self, key: str) -> Optional[CacheEntry]:
        """Load entry from disk"""
        try:
            cache_file = self._get_cache_file_path(key)
            if os.path.exists(cache_file):
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                return CacheEntry.from_dict(data)
        except Exception as e:
            self.logger.error(f"Error loading from disk: {e}")
            # Remove corrupted file
            try:
                os.remove(cache_file)
            except:
                pass
        return None
    
    async def _clear_disk_pattern(self, pattern: str, source: Optional[str]):
        """Clear disk cache entries matching pattern"""
        import glob
        
        cache_pattern = os.path.join(self.cache_dir, "*.cache")
        for cache_file in glob.glob(cache_pattern):
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                
                if pattern.replace('*', '') in data.get('key', ''):
                    if source is None or data.get('source') == source:
                        os.remove(cache_file)
            except:
                # Remove corrupted files
                try:
                    os.remove(cache_file)
                except:
                    pass
    
    async def _clear_expired_disk(self):
        """Clear expired entries from disk"""
        import glob
        
        current_time = time.time()
        cache_pattern = os.path.join(self.cache_dir, "*.cache")
        
        for cache_file in glob.glob(cache_pattern):
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                
                if current_time - data.get('created_at', 0) > data.get('ttl', 3600):
                    os.remove(cache_file)
            except:
                # Remove corrupted files
                try:
                    os.remove(cache_file)
                except:
                    pass
    
    async def _get_disk_usage(self) -> float:
        """Get disk cache usage in MB"""
        total_size = 0
        for filename in os.listdir(self.cache_dir):
            if filename.endswith('.cache'):
                filepath = os.path.join(self.cache_dir, filename)
                try:
                    total_size += os.path.getsize(filepath)
                except:
                    pass
        
        return total_size / (1024 * 1024)
    
    def _get_cache_file_path(self, key: str) -> str:
        """Get file path for cache key"""
        safe_key = hashlib.md5(key.encode()).hexdigest()
        return os.path.join(self.cache_dir, f"{safe_key}.cache")
    
    def _get_top_accessed_keys(self, limit: int) -> list:
        """Get most frequently accessed keys"""
        items = [(key, entry.access_count) for key, entry in self._memory_cache.items()]
        items.sort(key=lambda x: x[1], reverse=True)
        return items[:limit]


# Global smart cache instance
smart_cache = SmartCache()