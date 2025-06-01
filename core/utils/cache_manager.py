"""
Cache management for API responses
"""

import os
import json
import pickle
import time
import hashlib
from datetime import datetime, timedelta
from typing import Any, Optional
import logging


class CacheManager:
    """Manages caching of API responses"""
    
    def __init__(self, cache_dir: Optional[str] = None, max_size_mb: int = 100):
        self.cache_dir = cache_dir or os.path.expanduser("~/.monitor_legislativo/cache")
        self.max_size_mb = max_size_mb
        self.logger = logging.getLogger(__name__)
        
        # Create cache directory if it doesn't exist
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # In-memory cache for fast access
        self.memory_cache = {}
        self.memory_cache_timestamps = {}
        self.max_memory_items = 100
    
    def get(self, key: str) -> Optional[Any]:
        """Get item from cache"""
        # Check memory cache first
        if key in self.memory_cache:
            timestamp = self.memory_cache_timestamps.get(key, 0)
            if time.time() - timestamp < 3600:  # 1 hour memory cache
                self.logger.debug(f"Cache hit (memory): {key}")
                return self.memory_cache[key]
            else:
                # Expired in memory
                del self.memory_cache[key]
                del self.memory_cache_timestamps[key]
        
        # Check disk cache
        cache_file = self._get_cache_file_path(key)
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'rb') as f:
                    data = pickle.load(f)
                
                # Check if expired
                if time.time() - data['timestamp'] < data.get('ttl', 3600):
                    self.logger.debug(f"Cache hit (disk): {key}")
                    # Add to memory cache
                    self._add_to_memory_cache(key, data['value'])
                    return data['value']
                else:
                    # Expired, remove file
                    os.remove(cache_file)
                    
            except Exception as e:
                self.logger.error(f"Error reading cache file {cache_file}: {e}")
                # Remove corrupted file
                try:
                    os.remove(cache_file)
                except:
                    pass
        
        self.logger.debug(f"Cache miss: {key}")
        return None
    
    def set(self, key: str, value: Any, ttl: int = 3600):
        """Set item in cache with TTL in seconds"""
        # Add to memory cache
        self._add_to_memory_cache(key, value)
        
        # Save to disk
        cache_file = self._get_cache_file_path(key)
        try:
            data = {
                'value': value,
                'timestamp': time.time(),
                'ttl': ttl
            }
            
            with open(cache_file, 'wb') as f:
                pickle.dump(data, f)
            
            self.logger.debug(f"Cached: {key}")
            
            # Check cache size
            self._check_cache_size()
            
        except Exception as e:
            self.logger.error(f"Error writing cache file {cache_file}: {e}")
    
    def clear(self, key: str):
        """Clear specific cache entry"""
        # Remove from memory
        if key in self.memory_cache:
            del self.memory_cache[key]
            del self.memory_cache_timestamps[key]
        
        # Remove from disk
        cache_file = self._get_cache_file_path(key)
        if os.path.exists(cache_file):
            try:
                os.remove(cache_file)
                self.logger.debug(f"Cleared cache: {key}")
            except Exception as e:
                self.logger.error(f"Error removing cache file: {e}")
    
    def clear_pattern(self, pattern: str):
        """Clear cache entries matching pattern"""
        import glob
        
        # Clear from memory
        keys_to_remove = [k for k in self.memory_cache.keys() if pattern.replace('*', '') in k]
        for key in keys_to_remove:
            del self.memory_cache[key]
            del self.memory_cache_timestamps[key]
        
        # Clear from disk
        cache_pattern = os.path.join(self.cache_dir, f"{pattern}.cache")
        for cache_file in glob.glob(cache_pattern):
            try:
                os.remove(cache_file)
            except Exception as e:
                self.logger.error(f"Error removing cache file {cache_file}: {e}")
    
    def clear_all(self):
        """Clear all cache entries"""
        # Clear memory cache
        self.memory_cache.clear()
        self.memory_cache_timestamps.clear()
        
        # Clear disk cache
        for filename in os.listdir(self.cache_dir):
            if filename.endswith('.cache'):
                try:
                    os.remove(os.path.join(self.cache_dir, filename))
                except Exception as e:
                    self.logger.error(f"Error removing cache file: {e}")
        
        self.logger.info("Cleared all cache")
    
    def clear_expired(self):
        """Remove expired cache entries"""
        current_time = time.time()
        
        # Clear expired from memory
        expired_keys = []
        for key, timestamp in self.memory_cache_timestamps.items():
            if current_time - timestamp > 3600:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.memory_cache[key]
            del self.memory_cache_timestamps[key]
        
        # Clear expired from disk
        for filename in os.listdir(self.cache_dir):
            if filename.endswith('.cache'):
                filepath = os.path.join(self.cache_dir, filename)
                try:
                    with open(filepath, 'rb') as f:
                        data = pickle.load(f)
                    
                    if current_time - data['timestamp'] > data.get('ttl', 3600):
                        os.remove(filepath)
                        
                except Exception as e:
                    # Remove corrupted files
                    try:
                        os.remove(filepath)
                    except:
                        pass
    
    def _get_cache_file_path(self, key: str) -> str:
        """Get file path for cache key"""
        # Create safe filename from key
        safe_key = hashlib.md5(key.encode()).hexdigest()
        return os.path.join(self.cache_dir, f"{safe_key}.cache")
    
    def _add_to_memory_cache(self, key: str, value: Any):
        """Add item to memory cache with LRU eviction"""
        # Check if we need to evict items
        if len(self.memory_cache) >= self.max_memory_items:
            # Remove oldest item
            oldest_key = min(self.memory_cache_timestamps, 
                           key=self.memory_cache_timestamps.get)
            del self.memory_cache[oldest_key]
            del self.memory_cache_timestamps[oldest_key]
        
        self.memory_cache[key] = value
        self.memory_cache_timestamps[key] = time.time()
    
    def _check_cache_size(self):
        """Check and manage cache directory size"""
        total_size = 0
        cache_files = []
        
        for filename in os.listdir(self.cache_dir):
            if filename.endswith('.cache'):
                filepath = os.path.join(self.cache_dir, filename)
                try:
                    size = os.path.getsize(filepath)
                    total_size += size
                    cache_files.append((filepath, size, os.path.getmtime(filepath)))
                except:
                    pass
        
        # Convert to MB
        total_size_mb = total_size / (1024 * 1024)
        
        if total_size_mb > self.max_size_mb:
            # Remove oldest files until under limit
            cache_files.sort(key=lambda x: x[2])  # Sort by modification time
            
            for filepath, size, _ in cache_files:
                try:
                    os.remove(filepath)
                    total_size_mb -= size / (1024 * 1024)
                    
                    if total_size_mb <= self.max_size_mb * 0.8:  # Keep 80% full
                        break
                        
                except Exception as e:
                    self.logger.error(f"Error removing cache file: {e}")
    
    def get_stats(self) -> dict:
        """Get cache statistics"""
        total_size = 0
        file_count = 0
        
        for filename in os.listdir(self.cache_dir):
            if filename.endswith('.cache'):
                filepath = os.path.join(self.cache_dir, filename)
                try:
                    total_size += os.path.getsize(filepath)
                    file_count += 1
                except:
                    pass
        
        return {
            'memory_items': len(self.memory_cache),
            'disk_files': file_count,
            'total_size_mb': total_size / (1024 * 1024),
            'max_size_mb': self.max_size_mb
        }