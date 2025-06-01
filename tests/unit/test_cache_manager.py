"""Unit tests for cache management functionality."""

import pytest
from unittest.mock import Mock, patch, AsyncMock
import asyncio
from datetime import datetime, timedelta
import json

from core.utils.cache_manager import CacheManager, CacheKey, CacheEntry


class TestCacheManager:
    """Test suite for CacheManager class."""

    @pytest.fixture
    def cache_manager(self):
        """Create a cache manager instance for testing."""
        return CacheManager(max_size=100, ttl_seconds=3600)

    @pytest.fixture
    def sample_cache_key(self):
        """Create a sample cache key."""
        return CacheKey(
            service="test_service",
            endpoint="test_endpoint",
            params={"param1": "value1", "param2": "value2"}
        )

    @pytest.fixture
    def sample_cache_entry(self):
        """Create a sample cache entry."""
        return CacheEntry(
            data={"result": "test_data"},
            timestamp=datetime.now(),
            ttl=3600,
            access_count=1
        )

    def test_cache_manager_initialization(self, cache_manager):
        """Test cache manager initialization."""
        assert cache_manager.max_size == 100
        assert cache_manager.ttl_seconds == 3600
        assert len(cache_manager._cache) == 0

    def test_cache_key_generation(self, sample_cache_key):
        """Test cache key generation and hashing."""
        key_str = sample_cache_key.generate_key()
        
        assert "test_service" in key_str
        assert "test_endpoint" in key_str
        
        # Test that same parameters generate same key
        key2 = CacheKey(
            service="test_service",
            endpoint="test_endpoint", 
            params={"param1": "value1", "param2": "value2"}
        )
        assert sample_cache_key.generate_key() == key2.generate_key()

    def test_cache_key_with_different_param_order(self):
        """Test that parameter order doesn't affect key generation."""
        key1 = CacheKey(
            service="test",
            endpoint="test",
            params={"a": "1", "b": "2"}
        )
        key2 = CacheKey(
            service="test",
            endpoint="test",
            params={"b": "2", "a": "1"}
        )
        
        assert key1.generate_key() == key2.generate_key()

    def test_cache_entry_expiration(self, sample_cache_entry):
        """Test cache entry expiration logic."""
        # Fresh entry should not be expired
        assert not sample_cache_entry.is_expired()
        
        # Create expired entry
        expired_entry = CacheEntry(
            data={"result": "old_data"},
            timestamp=datetime.now() - timedelta(hours=2),
            ttl=3600,  # 1 hour TTL
            access_count=1
        )
        
        assert expired_entry.is_expired()

    def test_cache_set_and_get(self, cache_manager, sample_cache_key):
        """Test basic cache set and get operations."""
        test_data = {"result": "test_value"}
        
        # Set cache entry
        cache_manager.set(sample_cache_key, test_data)
        
        # Get cache entry
        result = cache_manager.get(sample_cache_key)
        
        assert result == test_data

    def test_cache_get_nonexistent_key(self, cache_manager):
        """Test getting non-existent cache key."""
        nonexistent_key = CacheKey("missing", "endpoint", {})
        
        result = cache_manager.get(nonexistent_key)
        
        assert result is None

    def test_cache_get_expired_entry(self, cache_manager):
        """Test getting expired cache entry."""
        key = CacheKey("service", "endpoint", {})
        
        # Manually insert expired entry
        expired_entry = CacheEntry(
            data={"result": "expired_data"},
            timestamp=datetime.now() - timedelta(hours=2),
            ttl=3600,
            access_count=1
        )
        cache_manager._cache[key.generate_key()] = expired_entry
        
        result = cache_manager.get(key)
        
        assert result is None  # Should return None for expired entries

    def test_cache_size_limit_enforcement(self):
        """Test that cache enforces size limits."""
        small_cache = CacheManager(max_size=2, ttl_seconds=3600)
        
        # Add entries up to limit
        key1 = CacheKey("service1", "endpoint", {})
        key2 = CacheKey("service2", "endpoint", {})
        key3 = CacheKey("service3", "endpoint", {})
        
        small_cache.set(key1, {"data": "1"})
        small_cache.set(key2, {"data": "2"})
        
        assert len(small_cache._cache) == 2
        
        # Adding third entry should evict oldest
        small_cache.set(key3, {"data": "3"})
        
        assert len(small_cache._cache) == 2
        assert small_cache.get(key3) == {"data": "3"}

    def test_cache_access_count_tracking(self, cache_manager, sample_cache_key):
        """Test that access count is tracked."""
        test_data = {"result": "test_value"}
        
        cache_manager.set(sample_cache_key, test_data)
        
        # Multiple gets should increase access count
        cache_manager.get(sample_cache_key)
        cache_manager.get(sample_cache_key)
        cache_manager.get(sample_cache_key)
        
        entry = cache_manager._cache[sample_cache_key.generate_key()]
        assert entry.access_count >= 3

    def test_cache_invalidation(self, cache_manager, sample_cache_key):
        """Test cache entry invalidation."""
        test_data = {"result": "test_value"}
        
        cache_manager.set(sample_cache_key, test_data)
        assert cache_manager.get(sample_cache_key) is not None
        
        cache_manager.invalidate(sample_cache_key)
        assert cache_manager.get(sample_cache_key) is None

    def test_cache_clear_all(self, cache_manager):
        """Test clearing all cache entries."""
        key1 = CacheKey("service1", "endpoint", {})
        key2 = CacheKey("service2", "endpoint", {})
        
        cache_manager.set(key1, {"data": "1"})
        cache_manager.set(key2, {"data": "2"})
        
        assert len(cache_manager._cache) == 2
        
        cache_manager.clear()
        
        assert len(cache_manager._cache) == 0

    def test_cache_cleanup_expired_entries(self, cache_manager):
        """Test cleanup of expired entries."""
        # Add fresh entry
        fresh_key = CacheKey("fresh", "endpoint", {})
        cache_manager.set(fresh_key, {"data": "fresh"})
        
        # Manually add expired entry
        expired_key = CacheKey("expired", "endpoint", {})
        expired_entry = CacheEntry(
            data={"data": "expired"},
            timestamp=datetime.now() - timedelta(hours=2),
            ttl=3600,
            access_count=1
        )
        cache_manager._cache[expired_key.generate_key()] = expired_entry
        
        # Run cleanup
        cache_manager.cleanup_expired()
        
        # Fresh entry should remain, expired should be removed
        assert cache_manager.get(fresh_key) is not None
        assert cache_manager.get(expired_key) is None

    def test_cache_statistics(self, cache_manager):
        """Test cache statistics generation."""
        key1 = CacheKey("service1", "endpoint", {})
        key2 = CacheKey("service2", "endpoint", {})
        
        cache_manager.set(key1, {"data": "1"})
        cache_manager.set(key2, {"data": "2"})
        
        # Generate some hits and misses
        cache_manager.get(key1)  # Hit
        cache_manager.get(key1)  # Hit
        cache_manager.get(CacheKey("missing", "endpoint", {}))  # Miss
        
        stats = cache_manager.get_statistics()
        
        assert stats['total_entries'] == 2
        assert stats['cache_hits'] >= 2
        assert stats['cache_misses'] >= 1
        assert 'hit_ratio' in stats

    @pytest.mark.asyncio
    async def test_async_cache_operations(self, cache_manager):
        """Test asynchronous cache operations."""
        key = CacheKey("async_service", "endpoint", {})
        
        # Simulate async data fetching
        async def fetch_data():
            await asyncio.sleep(0.1)  # Simulate API call
            return {"async_result": "success"}
        
        # Cache miss - should fetch data
        data = await cache_manager.get_or_fetch_async(key, fetch_data)
        assert data == {"async_result": "success"}
        
        # Cache hit - should return cached data without fetching
        with patch.object(cache_manager, '_fetch_function') as mock_fetch:
            data = await cache_manager.get_or_fetch_async(key, fetch_data)
            assert data == {"async_result": "success"}
            # Fetch function should not be called

    def test_cache_serialization(self, cache_manager, sample_cache_key):
        """Test cache entry serialization for persistence."""
        complex_data = {
            "list": [1, 2, 3],
            "dict": {"nested": "value"},
            "datetime": datetime.now().isoformat()
        }
        
        cache_manager.set(sample_cache_key, complex_data)
        
        # Test that data can be serialized and deserialized
        entry = cache_manager._cache[sample_cache_key.generate_key()]
        serialized = json.dumps(entry.data)
        deserialized = json.loads(serialized)
        
        assert deserialized == complex_data

    def test_cache_memory_efficiency(self):
        """Test cache memory usage optimization."""
        cache_manager = CacheManager(max_size=1000, ttl_seconds=3600)
        
        # Add many entries
        for i in range(100):
            key = CacheKey(f"service_{i}", "endpoint", {"id": i})
            cache_manager.set(key, {"data": f"value_{i}"})
        
        # Check memory usage is reasonable
        memory_usage = cache_manager.get_memory_usage()
        assert memory_usage['total_entries'] == 100
        assert memory_usage['estimated_size_mb'] < 10  # Should be small

    def test_cache_pattern_invalidation(self, cache_manager):
        """Test invalidation by pattern matching."""
        # Add entries with different patterns
        key1 = CacheKey("user_service", "get_user", {"id": "1"})
        key2 = CacheKey("user_service", "get_user", {"id": "2"})
        key3 = CacheKey("post_service", "get_post", {"id": "1"})
        
        cache_manager.set(key1, {"user": "1"})
        cache_manager.set(key2, {"user": "2"})
        cache_manager.set(key3, {"post": "1"})
        
        # Invalidate all user_service entries
        cache_manager.invalidate_pattern("user_service")
        
        assert cache_manager.get(key1) is None
        assert cache_manager.get(key2) is None
        assert cache_manager.get(key3) is not None  # Should remain

    def test_cache_concurrent_access(self, cache_manager):
        """Test cache behavior under concurrent access."""
        import threading
        import time
        
        key = CacheKey("concurrent", "test", {})
        results = []
        
        def cache_operation():
            cache_manager.set(key, {"timestamp": time.time()})
            result = cache_manager.get(key)
            results.append(result)
        
        # Start multiple threads
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=cache_operation)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # All operations should complete successfully
        assert len(results) == 10
        assert all(result is not None for result in results)