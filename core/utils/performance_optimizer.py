"""
Performance Optimization Utilities
Provides caching, connection pooling, and request optimization
"""

import asyncio
import time
from typing import Dict, Any, List, Optional, Callable, TypeVar, Awaitable
from dataclasses import dataclass, field
from collections import defaultdict, deque
import weakref
from functools import wraps
import hashlib
import json

T = TypeVar('T')


@dataclass
class PerformanceMetrics:
    """Track performance metrics for optimization"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_response_time: float = 0.0
    cache_hits: int = 0
    cache_misses: int = 0
    concurrent_requests: int = 0
    max_concurrent: int = 0
    
    @property
    def success_rate(self) -> float:
        return (self.successful_requests / self.total_requests * 100) if self.total_requests > 0 else 0
    
    @property
    def average_response_time(self) -> float:
        return (self.total_response_time / self.successful_requests) if self.successful_requests > 0 else 0
    
    @property
    def cache_hit_rate(self) -> float:
        total_cache_requests = self.cache_hits + self.cache_misses
        return (self.cache_hits / total_cache_requests * 100) if total_cache_requests > 0 else 0


class AsyncLRUCache:
    """Thread-safe async LRU cache with TTL support"""
    
    def __init__(self, maxsize: int = 128, ttl: float = 300):
        self.maxsize = maxsize
        self.ttl = ttl
        self.cache: Dict[str, Any] = {}
        self.access_times: Dict[str, float] = {}
        self.creation_times: Dict[str, float] = {}
        self.access_order: deque = deque()
        self._lock = asyncio.Lock()
    
    async def get(self, key: str) -> Optional[Any]:
        """Get item from cache"""
        async with self._lock:
            if key not in self.cache:
                return None
            
            # Check TTL
            if time.time() - self.creation_times[key] > self.ttl:
                await self._remove_key(key)
                return None
            
            # Update access order
            if key in self.access_order:
                self.access_order.remove(key)
            self.access_order.append(key)
            self.access_times[key] = time.time()
            
            return self.cache[key]
    
    async def set(self, key: str, value: Any) -> None:
        """Set item in cache"""
        async with self._lock:
            current_time = time.time()
            
            # If key exists, update it
            if key in self.cache:
                self.cache[key] = value
                self.creation_times[key] = current_time
                self.access_times[key] = current_time
                if key in self.access_order:
                    self.access_order.remove(key)
                self.access_order.append(key)
                return
            
            # Check if we need to evict
            while len(self.cache) >= self.maxsize:
                await self._evict_lru()
            
            # Add new item
            self.cache[key] = value
            self.creation_times[key] = current_time
            self.access_times[key] = current_time
            self.access_order.append(key)
    
    async def _evict_lru(self) -> None:
        """Evict least recently used item"""
        if self.access_order:
            key = self.access_order.popleft()
            await self._remove_key(key)
    
    async def _remove_key(self, key: str) -> None:
        """Remove key from all data structures"""
        self.cache.pop(key, None)
        self.creation_times.pop(key, None)
        self.access_times.pop(key, None)
        if key in self.access_order:
            self.access_order.remove(key)
    
    async def clear(self) -> None:
        """Clear all cache entries"""
        async with self._lock:
            self.cache.clear()
            self.creation_times.clear()
            self.access_times.clear()
            self.access_order.clear()
    
    def stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return {
            "size": len(self.cache),
            "maxsize": self.maxsize,
            "ttl": self.ttl
        }


class RequestBatcher:
    """Batch similar requests to improve performance"""
    
    def __init__(self, batch_size: int = 10, batch_timeout: float = 0.1):
        self.batch_size = batch_size
        self.batch_timeout = batch_timeout
        self.pending_requests: Dict[str, List] = defaultdict(list)
        self._timers: Dict[str, asyncio.Task] = {}
    
    async def add_request(self, batch_key: str, request_data: Any, 
                         handler: Callable[[List[Any]], Awaitable[List[T]]]) -> T:
        """Add request to batch"""
        future = asyncio.Future()
        
        self.pending_requests[batch_key].append({
            'data': request_data,
            'future': future
        })
        
        # Start timer for this batch if not already started
        if batch_key not in self._timers:
            self._timers[batch_key] = asyncio.create_task(
                self._batch_timer(batch_key, handler)
            )
        
        # Execute immediately if batch is full
        if len(self.pending_requests[batch_key]) >= self.batch_size:
            await self._execute_batch(batch_key, handler)
        
        return await future
    
    async def _batch_timer(self, batch_key: str, handler: Callable) -> None:
        """Timer to execute batch after timeout"""
        await asyncio.sleep(self.batch_timeout)
        if batch_key in self.pending_requests and self.pending_requests[batch_key]:
            await self._execute_batch(batch_key, handler)
    
    async def _execute_batch(self, batch_key: str, handler: Callable) -> None:
        """Execute batch of requests"""
        if batch_key not in self.pending_requests:
            return
        
        requests = self.pending_requests[batch_key]
        if not requests:
            return
        
        # Clear pending requests
        del self.pending_requests[batch_key]
        
        # Cancel timer
        if batch_key in self._timers:
            self._timers[batch_key].cancel()
            del self._timers[batch_key]
        
        try:
            # Execute batched requests
            request_data = [req['data'] for req in requests]
            results = await handler(request_data)
            
            # Distribute results to futures
            for i, req in enumerate(requests):
                if i < len(results):
                    req['future'].set_result(results[i])
                else:
                    req['future'].set_exception(
                        IndexError("Insufficient results from batch handler")
                    )
        
        except Exception as e:
            # Set exception for all futures
            for req in requests:
                req['future'].set_exception(e)


class ConcurrencyLimiter:
    """Limit concurrent operations to prevent overload"""
    
    def __init__(self, max_concurrent: int = 10):
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.active_operations = 0
        self.max_concurrent = max_concurrent
        self.wait_queue_size = 0
    
    async def __aenter__(self):
        self.wait_queue_size += 1
        await self.semaphore.acquire()
        self.wait_queue_size -= 1
        self.active_operations += 1
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.active_operations -= 1
        self.semaphore.release()
    
    @property
    def stats(self) -> Dict[str, int]:
        return {
            "active": self.active_operations,
            "max_concurrent": self.max_concurrent,
            "waiting": self.wait_queue_size
        }


class PerformanceOptimizer:
    """Main performance optimization coordinator"""
    
    def __init__(self):
        self.metrics: Dict[str, PerformanceMetrics] = defaultdict(PerformanceMetrics)
        self.cache = AsyncLRUCache(maxsize=1000, ttl=300)
        self.concurrency_limiter = ConcurrencyLimiter(max_concurrent=20)
        self.request_batcher = RequestBatcher(batch_size=5, batch_timeout=0.05)
        self._start_time = time.time()
    
    def cache_key(self, service: str, operation: str, **kwargs) -> str:
        """Generate cache key for operation"""
        key_data = {
            "service": service,
            "operation": operation,
            **kwargs
        }
        key_string = json.dumps(key_data, sort_keys=True)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    async def cached_operation(self, cache_key: str, operation: Callable[[], Awaitable[T]], 
                              ttl: Optional[float] = None) -> T:
        """Execute operation with caching"""
        service = cache_key.split(':')[0] if ':' in cache_key else 'unknown'
        
        # Try cache first
        cached_result = await self.cache.get(cache_key)
        if cached_result is not None:
            self.metrics[service].cache_hits += 1
            return cached_result
        
        self.metrics[service].cache_misses += 1
        
        # Execute operation
        start_time = time.time()
        try:
            async with self.concurrency_limiter:
                self.metrics[service].concurrent_requests += 1
                self.metrics[service].max_concurrent = max(
                    self.metrics[service].max_concurrent,
                    self.metrics[service].concurrent_requests
                )
                
                result = await operation()
                
                response_time = time.time() - start_time
                self.metrics[service].total_requests += 1
                self.metrics[service].successful_requests += 1
                self.metrics[service].total_response_time += response_time
                
                # Cache result
                cache_ttl = ttl or self.cache.ttl
                if cache_ttl > 0:
                    await self.cache.set(cache_key, result)
                
                return result
        
        except Exception as e:
            response_time = time.time() - start_time
            self.metrics[service].total_requests += 1
            self.metrics[service].failed_requests += 1
            self.metrics[service].total_response_time += response_time
            raise
        
        finally:
            self.metrics[service].concurrent_requests -= 1
    
    async def batched_operation(self, batch_key: str, request_data: Any,
                               handler: Callable[[List[Any]], Awaitable[List[T]]]) -> T:
        """Execute operation with batching"""
        return await self.request_batcher.add_request(batch_key, request_data, handler)
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get comprehensive performance statistics"""
        uptime = time.time() - self._start_time
        
        stats = {
            "uptime_seconds": uptime,
            "cache_stats": self.cache.stats(),
            "concurrency_stats": self.concurrency_limiter.stats,
            "service_metrics": {}
        }
        
        for service, metrics in self.metrics.items():
            stats["service_metrics"][service] = {
                "total_requests": metrics.total_requests,
                "success_rate": round(metrics.success_rate, 2),
                "average_response_time": round(metrics.average_response_time, 3),
                "cache_hit_rate": round(metrics.cache_hit_rate, 2),
                "max_concurrent": metrics.max_concurrent
            }
        
        return stats
    
    async def optimize_for_service(self, service_name: str) -> Dict[str, Any]:
        """Provide optimization recommendations for a service"""
        metrics = self.metrics[service_name]
        recommendations = []
        
        # Analyze performance patterns
        if metrics.success_rate < 90:
            recommendations.append({
                "type": "reliability",
                "priority": "high",
                "message": f"Success rate is {metrics.success_rate:.1f}% - consider implementing retries or circuit breakers"
            })
        
        if metrics.average_response_time > 5.0:
            recommendations.append({
                "type": "performance",
                "priority": "medium",
                "message": f"Average response time is {metrics.average_response_time:.1f}s - consider caching or request optimization"
            })
        
        if metrics.cache_hit_rate < 50:
            recommendations.append({
                "type": "caching",
                "priority": "low",
                "message": f"Cache hit rate is {metrics.cache_hit_rate:.1f}% - review caching strategy"
            })
        
        if metrics.max_concurrent > 15:
            recommendations.append({
                "type": "concurrency",
                "priority": "medium",
                "message": f"High concurrency detected ({metrics.max_concurrent}) - consider implementing rate limiting"
            })
        
        return {
            "service": service_name,
            "current_metrics": {
                "requests": metrics.total_requests,
                "success_rate": metrics.success_rate,
                "avg_response_time": metrics.average_response_time,
                "cache_hit_rate": metrics.cache_hit_rate
            },
            "recommendations": recommendations
        }


# Global optimizer instance
performance_optimizer = PerformanceOptimizer()


def optimized(cache_ttl: float = 300):
    """Decorator to add performance optimization to async functions"""
    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            # Generate cache key
            service_name = getattr(args[0], '__class__', {}).get('__name__', 'unknown')
            cache_key = performance_optimizer.cache_key(
                service=service_name,
                operation=func.__name__,
                args=str(args[1:]),  # Skip self
                kwargs=kwargs
            )
            
            # Execute with optimization
            return await performance_optimizer.cached_operation(
                cache_key=cache_key,
                operation=lambda: func(*args, **kwargs),
                ttl=cache_ttl
            )
        
        return wrapper
    return decorator