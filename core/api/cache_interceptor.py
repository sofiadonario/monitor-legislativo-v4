"""
API Cache Interceptor for Monitor Legislativo
Implements intelligent caching middleware for FastAPI
"""

import json
import time
import hashlib
from typing import Callable, Dict, Any, Optional
from collections import defaultdict
import logging

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from core.cache.cache_manager import get_cache_manager
from core.cache.redis_config import redis_config

logger = logging.getLogger(__name__)


class CacheInterceptor(BaseHTTPMiddleware):
    """
    FastAPI middleware for intelligent API response caching
    
    Features:
    - Automatic cache key generation
    - TTL management based on endpoint patterns
    - Cache hit/miss tracking
    - Stale-while-revalidate support
    - Conditional caching based on response status
    """
    
    def __init__(self, app: ASGIApp, exclude_paths: Optional[list] = None):
        super().__init__(app)
        self.cache_manager = get_cache_manager()
        self.exclude_paths = exclude_paths or ['/api/health', '/api/metrics', '/api/docs']
        self.stats = defaultdict(int)
        
        # Cache strategies by endpoint pattern
        self.cache_strategies = {
            '/api/v1/search': {
                'ttl': redis_config.TTL.search_results,
                'cache_on_params': True,
                'stale_while_revalidate': 300
            },
            '/api/v1/proposals': {
                'ttl': redis_config.TTL.api_camara,
                'cache_on_params': True,
                'stale_while_revalidate': 600
            },
            '/api/v1/sources': {
                'ttl': redis_config.TTL.geography,
                'cache_on_params': False,
                'stale_while_revalidate': 3600
            },
            '/api/v1/geography': {
                'ttl': redis_config.TTL.geography,
                'cache_on_params': True,
                'stale_while_revalidate': 7200
            },
            '/api/v1/export': {
                'ttl': redis_config.TTL.export,
                'cache_on_params': True,
                'stale_while_revalidate': 900
            },
            '/api/v1/statistics': {
                'ttl': redis_config.TTL.statistics,
                'cache_on_params': True,
                'stale_while_revalidate': 1800
            }
        }
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Main middleware dispatch method"""
        # Skip non-GET requests
        if request.method != 'GET':
            return await call_next(request)
        
        # Skip excluded paths
        path = request.url.path
        if any(path.startswith(exclude) for exclude in self.exclude_paths):
            return await call_next(request)
        
        # Generate cache key
        cache_key = await self.generate_cache_key(request)
        
        # Check cache
        cached_response = await self.get_cached_response(cache_key, request)
        if cached_response:
            self.stats['hits'] += 1
            return cached_response
        
        # Process request
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        
        # Cache successful responses
        if response.status_code == 200:
            await self.cache_response(cache_key, response, request)
        
        self.stats['misses'] += 1
        
        # Add cache headers
        response.headers['X-Cache'] = 'MISS'
        response.headers['X-Process-Time'] = f"{process_time:.3f}"
        
        return response
    
    async def generate_cache_key(self, request: Request) -> str:
        """Generate cache key from request"""
        path = request.url.path
        
        # Get cache strategy for this endpoint
        strategy = self.get_cache_strategy(path)
        
        if strategy.get('cache_on_params', True):
            # Include query parameters in cache key
            params = dict(request.query_params)
            
            # Sort parameters for consistency
            sorted_params = sorted(params.items())
            param_str = json.dumps(sorted_params, sort_keys=True)
            param_hash = hashlib.md5(param_str.encode()).hexdigest()[:12]
            
            cache_key = f"api:{path.strip('/')}:{param_hash}"
        else:
            # Cache based on path only
            cache_key = f"api:{path.strip('/')}"
        
        return cache_key.replace('/', ':')
    
    def get_cache_strategy(self, path: str) -> Dict[str, Any]:
        """Get caching strategy for endpoint"""
        # Check exact match first
        if path in self.cache_strategies:
            return self.cache_strategies[path]
        
        # Check pattern match
        for pattern, strategy in self.cache_strategies.items():
            if path.startswith(pattern):
                return strategy
        
        # Default strategy
        return {
            'ttl': redis_config.TTL.default,
            'cache_on_params': True,
            'stale_while_revalidate': 300
        }
    
    async def get_cached_response(self, cache_key: str, request: Request) -> Optional[Response]:
        """Get cached response if available"""
        try:
            # Check main cache
            cached_data = self.cache_manager.get(cache_key)
            
            if cached_data:
                # Parse cached response
                if isinstance(cached_data, dict):
                    content = cached_data.get('content', {})
                    headers = cached_data.get('headers', {})
                    cache_time = cached_data.get('cache_time', 0)
                else:
                    content = cached_data
                    headers = {}
                    cache_time = 0
                
                # Create response
                response = JSONResponse(
                    content=content,
                    headers={
                        **headers,
                        'X-Cache': 'HIT',
                        'X-Cache-Time': str(cache_time),
                        'X-Cache-Age': str(int(time.time() - cache_time))
                    }
                )
                
                return response
            
            # Check stale cache for stale-while-revalidate
            stale_key = f"stale:{cache_key}"
            stale_data = self.cache_manager.get(stale_key)
            
            if stale_data:
                # Return stale data while revalidating in background
                self._schedule_revalidation(cache_key, request)
                
                content = stale_data.get('content', stale_data)
                return JSONResponse(
                    content=content,
                    headers={
                        'X-Cache': 'STALE',
                        'X-Cache-Warning': '110 - Response is stale'
                    }
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting cached response: {e}")
            return None
    
    async def cache_response(self, cache_key: str, response: Response, request: Request):
        """Cache the response"""
        try:
            # Read response body
            body = b""
            async for chunk in response.body_iterator:
                body += chunk
            
            # Parse body
            try:
                content = json.loads(body.decode())
            except json.JSONDecodeError:
                content = body.decode()
            
            # Get caching strategy
            strategy = self.get_cache_strategy(request.url.path)
            ttl = strategy['ttl']
            stale_ttl = strategy.get('stale_while_revalidate', 300)
            
            # Prepare cache data
            cache_data = {
                'content': content,
                'headers': dict(response.headers),
                'cache_time': time.time(),
                'request_path': request.url.path
            }
            
            # Cache main data
            self.cache_manager.set(cache_key, cache_data, ttl)
            
            # Cache stale version for fallback
            stale_key = f"stale:{cache_key}"
            self.cache_manager.set(stale_key, cache_data, ttl + stale_ttl)
            
            # Update response body for client
            response.body_iterator = self._iterate_body(body)
            
        except Exception as e:
            logger.error(f"Error caching response: {e}")
    
    def _iterate_body(self, body: bytes):
        """Helper to create body iterator"""
        yield body
    
    def _schedule_revalidation(self, cache_key: str, request: Request):
        """Schedule background revalidation of stale cache"""
        # This would typically trigger a background task
        # For now, just log it
        logger.info(f"Scheduling revalidation for cache key: {cache_key}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache interceptor statistics"""
        total = self.stats['hits'] + self.stats['misses']
        hit_rate = (self.stats['hits'] / total * 100) if total > 0 else 0
        
        return {
            'hits': self.stats['hits'],
            'misses': self.stats['misses'],
            'total_requests': total,
            'hit_rate': hit_rate,
            'cache_metrics': self.cache_manager.get_metrics()
        }


class APICacheMiddleware:
    """
    Alternative cache middleware implementation for specific endpoints
    Can be used as a decorator for individual routes
    """
    
    def __init__(self, ttl: Optional[int] = None, key_prefix: str = "api"):
        self.ttl = ttl
        self.key_prefix = key_prefix
        self.cache_manager = get_cache_manager()
    
    async def __call__(self, request: Request, call_next: Callable):
        """Middleware implementation"""
        # Generate cache key
        cache_key = self._generate_key(request)
        
        # Try cache
        cached = self.cache_manager.get(cache_key)
        if cached:
            return JSONResponse(
                content=cached,
                headers={'X-Cache': 'HIT'}
            )
        
        # Get fresh response
        response = await call_next(request)
        
        # Cache if successful
        if response.status_code == 200:
            # Read response
            body = b""
            async for chunk in response.body_iterator:
                body += chunk
            
            try:
                content = json.loads(body.decode())
                self.cache_manager.set(cache_key, content, self.ttl)
            except:
                pass
            
            # Reset body iterator
            response.body_iterator = self._iterate_body(body)
        
        response.headers['X-Cache'] = 'MISS'
        return response
    
    def _generate_key(self, request: Request) -> str:
        """Generate cache key from request"""
        path = request.url.path
        params = dict(request.query_params)
        
        param_str = json.dumps(params, sort_keys=True)
        param_hash = hashlib.md5(param_str.encode()).hexdigest()[:12]
        
        return f"{self.key_prefix}:{path}:{param_hash}"
    
    def _iterate_body(self, body: bytes):
        """Helper to create body iterator"""
        yield body


def cache_route(ttl: Optional[int] = None, key_prefix: str = "api"):
    """
    Decorator to cache individual routes
    
    Usage:
        @app.get("/api/data")
        @cache_route(ttl=3600)
        async def get_data():
            return {"data": "value"}
    """
    def decorator(func: Callable) -> Callable:
        async def wrapper(request: Request, *args, **kwargs):
            cache_manager = get_cache_manager()
            
            # Generate cache key
            path = request.url.path
            params = dict(request.query_params)
            param_str = json.dumps(params, sort_keys=True)
            param_hash = hashlib.md5(param_str.encode()).hexdigest()[:12]
            cache_key = f"{key_prefix}:{path}:{param_hash}"
            
            # Try cache
            cached = cache_manager.get(cache_key)
            if cached:
                return JSONResponse(
                    content=cached,
                    headers={'X-Cache': 'HIT'}
                )
            
            # Get fresh data
            result = await func(request, *args, **kwargs)
            
            # Cache result
            if isinstance(result, dict):
                cache_manager.set(cache_key, result, ttl)
            
            if isinstance(result, JSONResponse):
                result.headers['X-Cache'] = 'MISS'
            else:
                result = JSONResponse(
                    content=result,
                    headers={'X-Cache': 'MISS'}
                )
            
            return result
        
        return wrapper
    return decorator