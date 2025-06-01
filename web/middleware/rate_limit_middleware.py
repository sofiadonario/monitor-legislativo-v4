"""
Flask Rate Limiting Middleware
Integrates rate limiting with Flask routes
"""

from functools import wraps
from flask import request, jsonify, g
import logging
from typing import Optional, Dict, Any, Callable

from core.utils.rate_limiter import (
    get_rate_limiter, 
    RateLimitResult, 
    RateLimitConfig, 
    QuotaConfig
)

logger = logging.getLogger(__name__)

class RateLimitMiddleware:
    """Flask middleware for rate limiting"""
    
    def __init__(self, app=None, 
                 rate_config: RateLimitConfig = None,
                 quota_config: QuotaConfig = None):
        self.rate_config = rate_config
        self.quota_config = quota_config
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize middleware with Flask app"""
        from core.utils.rate_limiter import init_rate_limiter
        
        # Initialize rate limiter with configs
        init_rate_limiter(self.rate_config, self.quota_config)
        
        # Add before_request handler
        app.before_request(self.before_request)
        
        # Store reference in app
        app.rate_limit_middleware = self
    
    def before_request(self):
        """Check rate limits before each request"""
        # Skip rate limiting for certain paths
        if self._should_skip_rate_limiting():
            return
        
        client_id = self._get_client_id()
        endpoint = self._get_endpoint_key()
        
        rate_limiter = get_rate_limiter()
        result = rate_limiter.check_limits(client_id, endpoint)
        
        # Store result for use in response headers
        g.rate_limit_result = result
        
        if not result.allowed:
            return self._create_rate_limit_response(result)
    
    def _should_skip_rate_limiting(self) -> bool:
        """Check if rate limiting should be skipped for this request"""
        skip_paths = [
            '/health',
            '/metrics',
            '/static/',
            '/favicon.ico'
        ]
        
        path = request.path
        return any(path.startswith(skip_path) for skip_path in skip_paths)
    
    def _get_client_id(self) -> str:
        """Extract client ID from request"""
        # Try multiple methods to identify client
        
        # 1. API key from header
        api_key = request.headers.get('X-API-Key')
        if api_key:
            return f"api_key:{api_key}"
        
        # 2. Authorization header (JWT token)
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header[7:]
            # In production, you'd decode JWT to get user ID
            # For now, use token hash
            import hashlib
            token_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
            return f"jwt:{token_hash}"
        
        # 3. Session ID
        session_id = request.headers.get('X-Session-ID')
        if session_id:
            return f"session:{session_id}"
        
        # 4. IP address (fallback)
        client_ip = self._get_client_ip()
        return f"ip:{client_ip}"
    
    def _get_client_ip(self) -> str:
        """Get client IP address"""
        # Check for forwarded headers (proxy/load balancer)
        forwarded_ips = request.headers.get('X-Forwarded-For')
        if forwarded_ips:
            return forwarded_ips.split(',')[0].strip()
        
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip
        
        return request.remote_addr or 'unknown'
    
    def _get_endpoint_key(self) -> str:
        """Generate endpoint key for rate limiting"""
        # Combine method and route pattern
        method = request.method
        path = request.path
        
        # Normalize paths with IDs to patterns
        # e.g., /api/projects/123 -> /api/projects/{id}
        normalized_path = self._normalize_path(path)
        
        return f"{method}:{normalized_path}"
    
    def _normalize_path(self, path: str) -> str:
        """Normalize path by replacing IDs with placeholders"""
        import re
        
        # Replace numeric IDs
        path = re.sub(r'/\d+', '/{id}', path)
        
        # Replace UUIDs
        uuid_pattern = r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        path = re.sub(uuid_pattern, '/{uuid}', path, flags=re.IGNORECASE)
        
        return path
    
    def _create_rate_limit_response(self, result: RateLimitResult) -> Dict[str, Any]:
        """Create rate limit exceeded response"""
        response_data = {
            'error': 'Rate limit exceeded',
            'message': 'Too many requests. Please try again later.',
            'retry_after': result.retry_after,
            'reset_time': result.reset_time
        }
        
        response = jsonify(response_data)
        response.status_code = 429
        
        # Add rate limit headers
        self._add_rate_limit_headers(response, result)
        
        return response
    
    def _add_rate_limit_headers(self, response, result: RateLimitResult):
        """Add rate limiting headers to response"""
        response.headers['X-RateLimit-Remaining'] = str(result.remaining)
        response.headers['X-RateLimit-Reset'] = str(result.reset_time)
        
        if result.retry_after:
            response.headers['Retry-After'] = str(result.retry_after)
        
        if result.quota_remaining is not None:
            response.headers['X-Quota-Remaining'] = str(result.quota_remaining)

def add_rate_limit_headers(response):
    """Add rate limit headers to successful responses"""
    if hasattr(g, 'rate_limit_result'):
        result = g.rate_limit_result
        response.headers['X-RateLimit-Remaining'] = str(result.remaining)
        response.headers['X-RateLimit-Reset'] = str(result.reset_time)
        
        if result.quota_remaining is not None:
            response.headers['X-Quota-Remaining'] = str(result.quota_remaining)
    
    return response

# Decorators for route-specific rate limiting

def rate_limit(requests_per_minute: int = None, 
               requests_per_hour: int = None,
               skip_global: bool = False):
    """Decorator for route-specific rate limiting"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not skip_global and hasattr(g, 'rate_limit_result'):
                # Global rate limiting already checked
                if not g.rate_limit_result.allowed:
                    return _create_rate_limit_response(g.rate_limit_result)
            
            # Apply route-specific limits if specified
            if requests_per_minute or requests_per_hour:
                client_id = _get_client_id_for_decorator()
                endpoint = f"{request.method}:{request.endpoint}"
                
                # Create custom config for this route
                from core.utils.rate_limiter import RateLimitConfig, MemoryRateLimiter
                
                custom_config = RateLimitConfig(
                    requests_per_minute=requests_per_minute or 60,
                    requests_per_hour=requests_per_hour or 1000
                )
                
                custom_limiter = MemoryRateLimiter(custom_config)
                result = custom_limiter.check_rate_limit(f"{client_id}:{endpoint}")
                
                if not result.allowed:
                    return _create_rate_limit_response(result)
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator

def _get_client_id_for_decorator() -> str:
    """Helper to get client ID in decorator context"""
    api_key = request.headers.get('X-API-Key')
    if api_key:
        return f"api_key:{api_key}"
    
    client_ip = request.remote_addr or 'unknown'
    return f"ip:{client_ip}"

def _create_rate_limit_response(result: RateLimitResult) -> Dict[str, Any]:
    """Helper to create rate limit response in decorator context"""
    response_data = {
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Please try again later.',
        'retry_after': result.retry_after,
        'reset_time': result.reset_time
    }
    
    response = jsonify(response_data)
    response.status_code = 429
    
    response.headers['X-RateLimit-Remaining'] = str(result.remaining)
    response.headers['X-RateLimit-Reset'] = str(result.reset_time)
    
    if result.retry_after:
        response.headers['Retry-After'] = str(result.retry_after)
    
    return response

# API key based rate limiting
def api_key_rate_limit(tier: str = 'basic'):
    """Decorator for API key based rate limiting with tiers"""
    
    # Define rate limit tiers
    tiers = {
        'basic': {'per_minute': 30, 'per_hour': 500, 'per_day': 5000},
        'premium': {'per_minute': 100, 'per_hour': 2000, 'per_day': 20000},
        'enterprise': {'per_minute': 300, 'per_hour': 10000, 'per_day': 100000}
    }
    
    tier_config = tiers.get(tier, tiers['basic'])
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            api_key = request.headers.get('X-API-Key')
            if not api_key:
                return jsonify({'error': 'API key required'}), 401
            
            # Check tier-specific limits
            client_id = f"api_key:{api_key}"
            endpoint = f"{request.method}:{request.endpoint}"
            
            from core.utils.rate_limiter import RateLimitConfig, MemoryRateLimiter
            
            tier_limiter_config = RateLimitConfig(
                requests_per_minute=tier_config['per_minute'],
                requests_per_hour=tier_config['per_hour']
            )
            
            tier_limiter = MemoryRateLimiter(tier_limiter_config)
            result = tier_limiter.check_rate_limit(f"{client_id}:{endpoint}")
            
            if not result.allowed:
                return _create_rate_limit_response(result)
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator