"""
Flask Performance Monitoring Middleware
Automatic request tracking and performance metrics
"""

import time
import logging
from typing import Dict, Any, Optional
from flask import Flask, request, g, Response
from werkzeug.exceptions import HTTPException
import uuid

from core.monitoring.performance_monitor import get_performance_monitor, RequestMetrics

logger = logging.getLogger(__name__)

class PerformanceMiddleware:
    """Flask middleware for performance monitoring"""
    
    def __init__(self, app: Flask = None, 
                 enable_profiling: bool = True,
                 track_db_queries: bool = True,
                 track_cache: bool = True):
        self.app = app
        self.enable_profiling = enable_profiling
        self.track_db_queries = track_db_queries
        self.track_cache = track_cache
        self.monitor = get_performance_monitor()
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask):
        """Initialize middleware with Flask app"""
        self.app = app
        
        # Register handlers
        app.before_request(self._before_request)
        app.after_request(self._after_request)
        app.teardown_request(self._teardown_request)
        
        # Add error handler
        app.errorhandler(Exception)(self._handle_error)
        
        # Add performance endpoints
        self._add_performance_endpoints()
        
        logger.info("Performance monitoring middleware initialized")
    
    def _before_request(self):
        """Start request tracking"""
        if not self.enable_profiling:
            return
        
        # Generate request ID
        g.request_id = str(uuid.uuid4())
        g.start_time = time.time()
        
        # Create request metrics
        g.request_metrics = RequestMetrics(
            request_id=g.request_id,
            endpoint=request.endpoint or request.path,
            method=request.method,
            start_time=time.time()
        )
        
        # Store in monitor
        self.monitor.current_requests[g.request_id] = g.request_metrics
        
        # Log request start
        logger.debug(f"Request started: {g.request_id} - {request.method} {request.path}")
    
    def _after_request(self, response: Response) -> Response:
        """Complete request tracking"""
        if not self.enable_profiling or not hasattr(g, 'request_metrics'):
            return response
        
        # Update metrics
        g.request_metrics.status_code = response.status_code
        
        # Add performance headers
        if hasattr(g, 'request_id'):
            response.headers['X-Request-ID'] = g.request_id
        
        if hasattr(g, 'start_time'):
            duration_ms = (time.time() - g.start_time) * 1000
            response.headers['X-Response-Time'] = f"{duration_ms:.2f}ms"
        
        return response
    
    def _teardown_request(self, exception=None):
        """Finalize request tracking"""
        if not self.enable_profiling or not hasattr(g, 'request_metrics'):
            return
        
        # Calculate final metrics
        g.request_metrics.end_time = time.time()
        g.request_metrics.duration_ms = (g.request_metrics.end_time - g.request_metrics.start_time) * 1000
        
        if exception:
            g.request_metrics.error = str(exception)
        
        # Record metrics
        self.monitor.collector.record_request(g.request_metrics)
        
        # Clean up
        if hasattr(g, 'request_id') and g.request_id in self.monitor.current_requests:
            del self.monitor.current_requests[g.request_id]
        
        # Log request completion
        logger.debug(f"Request completed: {getattr(g, 'request_id', 'unknown')} - "
                    f"{g.request_metrics.duration_ms:.2f}ms")
    
    def _handle_error(self, error: Exception) -> tuple:
        """Handle and track errors"""
        if hasattr(g, 'request_metrics'):
            g.request_metrics.error = str(error)
            
            if isinstance(error, HTTPException):
                g.request_metrics.status_code = error.code
            else:
                g.request_metrics.status_code = 500
        
        # Re-raise for default error handling
        raise error
    
    def _add_performance_endpoints(self):
        """Add performance monitoring endpoints"""
        
        @self.app.route('/api/performance/stats')
        def performance_stats():
            """Get performance statistics"""
            time_range = request.args.get('time_range', type=int)
            metric_name = request.args.get('metric')
            
            stats = self.monitor.get_stats(
                metric_name=metric_name,
                time_range=time_range
            )
            
            return stats
        
        @self.app.route('/api/performance/health')
        def performance_health():
            """Get health status"""
            return self.monitor.get_health_status()
        
        @self.app.route('/api/performance/metrics')
        def performance_metrics():
            """Get metrics in various formats"""
            format = request.args.get('format', 'json')
            
            try:
                metrics = self.monitor.export_metrics(format)
                
                if format == 'prometheus':
                    return Response(metrics, mimetype='text/plain')
                else:
                    return Response(metrics, mimetype='application/json')
                    
            except ValueError as e:
                return {'error': str(e)}, 400

# Database query tracking integration

def track_db_query(func):
    """Decorator to track database query performance"""
    def wrapper(*args, **kwargs):
        if not hasattr(g, 'request_id'):
            return func(*args, **kwargs)
        
        start_time = time.time()
        
        try:
            result = func(*args, **kwargs)
            duration_ms = (time.time() - start_time) * 1000
            
            # Track in performance monitor
            monitor = get_performance_monitor()
            monitor.track_db_query(g.request_id, duration_ms)
            
            # Record metric
            monitor.record_metric(
                name='db.query.duration',
                value=duration_ms,
                unit='ms',
                tags={
                    'operation': func.__name__,
                    'status': 'success'
                }
            )
            
            return result
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            
            # Track error
            monitor = get_performance_monitor()
            monitor.record_metric(
                name='db.query.duration',
                value=duration_ms,
                unit='ms',
                tags={
                    'operation': func.__name__,
                    'status': 'error',
                    'error': type(e).__name__
                }
            )
            
            raise
    
    return wrapper

# Cache tracking integration

def track_cache_access(key: str, hit: bool):
    """Track cache access"""
    if hasattr(g, 'request_id'):
        monitor = get_performance_monitor()
        monitor.track_cache_access(g.request_id, hit)
        
        # Record metric
        monitor.record_metric(
            name='cache.access',
            value=1,
            unit='count',
            tags={
                'result': 'hit' if hit else 'miss',
                'key_prefix': key.split(':')[0] if ':' in key else 'unknown'
            }
        )

# External API tracking

class APICallTracker:
    """Context manager for tracking external API calls"""
    
    def __init__(self, api_name: str, endpoint: str):
        self.api_name = api_name
        self.endpoint = endpoint
        self.start_time = None
        self.monitor = get_performance_monitor()
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration_ms = (time.time() - self.start_time) * 1000
        
        # Track in request if available
        if hasattr(g, 'request_id'):
            self.monitor.track_external_api(g.request_id, duration_ms)
        
        # Record metric
        self.monitor.record_metric(
            name='external_api.duration',
            value=duration_ms,
            unit='ms',
            tags={
                'api': self.api_name,
                'endpoint': self.endpoint,
                'status': 'error' if exc_type else 'success',
                'error': exc_type.__name__ if exc_type else None
            }
        )

# Performance monitoring utilities

def measure_time(name: str, tags: Dict[str, str] = None):
    """Decorator to measure function execution time"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                duration_ms = (time.time() - start_time) * 1000
                
                monitor = get_performance_monitor()
                monitor.record_metric(
                    name=f'function.{name}.duration',
                    value=duration_ms,
                    unit='ms',
                    tags={**(tags or {}), 'status': 'success'}
                )
                
                return result
                
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                
                monitor = get_performance_monitor()
                monitor.record_metric(
                    name=f'function.{name}.duration',
                    value=duration_ms,
                    unit='ms',
                    tags={
                        **(tags or {}), 
                        'status': 'error',
                        'error': type(e).__name__
                    }
                )
                
                raise
        
        return wrapper
    return decorator

def record_business_metric(name: str, value: float, unit: str = 'count', 
                         tags: Dict[str, str] = None):
    """Record a business metric"""
    monitor = get_performance_monitor()
    monitor.record_metric(name, value, unit, tags)

# Example usage with Flask app

def setup_performance_monitoring(app: Flask) -> PerformanceMiddleware:
    """Setup complete performance monitoring for Flask app"""
    
    # Initialize middleware
    middleware = PerformanceMiddleware(
        app=app,
        enable_profiling=True,
        track_db_queries=True,
        track_cache=True
    )
    
    # Add custom monitors
    monitor = get_performance_monitor()
    
    def check_request_queue(monitor):
        """Monitor request queue size"""
        queue_size = len(monitor.current_requests)
        monitor.record_metric(
            name='request.queue_size',
            value=queue_size,
            unit='count'
        )
        
        if queue_size > 100:
            logger.warning(f"High request queue size: {queue_size}")
    
    monitor.add_monitor(check_request_queue)
    
    return middleware