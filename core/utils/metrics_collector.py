"""Metrics collection and instrumentation for the Legislative Monitoring System."""

import time
import logging
from typing import Dict, Any, Optional
from functools import wraps
from prometheus_client import Counter, Histogram, Gauge, Info, start_http_server
from datetime import datetime
import threading

logger = logging.getLogger(__name__)

# Prometheus metrics
http_requests_total = Counter(
    'http_requests_total',
    'Total number of HTTP requests',
    ['method', 'endpoint', 'status']
)

http_request_duration_seconds = Histogram(
    'http_request_duration_seconds',
    'Time spent on HTTP requests',
    ['method', 'endpoint']
)

external_api_requests_total = Counter(
    'external_api_requests_total',
    'Total number of external API requests',
    ['provider', 'endpoint', 'status']
)

external_api_duration_seconds = Histogram(
    'external_api_duration_seconds',
    'Time spent on external API requests',
    ['provider', 'endpoint']
)

cache_hits_total = Counter(
    'cache_hits_total',
    'Total number of cache hits',
    ['cache_type']
)

cache_misses_total = Counter(
    'cache_misses_total',
    'Total number of cache misses',
    ['cache_type']
)

circuit_breaker_state = Gauge(
    'circuit_breaker_state',
    'Circuit breaker state (0=closed, 1=open, 2=half-open)',
    ['service']
)

data_ingestion_total = Counter(
    'data_ingestion_total',
    'Total number of data items ingested',
    ['source', 'type']
)

data_ingestion_queue_size = Gauge(
    'data_ingestion_queue_size',
    'Current size of data ingestion queue',
    ['queue_type']
)

search_queries_total = Counter(
    'search_queries_total',
    'Total number of search queries',
    ['query_type', 'source']
)

export_jobs_total = Counter(
    'export_jobs_total',
    'Total number of export jobs',
    ['format', 'status']
)

export_jobs_failed_total = Counter(
    'export_jobs_failed_total',
    'Total number of failed export jobs',
    ['format', 'error_type']
)

database_connections_active = Gauge(
    'database_connections_active',
    'Number of active database connections'
)

system_info = Info(
    'system_info',
    'System information'
)


class MetricsCollector:
    """Centralized metrics collection and instrumentation."""
    
    def __init__(self):
        self._start_time = time.time()
        self._metrics_server_started = False
        self._lock = threading.Lock()
    
    def start_metrics_server(self, port: int = 8000):
        """Start Prometheus metrics server."""
        with self._lock:
            if not self._metrics_server_started:
                try:
                    start_http_server(port)
                    self._metrics_server_started = True
                    logger.info(f"Metrics server started on port {port}")
                    
                    # Set system information
                    system_info.info({
                        'version': '4.0.0',
                        'environment': 'production',
                        'start_time': str(datetime.fromtimestamp(self._start_time))
                    })
                    
                except Exception as e:
                    logger.error(f"Failed to start metrics server: {e}")
    
    @staticmethod
    def record_http_request(method: str, endpoint: str, status: str, duration: float):
        """Record HTTP request metrics."""
        http_requests_total.labels(method=method, endpoint=endpoint, status=status).inc()
        http_request_duration_seconds.labels(method=method, endpoint=endpoint).observe(duration)
    
    @staticmethod
    def record_external_api_request(provider: str, endpoint: str, status: str, duration: float):
        """Record external API request metrics."""
        external_api_requests_total.labels(
            provider=provider, 
            endpoint=endpoint, 
            status=status
        ).inc()
        external_api_duration_seconds.labels(
            provider=provider, 
            endpoint=endpoint
        ).observe(duration)
    
    @staticmethod
    def record_cache_hit(cache_type: str = 'redis'):
        """Record cache hit."""
        cache_hits_total.labels(cache_type=cache_type).inc()
    
    @staticmethod
    def record_cache_miss(cache_type: str = 'redis'):
        """Record cache miss."""
        cache_misses_total.labels(cache_type=cache_type).inc()
    
    @staticmethod
    def set_circuit_breaker_state(service: str, state: str):
        """Set circuit breaker state."""
        state_map = {'closed': 0, 'open': 1, 'half-open': 2}
        circuit_breaker_state.labels(service=service).set(state_map.get(state, 0))
    
    @staticmethod
    def record_data_ingestion(source: str, data_type: str, count: int = 1):
        """Record data ingestion."""
        data_ingestion_total.labels(source=source, type=data_type).inc(count)
    
    @staticmethod
    def set_ingestion_queue_size(queue_type: str, size: int):
        """Set ingestion queue size."""
        data_ingestion_queue_size.labels(queue_type=queue_type).set(size)
    
    @staticmethod
    def record_search_query(query_type: str, source: str):
        """Record search query."""
        search_queries_total.labels(query_type=query_type, source=source).inc()
    
    @staticmethod
    def record_export_job(format_type: str, status: str):
        """Record export job."""
        export_jobs_total.labels(format=format_type, status=status).inc()
        
        if status == 'failed':
            export_jobs_failed_total.labels(format=format_type, error_type='unknown').inc()
    
    @staticmethod
    def record_export_job_failure(format_type: str, error_type: str):
        """Record export job failure."""
        export_jobs_failed_total.labels(format=format_type, error_type=error_type).inc()
    
    @staticmethod
    def set_database_connections(count: int):
        """Set active database connections count."""
        database_connections_active.set(count)


# Global metrics collector instance
metrics = MetricsCollector()


def monitor_http_requests(func):
    """Decorator to monitor HTTP requests."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        method = kwargs.get('method', 'GET')
        endpoint = kwargs.get('endpoint', 'unknown')
        status = '200'
        
        try:
            result = func(*args, **kwargs)
            return result
        except Exception as e:
            status = '500'
            raise
        finally:
            duration = time.time() - start_time
            metrics.record_http_request(method, endpoint, status, duration)
    
    return wrapper


def monitor_external_api_calls(provider: str):
    """Decorator to monitor external API calls."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            endpoint = kwargs.get('endpoint', 'unknown')
            status = '200'
            
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                status = '500'
                raise
            finally:
                duration = time.time() - start_time
                metrics.record_external_api_request(provider, endpoint, status, duration)
        
        return wrapper
    return decorator


def monitor_cache_operations(cache_type: str = 'redis'):
    """Decorator to monitor cache operations."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                result = func(*args, **kwargs)
                if result is not None:
                    metrics.record_cache_hit(cache_type)
                else:
                    metrics.record_cache_miss(cache_type)
                return result
            except Exception as e:
                metrics.record_cache_miss(cache_type)
                raise
        
        return wrapper
    return decorator


class BusinessMetrics:
    """Business-specific metrics collection."""
    
    @staticmethod
    def record_legislative_proposal_processed(source: str, proposal_type: str):
        """Record processing of legislative proposal."""
        metrics.record_data_ingestion(source, f'proposal_{proposal_type}')
    
    @staticmethod
    def record_search_performed(keywords: str, sources: list, results_count: int):
        """Record search operation."""
        query_type = 'unified' if len(sources) > 1 else 'single_source'
        for source in sources:
            metrics.record_search_query(query_type, source)
    
    @staticmethod
    def record_user_session_started():
        """Record user session start."""
        metrics.record_data_ingestion('user_sessions', 'session_start')
    
    @staticmethod
    def record_api_key_usage(api_key_id: str, endpoint: str):
        """Record API key usage."""
        # This could be expanded to track API key specific metrics
        metrics.record_data_ingestion('api_usage', f'key_{api_key_id}')
    
    @staticmethod
    def record_alert_triggered(alert_type: str, severity: str):
        """Record alert being triggered."""
        metrics.record_data_ingestion('alerts', f'{severity}_{alert_type}')


class HealthMetrics:
    """Health and availability metrics."""
    
    @staticmethod
    def record_service_health_check(service: str, healthy: bool):
        """Record service health check result."""
        status = 'healthy' if healthy else 'unhealthy'
        metrics.record_data_ingestion('health_checks', f'{service}_{status}')
    
    @staticmethod
    def record_dependency_availability(dependency: str, available: bool):
        """Record external dependency availability."""
        status = 'available' if available else 'unavailable'
        metrics.record_data_ingestion('dependencies', f'{dependency}_{status}')
    
    @staticmethod
    def set_queue_sizes(queue_metrics: Dict[str, int]):
        """Set various queue sizes."""
        for queue_type, size in queue_metrics.items():
            metrics.set_ingestion_queue_size(queue_type, size)


class PerformanceMetrics:
    """Performance-specific metrics."""
    
    @staticmethod
    def record_database_query_time(query_type: str, duration: float):
        """Record database query performance."""
        # This would integrate with database-specific metrics
        pass
    
    @staticmethod
    def record_cache_performance(operation: str, duration: float, hit: bool):
        """Record cache operation performance."""
        if hit:
            metrics.record_cache_hit()
        else:
            metrics.record_cache_miss()
    
    @staticmethod
    def record_export_performance(export_format: str, file_size: int, duration: float):
        """Record export operation performance."""
        metrics.record_export_job(export_format, 'completed')


# Initialize metrics collection
def initialize_metrics(port: int = 8000):
    """Initialize metrics collection system."""
    try:
        metrics.start_metrics_server(port)
        logger.info("Metrics collection initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize metrics: {e}")


# Export commonly used functions
__all__ = [
    'metrics',
    'BusinessMetrics',
    'HealthMetrics',
    'PerformanceMetrics',
    'monitor_http_requests',
    'monitor_external_api_calls',
    'monitor_cache_operations',
    'initialize_metrics'
]