"""Custom Prometheus metrics for Monitor Legislativo."""
from prometheus_client import Counter, Histogram, Gauge
import time
from functools import wraps
from typing import Callable, Any
import logging

logger = logging.getLogger(__name__)

# Database metrics
db_query_duration = Histogram(
    'database_query_duration_seconds',
    'Time spent on database queries',
    ['query_type', 'table']
)

db_query_count = Counter(
    'database_queries_total',
    'Total number of database queries',
    ['query_type', 'table', 'status']
)

db_connection_count = Gauge(
    'database_connections_active',
    'Number of active database connections'
)

# API metrics
api_search_requests = Counter(
    'api_search_requests_total',
    'Total number of search requests',
    ['search_type', 'status']
)

api_cache_hits = Counter(
    'api_cache_hits_total',
    'Total number of cache hits',
    ['cache_type']
)

api_cache_misses = Counter(
    'api_cache_misses_total',
    'Total number of cache misses',
    ['cache_type']
)

# Document processing metrics
documents_processed = Counter(
    'documents_processed_total',
    'Total number of documents processed',
    ['source', 'status']
)

document_processing_duration = Histogram(
    'document_processing_duration_seconds',
    'Time spent processing documents',
    ['source', 'processing_stage']
)


def track_database_query(query_type: str, table: str = "unknown"):
    """Decorator to track database query metrics."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            start_time = time.time()
            status = "success"
            
            try:
                result = await func(*args, **kwargs)
                return result
            except Exception as e:
                status = "error"
                logger.error(f"Database query failed: {e}")
                raise
            finally:
                duration = time.time() - start_time
                db_query_duration.labels(
                    query_type=query_type,
                    table=table
                ).observe(duration)
                
                db_query_count.labels(
                    query_type=query_type,
                    table=table,
                    status=status
                ).inc()
        
        return wrapper
    return decorator


def track_search_request(search_type: str):
    """Decorator to track search request metrics."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            status = "success"
            
            try:
                result = await func(*args, **kwargs)
                return result
            except Exception as e:
                status = "error"
                logger.error(f"Search request failed: {e}")
                raise
            finally:
                api_search_requests.labels(
                    search_type=search_type,
                    status=status
                ).inc()
        
        return wrapper
    return decorator


def record_cache_hit(cache_type: str):
    """Record a cache hit."""
    api_cache_hits.labels(cache_type=cache_type).inc()


def record_cache_miss(cache_type: str):
    """Record a cache miss."""
    api_cache_misses.labels(cache_type=cache_type).inc()


def record_document_processed(source: str, status: str = "success"):
    """Record a processed document."""
    documents_processed.labels(source=source, status=status).inc()


def track_document_processing(source: str, stage: str):
    """Decorator to track document processing time."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            start_time = time.time()
            
            try:
                result = await func(*args, **kwargs)
                return result
            finally:
                duration = time.time() - start_time
                document_processing_duration.labels(
                    source=source,
                    processing_stage=stage
                ).observe(duration)
        
        return wrapper
    return decorator