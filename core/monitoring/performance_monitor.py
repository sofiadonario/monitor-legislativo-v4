"""
Enhanced Performance Monitoring System
Application Performance Monitoring with detailed metrics and profiling
"""

import time
import psutil
import threading
import logging
from typing import Dict, List, Any, Optional, Callable, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict, field
from collections import defaultdict, deque
import statistics
import json
import traceback
import asyncio
from contextlib import contextmanager
from functools import wraps
import inspect

logger = logging.getLogger(__name__)

@dataclass
class PerformanceMetric:
    """Individual performance metric"""
    name: str
    value: float
    unit: str
    timestamp: datetime
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class RequestMetrics:
    """Metrics for a single request"""
    request_id: str
    endpoint: str
    method: str
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_ms: Optional[float] = None
    status_code: Optional[int] = None
    error: Optional[str] = None
    db_queries: int = 0
    db_time_ms: float = 0.0
    cache_hits: int = 0
    cache_misses: int = 0
    external_api_calls: int = 0
    external_api_time_ms: float = 0.0
    memory_used_mb: float = 0.0
    cpu_percent: float = 0.0
    custom_metrics: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SystemMetrics:
    """System-wide performance metrics"""
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    memory_available_mb: float
    disk_usage_percent: float
    disk_io_read_mb: float
    disk_io_write_mb: float
    network_sent_mb: float
    network_recv_mb: float
    open_connections: int
    thread_count: int
    process_count: int

class MetricsCollector:
    """Collects and aggregates performance metrics"""
    
    def __init__(self, window_size: int = 300):  # 5-minute window
        self.window_size = window_size
        self.metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.request_metrics: deque = deque(maxlen=10000)
        self.system_metrics: deque = deque(maxlen=1000)
        self._lock = threading.RLock()
        
        # Aggregated stats
        self._stats_cache = {}
        self._stats_cache_time = None
        self._stats_cache_ttl = 10  # seconds
    
    def record_metric(self, metric: PerformanceMetric):
        """Record a performance metric"""
        with self._lock:
            key = f"{metric.name}:{json.dumps(metric.tags, sort_keys=True)}"
            self.metrics[key].append(metric)
    
    def record_request(self, request: RequestMetrics):
        """Record request metrics"""
        with self._lock:
            self.request_metrics.append(request)
    
    def record_system(self, system: SystemMetrics):
        """Record system metrics"""
        with self._lock:
            self.system_metrics.append(system)
    
    def get_stats(self, metric_name: str = None, 
                  time_range: int = None) -> Dict[str, Any]:
        """Get aggregated statistics"""
        
        # Check cache
        cache_key = f"{metric_name}:{time_range}"
        now = time.time()
        
        if (self._stats_cache_time and 
            (now - self._stats_cache_time) < self._stats_cache_ttl and
            cache_key in self._stats_cache):
            return self._stats_cache[cache_key]
        
        with self._lock:
            if metric_name:
                # Stats for specific metric
                stats = self._calculate_metric_stats(metric_name, time_range)
            else:
                # Overall stats
                stats = self._calculate_overall_stats(time_range)
            
            # Cache results
            self._stats_cache[cache_key] = stats
            self._stats_cache_time = now
            
            return stats
    
    def _calculate_metric_stats(self, metric_name: str, 
                               time_range: int = None) -> Dict[str, Any]:
        """Calculate statistics for specific metric"""
        
        # Find all metrics matching name
        matching_metrics = []
        cutoff_time = None
        
        if time_range:
            cutoff_time = datetime.utcnow() - timedelta(seconds=time_range)
        
        for key, metrics in self.metrics.items():
            if metric_name in key:
                for metric in metrics:
                    if not cutoff_time or metric.timestamp >= cutoff_time:
                        matching_metrics.append(metric)
        
        if not matching_metrics:
            return {}
        
        values = [m.value for m in matching_metrics]
        
        return {
            'metric': metric_name,
            'count': len(values),
            'mean': statistics.mean(values),
            'median': statistics.median(values),
            'min': min(values),
            'max': max(values),
            'std_dev': statistics.stdev(values) if len(values) > 1 else 0,
            'percentiles': {
                'p50': statistics.median(values),
                'p90': self._percentile(values, 90),
                'p95': self._percentile(values, 95),
                'p99': self._percentile(values, 99)
            },
            'latest': matching_metrics[-1].value if matching_metrics else None,
            'unit': matching_metrics[0].unit if matching_metrics else None
        }
    
    def _calculate_overall_stats(self, time_range: int = None) -> Dict[str, Any]:
        """Calculate overall system statistics"""
        
        cutoff_time = None
        if time_range:
            cutoff_time = datetime.utcnow() - timedelta(seconds=time_range)
        
        # Request statistics
        recent_requests = [
            r for r in self.request_metrics
            if not cutoff_time or r.start_time >= cutoff_time
        ]
        
        request_stats = self._calculate_request_stats(recent_requests)
        
        # System statistics
        recent_system = [
            s for s in self.system_metrics
            if not cutoff_time or s.timestamp >= cutoff_time
        ]
        
        system_stats = self._calculate_system_stats(recent_system)
        
        return {
            'requests': request_stats,
            'system': system_stats,
            'time_range_seconds': time_range,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def _calculate_request_stats(self, requests: List[RequestMetrics]) -> Dict[str, Any]:
        """Calculate request statistics"""
        
        if not requests:
            return {}
        
        # Basic stats
        total_requests = len(requests)
        successful_requests = len([r for r in requests if r.status_code and 200 <= r.status_code < 400])
        failed_requests = len([r for r in requests if r.status_code and r.status_code >= 400])
        error_requests = len([r for r in requests if r.error])
        
        # Response times
        response_times = [r.duration_ms for r in requests if r.duration_ms]
        
        # Database stats
        db_times = [r.db_time_ms for r in requests if r.db_queries > 0]
        total_db_queries = sum(r.db_queries for r in requests)
        
        # Cache stats
        total_cache_hits = sum(r.cache_hits for r in requests)
        total_cache_misses = sum(r.cache_misses for r in requests)
        
        # Endpoint breakdown
        endpoint_stats = defaultdict(lambda: {'count': 0, 'total_time': 0, 'errors': 0})
        for r in requests:
            endpoint_stats[r.endpoint]['count'] += 1
            if r.duration_ms:
                endpoint_stats[r.endpoint]['total_time'] += r.duration_ms
            if r.error or (r.status_code and r.status_code >= 400):
                endpoint_stats[r.endpoint]['errors'] += 1
        
        # Calculate endpoint averages
        for endpoint, stats in endpoint_stats.items():
            if stats['count'] > 0:
                stats['avg_time'] = stats['total_time'] / stats['count']
                stats['error_rate'] = stats['errors'] / stats['count'] * 100
        
        return {
            'total': total_requests,
            'successful': successful_requests,
            'failed': failed_requests,
            'errors': error_requests,
            'success_rate': (successful_requests / total_requests * 100) if total_requests else 0,
            'error_rate': (error_requests / total_requests * 100) if total_requests else 0,
            'response_times': {
                'mean': statistics.mean(response_times) if response_times else 0,
                'median': statistics.median(response_times) if response_times else 0,
                'min': min(response_times) if response_times else 0,
                'max': max(response_times) if response_times else 0,
                'p95': self._percentile(response_times, 95) if response_times else 0,
                'p99': self._percentile(response_times, 99) if response_times else 0
            },
            'database': {
                'total_queries': total_db_queries,
                'avg_queries_per_request': total_db_queries / total_requests if total_requests else 0,
                'avg_time_ms': statistics.mean(db_times) if db_times else 0
            },
            'cache': {
                'hits': total_cache_hits,
                'misses': total_cache_misses,
                'hit_rate': (total_cache_hits / (total_cache_hits + total_cache_misses) * 100) 
                           if (total_cache_hits + total_cache_misses) else 0
            },
            'endpoints': dict(endpoint_stats)
        }
    
    def _calculate_system_stats(self, metrics: List[SystemMetrics]) -> Dict[str, Any]:
        """Calculate system statistics"""
        
        if not metrics:
            return {}
        
        latest = metrics[-1] if metrics else None
        
        cpu_values = [m.cpu_percent for m in metrics]
        memory_values = [m.memory_percent for m in metrics]
        
        return {
            'cpu': {
                'current': latest.cpu_percent if latest else 0,
                'mean': statistics.mean(cpu_values) if cpu_values else 0,
                'max': max(cpu_values) if cpu_values else 0
            },
            'memory': {
                'current_percent': latest.memory_percent if latest else 0,
                'current_used_mb': latest.memory_used_mb if latest else 0,
                'mean_percent': statistics.mean(memory_values) if memory_values else 0,
                'max_percent': max(memory_values) if memory_values else 0
            },
            'disk': {
                'usage_percent': latest.disk_usage_percent if latest else 0,
                'io_read_mb': sum(m.disk_io_read_mb for m in metrics),
                'io_write_mb': sum(m.disk_io_write_mb for m in metrics)
            },
            'network': {
                'sent_mb': sum(m.network_sent_mb for m in metrics),
                'recv_mb': sum(m.network_recv_mb for m in metrics)
            },
            'connections': latest.open_connections if latest else 0,
            'threads': latest.thread_count if latest else 0,
            'processes': latest.process_count if latest else 0
        }
    
    def _percentile(self, values: List[float], percentile: float) -> float:
        """Calculate percentile value"""
        if not values:
            return 0
        
        sorted_values = sorted(values)
        index = int(len(sorted_values) * percentile / 100)
        
        if index >= len(sorted_values):
            return sorted_values[-1]
        
        return sorted_values[index]

class PerformanceMonitor:
    """Main performance monitoring service"""
    
    def __init__(self):
        self.collector = MetricsCollector()
        self.current_requests: Dict[str, RequestMetrics] = {}
        self._monitoring_thread = None
        self._running = False
        self._monitors: List[Callable] = []
        
        # System metrics baseline
        self._baseline_stats = None
        self._collect_baseline()
    
    def _collect_baseline(self):
        """Collect baseline system metrics"""
        try:
            process = psutil.Process()
            
            self._baseline_stats = {
                'cpu_count': psutil.cpu_count(),
                'memory_total_mb': psutil.virtual_memory().total / 1024 / 1024,
                'disk_total_gb': psutil.disk_usage('/').total / 1024 / 1024 / 1024,
                'process_create_time': process.create_time()
            }
        except Exception as e:
            logger.error(f"Failed to collect baseline stats: {e}")
    
    def start_monitoring(self, interval: int = 10):
        """Start system monitoring"""
        if self._running:
            return
        
        self._running = True
        self._monitoring_thread = threading.Thread(
            target=self._monitor_system,
            args=(interval,)
        )
        self._monitoring_thread.daemon = True
        self._monitoring_thread.start()
        
        logger.info("Performance monitoring started")
    
    def stop_monitoring(self):
        """Stop system monitoring"""
        self._running = False
        if self._monitoring_thread:
            self._monitoring_thread.join()
        
        logger.info("Performance monitoring stopped")
    
    def _monitor_system(self, interval: int):
        """Monitor system metrics periodically"""
        
        # Initialize previous values for delta calculations
        prev_disk_io = psutil.disk_io_counters()
        prev_net_io = psutil.net_io_counters()
        prev_time = time.time()
        
        while self._running:
            try:
                # Collect system metrics
                current_time = time.time()
                time_delta = current_time - prev_time
                
                # CPU and Memory
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                
                # Disk
                disk_usage = psutil.disk_usage('/')
                disk_io = psutil.disk_io_counters()
                
                # Network
                net_io = psutil.net_io_counters()
                
                # Process specific
                process = psutil.Process()
                
                # Calculate deltas
                disk_read_mb = (disk_io.read_bytes - prev_disk_io.read_bytes) / 1024 / 1024 / time_delta
                disk_write_mb = (disk_io.write_bytes - prev_disk_io.write_bytes) / 1024 / 1024 / time_delta
                net_sent_mb = (net_io.bytes_sent - prev_net_io.bytes_sent) / 1024 / 1024 / time_delta
                net_recv_mb = (net_io.bytes_recv - prev_net_io.bytes_recv) / 1024 / 1024 / time_delta
                
                # Create system metrics
                metrics = SystemMetrics(
                    timestamp=datetime.utcnow(),
                    cpu_percent=cpu_percent,
                    memory_percent=memory.percent,
                    memory_used_mb=memory.used / 1024 / 1024,
                    memory_available_mb=memory.available / 1024 / 1024,
                    disk_usage_percent=disk_usage.percent,
                    disk_io_read_mb=max(0, disk_read_mb),
                    disk_io_write_mb=max(0, disk_write_mb),
                    network_sent_mb=max(0, net_sent_mb),
                    network_recv_mb=max(0, net_recv_mb),
                    open_connections=len(process.connections()),
                    thread_count=process.num_threads(),
                    process_count=len(psutil.pids())
                )
                
                self.collector.record_system(metrics)
                
                # Update previous values
                prev_disk_io = disk_io
                prev_net_io = net_io
                prev_time = current_time
                
                # Run custom monitors
                for monitor in self._monitors:
                    try:
                        monitor(self)
                    except Exception as e:
                        logger.error(f"Custom monitor error: {e}")
                
                # Sleep for remaining interval
                elapsed = time.time() - current_time
                sleep_time = max(0, interval - elapsed)
                time.sleep(sleep_time)
                
            except Exception as e:
                logger.error(f"System monitoring error: {e}")
                time.sleep(interval)
    
    @contextmanager
    def track_request(self, endpoint: str, method: str = "GET") -> RequestMetrics:
        """Context manager to track request performance"""
        
        request_id = str(time.time())
        request = RequestMetrics(
            request_id=request_id,
            endpoint=endpoint,
            method=method,
            start_time=datetime.utcnow()
        )
        
        self.current_requests[request_id] = request
        
        # Track initial resource usage
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024
        
        try:
            yield request
            
        except Exception as e:
            request.error = str(e)
            raise
            
        finally:
            # Calculate duration
            request.end_time = datetime.utcnow()
            request.duration_ms = (request.end_time - request.start_time).total_seconds() * 1000
            
            # Calculate resource usage
            final_memory = process.memory_info().rss / 1024 / 1024
            request.memory_used_mb = final_memory - initial_memory
            request.cpu_percent = process.cpu_percent()
            
            # Record metrics
            self.collector.record_request(request)
            
            # Clean up
            del self.current_requests[request_id]
    
    def track_function(self, name: str = None, tags: Dict[str, str] = None):
        """Decorator to track function performance"""
        
        def decorator(func):
            func_name = name or f"{func.__module__}.{func.__name__}"
            
            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                start_time = time.time()
                
                try:
                    result = func(*args, **kwargs)
                    
                    # Record success metric
                    duration_ms = (time.time() - start_time) * 1000
                    self.record_metric(
                        name=f"function.{func_name}.duration",
                        value=duration_ms,
                        unit="ms",
                        tags={**(tags or {}), 'status': 'success'}
                    )
                    
                    return result
                    
                except Exception as e:
                    # Record error metric
                    duration_ms = (time.time() - start_time) * 1000
                    self.record_metric(
                        name=f"function.{func_name}.duration",
                        value=duration_ms,
                        unit="ms",
                        tags={**(tags or {}), 'status': 'error', 'error': type(e).__name__}
                    )
                    raise
            
            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                start_time = time.time()
                
                try:
                    result = await func(*args, **kwargs)
                    
                    # Record success metric
                    duration_ms = (time.time() - start_time) * 1000
                    self.record_metric(
                        name=f"function.{func_name}.duration",
                        value=duration_ms,
                        unit="ms",
                        tags={**(tags or {}), 'status': 'success'}
                    )
                    
                    return result
                    
                except Exception as e:
                    # Record error metric
                    duration_ms = (time.time() - start_time) * 1000
                    self.record_metric(
                        name=f"function.{func_name}.duration",
                        value=duration_ms,
                        unit="ms",
                        tags={**(tags or {}), 'status': 'error', 'error': type(e).__name__}
                    )
                    raise
            
            # Return appropriate wrapper
            if asyncio.iscoroutinefunction(func):
                return async_wrapper
            else:
                return sync_wrapper
        
        return decorator
    
    def record_metric(self, name: str, value: float, unit: str = "count",
                     tags: Dict[str, str] = None, metadata: Dict[str, Any] = None):
        """Record a custom metric"""
        
        metric = PerformanceMetric(
            name=name,
            value=value,
            unit=unit,
            timestamp=datetime.utcnow(),
            tags=tags or {},
            metadata=metadata or {}
        )
        
        self.collector.record_metric(metric)
    
    def track_db_query(self, request_id: str, duration_ms: float):
        """Track database query for current request"""
        
        if request_id in self.current_requests:
            request = self.current_requests[request_id]
            request.db_queries += 1
            request.db_time_ms += duration_ms
    
    def track_cache_access(self, request_id: str, hit: bool):
        """Track cache access for current request"""
        
        if request_id in self.current_requests:
            request = self.current_requests[request_id]
            if hit:
                request.cache_hits += 1
            else:
                request.cache_misses += 1
    
    def track_external_api(self, request_id: str, duration_ms: float):
        """Track external API call for current request"""
        
        if request_id in self.current_requests:
            request = self.current_requests[request_id]
            request.external_api_calls += 1
            request.external_api_time_ms += duration_ms
    
    def add_monitor(self, monitor_func: Callable):
        """Add custom monitor function"""
        self._monitors.append(monitor_func)
    
    def get_stats(self, metric_name: str = None, 
                  time_range: int = None) -> Dict[str, Any]:
        """Get performance statistics"""
        return self.collector.get_stats(metric_name, time_range)
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get overall health status"""
        
        stats = self.get_stats(time_range=300)  # Last 5 minutes
        
        # Define health thresholds
        thresholds = {
            'cpu_percent': 80,
            'memory_percent': 85,
            'error_rate': 5,
            'response_time_p95': 1000,  # 1 second
            'db_avg_time': 100  # 100ms
        }
        
        # Check health conditions
        issues = []
        
        if stats.get('system', {}).get('cpu', {}).get('mean', 0) > thresholds['cpu_percent']:
            issues.append(f"High CPU usage: {stats['system']['cpu']['mean']:.1f}%")
        
        if stats.get('system', {}).get('memory', {}).get('mean_percent', 0) > thresholds['memory_percent']:
            issues.append(f"High memory usage: {stats['system']['memory']['mean_percent']:.1f}%")
        
        if stats.get('requests', {}).get('error_rate', 0) > thresholds['error_rate']:
            issues.append(f"High error rate: {stats['requests']['error_rate']:.1f}%")
        
        if stats.get('requests', {}).get('response_times', {}).get('p95', 0) > thresholds['response_time_p95']:
            issues.append(f"Slow response times: p95={stats['requests']['response_times']['p95']:.0f}ms")
        
        if stats.get('requests', {}).get('database', {}).get('avg_time_ms', 0) > thresholds['db_avg_time']:
            issues.append(f"Slow database queries: {stats['requests']['database']['avg_time_ms']:.0f}ms")
        
        # Determine overall status
        if not issues:
            status = 'healthy'
        elif len(issues) <= 2:
            status = 'degraded'
        else:
            status = 'unhealthy'
        
        return {
            'status': status,
            'issues': issues,
            'stats': stats,
            'baseline': self._baseline_stats,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def export_metrics(self, format: str = 'json') -> str:
        """Export metrics in various formats"""
        
        if format == 'json':
            data = {
                'stats': self.get_stats(),
                'health': self.get_health_status(),
                'timestamp': datetime.utcnow().isoformat()
            }
            return json.dumps(data, indent=2, default=str)
        
        elif format == 'prometheus':
            # Prometheus text format
            lines = []
            stats = self.get_stats()
            
            # Request metrics
            if 'requests' in stats:
                req_stats = stats['requests']
                lines.append(f"# HELP http_requests_total Total HTTP requests")
                lines.append(f"# TYPE http_requests_total counter")
                lines.append(f"http_requests_total {req_stats.get('total', 0)}")
                
                lines.append(f"# HELP http_request_duration_seconds HTTP request duration")
                lines.append(f"# TYPE http_request_duration_seconds histogram")
                
                for percentile, value in req_stats.get('response_times', {}).items():
                    if percentile.startswith('p'):
                        quantile = int(percentile[1:]) / 100
                        lines.append(f'http_request_duration_seconds{{quantile="{quantile}"}} {value/1000}')
            
            # System metrics
            if 'system' in stats:
                sys_stats = stats['system']
                lines.append(f"# HELP cpu_usage_percent CPU usage percentage")
                lines.append(f"# TYPE cpu_usage_percent gauge")
                lines.append(f"cpu_usage_percent {sys_stats.get('cpu', {}).get('current', 0)}")
                
                lines.append(f"# HELP memory_usage_percent Memory usage percentage")
                lines.append(f"# TYPE memory_usage_percent gauge")
                lines.append(f"memory_usage_percent {sys_stats.get('memory', {}).get('current_percent', 0)}")
            
            return '\n'.join(lines)
        
        else:
            raise ValueError(f"Unsupported format: {format}")

# Global performance monitor instance
_monitor: Optional[PerformanceMonitor] = None

def get_performance_monitor() -> PerformanceMonitor:
    """Get global performance monitor instance"""
    global _monitor
    if _monitor is None:
        _monitor = PerformanceMonitor()
        _monitor.start_monitoring()
    return _monitor

def init_performance_monitor() -> PerformanceMonitor:
    """Initialize global performance monitor"""
    global _monitor
    _monitor = PerformanceMonitor()
    _monitor.start_monitoring()
    return _monitor