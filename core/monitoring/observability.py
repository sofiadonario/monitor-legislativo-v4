"""Production monitoring and observability stack."""

import logging
import time
import threading
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import json
import psutil
import os
from functools import wraps

try:
    import prometheus_client
    from prometheus_client import Counter, Histogram, Gauge, Summary
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False


@dataclass
class HealthStatus:
    """Service health status."""
    service_name: str
    status: str  # 'healthy', 'degraded', 'unhealthy'
    timestamp: str
    response_time_ms: float
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = None


@dataclass
class MetricPoint:
    """Single metric measurement."""
    name: str
    value: float
    timestamp: str
    labels: Dict[str, str] = None
    unit: str = ""


@dataclass
class Alert:
    """System alert."""
    id: str
    severity: str  # 'critical', 'warning', 'info'
    message: str
    source: str
    timestamp: str
    resolved: bool = False
    metadata: Dict[str, Any] = None


class ObservabilityManager:
    """Central observability and monitoring manager."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Health tracking
        self.health_checks: Dict[str, Callable] = {}
        self.health_status: Dict[str, HealthStatus] = {}
        
        # Metrics
        self.metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.metric_callbacks: Dict[str, Callable] = {}
        
        # Alerts
        self.alerts: List[Alert] = []
        self.alert_callbacks: List[Callable] = []
        
        # Performance tracking
        self.request_durations: deque = deque(maxlen=1000)
        self.error_counts: defaultdict = defaultdict(int)
        
        # System metrics
        self.system_metrics_enabled = True
        self.custom_metrics: Dict[str, Any] = {}
        
        # Prometheus metrics (if available)
        if PROMETHEUS_AVAILABLE:
            self._setup_prometheus_metrics()
        
        # Background tasks
        self._monitoring_thread = None
        self._running = False
    
    def _setup_prometheus_metrics(self):
        """Setup Prometheus metrics."""
        self.prom_request_counter = Counter(
            'monitor_legislativo_requests_total',
            'Total number of requests',
            ['method', 'endpoint', 'status']
        )
        
        self.prom_request_duration = Histogram(
            'monitor_legislativo_request_duration_seconds',
            'Request duration in seconds',
            ['method', 'endpoint']
        )
        
        self.prom_error_counter = Counter(
            'monitor_legislativo_errors_total',
            'Total number of errors',
            ['error_type', 'service']
        )
        
        self.prom_system_cpu = Gauge(
            'monitor_legislativo_system_cpu_percent',
            'System CPU usage percentage'
        )
        
        self.prom_system_memory = Gauge(
            'monitor_legislativo_system_memory_percent',
            'System memory usage percentage'
        )
        
        self.prom_active_users = Gauge(
            'monitor_legislativo_active_users',
            'Number of active users'
        )
        
        self.prom_documents_processed = Counter(
            'monitor_legislativo_documents_processed_total',
            'Total documents processed',
            ['source', 'status']
        )
    
    def start_monitoring(self):
        """Start background monitoring."""
        if self._running:
            return
        
        self._running = True
        self._monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self._monitoring_thread.start()
        
        self.logger.info("Observability monitoring started")
    
    def stop_monitoring(self):
        """Stop background monitoring."""
        self._running = False
        if self._monitoring_thread:
            self._monitoring_thread.join(timeout=5)
        
        self.logger.info("Observability monitoring stopped")
    
    def _monitoring_loop(self):
        """Background monitoring loop."""
        while self._running:
            try:
                # Collect system metrics
                self._collect_system_metrics()
                
                # Run health checks
                self._run_health_checks()
                
                # Check for alerts
                self._check_alert_conditions()
                
                # Clean old data
                self._cleanup_old_data()
                
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(60)  # Wait longer on error
    
    def register_health_check(self, service_name: str, check_func: Callable[[], bool]):
        """Register a health check function."""
        self.health_checks[service_name] = check_func
        self.logger.info(f"Registered health check for {service_name}")
    
    def record_metric(self, name: str, value: float, labels: Dict[str, str] = None, unit: str = ""):
        """Record a custom metric."""
        metric_point = MetricPoint(
            name=name,
            value=value,
            timestamp=datetime.now().isoformat(),
            labels=labels or {},
            unit=unit
        )
        
        self.metrics[name].append(metric_point)
        
        # Update Prometheus if available
        if PROMETHEUS_AVAILABLE and hasattr(self, f'prom_{name}'):
            prom_metric = getattr(self, f'prom_{name}')
            if labels:
                prom_metric.labels(**labels).set(value)
            else:
                prom_metric.set(value)
    
    def record_request(self, method: str, endpoint: str, status_code: int, duration: float):
        """Record HTTP request metrics."""
        # Store duration
        self.request_durations.append(duration)
        
        # Count by status
        status_category = f"{status_code // 100}xx"
        self.record_metric(f"requests_{status_category}", 1, 
                          labels={'method': method, 'endpoint': endpoint})
        
        # Record duration
        self.record_metric("request_duration", duration,
                          labels={'method': method, 'endpoint': endpoint}, unit="seconds")
        
        # Update Prometheus
        if PROMETHEUS_AVAILABLE:
            self.prom_request_counter.labels(
                method=method, endpoint=endpoint, status=status_code
            ).inc()
            
            self.prom_request_duration.labels(
                method=method, endpoint=endpoint
            ).observe(duration)
    
    def record_error(self, error_type: str, service: str, error_message: str = ""):
        """Record an error occurrence."""
        self.error_counts[f"{service}:{error_type}"] += 1
        
        # Record metric
        self.record_metric("errors", 1, labels={'error_type': error_type, 'service': service})
        
        # Update Prometheus
        if PROMETHEUS_AVAILABLE:
            self.prom_error_counter.labels(error_type=error_type, service=service).inc()
        
        # Create alert if error rate is high
        error_rate = self._calculate_error_rate(service)
        if error_rate > 0.1:  # 10% error rate threshold
            self.create_alert(
                severity='warning',
                message=f"High error rate in {service}: {error_rate:.2%}",
                source='error_monitoring',
                metadata={'error_type': error_type, 'error_message': error_message}
            )
    
    def record_document_processed(self, source: str, status: str):
        """Record document processing metrics."""
        self.record_metric("documents_processed", 1, 
                          labels={'source': source, 'status': status})
        
        if PROMETHEUS_AVAILABLE:
            self.prom_documents_processed.labels(source=source, status=status).inc()
    
    def create_alert(self, severity: str, message: str, source: str, metadata: Dict[str, Any] = None):
        """Create a system alert."""
        alert = Alert(
            id=f"alert_{int(time.time())}_{len(self.alerts)}",
            severity=severity,
            message=message,
            source=source,
            timestamp=datetime.now().isoformat(),
            metadata=metadata or {}
        )
        
        self.alerts.append(alert)
        
        # Trigger callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                self.logger.error(f"Error in alert callback: {e}")
        
        self.logger.warning(f"Alert created: {alert.severity} - {alert.message}")
    
    def add_alert_callback(self, callback: Callable[[Alert], None]):
        """Add callback for alert notifications."""
        self.alert_callbacks.append(callback)
    
    def get_health_status(self, service_name: str = None) -> Dict[str, HealthStatus]:
        """Get health status for services."""
        if service_name:
            return {service_name: self.health_status.get(service_name)}
        return self.health_status.copy()
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get metrics summary."""
        summary = {
            'system': self._get_system_metrics_summary(),
            'requests': self._get_request_metrics_summary(),
            'errors': self._get_error_metrics_summary(),
            'custom': self._get_custom_metrics_summary()
        }
        return summary
    
    def get_active_alerts(self, severity: str = None) -> List[Alert]:
        """Get active alerts."""
        active_alerts = [alert for alert in self.alerts if not alert.resolved]
        
        if severity:
            active_alerts = [alert for alert in active_alerts if alert.severity == severity]
        
        return sorted(active_alerts, key=lambda x: x.timestamp, reverse=True)
    
    def resolve_alert(self, alert_id: str) -> bool:
        """Resolve an alert."""
        for alert in self.alerts:
            if alert.id == alert_id:
                alert.resolved = True
                self.logger.info(f"Alert resolved: {alert_id}")
                return True
        return False
    
    def _collect_system_metrics(self):
        """Collect system metrics."""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            self.record_metric("system_cpu_percent", cpu_percent, unit="percent")
            if PROMETHEUS_AVAILABLE:
                self.prom_system_cpu.set(cpu_percent)
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            self.record_metric("system_memory_percent", memory_percent, unit="percent")
            self.record_metric("system_memory_available", memory.available, unit="bytes")
            if PROMETHEUS_AVAILABLE:
                self.prom_system_memory.set(memory_percent)
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            self.record_metric("system_disk_percent", disk_percent, unit="percent")
            
            # Network I/O
            network = psutil.net_io_counters()
            self.record_metric("network_bytes_sent", network.bytes_sent, unit="bytes")
            self.record_metric("network_bytes_recv", network.bytes_recv, unit="bytes")
            
            # Process info
            process = psutil.Process(os.getpid())
            self.record_metric("process_memory_rss", process.memory_info().rss, unit="bytes")
            self.record_metric("process_cpu_percent", process.cpu_percent(), unit="percent")
            
        except Exception as e:
            self.logger.error(f"Error collecting system metrics: {e}")
    
    def _run_health_checks(self):
        """Run all registered health checks."""
        for service_name, check_func in self.health_checks.items():
            try:
                start_time = time.time()
                is_healthy = check_func()
                response_time = (time.time() - start_time) * 1000
                
                status = 'healthy' if is_healthy else 'unhealthy'
                
                health_status = HealthStatus(
                    service_name=service_name,
                    status=status,
                    timestamp=datetime.now().isoformat(),
                    response_time_ms=response_time
                )
                
                self.health_status[service_name] = health_status
                
                # Create alert if service is unhealthy
                if not is_healthy:
                    self.create_alert(
                        severity='critical',
                        message=f"Service {service_name} is unhealthy",
                        source='health_check',
                        metadata={'response_time_ms': response_time}
                    )
                
            except Exception as e:
                error_msg = str(e)
                self.health_status[service_name] = HealthStatus(
                    service_name=service_name,
                    status='unhealthy',
                    timestamp=datetime.now().isoformat(),
                    response_time_ms=0,
                    error_message=error_msg
                )
                
                self.create_alert(
                    severity='critical',
                    message=f"Health check failed for {service_name}: {error_msg}",
                    source='health_check'
                )
    
    def _check_alert_conditions(self):
        """Check for alert conditions."""
        # High CPU usage
        cpu_metrics = [m for m in self.metrics.get('system_cpu_percent', []) if m]
        if cpu_metrics and len(cpu_metrics) >= 3:
            recent_cpu = [m.value for m in cpu_metrics[-3:]]
            avg_cpu = sum(recent_cpu) / len(recent_cpu)
            
            if avg_cpu > 80:
                self.create_alert(
                    severity='warning',
                    message=f"High CPU usage: {avg_cpu:.1f}%",
                    source='system_monitoring'
                )
        
        # High memory usage
        memory_metrics = [m for m in self.metrics.get('system_memory_percent', []) if m]
        if memory_metrics and len(memory_metrics) >= 3:
            recent_memory = [m.value for m in memory_metrics[-3:]]
            avg_memory = sum(recent_memory) / len(recent_memory)
            
            if avg_memory > 85:
                self.create_alert(
                    severity='warning',
                    message=f"High memory usage: {avg_memory:.1f}%",
                    source='system_monitoring'
                )
        
        # High error rate
        if len(self.request_durations) > 10:
            error_rate = self._calculate_overall_error_rate()
            if error_rate > 0.05:  # 5% error rate
                self.create_alert(
                    severity='warning',
                    message=f"High error rate: {error_rate:.2%}",
                    source='error_monitoring'
                )
    
    def _calculate_error_rate(self, service: str) -> float:
        """Calculate error rate for a service."""
        # This is a simplified calculation
        # In production, you'd want more sophisticated error rate calculation
        total_errors = sum(count for key, count in self.error_counts.items() 
                          if key.startswith(f"{service}:"))
        total_requests = len(self.request_durations)
        
        if total_requests == 0:
            return 0.0
        
        return total_errors / total_requests
    
    def _calculate_overall_error_rate(self) -> float:
        """Calculate overall error rate."""
        total_errors = sum(self.error_counts.values())
        total_requests = len(self.request_durations)
        
        if total_requests == 0:
            return 0.0
        
        return total_errors / total_requests
    
    def _cleanup_old_data(self):
        """Clean up old monitoring data."""
        # Remove old alerts (keep last 1000)
        if len(self.alerts) > 1000:
            self.alerts = self.alerts[-1000:]
        
        # Clear old error counts (keep last hour worth)
        # This is simplified - in production you'd want time-based cleanup
        if len(self.error_counts) > 100:
            # Keep only the most recent error types
            sorted_errors = sorted(self.error_counts.items(), key=lambda x: x[1], reverse=True)
            self.error_counts = defaultdict(int, dict(sorted_errors[:100]))
    
    def _get_system_metrics_summary(self) -> Dict[str, Any]:
        """Get system metrics summary."""
        summary = {}
        
        for metric_name in ['system_cpu_percent', 'system_memory_percent', 'system_disk_percent']:
            metrics = list(self.metrics.get(metric_name, []))
            if metrics:
                values = [m.value for m in metrics[-10:]]  # Last 10 readings
                summary[metric_name] = {
                    'current': values[-1] if values else 0,
                    'average': sum(values) / len(values),
                    'max': max(values),
                    'min': min(values)
                }
        
        return summary
    
    def _get_request_metrics_summary(self) -> Dict[str, Any]:
        """Get request metrics summary."""
        if not self.request_durations:
            return {}
        
        durations = list(self.request_durations)
        return {
            'total_requests': len(durations),
            'avg_response_time': sum(durations) / len(durations),
            'max_response_time': max(durations),
            'min_response_time': min(durations),
            'p95_response_time': sorted(durations)[int(len(durations) * 0.95)] if durations else 0,
            'p99_response_time': sorted(durations)[int(len(durations) * 0.99)] if durations else 0
        }
    
    def _get_error_metrics_summary(self) -> Dict[str, Any]:
        """Get error metrics summary."""
        total_errors = sum(self.error_counts.values())
        total_requests = len(self.request_durations)
        
        return {
            'total_errors': total_errors,
            'error_rate': total_errors / total_requests if total_requests > 0 else 0,
            'error_breakdown': dict(self.error_counts)
        }
    
    def _get_custom_metrics_summary(self) -> Dict[str, Any]:
        """Get custom metrics summary."""
        summary = {}
        
        for metric_name, metric_points in self.metrics.items():
            if metric_name.startswith('system_') or metric_name in ['requests_', 'request_duration', 'errors']:
                continue  # Skip system metrics
            
            if metric_points:
                recent_points = list(metric_points)[-10:]  # Last 10 points
                values = [p.value for p in recent_points]
                
                summary[metric_name] = {
                    'current': values[-1] if values else 0,
                    'count': len(recent_points),
                    'sum': sum(values),
                    'average': sum(values) / len(values) if values else 0
                }
        
        return summary


# Global observability manager instance
observability = ObservabilityManager()


def monitor_function(func_name: str = None):
    """Decorator to monitor function execution."""
    def decorator(func):
        name = func_name or func.__name__
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                observability.record_metric(f"function_{name}_duration", duration, unit="seconds")
                observability.record_metric(f"function_{name}_calls", 1)
                return result
            except Exception as e:
                duration = time.time() - start_time
                observability.record_error('function_error', name, str(e))
                observability.record_metric(f"function_{name}_duration", duration, unit="seconds")
                observability.record_metric(f"function_{name}_errors", 1)
                raise
        
        return wrapper
    return decorator


def monitor_request(func):
    """Decorator to monitor HTTP requests."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        method = getattr(args[0] if args else None, 'method', 'UNKNOWN')
        endpoint = getattr(args[0] if args else None, 'endpoint', 'unknown')
        
        try:
            result = func(*args, **kwargs)
            duration = time.time() - start_time
            
            # Extract status code from result
            status_code = 200
            if hasattr(result, 'status_code'):
                status_code = result.status_code
            elif isinstance(result, tuple) and len(result) > 1:
                status_code = result[1]
            
            observability.record_request(method, endpoint, status_code, duration)
            return result
            
        except Exception as e:
            duration = time.time() - start_time
            observability.record_request(method, endpoint, 500, duration)
            observability.record_error('request_error', 'web', str(e))
            raise
    
    return wrapper