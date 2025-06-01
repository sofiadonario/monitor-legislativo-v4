"""
Enhanced Health Check System
Implements comprehensive monitoring as specified in technical recommendations
"""

import asyncio
import time
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from enum import Enum

from .circuit_breaker import circuit_manager
from .smart_cache import smart_cache
from .session_factory import SessionFactory


class HealthStatus(Enum):
    """Health status levels"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class HealthCheckResult:
    """Result of a health check"""
    component: str
    status: HealthStatus
    response_time_ms: float
    message: str
    timestamp: datetime
    details: Dict[str, Any] = None
    
    def to_dict(self) -> dict:
        return {
            'component': self.component,
            'status': self.status.value,
            'response_time_ms': self.response_time_ms,
            'message': self.message,
            'timestamp': self.timestamp.isoformat(),
            'details': self.details or {}
        }


@dataclass
class SystemHealth:
    """Overall system health summary"""
    status: HealthStatus
    overall_response_time_ms: float
    checks: List[HealthCheckResult]
    timestamp: datetime
    uptime_seconds: float
    
    def to_dict(self) -> dict:
        return {
            'status': self.status.value,
            'overall_response_time_ms': self.overall_response_time_ms,
            'checks': [check.to_dict() for check in self.checks],
            'timestamp': self.timestamp.isoformat(),
            'uptime_seconds': self.uptime_seconds,
            'summary': {
                'total_checks': len(self.checks),
                'healthy': len([c for c in self.checks if c.status == HealthStatus.HEALTHY]),
                'degraded': len([c for c in self.checks if c.status == HealthStatus.DEGRADED]),
                'unhealthy': len([c for c in self.checks if c.status == HealthStatus.UNHEALTHY])
            }
        }


class HealthMonitor:
    """
    Advanced health monitoring system with:
    - Component-specific health checks
    - Circuit breaker integration
    - Performance metrics tracking
    - Automatic alerting capabilities
    - Historical health data
    """
    
    def __init__(self, check_interval: int = 300):  # 5 minutes default
        self.check_interval = check_interval
        self.logger = logging.getLogger(__name__)
        self.start_time = time.time()
        
        # Health check registry
        self._health_checks: Dict[str, Callable] = {}
        self._last_results: Dict[str, HealthCheckResult] = {}
        self._health_history: List[SystemHealth] = []
        self._running = False
        self._monitor_task: Optional[asyncio.Task] = None
        
        # Alert configuration
        self._alert_threshold = 3  # Consecutive failures before alert
        self._consecutive_failures: Dict[str, int] = {}
        self._alert_callbacks: List[Callable] = []
        
        # Register default health checks
        self._register_default_checks()
    
    def register_health_check(self, name: str, check_func: Callable) -> None:
        """Register a health check function"""
        self._health_checks[name] = check_func
        self.logger.info(f"Registered health check: {name}")
    
    def register_alert_callback(self, callback: Callable) -> None:
        """Register callback for health alerts"""
        self._alert_callbacks.append(callback)
    
    async def start_monitoring(self) -> None:
        """Start continuous health monitoring"""
        if self._running:
            return
        
        self._running = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        self.logger.info("Health monitoring started")
    
    async def stop_monitoring(self) -> None:
        """Stop health monitoring"""
        self._running = False
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        self.logger.info("Health monitoring stopped")
    
    async def check_all_health(self) -> SystemHealth:
        """Perform all health checks and return system health"""
        start_time = time.time()
        checks = []
        
        # Run all registered health checks
        for name, check_func in self._health_checks.items():
            try:
                result = await self._run_health_check(name, check_func)
                checks.append(result)
                self._last_results[name] = result
                
                # Track consecutive failures for alerting
                if result.status == HealthStatus.UNHEALTHY:
                    self._consecutive_failures[name] = self._consecutive_failures.get(name, 0) + 1
                    
                    # Trigger alert if threshold reached
                    if self._consecutive_failures[name] >= self._alert_threshold:
                        await self._trigger_alert(name, result)
                else:
                    self._consecutive_failures[name] = 0
                    
            except Exception as e:
                self.logger.error(f"Health check {name} failed with exception: {e}")
                result = HealthCheckResult(
                    component=name,
                    status=HealthStatus.UNHEALTHY,
                    response_time_ms=0,
                    message=f"Check failed: {str(e)}",
                    timestamp=datetime.now()
                )
                checks.append(result)
        
        # Calculate overall health
        overall_time = (time.time() - start_time) * 1000
        overall_status = self._calculate_overall_status(checks)
        
        system_health = SystemHealth(
            status=overall_status,
            overall_response_time_ms=overall_time,
            checks=checks,
            timestamp=datetime.now(),
            uptime_seconds=time.time() - self.start_time
        )
        
        # Store in history (keep last 100 entries)
        self._health_history.append(system_health)
        if len(self._health_history) > 100:
            self._health_history.pop(0)
        
        return system_health
    
    async def check_component_health(self, component: str) -> Optional[HealthCheckResult]:
        """Check health of specific component"""
        if component not in self._health_checks:
            return None
        
        check_func = self._health_checks[component]
        return await self._run_health_check(component, check_func)
    
    def get_health_history(self, hours: int = 24) -> List[SystemHealth]:
        """Get health history for specified hours"""
        cutoff = datetime.now() - timedelta(hours=hours)
        return [h for h in self._health_history if h.timestamp >= cutoff]
    
    def get_component_status(self, component: str) -> Optional[HealthCheckResult]:
        """Get last known status of component"""
        return self._last_results.get(component)
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get health metrics summary"""
        if not self._health_history:
            return {}
        
        recent_checks = self.get_health_history(1)  # Last hour
        
        metrics = {
            'uptime_seconds': time.time() - self.start_time,
            'total_checks_run': len(self._health_history),
            'last_check': self._health_history[-1].timestamp.isoformat() if self._health_history else None,
            'recent_availability': self._calculate_availability(recent_checks),
            'average_response_time_ms': self._calculate_avg_response_time(recent_checks),
            'component_status': {name: result.status.value for name, result in self._last_results.items()}
        }
        
        return metrics
    
    async def _monitor_loop(self) -> None:
        """Main monitoring loop"""
        while self._running:
            try:
                await self.check_all_health()
                await asyncio.sleep(self.check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(30)  # Wait before retrying
    
    async def _run_health_check(self, name: str, check_func: Callable) -> HealthCheckResult:
        """Run individual health check with timing"""
        start_time = time.time()
        
        try:
            if asyncio.iscoroutinefunction(check_func):
                result = await check_func()
            else:
                result = check_func()
            
            response_time = (time.time() - start_time) * 1000
            
            # Parse result based on type
            if isinstance(result, dict):
                status = HealthStatus(result.get('status', 'unknown'))
                message = result.get('message', 'OK')
                details = result.get('details', {})
            elif isinstance(result, bool):
                status = HealthStatus.HEALTHY if result else HealthStatus.UNHEALTHY
                message = 'OK' if result else 'Check failed'
                details = {}
            else:
                status = HealthStatus.HEALTHY
                message = str(result)
                details = {}
            
            return HealthCheckResult(
                component=name,
                status=status,
                response_time_ms=response_time,
                message=message,
                timestamp=datetime.now(),
                details=details
            )
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return HealthCheckResult(
                component=name,
                status=HealthStatus.UNHEALTHY,
                response_time_ms=response_time,
                message=f"Check failed: {str(e)}",
                timestamp=datetime.now()
            )
    
    def _calculate_overall_status(self, checks: List[HealthCheckResult]) -> HealthStatus:
        """Calculate overall system status from component checks"""
        if not checks:
            return HealthStatus.UNKNOWN
        
        unhealthy_count = len([c for c in checks if c.status == HealthStatus.UNHEALTHY])
        degraded_count = len([c for c in checks if c.status == HealthStatus.DEGRADED])
        
        # If more than 50% unhealthy, system is unhealthy
        if unhealthy_count > len(checks) * 0.5:
            return HealthStatus.UNHEALTHY
        
        # If any unhealthy or more than 30% degraded, system is degraded
        if unhealthy_count > 0 or degraded_count > len(checks) * 0.3:
            return HealthStatus.DEGRADED
        
        return HealthStatus.HEALTHY
    
    def _calculate_availability(self, checks: List[SystemHealth]) -> float:
        """Calculate availability percentage"""
        if not checks:
            return 0.0
        
        healthy_count = len([c for c in checks if c.status in [HealthStatus.HEALTHY, HealthStatus.DEGRADED]])
        return (healthy_count / len(checks)) * 100
    
    def _calculate_avg_response_time(self, checks: List[SystemHealth]) -> float:
        """Calculate average response time"""
        if not checks:
            return 0.0
        
        total_time = sum(c.overall_response_time_ms for c in checks)
        return total_time / len(checks)
    
    async def _trigger_alert(self, component: str, result: HealthCheckResult) -> None:
        """Trigger alert for component failure"""
        alert_data = {
            'component': component,
            'status': result.status.value,
            'message': result.message,
            'consecutive_failures': self._consecutive_failures[component],
            'timestamp': result.timestamp.isoformat()
        }
        
        self.logger.warning(f"ALERT: {component} is {result.status.value} - {result.message}")
        
        # Call registered alert callbacks
        for callback in self._alert_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(alert_data)
                else:
                    callback(alert_data)
            except Exception as e:
                self.logger.error(f"Alert callback failed: {e}")
    
    def _register_default_checks(self) -> None:
        """Register default system health checks"""
        
        async def cache_health():
            """Check cache system health"""
            return await smart_cache.health_check()
        
        async def circuit_breaker_health():
            """Check circuit breaker status"""
            stats = circuit_manager.get_all_stats()
            failing_breakers = [name for name, stat in stats.items() 
                              if stat['state'] == 'open']
            
            if failing_breakers:
                return {
                    'status': 'degraded',
                    'message': f"Circuit breakers open: {', '.join(failing_breakers)}",
                    'details': {'open_breakers': failing_breakers}
                }
            else:
                return {
                    'status': 'healthy',
                    'message': 'All circuit breakers operational',
                    'details': {'total_breakers': len(stats)}
                }
        
        async def session_factory_health():
            """Check HTTP session factory"""
            try:
                session = await SessionFactory.get_session()
                if session and not session.closed:
                    return {
                        'status': 'healthy',
                        'message': 'Session factory operational'
                    }
                else:
                    return {
                        'status': 'unhealthy',
                        'message': 'Session factory not available'
                    }
            except Exception as e:
                return {
                    'status': 'unhealthy',
                    'message': f"Session factory error: {str(e)}"
                }
        
        # Register the checks
        self.register_health_check('cache', cache_health)
        self.register_health_check('circuit_breakers', circuit_breaker_health)
        self.register_health_check('session_factory', session_factory_health)


# Global health monitor instance
health_monitor = HealthMonitor()