"""
Enhanced Monitoring Dashboard
Real-time status monitoring for all 14 data sources
Implements recommendations from monitor-legislativo-analysis.md
"""

import asyncio
import time
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import logging

from .health_monitor import health_monitor, HealthStatus
from .circuit_breaker import circuit_manager
from .smart_cache import smart_cache


class SourceType(Enum):
    """Data source types"""
    LEGISLATIVE_API = "legislative_api"
    REGULATORY_SCRAPER = "regulatory_scraper"
    WEB_PORTAL = "web_portal"


@dataclass
class SourceStatus:
    """Individual source status"""
    name: str
    type: SourceType
    status: HealthStatus
    response_time_ms: float
    last_success: Optional[datetime]
    last_failure: Optional[datetime]
    error_count_24h: int
    success_rate_24h: float
    circuit_breaker_state: str
    cache_hit_rate: float
    data_freshness_hours: float
    
    def to_dict(self) -> dict:
        return {
            'name': self.name,
            'type': self.type.value,
            'status': self.status.value,
            'response_time_ms': self.response_time_ms,
            'last_success': self.last_success.isoformat() if self.last_success else None,
            'last_failure': self.last_failure.isoformat() if self.last_failure else None,
            'error_count_24h': self.error_count_24h,
            'success_rate_24h': self.success_rate_24h,
            'circuit_breaker_state': self.circuit_breaker_state,
            'cache_hit_rate': self.cache_hit_rate,
            'data_freshness_hours': self.data_freshness_hours
        }


@dataclass
class SystemMetrics:
    """Overall system metrics"""
    total_sources: int
    healthy_sources: int
    degraded_sources: int
    unhealthy_sources: int
    avg_response_time_ms: float
    overall_success_rate: float
    cache_efficiency: float
    data_processed_24h: int
    alerts_active: int
    
    @property
    def health_percentage(self) -> float:
        if self.total_sources == 0:
            return 0.0
        return (self.healthy_sources / self.total_sources) * 100


class MonitoringDashboard:
    """
    Enhanced monitoring dashboard with real-time metrics
    Implements comprehensive monitoring as recommended in analysis
    """
    
    def __init__(self, update_interval: int = 300):  # 5 minutes
        self.update_interval = update_interval
        self.logger = logging.getLogger(__name__)
        
        # Data source configuration
        self.sources_config = {
            # Legislative APIs
            'camara': SourceType.LEGISLATIVE_API,
            'senado': SourceType.LEGISLATIVE_API,
            'planalto': SourceType.WEB_PORTAL,
            
            # Regulatory Agencies
            'aneel': SourceType.REGULATORY_SCRAPER,
            'anatel': SourceType.REGULATORY_SCRAPER,
            'anvisa': SourceType.REGULATORY_SCRAPER,
            'ans': SourceType.REGULATORY_SCRAPER,
            'ana': SourceType.REGULATORY_SCRAPER,
            'ancine': SourceType.REGULATORY_SCRAPER,
            'antt': SourceType.REGULATORY_SCRAPER,
            'antaq': SourceType.REGULATORY_SCRAPER,
            'anac': SourceType.REGULATORY_SCRAPER,
            'anp': SourceType.REGULATORY_SCRAPER,
            'anm': SourceType.REGULATORY_SCRAPER,
        }
        
        # Metrics storage
        self.current_status: Dict[str, SourceStatus] = {}
        self.historical_metrics: List[Dict[str, Any]] = []
        self.alerts: List[Dict[str, Any]] = []
        self.performance_baselines: Dict[str, Dict[str, float]] = {}
        
        # Monitoring state
        self._monitoring_active = False
        self._monitor_task: Optional[asyncio.Task] = None
        
        # Initialize baselines
        self._initialize_baselines()
    
    async def start_monitoring(self):
        """Start continuous monitoring"""
        if self._monitoring_active:
            return
        
        self._monitoring_active = True
        self._monitor_task = asyncio.create_task(self._monitoring_loop())
        self.logger.info("Enhanced monitoring dashboard started")
    
    async def stop_monitoring(self):
        """Stop monitoring"""
        self._monitoring_active = False
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        
        self.logger.info("Enhanced monitoring dashboard stopped")
    
    async def get_realtime_status(self) -> Dict[str, Any]:
        """Get current real-time status for all sources"""
        await self._update_all_sources()
        
        system_metrics = self._calculate_system_metrics()
        
        return {
            'timestamp': datetime.now().isoformat(),
            'system_metrics': asdict(system_metrics),
            'sources': {name: status.to_dict() for name, status in self.current_status.items()},
            'circuit_breakers': circuit_manager.get_all_stats(),
            'cache_stats': await smart_cache.health_check(),
            'active_alerts': self.alerts[-10:],  # Last 10 alerts
            'performance_summary': self._get_performance_summary()
        }
    
    async def get_historical_data(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get historical metrics for specified time period"""
        cutoff = datetime.now() - timedelta(hours=hours)
        
        return [
            metric for metric in self.historical_metrics
            if datetime.fromisoformat(metric['timestamp']) >= cutoff
        ]
    
    async def check_source_health(self, source_name: str) -> SourceStatus:
        """Check health of specific source"""
        if source_name not in self.sources_config:
            raise ValueError(f"Unknown source: {source_name}")
        
        # Get basic health from health monitor
        health_result = await health_monitor.check_component_health(source_name)
        
        # Get circuit breaker stats
        cb_stats = circuit_manager.get_all_stats().get(source_name, {})
        
        # Calculate additional metrics
        error_count = await self._get_error_count_24h(source_name)
        success_rate = await self._get_success_rate_24h(source_name)
        cache_hit_rate = await self._get_cache_hit_rate(source_name)
        data_freshness = await self._get_data_freshness(source_name)
        
        # Determine overall status
        if health_result:
            status = HealthStatus(health_result.status)
            response_time = health_result.response_time_ms
            last_success = health_result.timestamp
            last_failure = None
        else:
            status = HealthStatus.UNKNOWN
            response_time = 0.0
            last_success = None
            last_failure = datetime.now()
        
        return SourceStatus(
            name=source_name,
            type=self.sources_config[source_name],
            status=status,
            response_time_ms=response_time,
            last_success=last_success,
            last_failure=last_failure,
            error_count_24h=error_count,
            success_rate_24h=success_rate,
            circuit_breaker_state=cb_stats.get('state', 'unknown'),
            cache_hit_rate=cache_hit_rate,
            data_freshness_hours=data_freshness
        )
    
    async def generate_alert(self, source: str, alert_type: str, message: str, severity: str = "warning"):
        """Generate monitoring alert"""
        alert = {
            'id': f"{source}_{alert_type}_{int(time.time())}",
            'timestamp': datetime.now().isoformat(),
            'source': source,
            'type': alert_type,
            'message': message,
            'severity': severity,  # info, warning, error, critical
            'resolved': False
        }
        
        self.alerts.append(alert)
        
        # Keep only last 1000 alerts
        if len(self.alerts) > 1000:
            self.alerts = self.alerts[-1000:]
        
        self.logger.warning(f"Alert generated: {alert}")
        
        # Auto-resolve certain alert types
        if alert_type in ['performance_degradation', 'high_error_rate']:
            asyncio.create_task(self._auto_resolve_alert(alert['id'], 300))  # 5 minutes
    
    async def _monitoring_loop(self):
        """Main monitoring loop"""
        while self._monitoring_active:
            try:
                await self._update_all_sources()
                await self._check_alert_conditions()
                await self._store_historical_data()
                await asyncio.sleep(self.update_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(30)  # Wait before retrying
    
    async def _update_all_sources(self):
        """Update status for all sources"""
        tasks = [
            self.check_source_health(source_name)
            for source_name in self.sources_config.keys()
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for source_name, result in zip(self.sources_config.keys(), results):
            if isinstance(result, SourceStatus):
                self.current_status[source_name] = result
            else:
                self.logger.error(f"Failed to get status for {source_name}: {result}")
    
    def _calculate_system_metrics(self) -> SystemMetrics:
        """Calculate overall system metrics"""
        if not self.current_status:
            return SystemMetrics(0, 0, 0, 0, 0.0, 0.0, 0.0, 0, 0)
        
        statuses = list(self.current_status.values())
        
        healthy = len([s for s in statuses if s.status == HealthStatus.HEALTHY])
        degraded = len([s for s in statuses if s.status == HealthStatus.DEGRADED])
        unhealthy = len([s for s in statuses if s.status == HealthStatus.UNHEALTHY])
        
        avg_response_time = sum(s.response_time_ms for s in statuses) / len(statuses)
        avg_success_rate = sum(s.success_rate_24h for s in statuses) / len(statuses)
        avg_cache_efficiency = sum(s.cache_hit_rate for s in statuses) / len(statuses)
        
        active_alerts = len([a for a in self.alerts if not a.get('resolved', False)])
        
        return SystemMetrics(
            total_sources=len(statuses),
            healthy_sources=healthy,
            degraded_sources=degraded,
            unhealthy_sources=unhealthy,
            avg_response_time_ms=avg_response_time,
            overall_success_rate=avg_success_rate,
            cache_efficiency=avg_cache_efficiency,
            data_processed_24h=0,  # TODO: Implement from metrics collector
            alerts_active=active_alerts
        )
    
    async def _check_alert_conditions(self):
        """Check for conditions that should trigger alerts"""
        for source_name, status in self.current_status.items():
            # Check for high error rate
            if status.success_rate_24h < 80:
                await self.generate_alert(
                    source_name,
                    "high_error_rate",
                    f"Success rate dropped to {status.success_rate_24h:.1f}%",
                    "warning"
                )
            
            # Check for slow response times
            baseline = self.performance_baselines.get(source_name, {}).get('response_time', 5000)
            if status.response_time_ms > baseline * 2:
                await self.generate_alert(
                    source_name,
                    "performance_degradation",
                    f"Response time {status.response_time_ms:.0f}ms exceeds baseline",
                    "warning"
                )
            
            # Check for circuit breaker open
            if status.circuit_breaker_state == "open":
                await self.generate_alert(
                    source_name,
                    "circuit_breaker_open",
                    "Circuit breaker is open - service unavailable",
                    "error"
                )
            
            # Check for stale data
            if status.data_freshness_hours > 48:  # 2 days
                await self.generate_alert(
                    source_name,
                    "stale_data",
                    f"Data is {status.data_freshness_hours:.1f} hours old",
                    "warning"
                )
    
    async def _store_historical_data(self):
        """Store current metrics as historical data"""
        system_metrics = self._calculate_system_metrics()
        
        historical_entry = {
            'timestamp': datetime.now().isoformat(),
            'system_metrics': asdict(system_metrics),
            'source_count_by_status': {
                'healthy': system_metrics.healthy_sources,
                'degraded': system_metrics.degraded_sources,
                'unhealthy': system_metrics.unhealthy_sources
            },
            'performance_metrics': {
                'avg_response_time': system_metrics.avg_response_time_ms,
                'success_rate': system_metrics.overall_success_rate,
                'cache_efficiency': system_metrics.cache_efficiency
            }
        }
        
        self.historical_metrics.append(historical_entry)
        
        # Keep only last 7 days of data
        cutoff = datetime.now() - timedelta(days=7)
        self.historical_metrics = [
            entry for entry in self.historical_metrics
            if datetime.fromisoformat(entry['timestamp']) >= cutoff
        ]
    
    def _initialize_baselines(self):
        """Initialize performance baselines for each source"""
        # Set baseline performance expectations
        self.performance_baselines = {
            # Legislative APIs (should be fast)
            'camara': {'response_time': 2000, 'success_rate': 95},
            'senado': {'response_time': 3000, 'success_rate': 90},
            'planalto': {'response_time': 30000, 'success_rate': 70},  # Slow due to Playwright
            
            # Regulatory agencies (expect higher variability)
            'aneel': {'response_time': 5000, 'success_rate': 80},
            'anatel': {'response_time': 5000, 'success_rate': 80},
            'anvisa': {'response_time': 10000, 'success_rate': 70},  # Playwright required
        }
        
        # Set defaults for remaining agencies
        for source in self.sources_config.keys():
            if source not in self.performance_baselines:
                self.performance_baselines[source] = {'response_time': 8000, 'success_rate': 75}
    
    async def _get_error_count_24h(self, source: str) -> int:
        """Get error count for source in last 24 hours"""
        # TODO: Implement with metrics collector
        return 0
    
    async def _get_success_rate_24h(self, source: str) -> float:
        """Get success rate for source in last 24 hours"""
        cb_stats = circuit_manager.get_all_stats().get(source, {})
        return cb_stats.get('success_rate', 0.0)
    
    async def _get_cache_hit_rate(self, source: str) -> float:
        """Get cache hit rate for source"""
        # TODO: Implement with smart_cache stats
        return 0.0
    
    async def _get_data_freshness(self, source: str) -> float:
        """Get data freshness in hours"""
        # TODO: Implement by checking last successful data fetch
        return 0.0
    
    def _get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary by source type"""
        api_sources = [s for s, t in self.sources_config.items() if t == SourceType.LEGISLATIVE_API]
        scraper_sources = [s for s, t in self.sources_config.items() if t == SourceType.REGULATORY_SCRAPER]
        
        def get_avg_for_sources(sources, metric):
            if not sources:
                return 0.0
            values = [getattr(self.current_status.get(s), metric, 0) for s in sources]
            return sum(values) / len(values)
        
        return {
            'legislative_apis': {
                'avg_response_time': get_avg_for_sources(api_sources, 'response_time_ms'),
                'avg_success_rate': get_avg_for_sources(api_sources, 'success_rate_24h'),
                'healthy_count': len([s for s in api_sources if self.current_status.get(s, {}).status == HealthStatus.HEALTHY])
            },
            'regulatory_scrapers': {
                'avg_response_time': get_avg_for_sources(scraper_sources, 'response_time_ms'),
                'avg_success_rate': get_avg_for_sources(scraper_sources, 'success_rate_24h'),
                'healthy_count': len([s for s in scraper_sources if self.current_status.get(s, {}).status == HealthStatus.HEALTHY])
            }
        }
    
    async def _auto_resolve_alert(self, alert_id: str, delay_seconds: int):
        """Auto-resolve alert after delay"""
        await asyncio.sleep(delay_seconds)
        
        for alert in self.alerts:
            if alert['id'] == alert_id:
                alert['resolved'] = True
                alert['resolved_at'] = datetime.now().isoformat()
                break


# Global monitoring dashboard instance
monitoring_dashboard = MonitoringDashboard()