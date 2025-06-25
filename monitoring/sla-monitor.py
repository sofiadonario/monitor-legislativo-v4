# SLA Monitoring and Alerting System for Monitor Legislativo v4
# Phase 4 Week 15: Automated SLA tracking with intelligent alerting
# Monitors service level objectives and generates comprehensive reports

import asyncio
import aiohttp
import asyncpg
import logging
import time
import json
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
import os
import statistics
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)

class SLAStatus(Enum):
    """SLA compliance status"""
    HEALTHY = "healthy"         # Meeting all SLA targets
    WARNING = "warning"         # Approaching SLA breach
    CRITICAL = "critical"       # SLA breach detected
    UNKNOWN = "unknown"         # Cannot determine status

class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"

@dataclass
class SLATarget:
    """Service Level Agreement target definition"""
    name: str
    description: str
    target_value: float
    unit: str
    metric_query: str           # Prometheus query for this metric
    evaluation_period: str      # Time window for evaluation (e.g., "5m", "1h")
    warning_threshold: float    # Warning threshold (% of target)
    critical_threshold: float   # Critical threshold (% of target)
    alert_on_breach: bool = True
    business_impact: str = "medium"
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class SLAMeasurement:
    """SLA measurement result"""
    target_name: str
    timestamp: datetime
    actual_value: float
    target_value: float
    compliance_percentage: float
    status: SLAStatus
    breach_duration: Optional[timedelta] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['status'] = self.status.value
        result['timestamp'] = self.timestamp.isoformat()
        if self.breach_duration:
            result['breach_duration'] = str(self.breach_duration)
        return result

@dataclass
class SLAReport:
    """Comprehensive SLA compliance report"""
    period_start: datetime
    period_end: datetime
    overall_compliance: float
    measurements: List[SLAMeasurement]
    breaches: List[SLAMeasurement]
    trends: Dict[str, Any]
    recommendations: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['period_start'] = self.period_start.isoformat()
        result['period_end'] = self.period_end.isoformat()
        result['measurements'] = [m.to_dict() for m in self.measurements]
        result['breaches'] = [b.to_dict() for b in self.breaches]
        return result

class SLAMonitor:
    """
    Comprehensive SLA monitoring system for Monitor Legislativo v4
    
    Monitors key service level objectives including:
    - API response times and availability
    - Database performance metrics
    - Data freshness and collection reliability
    - User experience metrics
    - Brazilian government API dependencies
    """
    
    def __init__(self, prometheus_url: str = "http://prometheus:9090", 
                 alertmanager_url: str = "http://alertmanager:9093"):
        self.prometheus_url = prometheus_url
        self.alertmanager_url = alertmanager_url
        self.sla_targets = {}
        self.measurements_history = {}
        self.alert_rules = {}
        self.is_monitoring = False
        self._monitor_task: Optional[asyncio.Task] = None
        
        # Initialize SLA targets for Monitor Legislativo v4
        self._initialize_sla_targets()
    
    def _initialize_sla_targets(self) -> None:
        """Initialize SLA targets specific to Monitor Legislativo v4"""
        
        # API Availability - Critical for platform access
        self.register_sla_target(SLATarget(
            name="api_availability",
            description="Backend API service availability",
            target_value=99.5,  # 99.5% uptime
            unit="percent",
            metric_query='avg(up{job="backend-api"}) * 100',
            evaluation_period="5m",
            warning_threshold=99.0,
            critical_threshold=98.0,
            business_impact="high"
        ))
        
        # API Response Time - User experience critical
        self.register_sla_target(SLATarget(
            name="api_response_time",
            description="95th percentile API response time",
            target_value=2.0,  # 2 seconds
            unit="seconds",
            metric_query='histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{job="backend-api"}[5m]))',
            evaluation_period="5m",
            warning_threshold=1.5,  # 1.5 seconds warning
            critical_threshold=3.0,  # 3 seconds critical
            business_impact="high"
        ))
        
        # Database Response Time - Core data access
        self.register_sla_target(SLATarget(
            name="database_response_time",
            description="Average database query response time",
            target_value=1.0,  # 1 second
            unit="seconds",
            metric_query='rate(postgresql_query_duration_seconds_sum[5m]) / rate(postgresql_query_duration_seconds_count[5m])',
            evaluation_period="5m",
            warning_threshold=0.8,
            critical_threshold=2.0,
            business_impact="high"
        ))
        
        # Search Performance - Core user functionality
        self.register_sla_target(SLATarget(
            name="search_response_time",
            description="Legislative document search response time",
            target_value=5.0,  # 5 seconds for complex searches
            unit="seconds",
            metric_query='histogram_quantile(0.95, rate(monitor_legislativo_search_duration_seconds_bucket[5m]))',
            evaluation_period="5m",
            warning_threshold=4.0,
            critical_threshold=8.0,
            business_impact="medium"
        ))
        
        # Data Freshness - Academic requirement
        self.register_sla_target(SLATarget(
            name="data_freshness",
            description="Maximum age of legislative data",
            target_value=24.0,  # 24 hours
            unit="hours",
            metric_query='(time() - monitor_legislativo_data_freshness_timestamp) / 3600',
            evaluation_period="1h",
            warning_threshold=12.0,  # 12 hours warning
            critical_threshold=48.0,  # 48 hours critical
            business_impact="medium"
        ))
        
        # Collection Success Rate - Data reliability
        self.register_sla_target(SLATarget(
            name="collection_success_rate",
            description="Data collection success rate from government APIs",
            target_value=95.0,  # 95% success rate
            unit="percent",
            metric_query='(rate(monitor_legislativo_collection_attempts_total[1h]) - rate(monitor_legislativo_collection_failures_total[1h])) / rate(monitor_legislativo_collection_attempts_total[1h]) * 100',
            evaluation_period="1h",
            warning_threshold=90.0,
            critical_threshold=80.0,
            business_impact="medium"
        ))
        
        # Cache Hit Rate - Performance optimization
        self.register_sla_target(SLATarget(
            name="cache_hit_rate",
            description="Redis cache hit rate for application performance",
            target_value=80.0,  # 80% cache hit rate
            unit="percent",
            metric_query='redis_keyspace_hits_total / (redis_keyspace_hits_total + redis_keyspace_misses_total) * 100',
            evaluation_period="15m",
            warning_threshold=70.0,
            critical_threshold=50.0,
            business_impact="low"
        ))
        
        # Error Rate - Application reliability
        self.register_sla_target(SLATarget(
            name="error_rate",
            description="HTTP 5xx error rate for API endpoints",
            target_value=1.0,  # Maximum 1% error rate
            unit="percent",
            metric_query='rate(http_requests_total{job="backend-api",status=~"5.."}[5m]) / rate(http_requests_total{job="backend-api"}[5m]) * 100',
            evaluation_period="5m",
            warning_threshold=0.5,
            critical_threshold=2.0,
            business_impact="high"
        ))
        
        # LexML API Dependency - External service reliability
        self.register_sla_target(SLATarget(
            name="lexml_api_availability",
            description="LexML Brasil API availability for legislative data",
            target_value=95.0,  # 95% availability (external dependency)
            unit="percent",
            metric_query='avg(probe_success{instance="https://www.lexml.gov.br",job="lexml-api"}) * 100',
            evaluation_period="15m",
            warning_threshold=90.0,
            critical_threshold=80.0,
            business_impact="medium"
        ))
        
        # Backup Reliability - Data protection
        self.register_sla_target(SLATarget(
            name="backup_freshness",
            description="Time since last successful database backup",
            target_value=24.0,  # 24 hours maximum
            unit="hours",
            metric_query='(time() - monitor_legislativo_backup_last_success_timestamp) / 3600',
            evaluation_period="1h",
            warning_threshold=18.0,  # 18 hours warning
            critical_threshold=48.0,  # 48 hours critical
            business_impact="high"
        ))
    
    def register_sla_target(self, target: SLATarget) -> None:
        """Register an SLA target for monitoring"""
        self.sla_targets[target.name] = target
        self.measurements_history[target.name] = []
        logger.info(f"Registered SLA target: {target.name}")
    
    async def start_monitoring(self, check_interval: int = 60) -> None:
        """Start continuous SLA monitoring"""
        if not self.is_monitoring:
            self.is_monitoring = True
            self._monitor_task = asyncio.create_task(self._monitoring_loop(check_interval))
            logger.info(f"SLA monitoring started with {check_interval}s interval")
    
    async def stop_monitoring(self) -> None:
        """Stop SLA monitoring"""
        self.is_monitoring = False
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        logger.info("SLA monitoring stopped")
    
    async def _monitoring_loop(self, check_interval: int) -> None:
        """Main monitoring loop"""
        while self.is_monitoring:
            try:
                # Measure all SLA targets
                measurements = await self._measure_all_slas()
                
                # Process measurements and trigger alerts
                for measurement in measurements:
                    await self._process_measurement(measurement)
                    
                    # Store measurement in history
                    history = self.measurements_history[measurement.target_name]
                    history.append(measurement)
                    
                    # Keep only last 24 hours of measurements
                    cutoff_time = datetime.now() - timedelta(hours=24)
                    self.measurements_history[measurement.target_name] = [
                        m for m in history if m.timestamp > cutoff_time
                    ]
                
                # Generate periodic reports
                if datetime.now().minute % 15 == 0:  # Every 15 minutes
                    await self._generate_status_report()
                
                await asyncio.sleep(check_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"SLA monitoring error: {e}")
                await asyncio.sleep(10)  # Brief pause before retry
    
    async def _measure_all_slas(self) -> List[SLAMeasurement]:
        """Measure all registered SLA targets"""
        measurements = []
        
        async with aiohttp.ClientSession() as session:
            for target_name, target in self.sla_targets.items():
                try:
                    measurement = await self._measure_sla_target(session, target)
                    measurements.append(measurement)
                except Exception as e:
                    logger.error(f"Failed to measure SLA target {target_name}: {e}")
                    # Create error measurement
                    measurements.append(SLAMeasurement(
                        target_name=target_name,
                        timestamp=datetime.now(),
                        actual_value=0.0,
                        target_value=target.target_value,
                        compliance_percentage=0.0,
                        status=SLAStatus.UNKNOWN,
                        metadata={"error": str(e)}
                    ))
        
        return measurements
    
    async def _measure_sla_target(self, session: aiohttp.ClientSession, target: SLATarget) -> SLAMeasurement:
        """Measure a specific SLA target using Prometheus query"""
        # Construct Prometheus query URL
        query_url = f"{self.prometheus_url}/api/v1/query"
        params = {
            "query": target.metric_query,
            "time": int(time.time())
        }
        
        async with session.get(query_url, params=params) as response:
            if response.status != 200:
                raise Exception(f"Prometheus query failed: {response.status}")
            
            data = await response.json()
            
            if data["status"] != "success":
                raise Exception(f"Prometheus query error: {data.get('error', 'Unknown error')}")
            
            result = data["data"]["result"]
            if not result:
                raise Exception("No data returned from Prometheus query")
            
            # Extract metric value
            actual_value = float(result[0]["value"][1])
            
            # Calculate compliance and status
            compliance_percentage, status = self._calculate_compliance(target, actual_value)
            
            return SLAMeasurement(
                target_name=target.name,
                timestamp=datetime.now(),
                actual_value=actual_value,
                target_value=target.target_value,
                compliance_percentage=compliance_percentage,
                status=status,
                metadata={
                    "query": target.metric_query,
                    "evaluation_period": target.evaluation_period,
                    "business_impact": target.business_impact
                }
            )
    
    def _calculate_compliance(self, target: SLATarget, actual_value: float) -> Tuple[float, SLAStatus]:
        """Calculate compliance percentage and status for an SLA target"""
        
        # Different calculation logic based on metric type
        if target.name in ["api_response_time", "database_response_time", "search_response_time", 
                          "data_freshness", "backup_freshness"]:
            # Lower is better - calculate compliance as target/actual * 100
            if actual_value <= target.target_value:
                compliance_percentage = 100.0
                status = SLAStatus.HEALTHY
            else:
                compliance_percentage = (target.target_value / actual_value) * 100
                
                if actual_value <= target.warning_threshold:
                    status = SLAStatus.HEALTHY
                elif actual_value <= target.critical_threshold:
                    status = SLAStatus.WARNING
                else:
                    status = SLAStatus.CRITICAL
                    
        elif target.name == "error_rate":
            # Lower is better for error rate - invert the calculation
            if actual_value <= target.target_value:
                compliance_percentage = 100.0
                status = SLAStatus.HEALTHY
            else:
                compliance_percentage = max(0, 100 - (actual_value - target.target_value) * 10)
                
                if actual_value <= target.warning_threshold:
                    status = SLAStatus.HEALTHY
                elif actual_value <= target.critical_threshold:
                    status = SLAStatus.WARNING
                else:
                    status = SLAStatus.CRITICAL
        
        else:
            # Higher is better (availability, success rate, cache hit rate)
            compliance_percentage = (actual_value / target.target_value) * 100
            
            if actual_value >= target.target_value:
                status = SLAStatus.HEALTHY
            elif actual_value >= target.warning_threshold:
                status = SLAStatus.WARNING
            else:
                status = SLAStatus.CRITICAL
        
        return min(100.0, max(0.0, compliance_percentage)), status
    
    async def _process_measurement(self, measurement: SLAMeasurement) -> None:
        """Process an SLA measurement and trigger alerts if needed"""
        target = self.sla_targets[measurement.target_name]
        
        # Check for SLA breaches and trigger alerts
        if measurement.status in [SLAStatus.WARNING, SLAStatus.CRITICAL] and target.alert_on_breach:
            await self._trigger_sla_alert(measurement, target)
        
        # Check for recovery from previous breach
        recent_measurements = self.measurements_history.get(measurement.target_name, [])
        if len(recent_measurements) > 0:
            last_measurement = recent_measurements[-1]
            if (last_measurement.status in [SLAStatus.WARNING, SLAStatus.CRITICAL] and 
                measurement.status == SLAStatus.HEALTHY):
                await self._trigger_sla_recovery_alert(measurement, target)
    
    async def _trigger_sla_alert(self, measurement: SLAMeasurement, target: SLATarget) -> None:
        """Trigger an SLA breach alert"""
        severity = AlertSeverity.WARNING if measurement.status == SLAStatus.WARNING else AlertSeverity.CRITICAL
        
        alert_data = {
            "receiver": "sla-alerts",
            "status": "firing",
            "alerts": [{
                "status": "firing",
                "labels": {
                    "alertname": f"SLABreach_{target.name}",
                    "severity": severity.value,
                    "service": "monitor-legislativo",
                    "sla_target": target.name,
                    "business_impact": target.business_impact
                },
                "annotations": {
                    "summary": f"SLA breach detected for {target.description}",
                    "description": f"Target: {target.target_value}{target.unit}, Actual: {measurement.actual_value:.2f}{target.unit}, Compliance: {measurement.compliance_percentage:.1f}%",
                    "impact": self._get_business_impact_description(target.business_impact),
                    "runbook_url": f"https://docs.monitor-legislativo.com/runbooks/sla-{target.name}",
                    "dashboard_url": f"http://grafana:3000/d/sla-dashboard"
                },
                "generatorURL": f"http://prometheus:9090/graph?g0.expr={target.metric_query}",
                "startsAt": measurement.timestamp.isoformat()
            }]
        }
        
        # Send to Alertmanager
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{self.alertmanager_url}/api/v1/alerts", 
                                      json=alert_data) as response:
                    if response.status == 200:
                        logger.info(f"SLA alert sent for {target.name}")
                    else:
                        logger.error(f"Failed to send SLA alert: {response.status}")
        except Exception as e:
            logger.error(f"Error sending SLA alert: {e}")
    
    async def _trigger_sla_recovery_alert(self, measurement: SLAMeasurement, target: SLATarget) -> None:
        """Trigger an SLA recovery notification"""
        alert_data = {
            "receiver": "sla-alerts",
            "status": "resolved",
            "alerts": [{
                "status": "resolved",
                "labels": {
                    "alertname": f"SLABreach_{target.name}",
                    "severity": "info",
                    "service": "monitor-legislativo",
                    "sla_target": target.name
                },
                "annotations": {
                    "summary": f"SLA recovered for {target.description}",
                    "description": f"Current value: {measurement.actual_value:.2f}{target.unit}, Compliance: {measurement.compliance_percentage:.1f}%"
                },
                "endsAt": measurement.timestamp.isoformat()
            }]
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{self.alertmanager_url}/api/v1/alerts", 
                                      json=alert_data) as response:
                    if response.status == 200:
                        logger.info(f"SLA recovery alert sent for {target.name}")
        except Exception as e:
            logger.error(f"Error sending SLA recovery alert: {e}")
    
    def _get_business_impact_description(self, impact_level: str) -> str:
        """Get business impact description"""
        impact_descriptions = {
            "low": "Minor impact on user experience",
            "medium": "Moderate impact on platform functionality", 
            "high": "Significant impact on core services",
            "critical": "Severe impact on platform availability"
        }
        return impact_descriptions.get(impact_level, "Unknown impact")
    
    async def _generate_status_report(self) -> None:
        """Generate periodic SLA status report"""
        logger.info("Generating SLA status report...")
        
        current_status = {}
        for target_name, target in self.sla_targets.items():
            measurements = self.measurements_history.get(target_name, [])
            if measurements:
                latest = measurements[-1]
                current_status[target_name] = {
                    "status": latest.status.value,
                    "compliance": latest.compliance_percentage,
                    "actual_value": latest.actual_value,
                    "target_value": target.target_value,
                    "unit": target.unit
                }
        
        # Log summary
        healthy_count = sum(1 for status in current_status.values() if status["status"] == "healthy")
        total_count = len(current_status)
        
        logger.info(f"SLA Status Summary: {healthy_count}/{total_count} targets healthy")
        
        # Save to file for external consumption
        report_file = f"/tmp/sla-status-{int(time.time())}.json"
        with open(report_file, 'w') as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "overall_health": f"{healthy_count}/{total_count}",
                "targets": current_status
            }, f, indent=2)
    
    async def generate_comprehensive_report(self, period_hours: int = 24) -> SLAReport:
        """Generate comprehensive SLA compliance report"""
        period_start = datetime.now() - timedelta(hours=period_hours)
        period_end = datetime.now()
        
        all_measurements = []
        all_breaches = []
        compliance_scores = []
        
        # Collect measurements from all targets
        for target_name, measurements in self.measurements_history.items():
            period_measurements = [
                m for m in measurements 
                if period_start <= m.timestamp <= period_end
            ]
            
            all_measurements.extend(period_measurements)
            
            # Identify breaches
            breaches = [
                m for m in period_measurements
                if m.status in [SLAStatus.WARNING, SLAStatus.CRITICAL]
            ]
            all_breaches.extend(breaches)
            
            # Calculate compliance score for this target
            if period_measurements:
                target_compliance = statistics.mean([m.compliance_percentage for m in period_measurements])
                compliance_scores.append(target_compliance)
        
        # Calculate overall compliance
        overall_compliance = statistics.mean(compliance_scores) if compliance_scores else 0.0
        
        # Generate trends and recommendations
        trends = self._analyze_trends(period_hours)
        recommendations = self._generate_recommendations(all_measurements, all_breaches)
        
        return SLAReport(
            period_start=period_start,
            period_end=period_end,
            overall_compliance=overall_compliance,
            measurements=all_measurements,
            breaches=all_breaches,
            trends=trends,
            recommendations=recommendations
        )
    
    def _analyze_trends(self, period_hours: int) -> Dict[str, Any]:
        """Analyze SLA trends over the specified period"""
        trends = {}
        
        for target_name, measurements in self.measurements_history.items():
            if len(measurements) < 2:
                continue
            
            # Calculate trend over time
            recent_measurements = measurements[-10:]  # Last 10 measurements
            if len(recent_measurements) >= 2:
                values = [m.compliance_percentage for m in recent_measurements]
                
                # Simple linear trend calculation
                x = list(range(len(values)))
                n = len(values)
                sum_x = sum(x)
                sum_y = sum(values)
                sum_xy = sum(x[i] * values[i] for i in range(n))
                sum_x2 = sum(x[i] * x[i] for i in range(n))
                
                slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)
                
                trends[target_name] = {
                    "trend_direction": "improving" if slope > 0.1 else "degrading" if slope < -0.1 else "stable",
                    "trend_slope": slope,
                    "current_compliance": values[-1],
                    "average_compliance": statistics.mean(values),
                    "measurement_count": len(recent_measurements)
                }
        
        return trends
    
    def _generate_recommendations(self, measurements: List[SLAMeasurement], 
                                breaches: List[SLAMeasurement]) -> List[str]:
        """Generate actionable recommendations based on SLA analysis"""
        recommendations = []
        
        # Analyze breach patterns
        breach_counts = {}
        for breach in breaches:
            breach_counts[breach.target_name] = breach_counts.get(breach.target_name, 0) + 1
        
        # Generate target-specific recommendations
        for target_name, breach_count in breach_counts.items():
            target = self.sla_targets[target_name]
            
            if breach_count > 5:  # Frequent breaches
                if target_name == "api_response_time":
                    recommendations.append("Consider scaling API instances or optimizing database queries to improve response times")
                elif target_name == "database_response_time":
                    recommendations.append("Review database indexes and query performance, consider connection pool optimization")
                elif target_name == "data_freshness":
                    recommendations.append("Investigate data collection scheduler and government API reliability")
                elif target_name == "cache_hit_rate":
                    recommendations.append("Review cache configuration and implement cache warming strategies")
        
        # General recommendations based on overall patterns
        if len(breaches) > len(measurements) * 0.1:  # More than 10% breach rate
            recommendations.append("Overall SLA compliance is concerning - consider infrastructure scaling or optimization")
        
        if not recommendations:
            recommendations.append("SLA compliance is healthy - continue monitoring and maintain current service levels")
        
        return recommendations
    
    async def get_current_status(self) -> Dict[str, Any]:
        """Get current SLA status for all targets"""
        status = {}
        
        for target_name, target in self.sla_targets.items():
            measurements = self.measurements_history.get(target_name, [])
            if measurements:
                latest = measurements[-1]
                status[target_name] = {
                    "target": target.to_dict(),
                    "current_measurement": latest.to_dict(),
                    "recent_measurements": len(measurements),
                    "breach_count_24h": len([m for m in measurements 
                                           if m.status in [SLAStatus.WARNING, SLAStatus.CRITICAL]])
                }
            else:
                status[target_name] = {
                    "target": target.to_dict(),
                    "current_measurement": None,
                    "recent_measurements": 0,
                    "breach_count_24h": 0
                }
        
        return status

# Factory function for easy creation
async def create_sla_monitor(prometheus_url: str = None, alertmanager_url: str = None) -> SLAMonitor:
    """Create and initialize SLA monitor"""
    prometheus_url = prometheus_url or os.getenv("PROMETHEUS_URL", "http://prometheus:9090")
    alertmanager_url = alertmanager_url or os.getenv("ALERTMANAGER_URL", "http://alertmanager:9093")
    
    monitor = SLAMonitor(prometheus_url, alertmanager_url)
    return monitor

# Export main classes
__all__ = [
    'SLAMonitor',
    'SLATarget',
    'SLAMeasurement', 
    'SLAReport',
    'SLAStatus',
    'AlertSeverity',
    'create_sla_monitor'
]