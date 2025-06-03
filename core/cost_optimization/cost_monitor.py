"""
Cost Monitor for Monitor Legislativo v4
Real-time cost tracking and alerting

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import json

logger = logging.getLogger(__name__)

class ResourceType(Enum):
    """Types of resources to monitor"""
    COMPUTE = "compute"
    STORAGE = "storage"
    DATABASE = "database"
    NETWORK = "network"
    CACHE = "cache"
    MONITORING = "monitoring"

class CostPeriod(Enum):
    """Cost tracking periods"""
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"

@dataclass
class ResourceUsage:
    """Resource usage data"""
    resource_id: str
    resource_type: ResourceType
    usage_amount: float
    unit: str  # hours, GB, requests, etc.
    cost_per_unit: float
    total_cost: float
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class CostMetrics:
    """Cost metrics for a period"""
    period: CostPeriod
    start_time: datetime
    end_time: datetime
    total_cost: float
    cost_by_resource: Dict[ResourceType, float] = field(default_factory=dict)
    cost_by_service: Dict[str, float] = field(default_factory=dict)
    usage_metrics: List[ResourceUsage] = field(default_factory=list)
    projected_monthly_cost: float = 0.0

@dataclass
class CostAlert:
    """Cost alert configuration and data"""
    id: str
    name: str
    threshold_amount: float
    threshold_type: str  # "absolute", "percentage", "trend"
    period: CostPeriod
    resource_types: List[ResourceType] = field(default_factory=list)
    enabled: bool = True
    notification_channels: List[str] = field(default_factory=list)
    
    # Alert state
    triggered: bool = False
    last_triggered: Optional[datetime] = None
    trigger_count: int = 0

class CostMonitor:
    """Main cost monitoring service"""
    
    def __init__(self):
        self.usage_data: List[ResourceUsage] = []
        self.cost_metrics: Dict[str, CostMetrics] = {}
        self.alerts: Dict[str, CostAlert] = {}
        self.monitoring_enabled = True
        
        # Configuration
        self.config = {
            "collection_interval_minutes": 5,
            "data_retention_days": 90,
            "alert_cooldown_minutes": 60,
            "currency": "BRL",
            "tax_rate": 0.0  # Additional taxes/fees
        }
        
        # Pricing data (simplified - would come from cloud provider APIs)
        self.pricing = {
            ResourceType.COMPUTE: {
                "t3.micro": 0.0116,  # USD per hour
                "t3.small": 0.0232,
                "t3.medium": 0.0464
            },
            ResourceType.STORAGE: {
                "standard": 0.023,  # USD per GB per month
                "ssd": 0.10
            },
            ResourceType.DATABASE: {
                "db.t3.micro": 0.017,  # USD per hour
                "db.t3.small": 0.034
            },
            ResourceType.NETWORK: {
                "data_transfer": 0.09,  # USD per GB
                "requests": 0.0000004  # USD per request
            }
        }
        
        # Monitoring task
        self._monitoring_task: Optional[asyncio.Task] = None
        
        # Callbacks
        self.cost_callbacks: List[Callable] = []
        self.alert_callbacks: List[Callable] = []
    
    async def start_monitoring(self) -> None:
        """Start cost monitoring"""
        if self._monitoring_task and not self._monitoring_task.done():
            return
        
        self.monitoring_enabled = True
        self._monitoring_task = asyncio.create_task(self._monitoring_loop())
        logger.info("Cost monitoring started")
    
    async def stop_monitoring(self) -> None:
        """Stop cost monitoring"""
        self.monitoring_enabled = False
        
        if self._monitoring_task:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Cost monitoring stopped")
    
    async def _monitoring_loop(self) -> None:
        """Main monitoring loop"""
        while self.monitoring_enabled:
            try:
                # Collect usage data
                await self._collect_usage_data()
                
                # Calculate costs
                await self._calculate_costs()
                
                # Check alerts
                await self._check_alerts()
                
                # Cleanup old data
                await self._cleanup_old_data()
                
                # Wait for next interval
                await asyncio.sleep(self.config["collection_interval_minutes"] * 60)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cost monitoring loop: {e}")
                await asyncio.sleep(60)  # Wait before retrying
    
    async def _collect_usage_data(self) -> None:
        """Collect current resource usage"""
        current_time = datetime.now()
        
        # Simulate collecting usage data from various sources
        # In production, this would integrate with cloud provider APIs
        
        # Compute resources
        compute_usage = ResourceUsage(
            resource_id="web-server-1",
            resource_type=ResourceType.COMPUTE,
            usage_amount=1.0,  # 1 hour
            unit="hours",
            cost_per_unit=self.pricing[ResourceType.COMPUTE]["t3.small"],
            total_cost=self.pricing[ResourceType.COMPUTE]["t3.small"],
            timestamp=current_time,
            metadata={"instance_type": "t3.small", "region": "us-east-1"}
        )
        self.usage_data.append(compute_usage)
        
        # Storage resources
        storage_usage = ResourceUsage(
            resource_id="app-storage",
            resource_type=ResourceType.STORAGE,
            usage_amount=50.0,  # 50 GB
            unit="GB",
            cost_per_unit=self.pricing[ResourceType.STORAGE]["standard"] / 30 / 24,  # Per hour
            total_cost=(self.pricing[ResourceType.STORAGE]["standard"] / 30 / 24) * 50,
            timestamp=current_time,
            metadata={"storage_type": "standard", "location": "us-east-1"}
        )
        self.usage_data.append(storage_usage)
        
        # Database resources
        db_usage = ResourceUsage(
            resource_id="postgres-main",
            resource_type=ResourceType.DATABASE,
            usage_amount=1.0,  # 1 hour
            unit="hours",
            cost_per_unit=self.pricing[ResourceType.DATABASE]["db.t3.micro"],
            total_cost=self.pricing[ResourceType.DATABASE]["db.t3.micro"],
            timestamp=current_time,
            metadata={"db_type": "postgres", "instance_class": "db.t3.micro"}
        )
        self.usage_data.append(db_usage)
        
        # Network resources
        network_usage = ResourceUsage(
            resource_id="data-transfer",
            resource_type=ResourceType.NETWORK,
            usage_amount=5.0,  # 5 GB transferred
            unit="GB",
            cost_per_unit=self.pricing[ResourceType.NETWORK]["data_transfer"],
            total_cost=self.pricing[ResourceType.NETWORK]["data_transfer"] * 5,
            timestamp=current_time,
            metadata={"transfer_type": "outbound"}
        )
        self.usage_data.append(network_usage)
        
        logger.debug(f"Collected usage data for {len(self.usage_data)} resources")
    
    async def _calculate_costs(self) -> None:
        """Calculate cost metrics for different periods"""
        current_time = datetime.now()
        
        # Calculate daily costs
        daily_start = current_time.replace(hour=0, minute=0, second=0, microsecond=0)
        daily_metrics = await self._calculate_period_costs(
            CostPeriod.DAILY, daily_start, current_time
        )
        self.cost_metrics["daily"] = daily_metrics
        
        # Calculate monthly costs
        monthly_start = current_time.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        monthly_metrics = await self._calculate_period_costs(
            CostPeriod.MONTHLY, monthly_start, current_time
        )
        self.cost_metrics["monthly"] = monthly_metrics
        
        # Project monthly cost
        if daily_metrics.total_cost > 0:
            days_in_month = 30  # Simplified
            days_elapsed = (current_time - monthly_start).days + 1
            monthly_metrics.projected_monthly_cost = (
                monthly_metrics.total_cost / days_elapsed * days_in_month
            )
        
        # Notify callbacks
        await self._notify_cost_callbacks(daily_metrics)
    
    async def _calculate_period_costs(self, period: CostPeriod, 
                                    start_time: datetime, 
                                    end_time: datetime) -> CostMetrics:
        """Calculate costs for a specific period"""
        period_usage = [
            usage for usage in self.usage_data
            if start_time <= usage.timestamp <= end_time
        ]
        
        total_cost = sum(usage.total_cost for usage in period_usage)
        
        # Cost by resource type
        cost_by_resource = {}
        for resource_type in ResourceType:
            type_cost = sum(
                usage.total_cost for usage in period_usage
                if usage.resource_type == resource_type
            )
            if type_cost > 0:
                cost_by_resource[resource_type] = type_cost
        
        # Cost by service (simplified)
        cost_by_service = {
            "web_servers": cost_by_resource.get(ResourceType.COMPUTE, 0),
            "database": cost_by_resource.get(ResourceType.DATABASE, 0),
            "storage": cost_by_resource.get(ResourceType.STORAGE, 0),
            "networking": cost_by_resource.get(ResourceType.NETWORK, 0)
        }
        
        return CostMetrics(
            period=period,
            start_time=start_time,
            end_time=end_time,
            total_cost=total_cost,
            cost_by_resource=cost_by_resource,
            cost_by_service=cost_by_service,
            usage_metrics=period_usage
        )
    
    async def _check_alerts(self) -> None:
        """Check cost alerts"""
        current_time = datetime.now()
        
        for alert in self.alerts.values():
            if not alert.enabled:
                continue
            
            # Check cooldown
            if (alert.last_triggered and 
                (current_time - alert.last_triggered).total_seconds() < 
                self.config["alert_cooldown_minutes"] * 60):
                continue
            
            # Get relevant metrics
            period_key = alert.period.value
            if period_key not in self.cost_metrics:
                continue
            
            metrics = self.cost_metrics[period_key]
            should_trigger = False
            
            # Check threshold
            if alert.threshold_type == "absolute":
                should_trigger = metrics.total_cost >= alert.threshold_amount
            elif alert.threshold_type == "projected_monthly":
                should_trigger = metrics.projected_monthly_cost >= alert.threshold_amount
            
            # Filter by resource types if specified
            if alert.resource_types and should_trigger:
                filtered_cost = sum(
                    metrics.cost_by_resource.get(rt, 0)
                    for rt in alert.resource_types
                )
                should_trigger = filtered_cost >= alert.threshold_amount
            
            if should_trigger and not alert.triggered:
                await self._trigger_alert(alert, metrics)
            elif not should_trigger and alert.triggered:
                alert.triggered = False
    
    async def _trigger_alert(self, alert: CostAlert, metrics: CostMetrics) -> None:
        """Trigger a cost alert"""
        alert.triggered = True
        alert.last_triggered = datetime.now()
        alert.trigger_count += 1
        
        alert_data = {
            "alert": alert,
            "metrics": metrics,
            "message": f"Cost alert '{alert.name}' triggered: "
                      f"{self.config['currency']} {metrics.total_cost:.2f}"
        }
        
        logger.warning(f"Cost alert triggered: {alert.name}")
        
        # Notify callbacks
        for callback in self.alert_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(alert_data)
                else:
                    callback(alert_data)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")
    
    async def _cleanup_old_data(self) -> None:
        """Clean up old usage data"""
        cutoff_time = datetime.now() - timedelta(days=self.config["data_retention_days"])
        
        initial_count = len(self.usage_data)
        self.usage_data = [
            usage for usage in self.usage_data
            if usage.timestamp > cutoff_time
        ]
        
        cleaned_count = initial_count - len(self.usage_data)
        if cleaned_count > 0:
            logger.info(f"Cleaned up {cleaned_count} old usage records")
    
    async def _notify_cost_callbacks(self, metrics: CostMetrics) -> None:
        """Notify cost update callbacks"""
        for callback in self.cost_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(metrics)
                else:
                    callback(metrics)
            except Exception as e:
                logger.error(f"Error in cost callback: {e}")
    
    # Public API methods
    
    def add_alert(self, alert: CostAlert) -> None:
        """Add a cost alert"""
        self.alerts[alert.id] = alert
        logger.info(f"Added cost alert: {alert.name}")
    
    def remove_alert(self, alert_id: str) -> bool:
        """Remove a cost alert"""
        if alert_id in self.alerts:
            del self.alerts[alert_id]
            logger.info(f"Removed cost alert: {alert_id}")
            return True
        return False
    
    def get_current_costs(self, period: CostPeriod = CostPeriod.DAILY) -> Optional[CostMetrics]:
        """Get current cost metrics"""
        return self.cost_metrics.get(period.value)
    
    def get_usage_history(self, 
                         resource_type: Optional[ResourceType] = None,
                         hours: int = 24) -> List[ResourceUsage]:
        """Get usage history"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        history = [
            usage for usage in self.usage_data
            if usage.timestamp > cutoff_time
        ]
        
        if resource_type:
            history = [
                usage for usage in history
                if usage.resource_type == resource_type
            ]
        
        return sorted(history, key=lambda x: x.timestamp, reverse=True)
    
    def add_cost_callback(self, callback: Callable) -> None:
        """Add cost update callback"""
        self.cost_callbacks.append(callback)
    
    def add_alert_callback(self, callback: Callable) -> None:
        """Add alert callback"""
        self.alert_callbacks.append(callback)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics"""
        current_daily = self.cost_metrics.get("daily")
        current_monthly = self.cost_metrics.get("monthly")
        
        return {
            "monitoring_enabled": self.monitoring_enabled,
            "total_usage_records": len(self.usage_data),
            "active_alerts": len([a for a in self.alerts.values() if a.enabled]),
            "triggered_alerts": len([a for a in self.alerts.values() if a.triggered]),
            "current_daily_cost": current_daily.total_cost if current_daily else 0,
            "current_monthly_cost": current_monthly.total_cost if current_monthly else 0,
            "projected_monthly_cost": current_monthly.projected_monthly_cost if current_monthly else 0,
            "currency": self.config["currency"]
        }
    
    async def force_cost_calculation(self) -> None:
        """Force immediate cost calculation"""
        await self._collect_usage_data()
        await self._calculate_costs()
        logger.info("Forced cost calculation completed")

# Global cost monitor instance
cost_monitor = CostMonitor()