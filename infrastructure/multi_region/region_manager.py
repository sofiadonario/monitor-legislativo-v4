"""
Multi-Region Manager for Monitor Legislativo v4
Manages deployment across multiple regions for high availability

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import json

logger = logging.getLogger(__name__)

class RegionStatus(Enum):
    """Status of a region"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    DEPLOYING = "deploying"
    DRAINING = "draining"
    FAILED = "failed"
    MAINTENANCE = "maintenance"

class RegionTier(Enum):
    """Region tier classification"""
    PRIMARY = "primary"
    SECONDARY = "secondary"
    DISASTER_RECOVERY = "disaster_recovery"

@dataclass
class RegionConfig:
    """Configuration for a region"""
    # Infrastructure
    instance_types: List[str] = field(default_factory=lambda: ["t3.medium"])
    min_instances: int = 2
    max_instances: int = 10
    auto_scaling: bool = True
    
    # Database
    database_tier: str = "standard"
    read_replicas: int = 1
    backup_retention_days: int = 7
    
    # Storage
    storage_type: str = "gp3"
    storage_size_gb: int = 100
    
    # Network
    vpc_cidr: str = "10.0.0.0/16"
    availability_zones: List[str] = field(default_factory=lambda: ["a", "b"])
    
    # Monitoring
    health_check_path: str = "/health"
    health_check_interval: int = 30
    
    # Custom settings
    environment_variables: Dict[str, str] = field(default_factory=dict)
    feature_flags: Dict[str, bool] = field(default_factory=dict)

@dataclass
class Region:
    """Represents a deployment region"""
    id: str
    name: str
    cloud_region: str  # e.g., "us-east-1", "sa-east-1"
    tier: RegionTier
    status: RegionStatus = RegionStatus.INACTIVE
    
    # Configuration
    config: RegionConfig = field(default_factory=RegionConfig)
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    last_deployment: Optional[datetime] = None
    last_health_check: Optional[datetime] = None
    
    # Metrics
    current_instances: int = 0
    cpu_utilization: float = 0.0
    memory_utilization: float = 0.0
    request_count: int = 0
    error_rate: float = 0.0
    latency_ms: float = 0.0
    
    # Traffic
    traffic_percentage: float = 0.0
    target_traffic_percentage: float = 0.0

class RegionManager:
    """Manages multiple regions for the application"""
    
    def __init__(self):
        self.regions: Dict[str, Region] = {}
        self.region_templates: Dict[str, RegionConfig] = {}
        
        # Global configuration
        self.global_config = {
            "default_tier": RegionTier.SECONDARY,
            "min_active_regions": 2,
            "max_regions": 10,
            "health_check_timeout": 30,
            "deployment_timeout_minutes": 30,
            "traffic_shift_interval": 300,  # 5 minutes
        }
        
        # Initialize default regions
        self._initialize_default_regions()
        
        # Monitoring
        self._monitoring_task: Optional[asyncio.Task] = None
        self.monitoring_enabled = False
    
    def _initialize_default_regions(self) -> None:
        """Initialize default regions for Brazil"""
        
        # Primary region - São Paulo
        sao_paulo = Region(
            id="sa-east-1",
            name="São Paulo",
            cloud_region="sa-east-1",
            tier=RegionTier.PRIMARY,
            status=RegionStatus.ACTIVE,
            config=RegionConfig(
                min_instances=3,
                max_instances=20,
                database_tier="production",
                read_replicas=2,
                backup_retention_days=30
            ),
            traffic_percentage=80.0,
            target_traffic_percentage=80.0
        )
        
        # Secondary region - North Virginia (for global reach)
        virginia = Region(
            id="us-east-1",
            name="North Virginia",
            cloud_region="us-east-1", 
            tier=RegionTier.SECONDARY,
            status=RegionStatus.ACTIVE,
            config=RegionConfig(
                min_instances=2,
                max_instances=10,
                read_replicas=1,
                backup_retention_days=14
            ),
            traffic_percentage=20.0,
            target_traffic_percentage=20.0
        )
        
        # DR region - Rio de Janeiro
        rio = Region(
            id="sa-east-2",
            name="Rio de Janeiro", 
            cloud_region="sa-east-1b",  # Simulated second Brazil region
            tier=RegionTier.DISASTER_RECOVERY,
            status=RegionStatus.INACTIVE,
            config=RegionConfig(
                min_instances=1,
                max_instances=5,
                read_replicas=0,
                backup_retention_days=7
            ),
            traffic_percentage=0.0,
            target_traffic_percentage=0.0
        )
        
        self.regions = {
            sao_paulo.id: sao_paulo,
            virginia.id: virginia,
            rio.id: rio
        }
        
        logger.info(f"Initialized {len(self.regions)} default regions")
    
    async def add_region(self, region: Region) -> bool:
        """Add a new region"""
        if region.id in self.regions:
            logger.warning(f"Region {region.id} already exists")
            return False
        
        if len(self.regions) >= self.global_config["max_regions"]:
            logger.error("Maximum number of regions reached")
            return False
        
        self.regions[region.id] = region
        logger.info(f"Added region {region.id} ({region.name})")
        
        return True
    
    async def remove_region(self, region_id: str, force: bool = False) -> bool:
        """Remove a region"""
        if region_id not in self.regions:
            return False
        
        region = self.regions[region_id]
        
        # Safety checks
        if not force:
            if region.tier == RegionTier.PRIMARY:
                logger.error("Cannot remove primary region without force flag")
                return False
            
            active_regions = self.get_active_regions()
            if len(active_regions) <= self.global_config["min_active_regions"]:
                logger.error("Cannot remove region - would fall below minimum active regions")
                return False
        
        # Drain traffic first
        if region.status == RegionStatus.ACTIVE:
            await self.drain_region(region_id)
        
        del self.regions[region_id]
        logger.info(f"Removed region {region_id}")
        
        return True
    
    async def activate_region(self, region_id: str) -> bool:
        """Activate a region"""
        if region_id not in self.regions:
            return False
        
        region = self.regions[region_id]
        
        if region.status == RegionStatus.ACTIVE:
            return True
        
        logger.info(f"Activating region {region_id}")
        
        try:
            region.status = RegionStatus.DEPLOYING
            
            # Deploy infrastructure
            await self._deploy_region_infrastructure(region)
            
            # Health check
            if await self._health_check_region(region):
                region.status = RegionStatus.ACTIVE
                region.last_deployment = datetime.now()
                logger.info(f"Successfully activated region {region_id}")
                return True
            else:
                region.status = RegionStatus.FAILED
                logger.error(f"Health check failed for region {region_id}")
                return False
                
        except Exception as e:
            region.status = RegionStatus.FAILED
            logger.error(f"Failed to activate region {region_id}: {e}")
            return False
    
    async def deactivate_region(self, region_id: str) -> bool:
        """Deactivate a region"""
        if region_id not in self.regions:
            return False
        
        region = self.regions[region_id]
        
        # Don't deactivate if it would leave too few active regions
        active_regions = self.get_active_regions()
        if len(active_regions) <= self.global_config["min_active_regions"]:
            logger.error("Cannot deactivate - would fall below minimum active regions")
            return False
        
        logger.info(f"Deactivating region {region_id}")
        
        # Drain traffic first
        await self.drain_region(region_id)
        
        region.status = RegionStatus.INACTIVE
        region.traffic_percentage = 0.0
        region.target_traffic_percentage = 0.0
        
        logger.info(f"Successfully deactivated region {region_id}")
        return True
    
    async def drain_region(self, region_id: str) -> bool:
        """Drain traffic from a region gradually"""
        if region_id not in self.regions:
            return False
        
        region = self.regions[region_id]
        
        if region.traffic_percentage == 0:
            return True
        
        logger.info(f"Draining traffic from region {region_id}")
        region.status = RegionStatus.DRAINING
        
        # Gradually reduce traffic
        steps = 10
        step_size = region.traffic_percentage / steps
        
        for i in range(steps):
            region.target_traffic_percentage = max(0, region.traffic_percentage - step_size * (i + 1))
            await self._update_traffic_routing()
            await asyncio.sleep(30)  # Wait 30 seconds between steps
        
        region.traffic_percentage = 0.0
        region.target_traffic_percentage = 0.0
        
        logger.info(f"Successfully drained region {region_id}")
        return True
    
    async def _deploy_region_infrastructure(self, region: Region) -> None:
        """Deploy infrastructure for a region"""
        logger.info(f"Deploying infrastructure for region {region.id}")
        
        # Simulate infrastructure deployment
        deployment_steps = [
            "Creating VPC and subnets",
            "Setting up security groups", 
            "Launching compute instances",
            "Configuring load balancer",
            "Setting up database",
            "Configuring monitoring",
            "Running health checks"
        ]
        
        for step in deployment_steps:
            logger.debug(f"Region {region.id}: {step}")
            await asyncio.sleep(2)  # Simulate deployment time
        
        # Update region metrics
        region.current_instances = region.config.min_instances
        region.last_deployment = datetime.now()
    
    async def _health_check_region(self, region: Region) -> bool:
        """Perform health check on a region"""
        logger.debug(f"Health checking region {region.id}")
        
        # Simulate health check
        await asyncio.sleep(1)
        
        # Update metrics
        region.last_health_check = datetime.now()
        region.cpu_utilization = 45.0  # Mock data
        region.memory_utilization = 60.0
        region.latency_ms = 150.0
        region.error_rate = 0.01
        
        # Health check passes if error rate is low
        healthy = region.error_rate < 0.05
        
        if healthy:
            logger.debug(f"Region {region.id} health check passed")
        else:
            logger.warning(f"Region {region.id} health check failed")
        
        return healthy
    
    async def _update_traffic_routing(self) -> None:
        """Update traffic routing based on target percentages"""
        # This would integrate with load balancer/DNS to update traffic routing
        logger.debug("Updating traffic routing configuration")
        
        # Simulate traffic routing update
        for region in self.regions.values():
            if region.status == RegionStatus.ACTIVE:
                # Gradually move traffic percentage toward target
                diff = region.target_traffic_percentage - region.traffic_percentage
                step = min(abs(diff), 5.0)  # Max 5% change per update
                
                if diff > 0:
                    region.traffic_percentage = min(
                        region.target_traffic_percentage,
                        region.traffic_percentage + step
                    )
                elif diff < 0:
                    region.traffic_percentage = max(
                        region.target_traffic_percentage,
                        region.traffic_percentage - step
                    )
    
    async def start_monitoring(self) -> None:
        """Start region monitoring"""
        if self.monitoring_enabled:
            return
        
        self.monitoring_enabled = True
        self._monitoring_task = asyncio.create_task(self._monitoring_loop())
        logger.info("Started multi-region monitoring")
    
    async def stop_monitoring(self) -> None:
        """Stop region monitoring"""
        self.monitoring_enabled = False
        
        if self._monitoring_task:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Stopped multi-region monitoring")
    
    async def _monitoring_loop(self) -> None:
        """Main monitoring loop"""
        while self.monitoring_enabled:
            try:
                # Health check all active regions
                for region in self.get_active_regions():
                    await self._health_check_region(region)
                
                # Update traffic routing
                await self._update_traffic_routing()
                
                # Check for failover conditions
                await self._check_failover_conditions()
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(60)
    
    async def _check_failover_conditions(self) -> None:
        """Check if failover is needed"""
        for region in self.regions.values():
            if region.status != RegionStatus.ACTIVE:
                continue
            
            # Check if region is unhealthy
            if (region.error_rate > 0.1 or  # > 10% error rate
                region.latency_ms > 5000):  # > 5 second latency
                
                logger.warning(f"Region {region.id} showing poor health metrics")
                
                if region.tier == RegionTier.PRIMARY:
                    await self._initiate_failover(region)
    
    async def _initiate_failover(self, failed_region: Region) -> None:
        """Initiate failover from failed primary region"""
        logger.critical(f"Initiating failover from primary region {failed_region.id}")
        
        # Find best secondary region to promote
        secondary_regions = [
            r for r in self.regions.values()
            if r.tier == RegionTier.SECONDARY and r.status == RegionStatus.ACTIVE
        ]
        
        if not secondary_regions:
            logger.critical("No healthy secondary regions available for failover!")
            return
        
        # Choose secondary with lowest latency
        best_secondary = min(secondary_regions, key=lambda r: r.latency_ms)
        
        logger.info(f"Promoting region {best_secondary.id} to primary")
        
        # Update tiers
        failed_region.tier = RegionTier.SECONDARY
        best_secondary.tier = RegionTier.PRIMARY
        
        # Redirect traffic
        failed_region.target_traffic_percentage = 0.0
        best_secondary.target_traffic_percentage = 80.0
        
        # Mark failed region for maintenance
        failed_region.status = RegionStatus.MAINTENANCE
    
    # Public API methods
    
    def get_region(self, region_id: str) -> Optional[Region]:
        """Get region by ID"""
        return self.regions.get(region_id)
    
    def get_active_regions(self) -> List[Region]:
        """Get all active regions"""
        return [r for r in self.regions.values() if r.status == RegionStatus.ACTIVE]
    
    def get_primary_region(self) -> Optional[Region]:
        """Get primary region"""
        primary_regions = [r for r in self.regions.values() if r.tier == RegionTier.PRIMARY]
        return primary_regions[0] if primary_regions else None
    
    def get_region_summary(self) -> Dict[str, Any]:
        """Get summary of all regions"""
        active_regions = self.get_active_regions()
        
        return {
            "total_regions": len(self.regions),
            "active_regions": len(active_regions),
            "primary_region": self.get_primary_region().id if self.get_primary_region() else None,
            "total_traffic": sum(r.traffic_percentage for r in active_regions),
            "total_instances": sum(r.current_instances for r in active_regions),
            "average_latency": sum(r.latency_ms for r in active_regions) / len(active_regions) if active_regions else 0,
            "average_error_rate": sum(r.error_rate for r in active_regions) / len(active_regions) if active_regions else 0,
            "regions": {
                r.id: {
                    "name": r.name,
                    "status": r.status.value,
                    "tier": r.tier.value,
                    "traffic_percentage": r.traffic_percentage,
                    "instances": r.current_instances,
                    "latency_ms": r.latency_ms,
                    "error_rate": r.error_rate
                }
                for r in self.regions.values()
            }
        }

# Global region manager instance
region_manager = RegionManager()