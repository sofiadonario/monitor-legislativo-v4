"""
Multi-Region Deployment for Monitor Legislativo v4
Infrastructure for global deployment and high availability

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

from .region_manager import (
    RegionManager,
    Region,
    RegionStatus,
    RegionConfig,
    region_manager
)

from .deployment_orchestrator import (
    DeploymentOrchestrator,
    Deployment,
    DeploymentStatus,
    DeploymentStrategy,
    deployment_orchestrator
)

from .traffic_router import (
    TrafficRouter,
    RoutingRule,
    RoutingStrategy,
    HealthCheckConfig,
    traffic_router
)

from .data_sync import (
    DataSyncManager,
    SyncStrategy,
    SyncStatus,
    ReplicationConfig,
    data_sync_manager
)

from .failover_manager import (
    FailoverManager,
    FailoverPlan,
    FailoverTrigger,
    RecoveryAction,
    failover_manager
)

from .monitoring import (
    MultiRegionMonitor,
    RegionHealth,
    CrossRegionMetrics,
    LatencyMonitor,
    multi_region_monitor
)

__all__ = [
    # Region management
    "RegionManager",
    "Region", 
    "RegionStatus",
    "RegionConfig",
    "region_manager",
    
    # Deployment orchestration
    "DeploymentOrchestrator",
    "Deployment",
    "DeploymentStatus", 
    "DeploymentStrategy",
    "deployment_orchestrator",
    
    # Traffic routing
    "TrafficRouter",
    "RoutingRule",
    "RoutingStrategy",
    "HealthCheckConfig",
    "traffic_router",
    
    # Data synchronization
    "DataSyncManager",
    "SyncStrategy",
    "SyncStatus",
    "ReplicationConfig", 
    "data_sync_manager",
    
    # Failover management
    "FailoverManager",
    "FailoverPlan",
    "FailoverTrigger",
    "RecoveryAction",
    "failover_manager",
    
    # Monitoring
    "MultiRegionMonitor",
    "RegionHealth",
    "CrossRegionMetrics",
    "LatencyMonitor",
    "multi_region_monitor"
]