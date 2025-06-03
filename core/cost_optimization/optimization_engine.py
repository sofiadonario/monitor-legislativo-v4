"""
Optimization Engine for Monitor Legislativo v4
Provides cost optimization recommendations

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import statistics

from .cost_monitor import CostMonitor, ResourceUsage, ResourceType

logger = logging.getLogger(__name__)

class OptimizationType(Enum):
    """Types of optimizations"""
    RIGHT_SIZING = "right_sizing"
    RESERVED_INSTANCES = "reserved_instances"
    SPOT_INSTANCES = "spot_instances"
    STORAGE_OPTIMIZATION = "storage_optimization"
    NETWORK_OPTIMIZATION = "network_optimization"
    SCHEDULE_BASED = "schedule_based"
    AUTO_SCALING = "auto_scaling"
    RESOURCE_CLEANUP = "resource_cleanup"

class Priority(Enum):
    """Recommendation priority"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SavingsEstimate:
    """Estimated savings from optimization"""
    monthly_savings: float
    annual_savings: float
    percentage_savings: float
    implementation_cost: float = 0.0
    payback_period_months: float = 0.0

@dataclass
class OptimizationRecommendation:
    """Optimization recommendation"""
    id: str
    type: OptimizationType
    title: str
    description: str
    priority: Priority
    
    # Target resources
    affected_resources: List[str] = field(default_factory=list)
    resource_type: Optional[ResourceType] = None
    
    # Savings
    savings_estimate: Optional[SavingsEstimate] = None
    
    # Implementation
    implementation_steps: List[str] = field(default_factory=list)
    implementation_complexity: str = "medium"  # low, medium, high
    estimated_implementation_hours: float = 0.0
    
    # Risk assessment
    risk_level: str = "low"  # low, medium, high
    potential_impacts: List[str] = field(default_factory=list)
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    status: str = "pending"  # pending, approved, implemented, rejected
    tags: List[str] = field(default_factory=list)

class OptimizationEngine:
    """Engine for generating cost optimization recommendations"""
    
    def __init__(self, cost_monitor: CostMonitor):
        self.cost_monitor = cost_monitor
        self.recommendations: Dict[str, OptimizationRecommendation] = {}
        
        # Analysis configuration
        self.config = {
            "analysis_period_days": 30,
            "min_savings_threshold": 5.0,  # Minimum $5/month savings
            "utilization_threshold_low": 0.2,  # 20% utilization considered low
            "utilization_threshold_high": 0.8,  # 80% utilization considered high
            "cost_spike_threshold": 2.0,  # 2x normal cost considered spike
        }
        
        # Optimization rules
        self.optimization_rules = [
            self._analyze_compute_right_sizing,
            self._analyze_storage_optimization,
            self._analyze_reserved_instances,
            self._analyze_unused_resources,
            self._analyze_network_optimization,
            self._analyze_schedule_opportunities,
            self._analyze_auto_scaling_opportunities
        ]
    
    async def generate_recommendations(self) -> List[OptimizationRecommendation]:
        """Generate optimization recommendations"""
        logger.info("Generating cost optimization recommendations")
        
        # Clear previous recommendations
        self.recommendations.clear()
        
        # Run all optimization rules
        for rule in self.optimization_rules:
            try:
                recommendations = await rule()
                for rec in recommendations:
                    self.recommendations[rec.id] = rec
            except Exception as e:
                logger.error(f"Error in optimization rule {rule.__name__}: {e}")
        
        # Sort by potential savings
        sorted_recommendations = sorted(
            self.recommendations.values(),
            key=lambda r: r.savings_estimate.monthly_savings if r.savings_estimate else 0,
            reverse=True
        )
        
        logger.info(f"Generated {len(sorted_recommendations)} optimization recommendations")
        return sorted_recommendations
    
    async def _analyze_compute_right_sizing(self) -> List[OptimizationRecommendation]:
        """Analyze compute resource right-sizing opportunities"""
        recommendations = []
        
        # Get compute usage history
        usage_history = self.cost_monitor.get_usage_history(
            resource_type=ResourceType.COMPUTE,
            hours=24 * self.config["analysis_period_days"]
        )
        
        if not usage_history:
            return recommendations
        
        # Group by resource
        resource_usage = {}
        for usage in usage_history:
            resource_id = usage.resource_id
            if resource_id not in resource_usage:
                resource_usage[resource_id] = []
            resource_usage[resource_id].append(usage)
        
        # Analyze each resource
        for resource_id, usages in resource_usage.items():
            if len(usages) < 10:  # Need sufficient data
                continue
            
            # Calculate average utilization (simplified)
            avg_cost = statistics.mean(usage.total_cost for usage in usages)
            current_instance_type = usages[0].metadata.get("instance_type", "unknown")
            
            # Simulate utilization analysis
            simulated_cpu_utilization = 0.3  # 30% average utilization
            
            if simulated_cpu_utilization < self.config["utilization_threshold_low"]:
                # Recommend downsizing
                savings_estimate = SavingsEstimate(
                    monthly_savings=avg_cost * 24 * 30 * 0.4,  # 40% savings
                    annual_savings=avg_cost * 24 * 365 * 0.4,
                    percentage_savings=40.0
                )
                
                recommendation = OptimizationRecommendation(
                    id=f"rightsize_{resource_id}",
                    type=OptimizationType.RIGHT_SIZING,
                    title=f"Downsize {resource_id}",
                    description=f"Resource {resource_id} shows low utilization ({simulated_cpu_utilization*100:.1f}%). "
                               f"Consider downsizing from {current_instance_type}.",
                    priority=Priority.MEDIUM,
                    affected_resources=[resource_id],
                    resource_type=ResourceType.COMPUTE,
                    savings_estimate=savings_estimate,
                    implementation_steps=[
                        "1. Monitor resource during peak hours",
                        "2. Test application performance with smaller instance",
                        "3. Schedule downtime for instance resize",
                        "4. Resize instance and monitor performance"
                    ],
                    implementation_complexity="medium",
                    estimated_implementation_hours=4.0,
                    risk_level="medium",
                    potential_impacts=["Temporary service downtime", "Potential performance impact"],
                    tags=["compute", "right-sizing", "cost-savings"]
                )
                
                recommendations.append(recommendation)
        
        return recommendations
    
    async def _analyze_storage_optimization(self) -> List[OptimizationRecommendation]:
        """Analyze storage optimization opportunities"""
        recommendations = []
        
        # Get storage usage history
        usage_history = self.cost_monitor.get_usage_history(
            resource_type=ResourceType.STORAGE,
            hours=24 * self.config["analysis_period_days"]
        )
        
        if not usage_history:
            return recommendations
        
        # Analyze storage patterns
        storage_usage = {}
        for usage in usage_history:
            resource_id = usage.resource_id
            if resource_id not in storage_usage:
                storage_usage[resource_id] = []
            storage_usage[resource_id].append(usage)
        
        for resource_id, usages in storage_usage.items():
            if len(usages) < 5:
                continue
            
            storage_type = usages[0].metadata.get("storage_type", "standard")
            avg_size_gb = statistics.mean(usage.usage_amount for usage in usages)
            
            # Check for optimization opportunities
            if storage_type == "ssd" and avg_size_gb > 100:
                # Recommend storage tiering
                savings_estimate = SavingsEstimate(
                    monthly_savings=avg_size_gb * 0.077,  # Difference between SSD and standard
                    annual_savings=avg_size_gb * 0.077 * 12,
                    percentage_savings=77.0
                )
                
                recommendation = OptimizationRecommendation(
                    id=f"storage_tier_{resource_id}",
                    type=OptimizationType.STORAGE_OPTIMIZATION,
                    title=f"Optimize storage tiering for {resource_id}",
                    description=f"Large SSD storage ({avg_size_gb:.1f} GB) could benefit from tiering. "
                               f"Move infrequently accessed data to standard storage.",
                    priority=Priority.LOW,
                    affected_resources=[resource_id],
                    resource_type=ResourceType.STORAGE,
                    savings_estimate=savings_estimate,
                    implementation_steps=[
                        "1. Analyze data access patterns",
                        "2. Identify infrequently accessed data",
                        "3. Set up automated tiering policy",
                        "4. Monitor storage performance"
                    ],
                    implementation_complexity="low",
                    estimated_implementation_hours=2.0,
                    risk_level="low",
                    potential_impacts=["Slight increase in access time for cold data"],
                    tags=["storage", "tiering", "cost-optimization"]
                )
                
                recommendations.append(recommendation)
        
        return recommendations
    
    async def _analyze_reserved_instances(self) -> List[OptimizationRecommendation]:
        """Analyze reserved instance opportunities"""
        recommendations = []
        
        # Get compute usage for consistent workloads
        usage_history = self.cost_monitor.get_usage_history(
            resource_type=ResourceType.COMPUTE,
            hours=24 * self.config["analysis_period_days"]
        )
        
        if not usage_history:
            return recommendations
        
        # Find consistent usage patterns
        resource_consistency = {}
        for usage in usage_history:
            resource_id = usage.resource_id
            if resource_id not in resource_consistency:
                resource_consistency[resource_id] = []
            resource_consistency[resource_id].append(usage.timestamp)
        
        for resource_id, timestamps in resource_consistency.items():
            # Check if resource runs consistently (simplified)
            days_running = len(set(ts.date() for ts in timestamps))
            total_days = self.config["analysis_period_days"]
            
            consistency_ratio = days_running / total_days
            
            if consistency_ratio > 0.8:  # Running 80%+ of the time
                # Recommend reserved instance
                monthly_on_demand_cost = 100.0  # Simplified calculation
                reserved_instance_savings = monthly_on_demand_cost * 0.3  # 30% savings
                
                savings_estimate = SavingsEstimate(
                    monthly_savings=reserved_instance_savings,
                    annual_savings=reserved_instance_savings * 12,
                    percentage_savings=30.0,
                    implementation_cost=monthly_on_demand_cost * 12,  # Upfront payment
                    payback_period_months=1.0
                )
                
                recommendation = OptimizationRecommendation(
                    id=f"reserved_{resource_id}",
                    type=OptimizationType.RESERVED_INSTANCES,
                    title=f"Purchase reserved instance for {resource_id}",
                    description=f"Resource {resource_id} shows consistent usage ({consistency_ratio*100:.1f}% uptime). "
                               f"Reserved instance could save 30% on compute costs.",
                    priority=Priority.HIGH,
                    affected_resources=[resource_id],
                    resource_type=ResourceType.COMPUTE,
                    savings_estimate=savings_estimate,
                    implementation_steps=[
                        "1. Confirm long-term usage requirements",
                        "2. Compare reserved instance options",
                        "3. Purchase appropriate reserved instance",
                        "4. Monitor cost savings"
                    ],
                    implementation_complexity="low",
                    estimated_implementation_hours=1.0,
                    risk_level="low",
                    potential_impacts=["Upfront payment required", "Reduced flexibility"],
                    tags=["compute", "reserved-instances", "long-term-savings"]
                )
                
                recommendations.append(recommendation)
        
        return recommendations
    
    async def _analyze_unused_resources(self) -> List[OptimizationRecommendation]:
        """Analyze unused or idle resources"""
        recommendations = []
        
        # Look for resources with very low or zero usage
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(days=7)  # Last 7 days
        
        all_usage = self.cost_monitor.get_usage_history(hours=24 * 7)
        
        # Group by resource
        resource_activity = {}
        for usage in all_usage:
            resource_id = usage.resource_id
            if resource_id not in resource_activity:
                resource_activity[resource_id] = []
            resource_activity[resource_id].append(usage)
        
        # Find idle resources
        for resource_id, usages in resource_activity.items():
            if not usages:
                continue
            
            latest_usage = max(usages, key=lambda u: u.timestamp)
            
            # If no recent usage, recommend cleanup
            if latest_usage.timestamp < cutoff_time:
                monthly_cost = sum(u.total_cost for u in usages) * 4  # Approximate monthly
                
                savings_estimate = SavingsEstimate(
                    monthly_savings=monthly_cost,
                    annual_savings=monthly_cost * 12,
                    percentage_savings=100.0
                )
                
                recommendation = OptimizationRecommendation(
                    id=f"cleanup_{resource_id}",
                    type=OptimizationType.RESOURCE_CLEANUP,
                    title=f"Remove unused resource {resource_id}",
                    description=f"Resource {resource_id} hasn't been used for over a week. "
                               f"Consider decommissioning to save ${monthly_cost:.2f}/month.",
                    priority=Priority.HIGH,
                    affected_resources=[resource_id],
                    savings_estimate=savings_estimate,
                    implementation_steps=[
                        "1. Verify resource is truly unused",
                        "2. Check for dependencies",
                        "3. Create backup if needed",
                        "4. Decommission resource"
                    ],
                    implementation_complexity="low",
                    estimated_implementation_hours=1.0,
                    risk_level="medium",
                    potential_impacts=["Data loss if not properly backed up"],
                    tags=["cleanup", "unused-resources", "immediate-savings"]
                )
                
                recommendations.append(recommendation)
        
        return recommendations
    
    async def _analyze_network_optimization(self) -> List[OptimizationRecommendation]:
        """Analyze network optimization opportunities"""
        recommendations = []
        
        # Get network usage
        network_usage = self.cost_monitor.get_usage_history(
            resource_type=ResourceType.NETWORK,
            hours=24 * self.config["analysis_period_days"]
        )
        
        if not network_usage:
            return recommendations
        
        # Analyze data transfer patterns
        total_transfer_gb = sum(usage.usage_amount for usage in network_usage)
        monthly_transfer_gb = total_transfer_gb * 30 / self.config["analysis_period_days"]
        
        if monthly_transfer_gb > 1000:  # High data transfer
            # Recommend CDN
            current_monthly_cost = monthly_transfer_gb * 0.09  # Current rate
            cdn_monthly_cost = monthly_transfer_gb * 0.02  # CDN rate
            
            savings_estimate = SavingsEstimate(
                monthly_savings=current_monthly_cost - cdn_monthly_cost,
                annual_savings=(current_monthly_cost - cdn_monthly_cost) * 12,
                percentage_savings=77.8,
                implementation_cost=100.0  # Setup cost
            )
            
            recommendation = OptimizationRecommendation(
                id="network_cdn_optimization",
                type=OptimizationType.NETWORK_OPTIMIZATION,
                title="Implement CDN for data transfer optimization",
                description=f"High data transfer volume ({monthly_transfer_gb:.0f} GB/month) "
                           f"could benefit from CDN implementation.",
                priority=Priority.MEDIUM,
                resource_type=ResourceType.NETWORK,
                savings_estimate=savings_estimate,
                implementation_steps=[
                    "1. Analyze content delivery patterns",
                    "2. Choose appropriate CDN provider",
                    "3. Configure CDN endpoints",
                    "4. Update application to use CDN",
                    "5. Monitor performance and costs"
                ],
                implementation_complexity="medium",
                estimated_implementation_hours=8.0,
                risk_level="low",
                potential_impacts=["Initial setup complexity", "Improved performance"],
                tags=["network", "cdn", "performance", "cost-optimization"]
            )
            
            recommendations.append(recommendation)
        
        return recommendations
    
    async def _analyze_schedule_opportunities(self) -> List[OptimizationRecommendation]:
        """Analyze schedule-based optimization opportunities"""
        recommendations = []
        
        # This would analyze usage patterns to identify off-hours
        # For now, provide a generic recommendation
        
        savings_estimate = SavingsEstimate(
            monthly_savings=200.0,  # Estimated savings
            annual_savings=2400.0,
            percentage_savings=25.0
        )
        
        recommendation = OptimizationRecommendation(
            id="schedule_optimization",
            type=OptimizationType.SCHEDULE_BASED,
            title="Implement scheduled scaling for non-production environments",
            description="Non-production environments could be shut down during off-hours "
                       "(nights and weekends) to reduce costs.",
            priority=Priority.MEDIUM,
            savings_estimate=savings_estimate,
            implementation_steps=[
                "1. Identify non-production environments",
                "2. Analyze usage patterns",
                "3. Create automated shutdown/startup schedules",
                "4. Test scheduling system",
                "5. Monitor cost savings"
            ],
            implementation_complexity="medium",
            estimated_implementation_hours=6.0,
            risk_level="low",
            potential_impacts=["Reduced availability for development/testing"],
            tags=["scheduling", "automation", "non-production", "cost-savings"]
        )
        
        recommendations.append(recommendation)
        return recommendations
    
    async def _analyze_auto_scaling_opportunities(self) -> List[OptimizationRecommendation]:
        """Analyze auto-scaling optimization opportunities"""
        recommendations = []
        
        # Analyze if auto-scaling could optimize costs
        savings_estimate = SavingsEstimate(
            monthly_savings=150.0,
            annual_savings=1800.0,
            percentage_savings=20.0,
            implementation_cost=50.0
        )
        
        recommendation = OptimizationRecommendation(
            id="auto_scaling_optimization",
            type=OptimizationType.AUTO_SCALING,
            title="Implement auto-scaling for compute resources",
            description="Auto-scaling could optimize resource allocation based on demand, "
                       "reducing costs during low-usage periods.",
            priority=Priority.MEDIUM,
            resource_type=ResourceType.COMPUTE,
            savings_estimate=savings_estimate,
            implementation_steps=[
                "1. Analyze application scaling requirements",
                "2. Set up auto-scaling policies",
                "3. Configure scaling metrics and thresholds",
                "4. Test scaling behavior",
                "5. Monitor and tune scaling policies"
            ],
            implementation_complexity="high",
            estimated_implementation_hours=12.0,
            risk_level="medium",
            potential_impacts=["Complex configuration", "Potential performance variations"],
            tags=["auto-scaling", "automation", "demand-based", "optimization"]
        )
        
        recommendations.append(recommendation)
        return recommendations
    
    # Public API methods
    
    def get_recommendation(self, recommendation_id: str) -> Optional[OptimizationRecommendation]:
        """Get specific recommendation"""
        return self.recommendations.get(recommendation_id)
    
    def get_recommendations_by_type(self, optimization_type: OptimizationType) -> List[OptimizationRecommendation]:
        """Get recommendations by type"""
        return [
            rec for rec in self.recommendations.values()
            if rec.type == optimization_type
        ]
    
    def get_high_priority_recommendations(self) -> List[OptimizationRecommendation]:
        """Get high priority recommendations"""
        return [
            rec for rec in self.recommendations.values()
            if rec.priority in [Priority.HIGH, Priority.CRITICAL]
        ]
    
    def calculate_total_potential_savings(self) -> SavingsEstimate:
        """Calculate total potential savings from all recommendations"""
        monthly_total = sum(
            rec.savings_estimate.monthly_savings
            for rec in self.recommendations.values()
            if rec.savings_estimate and rec.status == "pending"
        )
        
        return SavingsEstimate(
            monthly_savings=monthly_total,
            annual_savings=monthly_total * 12,
            percentage_savings=0.0  # Would need baseline to calculate
        )
    
    def mark_recommendation_implemented(self, recommendation_id: str) -> bool:
        """Mark recommendation as implemented"""
        if recommendation_id in self.recommendations:
            self.recommendations[recommendation_id].status = "implemented"
            logger.info(f"Marked recommendation {recommendation_id} as implemented")
            return True
        return False

# Global optimization engine instance (will be initialized with cost_monitor)
optimization_engine = None

def initialize_optimization_engine(cost_monitor: CostMonitor) -> OptimizationEngine:
    """Initialize the optimization engine with cost monitor"""
    global optimization_engine
    optimization_engine = OptimizationEngine(cost_monitor)
    return optimization_engine