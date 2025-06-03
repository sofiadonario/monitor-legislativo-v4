"""
Capacity Planner for Monitor Legislativo v4
Automated capacity planning and resource forecasting

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
import math

logger = logging.getLogger(__name__)

class ResourceType(Enum):
    """Types of resources to plan for"""
    CPU = "cpu"
    MEMORY = "memory"
    STORAGE = "storage"
    NETWORK = "network"
    DATABASE = "database"
    CACHE = "cache"

class TimeHorizon(Enum):
    """Planning time horizons"""
    SHORT_TERM = "1_month"
    MEDIUM_TERM = "3_months"
    LONG_TERM = "12_months"

@dataclass
class ResourceRequirement:
    """Resource requirement specification"""
    resource_type: ResourceType
    current_capacity: float
    current_utilization: float
    required_capacity: float
    growth_rate: float
    unit: str
    confidence: float = 0.8

@dataclass
class GrowthProjection:
    """Growth projection data"""
    time_horizon: TimeHorizon
    growth_rate_monthly: float
    seasonal_factor: float = 1.0
    confidence_interval: Tuple[float, float] = (0.0, 0.0)
    factors: List[str] = field(default_factory=list)

@dataclass
class CapacityPlan:
    """Complete capacity plan"""
    plan_id: str
    created_at: datetime
    time_horizon: TimeHorizon
    
    # Current state
    current_metrics: Dict[ResourceType, float] = field(default_factory=dict)
    current_utilization: Dict[ResourceType, float] = field(default_factory=dict)
    
    # Projections
    growth_projections: Dict[ResourceType, GrowthProjection] = field(default_factory=dict)
    resource_requirements: List[ResourceRequirement] = field(default_factory=list)
    
    # Recommendations
    scaling_timeline: List[Dict[str, Any]] = field(default_factory=list)
    budget_impact: float = 0.0
    risk_assessment: Dict[str, str] = field(default_factory=dict)
    
    # Metadata
    confidence_score: float = 0.0
    assumptions: List[str] = field(default_factory=list)
    review_date: Optional[datetime] = None

class CapacityPlanner:
    """Main capacity planning engine"""
    
    def __init__(self):
        self.historical_data: Dict[str, List[Dict[str, Any]]] = {}
        self.current_plans: Dict[str, CapacityPlan] = {}
        
        # Configuration
        self.config = {
            "historical_data_days": 90,
            "min_data_points": 30,
            "default_growth_rate": 0.15,  # 15% monthly
            "safety_margin": 0.2,  # 20% buffer
            "confidence_threshold": 0.7,
            "utilization_target": 0.75,  # 75% target utilization
            "alert_threshold": 0.85  # Alert at 85% utilization
        }
        
        # Seasonal patterns (simplified)
        self.seasonal_patterns = {
            "legislative_session": {
                "peak_months": [3, 4, 5, 9, 10, 11],  # Session months
                "multiplier": 1.4
            },
            "year_end": {
                "peak_months": [11, 12],
                "multiplier": 1.2
            }
        }
    
    async def create_capacity_plan(self, time_horizon: TimeHorizon) -> CapacityPlan:
        """Create a comprehensive capacity plan"""
        logger.info(f"Creating capacity plan for {time_horizon.value}")
        
        plan_id = f"plan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Collect current metrics
        current_metrics = await self._collect_current_metrics()
        current_utilization = await self._calculate_current_utilization()
        
        # Analyze historical trends
        growth_projections = await self._analyze_growth_trends(time_horizon)
        
        # Calculate resource requirements
        resource_requirements = await self._calculate_resource_requirements(
            current_metrics, growth_projections, time_horizon
        )
        
        # Create scaling timeline
        scaling_timeline = await self._create_scaling_timeline(
            resource_requirements, time_horizon
        )
        
        # Calculate budget impact
        budget_impact = await self._calculate_budget_impact(scaling_timeline)
        
        # Assess risks
        risk_assessment = await self._assess_risks(resource_requirements)
        
        # Calculate confidence score
        confidence_score = self._calculate_confidence_score(growth_projections)
        
        plan = CapacityPlan(
            plan_id=plan_id,
            created_at=datetime.now(),
            time_horizon=time_horizon,
            current_metrics=current_metrics,
            current_utilization=current_utilization,
            growth_projections=growth_projections,
            resource_requirements=resource_requirements,
            scaling_timeline=scaling_timeline,
            budget_impact=budget_impact,
            risk_assessment=risk_assessment,
            confidence_score=confidence_score,
            assumptions=self._get_planning_assumptions(),
            review_date=datetime.now() + timedelta(days=30)
        )
        
        self.current_plans[plan_id] = plan
        logger.info(f"Created capacity plan {plan_id} with {len(resource_requirements)} requirements")
        
        return plan
    
    async def _collect_current_metrics(self) -> Dict[ResourceType, float]:
        """Collect current resource metrics"""
        # Simulate current metrics collection
        # In production, this would integrate with monitoring systems
        
        metrics = {
            ResourceType.CPU: 4.0,  # 4 vCPUs
            ResourceType.MEMORY: 16.0,  # 16 GB
            ResourceType.STORAGE: 500.0,  # 500 GB
            ResourceType.NETWORK: 1000.0,  # 1 Gbps
            ResourceType.DATABASE: 2.0,  # 2 DB instances
            ResourceType.CACHE: 4.0  # 4 GB cache
        }
        
        logger.debug(f"Collected current metrics: {metrics}")
        return metrics
    
    async def _calculate_current_utilization(self) -> Dict[ResourceType, float]:
        """Calculate current resource utilization"""
        # Simulate utilization calculation
        utilization = {
            ResourceType.CPU: 0.65,  # 65% CPU utilization
            ResourceType.MEMORY: 0.72,  # 72% memory utilization
            ResourceType.STORAGE: 0.48,  # 48% storage utilization
            ResourceType.NETWORK: 0.35,  # 35% network utilization
            ResourceType.DATABASE: 0.58,  # 58% DB utilization
            ResourceType.CACHE: 0.82  # 82% cache utilization
        }
        
        logger.debug(f"Calculated current utilization: {utilization}")
        return utilization
    
    async def _analyze_growth_trends(self, time_horizon: TimeHorizon) -> Dict[ResourceType, GrowthProjection]:
        """Analyze historical growth trends"""
        projections = {}
        
        # Simulate trend analysis based on time horizon
        base_growth_rates = {
            ResourceType.CPU: 0.08,  # 8% monthly
            ResourceType.MEMORY: 0.10,  # 10% monthly
            ResourceType.STORAGE: 0.15,  # 15% monthly
            ResourceType.NETWORK: 0.12,  # 12% monthly
            ResourceType.DATABASE: 0.06,  # 6% monthly
            ResourceType.CACHE: 0.18   # 18% monthly
        }
        
        # Adjust for time horizon
        horizon_multipliers = {
            TimeHorizon.SHORT_TERM: 1.0,
            TimeHorizon.MEDIUM_TERM: 0.8,
            TimeHorizon.LONG_TERM: 0.6
        }
        
        multiplier = horizon_multipliers[time_horizon]
        
        for resource_type, base_rate in base_growth_rates.items():
            adjusted_rate = base_rate * multiplier
            
            # Add seasonal factor
            seasonal_factor = self._get_seasonal_factor(resource_type)
            
            # Calculate confidence interval
            confidence_range = adjusted_rate * 0.3  # ±30%
            confidence_interval = (
                max(0, adjusted_rate - confidence_range),
                adjusted_rate + confidence_range
            )
            
            projection = GrowthProjection(
                time_horizon=time_horizon,
                growth_rate_monthly=adjusted_rate,
                seasonal_factor=seasonal_factor,
                confidence_interval=confidence_interval,
                factors=self._get_growth_factors(resource_type)
            )
            
            projections[resource_type] = projection
        
        logger.debug(f"Analyzed growth trends for {len(projections)} resource types")
        return projections
    
    def _get_seasonal_factor(self, resource_type: ResourceType) -> float:
        """Get seasonal adjustment factor"""
        current_month = datetime.now().month
        
        # Legislative session impact
        if current_month in self.seasonal_patterns["legislative_session"]["peak_months"]:
            return self.seasonal_patterns["legislative_session"]["multiplier"]
        
        # Year-end impact
        if current_month in self.seasonal_patterns["year_end"]["peak_months"]:
            return self.seasonal_patterns["year_end"]["multiplier"]
        
        return 1.0
    
    def _get_growth_factors(self, resource_type: ResourceType) -> List[str]:
        """Get factors influencing growth"""
        common_factors = [
            "User growth",
            "Feature expansion",
            "Data accumulation"
        ]
        
        resource_specific = {
            ResourceType.CPU: ["Query complexity", "Real-time processing"],
            ResourceType.MEMORY: ["Cache requirements", "Session data"],
            ResourceType.STORAGE: ["Document growth", "Historical data"],
            ResourceType.NETWORK: ["API usage", "File downloads"],
            ResourceType.DATABASE: ["Data volume", "Query complexity"],
            ResourceType.CACHE: ["Cache hit rate", "Session management"]
        }
        
        return common_factors + resource_specific.get(resource_type, [])
    
    async def _calculate_resource_requirements(self, 
                                             current_metrics: Dict[ResourceType, float],
                                             growth_projections: Dict[ResourceType, GrowthProjection],
                                             time_horizon: TimeHorizon) -> List[ResourceRequirement]:
        """Calculate future resource requirements"""
        requirements = []
        
        # Time periods
        months_ahead = {
            TimeHorizon.SHORT_TERM: 1,
            TimeHorizon.MEDIUM_TERM: 3,
            TimeHorizon.LONG_TERM: 12
        }[time_horizon]
        
        current_utilization = await self._calculate_current_utilization()
        
        for resource_type, current_capacity in current_metrics.items():
            if resource_type not in growth_projections:
                continue
            
            projection = growth_projections[resource_type]
            current_util = current_utilization.get(resource_type, 0.5)
            
            # Calculate future demand
            growth_factor = (1 + projection.growth_rate_monthly) ** months_ahead
            growth_factor *= projection.seasonal_factor
            
            # Current usage
            current_usage = current_capacity * current_util
            
            # Future usage
            future_usage = current_usage * growth_factor
            
            # Required capacity (with safety margin)
            target_utilization = self.config["utilization_target"]
            safety_margin = self.config["safety_margin"]
            
            required_capacity = future_usage / target_utilization * (1 + safety_margin)
            
            # Resource units
            units = {
                ResourceType.CPU: "vCPUs",
                ResourceType.MEMORY: "GB",
                ResourceType.STORAGE: "GB",
                ResourceType.NETWORK: "Mbps",
                ResourceType.DATABASE: "instances",
                ResourceType.CACHE: "GB"
            }
            
            requirement = ResourceRequirement(
                resource_type=resource_type,
                current_capacity=current_capacity,
                current_utilization=current_util,
                required_capacity=required_capacity,
                growth_rate=projection.growth_rate_monthly,
                unit=units[resource_type],
                confidence=min(projection.confidence_interval) / projection.growth_rate_monthly
            )
            
            requirements.append(requirement)
        
        logger.debug(f"Calculated {len(requirements)} resource requirements")
        return requirements
    
    async def _create_scaling_timeline(self, 
                                     requirements: List[ResourceRequirement],
                                     time_horizon: TimeHorizon) -> List[Dict[str, Any]]:
        """Create timeline for scaling actions"""
        timeline = []
        
        # Sort requirements by urgency (current utilization vs required capacity)
        urgent_requirements = [
            req for req in requirements
            if req.required_capacity > req.current_capacity * 1.2  # Need 20%+ more capacity
        ]
        
        # Create timeline entries
        for i, requirement in enumerate(urgent_requirements):
            # Calculate when scaling is needed
            growth_rate = requirement.growth_rate
            current_util = requirement.current_utilization
            
            # When will we hit 85% utilization?
            months_to_critical = 0
            if growth_rate > 0:
                target_util = 0.85
                months_to_critical = math.log(target_util / current_util) / math.log(1 + growth_rate)
                months_to_critical = max(1, months_to_critical)  # At least 1 month
            
            scaling_date = datetime.now() + timedelta(days=30 * months_to_critical)
            
            timeline_entry = {
                "date": scaling_date,
                "resource_type": requirement.resource_type.value,
                "current_capacity": requirement.current_capacity,
                "target_capacity": requirement.required_capacity,
                "scaling_factor": requirement.required_capacity / requirement.current_capacity,
                "urgency": "high" if months_to_critical < 2 else "medium",
                "estimated_cost": self._estimate_scaling_cost(requirement),
                "implementation_time_days": self._estimate_implementation_time(requirement.resource_type)
            }
            
            timeline.append(timeline_entry)
        
        # Sort by date
        timeline.sort(key=lambda x: x["date"])
        
        logger.debug(f"Created scaling timeline with {len(timeline)} entries")
        return timeline
    
    def _estimate_scaling_cost(self, requirement: ResourceRequirement) -> float:
        """Estimate cost of scaling"""
        # Simplified cost estimation
        capacity_increase = requirement.required_capacity - requirement.current_capacity
        
        cost_per_unit = {
            ResourceType.CPU: 50.0,  # $50 per vCPU per month
            ResourceType.MEMORY: 10.0,  # $10 per GB per month
            ResourceType.STORAGE: 0.5,  # $0.50 per GB per month
            ResourceType.NETWORK: 0.1,  # $0.10 per Mbps per month
            ResourceType.DATABASE: 200.0,  # $200 per instance per month
            ResourceType.CACHE: 15.0   # $15 per GB per month
        }
        
        unit_cost = cost_per_unit.get(requirement.resource_type, 10.0)
        return capacity_increase * unit_cost
    
    def _estimate_implementation_time(self, resource_type: ResourceType) -> int:
        """Estimate implementation time in days"""
        implementation_times = {
            ResourceType.CPU: 1,  # Instance resize
            ResourceType.MEMORY: 1,  # Instance resize
            ResourceType.STORAGE: 2,  # Storage expansion
            ResourceType.NETWORK: 3,  # Network configuration
            ResourceType.DATABASE: 5,  # Database scaling
            ResourceType.CACHE: 2   # Cache cluster scaling
        }
        
        return implementation_times.get(resource_type, 3)
    
    async def _calculate_budget_impact(self, scaling_timeline: List[Dict[str, Any]]) -> float:
        """Calculate total budget impact"""
        total_cost = sum(entry["estimated_cost"] for entry in scaling_timeline)
        logger.debug(f"Calculated total budget impact: ${total_cost:.2f}")
        return total_cost
    
    async def _assess_risks(self, requirements: List[ResourceRequirement]) -> Dict[str, str]:
        """Assess risks in the capacity plan"""
        risks = {}
        
        # High growth rate risk
        high_growth_resources = [
            req for req in requirements
            if req.growth_rate > 0.2  # > 20% monthly growth
        ]
        
        if high_growth_resources:
            risks["high_growth"] = f"High growth rate detected for {len(high_growth_resources)} resources"
        
        # Low confidence risk
        low_confidence_resources = [
            req for req in requirements
            if req.confidence < 0.6  # < 60% confidence
        ]
        
        if low_confidence_resources:
            risks["low_confidence"] = f"Low confidence predictions for {len(low_confidence_resources)} resources"
        
        # Capacity constraints
        high_utilization_resources = [
            req for req in requirements
            if req.current_utilization > 0.8  # > 80% current utilization
        ]
        
        if high_utilization_resources:
            risks["capacity_constraints"] = f"High current utilization for {len(high_utilization_resources)} resources"
        
        return risks
    
    def _calculate_confidence_score(self, projections: Dict[ResourceType, GrowthProjection]) -> float:
        """Calculate overall confidence score"""
        if not projections:
            return 0.0
        
        # Average confidence based on projection intervals
        confidence_scores = []
        for projection in projections.values():
            # Narrower confidence interval = higher confidence
            interval_width = projection.confidence_interval[1] - projection.confidence_interval[0]
            relative_width = interval_width / max(projection.growth_rate_monthly, 0.01)
            confidence = max(0, 1.0 - relative_width)
            confidence_scores.append(confidence)
        
        return statistics.mean(confidence_scores)
    
    def _get_planning_assumptions(self) -> List[str]:
        """Get planning assumptions"""
        return [
            "Historical growth patterns continue",
            "No major architecture changes",
            "Seasonal patterns remain consistent",
            "Budget approval for scaling actions",
            "Technical team availability for implementations"
        ]
    
    # Public API methods
    
    def get_plan(self, plan_id: str) -> Optional[CapacityPlan]:
        """Get capacity plan by ID"""
        return self.current_plans.get(plan_id)
    
    def get_latest_plan(self, time_horizon: TimeHorizon) -> Optional[CapacityPlan]:
        """Get latest plan for time horizon"""
        plans = [
            plan for plan in self.current_plans.values()
            if plan.time_horizon == time_horizon
        ]
        
        if not plans:
            return None
        
        return max(plans, key=lambda p: p.created_at)
    
    async def update_plan(self, plan_id: str) -> Optional[CapacityPlan]:
        """Update existing plan with latest data"""
        if plan_id not in self.current_plans:
            return None
        
        old_plan = self.current_plans[plan_id]
        new_plan = await self.create_capacity_plan(old_plan.time_horizon)
        
        # Replace old plan
        del self.current_plans[plan_id]
        self.current_plans[plan_id] = new_plan
        new_plan.plan_id = plan_id
        
        logger.info(f"Updated capacity plan {plan_id}")
        return new_plan
    
    def get_critical_actions(self, days_ahead: int = 30) -> List[Dict[str, Any]]:
        """Get critical scaling actions needed within timeframe"""
        cutoff_date = datetime.now() + timedelta(days=days_ahead)
        critical_actions = []
        
        for plan in self.current_plans.values():
            for action in plan.scaling_timeline:
                if action["date"] <= cutoff_date and action["urgency"] == "high":
                    critical_actions.append({
                        **action,
                        "plan_id": plan.plan_id
                    })
        
        return sorted(critical_actions, key=lambda x: x["date"])
    
    def get_planning_summary(self) -> Dict[str, Any]:
        """Get summary of all current plans"""
        total_budget_impact = sum(plan.budget_impact for plan in self.current_plans.values())
        avg_confidence = statistics.mean([plan.confidence_score for plan in self.current_plans.values()]) if self.current_plans else 0
        
        return {
            "total_plans": len(self.current_plans),
            "total_budget_impact": total_budget_impact,
            "average_confidence": avg_confidence,
            "critical_actions_30_days": len(self.get_critical_actions(30)),
            "plans_by_horizon": {
                horizon.value: len([p for p in self.current_plans.values() if p.time_horizon == horizon])
                for horizon in TimeHorizon
            }
        }

# Global capacity planner instance
capacity_planner = CapacityPlanner()