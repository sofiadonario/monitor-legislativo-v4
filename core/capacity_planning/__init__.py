"""
Automated Capacity Planning for Monitor Legislativo v4
Predicts and plans for future resource requirements

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

from .capacity_planner import (
    CapacityPlanner,
    CapacityPlan,
    ResourceRequirement,
    GrowthProjection,
    capacity_planner
)

from .demand_forecaster import (
    DemandForecaster,
    DemandForecast,
    SeasonalPattern,
    TrendAnalysis,
    demand_forecaster
)

from .resource_predictor import (
    ResourcePredictor,
    ResourcePrediction,
    PredictionModel,
    ModelType,
    resource_predictor
)

from .scaling_advisor import (
    ScalingAdvisor,
    ScalingRecommendation,
    ScalingTrigger,
    ScalingAction,
    scaling_advisor
)

from .capacity_monitor import (
    CapacityMonitor,
    CapacityMetrics,
    UtilizationAlert,
    ThresholdConfig,
    capacity_monitor
)

__all__ = [
    # Core planning
    "CapacityPlanner",
    "CapacityPlan",
    "ResourceRequirement",
    "GrowthProjection", 
    "capacity_planner",
    
    # Demand forecasting
    "DemandForecaster",
    "DemandForecast",
    "SeasonalPattern",
    "TrendAnalysis",
    "demand_forecaster",
    
    # Resource prediction
    "ResourcePredictor",
    "ResourcePrediction",
    "PredictionModel",
    "ModelType",
    "resource_predictor",
    
    # Scaling advice
    "ScalingAdvisor",
    "ScalingRecommendation",
    "ScalingTrigger",
    "ScalingAction",
    "scaling_advisor",
    
    # Monitoring
    "CapacityMonitor",
    "CapacityMetrics",
    "UtilizationAlert",
    "ThresholdConfig", 
    "capacity_monitor"
]