"""
Cost Optimization Monitoring for Monitor Legislativo v4
Tracks and optimizes resource usage and costs

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

from .cost_monitor import (
    CostMonitor,
    ResourceUsage,
    CostMetrics,
    CostAlert,
    cost_monitor
)

from .resource_tracker import (
    ResourceTracker,
    ComputeResourceTracker,
    StorageResourceTracker,
    NetworkResourceTracker,
    DatabaseResourceTracker,
    resource_tracker
)

from .optimization_engine import (
    OptimizationEngine,
    OptimizationRecommendation,
    OptimizationType,
    SavingsEstimate,
    optimization_engine
)

from .budget_manager import (
    BudgetManager,
    Budget,
    BudgetAlert,
    SpendingForecast,
    budget_manager
)

from .cost_analyzer import (
    CostAnalyzer,
    CostBreakdown,
    TrendAnalysis,
    AnomalyDetection,
    cost_analyzer
)

from .reports import (
    CostReportGenerator,
    CostReport,
    SavingsReport,
    UtilizationReport,
    report_generator
)

__all__ = [
    # Core monitoring
    "CostMonitor",
    "ResourceUsage",
    "CostMetrics", 
    "CostAlert",
    "cost_monitor",
    
    # Resource tracking
    "ResourceTracker",
    "ComputeResourceTracker",
    "StorageResourceTracker",
    "NetworkResourceTracker",
    "DatabaseResourceTracker",
    "resource_tracker",
    
    # Optimization
    "OptimizationEngine",
    "OptimizationRecommendation",
    "OptimizationType",
    "SavingsEstimate",
    "optimization_engine",
    
    # Budget management
    "BudgetManager",
    "Budget",
    "BudgetAlert",
    "SpendingForecast",
    "budget_manager",
    
    # Analysis
    "CostAnalyzer",
    "CostBreakdown",
    "TrendAnalysis", 
    "AnomalyDetection",
    "cost_analyzer",
    
    # Reporting
    "CostReportGenerator",
    "CostReport",
    "SavingsReport",
    "UtilizationReport",
    "report_generator"
]