"""
Chaos Engineering for Monitor Legislativo v4
Testing system resilience through controlled failures

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

from .chaos_engine import (
    ChaosEngine,
    ChaosExperiment,
    ExperimentResult,
    ExperimentStatus,
    chaos_engine
)

from .fault_injectors import (
    FaultInjector,
    NetworkFaultInjector,
    DatabaseFaultInjector,
    ServiceFaultInjector,
    ResourceFaultInjector,
    CPUStressFaultInjector,
    MemoryStressFaultInjector
)

from .experiments import (
    NetworkLatencyExperiment,
    DatabaseFailureExperiment,
    ServiceUnavailableExperiment,
    HighCPUExperiment,
    MemoryLeakExperiment,
    DiskFullExperiment,
    CacheFailureExperiment
)

from .monitors import (
    ChaosMonitor,
    SystemMetricsMonitor,
    ApplicationMetricsMonitor,
    UserExperienceMonitor,
    chaos_monitor
)

from .reports import (
    ChaosReportGenerator,
    ExperimentReport,
    ResilienceScore,
    report_generator
)

__all__ = [
    # Core chaos engine
    "ChaosEngine",
    "ChaosExperiment", 
    "ExperimentResult",
    "ExperimentStatus",
    "chaos_engine",
    
    # Fault injectors
    "FaultInjector",
    "NetworkFaultInjector",
    "DatabaseFaultInjector", 
    "ServiceFaultInjector",
    "ResourceFaultInjector",
    "CPUStressFaultInjector",
    "MemoryStressFaultInjector",
    
    # Experiments
    "NetworkLatencyExperiment",
    "DatabaseFailureExperiment",
    "ServiceUnavailableExperiment",
    "HighCPUExperiment", 
    "MemoryLeakExperiment",
    "DiskFullExperiment",
    "CacheFailureExperiment",
    
    # Monitoring
    "ChaosMonitor",
    "SystemMetricsMonitor",
    "ApplicationMetricsMonitor", 
    "UserExperienceMonitor",
    "chaos_monitor",
    
    # Reporting
    "ChaosReportGenerator",
    "ExperimentReport",
    "ResilienceScore",
    "report_generator"
]