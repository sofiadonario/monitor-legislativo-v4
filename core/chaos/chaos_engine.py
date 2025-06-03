"""
Chaos Engine for Monitor Legislativo v4
Core chaos engineering orchestration

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, field
import uuid
import json

logger = logging.getLogger(__name__)

class ExperimentStatus(Enum):
    """Status of chaos experiment"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"

class ImpactLevel(Enum):
    """Impact level of experiment"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ExperimentResult:
    """Result of a chaos experiment"""
    experiment_id: str
    status: ExperimentStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    
    # Metrics
    baseline_metrics: Dict[str, float] = field(default_factory=dict)
    experiment_metrics: Dict[str, float] = field(default_factory=dict)
    recovery_metrics: Dict[str, float] = field(default_factory=dict)
    
    # Analysis
    impact_detected: bool = False
    recovery_successful: bool = False
    recovery_time_seconds: float = 0.0
    
    # Observations
    observations: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    # Raw data
    raw_data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ChaosExperiment:
    """Definition of a chaos experiment"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    
    # Configuration
    target_service: str = ""
    fault_type: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    
    # Safety
    impact_level: ImpactLevel = ImpactLevel.LOW
    max_duration_minutes: int = 5
    abort_conditions: List[str] = field(default_factory=list)
    
    # Scheduling
    schedule: Optional[str] = None  # Cron expression
    enabled: bool = True
    
    # Metadata
    created_by: str = "system"
    created_at: datetime = field(default_factory=datetime.now)
    tags: List[str] = field(default_factory=list)

class ChaosEngine:
    """Main chaos engineering engine"""
    
    def __init__(self):
        self.experiments: Dict[str, ChaosExperiment] = {}
        self.running_experiments: Dict[str, asyncio.Task] = {}
        self.results: Dict[str, ExperimentResult] = {}
        
        # Safety controls
        self.safety_enabled = True
        self.max_concurrent_experiments = 3
        self.emergency_stop = False
        
        # Monitoring
        self.monitors: List[Callable] = []
        self.abort_callbacks: List[Callable] = []
        
        # Configuration
        self.config = {
            "default_timeout_minutes": 10,
            "metrics_collection_interval": 30,
            "auto_abort_threshold": 0.8,  # Abort if impact > 80%
            "production_mode": False
        }
        
        # Statistics
        self.stats = {
            "total_experiments": 0,
            "successful_experiments": 0,
            "failed_experiments": 0,
            "aborted_experiments": 0,
            "total_runtime_hours": 0.0
        }
    
    async def register_experiment(self, experiment: ChaosExperiment) -> str:
        """Register a new chaos experiment"""
        if not experiment.name:
            experiment.name = f"Experiment_{experiment.id[:8]}"
            
        # Validate experiment
        if not self._validate_experiment(experiment):
            raise ValueError("Invalid experiment configuration")
        
        # Safety checks
        if self.config["production_mode"] and experiment.impact_level == ImpactLevel.CRITICAL:
            raise ValueError("Critical experiments not allowed in production mode")
        
        self.experiments[experiment.id] = experiment
        logger.info(f"Registered chaos experiment: {experiment.name}")
        
        return experiment.id
    
    async def run_experiment(self, experiment_id: str) -> ExperimentResult:
        """Run a chaos experiment"""
        if not self.safety_enabled:
            raise RuntimeError("Chaos engine safety is disabled")
        
        if experiment_id not in self.experiments:
            raise ValueError(f"Experiment {experiment_id} not found")
        
        if len(self.running_experiments) >= self.max_concurrent_experiments:
            raise RuntimeError("Maximum concurrent experiments limit reached")
        
        experiment = self.experiments[experiment_id]
        
        # Create result
        result = ExperimentResult(
            experiment_id=experiment_id,
            status=ExperimentStatus.PENDING,
            start_time=datetime.now()
        )
        
        self.results[experiment_id] = result
        
        # Start experiment task
        task = asyncio.create_task(self._execute_experiment(experiment, result))
        self.running_experiments[experiment_id] = task
        
        try:
            await task
            return result
        finally:
            self.running_experiments.pop(experiment_id, None)
    
    async def abort_experiment(self, experiment_id: str, reason: str = "Manual abort") -> bool:
        """Abort a running experiment"""
        if experiment_id not in self.running_experiments:
            return False
        
        task = self.running_experiments[experiment_id]
        task.cancel()
        
        # Update result
        if experiment_id in self.results:
            result = self.results[experiment_id]
            result.status = ExperimentStatus.ABORTED
            result.end_time = datetime.now()
            result.observations.append(f"Aborted: {reason}")
        
        logger.warning(f"Aborted experiment {experiment_id}: {reason}")
        return True
    
    async def emergency_stop_all(self) -> None:
        """Emergency stop all running experiments"""
        self.emergency_stop = True
        
        logger.critical("EMERGENCY STOP: Aborting all chaos experiments")
        
        # Abort all running experiments
        for experiment_id in list(self.running_experiments.keys()):
            await self.abort_experiment(experiment_id, "Emergency stop")
        
        # Notify callbacks
        for callback in self.abort_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback("emergency_stop")
                else:
                    callback("emergency_stop")
            except Exception as e:
                logger.error(f"Error in abort callback: {e}")
    
    async def _execute_experiment(self, experiment: ChaosExperiment, result: ExperimentResult) -> None:
        """Execute a chaos experiment"""
        try:
            result.status = ExperimentStatus.RUNNING
            logger.info(f"Starting chaos experiment: {experiment.name}")
            
            # Collect baseline metrics
            result.baseline_metrics = await self._collect_metrics()
            
            # Import and get fault injector
            fault_injector = await self._get_fault_injector(experiment.fault_type)
            
            if not fault_injector:
                raise ValueError(f"Unknown fault type: {experiment.fault_type}")
            
            # Start fault injection
            await fault_injector.inject_fault(
                target=experiment.target_service,
                parameters=experiment.parameters
            )
            
            # Monitor experiment
            await self._monitor_experiment(experiment, result)
            
            # Stop fault injection
            await fault_injector.stop_fault()
            
            # Collect recovery metrics
            await asyncio.sleep(30)  # Wait for recovery
            result.recovery_metrics = await self._collect_metrics()
            
            # Analyze results
            await self._analyze_results(experiment, result)
            
            result.status = ExperimentStatus.COMPLETED
            result.end_time = datetime.now()
            result.duration_seconds = (result.end_time - result.start_time).total_seconds()
            
            # Update statistics
            self.stats["total_experiments"] += 1
            self.stats["successful_experiments"] += 1
            self.stats["total_runtime_hours"] += result.duration_seconds / 3600
            
            logger.info(f"Completed chaos experiment: {experiment.name}")
            
        except asyncio.CancelledError:
            result.status = ExperimentStatus.ABORTED
            result.end_time = datetime.now()
            self.stats["aborted_experiments"] += 1
            raise
            
        except Exception as e:
            result.status = ExperimentStatus.FAILED
            result.end_time = datetime.now()
            result.errors.append(str(e))
            self.stats["failed_experiments"] += 1
            
            logger.error(f"Chaos experiment failed: {experiment.name} - {e}")
            raise
    
    async def _monitor_experiment(self, experiment: ChaosExperiment, result: ExperimentResult) -> None:
        """Monitor experiment execution"""
        max_duration = timedelta(minutes=experiment.max_duration_minutes)
        start_time = datetime.now()
        
        while datetime.now() - start_time < max_duration:
            if self.emergency_stop:
                raise asyncio.CancelledError("Emergency stop")
            
            # Collect current metrics
            current_metrics = await self._collect_metrics()
            result.experiment_metrics = current_metrics
            
            # Check abort conditions
            if await self._should_abort(experiment, result, current_metrics):
                raise RuntimeError("Abort condition triggered")
            
            # Check for automatic safety abort
            impact_score = self._calculate_impact_score(result.baseline_metrics, current_metrics)
            if impact_score > self.config["auto_abort_threshold"]:
                raise RuntimeError(f"High impact detected: {impact_score:.2f}")
            
            await asyncio.sleep(self.config["metrics_collection_interval"])
    
    async def _collect_metrics(self) -> Dict[str, float]:
        """Collect system metrics"""
        metrics = {}
        
        # Simulate metric collection
        import random
        
        metrics.update({
            "response_time_ms": random.uniform(100, 500),
            "error_rate": random.uniform(0, 0.1),
            "throughput_rps": random.uniform(50, 200),
            "cpu_usage": random.uniform(20, 80),
            "memory_usage": random.uniform(30, 70),
            "disk_usage": random.uniform(40, 60),
            "active_connections": random.randint(10, 100),
            "queue_size": random.randint(0, 50)
        })
        
        # Call registered monitors
        for monitor in self.monitors:
            try:
                if asyncio.iscoroutinefunction(monitor):
                    additional_metrics = await monitor()
                else:
                    additional_metrics = monitor()
                
                if isinstance(additional_metrics, dict):
                    metrics.update(additional_metrics)
                    
            except Exception as e:
                logger.error(f"Error in metrics monitor: {e}")
        
        return metrics
    
    async def _get_fault_injector(self, fault_type: str):
        """Get fault injector for given type"""
        try:
            if fault_type == "network_latency":
                from .fault_injectors import NetworkFaultInjector
                return NetworkFaultInjector()
            elif fault_type == "database_failure":
                from .fault_injectors import DatabaseFaultInjector
                return DatabaseFaultInjector()
            elif fault_type == "service_unavailable":
                from .fault_injectors import ServiceFaultInjector
                return ServiceFaultInjector()
            elif fault_type == "high_cpu":
                from .fault_injectors import CPUStressFaultInjector
                return CPUStressFaultInjector()
            elif fault_type == "memory_leak":
                from .fault_injectors import MemoryStressFaultInjector
                return MemoryStressFaultInjector()
            else:
                logger.warning(f"Unknown fault type: {fault_type}")
                return None
                
        except ImportError as e:
            logger.error(f"Failed to import fault injector: {e}")
            return None
    
    async def _should_abort(self, experiment: ChaosExperiment, result: ExperimentResult, 
                          current_metrics: Dict[str, float]) -> bool:
        """Check if experiment should be aborted"""
        for condition in experiment.abort_conditions:
            if await self._evaluate_abort_condition(condition, current_metrics):
                result.observations.append(f"Abort condition triggered: {condition}")
                return True
        return False
    
    async def _evaluate_abort_condition(self, condition: str, metrics: Dict[str, float]) -> bool:
        """Evaluate an abort condition"""
        try:
            # Simple condition evaluation (could be more sophisticated)
            if "error_rate > 0.5" in condition:
                return metrics.get("error_rate", 0) > 0.5
            elif "response_time_ms > 5000" in condition:
                return metrics.get("response_time_ms", 0) > 5000
            elif "cpu_usage > 95" in condition:
                return metrics.get("cpu_usage", 0) > 95
            elif "memory_usage > 90" in condition:
                return metrics.get("memory_usage", 0) > 90
            
            return False
            
        except Exception as e:
            logger.error(f"Error evaluating abort condition '{condition}': {e}")
            return False
    
    def _calculate_impact_score(self, baseline: Dict[str, float], current: Dict[str, float]) -> float:
        """Calculate impact score (0.0 to 1.0)"""
        if not baseline or not current:
            return 0.0
        
        impact_scores = []
        
        # Response time impact
        baseline_rt = baseline.get("response_time_ms", 0)
        current_rt = current.get("response_time_ms", 0)
        if baseline_rt > 0:
            rt_impact = min((current_rt - baseline_rt) / baseline_rt, 5.0) / 5.0
            impact_scores.append(max(0, rt_impact))
        
        # Error rate impact
        baseline_er = baseline.get("error_rate", 0)
        current_er = current.get("error_rate", 0)
        er_impact = min(current_er - baseline_er, 1.0)
        impact_scores.append(max(0, er_impact))
        
        # Throughput impact
        baseline_tp = baseline.get("throughput_rps", 0)
        current_tp = current.get("throughput_rps", 0)
        if baseline_tp > 0:
            tp_impact = max(0, (baseline_tp - current_tp) / baseline_tp)
            impact_scores.append(tp_impact)
        
        return sum(impact_scores) / len(impact_scores) if impact_scores else 0.0
    
    async def _analyze_results(self, experiment: ChaosExperiment, result: ExperimentResult) -> None:
        """Analyze experiment results"""
        baseline = result.baseline_metrics
        experiment_metrics = result.experiment_metrics
        recovery = result.recovery_metrics
        
        # Detect impact
        impact_score = self._calculate_impact_score(baseline, experiment_metrics)
        result.impact_detected = impact_score > 0.1  # 10% threshold
        
        # Check recovery
        if recovery:
            recovery_score = self._calculate_impact_score(baseline, recovery)
            result.recovery_successful = recovery_score < 0.2  # Within 20% of baseline
            
            # Calculate recovery time (simplified)
            result.recovery_time_seconds = 30.0  # Mock recovery time
        
        # Add observations
        if result.impact_detected:
            result.observations.append(f"Impact detected with score: {impact_score:.3f}")
        
        if result.recovery_successful:
            result.observations.append("System recovered successfully")
        else:
            result.observations.append("System recovery issues detected")
    
    def _validate_experiment(self, experiment: ChaosExperiment) -> bool:
        """Validate experiment configuration"""
        if not experiment.target_service:
            return False
        
        if not experiment.fault_type:
            return False
        
        if experiment.max_duration_minutes <= 0 or experiment.max_duration_minutes > 60:
            return False
        
        return True
    
    def add_monitor(self, monitor: Callable) -> None:
        """Add metrics monitor"""
        self.monitors.append(monitor)
    
    def add_abort_callback(self, callback: Callable) -> None:
        """Add abort callback"""
        self.abort_callbacks.append(callback)
    
    def get_experiment_status(self, experiment_id: str) -> Optional[ExperimentStatus]:
        """Get experiment status"""
        if experiment_id in self.results:
            return self.results[experiment_id].status
        return None
    
    def get_running_experiments(self) -> List[str]:
        """Get list of running experiment IDs"""
        return list(self.running_experiments.keys())
    
    def get_experiment_results(self, experiment_id: str) -> Optional[ExperimentResult]:
        """Get experiment results"""
        return self.results.get(experiment_id)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get chaos engine statistics"""
        return {
            **self.stats,
            "registered_experiments": len(self.experiments),
            "running_experiments": len(self.running_experiments),
            "completed_experiments": len(self.results),
            "safety_enabled": self.safety_enabled,
            "emergency_stop": self.emergency_stop
        }
    
    def enable_safety(self) -> None:
        """Enable safety controls"""
        self.safety_enabled = True
        logger.info("Chaos engine safety enabled")
    
    def disable_safety(self) -> None:
        """Disable safety controls (use with extreme caution)"""
        self.safety_enabled = False
        logger.warning("Chaos engine safety DISABLED - use with caution!")

# Global chaos engine instance
chaos_engine = ChaosEngine()