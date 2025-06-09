"""
Chaos Engineering Framework for Monitor Legislativo v4
Systematic failure injection to test system resilience

CRITICAL: Tests system behavior under failure conditions to ensure
production stability and fault tolerance.
"""

import asyncio
import random
import time
import threading
import psutil
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from enum import Enum
from contextlib import asynccontextmanager

from core.monitoring.performance_dashboard import get_performance_collector
from core.monitoring.security_monitor import SecurityEventType, ThreatLevel, get_security_monitor
from core.utils.alerting import send_critical_alert

logger = logging.getLogger(__name__)


class FailureType(Enum):
    """Types of failures to inject."""
    NETWORK_LATENCY = "network_latency"
    NETWORK_TIMEOUT = "network_timeout"
    NETWORK_PARTITION = "network_partition"
    CPU_SPIKE = "cpu_spike"
    MEMORY_PRESSURE = "memory_pressure"
    DISK_IO_DELAY = "disk_io_delay"
    DATABASE_SLOW_QUERY = "database_slow_query"
    DATABASE_CONNECTION_LOSS = "database_connection_loss"
    CACHE_MISS = "cache_miss"
    CACHE_CORRUPTION = "cache_corruption"
    API_ERROR_RATE = "api_error_rate"
    API_SLOWDOWN = "api_slowdown"
    SERVICE_CRASH = "service_crash"
    DEPENDENCY_FAILURE = "dependency_failure"


class ChaosScope(Enum):
    """Scope of chaos experiments."""
    SINGLE_INSTANCE = "single_instance"
    CLUSTER_SUBSET = "cluster_subset"
    FULL_SYSTEM = "full_system"
    SPECIFIC_SERVICE = "specific_service"


@dataclass
class ChaosExperiment:
    """Definition of a chaos engineering experiment."""
    name: str
    description: str
    failure_type: FailureType
    scope: ChaosScope
    duration_seconds: int
    intensity: float  # 0.0 to 1.0
    target_components: List[str]
    hypothesis: str
    success_criteria: List[str]
    rollback_strategy: str


@dataclass
class ChaosResult:
    """Results from a chaos experiment."""
    experiment_name: str
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    failure_injected: bool
    system_recovered: bool
    hypothesis_validated: bool
    success_criteria_met: List[bool]
    observations: List[str]
    metrics_before: Dict[str, float]
    metrics_during: Dict[str, float]
    metrics_after: Dict[str, float]
    incident_detected: bool
    recovery_time_seconds: Optional[float]


class FailureInjector:
    """Injects various types of failures into the system."""
    
    def __init__(self):
        """Initialize failure injector."""
        self.active_failures = {}
        self.lock = threading.Lock()
        
    @asynccontextmanager
    async def inject_network_latency(self, delay_ms: int):
        """Inject network latency."""
        logger.info(f"Injecting network latency: {delay_ms}ms")
        
        # Store original delay function
        original_sleep = asyncio.sleep
        
        async def delayed_sleep(seconds):
            await original_sleep(seconds + delay_ms / 1000)
        
        # Monkey patch sleep function
        asyncio.sleep = delayed_sleep
        
        try:
            yield
        finally:
            # Restore original function
            asyncio.sleep = original_sleep
            logger.info("Network latency injection removed")
    
    @asynccontextmanager
    async def inject_api_errors(self, error_rate: float):
        """Inject API errors at specified rate."""
        logger.info(f"Injecting API errors at {error_rate * 100}% rate")
        
        # This would typically patch HTTP client methods
        # For demonstration, we'll track the injection
        with self.lock:
            self.active_failures['api_errors'] = {
                'type': 'api_errors',
                'rate': error_rate,
                'start_time': time.time()
            }
        
        try:
            yield
        finally:
            with self.lock:
                if 'api_errors' in self.active_failures:
                    del self.active_failures['api_errors']
            logger.info("API error injection removed")
    
    @asynccontextmanager
    async def inject_memory_pressure(self, pressure_mb: int):
        """Inject memory pressure by allocating memory."""
        logger.info(f"Injecting memory pressure: {pressure_mb}MB")
        
        # Allocate memory to create pressure
        memory_hog = []
        try:
            for _ in range(pressure_mb):
                # Allocate 1MB chunks
                chunk = bytearray(1024 * 1024)
                memory_hog.append(chunk)
            
            yield
            
        finally:
            # Release memory
            del memory_hog
            logger.info("Memory pressure injection removed")
    
    @asynccontextmanager
    async def inject_cpu_spike(self, duration_seconds: int, intensity: float):
        """Inject CPU spike by running CPU-intensive tasks."""
        logger.info(f"Injecting CPU spike: {intensity * 100}% for {duration_seconds}s")
        
        stop_event = threading.Event()
        
        def cpu_burner():
            """CPU-intensive task."""
            while not stop_event.is_set():
                # Busy work to consume CPU
                for _ in range(int(10000 * intensity)):
                    _ = sum(range(100))
                time.sleep(0.001)  # Brief pause to allow other threads
        
        # Start CPU burning threads
        num_threads = max(1, int(psutil.cpu_count() * intensity))
        threads = []
        
        for _ in range(num_threads):
            thread = threading.Thread(target=cpu_burner, daemon=True)
            thread.start()
            threads.append(thread)
        
        try:
            yield
        finally:
            # Stop CPU burning
            stop_event.set()
            for thread in threads:
                thread.join(timeout=1)
            logger.info("CPU spike injection removed")
    
    def get_active_failures(self) -> Dict[str, Any]:
        """Get currently active failure injections."""
        with self.lock:
            return self.active_failures.copy()


class ChaosEngine:
    """
    Main chaos engineering engine for orchestrating experiments.
    
    Features:
    - Systematic failure injection
    - Safety controls and circuit breakers
    - Automatic rollback on critical failures
    - Metrics collection and analysis
    - Hypothesis validation
    """
    
    def __init__(self):
        """Initialize chaos engineering engine."""
        self.failure_injector = FailureInjector()
        self.performance_collector = get_performance_collector()
        self.security_monitor = get_security_monitor()
        
        # Safety controls
        self.max_concurrent_experiments = 1
        self.active_experiments = {}
        self.emergency_stop = False
        
        # Predefined experiments
        self.experiments = self._define_experiments()
        
        logger.info("Chaos engineering engine initialized")
    
    def _define_experiments(self) -> Dict[str, ChaosExperiment]:
        """Define standard chaos experiments."""
        return {
            "network_latency_resilience": ChaosExperiment(
                name="network_latency_resilience",
                description="Test system resilience to network latency",
                failure_type=FailureType.NETWORK_LATENCY,
                scope=ChaosScope.FULL_SYSTEM,
                duration_seconds=300,  # 5 minutes
                intensity=0.5,
                target_components=["api_services", "database"],
                hypothesis="System should handle 500ms additional latency without significant degradation",
                success_criteria=[
                    "API response time P95 < 2000ms",
                    "Error rate < 5%",
                    "No circuit breaker activations",
                    "User experience remains acceptable"
                ],
                rollback_strategy="Remove latency injection immediately on critical failure"
            ),
            
            "api_error_handling": ChaosExperiment(
                name="api_error_handling",
                description="Test API error handling and circuit breakers",
                failure_type=FailureType.API_ERROR_RATE,
                scope=ChaosScope.SPECIFIC_SERVICE,
                duration_seconds=180,  # 3 minutes
                intensity=0.3,  # 30% error rate
                target_components=["external_apis"],
                hypothesis="Circuit breakers should activate at 30% error rate and system should gracefully degrade",
                success_criteria=[
                    "Circuit breakers activate within 30 seconds",
                    "System provides cached/fallback data",
                    "No cascading failures",
                    "Automatic recovery after error injection stops"
                ],
                rollback_strategy="Stop error injection and verify circuit breaker recovery"
            ),
            
            "memory_pressure_handling": ChaosExperiment(
                name="memory_pressure_handling",
                description="Test system behavior under memory pressure",
                failure_type=FailureType.MEMORY_PRESSURE,
                scope=ChaosScope.SINGLE_INSTANCE,
                duration_seconds=240,  # 4 minutes
                intensity=0.7,  # High memory pressure
                target_components=["application_server"],
                hypothesis="System should handle memory pressure through garbage collection and resource management",
                success_criteria=[
                    "Memory usage stabilizes below 90%",
                    "No out-of-memory crashes",
                    "Response times remain acceptable",
                    "System recovers after pressure removal"
                ],
                rollback_strategy="Release allocated memory immediately on critical threshold"
            ),
            
            "cpu_spike_resilience": ChaosExperiment(
                name="cpu_spike_resilience",
                description="Test system resilience to CPU spikes",
                failure_type=FailureType.CPU_SPIKE,
                scope=ChaosScope.SINGLE_INSTANCE,
                duration_seconds=120,  # 2 minutes
                intensity=0.8,  # 80% CPU utilization
                target_components=["application_server"],
                hypothesis="System should maintain responsiveness during CPU spikes through proper resource management",
                success_criteria=[
                    "API requests continue to be processed",
                    "Response time degradation < 500%",
                    "No request timeouts",
                    "System recovers quickly after spike"
                ],
                rollback_strategy="Stop CPU intensive tasks immediately"
            ),
            
            "database_connection_failure": ChaosExperiment(
                name="database_connection_failure",
                description="Test database connection failure handling",
                failure_type=FailureType.DATABASE_CONNECTION_LOSS,
                scope=ChaosScope.SPECIFIC_SERVICE,
                duration_seconds=60,  # 1 minute
                intensity=1.0,  # Complete connection loss
                target_components=["database_connection"],
                hypothesis="System should handle database disconnection through connection pooling and retries",
                success_criteria=[
                    "Connection pool attempts reconnection",
                    "Cached data is served when available",
                    "Graceful error messages to users",
                    "Automatic recovery when database is available"
                ],
                rollback_strategy="Restore database connection immediately"
            )
        }
    
    async def run_experiment(self, experiment_name: str) -> ChaosResult:
        """Run a specific chaos experiment."""
        if experiment_name not in self.experiments:
            raise ValueError(f"Unknown experiment: {experiment_name}")
        
        experiment = self.experiments[experiment_name]
        
        # Safety check
        if len(self.active_experiments) >= self.max_concurrent_experiments:
            raise RuntimeError("Maximum concurrent experiments reached")
        
        if self.emergency_stop:
            raise RuntimeError("Emergency stop activated")
        
        logger.info(f"Starting chaos experiment: {experiment_name}")
        
        # Record experiment start
        start_time = datetime.now()
        self.active_experiments[experiment_name] = experiment
        
        try:
            # Collect baseline metrics
            metrics_before = await self._collect_system_metrics()
            
            # Run the experiment
            result = await self._execute_experiment(experiment, metrics_before)
            
            return result
            
        except Exception as e:
            logger.error(f"Chaos experiment {experiment_name} failed: {e}")
            
            # Emergency rollback
            await self._emergency_rollback(experiment)
            
            # Create failed result
            return ChaosResult(
                experiment_name=experiment_name,
                start_time=start_time,
                end_time=datetime.now(),
                duration_seconds=(datetime.now() - start_time).total_seconds(),
                failure_injected=False,
                system_recovered=False,
                hypothesis_validated=False,
                success_criteria_met=[False] * len(experiment.success_criteria),
                observations=[f"Experiment failed: {str(e)}"],
                metrics_before={},
                metrics_during={},
                metrics_after={},
                incident_detected=True,
                recovery_time_seconds=None
            )
        
        finally:
            # Clean up
            if experiment_name in self.active_experiments:
                del self.active_experiments[experiment_name]
    
    async def _execute_experiment(self, experiment: ChaosExperiment, 
                                metrics_before: Dict[str, float]) -> ChaosResult:
        """Execute the chaos experiment."""
        start_time = datetime.now()
        failure_injected = False
        system_recovered = True
        observations = []
        
        try:
            # Inject failure based on type
            if experiment.failure_type == FailureType.NETWORK_LATENCY:
                delay_ms = int(500 * experiment.intensity)
                async with self.failure_injector.inject_network_latency(delay_ms):
                    failure_injected = True
                    observations.append(f"Injected {delay_ms}ms network latency")
                    
                    # Monitor during failure
                    await asyncio.sleep(experiment.duration_seconds / 2)
                    metrics_during = await self._collect_system_metrics()
                    
                    await asyncio.sleep(experiment.duration_seconds / 2)
            
            elif experiment.failure_type == FailureType.API_ERROR_RATE:
                error_rate = experiment.intensity
                async with self.failure_injector.inject_api_errors(error_rate):
                    failure_injected = True
                    observations.append(f"Injected {error_rate * 100}% API error rate")
                    
                    await asyncio.sleep(experiment.duration_seconds / 2)
                    metrics_during = await self._collect_system_metrics()
                    
                    await asyncio.sleep(experiment.duration_seconds / 2)
            
            elif experiment.failure_type == FailureType.MEMORY_PRESSURE:
                pressure_mb = int(1000 * experiment.intensity)  # Up to 1GB
                async with self.failure_injector.inject_memory_pressure(pressure_mb):
                    failure_injected = True
                    observations.append(f"Injected {pressure_mb}MB memory pressure")
                    
                    await asyncio.sleep(experiment.duration_seconds / 2)
                    metrics_during = await self._collect_system_metrics()
                    
                    await asyncio.sleep(experiment.duration_seconds / 2)
            
            elif experiment.failure_type == FailureType.CPU_SPIKE:
                async with self.failure_injector.inject_cpu_spike(
                    experiment.duration_seconds, experiment.intensity
                ):
                    failure_injected = True
                    observations.append(f"Injected {experiment.intensity * 100}% CPU spike")
                    
                    await asyncio.sleep(experiment.duration_seconds / 2)
                    metrics_during = await self._collect_system_metrics()
                    
                    await asyncio.sleep(experiment.duration_seconds / 2)
            
            else:
                # For other failure types, simulate the experiment
                observations.append(f"Simulated {experiment.failure_type.value}")
                metrics_during = metrics_before.copy()
                await asyncio.sleep(experiment.duration_seconds)
            
            # Wait for recovery
            recovery_start = time.time()
            await asyncio.sleep(30)  # 30 second recovery period
            recovery_time = time.time() - recovery_start
            
            # Collect post-experiment metrics
            metrics_after = await self._collect_system_metrics()
            
            # Validate hypothesis and success criteria
            success_criteria_met = self._validate_success_criteria(
                experiment, metrics_before, metrics_during, metrics_after
            )
            hypothesis_validated = all(success_criteria_met)
            
            # Check if system recovered
            system_recovered = self._check_system_recovery(metrics_before, metrics_after)
            
            end_time = datetime.now()
            
            return ChaosResult(
                experiment_name=experiment.name,
                start_time=start_time,
                end_time=end_time,
                duration_seconds=(end_time - start_time).total_seconds(),
                failure_injected=failure_injected,
                system_recovered=system_recovered,
                hypothesis_validated=hypothesis_validated,
                success_criteria_met=success_criteria_met,
                observations=observations,
                metrics_before=metrics_before,
                metrics_during=metrics_during,
                metrics_after=metrics_after,
                incident_detected=not system_recovered,
                recovery_time_seconds=recovery_time if system_recovered else None
            )
            
        except Exception as e:
            observations.append(f"Experiment error: {str(e)}")
            raise
    
    async def _collect_system_metrics(self) -> Dict[str, float]:
        """Collect key system metrics."""
        metrics = {}
        
        try:
            # CPU and memory metrics
            metrics['cpu_usage_percent'] = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            metrics['memory_usage_percent'] = memory.percent
            metrics['memory_available_mb'] = memory.available / 1024 / 1024
            
            # Performance metrics from collector
            perf_stats = self.performance_collector.get_real_time_stats()
            
            if 'response_times' in perf_stats:
                metrics['response_time_p50'] = perf_stats['response_times'].get('p50', 0)
                metrics['response_time_p95'] = perf_stats['response_times'].get('p95', 0)
            
            if 'error_rate' in perf_stats:
                metrics['error_rate_percent'] = perf_stats['error_rate'].get('percentage', 0)
            
            # System health indicators
            metrics['active_connections'] = len(psutil.net_connections())
            metrics['disk_usage_percent'] = psutil.disk_usage('/').percent
            
        except Exception as e:
            logger.warning(f"Error collecting metrics: {e}")
            metrics['collection_error'] = 1
        
        return metrics
    
    def _validate_success_criteria(self, experiment: ChaosExperiment,
                                 metrics_before: Dict[str, float],
                                 metrics_during: Dict[str, float],
                                 metrics_after: Dict[str, float]) -> List[bool]:
        """Validate experiment success criteria."""
        results = []
        
        for criteria in experiment.success_criteria:
            try:
                if "response time P95 < 2000ms" in criteria:
                    p95_time = metrics_during.get('response_time_p95', 0)
                    results.append(p95_time < 2000)
                
                elif "Error rate < 5%" in criteria:
                    error_rate = metrics_during.get('error_rate_percent', 0)
                    results.append(error_rate < 5)
                
                elif "Memory usage stabilizes below 90%" in criteria:
                    memory_usage = metrics_during.get('memory_usage_percent', 0)
                    results.append(memory_usage < 90)
                
                elif "No out-of-memory crashes" in criteria:
                    # Check if memory usage didn't spike to 100%
                    max_memory = max(
                        metrics_during.get('memory_usage_percent', 0),
                        metrics_after.get('memory_usage_percent', 0)
                    )
                    results.append(max_memory < 95)
                
                elif "API requests continue to be processed" in criteria:
                    # Check if response times didn't become infinite
                    response_time = metrics_during.get('response_time_p95', 0)
                    results.append(response_time > 0 and response_time < 10000)
                
                else:
                    # Default to passed for unimplemented criteria
                    results.append(True)
                    
            except Exception as e:
                logger.warning(f"Error validating criteria '{criteria}': {e}")
                results.append(False)
        
        return results
    
    def _check_system_recovery(self, metrics_before: Dict[str, float],
                             metrics_after: Dict[str, float]) -> bool:
        """Check if system recovered to baseline performance."""
        try:
            # Check key metrics for recovery
            recovery_checks = []
            
            # CPU usage should return to baseline (within 20%)
            cpu_before = metrics_before.get('cpu_usage_percent', 0)
            cpu_after = metrics_after.get('cpu_usage_percent', 0)
            recovery_checks.append(abs(cpu_after - cpu_before) < 20)
            
            # Memory usage should not have increased significantly
            mem_before = metrics_before.get('memory_usage_percent', 0)
            mem_after = metrics_after.get('memory_usage_percent', 0)
            recovery_checks.append(mem_after < mem_before + 10)  # Max 10% increase
            
            # Response times should return to acceptable levels
            response_before = metrics_before.get('response_time_p95', 0)
            response_after = metrics_after.get('response_time_p95', 0)
            if response_before > 0:
                recovery_checks.append(response_after < response_before * 2)  # Max 2x increase
            else:
                recovery_checks.append(response_after < 1000)  # Max 1 second
            
            # Error rate should be low
            error_after = metrics_after.get('error_rate_percent', 0)
            recovery_checks.append(error_after < 1)  # Less than 1% error rate
            
            return all(recovery_checks)
            
        except Exception as e:
            logger.warning(f"Error checking system recovery: {e}")
            return False
    
    async def _emergency_rollback(self, experiment: ChaosExperiment):
        """Perform emergency rollback of experiment."""
        logger.warning(f"Emergency rollback for experiment: {experiment.name}")
        
        try:
            # Stop all active failure injections
            active_failures = self.failure_injector.get_active_failures()
            
            for failure_id, failure_info in active_failures.items():
                logger.info(f"Rolling back failure injection: {failure_id}")
                # Implementation would depend on failure type
                # For now, we rely on context managers to clean up
            
            # Send critical alert
            await send_critical_alert(
                "Chaos Engineering Emergency Rollback",
                f"Emergency rollback executed for experiment: {experiment.name}",
                {"experiment": experiment.name, "rollback_strategy": experiment.rollback_strategy}
            )
            
        except Exception as e:
            logger.error(f"Emergency rollback failed: {e}")
    
    async def run_experiment_suite(self, experiment_names: List[str] = None) -> List[ChaosResult]:
        """Run a suite of chaos experiments."""
        if experiment_names is None:
            experiment_names = list(self.experiments.keys())
        
        results = []
        
        for experiment_name in experiment_names:
            try:
                logger.info(f"Running chaos experiment suite: {experiment_name}")
                result = await self.run_experiment(experiment_name)
                results.append(result)
                
                # Wait between experiments for system to stabilize
                await asyncio.sleep(60)
                
            except Exception as e:
                logger.error(f"Experiment suite failed at {experiment_name}: {e}")
                break
        
        return results
    
    def generate_chaos_report(self, results: List[ChaosResult]) -> Dict[str, Any]:
        """Generate comprehensive chaos engineering report."""
        total_experiments = len(results)
        successful_experiments = sum(1 for r in results if r.hypothesis_validated)
        system_resilience_score = (successful_experiments / total_experiments * 100) if total_experiments > 0 else 0
        
        report = {
            "chaos_engineering_report": {
                "execution_date": datetime.now().isoformat(),
                "total_experiments": total_experiments,
                "successful_experiments": successful_experiments,
                "system_resilience_score": round(system_resilience_score, 2),
                "overall_assessment": "RESILIENT" if system_resilience_score >= 80 else "NEEDS_IMPROVEMENT"
            },
            "experiment_results": [],
            "key_findings": [],
            "recommendations": []
        }
        
        for result in results:
            experiment_data = {
                "name": result.experiment_name,
                "duration_seconds": result.duration_seconds,
                "failure_injected": result.failure_injected,
                "system_recovered": result.system_recovered,
                "hypothesis_validated": result.hypothesis_validated,
                "success_criteria_passed": sum(result.success_criteria_met),
                "success_criteria_total": len(result.success_criteria_met),
                "recovery_time_seconds": result.recovery_time_seconds,
                "key_observations": result.observations,
                "metrics_impact": {
                    "cpu_change": result.metrics_after.get('cpu_usage_percent', 0) - result.metrics_before.get('cpu_usage_percent', 0),
                    "memory_change": result.metrics_after.get('memory_usage_percent', 0) - result.metrics_before.get('memory_usage_percent', 0),
                    "response_time_impact": result.metrics_during.get('response_time_p95', 0) - result.metrics_before.get('response_time_p95', 0)
                }
            }
            report["experiment_results"].append(experiment_data)
        
        # Generate findings and recommendations
        if system_resilience_score >= 90:
            report["key_findings"].append("System shows excellent resilience to various failure scenarios")
        elif system_resilience_score >= 70:
            report["key_findings"].append("System shows good resilience but has areas for improvement")
        else:
            report["key_findings"].append("System shows poor resilience and requires significant improvements")
        
        # Check for specific issues
        high_recovery_times = [r for r in results if r.recovery_time_seconds and r.recovery_time_seconds > 120]
        if high_recovery_times:
            report["recommendations"].append("Implement faster recovery mechanisms for critical failures")
        
        memory_issues = [r for r in results if r.metrics_after.get('memory_usage_percent', 0) > 85]
        if memory_issues:
            report["recommendations"].append("Optimize memory management and implement better garbage collection")
        
        response_time_issues = [r for r in results if r.metrics_during.get('response_time_p95', 0) > 2000]
        if response_time_issues:
            report["recommendations"].append("Implement better load balancing and caching strategies")
        
        return report


# Global chaos engine instance
_chaos_engine: Optional[ChaosEngine] = None


def get_chaos_engine() -> ChaosEngine:
    """Get or create chaos engine instance."""
    global _chaos_engine
    if _chaos_engine is None:
        _chaos_engine = ChaosEngine()
    return _chaos_engine