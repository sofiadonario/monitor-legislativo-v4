"""
Comprehensive Performance Testing Framework
Load, Stress, and Endurance Testing for Monitor Legislativo v4

CRITICAL: Tests system performance under various load conditions to ensure
production readiness and SLA compliance.
"""

import asyncio
import time
import threading
import statistics
import psutil
import pytest
import aiohttp
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import logging

from core.api.camara_service import CamaraService
from core.api.senado_service import SenadoService
from core.api.planalto_service import PlanaltoService
from core.api.lexml_integration import LexMLIntegration
from core.config.config import APIConfig
from core.utils.cache_manager import CacheManager
from core.monitoring.performance_dashboard import get_performance_collector
from core.database.models import get_session

logger = logging.getLogger(__name__)


@dataclass
class PerformanceMetric:
    """Performance measurement data point."""
    timestamp: datetime
    metric_name: str
    value: float
    unit: str
    test_scenario: str
    concurrent_users: int


@dataclass
class LoadTestResult:
    """Results from a load test execution."""
    scenario_name: str
    concurrent_users: int
    total_requests: int
    successful_requests: int
    failed_requests: int
    avg_response_time: float
    p50_response_time: float
    p95_response_time: float
    p99_response_time: float
    max_response_time: float
    throughput_rps: float
    error_rate: float
    cpu_usage_avg: float
    memory_usage_mb: float
    test_duration: float


class PerformanceTestFramework:
    """
    Comprehensive performance testing framework for legislative monitoring system.
    
    Features:
    - Load testing (normal operating conditions)
    - Stress testing (beyond normal capacity)
    - Endurance testing (sustained load over time)
    - Spike testing (sudden traffic bursts)
    - Resource monitoring during tests
    """
    
    def __init__(self):
        """Initialize performance testing framework."""
        self.config = APIConfig()
        self.cache_manager = CacheManager()
        self.performance_collector = get_performance_collector()
        
        # Test configuration
        self.test_data = self._generate_test_data()
        self.results: List[LoadTestResult] = []
        
        # Resource monitoring
        self.resource_monitor = ResourceMonitor()
        
        # SLA targets (from sprint roadmap)
        self.sla_targets = {
            "api_response_time_p50": 100.0,  # 100ms
            "api_response_time_p99": 500.0,  # 500ms
            "database_query_time": 5.0,      # 5ms
            "error_rate": 1.0,               # 1%
            "availability": 99.9,            # 99.9%
            "throughput": 1000               # 1000 requests/minute
        }
        
        logger.info("Performance testing framework initialized")
    
    def _generate_test_data(self) -> Dict[str, List[str]]:
        """Generate realistic test data for performance testing."""
        return {
            "search_queries": [
                "lei de trânsito",
                "projeto de lei transporte público",
                "decreto mobilidade urbana",
                "portaria ANTT",
                "resolução ANAC",
                "medida provisória combustível",
                "emenda constitucional transporte",
                "lei federal rodovias",
                "código de trânsito brasileiro",
                "regulamentação veículos autônomos",
                "norma técnica veículos",
                "legislação ambiental transporte",
                "política nacional mobilidade",
                "marco regulatório logística",
                "lei orgânica municípios transporte"
            ],
            "proposition_types": ["PL", "PLP", "PEC", "PDC", "PLS", "MP", "LOA"],
            "years": list(range(2020, 2025)),
            "authorities": ["Câmara dos Deputados", "Senado Federal", "Planalto", "Ministérios"]
        }
    
    async def run_load_test(self, 
                          concurrent_users: int = 50,
                          duration_minutes: int = 5,
                          ramp_up_minutes: int = 1) -> LoadTestResult:
        """
        Run load testing with specified parameters.
        
        Args:
            concurrent_users: Number of concurrent virtual users
            duration_minutes: Test duration in minutes
            ramp_up_minutes: Time to ramp up to full load
        """
        logger.info(f"Starting load test: {concurrent_users} users, {duration_minutes}min duration")
        
        start_time = time.time()
        self.resource_monitor.start_monitoring()
        
        # Track all requests and responses
        request_times = []
        errors = []
        
        try:
            # Create semaphore to control concurrent requests
            semaphore = asyncio.Semaphore(concurrent_users)
            
            # Calculate request intervals
            test_duration = duration_minutes * 60
            requests_per_user = int((test_duration / 60) * 10)  # 10 requests per minute per user
            
            # Generate all tasks
            tasks = []
            for user_id in range(concurrent_users):
                for request_id in range(requests_per_user):
                    # Stagger start times for ramp-up
                    delay = (user_id / concurrent_users) * (ramp_up_minutes * 60)
                    task = self._simulate_user_session(
                        semaphore, user_id, request_id, delay, request_times, errors
                    )
                    tasks.append(task)
            
            # Execute all tasks
            await asyncio.gather(*tasks, return_exceptions=True)
            
        finally:
            self.resource_monitor.stop_monitoring()
            end_time = time.time()
        
        # Calculate results
        total_requests = len(request_times) + len(errors)
        successful_requests = len(request_times)
        failed_requests = len(errors)
        
        if request_times:
            avg_response_time = statistics.mean(request_times)
            p50_response_time = statistics.median(request_times)
            p95_response_time = statistics.quantiles(request_times, n=20)[18] if len(request_times) > 20 else max(request_times)
            p99_response_time = statistics.quantiles(request_times, n=100)[98] if len(request_times) > 100 else max(request_times)
            max_response_time = max(request_times)
        else:
            avg_response_time = p50_response_time = p95_response_time = p99_response_time = max_response_time = 0
        
        actual_duration = end_time - start_time
        throughput_rps = successful_requests / actual_duration if actual_duration > 0 else 0
        error_rate = (failed_requests / total_requests * 100) if total_requests > 0 else 0
        
        # Get resource usage
        cpu_usage, memory_usage = self.resource_monitor.get_averages()
        
        result = LoadTestResult(
            scenario_name="Load Test",
            concurrent_users=concurrent_users,
            total_requests=total_requests,
            successful_requests=successful_requests,
            failed_requests=failed_requests,
            avg_response_time=avg_response_time,
            p50_response_time=p50_response_time,
            p95_response_time=p95_response_time,
            p99_response_time=p99_response_time,
            max_response_time=max_response_time,
            throughput_rps=throughput_rps,
            error_rate=error_rate,
            cpu_usage_avg=cpu_usage,
            memory_usage_mb=memory_usage,
            test_duration=actual_duration
        )
        
        self.results.append(result)
        
        logger.info(f"Load test completed: {successful_requests}/{total_requests} successful, "
                   f"avg response: {avg_response_time:.2f}ms, error rate: {error_rate:.2f}%")
        
        return result
    
    async def _simulate_user_session(self,
                                   semaphore: asyncio.Semaphore,
                                   user_id: int,
                                   request_id: int,
                                   delay: float,
                                   request_times: List[float],
                                   errors: List[str]):
        """Simulate a single user session with realistic behavior."""
        
        # Wait for ramp-up delay
        if delay > 0:
            await asyncio.sleep(delay)
        
        async with semaphore:
            try:
                # Choose random action based on realistic user behavior
                action = random.choices(
                    ["search", "get_details", "export_data"],
                    weights=[70, 20, 10],  # 70% search, 20% details, 10% export
                    k=1
                )[0]
                
                start_time = time.time()
                
                if action == "search":
                    await self._perform_search_request(user_id)
                elif action == "get_details":
                    await self._perform_details_request(user_id)
                elif action == "export_data":
                    await self._perform_export_request(user_id)
                
                end_time = time.time()
                response_time = (end_time - start_time) * 1000  # Convert to milliseconds
                request_times.append(response_time)
                
                # Record performance metric
                self.performance_collector.record_metric(
                    f"load_test_response_time",
                    response_time / 1000,  # Convert to seconds for collector
                    labels={
                        "action": action,
                        "user_id": str(user_id),
                        "request_id": str(request_id)
                    }
                )
                
            except Exception as e:
                errors.append(str(e))
                logger.debug(f"Request failed for user {user_id}: {e}")
            
            # Realistic think time between requests
            think_time = random.uniform(0.5, 2.0)
            await asyncio.sleep(think_time)
    
    async def _perform_search_request(self, user_id: int):
        """Perform a search request."""
        query = random.choice(self.test_data["search_queries"])
        filters = {
            "start_date": "2023-01-01",
            "end_date": "2023-12-31",
            "types": random.choice(self.test_data["proposition_types"]),
            "limit": random.randint(10, 50)
        }
        
        # Test different services
        service_choice = random.choice(["camara", "senado", "planalto"])
        
        if service_choice == "camara":
            service = CamaraService(self.config, self.cache_manager)
            result = await service.search(query, filters)
        elif service_choice == "senado":
            service = SenadoService(self.config, self.cache_manager)
            result = await service.search(query, filters)
        else:  # planalto
            service = PlanaltoService(self.config, self.cache_manager)
            result = await service.search(query, filters)
        
        # Validate result
        assert result is not None
        assert hasattr(result, 'propositions')
    
    async def _perform_details_request(self, user_id: int):
        """Perform a proposition details request."""
        # Simulate getting details for a random proposition
        prop_id = f"test_prop_{random.randint(1, 1000)}"
        
        service = CamaraService(self.config, self.cache_manager)
        result = await service.get_proposition_details(prop_id)
        
        # This might return None if proposition doesn't exist (expected in test)
    
    async def _perform_export_request(self, user_id: int):
        """Perform a data export request."""
        # Simulate data export
        filters = {
            "start_date": "2023-01-01",
            "end_date": "2023-03-31",
            "limit": random.randint(100, 500)
        }
        
        # This would normally call the export service
        await asyncio.sleep(random.uniform(0.1, 0.5))  # Simulate export processing
    
    async def run_stress_test(self, 
                            max_users: int = 200,
                            step_size: int = 25,
                            step_duration: int = 60) -> List[LoadTestResult]:
        """
        Run stress testing to find system breaking point.
        
        Args:
            max_users: Maximum number of concurrent users to test
            step_size: Increase in users at each step
            step_duration: Duration of each step in seconds
        """
        logger.info(f"Starting stress test: up to {max_users} users")
        
        stress_results = []
        current_users = step_size
        
        while current_users <= max_users:
            logger.info(f"Stress test step: {current_users} concurrent users")
            
            # Run load test for this step
            result = await self.run_load_test(
                concurrent_users=current_users,
                duration_minutes=step_duration / 60,
                ramp_up_minutes=0.5
            )
            result.scenario_name = f"Stress Test - {current_users} users"
            stress_results.append(result)
            
            # Check if system is showing stress (high error rate or response times)
            if result.error_rate > 10 or result.p95_response_time > 5000:  # 10% error rate or 5s response time
                logger.warning(f"System showing stress at {current_users} users: "
                             f"error_rate={result.error_rate:.2f}%, "
                             f"p95_response_time={result.p95_response_time:.2f}ms")
                
                if result.error_rate > 50:  # System breaking down
                    logger.error(f"System breakdown at {current_users} users")
                    break
            
            current_users += step_size
            
            # Brief recovery period between steps
            await asyncio.sleep(10)
        
        logger.info(f"Stress test completed with {len(stress_results)} steps")
        return stress_results
    
    async def run_endurance_test(self,
                               concurrent_users: int = 25,
                               duration_hours: int = 2) -> LoadTestResult:
        """
        Run endurance testing for sustained performance.
        
        Args:
            concurrent_users: Number of concurrent users (moderate load)
            duration_hours: Test duration in hours
        """
        logger.info(f"Starting endurance test: {concurrent_users} users for {duration_hours} hours")
        
        result = await self.run_load_test(
            concurrent_users=concurrent_users,
            duration_minutes=duration_hours * 60,
            ramp_up_minutes=5  # Longer ramp-up for endurance test
        )
        result.scenario_name = f"Endurance Test - {duration_hours}h"
        
        # Check for memory leaks and performance degradation
        memory_trend = self.resource_monitor.get_memory_trend()
        if memory_trend > 0.1:  # More than 10% memory increase per hour
            logger.warning(f"Potential memory leak detected: {memory_trend:.2f}% increase per hour")
        
        logger.info(f"Endurance test completed: {result.successful_requests} successful requests")
        return result
    
    async def run_spike_test(self,
                           baseline_users: int = 10,
                           spike_users: int = 100,
                           spike_duration: int = 30) -> LoadTestResult:
        """
        Run spike testing for sudden traffic bursts.
        
        Args:
            baseline_users: Normal load concurrent users
            spike_users: Peak load concurrent users
            spike_duration: Duration of spike in seconds
        """
        logger.info(f"Starting spike test: {baseline_users} -> {spike_users} users")
        
        start_time = time.time()
        self.resource_monitor.start_monitoring()
        
        request_times = []
        errors = []
        
        try:
            # Phase 1: Baseline load (30 seconds)
            await self._run_spike_phase("baseline", baseline_users, 30, request_times, errors)
            
            # Phase 2: Spike load
            await self._run_spike_phase("spike", spike_users, spike_duration, request_times, errors)
            
            # Phase 3: Return to baseline (30 seconds)
            await self._run_spike_phase("recovery", baseline_users, 30, request_times, errors)
            
        finally:
            self.resource_monitor.stop_monitoring()
            end_time = time.time()
        
        # Calculate results (similar to load test)
        total_requests = len(request_times) + len(errors)
        successful_requests = len(request_times)
        failed_requests = len(errors)
        
        if request_times:
            avg_response_time = statistics.mean(request_times)
            p95_response_time = statistics.quantiles(request_times, n=20)[18] if len(request_times) > 20 else max(request_times)
        else:
            avg_response_time = p95_response_time = 0
        
        actual_duration = end_time - start_time
        throughput_rps = successful_requests / actual_duration if actual_duration > 0 else 0
        error_rate = (failed_requests / total_requests * 100) if total_requests > 0 else 0
        
        cpu_usage, memory_usage = self.resource_monitor.get_averages()
        
        result = LoadTestResult(
            scenario_name="Spike Test",
            concurrent_users=spike_users,
            total_requests=total_requests,
            successful_requests=successful_requests,
            failed_requests=failed_requests,
            avg_response_time=avg_response_time,
            p50_response_time=statistics.median(request_times) if request_times else 0,
            p95_response_time=p95_response_time,
            p99_response_time=statistics.quantiles(request_times, n=100)[98] if len(request_times) > 100 else p95_response_time,
            max_response_time=max(request_times) if request_times else 0,
            throughput_rps=throughput_rps,
            error_rate=error_rate,
            cpu_usage_avg=cpu_usage,
            memory_usage_mb=memory_usage,
            test_duration=actual_duration
        )
        
        self.results.append(result)
        return result
    
    async def _run_spike_phase(self, phase_name: str, users: int, duration: int, 
                             request_times: List[float], errors: List[str]):
        """Run a phase of the spike test."""
        logger.info(f"Spike test phase: {phase_name} - {users} users for {duration}s")
        
        semaphore = asyncio.Semaphore(users)
        tasks = []
        
        # Generate tasks for this phase
        requests_per_user = max(1, int(duration / 10))  # One request every 10 seconds per user
        
        for user_id in range(users):
            for request_id in range(requests_per_user):
                task = self._simulate_user_session(
                    semaphore, user_id, request_id, 0, request_times, errors
                )
                tasks.append(task)
        
        # Run with timeout
        try:
            await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=duration + 10)
        except asyncio.TimeoutError:
            logger.warning(f"Spike test phase {phase_name} timed out")
    
    def validate_sla_compliance(self, result: LoadTestResult) -> Dict[str, bool]:
        """Validate SLA compliance for test results."""
        compliance = {}
        
        # Response time SLAs
        compliance["p50_response_time"] = result.p50_response_time <= self.sla_targets["api_response_time_p50"]
        compliance["p99_response_time"] = result.p99_response_time <= self.sla_targets["api_response_time_p99"]
        
        # Error rate SLA
        compliance["error_rate"] = result.error_rate <= self.sla_targets["error_rate"]
        
        # Throughput SLA (convert from RPS to RPM)
        compliance["throughput"] = (result.throughput_rps * 60) >= self.sla_targets["throughput"]
        
        # Availability (based on error rate)
        availability = 100 - result.error_rate
        compliance["availability"] = availability >= self.sla_targets["availability"]
        
        return compliance
    
    def generate_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance test report."""
        if not self.results:
            return {"error": "No test results available"}
        
        report = {
            "test_summary": {
                "total_tests": len(self.results),
                "test_date": datetime.now().isoformat(),
                "framework_version": "1.0"
            },
            "sla_targets": self.sla_targets,
            "test_results": [],
            "overall_compliance": {},
            "recommendations": []
        }
        
        # Process each test result
        for result in self.results:
            compliance = self.validate_sla_compliance(result)
            
            test_data = {
                "scenario": result.scenario_name,
                "metrics": {
                    "concurrent_users": result.concurrent_users,
                    "total_requests": result.total_requests,
                    "successful_requests": result.successful_requests,
                    "failed_requests": result.failed_requests,
                    "avg_response_time_ms": round(result.avg_response_time, 2),
                    "p50_response_time_ms": round(result.p50_response_time, 2),
                    "p95_response_time_ms": round(result.p95_response_time, 2),
                    "p99_response_time_ms": round(result.p99_response_time, 2),
                    "max_response_time_ms": round(result.max_response_time, 2),
                    "throughput_rps": round(result.throughput_rps, 2),
                    "error_rate_percent": round(result.error_rate, 2),
                    "cpu_usage_percent": round(result.cpu_usage_avg, 2),
                    "memory_usage_mb": round(result.memory_usage_mb, 2),
                    "test_duration_seconds": round(result.test_duration, 2)
                },
                "sla_compliance": compliance,
                "passed": all(compliance.values())
            }
            
            report["test_results"].append(test_data)
        
        # Overall compliance
        all_compliance = {}
        for metric in ["p50_response_time", "p99_response_time", "error_rate", "throughput", "availability"]:
            all_compliance[metric] = all(
                result["sla_compliance"][metric] for result in report["test_results"] 
                if metric in result["sla_compliance"]
            )
        
        report["overall_compliance"] = all_compliance
        
        # Generate recommendations
        if not all_compliance["p99_response_time"]:
            report["recommendations"].append("Optimize slow queries and implement better caching")
        
        if not all_compliance["error_rate"]:
            report["recommendations"].append("Implement better error handling and circuit breakers")
        
        if not all_compliance["throughput"]:
            report["recommendations"].append("Scale infrastructure or optimize application performance")
        
        return report


class ResourceMonitor:
    """Monitor system resources during performance tests."""
    
    def __init__(self):
        """Initialize resource monitor."""
        self.monitoring = False
        self.cpu_readings = []
        self.memory_readings = []
        self.timestamps = []
        self.monitor_thread = None
    
    def start_monitoring(self):
        """Start resource monitoring."""
        self.monitoring = True
        self.cpu_readings = []
        self.memory_readings = []
        self.timestamps = []
        
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop resource monitoring."""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
    
    def _monitor_loop(self):
        """Resource monitoring loop."""
        while self.monitoring:
            try:
                # Get system metrics
                cpu_percent = psutil.cpu_percent(interval=None)
                memory_info = psutil.virtual_memory()
                memory_mb = memory_info.used / 1024 / 1024
                
                self.cpu_readings.append(cpu_percent)
                self.memory_readings.append(memory_mb)
                self.timestamps.append(time.time())
                
                time.sleep(1)  # Sample every second
                
            except Exception as e:
                logger.debug(f"Resource monitoring error: {e}")
    
    def get_averages(self) -> Tuple[float, float]:
        """Get average CPU and memory usage."""
        cpu_avg = statistics.mean(self.cpu_readings) if self.cpu_readings else 0
        memory_avg = statistics.mean(self.memory_readings) if self.memory_readings else 0
        return cpu_avg, memory_avg
    
    def get_memory_trend(self) -> float:
        """Get memory usage trend (% increase per hour)."""
        if len(self.memory_readings) < 10:
            return 0
        
        # Calculate linear regression slope
        n = len(self.memory_readings)
        x = list(range(n))
        y = self.memory_readings
        
        x_mean = statistics.mean(x)
        y_mean = statistics.mean(y)
        
        numerator = sum((x[i] - x_mean) * (y[i] - y_mean) for i in range(n))
        denominator = sum((x[i] - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            return 0
        
        slope = numerator / denominator
        
        # Convert to percentage increase per hour
        samples_per_hour = 3600  # 1 sample per second
        trend_per_hour = (slope * samples_per_hour / y_mean) * 100 if y_mean > 0 else 0
        
        return trend_per_hour


# Test Classes

class TestLoadTesting:
    """Load testing scenarios."""
    
    @pytest.fixture
    def framework(self):
        """Create performance testing framework."""
        return PerformanceTestFramework()
    
    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_normal_load_performance(self, framework):
        """Test system performance under normal load."""
        result = await framework.run_load_test(
            concurrent_users=25,
            duration_minutes=2,
            ramp_up_minutes=0.5
        )
        
        # Validate SLA compliance
        compliance = framework.validate_sla_compliance(result)
        
        assert compliance["p50_response_time"], f"P50 response time {result.p50_response_time}ms exceeds 100ms SLA"
        assert compliance["p99_response_time"], f"P99 response time {result.p99_response_time}ms exceeds 500ms SLA"
        assert compliance["error_rate"], f"Error rate {result.error_rate}% exceeds 1% SLA"
        assert result.cpu_usage_avg < 80, f"CPU usage {result.cpu_usage_avg}% too high"
    
    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_peak_load_performance(self, framework):
        """Test system performance under peak load."""
        result = await framework.run_load_test(
            concurrent_users=100,
            duration_minutes=3,
            ramp_up_minutes=1
        )
        
        # More relaxed SLAs for peak load
        assert result.p95_response_time < 1000, f"P95 response time {result.p95_response_time}ms too high for peak load"
        assert result.error_rate < 5, f"Error rate {result.error_rate}% too high for peak load"
        assert result.cpu_usage_avg < 90, f"CPU usage {result.cpu_usage_avg}% too high"


class TestStressTesting:
    """Stress testing scenarios."""
    
    @pytest.fixture
    def framework(self):
        """Create performance testing framework."""
        return PerformanceTestFramework()
    
    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_breaking_point_identification(self, framework):
        """Identify system breaking point through stress testing."""
        results = await framework.run_stress_test(
            max_users=150,
            step_size=25,
            step_duration=60
        )
        
        # Find breaking point
        breaking_point = None
        for result in results:
            if result.error_rate > 50:  # 50% error rate indicates breakdown
                breaking_point = result.concurrent_users
                break
        
        if breaking_point:
            logger.info(f"System breaking point identified at {breaking_point} concurrent users")
            assert breaking_point >= 50, f"System breaks down too early at {breaking_point} users"
        else:
            logger.info("System handled maximum test load without breakdown")


class TestEnduranceTesting:
    """Endurance testing scenarios."""
    
    @pytest.fixture
    def framework(self):
        """Create performance testing framework."""
        return PerformanceTestFramework()
    
    @pytest.mark.asyncio
    @pytest.mark.very_slow
    async def test_sustained_performance(self, framework):
        """Test sustained performance over extended period."""
        result = await framework.run_endurance_test(
            concurrent_users=20,
            duration_hours=1  # Reduced for testing
        )
        
        # Check for performance degradation
        assert result.error_rate < 2, f"Error rate {result.error_rate}% increased during endurance test"
        
        # Check for memory leaks
        memory_trend = framework.resource_monitor.get_memory_trend()
        assert memory_trend < 10, f"Memory leak detected: {memory_trend}% increase per hour"


class TestSpikeTesting:
    """Spike testing scenarios."""
    
    @pytest.fixture
    def framework(self):
        """Create performance testing framework."""
        return PerformanceTestFramework()
    
    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_traffic_spike_handling(self, framework):
        """Test system response to sudden traffic spikes."""
        result = await framework.run_spike_test(
            baseline_users=10,
            spike_users=50,
            spike_duration=30
        )
        
        # System should handle spike without complete failure
        assert result.error_rate < 20, f"Error rate {result.error_rate}% too high during spike"
        assert result.p95_response_time < 2000, f"Response time {result.p95_response_time}ms too high during spike"


if __name__ == "__main__":
    # Run performance tests
    framework = PerformanceTestFramework()
    
    async def run_full_performance_suite():
        """Run complete performance test suite."""
        print("Starting comprehensive performance testing...")
        
        # Load test
        print("\n1. Running load test...")
        load_result = await framework.run_load_test(concurrent_users=25, duration_minutes=2)
        
        # Stress test
        print("\n2. Running stress test...")
        stress_results = await framework.run_stress_test(max_users=100, step_size=25, step_duration=30)
        
        # Spike test
        print("\n3. Running spike test...")
        spike_result = await framework.run_spike_test(baseline_users=10, spike_users=50, spike_duration=20)
        
        # Generate report
        print("\n4. Generating performance report...")
        report = framework.generate_performance_report()
        
        # Save report
        with open("performance_test_report.json", "w") as f:
            json.dump(report, f, indent=2)
        
        print("Performance testing complete! Report saved to performance_test_report.json")
        
        # Print summary
        print(f"\nSUMMARY:")
        print(f"Total tests: {len(framework.results)}")
        for result in framework.results:
            compliance = framework.validate_sla_compliance(result)
            status = "PASS" if all(compliance.values()) else "FAIL"
            print(f"- {result.scenario_name}: {status} ({result.successful_requests} requests, "
                  f"{result.error_rate:.1f}% error rate)")
    
    # Run the test suite
    asyncio.run(run_full_performance_suite())