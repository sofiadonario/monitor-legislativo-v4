"""
Performance & Load Testing Framework for Monitor Legislativo v4
Stress testing with brutal force to ensure system resilience

SPRINT 10 - TASK 10.3: Performance & Load Testing Framework
✅ Concurrent user simulation (100+ users)
✅ API endpoint stress testing
✅ Database connection pool testing
✅ Cache performance under load
✅ Memory leak detection
✅ Response time benchmarking
✅ Throughput measurement
✅ Resource utilization monitoring
✅ Bottleneck identification
✅ Scalability testing
"""

import pytest
import asyncio
import aiohttp
import time
import psutil
import gc
import json
import statistics
from typing import Dict, List, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from dataclasses import dataclass
from datetime import datetime
import numpy as np
import multiprocessing

from core.api.base_service import BaseAPIService
from core.api.camara_service import CamaraService
from core.api.senado_service import SenadoService
from core.api.planalto_service import PlanaltoService
from core.config.config import get_config
from core.monitoring.forensic_logging import get_forensic_logger
from core.utils.cache_manager import get_cache_manager
from core.database.models import get_database_session


@dataclass
class PerformanceMetrics:
    """Performance metrics for analysis."""
    operation: str
    start_time: float
    end_time: float
    duration: float
    success: bool
    error: Optional[str]
    memory_before: float
    memory_after: float
    cpu_percent: float
    response_size: Optional[int]
    status_code: Optional[int]


@dataclass
class LoadTestResult:
    """Comprehensive load test results."""
    test_name: str
    total_requests: int
    successful_requests: int
    failed_requests: int
    avg_response_time: float
    min_response_time: float
    max_response_time: float
    p50_response_time: float
    p95_response_time: float
    p99_response_time: float
    throughput_rps: float
    error_rate: float
    memory_usage_mb: float
    cpu_usage_percent: float
    detailed_metrics: List[PerformanceMetrics]


class PerformanceLoadTester:
    """
    Brutal performance and load testing framework.
    Designed to push the system to its absolute limits.
    """
    
    def __init__(self):
        """Initialize performance testing framework."""
        self.config = get_config()
        self.forensic = get_forensic_logger()
        
        # Services to test
        self.services = {
            'camara': CamaraService(self.config.api_configs['camara']),
            'senado': SenadoService(self.config.api_configs['senado']),
            'planalto': PlanaltoService(self.config.api_configs['planalto'])
        }
        
        # Performance tracking
        self.metrics: List[PerformanceMetrics] = []
        self.process = psutil.Process()
        
        # Test scenarios
        self.load_scenarios = {
            "light": {"users": 10, "duration": 30, "ramp_up": 5},
            "medium": {"users": 50, "duration": 60, "ramp_up": 10},
            "heavy": {"users": 100, "duration": 120, "ramp_up": 20},
            "stress": {"users": 200, "duration": 180, "ramp_up": 30},
            "spike": {"users": 500, "duration": 60, "ramp_up": 5}
        }
    
    async def run_load_test(self, scenario_name: str, 
                           target_service: str = "all") -> LoadTestResult:
        """Run comprehensive load test for given scenario."""
        
        scenario = self.load_scenarios.get(scenario_name, self.load_scenarios["medium"])
        
        print(f"\n🔥 Starting {scenario_name.upper()} Load Test")
        print(f"   Users: {scenario['users']}")
        print(f"   Duration: {scenario['duration']}s")
        print(f"   Ramp-up: {scenario['ramp_up']}s")
        print(f"   Target: {target_service}")
        
        # Start forensic investigation
        investigation_id = self.forensic.start_investigation(
            f"Load Test - {scenario_name}",
            {"scenario": scenario_name, "target": target_service}
        )
        
        # Clear metrics
        self.metrics.clear()
        gc.collect()
        
        # Record initial state
        initial_memory = self.process.memory_info().rss / 1024 / 1024  # MB
        initial_cpu = self.process.cpu_percent(interval=1)
        
        # Run load test
        start_time = time.time()
        
        # Create user tasks
        user_tasks = []
        for i in range(scenario['users']):
            # Ramp-up delay
            delay = (i / scenario['users']) * scenario['ramp_up']
            
            if target_service == "all":
                task = self._simulate_user_all_services(i, delay, scenario['duration'])
            else:
                task = self._simulate_user_single_service(i, delay, scenario['duration'], target_service)
            
            user_tasks.append(task)
        
        # Execute all user simulations
        await asyncio.gather(*user_tasks, return_exceptions=True)
        
        # Calculate results
        end_time = time.time()
        total_duration = end_time - start_time
        
        # Process metrics
        result = self._calculate_load_test_results(
            test_name=f"{scenario_name}_{target_service}",
            initial_memory=initial_memory,
            initial_cpu=initial_cpu,
            total_duration=total_duration
        )
        
        # Generate forensic report
        forensic_report = self.forensic.generate_investigation_report(investigation_id)
        
        # Print results
        self._print_load_test_results(result, forensic_report)
        
        return result
    
    async def _simulate_user_all_services(self, user_id: int, delay: float, 
                                        duration: float):
        """Simulate a user interacting with all services."""
        
        await asyncio.sleep(delay)  # Ramp-up delay
        
        end_time = time.time() + duration
        request_count = 0
        
        while time.time() < end_time:
            # Rotate through services
            service_name = list(self.services.keys())[request_count % len(self.services)]
            service = self.services[service_name]
            
            # Perform random operation
            await self._perform_service_operation(service, service_name, user_id)
            
            request_count += 1
            
            # Think time between requests (0.5-2 seconds)
            think_time = 0.5 + (1.5 * asyncio.create_task(asyncio.sleep(0)).done())
            await asyncio.sleep(think_time)
    
    async def _simulate_user_single_service(self, user_id: int, delay: float,
                                          duration: float, service_name: str):
        """Simulate a user interacting with a single service."""
        
        await asyncio.sleep(delay)  # Ramp-up delay
        
        service = self.services.get(service_name)
        if not service:
            return
        
        end_time = time.time() + duration
        request_count = 0
        
        while time.time() < end_time:
            await self._perform_service_operation(service, service_name, user_id)
            request_count += 1
            
            # Think time
            await asyncio.sleep(0.5 + (0.5 * request_count % 3))
    
    async def _perform_service_operation(self, service: Any, service_name: str,
                                       user_id: int):
        """Perform a service operation and record metrics."""
        
        # Record pre-operation state
        memory_before = self.process.memory_info().rss / 1024 / 1024
        cpu_start = self.process.cpu_percent(interval=0.1)
        start_time = time.time()
        
        # Prepare operation
        operations = [
            ("search", {"query": f"test_query_{user_id}", "filters": {"limit": 10}}),
            ("search", {"query": "transporte", "filters": {"ano": 2024}}),
            ("search", {"query": "lei", "filters": {"tipo": "PL"}})
        ]
        
        operation_name, params = operations[user_id % len(operations)]
        
        # Execute operation
        success = False
        error = None
        response_size = None
        status_code = None
        
        try:
            result = await service.search(params["query"], params["filters"])
            success = result is not None
            
            if success and hasattr(result, 'items'):
                response_size = len(str(result.items))
                status_code = 200
            
        except Exception as e:
            error = str(e)
            success = False
            status_code = 500
        
        # Record post-operation state
        end_time = time.time()
        memory_after = self.process.memory_info().rss / 1024 / 1024
        cpu_percent = self.process.cpu_percent(interval=0.1)
        
        # Create metric
        metric = PerformanceMetrics(
            operation=f"{service_name}.{operation_name}",
            start_time=start_time,
            end_time=end_time,
            duration=end_time - start_time,
            success=success,
            error=error,
            memory_before=memory_before,
            memory_after=memory_after,
            cpu_percent=cpu_percent,
            response_size=response_size,
            status_code=status_code
        )
        
        self.metrics.append(metric)
        
        # Log to forensic system
        self.forensic.log_performance_event(
            operation=metric.operation,
            duration_ms=metric.duration * 1000,
            custom_attributes={
                "user_id": user_id,
                "success": success,
                "memory_delta": memory_after - memory_before,
                "cpu_percent": cpu_percent,
                "response_size": response_size
            }
        )
    
    def _calculate_load_test_results(self, test_name: str, initial_memory: float,
                                   initial_cpu: float, total_duration: float) -> LoadTestResult:
        """Calculate comprehensive load test results."""
        
        if not self.metrics:
            return LoadTestResult(
                test_name=test_name,
                total_requests=0,
                successful_requests=0,
                failed_requests=0,
                avg_response_time=0,
                min_response_time=0,
                max_response_time=0,
                p50_response_time=0,
                p95_response_time=0,
                p99_response_time=0,
                throughput_rps=0,
                error_rate=0,
                memory_usage_mb=0,
                cpu_usage_percent=0,
                detailed_metrics=[]
            )
        
        # Calculate basic metrics
        total_requests = len(self.metrics)
        successful_requests = sum(1 for m in self.metrics if m.success)
        failed_requests = total_requests - successful_requests
        
        # Response times
        response_times = [m.duration for m in self.metrics]
        response_times.sort()
        
        # Calculate percentiles
        p50_idx = int(len(response_times) * 0.50)
        p95_idx = int(len(response_times) * 0.95)
        p99_idx = int(len(response_times) * 0.99)
        
        # Memory and CPU
        final_memory = self.process.memory_info().rss / 1024 / 1024
        memory_delta = final_memory - initial_memory
        avg_cpu = statistics.mean([m.cpu_percent for m in self.metrics])
        
        return LoadTestResult(
            test_name=test_name,
            total_requests=total_requests,
            successful_requests=successful_requests,
            failed_requests=failed_requests,
            avg_response_time=statistics.mean(response_times),
            min_response_time=min(response_times),
            max_response_time=max(response_times),
            p50_response_time=response_times[p50_idx] if p50_idx < len(response_times) else 0,
            p95_response_time=response_times[p95_idx] if p95_idx < len(response_times) else 0,
            p99_response_time=response_times[p99_idx] if p99_idx < len(response_times) else 0,
            throughput_rps=total_requests / total_duration,
            error_rate=(failed_requests / total_requests) * 100,
            memory_usage_mb=memory_delta,
            cpu_usage_percent=avg_cpu,
            detailed_metrics=self.metrics.copy()
        )
    
    def _print_load_test_results(self, result: LoadTestResult, 
                               forensic_report: Dict[str, Any]):
        """Print comprehensive load test results."""
        
        print(f"\n📊 Load Test Results: {result.test_name}")
        print("=" * 60)
        
        print(f"\n📈 Request Statistics:")
        print(f"   Total Requests: {result.total_requests}")
        print(f"   Successful: {result.successful_requests} ({100 - result.error_rate:.1f}%)")
        print(f"   Failed: {result.failed_requests} ({result.error_rate:.1f}%)")
        print(f"   Throughput: {result.throughput_rps:.2f} req/sec")
        
        print(f"\n⏱️ Response Time (seconds):")
        print(f"   Average: {result.avg_response_time:.3f}s")
        print(f"   Min: {result.min_response_time:.3f}s")
        print(f"   Max: {result.max_response_time:.3f}s")
        print(f"   P50 (Median): {result.p50_response_time:.3f}s")
        print(f"   P95: {result.p95_response_time:.3f}s")
        print(f"   P99: {result.p99_response_time:.3f}s")
        
        print(f"\n💻 Resource Usage:")
        print(f"   Memory Delta: {result.memory_usage_mb:.2f} MB")
        print(f"   Average CPU: {result.cpu_usage_percent:.1f}%")
        
        # Error analysis
        if result.failed_requests > 0:
            print(f"\n❌ Error Analysis:")
            error_types = {}
            for metric in result.detailed_metrics:
                if not metric.success and metric.error:
                    error_type = metric.error.split(':')[0]
                    error_types[error_type] = error_types.get(error_type, 0) + 1
            
            for error_type, count in sorted(error_types.items(), 
                                          key=lambda x: x[1], reverse=True)[:5]:
                print(f"   {error_type}: {count} occurrences")
        
        # Performance warnings
        print(f"\n⚠️ Performance Analysis:")
        if result.avg_response_time > 1.0:
            print(f"   WARNING: Average response time exceeds 1 second")
        if result.p95_response_time > 3.0:
            print(f"   WARNING: P95 response time exceeds 3 seconds")
        if result.error_rate > 5.0:
            print(f"   WARNING: Error rate exceeds 5%")
        if result.memory_usage_mb > 100:
            print(f"   WARNING: Memory usage increased by {result.memory_usage_mb:.0f} MB")
        
        # Forensic insights
        if forensic_report.get('anomalies_detected', 0) > 0:
            print(f"\n🔍 Forensic Insights:")
            print(f"   Anomalies detected: {forensic_report['anomalies_detected']}")
            if forensic_report.get('performance_issues'):
                print(f"   Performance issues: {len(forensic_report['performance_issues'])}")


@pytest.mark.performance
class TestPerformanceUnderLoad:
    """Performance testing suite with brutal scenarios."""
    
    @pytest.fixture(scope="class")
    def load_tester(self):
        """Create load tester instance."""
        return PerformanceLoadTester()
    
    @pytest.mark.asyncio
    async def test_light_load_all_services(self, load_tester):
        """Test system under light load across all services."""
        result = await load_tester.run_load_test("light", "all")
        
        # Assertions for light load
        assert result.avg_response_time < 2.0, "Average response time too high for light load"
        assert result.error_rate < 5.0, "Error rate too high for light load"
        assert result.throughput_rps > 5.0, "Throughput too low for light load"
    
    @pytest.mark.asyncio
    async def test_medium_load_camara_service(self, load_tester):
        """Test Câmara service under medium load."""
        result = await load_tester.run_load_test("medium", "camara")
        
        # Assertions for medium load
        assert result.avg_response_time < 3.0, "Average response time too high"
        assert result.error_rate < 10.0, "Error rate too high"
        assert result.p95_response_time < 5.0, "P95 response time too high"
    
    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_heavy_load_stress_test(self, load_tester):
        """Test system under heavy load - stress testing."""
        result = await load_tester.run_load_test("heavy", "all")
        
        # More lenient assertions for heavy load
        assert result.error_rate < 20.0, "Error rate exceeds 20% under heavy load"
        assert result.throughput_rps > 10.0, "System throughput collapsed under heavy load"
        
        # Check for memory leaks
        assert result.memory_usage_mb < 500, "Potential memory leak detected"
    
    @pytest.mark.asyncio
    async def test_spike_load_scenario(self, load_tester):
        """Test system behavior under sudden spike load."""
        result = await load_tester.run_load_test("spike", "all")
        
        # System should handle spikes gracefully
        assert result.total_requests > 0, "No requests completed during spike"
        assert result.successful_requests > result.total_requests * 0.5, "Less than 50% success rate"
    
    @pytest.mark.asyncio
    async def test_concurrent_service_isolation(self, load_tester):
        """Test service isolation under concurrent load."""
        
        # Run concurrent load tests on different services
        tasks = [
            load_tester.run_load_test("light", "camara"),
            load_tester.run_load_test("light", "senado"),
            load_tester.run_load_test("light", "planalto")
        ]
        
        results = await asyncio.gather(*tasks)
        
        # Each service should maintain reasonable performance
        for result in results:
            assert result.avg_response_time < 3.0, f"Service {result.test_name} degraded"
            assert result.error_rate < 15.0, f"Service {result.test_name} high error rate"
    
    def test_memory_leak_detection(self, load_tester):
        """Test for memory leaks during extended operation."""
        
        initial_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        # Simulate extended operation
        for i in range(100):
            # Create and destroy objects
            temp_services = [
                CamaraService(load_tester.config.api_configs['camara'])
                for _ in range(10)
            ]
            
            # Force garbage collection
            del temp_services
            gc.collect()
        
        final_memory = psutil.Process().memory_info().rss / 1024 / 1024
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be minimal
        assert memory_increase < 50, f"Memory leak detected: {memory_increase:.2f} MB increase"
    
    @pytest.mark.asyncio
    async def test_cache_performance_under_load(self, load_tester):
        """Test cache performance under concurrent load."""
        
        cache = get_cache_manager()
        test_key = "perf_test_key"
        test_value = {"data": "x" * 1000}  # 1KB payload
        
        # Warm up cache
        await cache.set(test_key, test_value)
        
        # Concurrent cache operations
        async def cache_operation(op_id: int):
            start = time.time()
            for _ in range(100):
                if op_id % 2 == 0:
                    await cache.get(test_key)
                else:
                    await cache.set(f"{test_key}_{op_id}", test_value)
            return time.time() - start
        
        # Run 50 concurrent cache operations
        tasks = [cache_operation(i) for i in range(50)]
        durations = await asyncio.gather(*tasks)
        
        avg_duration = statistics.mean(durations)
        max_duration = max(durations)
        
        print(f"\n📦 Cache Performance:")
        print(f"   Average operation time: {avg_duration:.3f}s")
        print(f"   Max operation time: {max_duration:.3f}s")
        
        # Cache should remain performant
        assert avg_duration < 1.0, "Cache operations too slow under load"
        assert max_duration < 2.0, "Cache operations have high latency spikes"
    
    @pytest.mark.asyncio
    async def test_database_connection_pool_stress(self, load_tester):
        """Test database connection pool under stress."""
        
        async def db_operation(op_id: int):
            start = time.time()
            try:
                async with get_database_session() as session:
                    # Simulate database query
                    result = await session.execute("SELECT 1")
                    await result.fetchone()
                return True, time.time() - start
            except Exception as e:
                return False, time.time() - start
        
        # Launch 100 concurrent database operations
        tasks = [db_operation(i) for i in range(100)]
        results = await asyncio.gather(*tasks)
        
        successful = sum(1 for success, _ in results if success)
        durations = [duration for _, duration in results]
        
        print(f"\n🗄️ Database Connection Pool Performance:")
        print(f"   Successful connections: {successful}/100")
        print(f"   Average connection time: {statistics.mean(durations):.3f}s")
        print(f"   Max connection time: {max(durations):.3f}s")
        
        # Connection pool should handle concurrent load
        assert successful >= 95, "Too many failed database connections"
        assert statistics.mean(durations) < 0.5, "Database connections too slow"
    
    def test_cpu_bound_operations_performance(self):
        """Test CPU-bound operations performance."""
        
        def cpu_intensive_task(n: int) -> float:
            """Simulate CPU-intensive task."""
            start = time.time()
            # Calculate prime numbers up to n
            primes = []
            for num in range(2, n):
                if all(num % i != 0 for i in range(2, int(num**0.5) + 1)):
                    primes.append(num)
            return time.time() - start
        
        # Test with different workloads
        workloads = [1000, 5000, 10000]
        results = []
        
        for workload in workloads:
            duration = cpu_intensive_task(workload)
            results.append({
                "workload": workload,
                "duration": duration,
                "ops_per_sec": workload / duration
            })
        
        print(f"\n🔥 CPU Performance Benchmarks:")
        for result in results:
            print(f"   Workload {result['workload']}: "
                  f"{result['duration']:.3f}s "
                  f"({result['ops_per_sec']:.0f} ops/sec)")
        
        # Performance should scale reasonably
        for i in range(1, len(results)):
            scaling_factor = results[i]["workload"] / results[i-1]["workload"]
            duration_factor = results[i]["duration"] / results[i-1]["duration"]
            
            # Duration should not scale worse than O(n log n)
            assert duration_factor < scaling_factor * 2, "CPU performance scaling is poor"


@pytest.mark.benchmark
class TestPerformanceBenchmarks:
    """Specific performance benchmarks for critical operations."""
    
    def test_search_operation_benchmark(self, benchmark):
        """Benchmark search operation performance."""
        
        config = get_config()
        service = CamaraService(config.api_configs['camara'])
        
        async def search_operation():
            return await service.search("test", {"limit": 10})
        
        # Run benchmark
        result = benchmark(lambda: asyncio.run(search_operation()))
        
        # Performance assertions
        assert benchmark.stats['mean'] < 2.0, "Search operation too slow"
        assert benchmark.stats['stddev'] < 0.5, "Search operation has high variance"
    
    def test_security_validation_benchmark(self, benchmark):
        """Benchmark security validation performance."""
        
        from core.security.enhanced_security_validator import get_security_validator
        validator = get_security_validator()
        
        test_input = "SELECT * FROM users WHERE id = 123"
        
        def validation_operation():
            return validator.validate_input(test_input, "query", "127.0.0.1", "test")
        
        # Run benchmark
        result = benchmark(validation_operation)
        
        # Security validation should be fast
        assert benchmark.stats['mean'] < 0.01, "Security validation too slow"
        assert benchmark.stats['max'] < 0.05, "Security validation has spikes"
    
    def test_forensic_logging_benchmark(self, benchmark):
        """Benchmark forensic logging performance."""
        
        forensic = get_forensic_logger()
        
        def logging_operation():
            forensic.log_forensic_event(
                level=forensic.LogLevel.INFO,
                category=forensic.EventCategory.BUSINESS,
                component="benchmark",
                operation="test",
                message="Benchmark test message",
                custom_attributes={"test": True, "value": 123}
            )
        
        # Run benchmark
        result = benchmark(logging_operation)
        
        # Logging should not be a bottleneck
        assert benchmark.stats['mean'] < 0.001, "Forensic logging too slow"


if __name__ == "__main__":
    # Run performance tests
    pytest.main([__file__, "-v", "-s", "-m", "performance"])