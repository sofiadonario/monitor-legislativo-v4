#!/usr/bin/env python3
"""
Load Testing Suite for Monitor Legislativo v4

Tests system performance under various load conditions:
- Concurrent user simulation
- API endpoint stress testing
- Database connection pooling
- Cache performance under load
- Memory leak detection
- Response time degradation analysis
"""

import asyncio
import aiohttp
import time
import statistics
import json
import sys
import argparse
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
from pathlib import Path
import psutil
import signal

@dataclass
class LoadTestResult:
    """Result of a load test scenario"""
    scenario_name: str
    concurrent_users: int
    duration: float
    total_requests: int
    successful_requests: int
    failed_requests: int
    avg_response_time: float
    min_response_time: float
    max_response_time: float
    p95_response_time: float
    requests_per_second: float
    error_rate: float
    memory_usage_mb: float
    cpu_usage_percent: float

@dataclass 
class LoadTestConfig:
    """Configuration for load testing"""
    base_url: str
    max_concurrent_users: int
    test_duration: int  # seconds
    ramp_up_time: int   # seconds
    endpoints: List[str]
    user_think_time: float  # seconds between requests

class LoadTester:
    """Advanced load testing implementation"""
    
    def __init__(self, config: LoadTestConfig):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.results: List[LoadTestResult] = []
        self.running = True
        self.start_time = 0
        
        # Statistics tracking
        self.response_times: List[float] = []
        self.request_count = 0
        self.error_count = 0
        
        # Resource monitoring
        self.process = psutil.Process()
        self.initial_memory = 0
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\n⚠️ Received signal {signum}, shutting down gracefully...")
        self.running = False
    
    async def __aenter__(self):
        """Async context manager entry"""
        connector = aiohttp.TCPConnector(
            limit=200,  # Total connection pool size
            limit_per_host=100,  # Connections per host
            ttl_dns_cache=300,
            use_dns_cache=True,
            keepalive_timeout=60,
            enable_cleanup_closed=True
        )
        
        timeout = aiohttp.ClientTimeout(
            total=30,
            sock_connect=10,
            sock_read=10
        )
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': 'LoadTester/1.0'}
        )
        
        self.initial_memory = self.process.memory_info().rss / 1024 / 1024
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def make_request(self, endpoint: str, user_id: int) -> Dict[str, Any]:
        """Make a single request and return metrics"""
        url = f"{self.config.base_url}{endpoint}"
        
        try:
            start_time = time.time()
            
            async with self.session.get(url) as response:
                await response.text()  # Read response body
                end_time = time.time()
                
                response_time = end_time - start_time
                
                return {
                    'success': response.status < 400,
                    'status_code': response.status,
                    'response_time': response_time,
                    'user_id': user_id,
                    'endpoint': endpoint,
                    'timestamp': start_time
                }
                
        except asyncio.TimeoutError:
            return {
                'success': False,
                'status_code': 408,
                'response_time': 30.0,  # Timeout duration
                'user_id': user_id,
                'endpoint': endpoint,
                'timestamp': time.time(),
                'error': 'timeout'
            }
        except Exception as e:
            return {
                'success': False,
                'status_code': 0,
                'response_time': 0.0,
                'user_id': user_id,
                'endpoint': endpoint,
                'timestamp': time.time(),
                'error': str(e)
            }
    
    async def simulate_user(self, user_id: int, start_delay: float) -> List[Dict]:
        """Simulate a single user's behavior"""
        # Wait for ramp-up
        await asyncio.sleep(start_delay)
        
        user_results = []
        user_start_time = time.time()
        
        while self.running and (time.time() - self.start_time) < self.config.test_duration:
            # Select random endpoint
            import random
            endpoint = random.choice(self.config.endpoints)
            
            # Make request
            result = await self.make_request(endpoint, user_id)
            user_results.append(result)
            
            # Update global stats
            self.request_count += 1
            if result['success']:
                self.response_times.append(result['response_time'])
            else:
                self.error_count += 1
            
            # Think time between requests
            if self.config.user_think_time > 0:
                await asyncio.sleep(self.config.user_think_time)
        
        return user_results
    
    async def run_load_test_scenario(self, concurrent_users: int) -> LoadTestResult:
        """Run a load test scenario with specified concurrent users"""
        print(f"🚀 Starting load test: {concurrent_users} concurrent users")
        
        # Reset statistics
        self.response_times = []
        self.request_count = 0
        self.error_count = 0
        self.running = True
        self.start_time = time.time()
        
        # Calculate ramp-up delays
        ramp_up_delay = self.config.ramp_up_time / concurrent_users if concurrent_users > 0 else 0
        
        # Start resource monitoring
        initial_memory = self.process.memory_info().rss / 1024 / 1024
        initial_cpu = self.process.cpu_percent()
        
        # Create user simulation tasks
        user_tasks = []
        for user_id in range(concurrent_users):
            start_delay = user_id * ramp_up_delay
            task = asyncio.create_task(
                self.simulate_user(user_id, start_delay)
            )
            user_tasks.append(task)
        
        print(f"  Ramping up {concurrent_users} users over {self.config.ramp_up_time}s...")
        
        # Wait for test completion or interruption
        try:
            await asyncio.wait_for(
                asyncio.gather(*user_tasks, return_exceptions=True),
                timeout=self.config.test_duration + self.config.ramp_up_time + 30
            )
        except asyncio.TimeoutError:
            print("  Test timed out, collecting results...")
        
        # Stop all tasks
        self.running = False
        for task in user_tasks:
            if not task.done():
                task.cancel()
        
        # Wait for tasks to complete cleanup
        await asyncio.gather(*user_tasks, return_exceptions=True)
        
        # Calculate final metrics
        test_duration = time.time() - self.start_time
        
        # Resource usage
        final_memory = self.process.memory_info().rss / 1024 / 1024
        final_cpu = self.process.cpu_percent()
        
        # Response time statistics
        if self.response_times:
            avg_response_time = statistics.mean(self.response_times)
            min_response_time = min(self.response_times)
            max_response_time = max(self.response_times)
            p95_response_time = statistics.quantiles(self.response_times, n=20)[18] if len(self.response_times) >= 20 else max_response_time
        else:
            avg_response_time = min_response_time = max_response_time = p95_response_time = 0.0
        
        # Request rate
        requests_per_second = self.request_count / test_duration if test_duration > 0 else 0
        
        # Error rate
        error_rate = (self.error_count / self.request_count * 100) if self.request_count > 0 else 0
        
        result = LoadTestResult(
            scenario_name=f"{concurrent_users}_users",
            concurrent_users=concurrent_users,
            duration=test_duration,
            total_requests=self.request_count,
            successful_requests=self.request_count - self.error_count,
            failed_requests=self.error_count,
            avg_response_time=avg_response_time,
            min_response_time=min_response_time,
            max_response_time=max_response_time,
            p95_response_time=p95_response_time,
            requests_per_second=requests_per_second,
            error_rate=error_rate,
            memory_usage_mb=final_memory,
            cpu_usage_percent=final_cpu
        )
        
        print(f"✅ Completed: {self.request_count} requests, {error_rate:.1f}% errors, {requests_per_second:.1f} req/s")
        
        return result
    
    async def run_spike_test(self) -> LoadTestResult:
        """Run spike test - sudden load increase"""
        print("⚡ Running spike test...")
        
        # Start with low load
        initial_users = 5
        spike_users = min(50, self.config.max_concurrent_users)
        
        # Reset stats
        self.response_times = []
        self.request_count = 0
        self.error_count = 0
        self.running = True
        self.start_time = time.time()
        
        # Start initial users
        initial_tasks = []
        for user_id in range(initial_users):
            task = asyncio.create_task(self.simulate_user(user_id, 0))
            initial_tasks.append(task)
        
        # Wait 10 seconds
        await asyncio.sleep(10)
        
        # Sudden spike
        spike_tasks = []
        for user_id in range(initial_users, spike_users):
            task = asyncio.create_task(self.simulate_user(user_id, 0))
            spike_tasks.append(task)
        
        print(f"  Spiking from {initial_users} to {spike_users} users...")
        
        # Run for remaining duration
        remaining_time = max(0, self.config.test_duration - 10)
        if remaining_time > 0:
            await asyncio.sleep(remaining_time)
        
        # Stop test
        self.running = False
        all_tasks = initial_tasks + spike_tasks
        
        for task in all_tasks:
            if not task.done():
                task.cancel()
        
        await asyncio.gather(*all_tasks, return_exceptions=True)
        
        # Calculate metrics
        test_duration = time.time() - self.start_time
        avg_response_time = statistics.mean(self.response_times) if self.response_times else 0
        requests_per_second = self.request_count / test_duration if test_duration > 0 else 0
        error_rate = (self.error_count / self.request_count * 100) if self.request_count > 0 else 0
        
        result = LoadTestResult(
            scenario_name="spike_test",
            concurrent_users=spike_users,
            duration=test_duration,
            total_requests=self.request_count,
            successful_requests=self.request_count - self.error_count,
            failed_requests=self.error_count,
            avg_response_time=avg_response_time,
            min_response_time=min(self.response_times) if self.response_times else 0,
            max_response_time=max(self.response_times) if self.response_times else 0,
            p95_response_time=statistics.quantiles(self.response_times, n=20)[18] if len(self.response_times) >= 20 else 0,
            requests_per_second=requests_per_second,
            error_rate=error_rate,
            memory_usage_mb=self.process.memory_info().rss / 1024 / 1024,
            cpu_usage_percent=self.process.cpu_percent()
        )
        
        print(f"✅ Spike test completed: {error_rate:.1f}% errors under spike load")
        
        return result
    
    async def run_endurance_test(self) -> LoadTestResult:
        """Run endurance test - sustained load"""
        print("⏰ Running endurance test...")
        
        users = min(20, self.config.max_concurrent_users // 2)
        original_duration = self.config.test_duration
        
        # Extend duration for endurance test
        self.config.test_duration = max(300, original_duration * 3)  # At least 5 minutes
        
        try:
            result = await self.run_load_test_scenario(users)
            result.scenario_name = "endurance_test"
            
            print(f"✅ Endurance test completed: sustained {users} users for {result.duration:.0f}s")
            
        finally:
            # Restore original duration
            self.config.test_duration = original_duration
        
        return result
    
    async def run_comprehensive_load_test(self) -> Dict[str, Any]:
        """Run comprehensive load testing suite"""
        print("🧪 Starting comprehensive load testing suite...")
        print("=" * 60)
        
        suite_start = time.time()
        
        # Progressive load scenarios
        user_scenarios = [1, 5, 10, 25]
        if self.config.max_concurrent_users > 25:
            user_scenarios.extend([50, 75, 100])
        
        # Limit scenarios based on max_concurrent_users
        user_scenarios = [u for u in user_scenarios if u <= self.config.max_concurrent_users]
        
        # Run progressive load tests
        for users in user_scenarios:
            if not self.running:
                break
                
            result = await self.run_load_test_scenario(users)
            self.results.append(result)
            
            # Brief pause between scenarios
            await asyncio.sleep(5)
        
        # Run special scenarios if still running
        if self.running and self.config.max_concurrent_users >= 20:
            # Spike test
            try:
                spike_result = await self.run_spike_test()
                self.results.append(spike_result)
                await asyncio.sleep(5)
            except Exception as e:
                print(f"⚠️ Spike test failed: {e}")
        
        if self.running and self.config.test_duration >= 60:
            # Endurance test
            try:
                endurance_result = await self.run_endurance_test()
                self.results.append(endurance_result)
            except Exception as e:
                print(f"⚠️ Endurance test failed: {e}")
        
        suite_duration = time.time() - suite_start
        
        return self.generate_load_test_report(suite_duration)
    
    def generate_load_test_report(self, suite_duration: float) -> Dict[str, Any]:
        """Generate comprehensive load test report"""
        print("\n" + "=" * 60)
        print("📊 LOAD TEST RESULTS")
        print("=" * 60)
        
        if not self.results:
            print("❌ No test results available")
            return {}
        
        # Find performance breakdown point
        breakdown_point = None
        for i, result in enumerate(self.results):
            if result.error_rate > 5.0 or result.avg_response_time > 5.0:
                breakdown_point = i
                break
        
        # Summary
        max_successful_users = 0
        best_throughput = 0
        
        for result in self.results:
            if result.error_rate <= 5.0:
                max_successful_users = max(max_successful_users, result.concurrent_users)
            best_throughput = max(best_throughput, result.requests_per_second)
        
        print(f"Suite Duration: {suite_duration:.1f} seconds")
        print(f"Max Stable Users: {max_successful_users}")
        print(f"Peak Throughput: {best_throughput:.1f} req/s")
        if breakdown_point is not None:
            print(f"Performance Breakdown: {self.results[breakdown_point].concurrent_users} users")
        
        # Detailed results
        print("\nDETAILED RESULTS:")
        print("-" * 60)
        print(f"{'Scenario':<15} {'Users':<6} {'Req/s':<8} {'Avg(ms)':<9} {'P95(ms)':<9} {'Errors':<8} {'Memory':<8}")
        print("-" * 60)
        
        for result in self.results:
            print(f"{result.scenario_name:<15} "
                  f"{result.concurrent_users:<6} "
                  f"{result.requests_per_second:<8.1f} "
                  f"{result.avg_response_time*1000:<9.0f} "
                  f"{result.p95_response_time*1000:<9.0f} "
                  f"{result.error_rate:<7.1f}% "
                  f"{result.memory_usage_mb:<7.0f}MB")
        
        # Performance insights
        print("\nPERFORMANCE INSIGHTS:")
        print("-" * 40)
        
        if max_successful_users >= 50:
            print("✅ System handles high load well (50+ concurrent users)")
        elif max_successful_users >= 25:
            print("⚠️ System handles moderate load (25+ concurrent users)")
        else:
            print("❌ System struggles with load (< 25 concurrent users)")
        
        if best_throughput >= 100:
            print("✅ Excellent throughput (100+ req/s)")
        elif best_throughput >= 50:
            print("⚠️ Good throughput (50+ req/s)")
        else:
            print("❌ Low throughput (< 50 req/s)")
        
        # Recommendations
        print("\nRECOMMENDATIONS:")
        print("-" * 40)
        
        if breakdown_point is not None:
            breakdown_result = self.results[breakdown_point]
            if breakdown_result.avg_response_time > 5.0:
                print("⚠️ Response time degrades under load - consider:")
                print("  • Database connection pooling")
                print("  • Cache optimization")
                print("  • Query optimization")
            
            if breakdown_result.error_rate > 5.0:
                print("⚠️ Error rate increases under load - consider:")
                print("  • Connection timeout tuning")
                print("  • Rate limiting")
                print("  • Circuit breaker pattern")
        
        memory_growth = [r.memory_usage_mb for r in self.results]
        if memory_growth and max(memory_growth) - min(memory_growth) > 100:
            print("⚠️ Significant memory growth detected - check for memory leaks")
        
        # Export data
        report_data = {
            "timestamp": time.time(),
            "suite_duration": suite_duration,
            "config": asdict(self.config),
            "summary": {
                "max_successful_users": max_successful_users,
                "peak_throughput": best_throughput,
                "breakdown_point": breakdown_point
            },
            "results": [asdict(result) for result in self.results]
        }
        
        return report_data
    
    def save_report(self, report_data: Dict[str, Any]) -> str:
        """Save load test report to file"""
        report_path = Path(__file__).parent / f"load_test_report_{int(time.time())}.json"
        
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"\n📄 Full report saved to: {report_path}")
        return str(report_path)

def create_default_config(base_url: str) -> LoadTestConfig:
    """Create default load test configuration"""
    return LoadTestConfig(
        base_url=base_url,
        max_concurrent_users=100,
        test_duration=60,  # 1 minute per scenario
        ramp_up_time=10,   # 10 seconds ramp-up
        endpoints=[
            "/health",
            "/api/v1/search?q=transporte",
            "/api/v1/search?q=mobilidade&sources=lexml",
            "/api/v1/collections/recent",
            "/api/v1/collections/latest"
        ],
        user_think_time=1.0  # 1 second between requests
    )

async def main():
    """Main load test runner"""
    parser = argparse.ArgumentParser(description="Load Testing Suite for Monitor Legislativo v4")
    parser.add_argument("--url", default="http://localhost:8000", help="Base URL for load testing")
    parser.add_argument("--users", type=int, default=100, help="Maximum concurrent users")
    parser.add_argument("--duration", type=int, default=60, help="Test duration per scenario (seconds)")
    parser.add_argument("--quick", action="store_true", help="Run quick load test only")
    args = parser.parse_args()
    
    print("🚀 Monitor Legislativo v4 - Load Testing Suite")
    print(f"Target: {args.url}")
    print(f"Max Users: {args.users}")
    print(f"Duration: {args.duration}s per scenario")
    print("=" * 60)
    
    config = create_default_config(args.url)
    config.max_concurrent_users = args.users
    config.test_duration = args.duration
    
    async with LoadTester(config) as tester:
        try:
            if args.quick:
                # Quick test with limited scenarios
                result = await tester.run_load_test_scenario(min(10, args.users))
                tester.results.append(result)
                report = tester.generate_load_test_report(result.duration)
            else:
                # Full load test suite
                report = await tester.run_comprehensive_load_test()
            
            # Save report
            tester.save_report(report)
            
            # Exit based on results
            if report.get("summary", {}).get("max_successful_users", 0) < 10:
                print("\n❌ Load test failed - system cannot handle minimum load")
                sys.exit(1)
            else:
                print("\n✅ Load test completed successfully")
                sys.exit(0)
                
        except KeyboardInterrupt:
            print("\n⚠️ Load test interrupted by user")
            sys.exit(130)
        except Exception as e:
            print(f"\n❌ Load test failed: {e}")
            sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())