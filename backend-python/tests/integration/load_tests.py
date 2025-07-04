"""
Load Testing for Monitor Legislativo
Tests system performance under various load conditions
"""

import asyncio
import random
import time
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any
import logging

# Add project root to path
project_root = Path(__file__).parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from core.api.api_service import APIService
from core.utils.monitoring import metrics_collector


class LoadTester:
    """Load testing for the Monitor Legislativo system"""
    
    def __init__(self):
        self.logger = logging.getLogger("LoadTester")
        self.api_service = APIService()
        
        # Test scenarios
        self.test_queries = [
            "energia renovável", "saúde pública", "educação", "meio ambiente",
            "segurança pública", "economia", "agricultura", "tecnologia",
            "infraestrutura", "direitos humanos", "transporte", "habitação"
        ]
        
        self.filter_scenarios = [
            {},  # No filters
            {"start_date": "2024-01-01"},  # Date filter
            {"end_date": "2024-12-31"},  # End date filter
            {"start_date": "2024-06-01", "end_date": "2024-12-31"}  # Date range
        ]
        
        self.results = []
    
    async def run_load_test(self, concurrent_users: int = 5, 
                           duration_minutes: int = 10,
                           requests_per_user: int = 20) -> Dict[str, Any]:
        """Run load test with specified parameters"""
        
        print(f"🔥 Starting Load Test")
        print(f"Users: {concurrent_users}, Duration: {duration_minutes}m, Requests/User: {requests_per_user}")
        print("=" * 60)
        
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=duration_minutes)
        
        # Create user tasks
        tasks = []
        for user_id in range(concurrent_users):
            task = asyncio.create_task(
                self._simulate_user(user_id, end_time, requests_per_user)
            )
            tasks.append(task)
        
        # Wait for all tasks to complete
        await asyncio.gather(*tasks)
        
        # Calculate results
        actual_duration = (datetime.now() - start_time).total_seconds()
        
        return self._calculate_load_test_results(actual_duration, concurrent_users)
    
    async def _simulate_user(self, user_id: int, end_time: datetime, max_requests: int):
        """Simulate a single user making requests"""
        request_count = 0
        
        while datetime.now() < end_time and request_count < max_requests:
            try:
                # Random delay between requests (1-5 seconds)
                await asyncio.sleep(random.uniform(1, 5))
                
                # Select random query and filters
                query = random.choice(self.test_queries)
                filters = random.choice(self.filter_scenarios)
                
                # Select random sources (1-3 sources)
                available_sources = list(self.api_service.get_available_sources().keys())
                num_sources = random.randint(1, min(3, len(available_sources)))
                selected_sources = random.sample(available_sources, num_sources)
                
                # Make request
                start_request = time.time()
                try:
                    results = await asyncio.wait_for(
                        self.api_service.search_all(query, filters, selected_sources),
                        timeout=30
                    )
                    
                    response_time = time.time() - start_request
                    total_results = sum(r.total_count for r in results)
                    
                    self.results.append({
                        "user_id": user_id,
                        "timestamp": datetime.now(),
                        "query": query,
                        "sources": selected_sources,
                        "response_time": response_time,
                        "result_count": total_results,
                        "success": True,
                        "error": None
                    })
                    
                    print(f"User {user_id}: {query} -> {total_results} results in {response_time:.2f}s")
                    
                except asyncio.TimeoutError:
                    self.results.append({
                        "user_id": user_id,
                        "timestamp": datetime.now(),
                        "query": query,
                        "sources": selected_sources,
                        "response_time": 30.0,
                        "result_count": 0,
                        "success": False,
                        "error": "timeout"
                    })
                    print(f"User {user_id}: {query} -> TIMEOUT")
                
                except Exception as e:
                    response_time = time.time() - start_request
                    self.results.append({
                        "user_id": user_id,
                        "timestamp": datetime.now(),
                        "query": query,
                        "sources": selected_sources,
                        "response_time": response_time,
                        "result_count": 0,
                        "success": False,
                        "error": str(e)
                    })
                    print(f"User {user_id}: {query} -> ERROR: {str(e)[:50]}")
                
                request_count += 1
                
            except Exception as e:
                self.logger.error(f"User {user_id} simulation error: {e}")
                await asyncio.sleep(1)
    
    def _calculate_load_test_results(self, duration: float, concurrent_users: int) -> Dict[str, Any]:
        """Calculate and format load test results"""
        
        if not self.results:
            return {"error": "No results collected"}
        
        # Basic statistics
        total_requests = len(self.results)
        successful_requests = sum(1 for r in self.results if r["success"])
        failed_requests = total_requests - successful_requests
        
        # Response time statistics
        response_times = [r["response_time"] for r in self.results if r["success"]]
        if response_times:
            avg_response_time = sum(response_times) / len(response_times)
            min_response_time = min(response_times)
            max_response_time = max(response_times)
            
            # Percentiles
            sorted_times = sorted(response_times)
            p50 = sorted_times[len(sorted_times) // 2]
            p95 = sorted_times[int(len(sorted_times) * 0.95)]
            p99 = sorted_times[int(len(sorted_times) * 0.99)]
        else:
            avg_response_time = min_response_time = max_response_time = 0
            p50 = p95 = p99 = 0
        
        # Throughput
        requests_per_second = total_requests / duration if duration > 0 else 0
        
        # Error analysis
        error_types = {}
        for result in self.results:
            if not result["success"] and result["error"]:
                error_type = result["error"]
                error_types[error_type] = error_types.get(error_type, 0) + 1
        
        # Source performance
        source_performance = {}
        for result in self.results:
            for source in result["sources"]:
                if source not in source_performance:
                    source_performance[source] = {"requests": 0, "successes": 0, "total_time": 0}
                
                source_performance[source]["requests"] += 1
                if result["success"]:
                    source_performance[source]["successes"] += 1
                    source_performance[source]["total_time"] += result["response_time"]
        
        # Calculate source success rates and avg response times
        for source, stats in source_performance.items():
            stats["success_rate"] = (stats["successes"] / stats["requests"]) * 100 if stats["requests"] > 0 else 0
            stats["avg_response_time"] = stats["total_time"] / stats["successes"] if stats["successes"] > 0 else 0
        
        return {
            "test_info": {
                "duration_seconds": round(duration, 2),
                "concurrent_users": concurrent_users,
                "timestamp": datetime.now().isoformat()
            },
            "summary": {
                "total_requests": total_requests,
                "successful_requests": successful_requests,
                "failed_requests": failed_requests,
                "success_rate": round((successful_requests / total_requests) * 100, 2) if total_requests > 0 else 0,
                "requests_per_second": round(requests_per_second, 2)
            },
            "response_times": {
                "average": round(avg_response_time, 2),
                "minimum": round(min_response_time, 2),
                "maximum": round(max_response_time, 2),
                "p50_median": round(p50, 2),
                "p95": round(p95, 2),
                "p99": round(p99, 2)
            },
            "errors": error_types,
            "source_performance": source_performance,
            "raw_results": self.results
        }
    
    async def run_stress_test(self) -> Dict[str, Any]:
        """Run stress test with increasing load"""
        print("💥 Starting Stress Test - Increasing Load")
        print("=" * 50)
        
        stress_results = []
        
        # Test with increasing concurrent users
        user_levels = [1, 3, 5, 10, 15, 20]
        
        for users in user_levels:
            print(f"\n🔸 Testing with {users} concurrent users...")
            
            # Reset results for this test
            self.results = []
            
            # Run test for 3 minutes
            result = await self.run_load_test(
                concurrent_users=users,
                duration_minutes=3,
                requests_per_user=10
            )
            
            stress_results.append({
                "concurrent_users": users,
                "summary": result["summary"],
                "response_times": result["response_times"]
            })
            
            # Print summary
            summary = result["summary"]
            response_times = result["response_times"]
            print(f"  Success Rate: {summary['success_rate']}%")
            print(f"  RPS: {summary['requests_per_second']}")
            print(f"  Avg Response: {response_times['average']}s")
            print(f"  P95: {response_times['p95']}s")
            
            # Break if performance degrades significantly
            if summary["success_rate"] < 50 or response_times["p95"] > 60:
                print(f"  ⚠️  Performance degraded significantly - stopping stress test")
                break
            
            # Wait between tests
            await asyncio.sleep(30)
        
        return {
            "stress_test_results": stress_results,
            "timestamp": datetime.now().isoformat()
        }
    
    def print_load_test_summary(self, results: Dict[str, Any]):
        """Print formatted load test summary"""
        print("\n" + "=" * 60)
        print("🔥 LOAD TEST SUMMARY")
        print("=" * 60)
        
        test_info = results["test_info"]
        summary = results["summary"]
        response_times = results["response_times"]
        
        print(f"Test Duration: {test_info['duration_seconds']}s")
        print(f"Concurrent Users: {test_info['concurrent_users']}")
        print(f"Total Requests: {summary['total_requests']}")
        print(f"Success Rate: {summary['success_rate']}%")
        print(f"Requests/Second: {summary['requests_per_second']}")
        
        print("\n📊 Response Times:")
        print(f"  Average: {response_times['average']}s")
        print(f"  Median (P50): {response_times['p50_median']}s")
        print(f"  P95: {response_times['p95']}s")
        print(f"  P99: {response_times['p99']}s")
        print(f"  Min: {response_times['minimum']}s")
        print(f"  Max: {response_times['maximum']}s")
        
        if "errors" in results and results["errors"]:
            print("\n❌ Errors:")
            for error_type, count in results["errors"].items():
                print(f"  {error_type}: {count}")
        
        print("\n📡 Source Performance:")
        for source, stats in results["source_performance"].items():
            print(f"  {source}: {stats['success_rate']:.1f}% success, {stats['avg_response_time']:.2f}s avg")
        
        print("\n" + "=" * 60)


async def run_load_tests():
    """Main function to run load tests"""
    tester = LoadTester()
    
    try:
        # Run basic load test
        print("Running basic load test...")
        basic_results = await tester.run_load_test(
            concurrent_users=5,
            duration_minutes=5,
            requests_per_user=15
        )
        
        tester.print_load_test_summary(basic_results)
        
        # Run stress test
        print("\nRunning stress test...")
        stress_results = await tester.run_stress_test()
        
        # Save results
        import json
        results_dir = project_root / "test_results"
        results_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        with open(results_dir / f"load_test_{timestamp}.json", 'w') as f:
            json.dump(basic_results, f, indent=2, default=str)
        
        with open(results_dir / f"stress_test_{timestamp}.json", 'w') as f:
            json.dump(stress_results, f, indent=2, default=str)
        
        print(f"\n💾 Results saved to test_results/")
        
        return basic_results, stress_results
        
    except Exception as e:
        print(f"❌ Load tests failed: {str(e)}")
        logging.error(f"Load tests failed: {str(e)}")
        return None, None


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run load tests
    asyncio.run(run_load_tests())