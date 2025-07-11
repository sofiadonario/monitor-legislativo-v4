#!/usr/bin/env python3
"""
Comprehensive Performance Testing Suite for Monitor Legislativo v4

This script tests the performance of all major components:
- API endpoints
- Database queries
- Cache operations
- LexML integration
- Frontend load times
- Memory usage
- Response times
"""

import asyncio
import time
import json
import statistics
import sys
import os
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
import aiohttp
import psutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
import traceback

# Add core to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent / "core"))

try:
    from config.config import get_config
    from services.lexml_service import LexMLService
    from services.database_service import DatabaseService
except ImportError as e:
    print(f"Warning: Could not import core modules: {e}")
    print("Running with limited functionality")

@dataclass
class PerformanceMetric:
    """Individual performance measurement"""
    name: str
    value: float
    unit: str
    threshold: float
    passed: bool
    timestamp: float
    details: Optional[Dict[str, Any]] = None

@dataclass
class TestResult:
    """Result of a performance test"""
    test_name: str
    metrics: List[PerformanceMetric]
    duration: float
    success: bool
    error: Optional[str] = None

class PerformanceTestSuite:
    """Comprehensive performance testing suite"""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.results: List[TestResult] = []
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Performance thresholds
        self.thresholds = {
            'api_response_time': 2.0,  # seconds
            'database_query_time': 1.0,  # seconds
            'cache_hit_rate': 70.0,  # percentage
            'memory_usage': 512.0,  # MB
            'cpu_usage': 80.0,  # percentage
            'concurrent_requests': 100,  # requests/second
            'error_rate': 5.0,  # percentage
            'frontend_load_time': 3.0,  # seconds
            'search_response_time': 1.5,  # seconds
            'export_time': 10.0  # seconds
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    def create_metric(self, name: str, value: float, unit: str, 
                     threshold: float, details: Optional[Dict] = None) -> PerformanceMetric:
        """Create a performance metric"""
        passed = value <= threshold if unit in ['seconds', 'ms', 'MB', '%error'] else value >= threshold
        return PerformanceMetric(
            name=name,
            value=value,
            unit=unit,
            threshold=threshold,
            passed=passed,
            timestamp=time.time(),
            details=details
        )
    
    async def test_api_endpoints(self) -> TestResult:
        """Test API endpoint performance"""
        print("🔍 Testing API endpoint performance...")
        start_time = time.time()
        metrics = []
        
        endpoints = [
            "/health",
            "/api/v1/search?q=transporte",
            "/api/v1/search?q=mobilidade&sources=lexml",
            "/api/v1/collections/recent",
            "/api/v1/collections/latest",
            "/api/v1/monitoring"
        ]
        
        try:
            response_times = []
            error_count = 0
            
            for endpoint in endpoints:
                url = f"{self.base_url}{endpoint}"
                endpoint_times = []
                
                # Test each endpoint 5 times
                for _ in range(5):
                    try:
                        start = time.time()
                        async with self.session.get(url) as response:
                            await response.text()
                            end = time.time()
                            
                            if response.status == 200:
                                endpoint_times.append(end - start)
                            else:
                                error_count += 1
                                
                    except Exception as e:
                        error_count += 1
                        print(f"Error testing {endpoint}: {e}")
                
                if endpoint_times:
                    avg_time = statistics.mean(endpoint_times)
                    response_times.extend(endpoint_times)
                    
                    metrics.append(self.create_metric(
                        f"API {endpoint} avg response",
                        avg_time,
                        "seconds",
                        self.thresholds['api_response_time'],
                        {"times": endpoint_times}
                    ))
            
            # Overall metrics
            if response_times:
                avg_response_time = statistics.mean(response_times)
                p95_response_time = statistics.quantiles(response_times, n=20)[18]  # 95th percentile
                
                metrics.append(self.create_metric(
                    "API average response time",
                    avg_response_time,
                    "seconds",
                    self.thresholds['api_response_time']
                ))
                
                metrics.append(self.create_metric(
                    "API 95th percentile response time",
                    p95_response_time,
                    "seconds",
                    self.thresholds['api_response_time'] * 2
                ))
            
            # Error rate
            total_requests = len(endpoints) * 5
            error_rate = (error_count / total_requests) * 100
            metrics.append(self.create_metric(
                "API error rate",
                error_rate,
                "%error",
                self.thresholds['error_rate']
            ))
            
            return TestResult(
                test_name="API Endpoints",
                metrics=metrics,
                duration=time.time() - start_time,
                success=True
            )
            
        except Exception as e:
            return TestResult(
                test_name="API Endpoints",
                metrics=metrics,
                duration=time.time() - start_time,
                success=False,
                error=str(e)
            )
    
    async def test_database_performance(self) -> TestResult:
        """Test database query performance"""
        print("🗄️ Testing database performance...")
        start_time = time.time()
        metrics = []
        
        try:
            # Test database connection and basic queries
            db_service = DatabaseService()
            
            # Test basic connection
            conn_start = time.time()
            await db_service.test_connection()
            conn_time = time.time() - conn_start
            
            metrics.append(self.create_metric(
                "Database connection time",
                conn_time,
                "seconds",
                0.5
            ))
            
            # Test common queries
            query_tests = [
                ("Count documents", "SELECT COUNT(*) FROM legislative_documents"),
                ("Recent documents", "SELECT * FROM legislative_documents ORDER BY date DESC LIMIT 100"),
                ("Search by keyword", "SELECT * FROM legislative_documents WHERE title ILIKE '%transporte%' LIMIT 50"),
                ("Filter by state", "SELECT * FROM legislative_documents WHERE state = 'SP' LIMIT 50")
            ]
            
            for test_name, query in query_tests:
                query_times = []
                
                # Run each query 3 times
                for _ in range(3):
                    try:
                        query_start = time.time()
                        result = await db_service.execute_query(query)
                        query_end = time.time()
                        query_times.append(query_end - query_start)
                    except Exception as e:
                        print(f"Query failed: {query} - {e}")
                
                if query_times:
                    avg_time = statistics.mean(query_times)
                    metrics.append(self.create_metric(
                        f"DB Query: {test_name}",
                        avg_time,
                        "seconds",
                        self.thresholds['database_query_time'],
                        {"times": query_times}
                    ))
            
            return TestResult(
                test_name="Database Performance",
                metrics=metrics,
                duration=time.time() - start_time,
                success=True
            )
            
        except Exception as e:
            return TestResult(
                test_name="Database Performance", 
                metrics=metrics,
                duration=time.time() - start_time,
                success=False,
                error=str(e)
            )
    
    async def test_cache_performance(self) -> TestResult:
        """Test cache system performance"""
        print("📦 Testing cache performance...")
        start_time = time.time()
        metrics = []
        
        try:
            # Test cache hit rates via API
            cache_endpoints = [
                "/api/v1/search?q=transporte",
                "/api/v1/search?q=mobilidade", 
                "/api/v1/collections/recent"
            ]
            
            # Prime cache
            for endpoint in cache_endpoints:
                url = f"{self.base_url}{endpoint}"
                try:
                    async with self.session.get(url) as response:
                        await response.text()
                except:
                    pass
            
            # Test cache hit performance
            cache_times = []
            for endpoint in cache_endpoints:
                url = f"{self.base_url}{endpoint}"
                endpoint_times = []
                
                for _ in range(10):  # Multiple requests to test cache
                    try:
                        start = time.time()
                        async with self.session.get(url) as response:
                            await response.text()
                            end = time.time()
                            endpoint_times.append(end - start)
                    except:
                        pass
                
                if endpoint_times:
                    cache_times.extend(endpoint_times)
            
            if cache_times:
                avg_cache_time = statistics.mean(cache_times)
                metrics.append(self.create_metric(
                    "Cache response time",
                    avg_cache_time,
                    "seconds", 
                    0.5,  # Cached responses should be very fast
                    {"times": cache_times}
                ))
            
            # Test memory usage
            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024
            metrics.append(self.create_metric(
                "Memory usage",
                memory_mb,
                "MB",
                self.thresholds['memory_usage']
            ))
            
            return TestResult(
                test_name="Cache Performance",
                metrics=metrics,
                duration=time.time() - start_time,
                success=True
            )
            
        except Exception as e:
            return TestResult(
                test_name="Cache Performance",
                metrics=metrics,
                duration=time.time() - start_time,
                success=False,
                error=str(e)
            )
    
    async def test_lexml_integration(self) -> TestResult:
        """Test LexML service performance"""
        print("⚖️ Testing LexML integration performance...")
        start_time = time.time()
        metrics = []
        
        try:
            # Test LexML search performance
            search_terms = ["transporte", "mobilidade urbana", "trânsito"]
            search_times = []
            
            for term in search_terms:
                url = f"{self.base_url}/api/v1/search?q={term}&sources=lexml"
                term_times = []
                
                for _ in range(3):
                    try:
                        search_start = time.time()
                        async with self.session.get(url) as response:
                            data = await response.json()
                            search_end = time.time()
                            
                            if response.status == 200:
                                term_times.append(search_end - search_start)
                                
                    except Exception as e:
                        print(f"LexML search error for '{term}': {e}")
                
                if term_times:
                    search_times.extend(term_times)
                    avg_term_time = statistics.mean(term_times)
                    metrics.append(self.create_metric(
                        f"LexML search '{term}'",
                        avg_term_time,
                        "seconds",
                        self.thresholds['search_response_time']
                    ))
            
            if search_times:
                avg_search_time = statistics.mean(search_times)
                metrics.append(self.create_metric(
                    "LexML average search time",
                    avg_search_time,
                    "seconds",
                    self.thresholds['search_response_time']
                ))
            
            return TestResult(
                test_name="LexML Integration",
                metrics=metrics,
                duration=time.time() - start_time,
                success=True
            )
            
        except Exception as e:
            return TestResult(
                test_name="LexML Integration",
                metrics=metrics,
                duration=time.time() - start_time,
                success=False,
                error=str(e)
            )
    
    async def test_concurrent_load(self) -> TestResult:
        """Test performance under concurrent load"""
        print("🚀 Testing concurrent load performance...")
        start_time = time.time()
        metrics = []
        
        try:
            # Concurrent request test
            url = f"{self.base_url}/api/v1/search?q=transporte"
            concurrent_users = [10, 25, 50]
            
            for users in concurrent_users:
                print(f"  Testing {users} concurrent users...")
                user_times = []
                errors = 0
                
                async def make_request():
                    try:
                        req_start = time.time()
                        async with self.session.get(url) as response:
                            await response.text()
                            req_end = time.time()
                            if response.status == 200:
                                return req_end - req_start
                            else:
                                return None
                    except:
                        return None
                
                # Run concurrent requests
                tasks = [make_request() for _ in range(users)]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in results:
                    if isinstance(result, (int, float)) and result is not None:
                        user_times.append(result)
                    else:
                        errors += 1
                
                if user_times:
                    avg_time = statistics.mean(user_times)
                    error_rate = (errors / users) * 100
                    
                    metrics.append(self.create_metric(
                        f"Concurrent {users} users avg response",
                        avg_time,
                        "seconds",
                        self.thresholds['api_response_time'] * 2
                    ))
                    
                    metrics.append(self.create_metric(
                        f"Concurrent {users} users error rate",
                        error_rate,
                        "%error",
                        self.thresholds['error_rate']
                    ))
            
            return TestResult(
                test_name="Concurrent Load",
                metrics=metrics,
                duration=time.time() - start_time,
                success=True
            )
            
        except Exception as e:
            return TestResult(
                test_name="Concurrent Load",
                metrics=metrics,
                duration=time.time() - start_time,
                success=False,
                error=str(e)
            )
    
    async def test_system_resources(self) -> TestResult:
        """Test system resource usage"""
        print("💻 Testing system resource usage...")
        start_time = time.time()
        metrics = []
        
        try:
            # Monitor CPU and memory during load
            process = psutil.Process()
            
            # Baseline measurements
            cpu_before = process.cpu_percent()
            memory_before = process.memory_info().rss / 1024 / 1024
            
            # Create some load
            load_tasks = []
            for _ in range(20):
                url = f"{self.base_url}/api/v1/search?q=test"
                load_tasks.append(self.session.get(url))
            
            await asyncio.gather(*load_tasks, return_exceptions=True)
            
            # Post-load measurements
            time.sleep(1)  # Let CPU settle
            cpu_after = process.cpu_percent()
            memory_after = process.memory_info().rss / 1024 / 1024
            
            metrics.append(self.create_metric(
                "CPU usage",
                cpu_after,
                "percentage",
                self.thresholds['cpu_usage']
            ))
            
            metrics.append(self.create_metric(
                "Memory usage",
                memory_after,
                "MB",
                self.thresholds['memory_usage']
            ))
            
            metrics.append(self.create_metric(
                "Memory growth",
                memory_after - memory_before,
                "MB",
                100.0  # Should not grow more than 100MB during test
            ))
            
            return TestResult(
                test_name="System Resources",
                metrics=metrics,
                duration=time.time() - start_time,
                success=True
            )
            
        except Exception as e:
            return TestResult(
                test_name="System Resources",
                metrics=metrics,
                duration=time.time() - start_time,
                success=False,
                error=str(e)
            )
    
    def test_frontend_build_performance(self) -> TestResult:
        """Test frontend build and bundle performance"""
        print("🎨 Testing frontend build performance...")
        start_time = time.time()
        metrics = []
        
        try:
            # Test npm build time
            build_start = time.time()
            result = subprocess.run(
                ["npm", "run", "build"],
                capture_output=True,
                text=True,
                cwd=Path(__file__).parent.parent.parent
            )
            build_time = time.time() - build_start
            
            if result.returncode == 0:
                metrics.append(self.create_metric(
                    "Frontend build time",
                    build_time,
                    "seconds",
                    120.0  # 2 minutes max
                ))
            else:
                print(f"Build failed: {result.stderr}")
            
            # Check bundle sizes
            dist_path = Path(__file__).parent.parent.parent / "dist"
            if dist_path.exists():
                bundle_sizes = []
                for js_file in dist_path.glob("**/*.js"):
                    size_mb = js_file.stat().st_size / 1024 / 1024
                    bundle_sizes.append(size_mb)
                
                if bundle_sizes:
                    total_size = sum(bundle_sizes)
                    metrics.append(self.create_metric(
                        "Total bundle size",
                        total_size,
                        "MB",
                        10.0  # 10MB max total
                    ))
            
            return TestResult(
                test_name="Frontend Build",
                metrics=metrics,
                duration=time.time() - start_time,
                success=True
            )
            
        except Exception as e:
            return TestResult(
                test_name="Frontend Build",
                metrics=metrics,
                duration=time.time() - start_time,
                success=False,
                error=str(e)
            )
    
    async def run_all_tests(self) -> Dict[str, Any]:
        """Run all performance tests"""
        print("🧪 Starting comprehensive performance test suite...")
        print("=" * 60)
        
        suite_start = time.time()
        
        # Run tests in sequence to avoid interference
        test_methods = [
            self.test_api_endpoints,
            self.test_database_performance,
            self.test_cache_performance,
            self.test_lexml_integration,
            self.test_concurrent_load,
            self.test_system_resources
        ]
        
        for test_method in test_methods:
            try:
                result = await test_method()
                self.results.append(result)
                print(f"✅ {result.test_name} completed in {result.duration:.2f}s")
            except Exception as e:
                print(f"❌ {test_method.__name__} failed: {e}")
                self.results.append(TestResult(
                    test_name=test_method.__name__,
                    metrics=[],
                    duration=0,
                    success=False,
                    error=str(e)
                ))
        
        # Run frontend test (synchronous)
        try:
            frontend_result = self.test_frontend_build_performance()
            self.results.append(frontend_result)
            print(f"✅ Frontend Build completed in {frontend_result.duration:.2f}s")
        except Exception as e:
            print(f"❌ Frontend Build failed: {e}")
        
        suite_duration = time.time() - suite_start
        
        return self.generate_report(suite_duration)
    
    def generate_report(self, suite_duration: float) -> Dict[str, Any]:
        """Generate comprehensive performance report"""
        print("\n" + "=" * 60)
        print("📊 PERFORMANCE TEST RESULTS")
        print("=" * 60)
        
        total_tests = len(self.results)
        successful_tests = sum(1 for r in self.results if r.success)
        
        all_metrics = []
        for result in self.results:
            all_metrics.extend(result.metrics)
        
        passed_metrics = sum(1 for m in all_metrics if m.passed)
        total_metrics = len(all_metrics)
        
        # Summary
        print(f"Suite Duration: {suite_duration:.2f} seconds")
        print(f"Tests: {successful_tests}/{total_tests} passed")
        print(f"Metrics: {passed_metrics}/{total_metrics} passed")
        print(f"Success Rate: {(passed_metrics/total_metrics*100):.1f}%" if total_metrics > 0 else "N/A")
        
        # Detailed results
        print("\nDETAILED RESULTS:")
        print("-" * 40)
        
        for result in self.results:
            status = "✅ PASS" if result.success else "❌ FAIL"
            print(f"\n{status} {result.test_name} ({result.duration:.2f}s)")
            
            if result.error:
                print(f"  Error: {result.error}")
            
            for metric in result.metrics:
                status_icon = "✅" if metric.passed else "❌"
                print(f"  {status_icon} {metric.name}: {metric.value:.3f} {metric.unit} (threshold: {metric.threshold})")
        
        # Performance recommendations
        print("\nPERFORMANCE RECOMMENDATIONS:")
        print("-" * 40)
        
        failed_metrics = [m for m in all_metrics if not m.passed]
        if not failed_metrics:
            print("🎉 All performance metrics passed! System is performing well.")
        else:
            for metric in failed_metrics:
                if "response" in metric.name.lower() and metric.value > metric.threshold:
                    print(f"⚠️ Slow response time for {metric.name} - consider caching or optimization")
                elif "memory" in metric.name.lower() and metric.value > metric.threshold:
                    print(f"⚠️ High memory usage - consider memory optimization")
                elif "error" in metric.name.lower() and metric.value > metric.threshold:
                    print(f"⚠️ High error rate for {metric.name} - investigate failures")
        
        # Export results
        report_data = {
            "timestamp": time.time(),
            "suite_duration": suite_duration,
            "summary": {
                "total_tests": total_tests,
                "successful_tests": successful_tests,
                "total_metrics": total_metrics,
                "passed_metrics": passed_metrics,
                "success_rate": (passed_metrics/total_metrics*100) if total_metrics > 0 else 0
            },
            "tests": [asdict(result) for result in self.results],
            "thresholds": self.thresholds
        }
        
        # Save report
        report_path = Path(__file__).parent / f"performance_report_{int(time.time())}.json"
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"\n📄 Full report saved to: {report_path}")
        
        return report_data


async def main():
    """Main test runner"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Performance Test Suite for Monitor Legislativo v4")
    parser.add_argument("--url", default="http://localhost:8000", help="Base URL for API tests")
    parser.add_argument("--quick", action="store_true", help="Run quick tests only")
    args = parser.parse_args()
    
    print("🚀 Monitor Legislativo v4 - Performance Test Suite")
    print(f"Testing against: {args.url}")
    print("=" * 60)
    
    async with PerformanceTestSuite(args.url) as suite:
        if args.quick:
            # Quick tests only
            suite.results.append(await suite.test_api_endpoints())
            suite.results.append(await suite.test_cache_performance())
            report = suite.generate_report(time.time())
        else:
            # Full test suite
            report = await suite.run_all_tests()
        
        # Exit with error code if tests failed
        success_rate = report["summary"]["success_rate"]
        if success_rate < 80:
            print(f"\n❌ Performance tests failed (success rate: {success_rate:.1f}%)")
            sys.exit(1)
        else:
            print(f"\n✅ Performance tests passed (success rate: {success_rate:.1f}%)")
            sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())