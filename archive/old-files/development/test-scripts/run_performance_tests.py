#!/usr/bin/env python3
"""
Performance Testing Orchestrator for Monitor Legislativo v4

Coordinates and runs comprehensive performance testing including:
- Backend API performance tests
- Frontend browser performance tests  
- Load testing with concurrent users
- System resource monitoring
- Report generation and analysis
"""

import asyncio
import subprocess
import sys
import time
import json
import argparse
from pathlib import Path
from typing import Dict, Any, List, Optional
import psutil
import signal

class PerformanceTestOrchestrator:
    """Orchestrates comprehensive performance testing suite"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.results: Dict[str, Any] = {}
        self.start_time = time.time()
        self.running = True
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Test script paths
        self.scripts_dir = Path(__file__).parent
        self.project_root = self.scripts_dir.parent.parent
        
        # Ensure output directory exists
        self.output_dir = self.scripts_dir / "performance_reports"
        self.output_dir.mkdir(exist_ok=True)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        print(f"\n⚠️ Received signal {signum}, stopping tests...")
        self.running = False
    
    async def check_system_requirements(self) -> bool:
        """Check if system meets requirements for testing"""
        print("🔍 Checking system requirements...")
        
        requirements_met = True
        
        # Check available memory
        memory = psutil.virtual_memory()
        available_gb = memory.available / (1024**3)
        
        if available_gb < 2.0:
            print(f"❌ Insufficient memory: {available_gb:.1f}GB available (2GB required)")
            requirements_met = False
        else:
            print(f"✅ Memory: {available_gb:.1f}GB available")
        
        # Check CPU cores
        cpu_count = psutil.cpu_count()
        if cpu_count < 2:
            print(f"❌ Insufficient CPU cores: {cpu_count} (2 required)")
            requirements_met = False
        else:
            print(f"✅ CPU: {cpu_count} cores")
        
        # Check disk space
        disk = psutil.disk_usage(self.scripts_dir)
        available_gb = disk.free / (1024**3)
        
        if available_gb < 1.0:
            print(f"❌ Insufficient disk space: {available_gb:.1f}GB (1GB required)")
            requirements_met = False
        else:
            print(f"✅ Disk: {available_gb:.1f}GB available")
        
        return requirements_met
    
    async def check_services_health(self) -> Dict[str, bool]:
        """Check if required services are running"""
        print("🔧 Checking service health...")
        
        health_status = {}
        
        # Check backend API
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.config['backend_url']}/health", timeout=aiohttp.ClientTimeout(total=10)) as response:
                    health_status['backend'] = response.status == 200
                    if health_status['backend']:
                        print(f"✅ Backend API: {self.config['backend_url']}")
                    else:
                        print(f"❌ Backend API: HTTP {response.status}")
        except Exception as e:
            print(f"❌ Backend API: {e}")
            health_status['backend'] = False
        
        # Check frontend (if URL provided)
        if self.config.get('frontend_url'):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(self.config['frontend_url'], timeout=aiohttp.ClientTimeout(total=10)) as response:
                        health_status['frontend'] = response.status == 200
                        if health_status['frontend']:
                            print(f"✅ Frontend: {self.config['frontend_url']}")
                        else:
                            print(f"❌ Frontend: HTTP {response.status}")
            except Exception as e:
                print(f"❌ Frontend: {e}")
                health_status['frontend'] = False
        else:
            health_status['frontend'] = True  # Not required if not specified
        
        return health_status
    
    async def run_backend_performance_tests(self) -> Dict[str, Any]:
        """Run backend performance tests"""
        if not self.running:
            return {"skipped": True}
        
        print("\n🔬 Running backend performance tests...")
        print("-" * 50)
        
        try:
            cmd = [
                sys.executable,
                str(self.scripts_dir / "performance_test_suite.py"),
                "--url", self.config['backend_url']
            ]
            
            if self.config.get('quick_mode'):
                cmd.append("--quick")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.get('backend_timeout', 600)  # 10 minutes
            )
            
            # Parse results from output
            backend_results = {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode
            }
            
            # Try to parse JSON report if available
            try:
                # Look for generated report file
                report_files = list(self.scripts_dir.glob("performance_report_*.json"))
                if report_files:
                    latest_report = max(report_files, key=lambda p: p.stat().st_mtime)
                    with open(latest_report) as f:
                        backend_results["detailed_results"] = json.load(f)
                    # Move to output directory
                    latest_report.rename(self.output_dir / latest_report.name)
            except Exception as e:
                print(f"Warning: Could not parse backend report: {e}")
            
            if backend_results["success"]:
                print("✅ Backend performance tests completed")
            else:
                print("❌ Backend performance tests failed")
                print(f"Error: {result.stderr}")
            
            return backend_results
            
        except subprocess.TimeoutExpired:
            print("❌ Backend performance tests timed out")
            return {"success": False, "error": "timeout"}
        except Exception as e:
            print(f"❌ Backend performance tests failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def run_frontend_performance_tests(self) -> Dict[str, Any]:
        """Run frontend performance tests"""
        if not self.running or not self.config.get('frontend_url'):
            return {"skipped": True}
        
        print("\n🎨 Running frontend performance tests...")
        print("-" * 50)
        
        try:
            # Check if Node.js and required packages are available
            node_check = subprocess.run(["node", "--version"], capture_output=True)
            if node_check.returncode != 0:
                print("❌ Node.js not found - skipping frontend tests")
                return {"skipped": True, "reason": "Node.js not available"}
            
            # Check if playwright is installed
            try:
                subprocess.run(["npm", "list", "playwright"], capture_output=True, check=True, cwd=self.project_root)
            except subprocess.CalledProcessError:
                print("⚠️ Playwright not found - installing...")
                try:
                    subprocess.run(["npm", "install", "playwright"], check=True, cwd=self.project_root)
                except subprocess.CalledProcessError:
                    print("❌ Failed to install Playwright - skipping frontend tests")
                    return {"skipped": True, "reason": "Playwright installation failed"}
            
            cmd = [
                "node",
                str(self.scripts_dir / "frontend_performance_test.js"),
                f"--url={self.config['frontend_url']}"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.get('frontend_timeout', 300),  # 5 minutes
                cwd=self.project_root
            )
            
            frontend_results = {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode
            }
            
            # Try to parse JSON report
            try:
                report_files = list(self.scripts_dir.glob("frontend_performance_report_*.json"))
                if report_files:
                    latest_report = max(report_files, key=lambda p: p.stat().st_mtime)
                    with open(latest_report) as f:
                        frontend_results["detailed_results"] = json.load(f)
                    # Move to output directory
                    latest_report.rename(self.output_dir / latest_report.name)
            except Exception as e:
                print(f"Warning: Could not parse frontend report: {e}")
            
            if frontend_results["success"]:
                print("✅ Frontend performance tests completed")
            else:
                print("❌ Frontend performance tests failed")
                print(f"Error: {result.stderr}")
            
            return frontend_results
            
        except subprocess.TimeoutExpired:
            print("❌ Frontend performance tests timed out")
            return {"success": False, "error": "timeout"}
        except Exception as e:
            print(f"❌ Frontend performance tests failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def run_load_tests(self) -> Dict[str, Any]:
        """Run load tests"""
        if not self.running:
            return {"skipped": True}
        
        print("\n🚀 Running load tests...")
        print("-" * 50)
        
        try:
            cmd = [
                sys.executable,
                str(self.scripts_dir / "load_test.py"),
                "--url", self.config['backend_url'],
                "--users", str(self.config.get('max_users', 50)),
                "--duration", str(self.config.get('load_test_duration', 60))
            ]
            
            if self.config.get('quick_mode'):
                cmd.append("--quick")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.get('load_test_timeout', 900)  # 15 minutes
            )
            
            load_results = {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode
            }
            
            # Try to parse JSON report
            try:
                report_files = list(self.scripts_dir.glob("load_test_report_*.json"))
                if report_files:
                    latest_report = max(report_files, key=lambda p: p.stat().st_mtime)
                    with open(latest_report) as f:
                        load_results["detailed_results"] = json.load(f)
                    # Move to output directory
                    latest_report.rename(self.output_dir / latest_report.name)
            except Exception as e:
                print(f"Warning: Could not parse load test report: {e}")
            
            if load_results["success"]:
                print("✅ Load tests completed")
            else:
                print("❌ Load tests failed")
                print(f"Error: {result.stderr}")
            
            return load_results
            
        except subprocess.TimeoutExpired:
            print("❌ Load tests timed out")
            return {"success": False, "error": "timeout"}
        except Exception as e:
            print(f"❌ Load tests failed: {e}")
            return {"success": False, "error": str(e)}
    
    def collect_system_metrics(self) -> Dict[str, Any]:
        """Collect current system metrics"""
        try:
            return {
                "cpu_percent": psutil.cpu_percent(interval=1),
                "memory": {
                    "total": psutil.virtual_memory().total,
                    "available": psutil.virtual_memory().available,
                    "percent": psutil.virtual_memory().percent
                },
                "disk": {
                    "total": psutil.disk_usage('.').total,
                    "free": psutil.disk_usage('.').free,
                    "percent": psutil.disk_usage('.').percent
                },
                "load_average": psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None,
                "boot_time": psutil.boot_time(),
                "timestamp": time.time()
            }
        except Exception as e:
            return {"error": str(e), "timestamp": time.time()}
    
    async def run_comprehensive_test_suite(self) -> Dict[str, Any]:
        """Run the complete performance testing suite"""
        print("🧪 Monitor Legislativo v4 - Comprehensive Performance Test Suite")
        print("=" * 70)
        
        # Pre-flight checks
        if not await self.check_system_requirements():
            print("❌ System requirements not met")
            return {"success": False, "error": "System requirements not met"}
        
        health_status = await self.check_services_health()
        if not health_status.get('backend', False):
            print("❌ Backend service not available")
            return {"success": False, "error": "Backend service unavailable"}
        
        # Collect initial system metrics
        initial_metrics = self.collect_system_metrics()
        
        # Run test suites
        test_results = {}
        
        # 1. Backend Performance Tests
        if self.config.get('run_backend_tests', True):
            test_results['backend'] = await self.run_backend_performance_tests()
        
        # 2. Frontend Performance Tests (if frontend URL provided)
        if self.config.get('run_frontend_tests', True) and self.config.get('frontend_url'):
            test_results['frontend'] = await self.run_frontend_performance_tests()
        
        # 3. Load Tests
        if self.config.get('run_load_tests', True):
            test_results['load'] = await self.run_load_tests()
        
        # Collect final system metrics
        final_metrics = self.collect_system_metrics()
        
        # Generate comprehensive report
        return self.generate_comprehensive_report(
            test_results,
            initial_metrics,
            final_metrics,
            health_status
        )
    
    def generate_comprehensive_report(
        self,
        test_results: Dict[str, Any],
        initial_metrics: Dict[str, Any],
        final_metrics: Dict[str, Any],
        health_status: Dict[str, bool]
    ) -> Dict[str, Any]:
        """Generate comprehensive performance test report"""
        
        suite_duration = time.time() - self.start_time
        
        print("\n" + "=" * 70)
        print("📊 COMPREHENSIVE PERFORMANCE TEST RESULTS")
        print("=" * 70)
        
        # Calculate overall success
        test_successes = []
        for test_name, result in test_results.items():
            if not result.get('skipped', False):
                test_successes.append(result.get('success', False))
        
        overall_success = len(test_successes) > 0 and all(test_successes)
        success_rate = (sum(test_successes) / len(test_successes) * 100) if test_successes else 0
        
        # Summary
        print(f"Suite Duration: {suite_duration:.1f} seconds")
        print(f"Tests Run: {len([r for r in test_results.values() if not r.get('skipped')])} / {len(test_results)}")
        print(f"Success Rate: {success_rate:.1f}%")
        print(f"Overall Result: {'✅ PASS' if overall_success else '❌ FAIL'}")
        
        # Individual test results
        print("\nTEST RESULTS SUMMARY:")
        print("-" * 40)
        
        for test_name, result in test_results.items():
            if result.get('skipped'):
                print(f"⏭️ {test_name.title()}: SKIPPED ({result.get('reason', 'Not configured')})")
            elif result.get('success'):
                print(f"✅ {test_name.title()}: PASSED")
            else:
                print(f"❌ {test_name.title()}: FAILED ({result.get('error', 'Unknown error')})")
        
        # Performance insights
        print("\nPERFORMANCE INSIGHTS:")
        print("-" * 40)
        
        insights = []
        
        # Backend insights
        if test_results.get('backend', {}).get('detailed_results'):
            backend_data = test_results['backend']['detailed_results']
            backend_success_rate = backend_data.get('summary', {}).get('success_rate', 0)
            
            if backend_success_rate >= 90:
                insights.append("✅ Backend performance excellent (90%+ metrics passed)")
            elif backend_success_rate >= 75:
                insights.append("⚠️ Backend performance good (75%+ metrics passed)")
            else:
                insights.append("❌ Backend performance needs improvement")
        
        # Load test insights
        if test_results.get('load', {}).get('detailed_results'):
            load_data = test_results['load']['detailed_results']
            max_users = load_data.get('summary', {}).get('max_successful_users', 0)
            
            if max_users >= 50:
                insights.append(f"✅ Excellent load handling ({max_users} concurrent users)")
            elif max_users >= 25:
                insights.append(f"⚠️ Good load handling ({max_users} concurrent users)")
            else:
                insights.append(f"❌ Poor load handling ({max_users} concurrent users)")
        
        # System resource insights
        if initial_metrics.get('memory') and final_metrics.get('memory'):
            memory_growth = (final_metrics['memory']['percent'] - initial_metrics['memory']['percent'])
            if memory_growth > 10:
                insights.append(f"⚠️ Significant memory usage increase (+{memory_growth:.1f}%)")
            else:
                insights.append("✅ Stable memory usage during testing")
        
        for insight in insights:
            print(insight)
        
        if not insights:
            print("ℹ️ No specific performance insights available")
        
        # Recommendations
        print("\nRECOMMENDATIONS:")
        print("-" * 40)
        
        recommendations = []
        
        if success_rate < 80:
            recommendations.append("🔧 Review failed tests and address performance bottlenecks")
        
        if not test_results.get('frontend', {}).get('success', True):
            recommendations.append("🎨 Optimize frontend bundle size and loading performance")
        
        if not test_results.get('load', {}).get('success', True):
            recommendations.append("⚡ Improve system scalability and concurrent user handling")
        
        if final_metrics.get('memory', {}).get('percent', 0) > 80:
            recommendations.append("💾 Monitor memory usage - consider optimization")
        
        recommendations.extend([
            "📊 Monitor performance metrics in production",
            "🔄 Run performance tests regularly",
            "📈 Set up automated performance monitoring"
        ])
        
        for rec in recommendations:
            print(rec)
        
        # Create comprehensive report data
        report_data = {
            "timestamp": time.time(),
            "config": self.config,
            "suite_duration": suite_duration,
            "health_status": health_status,
            "system_metrics": {
                "initial": initial_metrics,
                "final": final_metrics
            },
            "test_results": test_results,
            "summary": {
                "overall_success": overall_success,
                "success_rate": success_rate,
                "tests_run": len([r for r in test_results.values() if not r.get('skipped')]),
                "total_tests": len(test_results)
            },
            "insights": insights,
            "recommendations": recommendations
        }
        
        # Save report
        report_path = self.output_dir / f"comprehensive_performance_report_{int(time.time())}.json"
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"\n📄 Comprehensive report saved to: {report_path}")
        
        return report_data

def create_test_config(args) -> Dict[str, Any]:
    """Create test configuration from command line arguments"""
    return {
        "backend_url": args.backend_url,
        "frontend_url": args.frontend_url,
        "quick_mode": args.quick,
        "run_backend_tests": not args.skip_backend,
        "run_frontend_tests": not args.skip_frontend,
        "run_load_tests": not args.skip_load,
        "max_users": args.max_users,
        "load_test_duration": args.duration,
        "backend_timeout": 600,
        "frontend_timeout": 300,
        "load_test_timeout": 900
    }

async def main():
    """Main test orchestrator entry point"""
    parser = argparse.ArgumentParser(
        description="Comprehensive Performance Testing Suite for Monitor Legislativo v4"
    )
    
    parser.add_argument("--backend-url", default="http://localhost:8000", 
                       help="Backend API URL")
    parser.add_argument("--frontend-url", default="http://localhost:5173",
                       help="Frontend URL (optional)")
    parser.add_argument("--max-users", type=int, default=50,
                       help="Maximum concurrent users for load testing")
    parser.add_argument("--duration", type=int, default=60,
                       help="Duration per load test scenario (seconds)")
    parser.add_argument("--quick", action="store_true",
                       help="Run quick tests only")
    parser.add_argument("--skip-backend", action="store_true",
                       help="Skip backend performance tests")
    parser.add_argument("--skip-frontend", action="store_true", 
                       help="Skip frontend performance tests")
    parser.add_argument("--skip-load", action="store_true",
                       help="Skip load tests")
    
    args = parser.parse_args()
    
    config = create_test_config(args)
    orchestrator = PerformanceTestOrchestrator(config)
    
    try:
        report = await orchestrator.run_comprehensive_test_suite()
        
        # Exit with appropriate code
        if report.get('summary', {}).get('overall_success', False):
            print("\n🎉 All performance tests passed!")
            sys.exit(0)
        else:
            print("\n⚠️ Some performance tests failed - review results")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n⚠️ Performance testing interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Performance testing failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())