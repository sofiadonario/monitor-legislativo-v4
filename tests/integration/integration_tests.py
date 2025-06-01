"""
Integration testing system for Monitor Legislativo
Tests all APIs and generates health reports
"""

import asyncio
import logging
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add project root to path
project_root = Path(__file__).parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from core.api.api_service import APIService
from core.utils.monitoring import metrics_collector
from core.utils.circuit_breaker import circuit_manager


class IntegrationTester:
    """Automated integration testing for all data sources"""
    
    def __init__(self):
        self.logger = logging.getLogger("IntegrationTester")
        self.api_service = APIService()
        self.test_queries = [
            "energia",
            "saúde",
            "educação",
            "meio ambiente",
            "segurança"
        ]
        self.results = {}
    
    async def run_full_test_suite(self) -> Dict[str, Any]:
        """Run comprehensive tests on all sources"""
        print("🧪 Starting Integration Test Suite")
        print("=" * 50)
        
        start_time = datetime.now()
        
        # Test individual sources
        source_results = await self._test_all_sources()
        
        # Test search functionality
        search_results = await self._test_search_functionality()
        
        # Test health checks
        health_results = await self._test_health_checks()
        
        # Generate summary
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        summary = self._generate_test_summary(
            source_results, search_results, health_results, duration
        )
        
        # Save results
        await self._save_test_results(summary)
        
        return summary
    
    async def _test_all_sources(self) -> Dict[str, Any]:
        """Test each data source individually"""
        print("\n📡 Testing Individual Data Sources")
        print("-" * 30)
        
        sources = self.api_service.get_available_sources()
        source_results = {}
        
        for source_key, source_name in sources.items():
            print(f"Testing {source_name}...")
            
            result = await self._test_source(source_key, "energia")
            source_results[source_key] = result
            
            status = "✅" if result["success"] else "❌"
            print(f"  {status} {source_name}: {result['message']}")
        
        return source_results
    
    async def _test_source(self, source_key: str, query: str) -> Dict[str, Any]:
        """Test a single data source"""
        start_time = time.time()
        
        try:
            # Test search with timeout
            results = await asyncio.wait_for(
                self.api_service.search_all(query, {}, [source_key]),
                timeout=30
            )
            
            response_time = time.time() - start_time
            
            if results and len(results) > 0:
                result = results[0]
                if result.total_count > 0:
                    return {
                        "success": True,
                        "response_time": response_time,
                        "result_count": result.total_count,
                        "message": f"Found {result.total_count} results in {response_time:.2f}s"
                    }
                else:
                    return {
                        "success": True,
                        "response_time": response_time,
                        "result_count": 0,
                        "message": f"No results found (service working, {response_time:.2f}s)"
                    }
            else:
                return {
                    "success": False,
                    "response_time": response_time,
                    "result_count": 0,
                    "message": f"No response from service ({response_time:.2f}s)"
                }
                
        except asyncio.TimeoutError:
            return {
                "success": False,
                "response_time": 30.0,
                "result_count": 0,
                "message": "Timeout after 30 seconds"
            }
        except Exception as e:
            response_time = time.time() - start_time
            return {
                "success": False,
                "response_time": response_time,
                "result_count": 0,
                "message": f"Error: {str(e)}"
            }
    
    async def _test_search_functionality(self) -> Dict[str, Any]:
        """Test multi-source search functionality"""
        print("\n🔍 Testing Search Functionality")
        print("-" * 30)
        
        search_results = {}
        
        for query in self.test_queries:
            print(f"Testing query: '{query}'...")
            
            start_time = time.time()
            try:
                results = await asyncio.wait_for(
                    self.api_service.search_all(query, {}),
                    timeout=60
                )
                
                response_time = time.time() - start_time
                total_results = sum(r.total_count for r in results)
                working_sources = sum(1 for r in results if r.total_count > 0)
                
                search_results[query] = {
                    "success": True,
                    "response_time": response_time,
                    "total_results": total_results,
                    "working_sources": working_sources,
                    "total_sources": len(results),
                    "message": f"{total_results} results from {working_sources}/{len(results)} sources"
                }
                
                print(f"  ✅ {query}: {search_results[query]['message']}")
                
            except asyncio.TimeoutError:
                search_results[query] = {
                    "success": False,
                    "response_time": 60.0,
                    "message": "Timeout after 60 seconds"
                }
                print(f"  ❌ {query}: Timeout")
                
            except Exception as e:
                response_time = time.time() - start_time
                search_results[query] = {
                    "success": False,
                    "response_time": response_time,
                    "message": f"Error: {str(e)}"
                }
                print(f"  ❌ {query}: Error")
        
        return search_results
    
    async def _test_health_checks(self) -> Dict[str, Any]:
        """Test health check functionality"""
        print("\n❤️  Testing Health Checks")
        print("-" * 30)
        
        try:
            health_statuses = await self.api_service.get_api_status(force_check=True)
            
            health_results = {
                "total_services": len(health_statuses),
                "healthy_services": sum(1 for s in health_statuses if s.is_healthy),
                "unhealthy_services": sum(1 for s in health_statuses if not s.is_healthy),
                "services": {}
            }
            
            for status in health_statuses:
                health_results["services"][status.name] = {
                    "healthy": status.is_healthy,
                    "response_time": status.response_time,
                    "error_message": status.error_message
                }
                
                status_icon = "✅" if status.is_healthy else "❌"
                print(f"  {status_icon} {status.name}: {'Healthy' if status.is_healthy else 'Unhealthy'}")
            
            return health_results
            
        except Exception as e:
            return {
                "error": str(e),
                "message": "Failed to check health statuses"
            }
    
    def _generate_test_summary(self, source_results: Dict, search_results: Dict,
                              health_results: Dict, duration: float) -> Dict[str, Any]:
        """Generate comprehensive test summary"""
        
        # Source statistics
        successful_sources = sum(1 for r in source_results.values() if r["success"])
        total_sources = len(source_results)
        
        # Search statistics
        successful_searches = sum(1 for r in search_results.values() if r["success"])
        total_searches = len(search_results)
        
        # Overall health
        overall_health = "healthy"
        if successful_sources / total_sources < 0.5:
            overall_health = "critical"
        elif successful_sources / total_sources < 0.8:
            overall_health = "degraded"
        
        # Get circuit breaker stats
        circuit_stats = circuit_manager.get_all_stats()
        
        # Get monitoring data
        monitoring_data = metrics_collector.get_dashboard_data()
        
        summary = {
            "test_info": {
                "timestamp": datetime.now().isoformat(),
                "duration_seconds": round(duration, 2),
                "test_type": "full_integration"
            },
            "overall": {
                "health": overall_health,
                "success_rate": round((successful_sources / total_sources) * 100, 2),
                "total_sources": total_sources,
                "working_sources": successful_sources,
                "failed_sources": total_sources - successful_sources
            },
            "source_tests": source_results,
            "search_tests": search_results,
            "health_checks": health_results,
            "circuit_breakers": circuit_stats,
            "monitoring": monitoring_data,
            "recommendations": self._generate_recommendations(
                source_results, search_results, health_results
            )
        }
        
        return summary
    
    def _generate_recommendations(self, source_results: Dict, search_results: Dict,
                                 health_results: Dict) -> List[str]:
        """Generate recommendations based on test results"""
        recommendations = []
        
        # Check for consistently failing sources
        failed_sources = [name for name, result in source_results.items() if not result["success"]]
        if failed_sources:
            recommendations.append(
                f"Consider disabling or fixing these failing sources: {', '.join(failed_sources)}"
            )
        
        # Check for slow sources
        slow_sources = [
            name for name, result in source_results.items() 
            if result.get("response_time", 0) > 10
        ]
        if slow_sources:
            recommendations.append(
                f"These sources are slow (>10s): {', '.join(slow_sources)}"
            )
        
        # Check search performance
        failed_searches = sum(1 for r in search_results.values() if not r["success"])
        if failed_searches > 0:
            recommendations.append(
                f"{failed_searches} search queries failed - investigate timeout issues"
            )
        
        # Check overall health
        if source_results:
            success_rate = sum(1 for r in source_results.values() if r["success"]) / len(source_results)
            if success_rate < 0.8:
                recommendations.append(
                    "Overall system health is below 80% - immediate attention required"
                )
        
        if not recommendations:
            recommendations.append("System is performing well - no immediate action required")
        
        return recommendations
    
    async def _save_test_results(self, summary: Dict[str, Any]):
        """Save test results to file"""
        try:
            results_dir = project_root / "test_results"
            results_dir.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"integration_test_{timestamp}.json"
            
            import json
            with open(results_dir / filename, 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2, default=str)
            
            print(f"\n💾 Test results saved to: {filename}")
            
        except Exception as e:
            self.logger.error(f"Failed to save test results: {e}")
    
    def print_summary(self, summary: Dict[str, Any]):
        """Print formatted test summary"""
        print("\n" + "=" * 60)
        print("🧪 INTEGRATION TEST SUMMARY")
        print("=" * 60)
        
        overall = summary["overall"]
        print(f"Overall Health: {overall['health'].upper()}")
        print(f"Success Rate: {overall['success_rate']}%")
        print(f"Working Sources: {overall['working_sources']}/{overall['total_sources']}")
        print(f"Test Duration: {summary['test_info']['duration_seconds']}s")
        
        print("\n📊 Recommendations:")
        for i, rec in enumerate(summary["recommendations"], 1):
            print(f"  {i}. {rec}")
        
        print("\n" + "=" * 60)


async def run_integration_tests():
    """Main function to run integration tests"""
    tester = IntegrationTester()
    
    try:
        summary = await tester.run_full_test_suite()
        tester.print_summary(summary)
        return summary
        
    except Exception as e:
        print(f"❌ Integration tests failed: {str(e)}")
        logging.error(f"Integration tests failed: {str(e)}")
        return None


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run tests
    asyncio.run(run_integration_tests())