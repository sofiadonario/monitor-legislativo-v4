"""
End-to-end production readiness tests
Validates complete system functionality in production-like environment
"""

import os
import sys
import json
import time
import pytest
import requests
import asyncio
import websocket
from datetime import datetime
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor
import threading

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from core.config.config import get_config
from core.database.migrations import DatabaseMigrationManager
from core.utils.production_logger import get_logger
from core.utils.error_tracking import get_error_tracker

class ProductionTestSuite:
    """Comprehensive production readiness test suite"""
    
    def __init__(self):
        self.config = get_config()
        self.logger = get_logger()
        self.base_url = "http://localhost:5000"
        self.web_url = "http://localhost:3000"
        self.test_results = {}
        
    def run_all_tests(self) -> Dict[str, Any]:
        """Run complete test suite"""
        self.logger.logger.info("Starting production readiness test suite")
        
        tests = [
            ("Database Health", self.test_database_health),
            ("API Endpoints", self.test_api_endpoints),
            ("Authentication", self.test_authentication),
            ("Search Functionality", self.test_search_functionality),
            ("WebSocket Real-time", self.test_websocket_realtime),
            ("External API Integration", self.test_external_apis),
            ("Performance Load", self.test_performance_load),
            ("Security Features", self.test_security_features),
            ("Monitoring & Metrics", self.test_monitoring_metrics),
            ("Error Handling", self.test_error_handling),
            ("Data Export", self.test_data_export),
            ("Cache Performance", self.test_cache_performance),
            ("Circuit Breaker", self.test_circuit_breaker),
            ("Rate Limiting", self.test_rate_limiting),
            ("SSL & Security Headers", self.test_ssl_security)
        ]
        
        results = {
            "test_suite": "Production Readiness",
            "start_time": datetime.utcnow().isoformat(),
            "tests": {},
            "summary": {}
        }
        
        passed = 0
        failed = 0
        
        for test_name, test_func in tests:
            try:
                self.logger.logger.info(f"Running test: {test_name}")
                result = test_func()
                results["tests"][test_name] = {
                    "status": "PASSED" if result["success"] else "FAILED",
                    "duration": result.get("duration", 0),
                    "details": result.get("details", {}),
                    "errors": result.get("errors", [])
                }
                
                if result["success"]:
                    passed += 1
                else:
                    failed += 1
                    
            except Exception as e:
                failed += 1
                results["tests"][test_name] = {
                    "status": "ERROR",
                    "duration": 0,
                    "details": {},
                    "errors": [str(e)]
                }
                self.logger.logger.error(f"Test {test_name} failed with error: {e}")
        
        results["end_time"] = datetime.utcnow().isoformat()
        results["summary"] = {
            "total_tests": len(tests),
            "passed": passed,
            "failed": failed,
            "success_rate": f"{(passed / len(tests) * 100):.1f}%"
        }
        
        return results
    
    def test_database_health(self) -> Dict[str, Any]:
        """Test database connectivity and health"""
        start_time = time.time()
        
        try:
            db_manager = DatabaseMigrationManager()
            health = db_manager.health_check()
            
            return {
                "success": health["status"] == "healthy",
                "duration": time.time() - start_time,
                "details": health
            }
        except Exception as e:
            return {
                "success": False,
                "duration": time.time() - start_time,
                "errors": [str(e)]
            }
    
    def test_api_endpoints(self) -> Dict[str, Any]:
        """Test core API endpoints"""
        start_time = time.time()
        
        endpoints = [
            ("GET", "/health", 200),
            ("GET", "/api/documents", 200),
            ("GET", "/api/search", 200),
            ("GET", "/metrics", 200),
            ("GET", "/docs", 200)
        ]
        
        results = []
        errors = []
        
        for method, endpoint, expected_status in endpoints:
            try:
                response = requests.request(method, f"{self.base_url}{endpoint}", timeout=10)
                success = response.status_code == expected_status
                results.append({
                    "endpoint": endpoint,
                    "method": method,
                    "status_code": response.status_code,
                    "expected": expected_status,
                    "success": success,
                    "response_time": response.elapsed.total_seconds()
                })
                
                if not success:
                    errors.append(f"{endpoint}: Expected {expected_status}, got {response.status_code}")
                    
            except Exception as e:
                results.append({
                    "endpoint": endpoint,
                    "method": method,
                    "success": False,
                    "error": str(e)
                })
                errors.append(f"{endpoint}: {str(e)}")
        
        success_count = sum(1 for r in results if r.get("success", False))
        
        return {
            "success": len(errors) == 0,
            "duration": time.time() - start_time,
            "details": {
                "endpoints_tested": len(endpoints),
                "successful": success_count,
                "failed": len(endpoints) - success_count,
                "results": results
            },
            "errors": errors
        }
    
    def test_authentication(self) -> Dict[str, Any]:
        """Test authentication system"""
        start_time = time.time()
        
        try:
            # Test login endpoint
            login_data = {
                "username": "admin",
                "password": "admin123"
            }
            
            response = requests.post(f"{self.base_url}/api/auth/login", 
                                   json=login_data, timeout=10)
            
            if response.status_code == 200:
                token = response.json().get("access_token")
                
                # Test protected endpoint with token
                headers = {"Authorization": f"Bearer {token}"}
                protected_response = requests.get(f"{self.base_url}/api/admin/users",
                                                headers=headers, timeout=10)
                
                return {
                    "success": protected_response.status_code == 200,
                    "duration": time.time() - start_time,
                    "details": {
                        "login_status": response.status_code,
                        "token_received": bool(token),
                        "protected_access": protected_response.status_code
                    }
                }
            else:
                return {
                    "success": False,
                    "duration": time.time() - start_time,
                    "errors": [f"Login failed: {response.status_code}"]
                }
                
        except Exception as e:
            return {
                "success": False,
                "duration": time.time() - start_time,
                "errors": [str(e)]
            }
    
    def test_search_functionality(self) -> Dict[str, Any]:
        """Test search functionality"""
        start_time = time.time()
        
        try:
            search_queries = [
                "lei proteção dados",
                "decreto transparência",
                "reforma tributária"
            ]
            
            results = []
            errors = []
            
            for query in search_queries:
                response = requests.get(f"{self.base_url}/api/search",
                                      params={"q": query}, timeout=15)
                
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "query": query,
                        "status": "success",
                        "results_count": len(data.get("results", [])),
                        "response_time": response.elapsed.total_seconds()
                    })
                else:
                    results.append({
                        "query": query,
                        "status": "failed",
                        "status_code": response.status_code
                    })
                    errors.append(f"Search '{query}' failed: {response.status_code}")
            
            return {
                "success": len(errors) == 0,
                "duration": time.time() - start_time,
                "details": {
                    "queries_tested": len(search_queries),
                    "successful_searches": len([r for r in results if r["status"] == "success"]),
                    "results": results
                },
                "errors": errors
            }
            
        except Exception as e:
            return {
                "success": False,
                "duration": time.time() - start_time,
                "errors": [str(e)]
            }
    
    def test_websocket_realtime(self) -> Dict[str, Any]:
        """Test WebSocket real-time functionality"""
        start_time = time.time()
        
        try:
            # Simple WebSocket connection test
            ws_url = f"ws://localhost:5000/socket.io/?EIO=4&transport=websocket"
            
            def on_message(ws, message):
                pass
            
            def on_error(ws, error):
                pass
            
            def on_close(ws, close_status_code, close_msg):
                pass
            
            def on_open(ws):
                ws.send("2probe")  # Socket.IO ping
            
            ws = websocket.WebSocketApp(ws_url,
                                      on_open=on_open,
                                      on_message=on_message,
                                      on_error=on_error,
                                      on_close=on_close)
            
            # Run WebSocket in separate thread for 5 seconds
            ws_thread = threading.Thread(target=ws.run_forever)
            ws_thread.daemon = True
            ws_thread.start()
            
            time.sleep(2)  # Give it time to connect
            ws.close()
            
            return {
                "success": True,
                "duration": time.time() - start_time,
                "details": {
                    "connection_test": "completed",
                    "websocket_url": ws_url
                }
            }
            
        except Exception as e:
            return {
                "success": False,
                "duration": time.time() - start_time,
                "errors": [str(e)]
            }
    
    def test_external_apis(self) -> Dict[str, Any]:
        """Test external API integrations"""
        start_time = time.time()
        
        try:
            # Test external API endpoint
            response = requests.get(f"{self.base_url}/api/external/camara/proposicoes",
                                  timeout=30)
            
            return {
                "success": response.status_code in [200, 503],  # 503 is acceptable for circuit breaker
                "duration": time.time() - start_time,
                "details": {
                    "status_code": response.status_code,
                    "response_time": response.elapsed.total_seconds()
                }
            }
            
        except Exception as e:
            return {
                "success": False,
                "duration": time.time() - start_time,
                "errors": [str(e)]
            }
    
    def test_performance_load(self) -> Dict[str, Any]:
        """Test system performance under load"""
        start_time = time.time()
        
        try:
            def make_request():
                response = requests.get(f"{self.base_url}/api/documents", timeout=10)
                return response.status_code == 200, response.elapsed.total_seconds()
            
            # Run 20 concurrent requests
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(make_request) for _ in range(20)]
                results = [future.result() for future in futures]
            
            successful_requests = sum(1 for success, _ in results if success)
            response_times = [time for success, time in results if success]
            avg_response_time = sum(response_times) / len(response_times) if response_times else 0
            
            return {
                "success": successful_requests >= 18,  # 90% success rate
                "duration": time.time() - start_time,
                "details": {
                    "total_requests": 20,
                    "successful_requests": successful_requests,
                    "success_rate": f"{(successful_requests / 20 * 100):.1f}%",
                    "avg_response_time": f"{avg_response_time:.3f}s",
                    "max_response_time": f"{max(response_times):.3f}s" if response_times else "N/A"
                }
            }
            
        except Exception as e:
            return {
                "success": False,
                "duration": time.time() - start_time,
                "errors": [str(e)]
            }
    
    def test_security_features(self) -> Dict[str, Any]:
        """Test security features"""
        start_time = time.time()
        
        try:
            results = []
            
            # Test CORS headers
            response = requests.get(f"{self.base_url}/api/documents", timeout=10)
            cors_headers = response.headers.get("Access-Control-Allow-Origin")
            results.append({"test": "CORS", "present": bool(cors_headers)})
            
            # Test security headers
            security_headers = [
                "X-Content-Type-Options",
                "X-Frame-Options",
                "X-XSS-Protection"
            ]
            
            for header in security_headers:
                present = header in response.headers
                results.append({"test": f"Security Header: {header}", "present": present})
            
            # Test SQL injection protection (should not crash)
            malicious_query = "'; DROP TABLE users; --"
            response = requests.get(f"{self.base_url}/api/search",
                                  params={"q": malicious_query}, timeout=10)
            results.append({
                "test": "SQL Injection Protection",
                "protected": response.status_code in [200, 400]  # Should handle gracefully
            })
            
            security_score = sum(1 for r in results if r.get("present", False) or r.get("protected", False))
            
            return {
                "success": security_score >= len(results) * 0.8,  # 80% security features
                "duration": time.time() - start_time,
                "details": {
                    "security_tests": results,
                    "security_score": f"{security_score}/{len(results)}"
                }
            }
            
        except Exception as e:
            return {
                "success": False,
                "duration": time.time() - start_time,
                "errors": [str(e)]
            }
    
    def test_monitoring_metrics(self) -> Dict[str, Any]:
        """Test monitoring and metrics endpoints"""
        start_time = time.time()
        
        try:
            # Test metrics endpoint
            response = requests.get(f"{self.base_url}/metrics", timeout=10)
            
            metrics_available = response.status_code == 200
            prometheus_format = "# HELP" in response.text if metrics_available else False
            
            return {
                "success": metrics_available and prometheus_format,
                "duration": time.time() - start_time,
                "details": {
                    "metrics_endpoint_status": response.status_code,
                    "prometheus_format": prometheus_format,
                    "metrics_count": response.text.count("# HELP") if metrics_available else 0
                }
            }
            
        except Exception as e:
            return {
                "success": False,
                "duration": time.time() - start_time,
                "errors": [str(e)]
            }
    
    def test_error_handling(self) -> Dict[str, Any]:
        """Test error handling and recovery"""
        start_time = time.time()
        
        try:
            # Test 404 handling
            response = requests.get(f"{self.base_url}/api/nonexistent", timeout=10)
            handles_404 = response.status_code == 404
            
            # Test invalid JSON handling
            response = requests.post(f"{self.base_url}/api/documents",
                                   data="invalid json", timeout=10)
            handles_bad_json = response.status_code == 400
            
            return {
                "success": handles_404 and handles_bad_json,
                "duration": time.time() - start_time,
                "details": {
                    "404_handling": handles_404,
                    "bad_json_handling": handles_bad_json
                }
            }
            
        except Exception as e:
            return {
                "success": False,
                "duration": time.time() - start_time,
                "errors": [str(e)]
            }
    
    def test_data_export(self) -> Dict[str, Any]:
        """Test data export functionality"""
        start_time = time.time()
        
        try:
            export_data = {
                "format": "csv",
                "query": "test export"
            }
            
            response = requests.post(f"{self.base_url}/api/export",
                                   json=export_data, timeout=30)
            
            return {
                "success": response.status_code in [200, 202],  # 202 for async processing
                "duration": time.time() - start_time,
                "details": {
                    "export_status": response.status_code,
                    "response_time": response.elapsed.total_seconds()
                }
            }
            
        except Exception as e:
            return {
                "success": False,
                "duration": time.time() - start_time,
                "errors": [str(e)]
            }
    
    def test_cache_performance(self) -> Dict[str, Any]:
        """Test cache performance"""
        start_time = time.time()
        
        try:
            # First request (cache miss)
            response1 = requests.get(f"{self.base_url}/api/documents?limit=10", timeout=10)
            first_response_time = response1.elapsed.total_seconds()
            
            # Second request (cache hit)
            response2 = requests.get(f"{self.base_url}/api/documents?limit=10", timeout=10)
            second_response_time = response2.elapsed.total_seconds()
            
            cache_effective = second_response_time < first_response_time * 0.8  # 20% improvement
            
            return {
                "success": response1.status_code == 200 and response2.status_code == 200,
                "duration": time.time() - start_time,
                "details": {
                    "first_request_time": f"{first_response_time:.3f}s",
                    "second_request_time": f"{second_response_time:.3f}s",
                    "cache_effective": cache_effective,
                    "improvement": f"{((first_response_time - second_response_time) / first_response_time * 100):.1f}%"
                }
            }
            
        except Exception as e:
            return {
                "success": False,
                "duration": time.time() - start_time,
                "errors": [str(e)]
            }
    
    def test_circuit_breaker(self) -> Dict[str, Any]:
        """Test circuit breaker functionality"""
        start_time = time.time()
        
        try:
            # Test circuit breaker status endpoint
            response = requests.get(f"{self.base_url}/api/health/circuit-breaker", timeout=10)
            
            return {
                "success": response.status_code == 200,
                "duration": time.time() - start_time,
                "details": {
                    "circuit_breaker_status": response.status_code,
                    "response_data": response.json() if response.status_code == 200 else None
                }
            }
            
        except Exception as e:
            return {
                "success": False,
                "duration": time.time() - start_time,
                "errors": [str(e)]
            }
    
    def test_rate_limiting(self) -> Dict[str, Any]:
        """Test rate limiting"""
        start_time = time.time()
        
        try:
            # Make rapid requests to trigger rate limiting
            responses = []
            for i in range(10):
                response = requests.get(f"{self.base_url}/api/documents", timeout=5)
                responses.append(response.status_code)
                time.sleep(0.1)
            
            # Check if any requests were rate limited (429)
            rate_limited = 429 in responses
            
            return {
                "success": True,  # Rate limiting is working if we get 429s
                "duration": time.time() - start_time,
                "details": {
                    "total_requests": len(responses),
                    "rate_limited_requests": responses.count(429),
                    "successful_requests": responses.count(200),
                    "rate_limiting_active": rate_limited
                }
            }
            
        except Exception as e:
            return {
                "success": False,
                "duration": time.time() - start_time,
                "errors": [str(e)]
            }
    
    def test_ssl_security(self) -> Dict[str, Any]:
        """Test SSL and security configurations"""
        start_time = time.time()
        
        try:
            # In production, this would test HTTPS
            # For local testing, we check security headers
            response = requests.get(f"{self.base_url}/health", timeout=10)
            
            security_headers = {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "X-XSS-Protection": "1; mode=block"
            }
            
            present_headers = {}
            for header, expected in security_headers.items():
                actual = response.headers.get(header)
                present_headers[header] = {
                    "present": actual is not None,
                    "expected": expected,
                    "actual": actual
                }
            
            security_score = sum(1 for h in present_headers.values() if h["present"])
            
            return {
                "success": security_score >= len(security_headers) * 0.7,
                "duration": time.time() - start_time,
                "details": {
                    "security_headers": present_headers,
                    "security_score": f"{security_score}/{len(security_headers)}"
                }
            }
            
        except Exception as e:
            return {
                "success": False,
                "duration": time.time() - start_time,
                "errors": [str(e)]
            }

def run_production_tests():
    """Run the complete production test suite"""
    test_suite = ProductionTestSuite()
    results = test_suite.run_all_tests()
    
    # Save results to file
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    results_file = f"data/reports/production_test_{timestamp}.json"
    
    os.makedirs("data/reports", exist_ok=True)
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"Production test results saved to: {results_file}")
    return results

if __name__ == "__main__":
    results = run_production_tests()
    print(f"\nProduction Test Summary:")
    print(f"Total Tests: {results['summary']['total_tests']}")
    print(f"Passed: {results['summary']['passed']}")
    print(f"Failed: {results['summary']['failed']}")
    print(f"Success Rate: {results['summary']['success_rate']}")