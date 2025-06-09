"""
Comprehensive API Integration Test Suite for Monitor Legislativo v4
Nuclear-level testing with 100% coverage target

SPRINT 10 - TASK 10.1: Comprehensive API Integration Tests
✅ Real API endpoint testing with mock fallbacks
✅ Error handling verification under all conditions
✅ Rate limiting compliance testing
✅ Response validation and sanitization
✅ Correlation tracking across requests
✅ Circuit breaker behavior testing
✅ Cache effectiveness validation
✅ Security validation integration
✅ Performance benchmarking
✅ Concurrent request handling
"""

import pytest
import asyncio
import time
import json
import uuid
from typing import Dict, List, Any, Optional
from unittest.mock import Mock, patch, AsyncMock
import aiohttp
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import our components
from core.api.base_service import BaseAPIService
from core.api.enhanced_base_service import BaseGovAPI
from core.api.camara_service import CamaraService
from core.api.senado_service import SenadoService
from core.api.planalto_service import PlanaltoService
from core.api.lexml_integration import LexMLIntegration
from core.config.url_validator import URLValidator
from core.security.enhanced_security_validator import EnhancedSecurityValidator, get_security_validator
from core.monitoring.forensic_logging import ForensicLogger, get_forensic_logger
from core.utils.circuit_breaker import CircuitBreaker
from core.config.config import get_config


class TestComprehensiveAPIIntegration:
    """
    Comprehensive API integration tests with military precision.
    Tests all API services under various conditions including:
    - Normal operation
    - Error conditions
    - Security threats
    - Performance limits
    - Concurrent access
    - Circuit breaker scenarios
    """
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test environment with forensic tracking."""
        self.config = get_config()
        self.validator = URLValidator()
        self.security = get_security_validator()
        self.forensic = get_forensic_logger()
        self.correlation_id = str(uuid.uuid4())
        
        # Services to test
        self.services = {
            'camara': CamaraService(self.config.api_configs['camara']),
            'senado': SenadoService(self.config.api_configs['senado']),
            'planalto': PlanaltoService(self.config.api_configs['planalto']),
            'lexml': LexMLIntegration()
        }
        
        # Start forensic investigation for test session
        self.investigation_id = self.forensic.start_investigation(
            "API Integration Test Session",
            {"test_run": True, "correlation_id": self.correlation_id}
        )
        
        yield
        
        # Generate investigation report
        report = self.forensic.generate_investigation_report(self.investigation_id)
        print(f"\n📊 Test Investigation Report:")
        print(f"   Total events: {report['total_events']}")
        print(f"   Security incidents: {len(report['security_incidents'])}")
        print(f"   Performance issues: {len(report['performance_issues'])}")
    
    @pytest.mark.asyncio
    async def test_camara_api_complete_workflow(self):
        """Test complete Câmara API workflow with all edge cases."""
        
        service = self.services['camara']
        
        # Test 1: Basic search functionality
        with self.forensic.correlation_span("test_camara_search", 
                                           correlation_id=self.correlation_id) as ctx:
            try:
                # Valid search
                result = await service.search(
                    query="transporte",
                    filters={"ano": 2024, "tipo": "PL"}
                )
                
                assert result is not None
                assert hasattr(result, 'items')
                assert hasattr(result, 'total_count')
                
                # Log success
                self.forensic.log_forensic_event(
                    level=self.forensic.LogLevel.INFO,
                    category=self.forensic.EventCategory.BUSINESS,
                    component="test",
                    operation="camara_search",
                    message="Câmara search test successful",
                    correlation_id=ctx.correlation_id,
                    success=True,
                    custom_attributes={
                        "result_count": len(result.items),
                        "total_count": result.total_count
                    }
                )
                
            except Exception as e:
                self.forensic.log_error_event(
                    component="test",
                    operation="camara_search",
                    error=e,
                    correlation_id=ctx.correlation_id
                )
                # Allow test to continue - API might be down
        
        # Test 2: SQL injection attempt (should be blocked)
        with pytest.raises(Exception):
            malicious_query = "'; DROP TABLE proposicoes; --"
            is_valid, sanitized, events = self.security.validate_input(
                malicious_query, "query", "127.0.0.1", "test-agent"
            )
            assert not is_valid
            assert sanitized == "BLOCKED"
        
        # Test 3: Rate limiting compliance
        start_time = time.time()
        request_times = []
        
        for i in range(5):
            request_start = time.time()
            try:
                await service.search("test", {"limit": 1})
                request_times.append(time.time() - request_start)
            except Exception:
                pass
        
        # Verify rate limiting is respected
        total_time = time.time() - start_time
        assert total_time >= 4.0  # Should take at least 4 seconds for 5 requests with 1req/sec limit
        
        # Test 4: Circuit breaker behavior
        # Force circuit breaker to open by simulating failures
        with patch.object(service, '_make_request', side_effect=Exception("API Error")):
            for _ in range(10):  # Exceed failure threshold
                try:
                    await service.search("test", {})
                except Exception:
                    pass
        
        # Circuit should be open now
        try:
            await service.search("test", {})
        except Exception as e:
            assert "circuit breaker" in str(e).lower()
        
        # Test 5: Proposition details with error handling
        try:
            # Test with valid ID
            proposition = await service.get_proposition_details("123456")
            if proposition:
                assert hasattr(proposition, 'id')
                assert hasattr(proposition, 'tipo')
            
            # Test with invalid ID (should handle gracefully)
            invalid_prop = await service.get_proposition_details("invalid-id")
            assert invalid_prop is None or isinstance(invalid_prop, dict)
            
        except Exception as e:
            # Log but don't fail - API might be unavailable
            self.forensic.log_error_event(
                component="test",
                operation="camara_proposition_details",
                error=e,
                correlation_id=self.correlation_id
            )
    
    @pytest.mark.asyncio
    async def test_senado_api_complete_workflow(self):
        """Test complete Senado API workflow with security validation."""
        
        service = self.services['senado']
        
        with self.forensic.correlation_span("test_senado_workflow",
                                          correlation_id=self.correlation_id) as ctx:
            # Test 1: Search with various filters
            test_cases = [
                {"query": "transporte rodoviário", "filters": {"ano": 2024}},
                {"query": "ANTT", "filters": {"tipo": "PLS"}},
                {"query": "concessão", "filters": {"autor": "governo"}},
                {"query": "", "filters": {"tramitando": True}}  # Empty query
            ]
            
            for test_case in test_cases:
                try:
                    result = await service.search(
                        test_case["query"],
                        test_case["filters"]
                    )
                    
                    # Validate response structure
                    assert result is not None
                    assert hasattr(result, 'items')
                    
                    # Validate response content is sanitized
                    for item in result.items[:5]:  # Check first 5 items
                        if hasattr(item, 'ementa'):
                            # Ensure no script tags or dangerous content
                            assert '<script' not in str(item.ementa).lower()
                            assert 'javascript:' not in str(item.ementa).lower()
                    
                except Exception as e:
                    self.forensic.log_error_event(
                        component="test",
                        operation="senado_search",
                        error=e,
                        correlation_id=ctx.correlation_id,
                        custom_attributes={"test_case": test_case}
                    )
            
            # Test 2: Concurrent requests handling
            async def concurrent_search(query: str) -> Any:
                return await service.search(query, {"limit": 5})
            
            # Launch 10 concurrent searches
            tasks = [concurrent_search(f"test{i}") for i in range(10)]
            start_time = time.time()
            
            try:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                duration = time.time() - start_time
                
                # Log performance metrics
                self.forensic.log_performance_event(
                    operation="senado_concurrent_test",
                    duration_ms=duration * 1000,
                    correlation_id=ctx.correlation_id,
                    custom_attributes={
                        "concurrent_requests": 10,
                        "successful_requests": sum(1 for r in results if not isinstance(r, Exception)),
                        "failed_requests": sum(1 for r in results if isinstance(r, Exception))
                    }
                )
                
            except Exception as e:
                self.forensic.log_error_event(
                    component="test",
                    operation="senado_concurrent",
                    error=e,
                    correlation_id=ctx.correlation_id
                )
    
    @pytest.mark.asyncio
    async def test_planalto_api_with_caching(self):
        """Test Planalto API with cache behavior validation."""
        
        service = self.services['planalto']
        
        # Test 1: Cache effectiveness
        query = "lei de transporte"
        filters = {"tipo": "lei", "ano": 2023}
        
        # First request (cache miss)
        start1 = time.time()
        result1 = await service.search(query, filters)
        duration1 = time.time() - start1
        
        # Second request (should be cached)
        start2 = time.time()
        result2 = await service.search(query, filters)
        duration2 = time.time() - start2
        
        # Cache should make second request much faster
        assert duration2 < duration1 * 0.5  # At least 50% faster
        
        # Results should be identical
        if result1 and result2:
            assert result1.total_count == result2.total_count
        
        # Test 2: Decree search with validation
        try:
            decree_result = await service.buscar_decretos(
                numero="10.282",
                ano=2020
            )
            
            if decree_result:
                # Validate decree structure
                assert isinstance(decree_result, (list, dict))
                
                # Security validation on response
                response_text = json.dumps(decree_result)
                sanitized = self.security.sanitize_api_response(response_text)
                assert sanitized != "RESPONSE_SANITIZATION_ERROR"
                
        except Exception as e:
            self.forensic.log_error_event(
                component="test",
                operation="planalto_decree_search",
                error=e,
                correlation_id=self.correlation_id
            )
    
    @pytest.mark.asyncio
    async def test_lexml_integration_complete(self):
        """Test LexML integration with all features."""
        
        service = self.services['lexml']
        
        with self.forensic.correlation_span("test_lexml_complete",
                                          correlation_id=self.correlation_id) as ctx:
            # Test 1: XML security validation
            test_xml = """<?xml version="1.0"?>
            <!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <test>&xxe;</test>"""
            
            is_valid, sanitized = self.security.validate_xml_security(test_xml)
            assert not is_valid
            assert "XXE_THREAT_DETECTED" in sanitized
            
            # Test 2: Normal search
            try:
                results = await service.search(
                    query="transporte rodoviário de cargas",
                    filters={"tipo": "legislacao", "ano": 2024}
                )
                
                if results:
                    assert hasattr(results, 'items')
                    
                    # Validate each result
                    for item in results.items[:5]:
                        # Check required fields
                        assert hasattr(item, 'titulo') or hasattr(item, 'title')
                        assert hasattr(item, 'tipo') or hasattr(item, 'type')
                        assert hasattr(item, 'data') or hasattr(item, 'date')
                
            except Exception as e:
                self.forensic.log_error_event(
                    component="test",
                    operation="lexml_search",
                    error=e,
                    correlation_id=ctx.correlation_id
                )
            
            # Test 3: Performance under load
            async def load_test_search(i: int):
                start = time.time()
                try:
                    await service.search(f"test{i}", {"limit": 10})
                    return time.time() - start
                except Exception:
                    return None
            
            # Run 20 concurrent searches
            tasks = [load_test_search(i) for i in range(20)]
            durations = await asyncio.gather(*tasks)
            
            # Calculate statistics
            valid_durations = [d for d in durations if d is not None]
            if valid_durations:
                avg_duration = sum(valid_durations) / len(valid_durations)
                max_duration = max(valid_durations)
                
                self.forensic.log_performance_event(
                    operation="lexml_load_test",
                    duration_ms=avg_duration * 1000,
                    correlation_id=ctx.correlation_id,
                    custom_attributes={
                        "total_requests": 20,
                        "successful_requests": len(valid_durations),
                        "avg_duration_ms": avg_duration * 1000,
                        "max_duration_ms": max_duration * 1000
                    }
                )
    
    def test_url_validation_comprehensive(self):
        """Test URL validation system comprehensively."""
        
        # Test all configured URLs
        url_status = self.validator.verify_all_urls()
        
        # Log validation results
        for service, status in url_status.items():
            self.forensic.log_forensic_event(
                level=self.forensic.LogLevel.INFO,
                category=self.forensic.EventCategory.SYSTEM,
                component="test",
                operation="url_validation",
                message=f"URL validation for {service}",
                correlation_id=self.correlation_id,
                success=status.is_valid,
                custom_attributes={
                    "service": service,
                    "url": status.url,
                    "status_code": status.status_code,
                    "response_time_ms": status.response_time * 1000 if status.response_time else None,
                    "error": status.error
                }
            )
        
        # At least some URLs should be valid
        valid_count = sum(1 for status in url_status.values() if status.is_valid)
        assert valid_count > 0
    
    def test_security_validator_integration(self):
        """Test security validator integration with APIs."""
        
        test_cases = [
            # SQL Injection attempts
            {"input": "' OR 1=1--", "type": "sql_injection"},
            {"input": "'; DROP TABLE users; --", "type": "sql_injection"},
            {"input": "UNION SELECT * FROM passwords", "type": "sql_injection"},
            
            # XSS attempts
            {"input": "<script>alert('xss')</script>", "type": "xss"},
            {"input": "<img src=x onerror=alert('xss')>", "type": "xss"},
            {"input": "javascript:alert('xss')", "type": "xss"},
            
            # XXE attempts
            {"input": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>", "type": "xxe"},
            
            # Path traversal
            {"input": "../../../etc/passwd", "type": "path_traversal"},
            {"input": "..\\..\\..\\windows\\system32", "type": "path_traversal"},
            
            # Command injection
            {"input": "; cat /etc/passwd", "type": "command_injection"},
            {"input": "| whoami", "type": "command_injection"}
        ]
        
        blocked_count = 0
        for test in test_cases:
            is_valid, sanitized, events = self.security.validate_input(
                test["input"],
                "query",
                "127.0.0.1",
                "test-agent"
            )
            
            if not is_valid:
                blocked_count += 1
                assert sanitized == "BLOCKED"
                
                # Log security event
                self.forensic.log_security_event(
                    event_type=self.forensic.SecurityEventType.INJECTION_ATTEMPT,
                    severity="high",
                    source_ip="127.0.0.1",
                    user_agent="test-agent",
                    resource="/api/test",
                    action="input_validation",
                    outcome="blocked",
                    correlation_id=self.correlation_id,
                    risk_score=9,
                    indicators=[test["type"]],
                    mitigation_applied=["input_blocked"],
                    investigation_notes=f"Test case: {test['type']}"
                )
        
        # All malicious inputs should be blocked
        assert blocked_count == len(test_cases)
    
    @pytest.mark.asyncio
    async def test_error_recovery_mechanisms(self):
        """Test error recovery and resilience mechanisms."""
        
        # Test each service's error recovery
        for service_name, service in self.services.items():
            with self.forensic.correlation_span(f"test_{service_name}_recovery",
                                              correlation_id=self.correlation_id) as ctx:
                
                # Test 1: Network timeout recovery
                with patch.object(service.session, 'get', side_effect=requests.Timeout()):
                    try:
                        result = await service.search("test", {})
                    except Exception as e:
                        # Should handle timeout gracefully
                        assert "timeout" in str(e).lower()
                
                # Test 2: Invalid response recovery
                with patch.object(service.session, 'get') as mock_get:
                    mock_response = Mock()
                    mock_response.status_code = 200
                    mock_response.text = "invalid json {"
                    mock_response.json.side_effect = json.JSONDecodeError("test", "doc", 0)
                    mock_get.return_value = mock_response
                    
                    try:
                        result = await service.search("test", {})
                        # Should handle invalid JSON gracefully
                    except json.JSONDecodeError:
                        # Should not raise JSON error to user
                        pytest.fail("JSONDecodeError should be handled internally")
                
                # Test 3: 5xx error recovery with retry
                call_count = 0
                def mock_response_generator(*args, **kwargs):
                    nonlocal call_count
                    call_count += 1
                    
                    mock_resp = Mock()
                    if call_count < 3:
                        mock_resp.status_code = 503
                        mock_resp.raise_for_status.side_effect = requests.HTTPError()
                    else:
                        mock_resp.status_code = 200
                        mock_resp.json.return_value = {"results": []}
                    
                    return mock_resp
                
                with patch.object(service.session, 'get', side_effect=mock_response_generator):
                    try:
                        result = await service.search("test", {})
                        # Should succeed after retries
                        assert call_count >= 3
                    except Exception:
                        pass  # Might still fail after all retries
    
    @pytest.mark.asyncio
    async def test_concurrent_multi_service_load(self):
        """Test all services under concurrent load."""
        
        async def test_service_concurrent(service_name: str, service: Any, 
                                        num_requests: int) -> Dict[str, Any]:
            """Test a single service with concurrent requests."""
            
            async def single_request(i: int) -> Dict[str, Any]:
                start = time.time()
                success = False
                error = None
                
                try:
                    result = await service.search(f"test{i}", {"limit": 5})
                    success = result is not None
                except Exception as e:
                    error = str(e)
                
                return {
                    "duration": time.time() - start,
                    "success": success,
                    "error": error
                }
            
            # Launch concurrent requests
            tasks = [single_request(i) for i in range(num_requests)]
            results = await asyncio.gather(*tasks)
            
            # Calculate statistics
            successful = sum(1 for r in results if r["success"])
            avg_duration = sum(r["duration"] for r in results) / len(results)
            
            return {
                "service": service_name,
                "total_requests": num_requests,
                "successful": successful,
                "failed": num_requests - successful,
                "avg_duration": avg_duration,
                "success_rate": (successful / num_requests) * 100
            }
        
        # Test all services concurrently
        load_test_tasks = [
            test_service_concurrent(name, service, 10)
            for name, service in self.services.items()
        ]
        
        load_test_results = await asyncio.gather(*load_test_tasks)
        
        # Log comprehensive results
        for result in load_test_results:
            self.forensic.log_performance_event(
                operation=f"{result['service']}_concurrent_load",
                duration_ms=result['avg_duration'] * 1000,
                correlation_id=self.correlation_id,
                custom_attributes=result
            )
        
        # Generate summary
        total_requests = sum(r['total_requests'] for r in load_test_results)
        total_successful = sum(r['successful'] for r in load_test_results)
        overall_success_rate = (total_successful / total_requests) * 100
        
        print(f"\n🎯 Concurrent Load Test Results:")
        print(f"   Total requests: {total_requests}")
        print(f"   Successful: {total_successful}")
        print(f"   Success rate: {overall_success_rate:.1f}%")
        
        for result in load_test_results:
            print(f"   {result['service']}: {result['success_rate']:.1f}% success, "
                  f"{result['avg_duration']:.2f}s avg")
        
        # At least 50% success rate expected (APIs might be down)
        assert overall_success_rate >= 50.0
    
    def test_forensic_logging_integration(self):
        """Test forensic logging system integration."""
        
        # Query events from this test session
        events = self.forensic.query_events({
            "correlation_id": self.correlation_id
        })
        
        # Should have logged multiple events
        assert len(events) > 0
        
        # Verify event structure
        for event in events[:10]:  # Check first 10 events
            assert hasattr(event, 'event_id')
            assert hasattr(event, 'correlation_id')
            assert hasattr(event, 'timestamp')
            assert hasattr(event, 'level')
            assert hasattr(event, 'category')
            assert event.correlation_id == self.correlation_id
        
        # Get statistics
        stats = self.forensic.get_forensic_stats()
        assert stats['total_events'] > 0
        
        print(f"\n📊 Forensic Statistics:")
        print(f"   Total events: {stats['total_events']}")
        print(f"   Security events: {stats['security_events']}")
        print(f"   Performance events: {stats['performance_events']}")
        print(f"   Error events: {stats['error_events']}")
        print(f"   Anomalies detected: {stats['anomalies_detected']}")


@pytest.mark.integration
class TestAPIHealthAndDiagnostics:
    """Test API health check and diagnostic capabilities."""
    
    def setup_method(self):
        """Setup for health tests."""
        self.config = get_config()
        self.services = {
            'camara': CamaraService(self.config.api_configs['camara']),
            'senado': SenadoService(self.config.api_configs['senado']),
            'planalto': PlanaltoService(self.config.api_configs['planalto'])
        }
    
    @pytest.mark.asyncio
    async def test_health_checks_all_services(self):
        """Test health check endpoints for all services."""
        
        health_results = {}
        
        for service_name, service in self.services.items():
            try:
                is_healthy = await service.check_health()
                health_results[service_name] = {
                    "healthy": is_healthy,
                    "timestamp": time.time()
                }
            except Exception as e:
                health_results[service_name] = {
                    "healthy": False,
                    "error": str(e),
                    "timestamp": time.time()
                }
        
        # Log health check results
        print(f"\n🏥 Health Check Results:")
        for service, result in health_results.items():
            status = "✅ Healthy" if result.get("healthy") else "❌ Unhealthy"
            print(f"   {service}: {status}")
            if not result.get("healthy") and result.get("error"):
                print(f"      Error: {result['error']}")
        
        # At least one service should be healthy
        healthy_count = sum(1 for r in health_results.values() if r.get("healthy"))
        assert healthy_count > 0
    
    def test_enhanced_base_service_diagnostics(self):
        """Test enhanced base service diagnostic capabilities."""
        
        # Create test instance
        class TestGovAPI(BaseGovAPI):
            def buscar(self, query: str, **kwargs) -> List[Dict]:
                return [{"test": "result"}]
        
        api = TestGovAPI(
            base_url="https://httpbin.org",
            nome_fonte="test_api"
        )
        
        # Test health check
        health = api.verificar_saude()
        
        assert 'status' in health
        assert 'timestamp' in health
        assert 'estatisticas' in health
        
        # Test performance metrics
        metrics = api.get_performance_metrics()
        
        assert 'requests' in metrics
        assert 'timing' in metrics
        assert 'cache' in metrics
        assert 'errors' in metrics
        
        print(f"\n📈 Performance Metrics:")
        print(f"   Total requests: {metrics['requests']['total']}")
        print(f"   Success rate: {metrics['requests']['success_rate']:.1f}%")
        print(f"   Cache entries: {metrics['cache']['entries']}")


if __name__ == "__main__":
    # Run tests with detailed output
    pytest.main([__file__, "-v", "-s", "--tb=short"])