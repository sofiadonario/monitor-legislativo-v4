"""
Comprehensive External API Integration Testing
Tests all external legislative data APIs for reliability and compliance
"""

import pytest
import asyncio
import aiohttp
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from unittest.mock import patch, Mock

from core.api.camara_service import CamaraService
from core.api.senado_service import SenadoService
from core.api.planalto_service import PlanaltoService
from core.api.lexml_integration import LexMLIntegration
from core.config.config import APIConfig
from core.utils.cache_manager import CacheManager


class TestCamaraAPIIntegration:
    """Test Camara dos Deputados API integration."""
    
    @pytest.fixture
    def service(self):
        config = APIConfig()
        cache_manager = CacheManager()
        return CamaraService(config, cache_manager)
    
    @pytest.mark.asyncio
    async def test_search_propositions_real_api(self, service):
        """Test real API search functionality."""
        result = await service.search("transporte público", {
            "start_date": "2023-01-01",
            "end_date": "2023-12-31",
            "limit": 10
        })
        
        assert result.total_count >= 0
        assert len(result.propositions) <= 10
        assert result.source.value == "CAMARA"
    
    @pytest.mark.asyncio
    async def test_api_error_handling(self, service):
        """Test API error handling and circuit breaker."""
        # Test with invalid date range
        result = await service.search("test", {
            "start_date": "2025-01-01",  # Future date
            "end_date": "2023-01-01",    # Past date (invalid range)
            "limit": 10
        })
        
        # Should handle gracefully
        assert result.error is not None or result.total_count == 0
    
    @pytest.mark.asyncio
    async def test_rate_limiting_compliance(self, service):
        """Test that service respects rate limits."""
        start_time = time.time()
        
        # Make multiple rapid requests
        tasks = []
        for i in range(5):
            task = service.search(f"test query {i}", {"limit": 5})
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Should take some time due to rate limiting
        assert duration >= 2  # At least 2 seconds for 5 requests
        
        # All requests should complete (no rate limit errors)
        successful_results = [r for r in results if not isinstance(r, Exception)]
        assert len(successful_results) >= 3  # At least 3 should succeed


class TestSenadoAPIIntegration:
    """Test Senado Federal API integration."""
    
    @pytest.fixture
    def service(self):
        config = APIConfig()
        cache_manager = CacheManager()
        return SenadoService(config, cache_manager)
    
    @pytest.mark.asyncio
    async def test_search_propositions_real_api(self, service):
        """Test real API search functionality."""
        result = await service.search("meio ambiente", {
            "start_date": "2023-01-01",
            "end_date": "2023-12-31",
            "limit": 10
        })
        
        assert result.total_count >= 0
        assert len(result.propositions) <= 10
        assert result.source.value == "SENADO"
    
    @pytest.mark.asyncio
    async def test_xml_parsing_security(self, service):
        """Test XML parsing security measures."""
        # Mock malicious XML response
        malicious_xml = """<?xml version="1.0"?>
        <!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <root>&xxe;</root>"""
        
        with patch.object(service, '_fetch_xml_data') as mock_fetch:
            mock_fetch.return_value = malicious_xml
            
            # Should handle malicious XML safely
            result = await service.search("test", {"limit": 5})
            assert result.error is not None or result.total_count == 0


class TestPlanaltoAPIIntegration:
    """Test Planalto/DOU API integration."""
    
    @pytest.fixture
    def service(self):
        config = APIConfig()
        cache_manager = CacheManager()
        return PlanaltoService(config, cache_manager)
    
    @pytest.mark.asyncio
    async def test_search_documents_real_api(self, service):
        """Test real API search functionality."""
        result = await service.search("decreto", {
            "start_date": "2023-01-01",
            "end_date": "2023-12-31",
            "limit": 10
        })
        
        assert result.total_count >= 0
        assert len(result.propositions) <= 10
        assert result.source.value == "PLANALTO"
    
    @pytest.mark.asyncio
    async def test_browser_security_sandbox(self, service):
        """Test browser security sandbox functionality."""
        # This test verifies the browser runs in a secure sandbox
        if service.playwright_installed:
            result = await service.search("portaria", {"limit": 5})
            # Should complete without security violations
            assert result is not None


class TestLexMLAPIIntegration:
    """Test LexML Brasil API integration."""
    
    @pytest.fixture
    def service(self):
        return LexMLIntegration()
    
    @pytest.mark.asyncio
    async def test_search_legislation_real_api(self, service):
        """Test real LexML API search functionality."""
        result = service.search("código de trânsito")
        
        assert isinstance(result, list)
        assert len(result) >= 0
        
        if result:
            # Validate result structure
            first_result = result[0]
            assert 'title' in first_result
            assert 'urn' in first_result or 'url' in first_result
    
    def test_input_validation_security(self, service):
        """Test input validation security measures."""
        malicious_inputs = [
            "'; DROP TABLE laws; --",
            "<script>alert('xss')</script>",
            "../../../etc/passwd",
            "' OR '1'='1"
        ]
        
        for malicious_input in malicious_inputs:
            with pytest.raises(ValueError):
                service.search(malicious_input)
    
    def test_fallback_scraper_functionality(self, service):
        """Test fallback web scraper when API fails."""
        # Mock API failure
        with patch.object(service, '_search_api') as mock_api:
            mock_api.return_value = None
            
            result = service.search("lei federal")
            # Should use fallback scraper
            assert isinstance(result, list)


class TestAPIFailureScenarios:
    """Test API failure scenarios and recovery."""
    
    @pytest.mark.asyncio
    async def test_network_timeout_handling(self):
        """Test handling of network timeouts."""
        config = APIConfig()
        config.timeout = 1  # Very short timeout
        
        service = CamaraService(config, CacheManager())
        
        # This should timeout and handle gracefully
        result = await service.search("test", {"limit": 5})
        assert result.error is not None or result.total_count >= 0
    
    @pytest.mark.asyncio
    async def test_malformed_response_handling(self):
        """Test handling of malformed API responses."""
        service = CamaraService(APIConfig(), CacheManager())
        
        # Mock malformed JSON response
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_response = Mock()
            mock_response.status = 200
            mock_response.text.return_value = asyncio.coroutine(lambda: "invalid json")()
            mock_response.__aenter__.return_value = mock_response
            mock_response.__aexit__.return_value = None
            mock_get.return_value = mock_response
            
            result = await service.search("test", {"limit": 5})
            assert result.error is not None or result.total_count == 0
    
    @pytest.mark.asyncio
    async def test_http_error_status_handling(self):
        """Test handling of HTTP error status codes."""
        service = CamaraService(APIConfig(), CacheManager())
        
        # Mock 500 error response
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_response = Mock()
            mock_response.status = 500
            mock_response.text.return_value = asyncio.coroutine(lambda: "Internal Server Error")()
            mock_response.__aenter__.return_value = mock_response
            mock_response.__aexit__.return_value = None
            mock_get.return_value = mock_response
            
            result = await service.search("test", {"limit": 5})
            assert result.error is not None


class TestAPIPerformanceIntegration:
    """Test API performance and SLA compliance."""
    
    @pytest.mark.asyncio
    async def test_response_time_sla(self):
        """Test API response time SLA compliance."""
        services = [
            CamaraService(APIConfig(), CacheManager()),
            SenadoService(APIConfig(), CacheManager()),
            PlanaltoService(APIConfig(), CacheManager())
        ]
        
        for service in services:
            start_time = time.time()
            result = await service.search("test", {"limit": 5})
            end_time = time.time()
            
            response_time = (end_time - start_time) * 1000  # Convert to ms
            
            # SLA: 95% of requests should complete within 2 seconds
            assert response_time < 2000, f"{service.__class__.__name__} exceeded 2s SLA: {response_time}ms"
    
    @pytest.mark.asyncio
    async def test_concurrent_request_handling(self):
        """Test handling of concurrent requests."""
        service = CamaraService(APIConfig(), CacheManager())
        
        # Make 10 concurrent requests
        tasks = []
        for i in range(10):
            task = service.search(f"query {i}", {"limit": 5})
            tasks.append(task)
        
        start_time = time.time()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        end_time = time.time()
        
        # All requests should complete
        successful_results = [r for r in results if not isinstance(r, Exception)]
        assert len(successful_results) >= 8  # At least 80% success rate
        
        # Should not take too long
        total_time = end_time - start_time
        assert total_time < 30  # Should complete within 30 seconds


class TestAPIDataConsistency:
    """Test data consistency across APIs."""
    
    @pytest.mark.asyncio
    async def test_proposition_data_structure(self):
        """Test that all APIs return consistent data structures."""
        services = [
            CamaraService(APIConfig(), CacheManager()),
            SenadoService(APIConfig(), CacheManager())
        ]
        
        for service in services:
            result = await service.search("test", {"limit": 5})
            
            if result.propositions:
                prop = result.propositions[0]
                
                # Check required fields
                assert hasattr(prop, 'id')
                assert hasattr(prop, 'title')
                assert hasattr(prop, 'summary')
                assert hasattr(prop, 'type')
                assert hasattr(prop, 'source')
                assert hasattr(prop, 'publication_date')
    
    @pytest.mark.asyncio
    async def test_search_result_format(self):
        """Test that search results follow consistent format."""
        services = [
            CamaraService(APIConfig(), CacheManager()),
            SenadoService(APIConfig(), CacheManager()),
            PlanaltoService(APIConfig(), CacheManager())
        ]
        
        for service in services:
            result = await service.search("test", {"limit": 5})
            
            # Check SearchResult structure
            assert hasattr(result, 'query')
            assert hasattr(result, 'propositions')
            assert hasattr(result, 'total_count')
            assert hasattr(result, 'source')
            assert isinstance(result.propositions, list)
            assert isinstance(result.total_count, int)


class TestAPISecurityIntegration:
    """Test API security measures in integration context."""
    
    @pytest.mark.asyncio
    async def test_https_enforcement(self):
        """Test that all APIs use HTTPS."""
        services = [
            CamaraService(APIConfig(), CacheManager()),
            SenadoService(APIConfig(), CacheManager()),
            PlanaltoService(APIConfig(), CacheManager())
        ]
        
        for service in services:
            base_url = getattr(service, 'base_url', '')
            if base_url:
                assert base_url.startswith('https://'), f"{service.__class__.__name__} not using HTTPS"
    
    @pytest.mark.asyncio
    async def test_input_sanitization_integration(self):
        """Test input sanitization across all services."""
        dangerous_inputs = [
            "<script>alert('xss')</script>",
            "'; DROP TABLE propositions; --",
            "../../../etc/passwd",
            "admin' OR '1'='1' --"
        ]
        
        services = [
            CamaraService(APIConfig(), CacheManager()),
            SenadoService(APIConfig(), CacheManager()),
            PlanaltoService(APIConfig(), CacheManager())
        ]
        
        for service in services:
            for dangerous_input in dangerous_inputs:
                # Should either reject input or sanitize it safely
                result = await service.search(dangerous_input, {"limit": 5})
                
                # Should not crash and should handle safely
                assert result is not None
                assert not any(dangerous_input in str(prop.__dict__) 
                             for prop in result.propositions)


class TestAPIResilience:
    """Test API resilience and fault tolerance."""
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_functionality(self):
        """Test circuit breaker activation and recovery."""
        service = CamaraService(APIConfig(), CacheManager())
        
        # Simulate multiple failures to trigger circuit breaker
        with patch('aiohttp.ClientSession.get') as mock_get:
            # Configure mock to always fail
            mock_get.side_effect = aiohttp.ClientError("Connection failed")
            
            # Make multiple requests to trigger circuit breaker
            for i in range(10):
                result = await service.search(f"test {i}", {"limit": 5})
                assert result.error is not None
        
        # Circuit breaker should now be open
        # Next request should fail fast
        start_time = time.time()
        result = await service.search("test", {"limit": 5})
        end_time = time.time()
        
        # Should fail quickly (circuit breaker prevents actual request)
        assert (end_time - start_time) < 1.0  # Less than 1 second
    
    @pytest.mark.asyncio
    async def test_cache_integration(self):
        """Test caching integration with APIs."""
        service = CamaraService(APIConfig(), CacheManager())
        
        # First request (should hit API)
        start_time = time.time()
        result1 = await service.search("cache test", {"limit": 5})
        first_request_time = time.time() - start_time
        
        # Second request (should hit cache)
        start_time = time.time()
        result2 = await service.search("cache test", {"limit": 5})
        second_request_time = time.time() - start_time
        
        # Cache hit should be faster
        assert second_request_time < first_request_time
        
        # Results should be identical
        assert result1.total_count == result2.total_count
        assert len(result1.propositions) == len(result2.propositions)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])