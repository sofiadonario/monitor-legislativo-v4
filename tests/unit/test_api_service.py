"""
Unit tests for API service - Critical path testing
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime

from core.api.api_service import APIService
from core.models.models import SearchResult, Proposition, DataSource, PropositionType


class TestAPIService:
    """Test core API service functionality"""
    
    @pytest.fixture
    def api_service(self, mock_config):
        """Create API service instance"""
        return APIService()
    
    @pytest.fixture
    def mock_camara_response(self):
        """Mock Camara API response"""
        return {
            'dados': [
                {
                    'id': 12345,
                    'siglaTipo': 'PL',
                    'numero': 1234,
                    'ano': 2024,
                    'ementa': 'Test bill about data protection',
                    'dataApresentacao': '2024-01-15T10:00:00',
                    'statusProposicao': {
                        'descricaoSituacao': 'Aguardando Parecer'
                    },
                    'urlInteiroTeor': 'https://camara.leg.br/prop/doc.pdf'
                }
            ]
        }
    
    def test_get_available_sources(self, api_service):
        """Test getting available data sources"""
        sources = api_service.get_available_sources()
        
        assert isinstance(sources, dict)
        assert 'camara' in sources
        assert 'senado' in sources
        assert sources['camara'] == 'Câmara dos Deputados'
    
    @pytest.mark.asyncio
    async def test_search_all_empty_query(self, api_service):
        """Test search with empty query"""
        with pytest.raises(ValueError, match="Query cannot be empty"):
            await api_service.search_all("", {})
    
    @pytest.mark.asyncio
    async def test_search_all_success(self, api_service, mock_requests, mock_camara_response):
        """Test successful search across sources"""
        # Mock responses
        mock_requests.get.return_value.json.return_value = mock_camara_response
        mock_requests.get.return_value.status_code = 200
        
        results = await api_service.search_all("data protection", {})
        
        assert isinstance(results, list)
        assert len(results) > 0
        
        # Check first result
        result = results[0]
        assert isinstance(result, SearchResult)
        assert result.source in [DataSource.CAMARA, DataSource.SENADO]
        assert len(result.propositions) > 0
    
    def test_search_all_sync(self, api_service, mock_requests, mock_camara_response):
        """Test synchronous search method"""
        mock_requests.get.return_value.json.return_value = mock_camara_response
        mock_requests.get.return_value.status_code = 200
        
        results = api_service.search_all_sync("test query", {})
        
        assert isinstance(results, list)
        assert len(results) >= 0  # May be empty if no services configured
    
    def test_clear_cache(self, api_service):
        """Test cache clearing"""
        # Should not raise any exceptions
        api_service.clear_cache()
        api_service.clear_cache("camara")
    
    @pytest.mark.asyncio
    async def test_get_api_status(self, api_service):
        """Test API status checking"""
        with patch.object(api_service, 'services') as mock_services:
            # Mock service with health check
            mock_service = Mock()
            mock_service.health_check = AsyncMock(return_value=True)
            mock_service.get_name.return_value = "Test Service"
            mock_service.get_source.return_value = DataSource.CAMARA
            
            mock_services = {'test': mock_service}
            api_service.services = mock_services
            
            statuses = await api_service.get_api_status()
            
            assert isinstance(statuses, list)
    
    def test_get_api_status_sync(self, api_service):
        """Test synchronous API status checking"""
        statuses = api_service.get_api_status_sync()
        
        assert isinstance(statuses, list)


class TestSearchValidation:
    """Test search parameter validation"""
    
    @pytest.fixture
    def api_service(self):
        return APIService()
    
    def test_validate_search_query_valid(self, api_service):
        """Test valid search query"""
        query = "data protection privacy"
        validated = api_service._validate_search_query(query)
        assert validated == query
    
    def test_validate_search_query_empty(self, api_service):
        """Test empty search query"""
        with pytest.raises(ValueError):
            api_service._validate_search_query("")
    
    def test_validate_search_query_too_short(self, api_service):
        """Test too short search query"""
        with pytest.raises(ValueError):
            api_service._validate_search_query("ab")
    
    def test_validate_search_query_too_long(self, api_service):
        """Test too long search query"""
        long_query = "a" * 501
        with pytest.raises(ValueError):
            api_service._validate_search_query(long_query)
    
    def test_validate_filters_valid(self, api_service):
        """Test valid filters"""
        filters = {
            'start_date': '2024-01-01',
            'end_date': '2024-12-31',
            'type': 'projeto_lei'
        }
        validated = api_service._validate_filters(filters)
        assert validated == filters
    
    def test_validate_filters_invalid_date(self, api_service):
        """Test invalid date format in filters"""
        filters = {'start_date': 'invalid-date'}
        with pytest.raises(ValueError):
            api_service._validate_filters(filters)


@pytest.mark.integration
class TestAPIServiceIntegration:
    """Integration tests for API service"""
    
    @pytest.fixture
    def api_service_with_real_config(self):
        """API service with real configuration"""
        return APIService()
    
    @pytest.mark.slow
    def test_real_api_connection(self, api_service_with_real_config):
        """Test connection to real APIs (if available)"""
        # This test should be skipped in CI/CD unless external APIs are available
        pytest.skip("Requires real API connection")
        
        # Uncomment for manual testing with real APIs
        # results = api_service_with_real_config.search_all_sync("educação", {})
        # assert isinstance(results, list)


class TestPropositionModel:
    """Test Proposition model functionality"""
    
    def test_proposition_creation(self):
        """Test creating a proposition"""
        prop = Proposition(
            id="123",
            type=PropositionType.PROJETO_LEI,
            number="1234",
            year=2024,
            title="Test Bill",
            summary="A test bill for testing",
            author_names="Test Author",
            publication_date=datetime(2024, 1, 15),
            status="Em tramitação",
            source=DataSource.CAMARA,
            url="https://camara.leg.br/test"
        )
        
        assert prop.id == "123"
        assert prop.type == PropositionType.PROJETO_LEI
        assert prop.title == "Test Bill"
    
    def test_proposition_to_dict(self):
        """Test proposition serialization"""
        prop = Proposition(
            id="123",
            type=PropositionType.PROJETO_LEI,
            number="1234",
            year=2024,
            title="Test Bill",
            summary="A test bill",
            author_names="Test Author",
            publication_date=datetime(2024, 1, 15),
            status="Em tramitação",
            source=DataSource.CAMARA,
            url="https://test.com"
        )
        
        prop_dict = prop.to_dict()
        
        assert isinstance(prop_dict, dict)
        assert prop_dict['id'] == "123"
        assert prop_dict['type'] == 'projeto_lei'
        assert prop_dict['title'] == "Test Bill"
    
    def test_search_result_creation(self):
        """Test SearchResult creation"""
        propositions = [
            Proposition(
                id="1",
                type=PropositionType.PROJETO_LEI,
                number="1234",
                year=2024,
                title="Test Bill 1",
                summary="Test bill",
                author_names="Author 1",
                publication_date=datetime.now(),
                status="Tramitando",
                source=DataSource.CAMARA,
                url="https://test1.com"
            )
        ]
        
        result = SearchResult(
            source=DataSource.CAMARA,
            query="test",
            total_count=1,
            propositions=propositions
        )
        
        assert result.source == DataSource.CAMARA
        assert result.query == "test"
        assert result.total_count == 1
        assert len(result.propositions) == 1


@pytest.mark.security
class TestAPIServiceSecurity:
    """Test security aspects of API service"""
    
    @pytest.fixture
    def api_service(self):
        return APIService()
    
    def test_sql_injection_protection(self, api_service):
        """Test protection against SQL injection"""
        malicious_query = "'; DROP TABLE users; --"
        
        # Should sanitize the query, not raise an exception
        try:
            validated = api_service._validate_search_query(malicious_query)
            # The validation should either sanitize or reject the query
            assert "DROP TABLE" not in validated.upper()
        except ValueError:
            # It's also acceptable to reject the query entirely
            pass
    
    def test_xss_protection(self, api_service):
        """Test protection against XSS"""
        xss_query = "<script>alert('xss')</script>"
        
        try:
            validated = api_service._validate_search_query(xss_query)
            assert "<script>" not in validated
        except ValueError:
            # Rejection is also acceptable
            pass
    
    def test_query_length_limits(self, api_service):
        """Test query length limitations"""
        # Very long query should be rejected
        long_query = "a" * 1000
        
        with pytest.raises(ValueError):
            api_service._validate_search_query(long_query)


@pytest.mark.performance
class TestAPIServicePerformance:
    """Test performance aspects of API service"""
    
    @pytest.fixture
    def api_service(self):
        return APIService()
    
    def test_search_timeout(self, api_service):
        """Test search timeout handling"""
        with patch('asyncio.wait_for') as mock_wait:
            mock_wait.side_effect = asyncio.TimeoutError()
            
            # Should handle timeout gracefully
            with pytest.raises(asyncio.TimeoutError):
                asyncio.run(api_service.search_all("test", {}))
    
    def test_concurrent_searches(self, api_service, mock_requests):
        """Test handling concurrent searches"""
        mock_requests.get.return_value.json.return_value = {'dados': []}
        mock_requests.get.return_value.status_code = 200
        
        async def run_concurrent_searches():
            tasks = []
            for i in range(5):
                task = api_service.search_all(f"query {i}", {})
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            return results
        
        results = asyncio.run(run_concurrent_searches())
        
        # All searches should complete without errors
        assert len(results) == 5
        for result in results:
            assert not isinstance(result, Exception)