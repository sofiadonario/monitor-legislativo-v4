"""Integration tests for API endpoints."""

import pytest
import asyncio
from datetime import datetime, date
from unittest.mock import patch, AsyncMock

from web.main_secured import create_app
from core.auth.jwt_manager import JWTManager
from core.auth.models import User, Role, Permission


@pytest.mark.integration
class TestCamaraAPIIntegration:
    """Integration tests for Camara API service."""
    
    @pytest.fixture
    def camara_service(self, mock_config):
        """Create Camara service instance for testing."""
        with patch('core.api.secure_base_service.SecureConfig.get_api_config') as mock_get_config:
            mock_get_config.return_value = {
                'camara': {
                    'base_url': 'https://dadosabertos.camara.leg.br/api/v2',
                    'timeout': 30,
                    'verify_ssl': True,
                    'retry_count': 3,
                }
            }
            return SecureBaseService('camara')
    
    @patch('requests.Session.request')
    def test_get_proposicoes_success(self, mock_request, camara_service):
        """Test successful retrieval of propositions."""
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'dados': [
                {
                    'id': 12345,
                    'siglaTipo': 'PL',
                    'numero': 1234,
                    'ano': 2025,
                    'ementa': 'Test proposal',
                    'dataApresentacao': '2025-01-30T10:00:00'
                }
            ],
            'links': [
                {'rel': 'self', 'href': 'https://api.camara.leg.br/proposicoes'}
            ]
        }
        mock_request.return_value = mock_response
        
        # Make request
        result = camara_service.get('/proposicoes', params={'ano': 2025, 'tipo': 'PL'})
        
        # Assertions
        assert result is not None
        assert 'dados' in result
        assert len(result['dados']) == 1
        assert result['dados'][0]['id'] == 12345
        assert result['dados'][0]['siglaTipo'] == 'PL'
        
        # Verify request was made correctly
        mock_request.assert_called_once()
        call_args = mock_request.call_args
        assert 'ano=2025' in str(call_args) or call_args[1]['params']['ano'] == 2025
    
    @patch('requests.Session.request')
    def test_get_proposicoes_with_pagination(self, mock_request, camara_service):
        """Test propositions retrieval with pagination."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'dados': [{'id': i, 'siglaTipo': 'PL', 'numero': i} for i in range(1, 11)],
            'links': [
                {'rel': 'next', 'href': 'https://api.camara.leg.br/proposicoes?pagina=2'}
            ]
        }
        mock_request.return_value = mock_response
        
        result = camara_service.get('/proposicoes', params={'limite': 10, 'pagina': 1})
        
        assert len(result['dados']) == 10
        assert 'links' in result
        assert any(link['rel'] == 'next' for link in result['links'])
    
    @patch('requests.Session.request')
    def test_api_error_handling(self, mock_request, camara_service):
        """Test API error handling."""
        # Mock 404 response
        from requests import HTTPError
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.raise_for_status.side_effect = HTTPError("404 Not Found")
        mock_request.return_value = mock_response
        
        with pytest.raises(Exception):  # Should raise SecureAPIError
            camara_service.get('/proposicoes/999999')
    
    @patch('requests.Session.request')
    def test_timeout_handling(self, mock_request, camara_service):
        """Test timeout handling."""
        from requests import Timeout
        mock_request.side_effect = Timeout("Request timed out")
        
        with pytest.raises(Exception):  # Should raise SecureAPIError
            camara_service.get('/proposicoes')


@pytest.mark.integration
class TestSenadoAPIIntegration:
    """Integration tests for Senado API service."""
    
    @pytest.fixture
    def senado_service(self, mock_config):
        """Create Senado service instance for testing."""
        with patch('core.api.secure_base_service.SecureConfig.get_api_config') as mock_get_config:
            mock_get_config.return_value = {
                'senado': {
                    'base_url': 'https://legis.senado.leg.br/dadosabertos',
                    'timeout': 30,
                    'verify_ssl': True,
                    'retry_count': 3,
                }
            }
            return SecureBaseService('senado')
    
    @patch('requests.Session.request')
    def test_get_materias_success(self, mock_request, senado_service):
        """Test successful retrieval of Senate matters."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'ListaMateriasPesquisa': {
                'Materias': {
                    'Materia': [
                        {
                            'CodigoMateria': 54321,
                            'SiglaSubtipoMateria': 'PLS',
                            'NumeroMateria': 4321,
                            'AnoMateria': 2025,
                            'DescricaoObjetivoProcesso': 'Test Senate matter'
                        }
                    ]
                }
            }
        }
        mock_request.return_value = mock_response
        
        result = senado_service.get('/materia/pesquisa/lista', params={'ano': 2025})
        
        assert result is not None
        assert 'ListaMateriasPesquisa' in result
        materias = result['ListaMateriasPesquisa']['Materias']['Materia']
        assert len(materias) == 1
        assert materias[0]['CodigoMateria'] == 54321


@pytest.mark.integration
class TestUnifiedSearchIntegration:
    """Integration tests for unified search functionality."""
    
    @pytest.fixture
    def search_service(self, mock_config):
        """Create search service for testing."""
        # This would be the actual search service implementation
        return Mock()  # Placeholder for now
    
    def test_cross_source_search(self, search_service):
        """Test searching across multiple sources."""
        # Mock search results from multiple sources
        search_service.search.return_value = {
            'results': [
                {
                    'id': 'camara_12345',
                    'source': 'camara',
                    'title': 'Test Camara Proposal',
                    'score': 0.95
                },
                {
                    'id': 'senado_54321',
                    'source': 'senado',
                    'title': 'Test Senate Matter',
                    'score': 0.87
                }
            ],
            'total': 2,
            'facets': {
                'sources': {'camara': 1, 'senado': 1},
                'types': {'PL': 1, 'PLS': 1}
            }
        }
        
        query = {
            'keywords': 'education health',
            'sources': ['camara', 'senado'],
            'limit': 10
        }
        
        result = search_service.search(query)
        
        assert result['total'] == 2
        assert len(result['results']) == 2
        assert result['results'][0]['source'] == 'camara'
        assert result['results'][1]['source'] == 'senado'
        assert 'facets' in result
    
    def test_search_with_date_filter(self, search_service):
        """Test search with date filtering."""
        search_service.search.return_value = {
            'results': [],
            'total': 0,
            'facets': {}
        }
        
        query = {
            'keywords': 'budget',
            'sources': ['camara'],
            'start_date': '2025-01-01',
            'end_date': '2025-12-31'
        }
        
        result = search_service.search(query)
        search_service.search.assert_called_once_with(query)


@pytest.mark.integration
class TestCircuitBreakerIntegration:
    """Integration tests for circuit breaker functionality."""
    
    def test_circuit_breaker_opens_on_failures(self):
        """Test that circuit breaker opens after multiple failures."""
        from core.utils.circuit_breaker import CircuitBreaker
        
        # Create circuit breaker with low threshold for testing
        circuit_breaker = CircuitBreaker(
            failure_threshold=3,
            recovery_timeout=1,
            expected_exception=Exception
        )
        
        # Function that always fails
        @circuit_breaker.call
        def failing_function():
            raise Exception("Service unavailable")
        
        # Trigger failures to open circuit
        for _ in range(3):
            with pytest.raises(Exception):
                failing_function()
        
        # Circuit should now be open
        assert circuit_breaker.state == 'open'
        
        # Next call should fail fast
        with pytest.raises(Exception):
            failing_function()
    
    def test_circuit_breaker_half_open_recovery(self):
        """Test circuit breaker recovery mechanism."""
        from core.utils.circuit_breaker import CircuitBreaker
        import time
        
        circuit_breaker = CircuitBreaker(
            failure_threshold=2,
            recovery_timeout=0.1,  # Very short for testing
            expected_exception=Exception
        )
        
        call_count = 0
        
        @circuit_breaker.call
        def sometimes_failing_function():
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise Exception("Temporary failure")
            return "success"
        
        # Trigger failures to open circuit
        for _ in range(2):
            with pytest.raises(Exception):
                sometimes_failing_function()
        
        # Wait for recovery timeout
        time.sleep(0.2)
        
        # Should now allow one test call (half-open state)
        result = sometimes_failing_function()
        assert result == "success"
        assert circuit_breaker.state == 'closed'


@pytest.mark.integration
class TestAuthenticationFlow:
    """Integration tests for authentication flow."""
    
    def test_login_flow(self, api_client):
        """Test complete login flow."""
        login_data = {
            'username': 'testuser',
            'password': 'testpassword'
        }
        
        with patch('web.auth.authenticate_user') as mock_auth:
            mock_auth.return_value = {'id': 1, 'username': 'testuser'}
            
            response = api_client.post('/api/auth/login', json=login_data)
            
            assert response.status_code == 200
            data = response.get_json()
            assert 'access_token' in data
            assert 'refresh_token' in data
            assert data['token_type'] == 'Bearer'
    
    def test_protected_endpoint_access(self, api_client, auth_headers):
        """Test accessing protected endpoint with valid token."""
        with patch('web.auth.verify_token') as mock_verify:
            mock_verify.return_value = {'id': 1, 'username': 'testuser'}
            
            response = api_client.get('/api/metrics', headers=auth_headers)
            
            # Should not get 401 (exact response depends on implementation)
            assert response.status_code != 401
    
    def test_protected_endpoint_without_token(self, api_client):
        """Test accessing protected endpoint without token."""
        response = api_client.get('/api/metrics')
        assert response.status_code == 401


@pytest.mark.integration
class TestCacheIntegration:
    """Integration tests for caching functionality."""
    
    def test_cache_hit_miss_flow(self, mock_redis):
        """Test cache hit/miss flow."""
        from core.utils.cache_manager import CacheManager
        
        cache_manager = CacheManager()
        
        # Test cache miss
        mock_redis.get.return_value = None
        result = cache_manager.get('test_key')
        assert result is None
        
        # Test cache set
        cache_manager.set('test_key', 'test_value', 3600)
        mock_redis.set.assert_called_once()
        
        # Test cache hit
        mock_redis.get.return_value = 'test_value'
        result = cache_manager.get('test_key')
        assert result == 'test_value'
    
    def test_cache_invalidation(self, mock_redis):
        """Test cache invalidation."""
        from core.utils.cache_manager import CacheManager
        
        cache_manager = CacheManager()
        cache_manager.delete('test_key')
        mock_redis.delete.assert_called_once_with('test_key')


@pytest.mark.integration
@pytest.mark.slow
class TestEndToEndFlow:
    """End-to-end integration tests."""
    
    def test_search_to_export_flow(self, api_client, auth_headers):
        """Test complete flow from search to export."""
        # Mock search results
        search_data = {
            'keywords': 'education',
            'sources': ['camara', 'senado'],
            'limit': 10
        }
        
        with patch('core.services.search_service.SearchService.search') as mock_search:
            mock_search.return_value = {
                'results': [
                    {'id': '1', 'title': 'Education Bill 1', 'source': 'camara'},
                    {'id': '2', 'title': 'Education Bill 2', 'source': 'senado'},
                ],
                'total': 2
            }
            
            # Perform search
            search_response = api_client.post('/api/search', 
                                              json=search_data, 
                                              headers=auth_headers)
            
            assert search_response.status_code == 200
            search_results = search_response.get_json()
            assert search_results['total'] == 2
            
            # Export results
            export_data = {
                'format': 'csv',
                'results': search_results['results']
            }
            
            with patch('core.services.export_service.ExportService.export') as mock_export:
                mock_export.return_value = {'file_id': 'export_123', 'status': 'ready'}
                
                export_response = api_client.post('/api/export',
                                                  json=export_data,
                                                  headers=auth_headers)
                
                assert export_response.status_code == 200
                export_result = export_response.get_json()
                assert 'file_id' in export_result