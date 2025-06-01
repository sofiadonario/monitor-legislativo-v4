"""Unit tests for SecureBaseService."""

import pytest
from unittest.mock import Mock, patch, MagicMock
import requests
from core.api.secure_base_service import SecureBaseService, SecureAPIError


class TestSecureBaseService:
    """Test cases for SecureBaseService."""
    
    @pytest.fixture
    def service(self, mock_config):
        """Create a test service instance."""
        with patch('core.api.secure_base_service.SecureConfig.get_api_config') as mock_get_config:
            mock_get_config.return_value = {
                'test_service': {
                    'base_url': 'https://api.test.gov.br',
                    'api_key': 'test-key',
                    'timeout': 30,
                    'verify_ssl': True,
                    'retry_count': 3,
                    'retry_delay': 1,
                }
            }
            return SecureBaseService('test_service')
    
    def test_init(self, service):
        """Test service initialization."""
        assert service.service_name == 'test_service'
        assert service.config['base_url'] == 'https://api.test.gov.br'
        assert service.session is not None
        assert service.circuit_breaker is not None
    
    def test_create_secure_session(self, service):
        """Test secure session creation."""
        session = service._create_secure_session()
        
        # Check SSL verification is enabled
        assert session.verify is True
        
        # Check headers
        assert 'Authorization' in session.headers
        assert session.headers['Authorization'] == 'Bearer test-key'
        assert session.headers['User-Agent'] == 'Legislative-Monitor/1.0'
        assert session.headers['Accept'] == 'application/json'
    
    def test_validate_url_valid(self, service):
        """Test URL validation with valid URLs."""
        valid_urls = [
            'https://api.camara.leg.br/test',
            'https://api.senado.leg.br/test',
            'https://api.planalto.gov.br/test',
            'https://api.anatel.gov.br/test',
        ]
        
        for url in valid_urls:
            # Should not raise exception
            service._validate_url(url)
    
    def test_validate_url_invalid(self, service):
        """Test URL validation with invalid URLs."""
        invalid_urls = [
            'ftp://api.test.com/test',  # Wrong scheme
            'https://malicious.com/test',  # Not allowed domain
            'javascript:alert(1)',  # XSS attempt
            'file:///etc/passwd',  # Local file access
        ]
        
        for url in invalid_urls:
            with pytest.raises(SecureAPIError):
                service._validate_url(url)
    
    def test_sanitize_params(self, service):
        """Test parameter sanitization."""
        params = {
            'normal': 'value',
            'injection': 'value; DROP TABLE users;',
            'pipe': 'value | cat /etc/passwd',
            'ampersand': 'value & malicious command',
        }
        
        sanitized = service._sanitize_params(params)
        
        assert sanitized['normal'] == 'value'
        assert ';' not in sanitized['injection']
        assert '|' not in sanitized['pipe']
        assert '&' not in sanitized['ampersand']
    
    @patch('requests.Session.request')
    def test_make_request_success(self, mock_request, service):
        """Test successful API request."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True}
        mock_request.return_value = mock_response
        
        response = service.make_request('GET', '/test')
        
        assert response.status_code == 200
        mock_request.assert_called_once()
        call_args = mock_request.call_args
        assert call_args[1]['url'] == 'https://api.test.gov.br/test'
        assert call_args[1]['timeout'] == 30
    
    @patch('requests.Session.request')
    def test_make_request_ssl_error(self, mock_request, service):
        """Test SSL verification error."""
        mock_request.side_effect = requests.exceptions.SSLError("SSL verification failed")
        
        with pytest.raises(SecureAPIError) as exc_info:
            service.make_request('GET', '/test')
        
        assert "SSL verification failed" in str(exc_info.value)
    
    @patch('requests.Session.request')
    def test_make_request_timeout(self, mock_request, service):
        """Test request timeout."""
        mock_request.side_effect = requests.exceptions.Timeout("Request timed out")
        
        with pytest.raises(SecureAPIError) as exc_info:
            service.make_request('GET', '/test')
        
        assert "Request timeout" in str(exc_info.value)
    
    @patch('requests.Session.request')
    def test_get_method(self, mock_request, service):
        """Test GET method."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'data': 'test'}
        mock_request.return_value = mock_response
        
        result = service.get('/endpoint')
        
        assert result == {'data': 'test'}
        mock_request.assert_called_once_with(
            method='GET',
            url='https://api.test.gov.br/endpoint',
            params=None,
            json=None,
            timeout=30
        )
    
    @patch('requests.Session.request')
    def test_post_method(self, mock_request, service):
        """Test POST method."""
        mock_response = Mock()
        mock_response.status_code = 201
        mock_response.json.return_value = {'id': 123}
        mock_request.return_value = mock_response
        
        data = {'name': 'test'}
        result = service.post('/create', data)
        
        assert result == {'id': 123}
        mock_request.assert_called_once_with(
            method='POST',
            url='https://api.test.gov.br/create',
            params=None,
            json=data,
            timeout=30
        )
    
    @patch('requests.Session.request')
    def test_health_check_success(self, mock_request, service):
        """Test successful health check."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response
        
        assert service.health_check() is True
    
    @patch('requests.Session.request')
    def test_health_check_failure(self, mock_request, service):
        """Test failed health check."""
        mock_request.side_effect = Exception("Connection failed")
        
        assert service.health_check() is False
    
    def test_circuit_breaker_integration(self, service):
        """Test circuit breaker integration."""
        # Mock the circuit breaker to be open
        service.circuit_breaker.is_open = True
        
        with patch.object(service.circuit_breaker, 'call') as mock_call:
            mock_call.side_effect = Exception("Circuit breaker is open")
            
            with pytest.raises(Exception) as exc_info:
                service.make_request('GET', '/test')
            
            assert "Circuit breaker is open" in str(exc_info.value)