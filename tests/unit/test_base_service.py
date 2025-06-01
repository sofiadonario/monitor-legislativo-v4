"""Unit tests for base API service functionality."""

import pytest
from unittest.mock import Mock, patch, AsyncMock
import asyncio
from datetime import datetime

from core.api.base_service import BaseAPIService
from core.utils.circuit_breaker import CircuitBreaker


class TestBaseAPIService:
    """Test suite for BaseAPIService class."""

    @pytest.fixture
    def base_service(self):
        """Create a base service instance for testing."""
        return BaseAPIService()

    @pytest.fixture
    def mock_session(self):
        """Create a mock HTTP session."""
        session = Mock()
        session.get = AsyncMock()
        return session

    def test_init_creates_circuit_breaker(self, base_service):
        """Test that initialization creates a circuit breaker."""
        assert hasattr(base_service, 'circuit_breaker')
        assert isinstance(base_service.circuit_breaker, CircuitBreaker)

    @pytest.mark.asyncio
    async def test_make_request_success(self, base_service, mock_session):
        """Test successful API request."""
        mock_response = Mock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={'data': 'test'})
        mock_session.get.return_value.__aenter__.return_value = mock_response

        with patch.object(base_service, 'session', mock_session):
            result = await base_service._make_request('http://test.com')

        assert result == {'data': 'test'}
        mock_session.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_make_request_handles_404(self, base_service, mock_session):
        """Test handling of 404 responses."""
        mock_response = Mock()
        mock_response.status = 404
        mock_session.get.return_value.__aenter__.return_value = mock_response

        with patch.object(base_service, 'session', mock_session):
            result = await base_service._make_request('http://test.com')

        assert result is None

    @pytest.mark.asyncio
    async def test_make_request_handles_server_error(self, base_service, mock_session):
        """Test handling of server errors."""
        mock_response = Mock()
        mock_response.status = 500
        mock_session.get.return_value.__aenter__.return_value = mock_response

        with patch.object(base_service, 'session', mock_session):
            with pytest.raises(Exception):
                await base_service._make_request('http://test.com')

    def test_validate_date_range_valid(self, base_service):
        """Test date range validation with valid dates."""
        start_date = '2024-01-01'
        end_date = '2024-12-31'
        
        result = base_service._validate_date_range(start_date, end_date)
        
        assert result is True

    def test_validate_date_range_invalid_format(self, base_service):
        """Test date range validation with invalid format."""
        start_date = '01/01/2024'
        end_date = '2024-12-31'
        
        with pytest.raises(ValueError):
            base_service._validate_date_range(start_date, end_date)

    def test_validate_date_range_end_before_start(self, base_service):
        """Test date range validation when end date is before start date."""
        start_date = '2024-12-31'
        end_date = '2024-01-01'
        
        with pytest.raises(ValueError):
            base_service._validate_date_range(start_date, end_date)

    def test_format_search_params_basic(self, base_service):
        """Test basic search parameter formatting."""
        params = {'termo': 'test', 'data_inicio': '2024-01-01'}
        
        result = base_service._format_search_params(params)
        
        assert 'termo' in result
        assert 'data_inicio' in result
        assert result['termo'] == 'test'

    def test_format_search_params_removes_none_values(self, base_service):
        """Test that None values are removed from parameters."""
        params = {'termo': 'test', 'data_fim': None, 'tipo': ''}
        
        result = base_service._format_search_params(params)
        
        assert 'termo' in result
        assert 'data_fim' not in result
        assert 'tipo' not in result

    @pytest.mark.asyncio
    async def test_circuit_breaker_integration(self, base_service, mock_session):
        """Test circuit breaker integration with failed requests."""
        mock_response = Mock()
        mock_response.status = 500
        mock_session.get.return_value.__aenter__.return_value = mock_response

        with patch.object(base_service, 'session', mock_session):
            # First failure
            with pytest.raises(Exception):
                await base_service._make_request('http://test.com')
            
            # Circuit breaker should track failures
            assert base_service.circuit_breaker.failure_count > 0

    def test_build_url_with_params(self, base_service):
        """Test URL building with parameters."""
        base_url = 'http://api.test.com'
        params = {'q': 'search term', 'page': 1}
        
        with patch('urllib.parse.urlencode') as mock_urlencode:
            mock_urlencode.return_value = 'q=search+term&page=1'
            result = base_service._build_url(base_url, params)
        
        assert result == 'http://api.test.com?q=search+term&page=1'

    def test_build_url_no_params(self, base_service):
        """Test URL building without parameters."""
        base_url = 'http://api.test.com'
        
        result = base_service._build_url(base_url)
        
        assert result == base_url

    @pytest.mark.asyncio
    async def test_retry_mechanism(self, base_service, mock_session):
        """Test retry mechanism for transient failures."""
        # First call fails, second succeeds
        mock_response_fail = Mock()
        mock_response_fail.status = 503
        
        mock_response_success = Mock()
        mock_response_success.status = 200
        mock_response_success.json = AsyncMock(return_value={'data': 'success'})
        
        mock_session.get.return_value.__aenter__.side_effect = [
            mock_response_fail,
            mock_response_success
        ]

        with patch.object(base_service, 'session', mock_session):
            with patch.object(base_service, '_should_retry', return_value=True):
                result = await base_service._make_request_with_retry('http://test.com')

        assert result == {'data': 'success'}
        assert mock_session.get.call_count == 2

    def test_sanitize_input_basic(self, base_service):
        """Test basic input sanitization."""
        dangerous_input = "<script>alert('xss')</script>"
        
        result = base_service._sanitize_input(dangerous_input)
        
        assert '<script>' not in result
        assert 'alert' not in result

    def test_sanitize_input_sql_injection(self, base_service):
        """Test SQL injection prevention."""
        sql_input = "'; DROP TABLE users; --"
        
        result = base_service._sanitize_input(sql_input)
        
        assert 'DROP TABLE' not in result
        assert '--' not in result

    def test_rate_limit_check(self, base_service):
        """Test rate limiting functionality."""
        with patch.object(base_service, '_check_rate_limit') as mock_check:
            mock_check.return_value = True
            
            result = base_service._check_rate_limit()
            
            assert result is True
            mock_check.assert_called_once()

    @pytest.mark.asyncio
    async def test_health_check(self, base_service, mock_session):
        """Test service health check."""
        mock_response = Mock()
        mock_response.status = 200
        mock_session.get.return_value.__aenter__.return_value = mock_response

        with patch.object(base_service, 'session', mock_session):
            result = await base_service.health_check()

        assert result is True

    @pytest.mark.asyncio
    async def test_health_check_failure(self, base_service, mock_session):
        """Test service health check failure."""
        mock_session.get.side_effect = Exception("Connection failed")

        with patch.object(base_service, 'session', mock_session):
            result = await base_service.health_check()

        assert result is False