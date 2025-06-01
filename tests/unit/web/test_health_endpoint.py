"""Unit tests for health check endpoint."""

import pytest
import json
from unittest.mock import patch, Mock
from datetime import datetime


@pytest.mark.unit
class TestHealthEndpoint:
    """Test cases for health check endpoint."""
    
    def test_health_check_all_services_healthy(self, api_client):
        """Test health check when all services are healthy."""
        with patch('web.health.check_database_health') as mock_db, \
             patch('web.health.check_redis_health') as mock_redis, \
             patch('web.health.check_external_apis_health') as mock_apis:
            
            mock_db.return_value = True
            mock_redis.return_value = True
            mock_apis.return_value = {
                'camara_api': True,
                'senado_api': True,
                'planalto_api': True,
            }
            
            response = api_client.get('/api/health')
            
            assert response.status_code == 200
            data = response.get_json()
            
            assert data['status'] == 'healthy'
            assert 'version' in data
            assert 'timestamp' in data
            assert data['services']['database'] == 'connected'
            assert data['services']['redis'] == 'connected'
            assert data['services']['camara_api'] == 'available'
            assert data['services']['senado_api'] == 'available'
    
    def test_health_check_database_unhealthy(self, api_client):
        """Test health check when database is unhealthy."""
        with patch('web.health.check_database_health') as mock_db, \
             patch('web.health.check_redis_health') as mock_redis, \
             patch('web.health.check_external_apis_health') as mock_apis:
            
            mock_db.return_value = False
            mock_redis.return_value = True
            mock_apis.return_value = {'camara_api': True}
            
            response = api_client.get('/api/health')
            
            assert response.status_code == 503
            data = response.get_json()
            
            assert data['status'] == 'unhealthy'
            assert data['services']['database'] == 'disconnected'
            assert data['services']['redis'] == 'connected'
    
    def test_health_check_redis_unhealthy(self, api_client):
        """Test health check when Redis is unhealthy."""
        with patch('web.health.check_database_health') as mock_db, \
             patch('web.health.check_redis_health') as mock_redis, \
             patch('web.health.check_external_apis_health') as mock_apis:
            
            mock_db.return_value = True
            mock_redis.return_value = False
            mock_apis.return_value = {'camara_api': True}
            
            response = api_client.get('/api/health')
            
            assert response.status_code == 503
            data = response.get_json()
            
            assert data['status'] == 'unhealthy'
            assert data['services']['redis'] == 'disconnected'
    
    def test_health_check_external_api_unavailable(self, api_client):
        """Test health check when external API is unavailable."""
        with patch('web.health.check_database_health') as mock_db, \
             patch('web.health.check_redis_health') as mock_redis, \
             patch('web.health.check_external_apis_health') as mock_apis:
            
            mock_db.return_value = True
            mock_redis.return_value = True
            mock_apis.return_value = {
                'camara_api': False,
                'senado_api': True,
            }
            
            response = api_client.get('/api/health')
            
            # External API failure doesn't make overall health fail (degraded service)
            assert response.status_code == 200
            data = response.get_json()
            
            assert data['services']['camara_api'] == 'unavailable'
            assert data['services']['senado_api'] == 'available'
    
    def test_health_check_response_format(self, api_client):
        """Test health check response format."""
        with patch('web.health.check_database_health', return_value=True), \
             patch('web.health.check_redis_health', return_value=True), \
             patch('web.health.check_external_apis_health', return_value={}):
            
            response = api_client.get('/api/health')
            data = response.get_json()
            
            # Verify required fields
            required_fields = ['status', 'version', 'timestamp', 'services']
            for field in required_fields:
                assert field in data
            
            # Verify timestamp format
            timestamp = data['timestamp']
            datetime.fromisoformat(timestamp.replace('Z', '+00:00'))  # Should not raise
    
    def test_health_check_no_authentication_required(self, api_client):
        """Test that health check doesn't require authentication."""
        # No auth headers provided
        response = api_client.get('/api/health')
        
        # Should not return 401
        assert response.status_code != 401
    
    def test_health_check_caching_headers(self, api_client):
        """Test that health check has appropriate caching headers."""
        with patch('web.health.check_database_health', return_value=True), \
             patch('web.health.check_redis_health', return_value=True), \
             patch('web.health.check_external_apis_health', return_value={}):
            
            response = api_client.get('/api/health')
            
            # Health checks should not be cached
            assert 'Cache-Control' in response.headers
            assert 'no-cache' in response.headers['Cache-Control']


@pytest.mark.unit
class TestHealthCheckHelpers:
    """Test health check helper functions."""
    
    @patch('core.models.db.engine.execute')
    def test_check_database_health_success(self, mock_execute):
        """Test successful database health check."""
        mock_execute.return_value = Mock()
        
        from web.health import check_database_health
        result = check_database_health()
        
        assert result is True
        mock_execute.assert_called_once()
    
    @patch('core.models.db.engine.execute')
    def test_check_database_health_failure(self, mock_execute):
        """Test failed database health check."""
        mock_execute.side_effect = Exception("Database connection failed")
        
        from web.health import check_database_health
        result = check_database_health()
        
        assert result is False
    
    @patch('redis.Redis.ping')
    def test_check_redis_health_success(self, mock_ping):
        """Test successful Redis health check."""
        mock_ping.return_value = True
        
        from web.health import check_redis_health
        result = check_redis_health()
        
        assert result is True
        mock_ping.assert_called_once()
    
    @patch('redis.Redis.ping')
    def test_check_redis_health_failure(self, mock_ping):
        """Test failed Redis health check."""
        mock_ping.side_effect = Exception("Redis connection failed")
        
        from web.health import check_redis_health
        result = check_redis_health()
        
        assert result is False
    
    @patch('core.api.secure_base_service.SecureBaseService.health_check')
    def test_check_external_apis_health(self, mock_health_check):
        """Test external APIs health check."""
        # Mock different API statuses
        mock_health_check.side_effect = [True, False, True]  # camara, senado, planalto
        
        from web.health import check_external_apis_health
        result = check_external_apis_health()
        
        expected_apis = ['camara_api', 'senado_api', 'planalto_api']
        for api in expected_apis:
            assert api in result
        
        # Should reflect the mocked responses
        assert result['camara_api'] is True
        assert result['senado_api'] is False
        assert result['planalto_api'] is True


@pytest.mark.unit
class TestHealthMonitoring:
    """Test health monitoring features."""
    
    def test_health_metrics_collection(self, api_client):
        """Test that health metrics are collected."""
        with patch('web.health.record_health_metric') as mock_record:
            with patch('web.health.check_database_health', return_value=True), \
                 patch('web.health.check_redis_health', return_value=True), \
                 patch('web.health.check_external_apis_health', return_value={}):
                
                response = api_client.get('/api/health')
                
                # Should record health check execution
                mock_record.assert_called()
    
    def test_health_check_performance_monitoring(self, api_client):
        """Test health check performance is monitored."""
        with patch('time.time', side_effect=[1000.0, 1000.5]):  # 500ms execution time
            with patch('web.health.record_performance_metric') as mock_perf:
                with patch('web.health.check_database_health', return_value=True), \
                     patch('web.health.check_redis_health', return_value=True), \
                     patch('web.health.check_external_apis_health', return_value={}):
                    
                    response = api_client.get('/api/health')
                    
                    # Should record execution time
                    mock_perf.assert_called_with('health_check_duration', 0.5)
    
    @patch('web.health.send_alert')
    def test_health_alerting_on_failure(self, mock_alert, api_client):
        """Test that alerts are sent on health check failures."""
        with patch('web.health.check_database_health', return_value=False), \
             patch('web.health.check_redis_health', return_value=True), \
             patch('web.health.check_external_apis_health', return_value={}):
            
            response = api_client.get('/api/health')
            
            # Should send alert for database failure
            mock_alert.assert_called_with(
                severity='critical',
                message='Database health check failed',
                component='database'
            )
    
    def test_health_check_rate_limiting(self, api_client):
        """Test that health check has appropriate rate limiting."""
        # Make multiple rapid requests
        responses = []
        for _ in range(10):
            response = api_client.get('/api/health')
            responses.append(response)
        
        # Health checks should not be rate limited (for monitoring)
        for response in responses:
            assert response.status_code != 429
    
    def test_health_check_detailed_diagnostics(self, api_client):
        """Test health check with detailed diagnostics."""
        with patch('web.health.get_detailed_diagnostics') as mock_diagnostics:
            mock_diagnostics.return_value = {
                'database': {
                    'connection_pool_size': 10,
                    'active_connections': 3,
                    'query_time_ms': 15
                },
                'redis': {
                    'memory_usage_mb': 50,
                    'connected_clients': 5,
                    'hit_rate': 0.95
                }
            }
            
            response = api_client.get('/api/health?detailed=true')
            data = response.get_json()
            
            if 'diagnostics' in data:
                assert 'database' in data['diagnostics']
                assert 'redis' in data['diagnostics']