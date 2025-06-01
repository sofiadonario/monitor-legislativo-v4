"""Unit tests for SecureConfig."""

import pytest
import os
from unittest.mock import patch
from core.config.secure_config import SecureConfig, ConfigurationError


class TestSecureConfig:
    """Test cases for SecureConfig."""
    
    @patch.dict(os.environ, {
        'APP_SECRET_KEY': 'test-secret',
        'DATABASE_URL': 'postgresql://test',
        'JWT_SECRET_KEY': 'jwt-secret'
    })
    def test_init_with_required_configs(self):
        """Test initialization with all required configs present."""
        config = SecureConfig()
        assert config is not None
    
    @patch.dict(os.environ, {
        'DATABASE_URL': 'postgresql://test',
        'JWT_SECRET_KEY': 'jwt-secret'
    })
    def test_init_missing_required_config(self):
        """Test initialization with missing required config."""
        with pytest.raises(ConfigurationError) as exc_info:
            SecureConfig()
        assert "APP_SECRET_KEY" in str(exc_info.value)
    
    @patch.dict(os.environ, {'TEST_KEY': 'test_value'})
    def test_get_existing_value(self):
        """Test getting existing environment variable."""
        assert SecureConfig.get('TEST_KEY') == 'test_value'
    
    def test_get_missing_value_with_default(self):
        """Test getting missing value with default."""
        assert SecureConfig.get('MISSING_KEY', 'default') == 'default'
    
    def test_get_missing_required_value(self):
        """Test getting missing required value."""
        with pytest.raises(ConfigurationError):
            SecureConfig.get('MISSING_KEY', required=True)
    
    @patch.dict(os.environ, {
        'BOOL_TRUE_1': 'true',
        'BOOL_TRUE_2': 'True',
        'BOOL_TRUE_3': '1',
        'BOOL_TRUE_4': 'yes',
        'BOOL_FALSE_1': 'false',
        'BOOL_FALSE_2': 'False',
        'BOOL_FALSE_3': '0',
        'BOOL_FALSE_4': 'no',
    })
    def test_get_boolean_values(self):
        """Test boolean value conversion."""
        assert SecureConfig.get('BOOL_TRUE_1') is True
        assert SecureConfig.get('BOOL_TRUE_2') is True
        assert SecureConfig.get('BOOL_TRUE_3') is True
        assert SecureConfig.get('BOOL_TRUE_4') is True
        assert SecureConfig.get('BOOL_FALSE_1') is False
        assert SecureConfig.get('BOOL_FALSE_2') is False
        assert SecureConfig.get('BOOL_FALSE_3') is False
        assert SecureConfig.get('BOOL_FALSE_4') is False
    
    @patch.dict(os.environ, {
        'INT_VALUE': '42',
        'INVALID_INT': 'not_a_number'
    })
    def test_get_int(self):
        """Test integer value conversion."""
        assert SecureConfig.get_int('INT_VALUE') == 42
        assert SecureConfig.get_int('INVALID_INT', 10) == 10
        assert SecureConfig.get_int('MISSING_INT', 5) == 5
    
    @patch.dict(os.environ, {
        'FLOAT_VALUE': '3.14',
        'INVALID_FLOAT': 'not_a_float'
    })
    def test_get_float(self):
        """Test float value conversion."""
        assert SecureConfig.get_float('FLOAT_VALUE') == 3.14
        assert SecureConfig.get_float('INVALID_FLOAT', 2.5) == 2.5
        assert SecureConfig.get_float('MISSING_FLOAT', 1.0) == 1.0
    
    @patch.dict(os.environ, {
        'LIST_VALUE': 'item1,item2,item3',
        'LIST_WITH_SPACES': 'item1, item2 , item3',
        'CUSTOM_SEPARATOR': 'item1|item2|item3',
        'EMPTY_LIST': ''
    })
    def test_get_list(self):
        """Test list value conversion."""
        assert SecureConfig.get_list('LIST_VALUE') == ['item1', 'item2', 'item3']
        assert SecureConfig.get_list('LIST_WITH_SPACES') == ['item1', 'item2', 'item3']
        assert SecureConfig.get_list('CUSTOM_SEPARATOR', '|') == ['item1', 'item2', 'item3']
        assert SecureConfig.get_list('EMPTY_LIST') == []
        assert SecureConfig.get_list('MISSING_LIST', default=['default']) == ['default']
    
    @patch.dict(os.environ, {
        'DATABASE_URL': 'postgresql://user:pass@localhost/db',
        'DATABASE_POOL_SIZE': '20',
        'DATABASE_MAX_OVERFLOW': '30',
        'DATABASE_ECHO': 'true'
    })
    def test_get_database_config(self):
        """Test database configuration."""
        config = SecureConfig.get_database_config()
        assert config['url'] == 'postgresql://user:pass@localhost/db'
        assert config['pool_size'] == 20
        assert config['max_overflow'] == 30
        assert config['echo'] is True
    
    @patch.dict(os.environ, {
        'REDIS_URL': 'redis://localhost:6379/1',
        'REDIS_PASSWORD': 'secret',
        'REDIS_MAX_CONNECTIONS': '100'
    })
    def test_get_redis_config(self):
        """Test Redis configuration."""
        config = SecureConfig.get_redis_config()
        assert config['url'] == 'redis://localhost:6379/1'
        assert config['password'] == 'secret'
        assert config['max_connections'] == 100
        assert config['decode_responses'] is True
    
    @patch.dict(os.environ, {
        'CAMARA_API_KEY': 'camara-key',
        'SENADO_API_KEY': 'senado-key',
        'API_TIMEOUT': '60',
        'API_RETRY_COUNT': '5',
        'API_RETRY_DELAY': '2'
    })
    def test_get_api_config(self):
        """Test API configuration."""
        config = SecureConfig.get_api_config()
        
        assert config['camara']['api_key'] == 'camara-key'
        assert config['camara']['timeout'] == 60
        assert config['camara']['verify_ssl'] is True
        
        assert config['senado']['api_key'] == 'senado-key'
        assert config['retry_count'] == 5
        assert config['retry_delay'] == 2
    
    @patch.dict(os.environ, {
        'APP_SECRET_KEY': 'app-secret',
        'JWT_SECRET_KEY': 'jwt-secret',
        'JWT_ACCESS_TOKEN_EXPIRES': '7200',
        'CORS_ALLOWED_ORIGINS': 'http://localhost:3000,http://localhost:5000'
    })
    def test_get_security_config(self):
        """Test security configuration."""
        config = SecureConfig.get_security_config()
        assert config['secret_key'] == 'app-secret'
        assert config['jwt_secret'] == 'jwt-secret'
        assert config['jwt_access_expires'] == 7200
        assert config['cors_origins'] == ['http://localhost:3000', 'http://localhost:5000']
    
    @patch.dict(os.environ, {
        'APP_ENV': 'development',
        'APP_DEBUG': 'true'
    })
    def test_is_debug(self):
        """Test debug mode detection."""
        assert SecureConfig.is_debug() is True
    
    @patch.dict(os.environ, {
        'APP_ENV': 'production',
        'APP_DEBUG': 'true'
    })
    def test_is_debug_in_production(self):
        """Test debug mode is disabled in production."""
        assert SecureConfig.is_debug() is False
    
    @patch.dict(os.environ, {'APP_ENV': 'testing'})
    def test_is_testing(self):
        """Test testing mode detection."""
        assert SecureConfig.is_testing() is True
        assert SecureConfig.is_production() is False
    
    @patch.dict(os.environ, {'APP_ENV': 'production'})
    def test_is_production(self):
        """Test production mode detection."""
        assert SecureConfig.is_production() is True
        assert SecureConfig.is_testing() is False