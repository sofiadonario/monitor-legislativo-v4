"""Pytest configuration and fixtures for Legislative Monitoring System."""

import pytest
import os
from unittest.mock import Mock, patch
from pathlib import Path
import tempfile
import shutil

# Set testing environment
os.environ['APP_ENV'] = 'testing'
os.environ['APP_SECRET_KEY'] = 'test-secret-key'
os.environ['JWT_SECRET_KEY'] = 'test-jwt-secret'
os.environ['DATABASE_URL'] = 'sqlite:///:memory:'


@pytest.fixture(scope='session')
def test_data_dir():
    """Create a temporary directory for test data."""
    temp_dir = tempfile.mkdtemp()
    yield Path(temp_dir)
    shutil.rmtree(temp_dir)


@pytest.fixture
def mock_config():
    """Mock configuration for testing."""
    config = {
        'APP_ENV': 'testing',
        'APP_DEBUG': False,
        'APP_SECRET_KEY': 'test-secret-key',
        'DATABASE_URL': 'sqlite:///:memory:',
        'REDIS_URL': 'redis://localhost:6379/15',
        'API_TIMEOUT': 5,
        'API_RETRY_COUNT': 1,
        'API_RETRY_DELAY': 0.1,
    }
    
    with patch('os.getenv') as mock_getenv:
        mock_getenv.side_effect = lambda key, default=None: config.get(key, default)
        yield config


@pytest.fixture
def mock_requests():
    """Mock requests library for API testing."""
    with patch('requests.Session') as mock_session:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'data': 'test'}
        mock_response.text = '{"data": "test"}'
        mock_response.headers = {'content-type': 'application/json'}
        
        mock_session.return_value.request.return_value = mock_response
        mock_session.return_value.get.return_value = mock_response
        mock_session.return_value.post.return_value = mock_response
        
        yield mock_session


@pytest.fixture
def mock_redis():
    """Mock Redis client for testing."""
    with patch('redis.Redis') as mock_redis_client:
        mock_instance = Mock()
        mock_instance.get.return_value = None
        mock_instance.set.return_value = True
        mock_instance.delete.return_value = 1
        mock_instance.exists.return_value = False
        mock_instance.expire.return_value = True
        
        mock_redis_client.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def api_client():
    """Create a test client for the Flask application."""
    from web.main import create_app
    
    app = create_app('testing')
    app.config['TESTING'] = True
    
    with app.test_client() as client:
        with app.app_context():
            yield client


@pytest.fixture
def auth_headers():
    """Generate authentication headers for testing."""
    return {
        'Authorization': 'Bearer test-token',
        'Content-Type': 'application/json',
    }


@pytest.fixture
def sample_camara_data():
    """Sample data from Camara API."""
    return {
        'dados': [
            {
                'id': 12345,
                'siglaTipo': 'PL',
                'numero': 1234,
                'ano': 2025,
                'ementa': 'Test bill for Legislative Monitoring System',
                'dataApresentacao': '2025-01-30T10:00:00',
                'statusProposicao': {
                    'dataHora': '2025-01-30T10:00:00',
                    'descricaoSituacao': 'Aguardando Parecer',
                    'descricaoTramitacao': 'PLEN',
                },
                'autor': 'Deputado Test',
                'urlInteiroTeor': 'https://example.com/doc.pdf',
            }
        ],
        'links': [
            {'rel': 'self', 'href': 'https://api.camara.leg.br/proposicoes'},
            {'rel': 'next', 'href': 'https://api.camara.leg.br/proposicoes?pagina=2'},
        ],
    }


@pytest.fixture
def sample_senado_data():
    """Sample data from Senado API."""
    return {
        'ListaMateriasPesquisa': {
            'Materias': {
                'Materia': [
                    {
                        'CodigoMateria': 54321,
                        'SiglaSubtipoMateria': 'PLS',
                        'NumeroMateria': 4321,
                        'AnoMateria': 2025,
                        'DescricaoObjetivoProcesso': 'Test Senate bill',
                        'DataApresentacao': '30/01/2025',
                        'SituacaoAtual': {
                            'DataSituacao': '30/01/2025',
                            'DescricaoSituacao': 'Em tramitação',
                        },
                        'AutorPrincipal': {
                            'NomeAutor': 'Senador Test',
                        },
                    }
                ]
            }
        }
    }


@pytest.fixture
def sample_search_query():
    """Sample search query for testing."""
    return {
        'keywords': 'educação saúde',
        'start_date': '2025-01-01',
        'end_date': '2025-12-31',
        'sources': ['camara', 'senado'],
        'types': ['PL', 'PLS'],
        'limit': 10,
        'offset': 0,
    }


class MockCircuitBreaker:
    """Mock circuit breaker for testing."""
    
    def __init__(self):
        self.is_open = False
        self.failure_count = 0
    
    def call(self, func):
        """Mock circuit breaker call."""
        if self.is_open:
            raise Exception("Circuit breaker is open")
        return func
    
    def record_success(self):
        """Record successful call."""
        self.failure_count = 0
    
    def record_failure(self):
        """Record failed call."""
        self.failure_count += 1
        if self.failure_count >= 5:
            self.is_open = True


@pytest.fixture
def mock_circuit_breaker():
    """Mock circuit breaker for testing."""
    return MockCircuitBreaker()


# Markers for different test types
pytest.mark.unit = pytest.mark.unit
pytest.mark.integration = pytest.mark.integration
pytest.mark.security = pytest.mark.security
pytest.mark.performance = pytest.mark.performance
pytest.mark.slow = pytest.mark.slow