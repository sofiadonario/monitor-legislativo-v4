"""
Test Suite for LexML Refinado Package
=====================================

Comprehensive test suite for the Brazilian legislative document analysis system.
Includes unit tests, integration tests, and performance tests.

Test Categories:
---------------
- Unit tests: Individual component testing
- Integration tests: Component interaction testing
- Performance tests: Scalability and performance validation
- Data quality tests: Input/output validation
- End-to-end tests: Complete workflow testing

Test Organization:
-----------------
- test_classification_system.py: Document classification tests
- test_nlp_components.py: NLP pipeline tests
- test_ml_models.py: Machine learning model tests
- test_database_operations.py: Database integration tests
- test_utils.py: Utility function tests
- test_cli.py: Command-line interface tests
- test_integration.py: Integration tests
- test_performance.py: Performance and scalability tests

Usage:
------
Run all tests:
    pytest

Run specific test category:
    pytest tests/unit/
    pytest tests/integration/
    pytest tests/performance/

Run with coverage:
    pytest --cov=lexml_refinado --cov-report=html

Run specific test file:
    pytest tests/test_classification_system.py

Test Configuration:
------------------
Tests use pytest with the following plugins:
- pytest-cov: Coverage reporting
- pytest-mock: Mocking support
- pytest-benchmark: Performance benchmarking
- pytest-asyncio: Async testing support
"""

import os
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional

import pytest
import pandas as pd

# Add src to path for testing
src_path = Path(__file__).parent.parent
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

# Test data and fixtures
TEST_DATA_DIR = Path(__file__).parent / "data"
TEMP_DIR = Path(tempfile.gettempdir()) / "lexml_refinado_tests"

# Ensure test directories exist
TEST_DATA_DIR.mkdir(exist_ok=True)
TEMP_DIR.mkdir(exist_ok=True)

# Sample test data
SAMPLE_DOCUMENTS = [
    {
        'urn': 'urn:lex:br:federal:lei:2023-06-14;14.133',
        'title': 'Lei nº 14.133, de 1º de abril de 2021',
        'document_summary': 'Lei de Licitações e Contratos Administrativos',
        'document_type_full': 'Lei',
        'enacting_date': '2021-04-01',
        'state': 'Federal',
        'country': 'br'
    },
    {
        'urn': 'urn:lex:br:federal:decreto:2023-01-15;11.000',
        'title': 'Decreto nº 11.000, de 15 de janeiro de 2023',
        'document_summary': 'Regulamenta o transporte rodoviário de cargas',
        'document_type_full': 'Decreto',
        'enacting_date': '2023-01-15',
        'state': 'Federal',
        'country': 'br'
    },
    {
        'urn': 'urn:lex:br:sao.paulo:lei:2023-03-20;17.500',
        'title': 'Lei Estadual nº 17.500, de 20 de março de 2023',
        'document_summary': 'Institui programa de incentivo ao uso de biocombustíveis',
        'document_type_full': 'Lei',
        'enacting_date': '2023-03-20',
        'state': 'São Paulo',
        'country': 'br'
    }
]

SAMPLE_LEGAL_TEXT = """
Art. 1º Esta lei estabelece normas gerais sobre licitação e contratos administrativos 
pertinentes a obras, serviços, inclusive de publicidade, compras, alienações, 
concessões, permissões e locações no âmbito dos Poderes da União, dos Estados, 
do Distrito Federal e dos Municípios.

§ 1º Subordinam-se ao regime desta Lei, além dos órgãos da administração direta, 
os fundos especiais, as autarquias, as fundações públicas, as empresas públicas, 
as sociedades de economia mista e demais entidades controladas direta ou 
indiretamente pela União, Estados, Distrito Federal e Municípios.
"""

# Test configuration
class TestConfig:
    """Test configuration settings."""
    
    # Database settings for testing
    TEST_DATABASE_URL = "postgresql://test:test@localhost:5432/test_lexml"
    
    # File paths
    TEMP_DIR = TEMP_DIR
    TEST_DATA_DIR = TEST_DATA_DIR
    
    # Performance test settings
    PERFORMANCE_DOCUMENT_COUNT = 1000
    PERFORMANCE_TIMEOUT = 300  # 5 minutes
    
    # Test data settings
    SAMPLE_SIZE = 100
    RANDOM_SEED = 42

# Pytest fixtures
@pytest.fixture(scope="session")
def test_config():
    """Test configuration fixture."""
    return TestConfig()

@pytest.fixture
def sample_documents():
    """Sample document data for testing."""
    return SAMPLE_DOCUMENTS.copy()

@pytest.fixture
def sample_legal_text():
    """Sample legal text for NLP testing."""
    return SAMPLE_LEGAL_TEXT

@pytest.fixture
def temp_directory():
    """Temporary directory for test files."""
    temp_dir = TEMP_DIR / f"test_{os.getpid()}"
    temp_dir.mkdir(exist_ok=True)
    yield temp_dir
    
    # Cleanup
    import shutil
    if temp_dir.exists():
        shutil.rmtree(temp_dir)

@pytest.fixture
def sample_csv_file(temp_directory, sample_documents):
    """Create a sample CSV file for testing."""
    df = pd.DataFrame(sample_documents)
    csv_path = temp_directory / "sample_documents.csv"
    df.to_csv(csv_path, index=False)
    return csv_path

@pytest.fixture
def mock_database_connection():
    """Mock database connection for testing."""
    from unittest.mock import Mock
    
    mock_db = Mock()
    mock_db.connect.return_value = True
    mock_db.disconnect.return_value = None
    mock_db.execute_query.return_value = Mock(
        success=True,
        data=pd.DataFrame(SAMPLE_DOCUMENTS),
        row_count=len(SAMPLE_DOCUMENTS)
    )
    
    return mock_db

# Test utilities
def create_test_documents(count: int = 10) -> List[Dict[str, Any]]:
    """Create test documents for testing."""
    import random
    
    documents = []
    doc_types = ['Lei', 'Decreto', 'Portaria', 'Resolução']
    states = ['Federal', 'São Paulo', 'Rio de Janeiro', 'Minas Gerais']
    
    for i in range(count):
        doc_type = random.choice(doc_types)
        state = random.choice(states)
        
        doc = {
            'urn': f'urn:lex:br:federal:{doc_type.lower()}:2023-01-{i+1:02d};{1000+i}',
            'title': f'{doc_type} nº {1000+i}, de {i+1} de janeiro de 2023',
            'document_summary': f'Documento de teste número {i+1} sobre transporte',
            'document_type_full': doc_type,
            'enacting_date': f'2023-01-{i+1:02d}',
            'state': state,
            'country': 'br'
        }
        
        documents.append(doc)
    
    return documents

def assert_valid_classification(classification: Dict[str, Any]) -> None:
    """Assert that a classification result is valid."""
    required_keys = ['main_category', 'document_type', 'document_subtype']
    
    for key in required_keys:
        assert key in classification, f"Classification missing key: {key}"
        assert isinstance(classification[key], str), f"Classification {key} should be string"
    
    # Validate main categories
    valid_categories = ['legislation', 'jurisprudence', 'doctrine']
    assert classification['main_category'] in valid_categories, \
        f"Invalid main category: {classification['main_category']}"

def assert_valid_nlp_result(result) -> None:
    """Assert that an NLP analysis result is valid."""
    required_attrs = [
        'text_length', 'sentence_count', 'word_count', 'unique_words',
        'legal_entities', 'legal_references', 'regulatory_complexity',
        'primary_topics', 'readability_score'
    ]
    
    for attr in required_attrs:
        assert hasattr(result, attr), f"NLP result missing attribute: {attr}"
    
    # Validate numeric fields
    assert result.text_length >= 0, "Text length should be non-negative"
    assert result.sentence_count >= 0, "Sentence count should be non-negative"
    assert result.word_count >= 0, "Word count should be non-negative"
    assert 0 <= result.regulatory_complexity <= 1, "Regulatory complexity should be between 0 and 1"
    assert 0 <= result.readability_score <= 1, "Readability score should be between 0 and 1"

# Test markers
pytest_marks = {
    'unit': pytest.mark.unit,
    'integration': pytest.mark.integration,
    'performance': pytest.mark.performance,
    'slow': pytest.mark.slow,
    'database': pytest.mark.database,
    'nlp': pytest.mark.nlp,
    'ml': pytest.mark.ml
}

# Export test utilities
__all__ = [
    'TestConfig',
    'SAMPLE_DOCUMENTS',
    'SAMPLE_LEGAL_TEXT',
    'create_test_documents',
    'assert_valid_classification',
    'assert_valid_nlp_result',
    'pytest_marks'
]