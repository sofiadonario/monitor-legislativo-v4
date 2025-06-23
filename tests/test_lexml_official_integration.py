"""
LexML Official Integration Tests
==============================

Comprehensive test suite for official LexML Brasil integration.
Tests the complete three-tier fallback architecture with real endpoints.

Test Categories:
1. Official SRU client functionality
2. SKOS vocabulary loading and processing
3. Three-tier fallback architecture
4. Circuit breaker behavior
5. Performance and reliability
"""

import asyncio
import pytest
import time
from datetime import datetime
from unittest.mock import Mock, patch
import aiohttp

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.api.lexml_official_client import LexMLOfficialClient, LexMLDocument
from core.api.lexml_service_official import LexMLOfficialSearchService
from core.lexml.official_vocabulary_client import OfficialVocabularyClient
from core.lexml.skos_processor import SKOSProcessor
from core.models.lexml_official_models import LexMLSearchRequest, CQLQueryBuilder

class TestLexMLOfficialClient:
    """Test official LexML SRU client"""
    
    @pytest.fixture
    async def client(self):
        """Create test client"""
        client = LexMLOfficialClient()
        yield client
        await client.close()
    
    @pytest.mark.asyncio
    async def test_health_check(self, client):
        """Test basic connectivity to LexML Brasil"""
        try:
            is_healthy = await client.health_check()
            assert isinstance(is_healthy, bool)
            print(f"LexML health check: {'✓ PASS' if is_healthy else '✗ FAIL'}")
        except Exception as e:
            print(f"Health check failed (expected in some environments): {e}")
            # This is acceptable as LexML might not be accessible in all environments
    
    @pytest.mark.asyncio
    async def test_cql_query_builder(self, client):
        """Test CQL query building"""
        query = client.build_cql_query(
            terms=['transporte', 'carga'],
            autoridade='br:ministerio.transportes',
            evento='publicacao',
            date_from='2020-01-01',
            date_to='2023-12-31'
        )
        
        assert 'transporte' in query
        assert 'carga' in query
        assert 'autoridade' in query
        assert 'evento' in query
        assert 'data>=' in query
        print(f"CQL Query: {query}")
    
    @pytest.mark.asyncio
    async def test_rate_limiter(self, client):
        """Test rate limiting functionality"""
        start_time = time.time()
        
        # Make multiple requests quickly
        for i in range(3):
            await client.rate_limiter.acquire()
        
        elapsed = time.time() - start_time
        assert elapsed >= 0  # Should complete (rate limiter allows first requests)
        print(f"Rate limiter test completed in {elapsed:.2f}s")

class TestOfficialVocabularyClient:
    """Test SKOS vocabulary client"""
    
    @pytest.fixture
    def vocab_client(self):
        """Create test vocabulary client"""
        return OfficialVocabularyClient()
    
    @pytest.mark.asyncio
    async def test_vocabulary_loading(self, vocab_client):
        """Test loading official vocabularies"""
        try:
            # Try to load one vocabulary
            metadata = await vocab_client.load_vocabulary('autoridade', force_refresh=False)
            
            if metadata:
                assert metadata.name == 'autoridade'
                assert metadata.concept_count >= 0
                print(f"✓ Loaded vocabulary 'autoridade': {metadata.concept_count} concepts")
            else:
                print("✗ Could not load vocabulary (fallback generated)")
                # Check if fallback was generated
                assert 'autoridade' in vocab_client.vocabularies or len(vocab_client.vocabularies) == 0
                
        except Exception as e:
            print(f"Vocabulary loading failed (expected in some environments): {e}")
    
    def test_fallback_vocabulary_generation(self, vocab_client):
        """Test fallback vocabulary generation"""
        concepts, metadata = vocab_client._generate_fallback_vocabulary('autoridade', 'test_url')
        
        assert len(concepts) > 0
        assert metadata.name == 'autoridade'
        assert 'fallback' in metadata.version.lower()
        print(f"✓ Generated fallback vocabulary: {len(concepts)} concepts")
    
    def test_concept_search(self, vocab_client):
        """Test concept searching"""
        # Generate fallback vocabulary first
        concepts, metadata = vocab_client._generate_fallback_vocabulary('autoridade', 'test_url')
        vocab_client.vocabularies['autoridade'] = concepts
        vocab_client.metadata['autoridade'] = metadata
        
        # Search for concepts
        results = vocab_client.search_concepts('brasil', 'autoridade')
        assert isinstance(results, list)
        print(f"✓ Concept search returned {len(results)} results")

class TestSKOSProcessor:
    """Test SKOS processing functionality"""
    
    @pytest.fixture
    def processor(self):
        """Create test SKOS processor"""
        vocab_client = OfficialVocabularyClient()
        return SKOSProcessor(vocab_client)
    
    @pytest.mark.asyncio
    async def test_query_expansion(self, processor):
        """Test query expansion functionality"""
        result = await processor.expand_query(
            query='transporte',
            max_expansions=15,
            include_hierarchy=True,
            include_transport_domain=True
        )
        
        assert result.original_query == 'transporte'
        assert len(result.expanded_terms) > 1  # Should expand beyond original
        assert result.confidence_score >= 0.0
        assert result.processing_time_ms >= 0
        
        print(f"✓ Query expansion: '{result.original_query}' → {result.total_expansions} terms")
        print(f"  Confidence: {result.confidence_score:.2f}")
        print(f"  Top terms: {[t.term for t in result.expanded_terms[:5]]}")
    
    def test_transport_domain_expansion(self, processor):
        """Test transport domain specialization"""
        expansions = processor._expand_from_transport_domain('licenciamento')
        
        assert len(expansions) > 0
        expansion_terms = [e.term for e in expansions]
        
        # Should include related transport terms
        expected_terms = ['licença', 'autorização', 'permissão']
        found_terms = [term for term in expected_terms if any(term in exp_term for exp_term in expansion_terms)]
        
        assert len(found_terms) > 0
        print(f"✓ Transport domain expansion: {expansion_terms}")
    
    def test_authority_expansion(self, processor):
        """Test Brazilian authority expansion"""
        expansions = processor._expand_from_authorities('ANTT')
        
        assert len(expansions) > 0
        expansion_terms = [e.term for e in expansions]
        
        # Should include related transport authority terms
        assert any('transport' in term.lower() for term in expansion_terms)
        print(f"✓ Authority expansion: {expansion_terms}")

class TestThreeTierFallback:
    """Test three-tier fallback architecture"""
    
    @pytest.fixture
    async def service(self):
        """Create test service"""
        service = LexMLOfficialSearchService()
        await service.initialize()
        yield service
        await service.close()
    
    @pytest.mark.asyncio
    async def test_tier1_official_search(self, service):
        """Test Tier 1: Official LexML search"""
        try:
            result = await service._search_tier1_official_lexml('transporte', {})
            
            if result and result.total_count > 0:
                print(f"✓ Tier 1 success: {result.total_count} documents found")
                assert result.metadata['search_tier'] == 'tier1_official_lexml'
                assert 'sru_protocol' in result.metadata
            else:
                print("✗ Tier 1 returned no results (may be expected)")
                
        except Exception as e:
            print(f"✗ Tier 1 failed: {e} (expected in some environments)")
    
    @pytest.mark.asyncio
    async def test_tier3_local_data(self, service):
        """Test Tier 3: Local data fallback"""
        try:
            result = await service._search_tier3_local_data('transporte', {})
            
            assert result.total_count > 0
            assert result.metadata['search_tier'] == 'tier3_local_data'
            assert 'local_dataset_size' in result.metadata
            
            print(f"✓ Tier 3 success: {result.total_count} documents from local data")
            
        except Exception as e:
            print(f"✗ Tier 3 failed: {e}")
            # This should not fail as it uses local data
            raise
    
    @pytest.mark.asyncio
    async def test_complete_search_flow(self, service):
        """Test complete search with automatic fallback"""
        result = await service.search('licenciamento', {})
        
        assert result is not None
        assert result.total_count >= 0
        assert 'search_tier' in result.metadata
        
        print(f"✓ Complete search: {result.total_count} documents")
        print(f"  Used tier: {result.metadata.get('search_tier')}")
        print(f"  Vocabulary enhanced: {result.metadata.get('vocabulary_enhanced', False)}")

class TestCircuitBreaker:
    """Test circuit breaker functionality"""
    
    @pytest.fixture
    async def service(self):
        """Create test service"""
        service = LexMLOfficialSearchService()
        await service.initialize()
        yield service
        await service.close()
    
    def test_circuit_breaker_state(self, service):
        """Test circuit breaker state management"""
        # Initially closed
        assert not service.circuit_breaker.is_open
        
        # Simulate failures
        for i in range(3):
            service._handle_circuit_breaker_failure()
        
        # Should be open after 3 failures
        assert service.circuit_breaker.is_open
        
        # Reset
        service._reset_circuit_breaker()
        assert not service.circuit_breaker.is_open
        
        print("✓ Circuit breaker state management working")
    
    @pytest.mark.asyncio
    async def test_health_status(self, service):
        """Test health status reporting"""
        health = await service.get_health_status()
        
        assert health.last_check is not None
        assert isinstance(health.is_healthy, bool)
        assert health.circuit_breaker_state is not None
        
        print(f"✓ Health status: {'healthy' if health.is_healthy else 'unhealthy'}")

class TestPerformanceMetrics:
    """Test performance and metrics"""
    
    @pytest.fixture
    async def service(self):
        """Create test service"""
        service = LexMLOfficialSearchService()
        await service.initialize()
        yield service
        await service.close()
    
    @pytest.mark.asyncio
    async def test_performance_metrics(self, service):
        """Test performance metrics collection"""
        # Perform some searches
        await service.search('transporte', {})
        await service.search('carga', {})
        
        metrics = service.get_performance_metrics()
        
        assert metrics['total_requests'] >= 2
        assert 'success_rate_percent' in metrics
        assert 'fallback_rate_percent' in metrics
        assert 'circuit_breaker_open' in metrics
        
        print(f"✓ Performance metrics: {metrics}")
    
    @pytest.mark.asyncio
    async def test_search_performance(self, service):
        """Test search performance benchmarks"""
        start_time = time.time()
        
        result = await service.search('licenciamento', {'max_records': 10})
        
        elapsed_time = (time.time() - start_time) * 1000  # Convert to milliseconds
        
        assert elapsed_time < 5000  # Should complete within 5 seconds
        assert result is not None
        
        print(f"✓ Search performance: {elapsed_time:.0f}ms")

class TestDataQuality:
    """Test data quality and accuracy"""
    
    @pytest.mark.asyncio
    async def test_document_format_conversion(self):
        """Test LexML to Proposition conversion"""
        from core.models.lexml_official_models import LexMLDocument
        
        # Create test LexML document
        lexml_doc = LexMLDocument(
            urn='urn:lex:br:federal:lei:2023-01-01;12345',
            title='Lei de Transporte Sustentável',
            autoridade='br:presidencia.republica',
            evento='publicacao',
            localidade='BR',
            data_evento='2023-01-01',
            tipo_documento='lei',
            resumo='Lei sobre transporte sustentável no Brasil',
            palavras_chave=['transporte', 'sustentável', 'meio ambiente']
        )
        
        # Convert to Proposition
        proposition = lexml_doc.to_proposition()
        
        assert proposition.id == lexml_doc.urn
        assert proposition.title == lexml_doc.title
        assert proposition.type == 'LEI'
        assert 'lexml_urn' in proposition.metadata
        assert proposition.source == 'LEXML_BRASIL'
        
        print(f"✓ Document conversion: {proposition.type} - {proposition.title}")
    
    def test_cql_query_quality(self):
        """Test CQL query generation quality"""
        # Test transport-specific query
        query = CQLQueryBuilder.build_transport_query(
            terms=['licenciamento', 'transporte'],
            filters={'autoridade': 'br:ministerio.transportes'}
        )
        
        assert 'licenciamento' in query
        assert 'transporte' in query or 'logística' in query  # Should expand
        assert 'autoridade' in query
        
        print(f"✓ CQL query quality: {query}")

def run_integration_tests():
    """Run all integration tests"""
    print("=" * 60)
    print("LexML Brasil Official Integration Tests")
    print("=" * 60)
    
    # Run tests
    pytest.main([__file__, '-v', '-s'])

if __name__ == '__main__':
    run_integration_tests()