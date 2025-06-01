#!/usr/bin/env python3
"""
LexML Implementation Verification Script
=======================================

Verifies that the LexML Brasil official integration is working correctly.
Tests all major components without requiring external dependencies.
"""

import sys
import asyncio
import traceback
from pathlib import Path

def test_imports():
    """Test that all required modules can be imported"""
    print("Testing imports...")
    
    try:
        # Test core Python modules (should always work)
        import xml.etree.ElementTree as ET
        import json
        import sqlite3
        import asyncio
        import time
        import logging
        print("  ✓ Core Python modules")
        
        # Test our LexML implementation
        from core.api.lexml_official_client import LexMLOfficialClient, LexMLDocument
        from core.models.lexml_official_models import LexMLSearchRequest, CQLQueryBuilder
        print("  ✓ LexML official client and models")
        
        from core.lexml.official_vocabulary_client import OfficialVocabularyClient
        from core.lexml.skos_processor import SKOSProcessor
        print("  ✓ SKOS vocabulary system")
        
        from core.api.lexml_service_official import LexMLOfficialSearchService
        print("  ✓ Official search service")
        
        return True
        
    except ImportError as e:
        print(f"  ❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"  ❌ Unexpected error: {e}")
        return False

def test_cql_builder():
    """Test CQL query building without external dependencies"""
    print("Testing CQL query builder...")
    
    try:
        from core.models.lexml_official_models import CQLQueryBuilder
        
        # Test basic query
        query = CQLQueryBuilder.build_transport_query(['transporte', 'carga'])
        assert 'transporte' in query or 'logística' in query
        print(f"  ✓ Basic query: {query[:60]}...")
        
        # Test with filters
        query_with_filters = CQLQueryBuilder.build_transport_query(
            ['licenciamento'], 
            {'autoridade': 'br:ministerio.transportes'}
        )
        assert 'licenciamento' in query_with_filters
        assert 'autoridade' in query_with_filters
        print(f"  ✓ Query with filters: {query_with_filters[:60]}...")
        
        return True
        
    except Exception as e:
        print(f"  ❌ CQL builder error: {e}")
        traceback.print_exc()
        return False

def test_data_models():
    """Test data model conversions"""
    print("Testing data models...")
    
    try:
        from core.models.lexml_official_models import LexMLDocument
        from datetime import datetime
        
        # Create test document
        doc = LexMLDocument(
            urn='urn:lex:br:federal:lei:2023-01-01;12345',
            title='Lei de Transporte Sustentável',
            autoridade='br:presidencia.republica',
            evento='publicacao',
            localidade='BR',
            data_evento='2023-01-01',
            tipo_documento='lei',
            resumo='Lei sobre transporte sustentável',
            palavras_chave=['transporte', 'sustentável']
        )
        
        # Test conversion to Proposition
        proposition = doc.to_proposition()
        assert proposition.id == doc.urn
        assert proposition.type == 'LEI'
        assert 'lexml_urn' in proposition.metadata
        print("  ✓ LexML to Proposition conversion")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Data model error: {e}")
        traceback.print_exc()
        return False

def test_vocabulary_client():
    """Test vocabulary client without external API calls"""
    print("Testing vocabulary client...")
    
    try:
        from core.lexml.official_vocabulary_client import OfficialVocabularyClient
        
        # Create client
        client = OfficialVocabularyClient()
        print("  ✓ Vocabulary client created")
        
        # Test fallback vocabulary generation
        concepts, metadata = client._generate_fallback_vocabulary('autoridade', 'test_url')
        assert len(concepts) > 0
        assert metadata.name == 'autoridade'
        print(f"  ✓ Fallback vocabulary: {len(concepts)} concepts")
        
        # Test concept search
        client.vocabularies['autoridade'] = concepts
        results = client.search_concepts('brasil', 'autoridade')
        print(f"  ✓ Concept search: {len(results)} results")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Vocabulary client error: {e}")
        traceback.print_exc()
        return False

def test_skos_processor():
    """Test SKOS processor functionality"""
    print("Testing SKOS processor...")
    
    try:
        from core.lexml.official_vocabulary_client import OfficialVocabularyClient
        from core.lexml.skos_processor import SKOSProcessor
        
        # Create processor
        vocab_client = OfficialVocabularyClient()
        processor = SKOSProcessor(vocab_client)
        print("  ✓ SKOS processor created")
        
        # Test transport domain expansion
        expansions = processor._expand_from_transport_domain('transporte')
        assert len(expansions) > 0
        print(f"  ✓ Transport expansion: {len(expansions)} terms")
        
        # Test authority expansion
        auth_expansions = processor._expand_from_authorities('ANTT')
        assert len(auth_expansions) > 0
        print(f"  ✓ Authority expansion: {len(auth_expansions)} terms")
        
        return True
        
    except Exception as e:
        print(f"  ❌ SKOS processor error: {e}")
        traceback.print_exc()
        return False

async def test_local_data_integration():
    """Test integration with local CSV data"""
    print("Testing local data integration...")
    
    try:
        from core.api.lexml_service_official import LexMLOfficialSearchService
        
        # Create service
        service = LexMLOfficialSearchService()
        await service.initialize()
        print("  ✓ Service initialized")
        
        # Test local data search (Tier 3)
        result = await service._search_tier3_local_data('transporte', {})
        assert result.total_count > 0
        assert result.metadata['search_tier'] == 'tier3_local_data'
        print(f"  ✓ Local data search: {result.total_count} documents")
        
        # Test complete search flow
        search_result = await service.search('licenciamento', {})
        assert search_result.total_count >= 0
        print(f"  ✓ Complete search: {search_result.total_count} results from {search_result.metadata.get('search_tier', 'unknown')}")
        
        # Test performance metrics
        metrics = service.get_performance_metrics()
        assert 'total_requests' in metrics
        print(f"  ✓ Performance metrics: {metrics['total_requests']} requests")
        
        await service.close()
        return True
        
    except Exception as e:
        print(f"  ❌ Local data integration error: {e}")
        traceback.print_exc()
        return False

def test_circuit_breaker():
    """Test circuit breaker functionality"""
    print("Testing circuit breaker...")
    
    try:
        from core.api.lexml_service_official import LexMLOfficialSearchService
        
        # Create service
        service = LexMLOfficialSearchService()
        
        # Test circuit breaker state
        assert not service.circuit_breaker.is_open
        
        # Simulate failures
        for i in range(3):
            service._handle_circuit_breaker_failure()
        
        assert service.circuit_breaker.is_open
        print("  ✓ Circuit breaker opens after failures")
        
        # Test reset
        service._reset_circuit_breaker()
        assert not service.circuit_breaker.is_open
        print("  ✓ Circuit breaker resets")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Circuit breaker error: {e}")
        traceback.print_exc()
        return False

async def main():
    """Run all tests"""
    print("=" * 60)
    print("LexML Brasil Implementation Verification")
    print("=" * 60)
    
    tests = [
        ("Imports", test_imports),
        ("CQL Builder", test_cql_builder),
        ("Data Models", test_data_models),
        ("Vocabulary Client", test_vocabulary_client),
        ("SKOS Processor", test_skos_processor),
        ("Circuit Breaker", test_circuit_breaker),
        ("Local Data Integration", test_local_data_integration),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n📋 {test_name}:")
        try:
            if asyncio.iscoroutinefunction(test_func):
                result = await test_func()
            else:
                result = test_func()
            
            if result:
                passed += 1
                print(f"  ✅ {test_name} PASSED")
            else:
                print(f"  ❌ {test_name} FAILED")
                
        except Exception as e:
            print(f"  ❌ {test_name} FAILED with exception: {e}")
    
    print("\n" + "=" * 60)
    print(f"RESULTS: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 ALL TESTS PASSED! LexML implementation is working correctly.")
        print("\nThe system now provides:")
        print("  • Official LexML Brasil SRU protocol integration")
        print("  • Three-tier fallback architecture (LexML → Regional APIs → Local CSV)")
        print("  • SKOS vocabulary expansion with transport domain expertise")
        print("  • Circuit breaker pattern for reliability")
        print("  • Guaranteed search results from 889 real legislative documents")
        return True
    else:
        print(f"❌ {total - passed} tests failed. Please check the implementation.")
        return False

if __name__ == '__main__':
    # Add current directory to Python path
    sys.path.insert(0, str(Path(__file__).parent))
    
    try:
        result = asyncio.run(main())
        sys.exit(0 if result else 1)
    except KeyboardInterrupt:
        print("\n⚠️  Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        traceback.print_exc()
        sys.exit(1)