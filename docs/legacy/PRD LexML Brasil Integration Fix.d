PRD: LexML Brasil Integration Fix

    Senior Engineer Implementation Plan

    Executive Summary

    The current LexML implementation has architectural flaws and missing proper integration with LexML Brasil's official APIs and protocols. This PRD outlines a complete rebuild of the 
    LexML service using official standards and proper fallback mechanisms.

    Current Issues Analysis

    1. Incorrect API Integration

    - Current code attempts to use non-existent "enhanced" LexML APIs
    - Missing proper SRU (Search/Retrieve via URL) protocol implementation
    - No OAI-PMH (Open Archives Initiative Protocol for Metadata Harvesting) support
    - Fallback system relies on static CSV instead of real-time API

    2. Missing Official LexML Standards

    - No implementation of official LexML XML schema (oai_lexml.xsd)
    - Missing SKOS vocabulary integration per LexML specification
    - No URN (Uniform Resource Name) handling for LexML documents
    - Absent proper metadata extraction according to FRBROO standards

    3. Architecture Problems

    - Vocabulary manager trying to access non-existent remote vocabularies
    - Circuit breaker and caching not aligned with LexML's official rate limits
    - Missing proper data source prioritization (LexML → Regional APIs → CSV)

    Implementation Plan

    Phase 1: Core LexML Client Rebuild (Priority: CRITICAL)

    Deliverables:
    - New LexMLOfficialClient implementing SRU protocol per LexML Brasil specs
    - Proper XML parsing for oai_lexml format responses
    - URN resolution and metadata extraction
    - Official rate limiting (100 requests/minute as per documentation)

    Files to create/modify:
    - core/api/lexml_official_client.py (NEW)
    - core/models/lexml_official_models.py (NEW)
    - core/api/lexml_service.py (MAJOR REFACTOR)

    Phase 2: Vocabulary System Implementation (Priority: HIGH)

    Deliverables:
    - SKOS vocabulary loader using LexML's official vocabulary endpoints
    - Hierarchical term expansion using broader/narrower relationships
    - Transport-specific vocabulary integration
    - Vocabulary caching with 24h TTL per LexML recommendations

    Files to create/modify:
    - core/lexml/official_vocabulary_client.py (NEW)
    - core/lexml/skos_processor.py (NEW)
    - Update core/lexml/vocabulary_manager.py

    Phase 3: Proper Fallback Architecture (Priority: HIGH)

    Deliverables:
    - Three-tier fallback: LexML API → Regional APIs → Local CSV (889 documents)
    - Circuit breaker implementation with proper failure handling
    - Intelligent source selection based on query type and availability
    - Performance monitoring and automatic failover

    Files to modify:
    - core/api/api_service.py (search orchestration)
    - core/utils/fallback_manager.py (enhanced logic)
    - src/data/real_legislative_data.py (format standardization)

    Phase 4: Integration & Testing (Priority: MEDIUM)

    Deliverables:
    - Integration tests with real LexML endpoints
    - Performance benchmarking and optimization
    - Documentation updates
    - Deployment verification

    Technical Specifications

    1. LexML SRU Protocol Implementation

    # Official SRU endpoint: http://www.lexml.gov.br/oai/sru
    # Parameters: operation=searchRetrieve, query=CQL, recordSchema=oai_lexml

    2. Official Vocabulary Endpoints

    OFFICIAL_VOCABULARIES = {
        'autoridade': 'http://projeto.lexml.gov.br/vocabulario/autoridade.rdf',
        'evento': 'http://projeto.lexml.gov.br/vocabulario/evento.rdf',
        'tipo_documento': 'http://projeto.lexml.gov.br/vocabulario/tipo_documento.rdf'
    }

    3. Proper XML Schema Handling

    - Implement parsing for <LexML xmlns="http://www.lexml.gov.br/oai_lexml"> format
    - Extract proper metadata: URN, title, autoridade, evento, localidade
    - Handle new schema format (post-2010 correction)

    4. Performance Requirements

    - API response time: < 2s (95th percentile)
    - Fallback activation: < 500ms
    - Search result accuracy: > 90% using vocabulary expansion
    - System uptime: > 99.5% with proper fallback

    Risk Assessment

    High Risk

    - LexML API availability: Mitigated by robust fallback system
    - Vocabulary loading failures: Mitigated by local vocabulary cache
    - Schema changes: Mitigated by version detection and backwards compatibility

    Medium Risk

    - Performance degradation: Mitigated by intelligent caching and circuit breakers
    - Data format inconsistencies: Mitigated by proper validation and error handling

    Success Metrics

    Technical KPIs

    - Search latency reduction: 40% improvement
    - Search result accuracy: 85%+ relevance score
    - System availability: 99.5%+ uptime
    - API error rate: < 2%

    User Experience KPIs

    - Zero-result searches: < 5% (vs current high rate)
    - Search satisfaction: 90%+ relevant results
    - Performance consistency: < 3s response time

    Resource Requirements

    Development Time

    - Phase 1: 3-4 days (core client implementation)
    - Phase 2: 2-3 days (vocabulary system)
    - Phase 3: 2 days (fallback architecture)
    - Phase 4: 1-2 days (testing and deployment)

    Total: 8-11 days

    Dependencies

    - Access to LexML Brasil SRU endpoint
    - XML parsing libraries (already available)
    - SKOS/RDF processing capabilities
    - Existing CSV dataset (889 documents) as final fallback

    Implementation Priority

    This is a CRITICAL fix that addresses the core functionality failure. The system currently returns 0 results due to improper LexML integration. This fix will:

    1. Restore proper search functionality
    2. Implement industry-standard LexML protocols
    3. Provide reliable fallback mechanisms
    4. Enable vocabulary-enhanced academic research capabilities

    The implementation follows LexML Brasil's official specifications and uses the provided toolkit documentation as the authoritative source for integration requirements.